//! Connection adapter for HTTP/3 WebTransport bridging.
//! The adapter keeps QUIC connection state separate from per-session accounting.

use std::sync::{Arc, Mutex as StdMutex};
use std::task::Poll;

use anyhow::Context;
use bytes::{Buf, Bytes};
use futures_util::{future::poll_fn, ready};
use h3::frame::FrameStream;
use h3::proto::frame::Frame;
use h3::quic::{OpenStreams, SendStreamUnframed, StreamErrorIncoming, StreamId};
use h3::stream::{BidiStreamHeader, BufRecvStream, UniStreamHeader, WriteBuf};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_webtransport::SessionId;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{
  DispatcherEvent, DownstreamBidiEvent, DownstreamBidiStream, DownstreamUniRecvStream,
  DownstreamUniSendStream, H3DatagramReader, H3DatagramSender, H3OpenStreams, H3ServerConnection,
};

pub(super) struct DownstreamWebTransportConnection {
  conn: Arc<StdMutex<H3ServerConnection>>,
  opener: StdMutex<H3OpenStreams>,
}

impl DownstreamWebTransportConnection {
  pub(super) fn new(conn: H3ServerConnection) -> Self {
    let opener =
      <crate::quic::h3::Connection as h3::quic::Connection<Bytes>>::opener(&conn.inner.conn);
    Self {
      conn: Arc::new(StdMutex::new(conn)),
      opener: StdMutex::new(opener),
    }
  }

  pub(super) async fn open_bi(
    &self,
    session_id: SessionId,
  ) -> anyhow::Result<DownstreamBidiStream> {
    let stream = poll_fn(|cx| {
      self
        .opener
        .lock()
        .expect("downstream HTTP/3 opener lock poisoned")
        .poll_open_bidi(cx)
    })
    .await
    .map_err(downstream_stream_error)?;
    let mut stream = BufRecvStream::new(stream);
    send_webtransport_header(&mut stream, BidiStreamHeader::WebTransportBidi(session_id)).await?;
    Ok(stream)
  }

  pub(super) async fn open_uni(
    &self,
    session_id: SessionId,
  ) -> anyhow::Result<DownstreamUniSendStream> {
    let stream = poll_fn(|cx| {
      self
        .opener
        .lock()
        .expect("downstream HTTP/3 opener lock poisoned")
        .poll_open_send(cx)
    })
    .await
    .map_err(downstream_stream_error)?;
    let mut stream = BufRecvStream::new(stream);
    send_webtransport_header(&mut stream, UniStreamHeader::WebTransportUni(session_id)).await?;
    Ok(stream)
  }

  pub(super) fn datagram_reader(&self) -> H3DatagramReader {
    self
      .conn
      .lock()
      .expect("downstream HTTP/3 connection lock poisoned")
      .get_datagram_reader()
  }

  pub(super) fn datagram_sender(&self, stream_id: StreamId) -> H3DatagramSender {
    self
      .conn
      .lock()
      .expect("downstream HTTP/3 connection lock poisoned")
      .get_datagram_sender(stream_id)
  }
}

pub(super) fn spawn_downstream_reader_tasks(
  downstream: Arc<DownstreamWebTransportConnection>,
  events: mpsc::Sender<DispatcherEvent>,
) -> Vec<JoinHandle<()>> {
  vec![
    tokio::spawn(read_downstream_bidi_task(
      downstream.clone(),
      events.clone(),
    )),
    tokio::spawn(read_downstream_uni_task(downstream.clone(), events.clone())),
    tokio::spawn(read_downstream_datagrams_task(downstream, events)),
  ]
}

async fn read_downstream_bidi_task(
  downstream: Arc<DownstreamWebTransportConnection>,
  events: mpsc::Sender<DispatcherEvent>,
) {
  loop {
    match accept_downstream_bidi(&downstream).await {
      Ok(Some(DownstreamBidiEvent::WebTransport(session_id, stream))) => {
        if events
          .send(DispatcherEvent::DownstreamBidi(session_id, stream))
          .await
          .is_err()
        {
          return;
        }
      }
      Ok(Some(DownstreamBidiEvent::Request(request, stream))) => {
        if events
          .send(DispatcherEvent::DownstreamRequest(request, stream))
          .await
          .is_err()
        {
          return;
        }
      }
      Ok(Some(DownstreamBidiEvent::Closed)) => {}
      Ok(None) => {
        let _ = events.send(DispatcherEvent::ConnectionClosed).await;
        return;
      }
      Err(error) => {
        let _ = events.send(DispatcherEvent::Fatal(error)).await;
        return;
      }
    }
  }
}

async fn accept_downstream_bidi(
  downstream: &DownstreamWebTransportConnection,
) -> anyhow::Result<Option<DownstreamBidiEvent>> {
  let stream = poll_fn(|cx| {
    downstream
      .conn
      .lock()
      .expect("downstream HTTP/3 connection lock poisoned")
      .poll_accept_request_stream(cx)
  })
  .await
  .context("failed to accept downstream HTTP/3 bidirectional stream")?;

  let Some(stream) = stream else {
    return Ok(None);
  };
  let stream = FrameStream::new(BufRecvStream::new(stream));
  let mut resolver = {
    downstream
      .conn
      .lock()
      .expect("downstream HTTP/3 connection lock poisoned")
      .create_resolver(stream)
  };
  let frame = poll_fn(|cx| resolver.frame_stream.poll_next(cx)).await;

  match frame {
    Ok(Some(Frame::WebTransportStream(session_id))) => Ok(Some(DownstreamBidiEvent::WebTransport(
      session_id,
      resolver.frame_stream.into_inner(),
    ))),
    Ok(None) => Ok(Some(DownstreamBidiEvent::Closed)),
    frame => {
      let (request, stream) = resolver
        .accept_with_frame(frame)
        .context("failed to accept downstream HTTP/3 request frame")?
        .resolve()
        .await
        .context("failed to resolve downstream HTTP/3 request")?;
      Ok(Some(DownstreamBidiEvent::Request(
        request,
        Box::new(stream),
      )))
    }
  }
}

async fn read_downstream_uni_task(
  downstream: Arc<DownstreamWebTransportConnection>,
  events: mpsc::Sender<DispatcherEvent>,
) {
  loop {
    match accept_downstream_uni(&downstream).await {
      Ok((session_id, stream)) => {
        if events
          .send(DispatcherEvent::DownstreamUni(session_id, stream))
          .await
          .is_err()
        {
          return;
        }
      }
      Err(error) => {
        let _ = events.send(DispatcherEvent::Fatal(error)).await;
        return;
      }
    }
  }
}

async fn accept_downstream_uni(
  downstream: &DownstreamWebTransportConnection,
) -> anyhow::Result<(SessionId, DownstreamUniRecvStream)> {
  poll_fn(|cx| {
    let mut conn = downstream
      .conn
      .lock()
      .expect("downstream HTTP/3 connection lock poisoned");
    conn.inner.poll_accept_recv(cx)?;
    if let Some((session_id, stream)) = conn.inner.accepted_streams_mut().wt_uni_streams.pop() {
      return Poll::Ready(Ok::<
        (SessionId, DownstreamUniRecvStream),
        h3::error::ConnectionError,
      >((session_id, stream)));
    }
    Poll::Pending
  })
  .await
  .context("failed to accept downstream WebTransport unidirectional stream")
}

async fn read_downstream_datagrams_task(
  downstream: Arc<DownstreamWebTransportConnection>,
  events: mpsc::Sender<DispatcherEvent>,
) {
  let mut reader = downstream.datagram_reader();
  loop {
    match reader.read_datagram().await {
      Ok(datagram) => {
        let stream_id = datagram.stream_id();
        let mut payload = datagram.into_payload();
        let len = payload.remaining();
        let payload = payload.copy_to_bytes(len);
        if events
          .send(DispatcherEvent::DownstreamDatagram(stream_id, payload))
          .await
          .is_err()
        {
          return;
        }
      }
      Err(error) => {
        let _ = events.send(DispatcherEvent::Fatal(error.into())).await;
        return;
      }
    }
  }
}

async fn send_webtransport_header<S, H>(
  stream: &mut BufRecvStream<S, Bytes>,
  header: H,
) -> anyhow::Result<()>
where
  BufRecvStream<S, Bytes>: SendStreamUnframed<Bytes>,
  H: Into<WriteBuf<Bytes>>,
{
  let mut header = header.into();
  poll_fn(|cx| {
    while header.has_remaining() {
      ready!(stream.poll_send(cx, &mut header)).map_err(downstream_stream_error)?;
    }
    Poll::Ready(Ok(()))
  })
  .await
}

fn downstream_stream_error(error: StreamErrorIncoming) -> anyhow::Error {
  anyhow::anyhow!("downstream WebTransport stream error: {error:?}")
}
