//! Connection adapter for HTTP/3 WebTransport bridging.
//! The adapter keeps QUIC connection state separate from per-session accounting.

use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::task::Poll;

use anyhow::Context;
use bytes::{Buf, Bytes};
use futures_util::{future::poll_fn, ready};
use h3::frame::{FrameStream, FrameStreamError};
use h3::proto::frame::Frame;
use h3::quic::{OpenStreams, SendStreamUnframed, StreamErrorIncoming, StreamId};
use h3::stream::{BidiStreamHeader, BufRecvStream, UniStreamHeader, WriteBuf};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_webtransport::SessionId;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

use super::{
  DispatcherEvent, DownstreamBidiEvent, DownstreamBidiStream, DownstreamUniRecvStream,
  DownstreamUniSendStream, H3BidiStream, H3DatagramReader, H3DatagramSender, H3OpenStreams,
  H3ServerConnection,
};

pub(super) struct DownstreamWebTransportConnection {
  conn: Arc<StdMutex<H3ServerConnection>>,
  opener: StdMutex<H3OpenStreams>,
}

impl DownstreamWebTransportConnection {
  fn connection_guard(&self) -> anyhow::Result<MutexGuard<'_, H3ServerConnection>> {
    self
      .conn
      .lock()
      .map_err(|_| anyhow::anyhow!("downstream HTTP/3 connection state is unavailable"))
  }

  fn opener_guard(&self) -> anyhow::Result<MutexGuard<'_, H3OpenStreams>> {
    self
      .opener
      .lock()
      .map_err(|_| anyhow::anyhow!("downstream HTTP/3 opener state is unavailable"))
  }

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
      let mut opener = match self.opener_guard() {
        Ok(opener) => opener,
        Err(error) => return Poll::Ready(Err(error)),
      };
      match opener.poll_open_bidi(cx) {
        Poll::Ready(result) => Poll::Ready(result.map_err(downstream_stream_error)),
        Poll::Pending => Poll::Pending,
      }
    })
    .await?;
    let mut stream = BufRecvStream::new(stream);
    send_webtransport_header(&mut stream, BidiStreamHeader::WebTransportBidi(session_id)).await?;
    Ok(stream)
  }

  pub(super) async fn open_uni(
    &self,
    session_id: SessionId,
  ) -> anyhow::Result<DownstreamUniSendStream> {
    let stream = poll_fn(|cx| {
      let mut opener = match self.opener_guard() {
        Ok(opener) => opener,
        Err(error) => return Poll::Ready(Err(error)),
      };
      match opener.poll_open_send(cx) {
        Poll::Ready(result) => Poll::Ready(result.map_err(downstream_stream_error)),
        Poll::Pending => Poll::Pending,
      }
    })
    .await?;
    let mut stream = BufRecvStream::new(stream);
    send_webtransport_header(&mut stream, UniStreamHeader::WebTransportUni(session_id)).await?;
    Ok(stream)
  }

  pub(super) fn datagram_reader(&self) -> anyhow::Result<H3DatagramReader> {
    Ok(self.connection_guard()?.get_datagram_reader())
  }

  pub(super) fn datagram_sender(&self, stream_id: StreamId) -> anyhow::Result<H3DatagramSender> {
    Ok(self.connection_guard()?.get_datagram_sender(stream_id))
  }
}

pub(super) fn spawn_downstream_reader_tasks(
  downstream: Arc<DownstreamWebTransportConnection>,
  events: mpsc::Sender<DispatcherEvent>,
) -> Vec<JoinHandle<()>> {
  vec![
    tokio::spawn(read_downstream_streams_task(
      downstream.clone(),
      events.clone(),
    )),
    tokio::spawn(read_downstream_datagrams_task(downstream, events)),
  ]
}

async fn read_downstream_streams_task(
  downstream: Arc<DownstreamWebTransportConnection>,
  events: mpsc::Sender<DispatcherEvent>,
) {
  let mut resolvers = JoinSet::new();
  loop {
    tokio::select! {
      biased;
      resolved = resolvers.join_next(), if !resolvers.is_empty() => {
        let result = match resolved {
          Some(Ok(result)) => result,
          Some(Err(error)) => Err(error.into()),
          None => continue,
        };
        match result {
          Ok(event) => {
            if !send_downstream_bidi_event(&events, event).await {
              return;
            }
          }
          Err(error) => {
            let _ = events.send(DispatcherEvent::Fatal(error)).await;
            return;
          }
        }
      }
      accepted = accept_downstream_stream(&downstream) => {
        match accepted {
          Ok(AcceptedDownstreamStream::Bidi(stream)) => {
            let downstream = downstream.clone();
            resolvers.spawn(async move { resolve_downstream_bidi(&downstream, stream).await });
          }
          Ok(AcceptedDownstreamStream::Uni(session_id, stream)) => {
            if events
              .send(DispatcherEvent::DownstreamUni(session_id, stream))
              .await
              .is_err()
            {
              return;
            }
          }
          Ok(AcceptedDownstreamStream::ConnectionClosed) => {
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
  }
}

async fn send_downstream_bidi_event(
  events: &mpsc::Sender<DispatcherEvent>,
  event: DownstreamBidiEvent,
) -> bool {
  let event = match event {
    DownstreamBidiEvent::WebTransport(session_id, stream) => {
      DispatcherEvent::DownstreamBidi(session_id, stream)
    }
    DownstreamBidiEvent::Request(request, stream) => {
      DispatcherEvent::DownstreamRequest(request, stream)
    }
    DownstreamBidiEvent::Closed => return true,
  };
  events.send(event).await.is_ok()
}

enum AcceptedDownstreamStream<U = DownstreamUniRecvStream, B = H3BidiStream> {
  Bidi(B),
  Uni(SessionId, U),
  ConnectionClosed,
}

trait DownstreamStreamSource {
  type Uni;
  type Bidi;

  fn pop_uni(&mut self) -> Option<(SessionId, Self::Uni)>;
  fn poll_bidi(
    &mut self,
    context: &mut std::task::Context<'_>,
  ) -> Poll<anyhow::Result<Option<Self::Bidi>>>;
}

impl DownstreamStreamSource for H3ServerConnection {
  type Uni = DownstreamUniRecvStream;
  type Bidi = H3BidiStream;

  fn pop_uni(&mut self) -> Option<(SessionId, Self::Uni)> {
    self.inner.accepted_streams_mut().wt_uni_streams.pop()
  }

  fn poll_bidi(
    &mut self,
    context: &mut std::task::Context<'_>,
  ) -> Poll<anyhow::Result<Option<Self::Bidi>>> {
    match self.poll_accept_request_stream(context) {
      Poll::Ready(result) => {
        Poll::Ready(result.context("failed to accept downstream HTTP/3 bidirectional stream"))
      }
      Poll::Pending => Poll::Pending,
    }
  }
}

fn poll_downstream_stream<S>(
  source: &mut S,
  context: &mut std::task::Context<'_>,
) -> Poll<anyhow::Result<AcceptedDownstreamStream<S::Uni, S::Bidi>>>
where
  S: DownstreamStreamSource,
{
  if let Some((session_id, stream)) = source.pop_uni() {
    return Poll::Ready(Ok(AcceptedDownstreamStream::Uni(session_id, stream)));
  }
  match source.poll_bidi(context) {
    Poll::Ready(Ok(Some(stream))) => Poll::Ready(Ok(AcceptedDownstreamStream::Bidi(stream))),
    Poll::Ready(Ok(None)) => Poll::Ready(Ok(AcceptedDownstreamStream::ConnectionClosed)),
    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
    Poll::Pending => match source.pop_uni() {
      Some((session_id, stream)) => {
        Poll::Ready(Ok(AcceptedDownstreamStream::Uni(session_id, stream)))
      }
      None => Poll::Pending,
    },
  }
}

async fn accept_downstream_stream(
  downstream: &DownstreamWebTransportConnection,
) -> anyhow::Result<AcceptedDownstreamStream> {
  poll_fn(|context| {
    let mut connection = match downstream.connection_guard() {
      Ok(connection) => connection,
      Err(error) => return Poll::Ready(Err(error)),
    };
    poll_downstream_stream(&mut *connection, context)
  })
  .await
}

async fn resolve_downstream_bidi(
  downstream: &DownstreamWebTransportConnection,
  stream: H3BidiStream,
) -> anyhow::Result<DownstreamBidiEvent> {
  let stream = FrameStream::new(BufRecvStream::new(stream));
  let mut resolver = { downstream.connection_guard()?.create_resolver(stream) };
  let frame = poll_fn(|cx| resolver.frame_stream.poll_next(cx)).await;

  match frame {
    Ok(Some(Frame::WebTransportStream(session_id))) => Ok(DownstreamBidiEvent::WebTransport(
      session_id,
      resolver.frame_stream.into_inner(),
    )),
    Ok(None) => Ok(DownstreamBidiEvent::Closed),
    Err(error) if first_frame_stream_terminated(&error) => Ok(DownstreamBidiEvent::Closed),
    frame => {
      let (request, stream) = resolver
        .accept_with_frame(frame)
        .context("failed to accept downstream HTTP/3 request frame")?
        .resolve()
        .await
        .context("failed to resolve downstream HTTP/3 request")?;
      Ok(DownstreamBidiEvent::Request(request, Box::new(stream)))
    }
  }
}

fn first_frame_stream_terminated(error: &FrameStreamError) -> bool {
  matches!(
    error,
    FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated { .. })
  )
}

async fn read_downstream_datagrams_task(
  downstream: Arc<DownstreamWebTransportConnection>,
  events: mpsc::Sender<DispatcherEvent>,
) {
  let mut reader = match downstream.datagram_reader() {
    Ok(reader) => reader,
    Err(error) => {
      let _ = events.send(DispatcherEvent::Fatal(error)).await;
      return;
    }
  };
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

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;
  use std::task::{Context, Poll};

  use futures_util::task::noop_waker_ref;
  use h3::frame::{FrameProtocolError, FrameStreamError};
  use h3::quic::{ConnectionErrorIncoming, StreamErrorIncoming};
  use h3_webtransport::SessionId;

  use super::{
    AcceptedDownstreamStream, DownstreamStreamSource, first_frame_stream_terminated,
    poll_downstream_stream,
  };

  struct UniQueuedByBidiPoll {
    uni: VecDeque<(SessionId, &'static str)>,
    bidi_polls: usize,
  }

  impl DownstreamStreamSource for UniQueuedByBidiPoll {
    type Uni = &'static str;
    type Bidi = ();

    fn pop_uni(&mut self) -> Option<(SessionId, Self::Uni)> {
      self.uni.pop_front()
    }

    fn poll_bidi(&mut self, _: &mut Context<'_>) -> Poll<anyhow::Result<Option<Self::Bidi>>> {
      self.bidi_polls += 1;
      self.uni.push_back((SessionId::try_from(4).unwrap(), "uni"));
      Poll::Pending
    }
  }

  #[test]
  fn uni_queued_while_polling_bidi_does_not_need_another_wake() {
    let mut source = UniQueuedByBidiPoll {
      uni: VecDeque::new(),
      bidi_polls: 0,
    };
    let mut context = Context::from_waker(noop_waker_ref());

    match poll_downstream_stream(&mut source, &mut context) {
      Poll::Ready(Ok(AcceptedDownstreamStream::Uni(session_id, "uni"))) => {
        assert_eq!(session_id, SessionId::try_from(4).unwrap());
      }
      _ => panic!("uni stream queued by bidi polling remained asleep"),
    }
    assert_eq!(source.bidi_polls, 1);
    assert!(source.uni.is_empty());
  }

  #[test]
  fn reset_before_first_frame_is_stream_scoped() {
    assert!(first_frame_stream_terminated(&FrameStreamError::Quic(
      StreamErrorIncoming::StreamTerminated { error_code: 42 },
    )));
    assert!(!first_frame_stream_terminated(&FrameStreamError::Quic(
      StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: ConnectionErrorIncoming::InternalError("connection lost".into()),
      },
    )));
    assert!(!first_frame_stream_terminated(&FrameStreamError::Proto(
      FrameProtocolError::Malformed
    ),));
    assert!(!first_frame_stream_terminated(
      &FrameStreamError::UnexpectedEnd,
    ));
  }
}
