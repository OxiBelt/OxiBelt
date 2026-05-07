use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{self, Poll, ready};

use bytes::{Buf, Bytes};
use futures_util::stream::{self, Stream, StreamExt};
use h3::error::Code;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use h3_datagram::datagram::EncodedDatagram;
use h3_datagram::quic_traits::{
  DatagramConnectionExt, RecvDatagram, SendDatagram, SendDatagramErrorIncoming,
};
use h3_quinn::quinn::{self, ReadDatagram, ReadError, SendDatagramError, VarInt};
use tokio_util::sync::ReusableBoxFuture;

type BoxStreamSync<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + Sync + 'a>>;

#[derive(Clone, Default)]
pub(crate) struct EarlyDataTracker {
  stream_ids: Arc<Mutex<HashSet<StreamId>>>,
}

impl EarlyDataTracker {
  fn note(&self, stream_id: StreamId, is_0rtt: bool) {
    if is_0rtt {
      self
        .stream_ids
        .lock()
        .expect("HTTP/3 early-data tracker lock poisoned")
        .insert(stream_id);
    }
  }

  pub(crate) fn take(&self, stream_id: StreamId) -> bool {
    self
      .stream_ids
      .lock()
      .expect("HTTP/3 early-data tracker lock poisoned")
      .remove(&stream_id)
  }
}

pub(crate) struct Connection {
  conn: quinn::Connection,
  early_data: EarlyDataTracker,
  incoming_bi: BoxStreamSync<'static, <quinn::AcceptBi<'static> as Future>::Output>,
  opening_bi: Option<BoxStreamSync<'static, <quinn::OpenBi<'static> as Future>::Output>>,
  incoming_uni: BoxStreamSync<'static, <quinn::AcceptUni<'static> as Future>::Output>,
  opening_uni: Option<BoxStreamSync<'static, <quinn::OpenUni<'static> as Future>::Output>>,
}

impl Connection {
  pub(crate) fn new(conn: quinn::Connection, early_data: EarlyDataTracker) -> Self {
    Self {
      conn: conn.clone(),
      early_data,
      incoming_bi: Box::pin(stream::unfold(conn.clone(), |conn| async {
        Some((conn.accept_bi().await, conn))
      })),
      opening_bi: None,
      incoming_uni: Box::pin(stream::unfold(conn.clone(), |conn| async {
        Some((conn.accept_uni().await, conn))
      })),
      opening_uni: None,
    }
  }
}

impl<B> quic::Connection<B> for Connection
where
  B: Buf,
{
  type RecvStream = RecvStream;
  type OpenStreams = OpenStreams;

  fn poll_accept_bidi(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
    let (send, recv) = ready!(self.incoming_bi.poll_next_unpin(cx))
      .expect("incoming bidirectional stream source never ends")
      .map_err(convert_connection_error)?;
    self
      .early_data
      .note(h3_stream_id(recv.id()), recv.is_0rtt());
    Poll::Ready(Ok(BidiStream {
      send: SendStream::new(send),
      recv: RecvStream::new(recv),
    }))
  }

  fn poll_accept_recv(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
    let recv = ready!(self.incoming_uni.poll_next_unpin(cx))
      .expect("incoming unidirectional stream source never ends")
      .map_err(convert_connection_error)?;
    Poll::Ready(Ok(RecvStream::new(recv)))
  }

  fn opener(&self) -> Self::OpenStreams {
    OpenStreams {
      conn: self.conn.clone(),
      opening_bi: None,
      opening_uni: None,
    }
  }
}

impl<B> quic::OpenStreams<B> for Connection
where
  B: Buf,
{
  type SendStream = SendStream<B>;
  type BidiStream = BidiStream<B>;

  fn poll_open_bidi(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
    let bi = self.opening_bi.get_or_insert_with(|| {
      Box::pin(stream::unfold(self.conn.clone(), |conn| async {
        Some((conn.open_bi().await, conn))
      }))
    });
    let (send, recv) = ready!(bi.poll_next_unpin(cx))
      .expect("open bidi source never ends")
      .map_err(connection_error_as_stream_error)?;
    Poll::Ready(Ok(BidiStream {
      send: SendStream::new(send),
      recv: RecvStream::new(recv),
    }))
  }

  fn poll_open_send(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
    let uni = self.opening_uni.get_or_insert_with(|| {
      Box::pin(stream::unfold(self.conn.clone(), |conn| async {
        Some((conn.open_uni().await, conn))
      }))
    });
    let send = ready!(uni.poll_next_unpin(cx))
      .expect("open uni source never ends")
      .map_err(connection_error_as_stream_error)?;
    Poll::Ready(Ok(SendStream::new(send)))
  }

  fn close(&mut self, code: Code, reason: &[u8]) {
    self.conn.close(
      VarInt::from_u64(code.value()).expect("HTTP/3 error code fits QUIC varint"),
      reason,
    );
  }
}

pub(crate) struct OpenStreams {
  conn: quinn::Connection,
  opening_bi: Option<BoxStreamSync<'static, <quinn::OpenBi<'static> as Future>::Output>>,
  opening_uni: Option<BoxStreamSync<'static, <quinn::OpenUni<'static> as Future>::Output>>,
}

impl<B> quic::OpenStreams<B> for OpenStreams
where
  B: Buf,
{
  type SendStream = SendStream<B>;
  type BidiStream = BidiStream<B>;

  fn poll_open_bidi(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
    let bi = self.opening_bi.get_or_insert_with(|| {
      Box::pin(stream::unfold(self.conn.clone(), |conn| async {
        Some((conn.open_bi().await, conn))
      }))
    });
    let (send, recv) = ready!(bi.poll_next_unpin(cx))
      .expect("open bidi source never ends")
      .map_err(connection_error_as_stream_error)?;
    Poll::Ready(Ok(BidiStream {
      send: SendStream::new(send),
      recv: RecvStream::new(recv),
    }))
  }

  fn poll_open_send(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
    let uni = self.opening_uni.get_or_insert_with(|| {
      Box::pin(stream::unfold(self.conn.clone(), |conn| async {
        Some((conn.open_uni().await, conn))
      }))
    });
    let send = ready!(uni.poll_next_unpin(cx))
      .expect("open uni source never ends")
      .map_err(connection_error_as_stream_error)?;
    Poll::Ready(Ok(SendStream::new(send)))
  }

  fn close(&mut self, code: Code, reason: &[u8]) {
    self.conn.close(
      VarInt::from_u64(code.value()).expect("HTTP/3 error code fits QUIC varint"),
      reason,
    );
  }
}

impl Clone for OpenStreams {
  fn clone(&self) -> Self {
    Self {
      conn: self.conn.clone(),
      opening_bi: None,
      opening_uni: None,
    }
  }
}

pub(crate) struct BidiStream<B>
where
  B: Buf,
{
  send: SendStream<B>,
  recv: RecvStream,
}

impl<B> quic::BidiStream<B> for BidiStream<B>
where
  B: Buf,
{
  type SendStream = SendStream<B>;
  type RecvStream = RecvStream;

  fn split(self) -> (Self::SendStream, Self::RecvStream) {
    (self.send, self.recv)
  }
}

impl<B> quic::RecvStream for BidiStream<B>
where
  B: Buf,
{
  type Buf = Bytes;

  fn poll_data(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
    self.recv.poll_data(cx)
  }

  fn stop_sending(&mut self, error_code: u64) {
    self.recv.stop_sending(error_code);
  }

  fn recv_id(&self) -> StreamId {
    self.recv.recv_id()
  }
}

impl<B> quic::SendStream<B> for BidiStream<B>
where
  B: Buf,
{
  fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
    self.send.poll_ready(cx)
  }

  fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
    self.send.poll_finish(cx)
  }

  fn reset(&mut self, reset_code: u64) {
    self.send.reset(reset_code);
  }

  fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
    self.send.send_data(data)
  }

  fn send_id(&self) -> StreamId {
    self.send.send_id()
  }
}

impl<B> quic::SendStreamUnframed<B> for BidiStream<B>
where
  B: Buf,
{
  fn poll_send<D: Buf>(
    &mut self,
    cx: &mut task::Context<'_>,
    buf: &mut D,
  ) -> Poll<Result<usize, StreamErrorIncoming>> {
    self.send.poll_send(cx, buf)
  }
}

pub(crate) struct RecvStream {
  stream: Option<quinn::RecvStream>,
  read_chunk_fut: ReadChunkFuture,
}

type ReadChunkFuture = ReusableBoxFuture<
  'static,
  (
    quinn::RecvStream,
    Result<Option<quinn::Chunk>, quinn::ReadError>,
  ),
>;

impl RecvStream {
  fn new(stream: quinn::RecvStream) -> Self {
    Self {
      stream: Some(stream),
      read_chunk_fut: ReusableBoxFuture::new(async { unreachable!() }),
    }
  }
}

impl quic::RecvStream for RecvStream {
  type Buf = Bytes;

  fn poll_data(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
    if let Some(mut stream) = self.stream.take() {
      self.read_chunk_fut.set(async move {
        let chunk = stream.read_chunk(usize::MAX, true).await;
        (stream, chunk)
      });
    }

    let (stream, chunk) = ready!(self.read_chunk_fut.poll(cx));
    self.stream = Some(stream);
    Poll::Ready(Ok(
      chunk
        .map_err(convert_read_error_to_stream_error)?
        .map(|chunk| chunk.bytes),
    ))
  }

  fn stop_sending(&mut self, error_code: u64) {
    if let Some(stream) = self.stream.as_mut() {
      let _ = stream.stop(VarInt::from_u64(error_code).expect("invalid HTTP/3 error code"));
    }
  }

  fn recv_id(&self) -> StreamId {
    h3_stream_id(
      self
        .stream
        .as_ref()
        .expect("receive stream exists while polling HTTP/3")
        .id(),
    )
  }
}

pub(crate) struct SendStream<B: Buf> {
  stream: quinn::SendStream,
  writing: Option<WriteBuf<B>>,
}

impl<B> SendStream<B>
where
  B: Buf,
{
  fn new(stream: quinn::SendStream) -> Self {
    Self {
      stream,
      writing: None,
    }
  }
}

impl<B> quic::SendStream<B> for SendStream<B>
where
  B: Buf,
{
  fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
    if let Some(data) = self.writing.as_mut() {
      while data.has_remaining() {
        let stream = Pin::new(&mut self.stream);
        let written = ready!(stream.poll_write(cx, data.chunk()))
          .map_err(convert_write_error_to_stream_error)?;
        data.advance(written);
      }
    }
    self.writing = None;
    Poll::Ready(Ok(()))
  }

  fn poll_finish(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
    Poll::Ready(
      self
        .stream
        .finish()
        .map_err(|error| StreamErrorIncoming::Unknown(Box::new(error))),
    )
  }

  fn reset(&mut self, reset_code: u64) {
    let _ = self
      .stream
      .reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::MAX));
  }

  fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
    if self.writing.is_some() {
      return Err(StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: ConnectionErrorIncoming::InternalError(
          "HTTP/3 send stream was written before becoming ready".to_string(),
        ),
      });
    }
    self.writing = Some(data.into());
    Ok(())
  }

  fn send_id(&self) -> StreamId {
    h3_stream_id(self.stream.id())
  }
}

impl<B> quic::SendStreamUnframed<B> for SendStream<B>
where
  B: Buf,
{
  fn poll_send<D: Buf>(
    &mut self,
    cx: &mut task::Context<'_>,
    buf: &mut D,
  ) -> Poll<Result<usize, StreamErrorIncoming>> {
    let stream = Pin::new(&mut self.stream);
    let written =
      ready!(stream.poll_write(cx, buf.chunk())).map_err(convert_write_error_to_stream_error)?;
    buf.advance(written);
    Poll::Ready(Ok(written))
  }
}

pub(crate) struct SendDatagramHandler {
  conn: quinn::Connection,
}

impl<B: Buf> SendDatagram<B> for SendDatagramHandler {
  fn send_datagram<T: Into<EncodedDatagram<B>>>(
    &mut self,
    data: T,
  ) -> Result<(), SendDatagramErrorIncoming> {
    let mut buf: EncodedDatagram<B> = data.into();
    self
      .conn
      .send_datagram(buf.copy_to_bytes(buf.remaining()))
      .map_err(convert_send_datagram_error)
  }
}

pub(crate) struct RecvDatagramHandler {
  datagrams: BoxStreamSync<'static, <ReadDatagram<'static> as Future>::Output>,
}

impl RecvDatagram for RecvDatagramHandler {
  type Buffer = Bytes;

  fn poll_incoming_datagram(
    &mut self,
    cx: &mut task::Context<'_>,
  ) -> Poll<Result<Self::Buffer, h3_datagram::ConnectionErrorIncoming>> {
    Poll::Ready(
      ready!(self.datagrams.poll_next_unpin(cx))
        .expect("incoming datagram source never ends")
        .map_err(convert_connection_error_to_datagram_error),
    )
  }
}

impl<B: Buf> DatagramConnectionExt<B> for Connection {
  type SendDatagramHandler = SendDatagramHandler;
  type RecvDatagramHandler = RecvDatagramHandler;

  fn send_datagram_handler(&self) -> Self::SendDatagramHandler {
    SendDatagramHandler {
      conn: self.conn.clone(),
    }
  }

  fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler {
    RecvDatagramHandler {
      datagrams: Box::pin(stream::unfold(self.conn.clone(), |conn| async {
        Some((conn.read_datagram().await, conn))
      })),
    }
  }
}

fn h3_stream_id(id: quinn::StreamId) -> StreamId {
  let id: u64 = id.into();
  id.try_into().expect("QUIC stream ID fits HTTP/3 stream ID")
}

fn connection_error_as_stream_error(error: quinn::ConnectionError) -> StreamErrorIncoming {
  StreamErrorIncoming::ConnectionErrorIncoming {
    connection_error: convert_connection_error(error),
  }
}

fn convert_connection_error(error: quinn::ConnectionError) -> ConnectionErrorIncoming {
  match error {
    quinn::ConnectionError::ApplicationClosed(application_close) => {
      ConnectionErrorIncoming::ApplicationClose {
        error_code: application_close.error_code.into(),
      }
    }
    quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
    error => ConnectionErrorIncoming::Undefined(Arc::new(error)),
  }
}

fn convert_read_error_to_stream_error(error: ReadError) -> StreamErrorIncoming {
  match error {
    ReadError::Reset(error_code) => StreamErrorIncoming::StreamTerminated {
      error_code: error_code.into_inner(),
    },
    ReadError::ConnectionLost(error) => StreamErrorIncoming::ConnectionErrorIncoming {
      connection_error: convert_connection_error(error),
    },
    ReadError::IllegalOrderedRead => panic!("HTTP/3 performs ordered reads only"),
    error => StreamErrorIncoming::Unknown(Box::new(error)),
  }
}

fn convert_write_error_to_stream_error(error: quinn::WriteError) -> StreamErrorIncoming {
  match error {
    quinn::WriteError::Stopped(error_code) => StreamErrorIncoming::StreamTerminated {
      error_code: error_code.into_inner(),
    },
    quinn::WriteError::ConnectionLost(error) => StreamErrorIncoming::ConnectionErrorIncoming {
      connection_error: convert_connection_error(error),
    },
    error => StreamErrorIncoming::Unknown(Box::new(error)),
  }
}

fn convert_send_datagram_error(error: SendDatagramError) -> SendDatagramErrorIncoming {
  match error {
    SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
      SendDatagramErrorIncoming::NotAvailable
    }
    SendDatagramError::TooLarge => SendDatagramErrorIncoming::TooLarge,
    SendDatagramError::ConnectionLost(error) => {
      SendDatagramErrorIncoming::ConnectionError(convert_connection_error_to_datagram_error(error))
    }
  }
}

fn convert_connection_error_to_datagram_error(
  error: quinn::ConnectionError,
) -> h3_datagram::ConnectionErrorIncoming {
  convert_h3_connection_error_to_datagram_error(convert_connection_error(error))
}

fn convert_h3_connection_error_to_datagram_error(
  error: ConnectionErrorIncoming,
) -> h3_datagram::ConnectionErrorIncoming {
  match error {
    ConnectionErrorIncoming::ApplicationClose { error_code } => {
      h3_datagram::ConnectionErrorIncoming::ApplicationClose { error_code }
    }
    ConnectionErrorIncoming::Timeout => h3_datagram::ConnectionErrorIncoming::Timeout,
    ConnectionErrorIncoming::InternalError(error) => {
      h3_datagram::ConnectionErrorIncoming::InternalError(error)
    }
    ConnectionErrorIncoming::Undefined(error) => {
      h3_datagram::ConnectionErrorIncoming::Undefined(error)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn early_data_tracker_only_records_early_streams_once() {
    let tracker = EarlyDataTracker::default();
    let stream_id = StreamId::try_from(0).unwrap();

    tracker.note(stream_id, false);
    assert!(!tracker.take(stream_id));

    tracker.note(stream_id, true);
    assert!(tracker.take(stream_id));
    assert!(!tracker.take(stream_id));
  }
}
