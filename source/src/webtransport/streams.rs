//! Tokio I/O handles backed by a session's shared, bounded credit ledger.

use bytes::{Buf, Bytes};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::codec::{self, invalid};
use super::session::{Failure, Shared, pending};

pub(crate) struct SendStream {
  shared: Arc<Shared>,
  id: u64,
}

#[derive(Debug)]
pub(crate) struct StreamResetCode(pub(crate) u32);

impl std::fmt::Display for StreamResetCode {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(formatter, "WebTransport stream reset ({})", self.0)
  }
}

impl std::error::Error for StreamResetCode {}

pub(crate) fn stream_reset_code(error: &io::Error) -> Option<u32> {
  error
    .get_ref()
    .and_then(|cause| cause.downcast_ref::<StreamResetCode>())
    .map(|reset| reset.0)
}
pub(crate) struct RecvStream {
  shared: Arc<Shared>,
  id: u64,
}

impl SendStream {
  pub(super) fn new(shared: Arc<Shared>, id: u64) -> Self {
    Self { shared, id }
  }

  pub(crate) fn reset(&mut self, code: u32) -> io::Result<()> {
    let mut state = self.shared.lock()?;
    let Some(stream) = state.streams.get_mut(&self.id) else {
      return Ok(());
    };
    // The first reset owns its application code, including while it is queued.
    // Dropping this handle invokes cancellation and must not replace that code.
    if stream.send_fin || stream.send_reset.is_some() || stream.reset_requested.is_some() {
      return Ok(());
    }
    let discarded = stream.output_bytes;
    stream.output.clear();
    stream.output_staging = Default::default();
    stream.output_bytes = 0;
    stream.sent = stream.wire_sent;
    stream.reset_requested = Some(code);
    state.queued_send = state.queued_send.saturating_sub(discarded);
    state.sent = state.sent.saturating_sub(discarded as u64);
    state.ready(self.id);
    state.wake_streams();
    drop(state);
    self.shared.wake();
    Ok(())
  }

  /// Wait until the peer has sent STOP_SENDING for this virtual stream.
  ///
  /// A bridge must observe this even when its opposite receive half is idle;
  /// otherwise it cannot forward the STOP_SENDING and can retain the peer's
  /// receive credit indefinitely.
  pub(crate) fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<u32>> {
    let mut state = self.shared.lock()?;
    state.check()?;
    let stream = state
      .streams
      .get_mut(&self.id)
      .ok_or_else(|| invalid("unknown send stream"))?;
    if let Some(code) = stream.stop_code {
      return Poll::Ready(Ok(code));
    }
    if stream
      .write_waker
      .as_ref()
      .is_none_or(|waker| !waker.will_wake(cx.waker()))
    {
      stream.write_waker = Some(cx.waker().clone());
    }
    Poll::Pending
  }
}

impl AsyncWrite for SendStream {
  fn poll_write(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    bytes: &[u8],
  ) -> Poll<io::Result<usize>> {
    if bytes.is_empty() {
      return Poll::Ready(Ok(0));
    }
    let mut state = self.shared.lock()?;
    state.check()?;
    let available_session = state
      .options
      .limits
      .max_session_buffer_bytes
      .saturating_sub(state.queued_send);
    let session_credit = state.send_max_data.saturating_sub(state.sent);
    let stream_cap = state.options.limits.max_stream_buffer_bytes;
    let stream = state
      .streams
      .get_mut(&self.id)
      .ok_or_else(|| invalid("unknown send stream"))?;
    if stream.send_fin
      || stream.fin_requested
      || stream.send_reset.is_some()
      || stream.reset_requested.is_some()
    {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "WebTransport stream send side closed",
      )));
    }
    let block_space = codec::QUANTUM.saturating_sub(stream.output_staging.len());
    let size = bytes
      .len()
      .min(block_space)
      .min(stream_cap.saturating_sub(stream.output_bytes))
      .min(available_session)
      .min(session_credit.min(usize::MAX as u64) as usize)
      .min(
        stream
          .send_max
          .saturating_sub(stream.sent)
          .min(usize::MAX as u64) as usize,
      );
    if size == 0 {
      return pending(&mut stream.write_waker, cx);
    }
    stream.output_staging.extend_from_slice(&bytes[..size]);
    stream.output_bytes += size;
    stream.sent += size as u64;
    state.sent += size as u64;
    state.queued_send += size;
    state.ready(self.id);
    drop(state);
    self.shared.output.notify_one();
    Poll::Ready(Ok(size))
  }

  fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let mut state = self.shared.lock()?;
    state.check()?;
    let stream = state
      .streams
      .get_mut(&self.id)
      .ok_or_else(|| invalid("unknown send stream"))?;
    if stream.send_reset.is_some() || stream.reset_requested.is_some() {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "WebTransport stream reset",
      )));
    }
    if stream.output_bytes == 0 {
      return Poll::Ready(Ok(()));
    }
    pending(&mut stream.write_waker, cx).map_ok(|_| ())
  }

  fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let mut state = self.shared.lock()?;
    state.check()?;
    let stream = state
      .streams
      .get_mut(&self.id)
      .ok_or_else(|| invalid("unknown send stream"))?;
    if stream.send_fin {
      return Poll::Ready(Ok(()));
    }
    if stream.send_reset.is_some() || stream.reset_requested.is_some() {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        "WebTransport stream reset",
      )));
    }
    stream.fin_requested = true;
    let result = pending(&mut stream.write_waker, cx).map_ok(|_| ());
    state.ready(self.id);
    drop(state);
    self.shared.output.notify_one();
    result
  }
}

impl Drop for SendStream {
  fn drop(&mut self) {
    // Dropping an unfinished stream is an application cancellation, never a FIN.
    let _ = self.reset(0);
    if let Ok(mut state) = self.shared.lock() {
      if let Some(stream) = state.streams.get_mut(&self.id) {
        stream.write_handle = false;
      }
      if let Err(error) = state.reap(self.id) {
        state.failure = Some(error);
      }
    }
    self.shared.wake();
  }
}

impl RecvStream {
  pub(super) fn new(shared: Arc<Shared>, id: u64) -> Self {
    Self { shared, id }
  }
  #[cfg(test)]
  pub(crate) fn id(&self) -> u64 {
    self.id
  }

  /// The application reset code, if the peer reset this virtual stream.
  pub(crate) fn reset_code(&self) -> Option<u32> {
    self.shared.lock().ok().and_then(|state| {
      state
        .streams
        .get(&self.id)
        .and_then(|stream| stream.receive_reset)
    })
  }

  pub(crate) fn stop(&mut self, code: u32) -> io::Result<()> {
    let mut state = self.shared.lock()?;
    let Some(stream) = state.streams.get_mut(&self.id) else {
      return Ok(());
    };
    let discarded = stream.input_bytes;
    stream.input.clear();
    stream.input_staging = Default::default();
    stream.input_bytes = 0;
    stream.consumed += discarded as u64;
    let send_stop = !stream.receive_fin && stream.receive_reset.is_none() && !stream.stop_sent;
    if send_stop {
      stream.stop_sent = true;
    }
    stream.grant_pending = false;
    state.consumed += discarded as u64;
    state.receive_grant_pending |= discarded > 0;
    if send_stop {
      state
        .queue_control(codec::STOP_SENDING, &[self.id, u64::from(code)])
        .map_err(Failure::error)?;
    }
    drop(state);
    self.shared.wake();
    Ok(())
  }
}

impl AsyncRead for RecvStream {
  fn poll_read(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    if buffer.remaining() == 0 {
      return Poll::Ready(Ok(()));
    }
    let mut state = self.shared.lock()?;
    let failure = state.failure;
    let ended = state.ended || state.finish || state.closing.is_some();
    let stream = state
      .streams
      .get_mut(&self.id)
      .ok_or_else(|| invalid("unknown receive stream"))?;
    if !stream.input.is_empty() || !stream.input_staging.is_empty() {
      let (count, queued) = if let Some(bytes) = stream.input.front_mut() {
        let count = buffer.remaining().min(bytes.len());
        buffer.put_slice(&bytes[..count]);
        bytes.advance(count);
        (count, true)
      } else {
        let count = buffer.remaining().min(stream.input_staging.len());
        buffer.put_slice(&stream.input_staging[..count]);
        stream.input_staging.advance(count);
        (count, false)
      };
      if queued {
        if stream.input.front().is_some_and(Bytes::is_empty) {
          stream.input.pop_front();
        }
      } else if stream.input_staging.is_empty() {
        stream.input_staging = Default::default();
      }
      stream.input_bytes -= count;
      stream.consumed += count as u64;
      if !stream.stop_sent && !stream.receive_fin && stream.receive_reset.is_none() {
        stream.grant_pending = true;
      }
      state.consumed += count as u64;
      state.receive_grant_pending = true;
      drop(state);
      self.shared.output.notify_one();
      return Poll::Ready(Ok(()));
    }
    if let Some(code) = stream.receive_reset {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::ConnectionReset,
        StreamResetCode(code),
      )));
    }
    if stream.receive_fin {
      return Poll::Ready(Ok(()));
    }
    if let Some(error) = failure {
      return Poll::Ready(Err(error.error()));
    }
    if ended {
      return Poll::Ready(Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "WebTransport session ended before stream FIN",
      )));
    }
    pending(&mut stream.read_waker, cx).map_ok(|_| ())
  }
}

impl Drop for RecvStream {
  fn drop(&mut self) {
    let _ = self.stop(0);
    if let Ok(mut state) = self.shared.lock() {
      if let Some(stream) = state.streams.get_mut(&self.id) {
        stream.read_handle = false;
      }
      if let Err(error) = state.reap(self.id) {
        state.failure = Some(error);
      }
    }
    self.shared.wake();
  }
}
