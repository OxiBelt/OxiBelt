//! Independent carrier reader/writer futures keep control traffic live under backpressure.

use std::future::poll_fn;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use hyper::ext::{WebTransportReceive, WebTransportReset, WebTransportSend, WebTransportSession};

use super::{Failure, Shared, State};
use crate::webtransport::codec::{self, Decoder};

pub(super) async fn run(carrier: WebTransportSession, shared: Arc<Shared>) -> io::Result<()> {
  let (receive, send) = carrier.split();
  let reader = read(receive, shared.clone());
  let writer = async {
    let result = write(send, shared.clone()).await;
    if result.is_err() {
      shared.fail(Failure {
        reset: 2,
        message: "WebTransport carrier writer failed",
      });
    }
    result
  };
  // Both futures must finish: the reader reports errors through shared state so the
  // writer can emit the chosen reset, and clean receive EOF still closes our send side.
  let (read_result, write_result) = tokio::join!(reader, writer);
  if let Ok(mut state) = shared.lock() {
    state.ended = true;
    state.wake_streams();
  }
  shared.wake();
  read_result.and(write_result)
}

async fn read(mut receive: WebTransportReceive, shared: Arc<Shared>) -> io::Result<()> {
  let mut decoder = Decoder::default();
  let result = async {
    loop {
      let changed = shared.changed.notified();
      tokio::pin!(changed);
      changed.as_mut().enable();
      {
        let state = shared.lock()?;
        if state.failure.is_some() || state.ended {
          return Ok(());
        }
      }
      let data = tokio::select! {
        data = poll_fn(|cx| receive.poll_data(cx)) => data,
        _ = changed => { continue; }
      };
      let Some(data) = data else {
        decoder.finish()?;
        let mut state = shared.lock()?;
        state.finish = true;
        state.wake_streams();
        drop(state);
        shared.wake();
        return Ok(());
      };
      let mut data = data.map_err(io::Error::other)?;
      loop {
        let before = data.len();
        let event = decoder.next(&mut data)?;
        // Every byte is now copied into reserved application storage, retained in
        // the bounded decoder, or discarded. Releasing H2 credit cannot exceed it.
        let consumed = before - data.len();
        receive
          .release_capacity(consumed)
          .map_err(io::Error::other)?;
        let Some(event) = event else {
          break;
        };
        {
          let mut state = shared.lock()?;
          // Our CLOSE_SESSION can race with capsules the peer queued before
          // observing it. Keep draining the bounded carrier receive window
          // until the peer ends its HTTP/2 direction, without interpreting
          // those obsolete capsules against terminal session state. A close
          // initiated by the peer still rejects capsules that follow it.
          if !(state.finish && state.remote_close.is_none())
            && let Err(failure) = state.receive(event)
          {
            state.failure = Some(failure);
            state.wake_streams();
            drop(state);
            shared.wake();
            return Err(failure.error());
          }
        }
        shared.wake();
        // Bound one receive turn even for a single DATA frame full of capsules.
        tokio::task::yield_now().await;
      }
    }
  }
  .await;
  if result.is_err() {
    shared.fail(Failure::state(
      "invalid or interrupted WebTransport capsule stream",
    ));
  }
  result
}

fn reset_reason(code: u32) -> WebTransportReset {
  match code {
    3 => WebTransportReset::FlowControlError,
    8 => WebTransportReset::Cancel,
    11 => WebTransportReset::EnhanceYourCalm,
    2 => WebTransportReset::InternalError,
    _ => WebTransportReset::ProtocolError,
  }
}

async fn write(mut send: WebTransportSend, shared: Arc<Shared>) -> io::Result<()> {
  loop {
    let notified = shared.output.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let next = {
      let mut state = shared.lock()?;
      if let Some(failure) = state.failure {
        let _ = send.reset(reset_reason(failure.reset));
        state.ended = true;
        state.wake_streams();
        drop(state);
        shared.wake();
        return Err(failure.error());
      }
      state.next_output()
    };
    let next = match next {
      Ok(next) => next,
      Err(error) => {
        shared.fail(error);
        continue;
      }
    };
    match next {
      Some(Output::Close(bytes)) => {
        // A local CLOSE_SESSION must reach the carrier before the orderly
        // END_STREAM. `finish` rejects new writes after the close is scheduled,
        // so it must not cancel this capsule.
        loop {
          let changed = shared.changed.notified();
          tokio::pin!(changed);
          changed.as_mut().enable();
          let preempt = {
            let state = shared.lock()?;
            state.failure.is_some() || state.ended
          };
          if preempt {
            break;
          }
          let ready = tokio::select! {
            result = poll_fn(|cx| send.poll_ready(cx)) => Some(result),
            _ = changed => None,
          };
          if let Some(result) = ready {
            result.map_err(io::Error::other)?;
            send.send_data(bytes).map_err(io::Error::other)?;
            break;
          }
        }
      }
      Some(Output::Finish) => {
        // FIN follows queued data, so it uses the bounded payload queue. A
        // failure observed while waiting must return to the outer loop, where
        // the out-of-band reset path preempts the blocked payload.
        loop {
          let changed = shared.changed.notified();
          tokio::pin!(changed);
          changed.as_mut().enable();
          let preempt = {
            let state = shared.lock()?;
            state.failure.is_some() || state.ended
          };
          if preempt {
            break;
          }
          let ready = tokio::select! {
            result = poll_fn(|cx| send.poll_ready(cx)) => Some(result),
            _ = changed => None,
          };
          if let Some(result) = ready {
            result.map_err(io::Error::other)?;
            send.finish().map_err(io::Error::other)?;
            return Ok(());
          }
        }
      }
      Some(Output::Bytes { bytes, stream }) => {
        // Poll the independent send task while still allowing cancellation to win.
        loop {
          let changed = shared.changed.notified();
          tokio::pin!(changed);
          changed.as_mut().enable();
          let preempt = {
            let state = shared.lock()?;
            state.output_is_cancelled(stream)
          };
          if preempt {
            let mut state = shared.lock()?;
            state.discard_pending_output();
            break;
          }
          let ready = tokio::select! {
            result = poll_fn(|cx| send.poll_ready(cx)) => Some(result),
            _ = changed => None,
          };
          if let Some(result) = ready {
            if let Err(error) = result {
              shared.fail(Failure {
                reset: 2,
                message: "WebTransport carrier send failed",
              });
              return Err(io::Error::other(error));
            }
            // Readiness can race with RESET/STOP on another task. Keep the
            // final cancellation check, synchronous enqueue, and accounting
            // receipt under one lock so cancellation cannot rewind bytes that
            // subsequently enter the carrier.
            let mut state = shared.lock()?;
            if state.output_is_cancelled(stream) {
              state.discard_pending_output();
              break;
            }
            send.send_data(bytes).map_err(io::Error::other)?;
            if let Some((id, fin)) = stream {
              state
                .commit_pending_output(id, fin)
                .map_err(Failure::error)?;
            }
            drop(state);
            shared.wake();
            break;
          }
        }
      }
      None => notified.await,
    }
  }
}

enum Output {
  Close(Bytes),
  Bytes {
    bytes: Bytes,
    stream: Option<(u64, bool)>,
  },
  Finish,
}

impl State {
  fn output_is_cancelled(&self, stream: Option<(u64, bool)>) -> bool {
    self.failure.is_some()
      || self.finish
      || self.ended
      || stream.is_some_and(|(id, _)| {
        self.streams.get(&id).is_none_or(|stream| {
          stream.reset_requested.is_some() || stream.send_reset.is_some() || stream.stop_received
        })
      })
  }

  fn next_output(&mut self) -> Result<Option<Output>, Failure> {
    if self.pending_output.is_some() {
      return Err(Failure::state(
        "WebTransport stream output was not committed",
      ));
    }
    if self.finish {
      return Ok(Some(Output::Finish));
    }
    if let Some(bytes) = self.controls.pop_front() {
      return Ok(Some(Output::Bytes {
        bytes,
        stream: None,
      }));
    }
    if self.receive_grant_pending {
      self.receive_grant_pending = false;
      let next = self
        .consumed
        .checked_add(self.options.limits.max_session_buffer_bytes as u64)
        .filter(|n| *n <= codec::VARINT_MAX)
        .ok_or_else(|| Failure::flow("receive credit overflow"))?;
      if self.options.receive_application && next > self.receive_max_data {
        self.receive_max_data = next;
        return codec::control(codec::MAX_DATA, &[next])
          .map(|bytes| {
            Some(Output::Bytes {
              bytes,
              stream: None,
            })
          })
          .map_err(|_| Failure::flow("invalid receive credit"));
      }
    }
    for (index, kind) in [(0, codec::MAX_STREAMS_BIDI), (1, codec::MAX_STREAMS_UNI)] {
      if self.streams_grant_pending[index] {
        self.streams_grant_pending[index] = false;
        return codec::control(kind, &[self.receive_max_streams[index]])
          .map(|bytes| {
            Some(Output::Bytes {
              bytes,
              stream: None,
            })
          })
          .map_err(|_| Failure::flow("invalid stream credit"));
      }
    }
    while let Some((&id, stream)) = self
      .streams
      .iter_mut()
      .find(|(_, stream)| stream.grant_pending)
    {
      stream.grant_pending = false;
      if !stream.stop_sent && !stream.receive_fin && stream.receive_reset.is_none() {
        let next = stream
          .consumed
          .checked_add(self.options.limits.max_stream_buffer_bytes as u64)
          .filter(|n| *n <= codec::VARINT_MAX)
          .ok_or_else(|| Failure::flow("receive stream credit overflow"))?;
        if next > stream.receive_max {
          stream.receive_max = next;
          return codec::control(codec::MAX_STREAM_DATA, &[id, next])
            .map(|bytes| {
              Some(Output::Bytes {
                bytes,
                stream: None,
              })
            })
            .map_err(|_| Failure::flow("invalid receive stream credit"));
        }
      }
    }
    // One datagram slot, followed by round-robin stream payloads. The writer
    // checks controls again between every bounded payload capsule.
    if let Some(payload) = self.send_datagram.take() {
      return codec::encode(codec::DATAGRAM, &payload)
        .map(|bytes| {
          Some(Output::Bytes {
            bytes,
            stream: None,
          })
        })
        .map_err(|_| Failure::state("invalid outgoing datagram"));
    }
    while let Some(id) = self.ready_streams.pop_front() {
      let Some(stream) = self.streams.get_mut(&id) else {
        continue;
      };
      stream.ready = false;
      if let Some(code) = stream.reset_requested.take() {
        stream.send_reset = Some(code);
        let bytes = codec::control(
          codec::RESET_STREAM,
          &[id, u64::from(code), stream.wire_sent],
        )
        .map_err(|_| Failure::state("invalid outgoing reset"))?;
        if let Some(waker) = stream.write_waker.take() {
          waker.wake();
        }
        self.reap(id)?;
        return Ok(Some(Output::Bytes {
          bytes,
          stream: None,
        }));
      }
      if stream.send_fin || stream.send_reset.is_some() {
        continue;
      }
      let bytes = stream.output.pop_front().or_else(|| {
        (!stream.output_staging.is_empty())
          .then(|| std::mem::take(&mut stream.output_staging).freeze())
      });
      if bytes.is_none() && stream.opened_on_wire && !stream.fin_requested {
        continue;
      }
      let bytes = bytes.unwrap_or_default();
      stream.opened_on_wire = true;
      let fin = stream.fin_requested && stream.output.is_empty();
      let payload =
        codec::stream(id, &bytes, fin).map_err(|_| Failure::state("invalid outgoing stream"))?;
      self.pending_output = Some(super::PendingStreamOutput { id, bytes, fin });
      return Ok(Some(Output::Bytes {
        bytes: payload,
        stream: Some((id, fin)),
      }));
    }
    // CLOSE_SESSION follows already accepted control and stream output. This
    // preserves a terminal event's STREAM_FIN and DRAIN_SESSION rather than
    // discarding either when the application closes the session.
    if let Some(close) = self.closing.take() {
      self.finish = true;
      return Ok(Some(Output::Close(close)));
    }
    Ok(None)
  }

  fn commit_pending_output(&mut self, id: u64, fin: bool) -> Result<(), Failure> {
    let pending = self
      .pending_output
      .take()
      .ok_or_else(|| Failure::state("missing stream output receipt"))?;
    if pending.id != id || pending.fin != fin {
      return Err(Failure::state("mismatched stream output receipt"));
    }
    let len = pending.bytes.len();
    let stream = self
      .streams
      .get_mut(&id)
      .ok_or_else(|| Failure::state("stream disappeared before output receipt"))?;
    stream.output_bytes = stream.output_bytes.saturating_sub(len);
    stream.wire_sent = stream.wire_sent.saturating_add(len as u64);
    self.queued_send = self.queued_send.saturating_sub(len);
    stream.send_fin = fin;
    let again = !stream.output.is_empty();
    if let Some(waker) = stream.write_waker.take() {
      waker.wake();
    }
    if again {
      self.ready(id);
    }
    self.wake_streams();
    self.reap(id)
  }

  fn discard_pending_output(&mut self) {
    let Some(pending) = self.pending_output.take() else {
      return;
    };
    let len = pending.bytes.len();
    let mut requeue_reset = false;
    let mut waker = None;
    if let Some(stream) = self.streams.get_mut(&pending.id) {
      requeue_reset = stream.reset_requested.is_some();
      // RESET/STOP already discarded and refunded all buffered bytes,
      // including this selected capsule. Do not refund its payload twice.
      if !requeue_reset {
        stream.output_bytes = stream.output_bytes.saturating_sub(len);
        stream.sent = stream.sent.saturating_sub(len as u64);
        self.queued_send = self.queued_send.saturating_sub(len);
        self.sent = self.sent.saturating_sub(len as u64);
      }
      waker = stream.write_waker.take();
    }
    if requeue_reset {
      self.ready(pending.id);
    }
    if let Some(waker) = waker {
      waker.wake();
    }
  }
}
