//! Capsule state transitions. All counters are scoped to one CONNECT session.

use super::{Failure, State};
use crate::webtransport::codec::{self, Event};
use bytes::Bytes;

impl State {
  fn peer_stream(&mut self, id: u64) -> Result<bool, Failure> {
    if self.streams.contains_key(&id) {
      return Ok(false);
    }
    if id & 1 == self.options.role.bit() {
      return Err(Failure::state("peer referred to unopened local stream"));
    }
    let kind = ((id & 2) >> 1) as usize;
    let count = id / 4 + 1;
    if count <= self.peer_opened[kind] {
      return Err(Failure::state("peer reused a closed stream"));
    }
    if count > self.receive_max_streams[kind] {
      return Err(Failure::flow("peer exceeded stream count credit"));
    }
    let new = count - self.peer_opened[kind];
    let limit = if kind == 1 {
      self.options.limits.max_concurrent_uni_streams
    } else {
      self.options.limits.max_concurrent_bidi_streams
    };
    if !self.options.receive_application
      || self.peer_active[kind].saturating_add(new) > u64::from(limit)
    {
      return Err(Failure::flow("peer exceeded concurrent stream budget"));
    }
    // A higher ID implicitly opens lower IDs, but the checked active cap bounds this loop.
    for index in self.peer_opened[kind]..count {
      let stream_id = index * 4 + (1 - self.options.role.bit()) + (kind as u64 * 2);
      let mut stream = self.new_stream(stream_id, false);
      stream.grant_pending = true;
      self.streams.insert(stream_id, stream);
      self.accepted[kind].push_back(stream_id);
    }
    self.peer_opened[kind] = count;
    self.peer_active[kind] += new;
    Ok(true)
  }

  pub(super) fn receive(&mut self, event: Event) -> Result<(), Failure> {
    if self.finish || self.remote_close.is_some() {
      return Err(Failure::state("capsule after session close"));
    }
    match event {
      Event::Stream {
        id,
        data,
        fin,
        start: _,
      } => {
        self.peer_stream(id)?;
        let stream = self
          .streams
          .get_mut(&id)
          .ok_or_else(|| Failure::state("missing stream state"))?;
        if stream.receive_fin || stream.receive_reset.is_some() {
          return Err(Failure::state(
            "data after FIN/reset or on send-only stream",
          ));
        }
        let received = stream
          .received
          .checked_add(data.len() as u64)
          .filter(|value| *value <= stream.receive_max)
          .ok_or_else(|| Failure::flow("stream receive credit exceeded"))?;
        let total = self
          .received
          .checked_add(data.len() as u64)
          .filter(|value| *value <= self.receive_max_data)
          .ok_or_else(|| Failure::flow("session receive credit exceeded"))?;
        stream.received = received;
        self.received = total;
        if stream.stop_sent {
          stream.consumed += data.len() as u64;
          self.consumed += data.len() as u64;
          self.receive_grant_pending = true;
        } else if !data.is_empty() {
          if stream.input_bytes.saturating_add(data.len())
            > self.options.limits.max_stream_buffer_bytes
          {
            return Err(Failure::flow("stream receive storage exhausted"));
          }
          stream.input_bytes += data.len();
          // Copy out of the HTTP/2 DATA frame so a tiny slice cannot retain a large frame.
          // Coalescing prevents one-byte capsules from becoming one deque node
          // and allocation apiece.
          if stream.input_staging.len() + data.len() > codec::QUANTUM {
            stream
              .input
              .push_back(std::mem::take(&mut stream.input_staging).freeze());
          }
          stream.input_staging.extend_from_slice(&data);
          if stream.input_staging.len() == codec::QUANTUM {
            stream
              .input
              .push_back(std::mem::take(&mut stream.input_staging).freeze());
          }
        }
        if fin {
          stream.receive_fin = true;
          stream.grant_pending = false;
        }
        if let Some(waker) = stream.read_waker.take() {
          waker.wake();
        }
        self.reap(id)?;
      }
      Event::Datagram(data) => {
        if self.options.receive_application && self.receive_datagram.is_none() {
          self.receive_datagram = Some(data);
        }
      }
      Event::Close { code, reason } => {
        self.remote_close = Some((code, Bytes::from(reason)));
        self.finish = true;
        self.wake_streams();
      }
      Event::Drain => {
        self.draining = true;
      }
      Event::Control { kind, values } => self.control_received(kind, &values)?,
    }
    Ok(())
  }

  fn control_received(&mut self, kind: u64, values: &[u64]) -> Result<(), Failure> {
    match kind {
      codec::MAX_DATA => {
        if values[0] < self.send_max_data {
          return Err(Failure::flow("decreasing session send credit"));
        }
        self.send_max_data = values[0];
        self.wake_streams();
      }
      codec::MAX_STREAMS_BIDI | codec::MAX_STREAMS_UNI => {
        let index = usize::from(kind == codec::MAX_STREAMS_UNI);
        if values[0] < self.send_max_streams[index] || values[0] > (1 << 60) {
          return Err(Failure::flow("invalid cumulative stream credit"));
        }
        self.send_max_streams[index] = values[0];
      }
      codec::RESET_STREAM => {
        let id = values[0];
        self.peer_stream(id)?;
        let code = u32::try_from(values[1])
          .map_err(|_| Failure::state("application reset code exceeds u32"))?;
        let stream = self
          .streams
          .get_mut(&id)
          .ok_or_else(|| Failure::state("reset unknown stream"))?;
        if stream.receive_fin || stream.receive_reset.is_some() || stream.received != values[2] {
          return Err(Failure::state(
            "invalid stream reset state or reliable size",
          ));
        }
        stream.receive_reset = Some(code);
        stream.grant_pending = false;
        if let Some(waker) = stream.read_waker.take() {
          waker.wake();
        }
        self.reap(id)?;
      }
      codec::STOP_SENDING => {
        let id = values[0];
        self.peer_stream(id)?;
        let code = u32::try_from(values[1])
          .map_err(|_| Failure::state("application stop code exceeds u32"))?;
        let stream = self
          .streams
          .get_mut(&id)
          .ok_or_else(|| Failure::state("stop unknown stream"))?;
        if stream.stop_received || (id & 2 != 0 && id & 1 != self.options.role.bit()) {
          return Err(Failure::state(
            "duplicate stop or stop on receive-only stream",
          ));
        }
        stream.stop_received = true;
        stream.stop_code = Some(code);
        if let Some(waker) = stream.write_waker.take() {
          waker.wake();
        }
        if !stream.send_fin && stream.send_reset.is_none() {
          let discarded = stream.output_bytes;
          stream.output.clear();
          stream.output_staging = Default::default();
          stream.output_bytes = 0;
          stream.sent = stream.wire_sent;
          stream.reset_requested = Some(code);
          self.queued_send -= discarded;
          self.sent -= discarded as u64;
          self.ready(id);
          self.wake_streams();
        }
      }
      codec::MAX_STREAM_DATA => {
        let id = values[0];
        if id & 2 != 0 && id & 1 != self.options.role.bit() {
          return Err(Failure::state("credit for receive-only stream"));
        }
        let kind = ((id & 2) >> 1) as usize;
        let opened = if id & 1 == self.options.role.bit() {
          self.own_opened[kind]
        } else {
          self.peer_opened[kind]
        };
        if !self.streams.contains_key(&id) && id / 4 < opened {
          // The opposite direction can still carry credit sent before our
          // FIN/RESET reached the peer. Draft-15 section 5.2 enters QUIC's
          // terminal states immediately; terminal send streams ignore this
          // obsolete credit (RFC 9000 section 3.1). Do not resurrect state or
          // retain an unbounded history of completed streams.
          return Ok(());
        }
        self.peer_stream(id)?;
        let stream = self
          .streams
          .get_mut(&id)
          .ok_or_else(|| Failure::state("credit for unknown stream"))?;
        if stream.stop_received || (id & 2 != 0 && id & 1 != self.options.role.bit()) {
          return Err(Failure::state("credit for stopped/receive-only stream"));
        }
        if values[1] < stream.send_max {
          return Err(Failure::flow("decreasing stream credit"));
        }
        stream.send_max = values[1];
        if let Some(waker) = stream.write_waker.take() {
          waker.wake();
        }
      }
      codec::STREAM_DATA_BLOCKED => {
        let id = values[0];
        self.peer_stream(id)?;
        let stream = self
          .streams
          .get(&id)
          .ok_or_else(|| Failure::state("blocked unknown stream"))?;
        if stream.receive_fin || stream.receive_reset.is_some() {
          return Err(Failure::state("blocked signal after FIN/reset"));
        }
      }
      codec::STREAMS_BLOCKED_BIDI | codec::STREAMS_BLOCKED_UNI => {
        if values[0] > (1 << 60) {
          return Err(Failure::flow("invalid blocked stream count"));
        }
      }
      codec::DATA_BLOCKED => {}
      _ => return Err(Failure::state("unexpected control capsule")),
    }
    Ok(())
  }
}
