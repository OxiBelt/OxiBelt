//! Session lifetime, credit ledgers, and bounded application-facing handles.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use bytes::{Bytes, BytesMut};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::budget::{Budget, Reservation};
use super::codec::{self, invalid};
use super::streams::{RecvStream, SendStream};
use crate::config::H2WebTransportConfig;

#[path = "driver.rs"]
mod driver;
#[path = "protocol.rs"]
mod protocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
  Client,
  Server,
}

impl Role {
  pub(super) const fn bit(self) -> u64 {
    match self {
      Self::Client => 0,
      Self::Server => 1,
    }
  }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SessionOptions {
  pub(crate) role: Role,
  pub(crate) limits: H2WebTransportConfig,
  pub(crate) outbound_auxiliary_bytes: usize,
  pub(crate) receive_application: bool,
  pub(crate) peer_stream_limits: Option<[u64; 3]>,
}

impl SessionOptions {
  pub(crate) fn proxy(limits: H2WebTransportConfig, role: Role) -> Self {
    Self {
      role,
      limits,
      outbound_auxiliary_bytes: 0,
      receive_application: true,
      peer_stream_limits: None,
    }
  }

  #[cfg(any(feature = "admin-runtime", test))]
  pub(crate) fn admin(per_session: usize, total: usize) -> Self {
    // The producer has one serializer buffer and at most two chunks outside
    // the carrier queue. Keep all three inside the configured per-session
    // allocation, leaving the remainder for the typed carrier payload.
    let chunk = (per_session.min(16 * 1024) / 8).max(1);
    let auxiliary = chunk.saturating_mul(3);
    let payload = per_session.saturating_sub(auxiliary);
    Self {
      role: Role::Server,
      limits: H2WebTransportConfig {
        max_concurrent_uni_streams: 1,
        max_concurrent_bidi_streams: 0,
        max_stream_buffer_bytes: payload,
        max_session_buffer_bytes: payload,
        max_total_buffer_bytes: total,
      },
      outbound_auxiliary_bytes: auxiliary,
      receive_application: false,
      peer_stream_limits: None,
    }
  }

  #[cfg(any(feature = "admin-runtime", test))]
  pub(crate) const fn outbound_chunk_bytes(self) -> usize {
    self.outbound_auxiliary_bytes / 3
  }
}

#[derive(Clone)]
pub(crate) struct Session {
  pub(super) shared: Arc<Shared>,
}

pub(super) struct Shared {
  pub(super) state: Mutex<State>,
  pub(super) changed: Notify,
  pub(super) output: Notify,
  _reservation: Reservation,
}

pub(super) struct State {
  pub(super) options: SessionOptions,
  pub(super) streams: HashMap<u64, StreamState>,
  pub(super) accepted: [VecDeque<u64>; 2],
  pub(super) peer_opened: [u64; 2],
  pub(super) own_opened: [u64; 2],
  pub(super) peer_active: [u64; 2],
  pub(super) own_active: [u64; 2],
  pub(super) receive_max_streams: [u64; 2],
  pub(super) send_max_streams: [u64; 2],
  pub(super) initial_send_stream: [u64; 3],
  pub(super) initial_receive_stream: [u64; 3],
  pub(super) send_max_data: u64,
  pub(super) sent: u64,
  pub(super) receive_max_data: u64,
  pub(super) received: u64,
  pub(super) consumed: u64,
  pub(super) queued_send: usize,
  pub(super) controls: VecDeque<Bytes>,
  pub(super) send_datagram: Option<Bytes>,
  pub(super) receive_datagram: Option<Bytes>,
  pub(super) ready_streams: VecDeque<u64>,
  pub(super) pending_output: Option<PendingStreamOutput>,
  pub(super) closing: Option<Bytes>,
  pub(super) finish: bool,
  pub(super) failure: Option<Failure>,
  pub(super) ended: bool,
  pub(super) remote_close: Option<(u32, Bytes)>,
  pub(super) draining: bool,
  pub(super) receive_grant_pending: bool,
  pub(super) streams_grant_pending: [bool; 2],
}

pub(super) struct PendingStreamOutput {
  pub(super) id: u64,
  pub(super) bytes: Bytes,
  pub(super) fin: bool,
}

pub(super) struct StreamState {
  pub(super) input: VecDeque<Bytes>,
  pub(super) input_staging: BytesMut,
  pub(super) input_bytes: usize,
  pub(super) output: VecDeque<Bytes>,
  pub(super) output_staging: BytesMut,
  pub(super) output_bytes: usize,
  pub(super) received: u64,
  pub(super) consumed: u64,
  pub(super) sent: u64,
  pub(super) wire_sent: u64,
  pub(super) receive_max: u64,
  pub(super) send_max: u64,
  pub(super) receive_fin: bool,
  pub(super) receive_reset: Option<u32>,
  pub(super) send_fin: bool,
  pub(super) fin_requested: bool,
  pub(super) reset_requested: Option<u32>,
  pub(super) send_reset: Option<u32>,
  pub(super) stop_sent: bool,
  pub(super) stop_received: bool,
  pub(super) stop_code: Option<u32>,
  pub(super) ready: bool,
  pub(super) opened_on_wire: bool,
  pub(super) read_handle: bool,
  pub(super) write_handle: bool,
  pub(super) read_waker: Option<Waker>,
  pub(super) write_waker: Option<Waker>,
  pub(super) grant_pending: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Failure {
  pub(super) reset: u32,
  pub(super) message: &'static str,
}

impl Failure {
  pub(super) const fn state(message: &'static str) -> Self {
    Self { reset: 1, message }
  }
  pub(super) const fn flow(message: &'static str) -> Self {
    Self { reset: 3, message }
  }
  pub(super) const fn resource(message: &'static str) -> Self {
    Self { reset: 11, message }
  }
  pub(super) fn error(self) -> io::Error {
    invalid(self.message)
  }
}

impl Shared {
  pub(super) fn lock(&self) -> io::Result<MutexGuard<'_, State>> {
    self
      .state
      .lock()
      .map_err(|_| io::Error::other("WebTransport session state poisoned"))
  }

  pub(super) fn wake(&self) {
    self.changed.notify_waiters();
    self.output.notify_one();
  }

  pub(super) fn fail(&self, failure: Failure) {
    if let Ok(mut state) = self.lock() {
      if state.failure.is_none() {
        state.failure = Some(failure);
      }
      state.wake_streams();
    }
    self.wake();
  }
}

impl State {
  pub(super) fn check(&self) -> io::Result<()> {
    if let Some(failure) = self.failure {
      return Err(failure.error());
    }
    if self.ended || self.finish || self.closing.is_some() {
      return Err(io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "WebTransport session closed",
      ));
    }
    Ok(())
  }

  pub(super) fn wake_streams(&mut self) {
    for stream in self.streams.values_mut() {
      if let Some(waker) = stream.read_waker.take() {
        waker.wake();
      }
      if let Some(waker) = stream.write_waker.take() {
        waker.wake();
      }
    }
  }

  pub(super) fn queue_control(&mut self, kind: u64, values: &[u64]) -> Result<(), Failure> {
    if self.controls.len() >= 256 {
      return Err(Failure::resource("WebTransport control queue full"));
    }
    self.controls.push_back(
      codec::control(kind, values).map_err(|_| Failure::state("invalid control integer"))?,
    );
    Ok(())
  }

  pub(super) fn ready(&mut self, id: u64) {
    if let Some(stream) = self.streams.get_mut(&id)
      && !stream.ready
    {
      stream.ready = true;
      self.ready_streams.push_back(id);
    }
  }

  pub(super) fn new_stream(&self, id: u64, local: bool) -> StreamState {
    let uni = id & 2 != 0;
    let send_index = if uni {
      0
    } else if local {
      2
    } else {
      1
    };
    let receive_index = if uni {
      0
    } else if local {
      1
    } else {
      2
    };
    StreamState {
      input: VecDeque::new(),
      input_staging: BytesMut::new(),
      input_bytes: 0,
      output: VecDeque::new(),
      output_staging: BytesMut::new(),
      output_bytes: 0,
      received: 0,
      consumed: 0,
      sent: 0,
      wire_sent: 0,
      receive_max: self.initial_receive_stream[receive_index],
      send_max: self.initial_send_stream[send_index],
      receive_fin: uni && local,
      receive_reset: None,
      send_fin: uni && !local,
      fin_requested: false,
      reset_requested: None,
      send_reset: None,
      stop_sent: false,
      stop_received: false,
      stop_code: None,
      ready: false,
      opened_on_wire: !local,
      read_handle: !uni || !local,
      write_handle: !uni || local,
      read_waker: None,
      write_waker: None,
      grant_pending: false,
    }
  }

  pub(super) fn reap(&mut self, id: u64) -> Result<(), Failure> {
    let done = self.streams.get(&id).is_some_and(|stream| {
      (stream.receive_fin || stream.receive_reset.is_some())
        && (stream.send_fin || stream.send_reset.is_some())
        && !stream.read_handle
        && !stream.write_handle
    });
    if !done {
      return Ok(());
    }
    self.streams.remove(&id);
    let kind = ((id & 2) >> 1) as usize;
    if id & 1 == self.options.role.bit() {
      self.own_active[kind] = self.own_active[kind].saturating_sub(1);
    } else {
      self.peer_active[kind] = self.peer_active[kind].saturating_sub(1);
      self.receive_max_streams[kind] = self.receive_max_streams[kind]
        .checked_add(1)
        .filter(|value| *value <= (1 << 60))
        .ok_or_else(|| Failure::flow("stream credit overflow"))?;
      self.streams_grant_pending[kind] = true;
    }
    Ok(())
  }
}

impl Session {
  /// Reserve the configured session capacity before sending a successful CONNECT.
  pub(crate) fn reserve(options: SessionOptions, budget: Arc<Budget>) -> io::Result<Reservation> {
    if !options.receive_application {
      // Admin budgets name the outbound queue only. Fixed parser and control
      // overhead is separately bounded by the shared Admin session semaphore.
      return budget.reserve(
        options
          .limits
          .max_session_buffer_bytes
          .saturating_add(options.outbound_auxiliary_bytes),
        options.limits.max_total_buffer_bytes,
      );
    }
    let reserved = options
      .limits
      .session_reservation_bytes()
      .ok_or_else(|| invalid("session allocation overflow"))?;
    budget.reserve(reserved, options.limits.max_total_buffer_bytes)
  }

  pub(crate) fn start(
    carrier: hyper::ext::WebTransportSession,
    options: SessionOptions,
    budget: Arc<Budget>,
  ) -> io::Result<(Self, JoinHandle<io::Result<()>>)> {
    let reservation = Self::reserve(options, budget)?;
    Self::start_reserved(carrier, options, reservation)
  }

  pub(crate) fn start_reserved(
    carrier: hyper::ext::WebTransportSession,
    options: SessionOptions,
    reservation: Reservation,
  ) -> io::Result<(Self, JoinHandle<io::Result<()>>)> {
    let peer = carrier
      .peer_settings()
      .ok_or_else(|| invalid("missing peer WebTransport settings"))?;
    let local = carrier
      .local_settings()
      .ok_or_else(|| invalid("missing local WebTransport settings"))?;
    // SETTINGS_WT_ENABLED advertises server support. Clients can omit it;
    // their flow-control SETTINGS still apply to the server's send direction.
    let server_enabled = match options.role {
      Role::Client => peer.enabled,
      Role::Server => local.enabled,
    };
    if !server_enabled {
      return Err(invalid("server WebTransport SETTINGS are not enabled"));
    }
    let receive_max_data = if options.receive_application {
      options.limits.max_session_buffer_bytes as u64
    } else {
      0
    };
    let receive_max_streams = if options.receive_application {
      [
        u64::from(options.limits.max_concurrent_bidi_streams),
        u64::from(options.limits.max_concurrent_uni_streams),
      ]
    } else {
      [0, 0]
    };
    let initial_receive_stream = [
      u64::from(local.initial_max_stream_data_uni.unwrap_or(0)),
      u64::from(local.initial_max_stream_data_bidi_local.unwrap_or(0)),
      u64::from(local.initial_max_stream_data_bidi_remote.unwrap_or(0)),
    ];
    if u64::from(local.initial_max_data.unwrap_or(0)) > receive_max_data
      || u64::from(local.initial_max_streams_bidi.unwrap_or(0)) > receive_max_streams[0]
      || u64::from(local.initial_max_streams_uni.unwrap_or(0)) > receive_max_streams[1]
      || initial_receive_stream
        .iter()
        .any(|n| *n > options.limits.max_stream_buffer_bytes as u64)
    {
      return Err(invalid(
        "advertised WebTransport credit exceeds reservation",
      ));
    }
    let mut initial_send_stream = [
      u64::from(peer.initial_max_stream_data_uni.unwrap_or(0)),
      u64::from(peer.initial_max_stream_data_bidi_local.unwrap_or(0)),
      u64::from(peer.initial_max_stream_data_bidi_remote.unwrap_or(0)),
    ];
    if let Some(values) = options.peer_stream_limits {
      for (current, header) in initial_send_stream.iter_mut().zip(values) {
        *current = (*current).max(header);
      }
    }
    let mut state = State {
      options,
      streams: HashMap::new(),
      accepted: [VecDeque::new(), VecDeque::new()],
      peer_opened: [0, 0],
      own_opened: [0, 0],
      peer_active: [0, 0],
      own_active: [0, 0],
      receive_max_streams,
      send_max_streams: [
        u64::from(peer.initial_max_streams_bidi.unwrap_or(0)),
        u64::from(peer.initial_max_streams_uni.unwrap_or(0)),
      ],
      initial_send_stream,
      initial_receive_stream,
      send_max_data: u64::from(peer.initial_max_data.unwrap_or(0)),
      sent: 0,
      receive_max_data,
      received: 0,
      consumed: 0,
      queued_send: 0,
      controls: VecDeque::new(),
      send_datagram: None,
      receive_datagram: None,
      ready_streams: VecDeque::new(),
      pending_output: None,
      closing: None,
      finish: false,
      failure: None,
      ended: false,
      remote_close: None,
      draining: false,
      receive_grant_pending: false,
      streams_grant_pending: [false, false],
    };
    for (kind, value) in [
      (codec::MAX_DATA, receive_max_data),
      (codec::MAX_STREAMS_BIDI, receive_max_streams[0]),
      (codec::MAX_STREAMS_UNI, receive_max_streams[1]),
    ] {
      if value > 0 {
        state
          .queue_control(kind, &[value])
          .map_err(Failure::error)?;
      }
    }
    let shared = Arc::new(Shared {
      state: Mutex::new(state),
      changed: Notify::new(),
      output: Notify::new(),
      _reservation: reservation,
    });
    let session = Self {
      shared: shared.clone(),
    };
    let task = tokio::spawn(driver::run(carrier, shared));
    Ok((session, task))
  }

  async fn open(&self, uni: bool) -> io::Result<(u64, bool)> {
    loop {
      let notified = self.shared.changed.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      {
        let mut state = self.shared.lock()?;
        state.check()?;
        let kind = usize::from(uni);
        let cap = if uni {
          state.options.limits.max_concurrent_uni_streams
        } else {
          state.options.limits.max_concurrent_bidi_streams
        };
        if state.own_opened[kind] < state.send_max_streams[kind]
          && state.own_active[kind] < u64::from(cap)
        {
          let id = state.own_opened[kind]
            .checked_mul(4)
            .and_then(|n| n.checked_add(state.options.role.bit() + if uni { 2 } else { 0 }))
            .filter(|n| *n <= codec::VARINT_MAX)
            .ok_or_else(|| invalid("stream ID overflow"))?;
          state.own_opened[kind] += 1;
          state.own_active[kind] += 1;
          let mut stream = state.new_stream(id, true);
          // With zero initial stream-data SETTINGS, a locally opened bidi
          // stream has no peer capsule that can trigger its reverse receive
          // credit. Queue it with the opener so the peer can send on its
          // existing half after receiving MAX_STREAMS.
          if !uni {
            stream.grant_pending = true;
          }
          state.streams.insert(id, stream);
          state.ready(id);
          drop(state);
          self.shared.wake();
          return Ok((id, uni));
        }
      }
      notified.await;
    }
  }

  pub(crate) async fn open_uni(&self) -> io::Result<SendStream> {
    let (id, _) = self.open(true).await?;
    Ok(SendStream::new(self.shared.clone(), id))
  }

  pub(crate) async fn open_bi(&self) -> io::Result<(SendStream, RecvStream)> {
    let (id, _) = self.open(false).await?;
    Ok((
      SendStream::new(self.shared.clone(), id),
      RecvStream::new(self.shared.clone(), id),
    ))
  }

  async fn accept(&self, uni: bool) -> io::Result<u64> {
    loop {
      let notified = self.shared.changed.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      {
        let mut state = self.shared.lock()?;
        state.check()?;
        if let Some(id) = state.accepted[usize::from(uni)].pop_front() {
          return Ok(id);
        }
      }
      notified.await;
    }
  }

  pub(crate) async fn accept_uni(&self) -> io::Result<RecvStream> {
    Ok(RecvStream::new(
      self.shared.clone(),
      self.accept(true).await?,
    ))
  }

  pub(crate) async fn accept_bi(&self) -> io::Result<(SendStream, RecvStream)> {
    let id = self.accept(false).await?;
    Ok((
      SendStream::new(self.shared.clone(), id),
      RecvStream::new(self.shared.clone(), id),
    ))
  }

  pub(crate) fn send_datagram(&self, payload: Bytes) -> io::Result<()> {
    if payload.len() > codec::MAX_DATAGRAM {
      return Err(invalid("WebTransport datagram too large"));
    }
    let mut state = self.shared.lock()?;
    state.check()?;
    if state.send_datagram.is_none() {
      state.send_datagram = Some(payload);
    }
    drop(state);
    self.shared.wake();
    Ok(())
  }

  pub(crate) async fn read_datagram(&self) -> io::Result<Bytes> {
    loop {
      let notified = self.shared.changed.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      {
        let mut state = self.shared.lock()?;
        state.check()?;
        if let Some(bytes) = state.receive_datagram.take() {
          return Ok(bytes);
        }
      }
      notified.await;
    }
  }

  pub(crate) fn close(&self, code: u32, reason: &[u8]) {
    let Ok(close) = codec::close(code, reason) else {
      self.silent_close();
      return;
    };
    if let Ok(mut state) = self.shared.lock()
      && !state.ended
      && state.closing.is_none()
    {
      state.closing = Some(close);
      state.wake_streams();
    }
    self.shared.wake();
  }

  pub(crate) fn silent_close(&self) {
    self.shared.fail(Failure {
      reset: 8,
      message: "WebTransport session cancelled",
    });
  }

  pub(crate) fn drain(&self) {
    if let Ok(mut state) = self.shared.lock()
      && !state.draining
    {
      state.draining = true;
      if let Err(error) = state.queue_control(codec::DRAIN_SESSION, &[]) {
        state.failure = Some(error);
      }
    }
    self.shared.wake();
  }

  pub(crate) async fn closed(&self) -> io::Result<(u32, Bytes)> {
    loop {
      let notified = self.shared.changed.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      {
        let state = self.shared.lock()?;
        if let Some(close) = &state.remote_close {
          return Ok(close.clone());
        }
        if let Some(error) = state.failure {
          return Err(error.error());
        }
        if state.ended {
          return Ok((0, Bytes::new()));
        }
      }
      notified.await;
    }
  }
}

pub(super) fn pending(waker: &mut Option<Waker>, cx: &Context<'_>) -> Poll<io::Result<usize>> {
  if waker.as_ref().is_none_or(|old| !old.will_wake(cx.waker())) {
    *waker = Some(cx.waker().clone());
  }
  Poll::Pending
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn staging_blocks_are_reserved_for_both_peers() {
    let options = SessionOptions::proxy(H2WebTransportConfig::default(), Role::Client);
    assert_eq!(options.limits.session_reservation_bytes(), Some(12_533_760));
    let budget = Budget::new();
    let reservations = (0..5)
      .map(|_| Session::reserve(options, budget.clone()).unwrap())
      .collect::<Vec<_>>();
    assert!(Session::reserve(options, budget.clone()).is_err());
    drop(reservations);
    assert_eq!(budget.used(), 0);
  }

  #[test]
  fn admin_partitions_the_configured_total_between_queue_and_producer() {
    let options = SessionOptions::admin(64 * 1024, 64 * 1024);
    assert_eq!(options.outbound_chunk_bytes(), 2 * 1024);
    assert_eq!(options.outbound_auxiliary_bytes, 6 * 1024);
    assert_eq!(options.limits.max_session_buffer_bytes, 58 * 1024);
    let budget = Budget::new();
    let reservation = Session::reserve(options, budget.clone()).unwrap();
    assert_eq!(budget.used(), 64 * 1024);
    drop(reservation);
    assert_eq!(budget.used(), 0);
  }
}
