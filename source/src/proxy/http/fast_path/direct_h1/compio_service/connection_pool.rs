//! Worker-local connections and owned buffer reuse.

use std::collections::HashMap;
use std::net::{Shutdown, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use compio_driver::SharedFd;
use socket2::Socket;

use crate::circuit_breakers::AdmissionLease;
use crate::metrics::Metrics;
use crate::metrics::compio_direct_h1::{
  CompioDirectH1BufferEvent, CompioDirectH1ConnectionEvent, CompioDirectH1ConnectionState,
};

use super::super::origin::DirectH1OriginIdentity;

const MAX_RETAINED_BUFFER_CAPACITY: usize = 64 * 1024;
const MAX_RETAINED_BUFFERS: usize = 64;
const MAX_RETAINED_BUFFERS_PER_DIRECTION: usize = MAX_RETAINED_BUFFERS / 2;
const MIN_RETAINED_RESPONSE_BUFFER_CAPACITY: usize = 512;
const MAX_RETAINED_RESPONSE_BUFFERS: usize = 32;

pub(super) struct GlobalConnectionBudget {
  limit: usize,
  open: AtomicUsize,
  origins: Mutex<HashMap<DirectH1OriginIdentity, Arc<OriginConnectionCounts>>>,
  metrics: Arc<Metrics>,
}

#[derive(Default)]
struct OriginConnectionCounts {
  open: AtomicUsize,
  idle: AtomicUsize,
}

impl GlobalConnectionBudget {
  pub(super) fn new(limit: usize, metrics: Arc<Metrics>) -> Self {
    Self {
      limit,
      open: AtomicUsize::new(0),
      origins: Mutex::new(HashMap::new()),
      metrics,
    }
  }

  fn try_acquire(
    self: &Arc<Self>,
    origin: &DirectH1OriginIdentity,
    max_connections_per_origin: usize,
  ) -> Option<GlobalConnectionPermit> {
    if self
      .open
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        if current >= self.limit {
          None
        } else {
          current.checked_add(1)
        }
      })
      .is_err()
    {
      return None;
    }

    let origin_counts = {
      let mut origins = match self.origins.lock() {
        Ok(origins) => origins,
        Err(_) => {
          self.release_global();
          return None;
        }
      };
      let origin_counts = Arc::clone(origins.entry(origin.clone()).or_default());
      if origin_counts
        .open
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
          if current >= max_connections_per_origin {
            None
          } else {
            current.checked_add(1)
          }
        })
        .is_err()
      {
        self.release_global();
        return None;
      }
      origin_counts
    };

    self.adjust_active(1);
    Some(GlobalConnectionPermit {
      budget: Arc::clone(self),
      origin: origin.clone(),
      origin_counts,
      state: PermitState::Active,
      expected_release: false,
    })
  }

  fn decrement(count: &AtomicUsize, invariant: &'static str) -> usize {
    match count.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
      current.checked_sub(1)
    }) {
      Ok(previous) => previous - 1,
      Err(_) => {
        debug_assert!(false, "{invariant}");
        0
      }
    }
  }

  fn remove_empty_origin(
    &self,
    origin: &DirectH1OriginIdentity,
    origin_counts: &Arc<OriginConnectionCounts>,
  ) {
    if origin_counts.open.load(Ordering::Acquire) != 0 {
      return;
    }
    let Ok(mut origins) = self.origins.lock() else {
      return;
    };
    if origins.get(origin).is_some_and(|current| {
      Arc::ptr_eq(current, origin_counts) && current.open.load(Ordering::Acquire) == 0
    }) {
      origins.remove(origin);
    }
  }

  fn release_global(&self) {
    Self::decrement(
      &self.open,
      "Compio direct-H1 global connection accounting underflowed",
    );
  }

  fn release(
    &self,
    origin: &DirectH1OriginIdentity,
    origin_counts: &Arc<OriginConnectionCounts>,
    idle: bool,
  ) {
    if idle {
      Self::decrement(
        &origin_counts.idle,
        "Compio direct-H1 shared idle connection accounting underflowed",
      );
    }
    let remaining = Self::decrement(
      &origin_counts.open,
      "Compio direct-H1 per-origin connection accounting underflowed",
    );
    self.release_global();
    if remaining == 0 {
      self.remove_empty_origin(origin, origin_counts);
    }
  }

  fn try_reserve_idle(&self, origin_counts: &OriginConnectionCounts, max_idle: usize) -> bool {
    if max_idle == 0 {
      return false;
    }
    origin_counts
      .idle
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        if current >= max_idle {
          None
        } else {
          current.checked_add(1)
        }
      })
      .is_ok()
  }

  fn release_idle(&self, origin_counts: &OriginConnectionCounts) {
    Self::decrement(
      &origin_counts.idle,
      "Compio direct-H1 shared idle connection accounting underflowed",
    );
  }

  #[cfg(test)]
  fn open_for_origin(&self, origin: &DirectH1OriginIdentity) -> usize {
    self
      .origins
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(origin)
      .map(|counts| counts.open.load(Ordering::Acquire))
      .unwrap_or(0)
  }

  #[cfg(test)]
  fn idle_for_origin(&self, origin: &DirectH1OriginIdentity) -> usize {
    self
      .origins
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .get(origin)
      .map(|counts| counts.idle.load(Ordering::Acquire))
      .unwrap_or(0)
  }

  #[cfg(test)]
  fn open(&self) -> usize {
    self.open.load(Ordering::Acquire)
  }

  fn adjust_active(&self, delta: isize) {
    self
      .metrics
      .adjust_compio_direct_h1_connection_count(CompioDirectH1ConnectionState::Active, delta);
  }

  fn adjust_idle(&self, delta: isize) {
    self
      .metrics
      .adjust_compio_direct_h1_connection_count(CompioDirectH1ConnectionState::Idle, delta);
  }
}

pub(super) struct GlobalConnectionPermit {
  budget: Arc<GlobalConnectionBudget>,
  origin: DirectH1OriginIdentity,
  origin_counts: Arc<OriginConnectionCounts>,
  state: PermitState,
  expected_release: bool,
}

#[derive(Clone, Copy)]
enum PermitState {
  Active,
  Idle,
}

impl GlobalConnectionPermit {
  fn mark_active(&mut self) {
    if matches!(self.state, PermitState::Idle) {
      self.budget.release_idle(&self.origin_counts);
      self.budget.adjust_idle(-1);
      self.budget.adjust_active(1);
      self.state = PermitState::Active;
    }
  }

  fn try_mark_idle(&mut self, max_idle: usize) -> bool {
    if matches!(self.state, PermitState::Idle) {
      return true;
    }
    if !self.budget.try_reserve_idle(&self.origin_counts, max_idle) {
      return false;
    }
    self.budget.adjust_active(-1);
    self.budget.adjust_idle(1);
    self.state = PermitState::Idle;
    true
  }

  fn mark_expected_release(&mut self) {
    self.expected_release = true;
  }
}

impl Drop for GlobalConnectionPermit {
  fn drop(&mut self) {
    match self.state {
      PermitState::Active => self.budget.adjust_active(-1),
      PermitState::Idle => self.budget.adjust_idle(-1),
    }
    if !self.expected_release {
      self
        .budget
        .metrics
        .record_compio_direct_h1_connection_event(
          CompioDirectH1ConnectionEvent::RetiredWorkerFailure,
        );
    }
    self.budget.release(
      &self.origin,
      &self.origin_counts,
      matches!(self.state, PermitState::Idle),
    );
  }
}

pub(super) struct WorkerConnection {
  pub(super) fd: SharedFd<Socket>,
  pub(super) _endpoint: SocketAddr,
  pub(super) created_at: Instant,
  pub(super) last_used_at: Instant,
  pub(super) request_count: u64,
  pub(super) generation: u64,
  pub(super) recv_socket_nonempty: Option<bool>,
  permit: GlobalConnectionPermit,
  _shared_admission: Option<AdmissionLease>,
}

impl WorkerConnection {
  pub(super) fn new(
    fd: SharedFd<Socket>,
    endpoint: SocketAddr,
    generation: u64,
    permit: GlobalConnectionPermit,
    shared_admission: Option<AdmissionLease>,
  ) -> Self {
    let now = Instant::now();
    Self {
      fd,
      _endpoint: endpoint,
      created_at: now,
      last_used_at: now,
      request_count: 0,
      generation,
      recv_socket_nonempty: None,
      permit,
      _shared_admission: shared_admission,
    }
  }

  fn shutdown(&self) {
    let _ = self.fd.shutdown(Shutdown::Both);
  }
}

pub(super) enum Checkout {
  Reused(WorkerConnection),
  Reserved(GlobalConnectionPermit),
  Limited,
}

pub(super) struct WorkerConnectionPool {
  generation: u64,
  max_connections_per_origin: usize,
  budget: Arc<GlobalConnectionBudget>,
  metrics: Arc<Metrics>,
  idle: HashMap<DirectH1OriginIdentity, Vec<WorkerConnection>>,
  response_buffers: Vec<BytesMut>,
  write_buffers: Vec<Vec<u8>>,
}

impl WorkerConnectionPool {
  pub(super) fn new(
    generation: u64,
    max_connections_per_origin: usize,
    budget: Arc<GlobalConnectionBudget>,
    metrics: Arc<Metrics>,
  ) -> Self {
    Self {
      generation,
      max_connections_per_origin,
      budget,
      metrics,
      idle: HashMap::new(),
      response_buffers: Vec::new(),
      write_buffers: Vec::new(),
    }
  }

  pub(super) fn generation(&self) -> u64 {
    self.generation
  }

  pub(super) fn checkout(
    &mut self,
    origin: &DirectH1OriginIdentity,
    idle_timeout: Duration,
    max_lifetime: Duration,
  ) -> Checkout {
    let now = Instant::now();
    while let Some(connection) = self.idle.get_mut(origin).and_then(Vec::pop) {
      let retirement = if connection.generation != self.generation {
        Some(CompioDirectH1ConnectionEvent::RetiredStaleGeneration)
      } else if now.duration_since(connection.created_at) > max_lifetime {
        Some(CompioDirectH1ConnectionEvent::RetiredAbsoluteLifetime)
      } else if now.duration_since(connection.last_used_at) > idle_timeout {
        Some(CompioDirectH1ConnectionEvent::RetiredIdleTimeout)
      } else {
        None
      };
      if let Some(event) = retirement {
        self.retire_idle(origin, connection, event);
        continue;
      }
      let mut connection = connection;
      connection.permit.mark_active();
      self
        .metrics
        .record_compio_direct_h1_connection_event(CompioDirectH1ConnectionEvent::Reused);
      return Checkout::Reused(connection);
    }
    if self.idle.get(origin).is_some_and(Vec::is_empty) {
      self.idle.remove(origin);
    }

    let Some(permit) = self
      .budget
      .try_acquire(origin, self.max_connections_per_origin)
    else {
      return Checkout::Limited;
    };
    Checkout::Reserved(permit)
  }

  pub(super) fn connect_failed(
    &mut self,
    _origin: &DirectH1OriginIdentity,
    mut permit: GlobalConnectionPermit,
  ) {
    // `compio_io::connect` returns cancellation/timeout only after the driver
    // has returned terminal FD ownership, so this permit cannot be recycled
    // while a physical connect still exists.
    permit.mark_expected_release();
    drop(permit);
  }

  pub(super) fn put_idle(
    &mut self,
    origin: &DirectH1OriginIdentity,
    mut connection: WorkerConnection,
    max_idle: usize,
  ) {
    if !connection.permit.try_mark_idle(max_idle) {
      self.retire_active(
        origin,
        connection,
        CompioDirectH1ConnectionEvent::RetiredPoolFull,
      );
      return;
    }
    connection.last_used_at = Instant::now();
    if let Some(connections) = self.idle.get_mut(origin) {
      connections.push(connection);
    } else {
      self.idle.insert(origin.clone(), vec![connection]);
    }
  }

  pub(super) fn retire_active(
    &mut self,
    _origin: &DirectH1OriginIdentity,
    mut connection: WorkerConnection,
    event: CompioDirectH1ConnectionEvent,
  ) {
    // Active send/receive callers reach retirement only after their Compio
    // submission has returned terminal FD and buffer ownership.
    connection.shutdown();
    connection.permit.mark_expected_release();
    self.metrics.record_compio_direct_h1_connection_event(event);
    drop(connection);
  }

  fn retire_idle(
    &mut self,
    _origin: &DirectH1OriginIdentity,
    mut connection: WorkerConnection,
    event: CompioDirectH1ConnectionEvent,
  ) {
    connection.shutdown();
    connection.permit.mark_expected_release();
    self.metrics.record_compio_direct_h1_connection_event(event);
    drop(connection);
  }

  pub(super) fn take_buffer(&mut self, minimum_capacity: usize) -> Vec<u8> {
    if let Some(index) = self
      .write_buffers
      .iter()
      .position(|buffer| buffer.capacity() >= minimum_capacity)
    {
      let mut buffer = self.write_buffers.swap_remove(index);
      buffer.clear();
      self
        .metrics
        .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Reuse);
      return buffer;
    }
    self
      .metrics
      .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Allocate);
    Vec::with_capacity(minimum_capacity)
  }

  pub(super) fn put_buffer(&mut self, mut buffer: Vec<u8>) {
    buffer.clear();
    if buffer.capacity() > MAX_RETAINED_BUFFER_CAPACITY
      || self.write_buffers.len() >= MAX_RETAINED_BUFFERS_PER_DIRECTION
    {
      self
        .metrics
        .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Discard);
      return;
    }
    self.write_buffers.push(buffer);
  }

  pub(super) fn take_response_buffer(&mut self, initial_capacity: usize) -> BytesMut {
    if let Some(mut buffer) = self.response_buffers.pop() {
      buffer.clear();
      self
        .metrics
        .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Reuse);
      return buffer;
    }
    self
      .metrics
      .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Allocate);
    BytesMut::with_capacity(initial_capacity)
  }

  pub(super) fn put_response_buffer(&mut self, mut buffer: BytesMut) {
    buffer.clear();
    if buffer.capacity() < MIN_RETAINED_RESPONSE_BUFFER_CAPACITY
      || buffer.capacity() > MAX_RETAINED_BUFFER_CAPACITY
      || self.response_buffers.len() >= MAX_RETAINED_RESPONSE_BUFFERS
    {
      self
        .metrics
        .record_compio_direct_h1_buffer_event(CompioDirectH1BufferEvent::Discard);
      return;
    }
    self.response_buffers.push(buffer);
  }

  pub(super) fn close_idle(&mut self) {
    let idle = std::mem::take(&mut self.idle);
    for (origin, connections) in idle {
      for connection in connections {
        self.retire_idle(
          &origin,
          connection,
          CompioDirectH1ConnectionEvent::ClosedShutdown,
        );
      }
    }
  }
}

impl Drop for WorkerConnectionPool {
  fn drop(&mut self) {
    self.close_idle();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Barrier;
  use std::thread;

  fn origin(host: &str) -> DirectH1OriginIdentity {
    DirectH1OriginIdentity {
      host: Arc::from(host),
      port: 18080,
    }
  }

  #[test]
  fn shared_budget_enforces_global_and_per_origin_connection_limits() {
    let budget = Arc::new(GlobalConnectionBudget::new(3, Metrics::new()));
    let first_origin = origin("first.example");
    let second_origin = origin("second.example");
    let mut first = budget
      .try_acquire(&first_origin, 2)
      .expect("first origin connection should be admitted");
    let mut second = budget
      .try_acquire(&first_origin, 2)
      .expect("second origin connection should be admitted");
    assert!(budget.try_acquire(&first_origin, 2).is_none());
    let mut third = budget
      .try_acquire(&second_origin, 2)
      .expect("another origin should use remaining global capacity");
    assert!(budget.try_acquire(&second_origin, 2).is_none());
    assert_eq!(budget.open(), 3);
    assert_eq!(budget.open_for_origin(&first_origin), 2);
    assert_eq!(budget.open_for_origin(&second_origin), 1);

    first.mark_expected_release();
    second.mark_expected_release();
    third.mark_expected_release();
    drop((first, second, third));
    assert_eq!(budget.open(), 0);
    assert_eq!(budget.open_for_origin(&first_origin), 0);
    assert_eq!(budget.open_for_origin(&second_origin), 0);
  }

  #[test]
  fn shared_budget_enforces_fleet_wide_idle_limit() {
    let budget = Arc::new(GlobalConnectionBudget::new(2, Metrics::new()));
    let origin = origin("idle.example");
    let mut first = budget
      .try_acquire(&origin, 2)
      .expect("first connection should be admitted");
    let mut second = budget
      .try_acquire(&origin, 2)
      .expect("second connection should be admitted");

    assert!(first.try_mark_idle(1));
    assert!(!second.try_mark_idle(1));
    assert_eq!(budget.idle_for_origin(&origin), 1);
    first.mark_active();
    assert_eq!(budget.idle_for_origin(&origin), 0);
    assert!(second.try_mark_idle(1));
    assert_eq!(budget.idle_for_origin(&origin), 1);

    first.mark_expected_release();
    second.mark_expected_release();
    drop((first, second));
    assert_eq!(budget.open(), 0);
    assert_eq!(budget.idle_for_origin(&origin), 0);
  }

  #[test]
  fn per_origin_limit_remains_exact_during_entry_cleanup_races() {
    let budget = Arc::new(GlobalConnectionBudget::new(32, Metrics::new()));
    let origin = origin("raced.example");
    let held = Arc::new(AtomicUsize::new(0));
    let start = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for _ in 0..8 {
      let budget = Arc::clone(&budget);
      let origin = origin.clone();
      let held = Arc::clone(&held);
      let start = Arc::clone(&start);
      threads.push(thread::spawn(move || {
        start.wait();
        for _ in 0..500 {
          let Some(mut permit) = budget.try_acquire(&origin, 1) else {
            thread::yield_now();
            continue;
          };
          let previous = held.fetch_add(1, Ordering::AcqRel);
          assert_eq!(previous, 0, "per-origin admission exceeded its limit");
          thread::yield_now();
          held.fetch_sub(1, Ordering::AcqRel);
          permit.mark_expected_release();
          drop(permit);
        }
      }));
    }
    for thread in threads {
      assert!(thread.join().is_ok());
    }
    assert_eq!(held.load(Ordering::Acquire), 0);
    assert_eq!(budget.open(), 0);
    assert_eq!(budget.open_for_origin(&origin), 0);
  }

  #[test]
  fn response_buffer_pool_reuses_only_bounded_useful_capacity() {
    let metrics = Metrics::new();
    let budget = Arc::new(GlobalConnectionBudget::new(1, Arc::clone(&metrics)));
    let mut pool = WorkerConnectionPool::new(1, 1, budget, metrics);
    let mut buffer = pool.take_response_buffer(1024);
    buffer.extend_from_slice(b"HTTP/1.1 204 No Content\r\n\r\n");
    let _ = buffer.split().freeze();
    assert!(buffer.capacity() >= MIN_RETAINED_RESPONSE_BUFFER_CAPACITY);
    pool.put_response_buffer(buffer);
    assert_eq!(pool.response_buffers.len(), 1);

    let reused = pool.take_response_buffer(16 * 1024);
    assert_eq!(reused.len(), 0);
    assert!(reused.capacity() >= MIN_RETAINED_RESPONSE_BUFFER_CAPACITY);
    pool.put_response_buffer(reused);

    for _ in 0..MAX_RETAINED_RESPONSE_BUFFERS {
      pool.put_response_buffer(BytesMut::with_capacity(1024));
    }
    assert_eq!(pool.response_buffers.len(), MAX_RETAINED_RESPONSE_BUFFERS);
    pool.put_response_buffer(BytesMut::with_capacity(MAX_RETAINED_BUFFER_CAPACITY + 1));
    assert_eq!(pool.response_buffers.len(), MAX_RETAINED_RESPONSE_BUFFERS);

    let reused = pool.take_response_buffer(16 * 1024);
    assert_eq!(reused.len(), 0);
    assert!(reused.capacity() >= 1024);
  }
}
