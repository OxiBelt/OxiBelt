//! Process-local, route-shared bandwidth scheduling primitives.
//!
//! A limiter owns independent upload and download token buckets. Callers create
//! one [`BandwidthFlow`] per logical body or stream and repeatedly acquire
//! bounded grants before transferring payload bytes. Acquisitions borrow the
//! flow mutably, so a flow cannot hold more than one outstanding reservation.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// The maximum divisible grant assigned to one flow in a scheduler round.
pub const BANDWIDTH_QUANTUM_BYTES: usize = 16 * 1024;
/// Fail-closed bound on route/direction acquisitions waiting in scheduler state.
pub const MAX_PENDING_BANDWIDTH_ACQUISITIONS: usize = 1024;

const BYTE_UNITS: u128 = 1_000_000_000;

/// The client-facing traffic direction governed by a token bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BandwidthDirection {
  Upload = 0,
  Download = 1,
}

impl BandwidthDirection {
  const fn index(self) -> usize {
    self as usize
  }
}

/// A disabled or positive byte-per-second rate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BandwidthRate {
  Unlimited,
  BytesPerSecond(NonZeroU64),
}

impl From<Option<NonZeroU64>> for BandwidthRate {
  fn from(value: Option<NonZeroU64>) -> Self {
    value.map_or(Self::Unlimited, Self::BytesPerSecond)
  }
}

impl BandwidthRate {
  pub const fn bytes_per_second(self) -> Option<NonZeroU64> {
    match self {
      Self::Unlimited => None,
      Self::BytesPerSecond(rate) => Some(rate),
    }
  }
}

/// The independently configurable upload and download policy for one route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BandwidthPolicy {
  pub upload: BandwidthRate,
  pub download: BandwidthRate,
}

impl BandwidthPolicy {
  pub const UNLIMITED: Self = Self {
    upload: BandwidthRate::Unlimited,
    download: BandwidthRate::Unlimited,
  };

  pub const fn new(upload: BandwidthRate, download: BandwidthRate) -> Self {
    Self { upload, download }
  }

  const fn rate(self, direction: BandwidthDirection) -> BandwidthRate {
    match direction {
      BandwidthDirection::Upload => self.upload,
      BandwidthDirection::Download => self.download,
    }
  }
}

/// A successfully reserved byte grant and the deliberate limiter wait it incurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BandwidthGrant {
  bytes: usize,
  waited: Duration,
}

impl BandwidthGrant {
  pub const fn bytes(self) -> usize {
    self.bytes
  }

  pub const fn waited(self) -> Duration {
    self.waited
  }
}

/// A fail-closed bandwidth scheduler error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BandwidthError {
  StateUnavailable,
  ReservationMismatch,
  QueueFull {
    max_pending: usize,
  },
  IndivisibleDebtLimit {
    bytes: usize,
    capacity_bytes: u64,
    max_debt_bytes: usize,
  },
}

impl fmt::Display for BandwidthError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::StateUnavailable => formatter.write_str("bandwidth scheduler state is unavailable"),
      Self::ReservationMismatch => {
        formatter.write_str("bandwidth reservations belong to different flows")
      }
      Self::QueueFull { max_pending } => write!(
        formatter,
        "bandwidth scheduler has reached its {max_pending}-acquisition pending limit"
      ),
      Self::IndivisibleDebtLimit {
        bytes,
        capacity_bytes,
        max_debt_bytes,
      } => write!(
        formatter,
        "indivisible bandwidth item of {bytes} bytes exceeds capacity {capacity_bytes} plus bounded debt {max_debt_bytes}"
      ),
    }
  }
}

impl std::error::Error for BandwidthError {}

/// Process-local state shared by every flow selected for one route.
pub struct RouteBandwidthLimiter {
  state: Mutex<LimiterState>,
  notify: Notify,
  next_flow_id: AtomicU64,
}

impl fmt::Debug for RouteBandwidthLimiter {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RouteBandwidthLimiter")
      .field("policy", &self.policy())
      .finish_non_exhaustive()
  }
}

impl RouteBandwidthLimiter {
  /// Creates initially-full limited buckets and immediately-open unlimited buckets.
  pub fn new(policy: BandwidthPolicy) -> Arc<Self> {
    let now = Instant::now();
    Arc::new(Self {
      state: Mutex::new(LimiterState {
        buckets: [
          BucketState::new(policy.upload, now),
          BucketState::new(policy.download, now),
        ],
        next_ticket: 1,
      }),
      notify: Notify::new(),
      next_flow_id: AtomicU64::new(1),
    })
  }

  /// Creates a non-cloneable logical flow in one direction.
  pub fn flow(self: &Arc<Self>, direction: BandwidthDirection) -> BandwidthFlow {
    BandwidthFlow {
      limiter: Arc::clone(self),
      direction,
      id: self.next_flow_id.fetch_add(1, Ordering::Relaxed),
    }
  }

  /// Returns the active policy, or fails if scheduler state was poisoned.
  pub fn policy(&self) -> Result<BandwidthPolicy, BandwidthError> {
    let state = self.state_guard()?;
    Ok(BandwidthPolicy {
      upload: state.buckets[BandwidthDirection::Upload.index()].rate,
      download: state.buckets[BandwidthDirection::Download.index()].rate,
    })
  }

  /// Atomically updates both directions without minting credit.
  ///
  /// Each old bucket is refilled to the update instant under its old rate. Its
  /// credit is then preserved and clamped to the new one-second capacity. Debt
  /// is preserved. Disabling a direction releases all of its queued waiters;
  /// enabling a previously unlimited direction starts empty.
  pub fn update(&self, policy: BandwidthPolicy) -> Result<(), BandwidthError> {
    let now = Instant::now();
    let mut state = self.state_guard()?;
    for direction in [BandwidthDirection::Upload, BandwidthDirection::Download] {
      let bucket = &mut state.buckets[direction.index()];
      bucket.update(policy.rate(direction), now);
      bucket.dispatch(now);
    }
    drop(state);
    // Rate changes may shorten a sleeping waiter's deadline even if no grant
    // can be issued at the exact update instant.
    self.notify.notify_waiters();
    Ok(())
  }

  fn state_guard(&self) -> Result<MutexGuard<'_, LimiterState>, BandwidthError> {
    self
      .state
      .lock()
      .map_err(|_| BandwidthError::StateUnavailable)
  }

  async fn acquire(
    self: &Arc<Self>,
    flow_id: u64,
    direction: BandwidthDirection,
    request: AcquisitionRequest,
  ) -> Result<AcquiredBandwidth, BandwidthError> {
    if request.bytes() == 0 {
      return Ok(AcquiredBandwidth {
        grant: BandwidthGrant {
          bytes: 0,
          waited: Duration::ZERO,
        },
        reservation: Reservation {
          bytes: 0,
          credit_units: 0,
          debt_units: 0,
        },
      });
    }

    let started = Instant::now();
    let mut did_wait = false;
    let mut queued = QueuedAcquisition::new(Arc::clone(self), direction);
    loop {
      let notified = self.notify.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();

      let (deadline, completed_others) = {
        let now = Instant::now();
        let mut state = self.state_guard()?;
        let direction_index = direction.index();
        if queued.ticket.is_none() {
          if state.buckets[direction_index].rate == BandwidthRate::Unlimited {
            return Ok(AcquiredBandwidth {
              grant: BandwidthGrant {
                bytes: request.bytes(),
                waited: Duration::ZERO,
              },
              reservation: Reservation {
                bytes: request.bytes(),
                credit_units: 0,
                debt_units: 0,
              },
            });
          }
          let request = request.bounded_for_limited_bucket();
          state.validate_request(direction, request)?;
          let bucket = &state.buckets[direction_index];
          if bucket.queue.len().saturating_add(bucket.completed.len())
            >= MAX_PENDING_BANDWIDTH_ACQUISITIONS
          {
            return Err(BandwidthError::QueueFull {
              max_pending: MAX_PENDING_BANDWIDTH_ACQUISITIONS,
            });
          }
          let ticket = state.next_ticket;
          state.next_ticket = state.next_ticket.wrapping_add(1);
          debug_assert!(
            !state.buckets[direction_index]
              .queue
              .iter()
              .any(|waiter| waiter.flow_id == flow_id),
            "one flow must not hold multiple queued bandwidth acquisitions"
          );
          state.buckets[direction_index].queue.push_back(Waiter {
            ticket,
            flow_id,
            request,
            deficit_bytes: 0,
          });
          queued.ticket = Some(ticket);
        }

        let completed_others = state.buckets[direction_index].dispatch(now);
        let ticket = queued.ticket.unwrap_or_default();
        if let Some(completion) = state.buckets[direction_index].completed.remove(&ticket) {
          queued.commit();
          drop(state);
          if completed_others {
            self.notify.notify_waiters();
          }
          return completion.map(|reservation| AcquiredBandwidth {
            grant: BandwidthGrant {
              bytes: reservation.bytes,
              waited: if did_wait {
                Instant::now().saturating_duration_since(started)
              } else {
                Duration::ZERO
              },
            },
            reservation,
          });
        }
        (
          state.buckets[direction_index].next_deadline(now),
          completed_others,
        )
      };

      if completed_others {
        self.notify.notify_waiters();
      }
      did_wait = true;
      match deadline {
        Some(deadline) => {
          tokio::select! {
            () = notified.as_mut() => {}
            () = tokio::time::sleep_until(deadline) => {}
          }
        }
        None => notified.as_mut().await,
      }
    }
  }

  fn cancel(&self, direction: BandwidthDirection, ticket: u64) {
    let Ok(mut state) = self.state.lock() else {
      return;
    };
    let now = Instant::now();
    let bucket = &mut state.buckets[direction.index()];
    if let Some(index) = bucket
      .queue
      .iter()
      .position(|waiter| waiter.ticket == ticket)
    {
      bucket.queue.remove(index);
    }
    if let Some(completion) = bucket.completed.remove(&ticket)
      && let Ok(reservation) = completion
    {
      bucket.refund(reservation);
    }
    let completed = bucket.dispatch(now);
    drop(state);
    if completed {
      self.notify.notify_waiters();
    }
  }

  fn refund_reservation(&self, direction: BandwidthDirection, reservation: Reservation) {
    let Ok(mut state) = self.state.lock() else {
      return;
    };
    let now = Instant::now();
    let bucket = &mut state.buckets[direction.index()];
    bucket.refill(now);
    bucket.refund(reservation);
    let completed = bucket.dispatch(now);
    drop(state);
    if completed {
      self.notify.notify_waiters();
    }
  }
}

/// One logical upload or download flow.
///
/// The type is intentionally not `Clone`, and acquisitions require a mutable
/// borrow, ensuring at most one pending reservation per flow in safe Rust.
pub struct BandwidthFlow {
  limiter: Arc<RouteBandwidthLimiter>,
  direction: BandwidthDirection,
  id: u64,
}

impl fmt::Debug for BandwidthFlow {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("BandwidthFlow")
      .field("direction", &self.direction)
      .field("id", &self.id)
      .finish_non_exhaustive()
  }
}

mod flow;
pub(crate) use flow::RefundableBandwidthGrant;

#[derive(Clone, Copy, Debug)]
enum AcquisitionRequest {
  Divisible(usize),
  Indivisible { bytes: usize, max_debt_bytes: usize },
}

impl AcquisitionRequest {
  const fn bytes(self) -> usize {
    match self {
      Self::Divisible(bytes) | Self::Indivisible { bytes, .. } => bytes,
    }
  }

  const fn bounded_for_limited_bucket(self) -> Self {
    match self {
      Self::Divisible(bytes) => Self::Divisible(if bytes < BANDWIDTH_QUANTUM_BYTES {
        bytes
      } else {
        BANDWIDTH_QUANTUM_BYTES
      }),
      indivisible @ Self::Indivisible { .. } => indivisible,
    }
  }
}

#[derive(Debug)]
struct LimiterState {
  buckets: [BucketState; 2],
  next_ticket: u64,
}

impl LimiterState {
  fn validate_request(
    &self,
    direction: BandwidthDirection,
    request: AcquisitionRequest,
  ) -> Result<(), BandwidthError> {
    let AcquisitionRequest::Indivisible {
      bytes,
      max_debt_bytes,
    } = request
    else {
      return Ok(());
    };
    let capacity_bytes = self.buckets[direction.index()].capacity_bytes();
    if (bytes as u128) > u128::from(capacity_bytes).saturating_add(max_debt_bytes as u128) {
      return Err(BandwidthError::IndivisibleDebtLimit {
        bytes,
        capacity_bytes,
        max_debt_bytes,
      });
    }
    Ok(())
  }
}

#[derive(Debug)]
struct BucketState {
  rate: BandwidthRate,
  credit_units: u128,
  debt_units: u128,
  last_refill: Instant,
  queue: VecDeque<Waiter>,
  completed: HashMap<u64, Result<Reservation, BandwidthError>>,
}

impl BucketState {
  fn new(rate: BandwidthRate, now: Instant) -> Self {
    let credit_units = rate
      .bytes_per_second()
      .map_or(0, |rate| u128::from(rate.get()).saturating_mul(BYTE_UNITS));
    Self {
      rate,
      credit_units,
      debt_units: 0,
      last_refill: now,
      queue: VecDeque::new(),
      completed: HashMap::new(),
    }
  }

  fn capacity_bytes(&self) -> u64 {
    self.rate.bytes_per_second().map_or(0, NonZeroU64::get)
  }

  fn capacity_units(&self) -> u128 {
    u128::from(self.capacity_bytes()).saturating_mul(BYTE_UNITS)
  }

  fn update(&mut self, rate: BandwidthRate, now: Instant) {
    self.refill(now);
    self.rate = rate;
    self.credit_units = self.credit_units.min(self.capacity_units());
    self.last_refill = now;

    let capacity_bytes = self.capacity_bytes();
    let mut retained = VecDeque::with_capacity(self.queue.len());
    while let Some(waiter) = self.queue.pop_front() {
      let AcquisitionRequest::Indivisible {
        bytes,
        max_debt_bytes,
      } = waiter.request
      else {
        retained.push_back(waiter);
        continue;
      };
      if rate == BandwidthRate::Unlimited
        || (bytes as u128) <= u128::from(capacity_bytes).saturating_add(max_debt_bytes as u128)
      {
        retained.push_back(waiter);
        continue;
      }
      self.completed.insert(
        waiter.ticket,
        Err(BandwidthError::IndivisibleDebtLimit {
          bytes,
          capacity_bytes,
          max_debt_bytes,
        }),
      );
    }
    self.queue = retained;
  }

  fn refill(&mut self, now: Instant) {
    let elapsed = now.saturating_duration_since(self.last_refill);
    self.last_refill = now;
    let Some(rate) = self.rate.bytes_per_second() else {
      return;
    };
    let refill_units = elapsed.as_nanos().saturating_mul(u128::from(rate.get()));
    let debt_repaid = refill_units.min(self.debt_units);
    self.debt_units -= debt_repaid;
    let new_credit = refill_units - debt_repaid;
    self.credit_units = self
      .credit_units
      .saturating_add(new_credit)
      .min(self.capacity_units());
  }

  fn dispatch(&mut self, now: Instant) -> bool {
    self.refill(now);
    if self.queue.is_empty() {
      return false;
    }
    if self.rate == BandwidthRate::Unlimited {
      while let Some(waiter) = self.queue.pop_front() {
        self.completed.insert(
          waiter.ticket,
          Ok(Reservation {
            bytes: waiter.request.bytes(),
            credit_units: 0,
            debt_units: 0,
          }),
        );
      }
      return true;
    }
    if self.debt_units > 0 {
      return false;
    }

    let mut granted = false;
    let mut made_progress = true;
    while made_progress && !self.queue.is_empty() {
      made_progress = false;
      let round_len = self.queue.len();
      for _ in 0..round_len {
        let Some(mut waiter) = self.queue.pop_front() else {
          break;
        };
        let previous_deficit = waiter.deficit_bytes;
        waiter.deficit_bytes = waiter
          .deficit_bytes
          .saturating_add(BANDWIDTH_QUANTUM_BYTES)
          .min(waiter.request.bytes());
        made_progress |= waiter.deficit_bytes > previous_deficit;
        if let Some(reservation) = self.try_reserve(waiter.request, waiter.deficit_bytes) {
          self.completed.insert(waiter.ticket, Ok(reservation));
          granted = true;
          made_progress = true;
        } else {
          self.queue.push_back(waiter);
        }
      }
    }
    granted
  }

  fn try_reserve(
    &mut self,
    request: AcquisitionRequest,
    deficit_bytes: usize,
  ) -> Option<Reservation> {
    match request {
      AcquisitionRequest::Divisible(bytes) => {
        let available_bytes = self.credit_units / BYTE_UNITS;
        let grant = (bytes as u128)
          .min(BANDWIDTH_QUANTUM_BYTES as u128)
          .min(deficit_bytes as u128)
          .min(available_bytes);
        if grant == 0 {
          return None;
        }
        let credit_units = grant.saturating_mul(BYTE_UNITS);
        self.credit_units -= credit_units;
        Some(Reservation {
          bytes: usize::try_from(grant).unwrap_or(BANDWIDTH_QUANTUM_BYTES),
          credit_units,
          debt_units: 0,
        })
      }
      AcquisitionRequest::Indivisible {
        bytes,
        max_debt_bytes,
      } => {
        if deficit_bytes < bytes {
          return None;
        }
        let requested_units = (bytes as u128).saturating_mul(BYTE_UNITS);
        let capacity_units = self.capacity_units();
        if requested_units <= capacity_units {
          if self.credit_units < requested_units {
            return None;
          }
          self.credit_units -= requested_units;
          return Some(Reservation {
            bytes,
            credit_units: requested_units,
            debt_units: 0,
          });
        }
        if self.credit_units < capacity_units {
          return None;
        }
        let debt_units = requested_units - capacity_units;
        if debt_units > (max_debt_bytes as u128).saturating_mul(BYTE_UNITS) {
          return None;
        }
        self.credit_units = 0;
        self.debt_units = debt_units;
        Some(Reservation {
          bytes,
          credit_units: capacity_units,
          debt_units,
        })
      }
    }
  }

  fn next_deadline(&self, now: Instant) -> Option<Instant> {
    let rate = self.rate.bytes_per_second()?;
    if self.queue.is_empty() {
      return None;
    }
    let capacity_units = self.capacity_units();
    let needed_units = if self.debt_units > 0 {
      self.debt_units.saturating_add(BYTE_UNITS)
    } else {
      self
        .queue
        .iter()
        .map(|waiter| match waiter.request {
          AcquisitionRequest::Divisible(_) => BYTE_UNITS.saturating_sub(self.credit_units),
          AcquisitionRequest::Indivisible { bytes, .. } => {
            let requested_units = (bytes as u128).saturating_mul(BYTE_UNITS);
            requested_units
              .min(capacity_units)
              .saturating_sub(self.credit_units)
          }
        })
        .min()
        .unwrap_or(BYTE_UNITS)
    };
    if needed_units == 0 {
      return Some(now);
    }
    let rate = u128::from(rate.get());
    let wait_nanos = needed_units.saturating_add(rate - 1) / rate;
    let wait_nanos = u64::try_from(wait_nanos).unwrap_or(u64::MAX);
    Some(now + Duration::from_nanos(wait_nanos))
  }

  fn refund(&mut self, reservation: Reservation) {
    self.debt_units = self.debt_units.saturating_sub(reservation.debt_units);
    self.credit_units = self
      .credit_units
      .saturating_add(reservation.credit_units)
      .min(self.capacity_units());
  }
}

#[derive(Clone, Copy, Debug)]
struct Waiter {
  ticket: u64,
  flow_id: u64,
  request: AcquisitionRequest,
  deficit_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct Reservation {
  bytes: usize,
  credit_units: u128,
  debt_units: u128,
}

struct AcquiredBandwidth {
  grant: BandwidthGrant,
  reservation: Reservation,
}

struct QueuedAcquisition {
  limiter: Arc<RouteBandwidthLimiter>,
  direction: BandwidthDirection,
  ticket: Option<u64>,
}

impl QueuedAcquisition {
  fn new(limiter: Arc<RouteBandwidthLimiter>, direction: BandwidthDirection) -> Self {
    Self {
      limiter,
      direction,
      ticket: None,
    }
  }

  fn commit(&mut self) {
    self.ticket = None;
  }
}

impl Drop for QueuedAcquisition {
  fn drop(&mut self) {
    if let Some(ticket) = self.ticket.take() {
      self.limiter.cancel(self.direction, ticket);
    }
  }
}

#[cfg(test)]
#[path = "bandwidth/tests.rs"]
mod tests;
