//! Fixed-vocabulary priority admission for global downstream request slots.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{
  CircuitBreakerPriorityConfig, PriorityClass, PriorityClassPolicy, PriorityRejectionPolicy,
  max_class_requests,
};

use super::runtime::{AdmissionLease, AdmissionRejection, AdmissionRejectionReason};
use super::runtime::{CircuitBreakerRuntime, RuntimeState};
use super::types::{Allocation, ResourceKind, ResourceLimit, ScopeKey};

const ELIGIBLE_LANE: usize = 0;
const SHARED_LANE: usize = 1;
const LANE_COUNT: usize = 2;

/// Which portion of global request capacity an admitted class occupies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PriorityLeaseKind {
  Reserved,
  Shared,
}

/// Priority accounting retained by an admission lease until its response body ends.
#[derive(Clone, Copy, Debug)]
pub(super) struct PriorityLease {
  class: PriorityClass,
  kind: PriorityLeaseKind,
}

impl PriorityLease {
  pub(super) const fn new(class: PriorityClass, kind: PriorityLeaseKind) -> Self {
    Self { class, kind }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(super) enum PriorityRejectionReason {
  ShareLimit,
  QueueFull,
  Policy,
  QueueTimeout,
}

impl PriorityRejectionReason {
  const ALL: [Self; 4] = [
    Self::ShareLimit,
    Self::QueueFull,
    Self::Policy,
    Self::QueueTimeout,
  ];

  const fn as_str(self) -> &'static str {
    match self {
      Self::ShareLimit => "share_limit",
      Self::QueueFull => "queue_full",
      Self::Policy => "policy",
      Self::QueueTimeout => "queue_timeout",
    }
  }
}

#[derive(Clone, Copy, Debug)]
struct ResolvedPriorityPolicy {
  reserved_requests: usize,
  max_requests: usize,
  max_pending_requests: usize,
  queue_timeout: Duration,
  rejection_policy: PriorityRejectionPolicy,
}

impl ResolvedPriorityPolicy {
  fn from_config(policy: PriorityClassPolicy, global: ResourceLimit) -> Self {
    let automatic_queue = if policy.rejection_policy == PriorityRejectionPolicy::Queue {
      ((global.queue as f64 * policy.max_share).ceil() as usize).max(1)
    } else {
      0
    };
    let max_pending_requests = match policy.max_pending_requests {
      Some(value) => value.fixed().unwrap_or(automatic_queue),
      None => automatic_queue,
    };
    Self {
      reserved_requests: policy.reserved_requests,
      max_requests: max_class_requests(global.active, policy.max_share),
      max_pending_requests: if policy.rejection_policy == PriorityRejectionPolicy::Reject {
        0
      } else {
        max_pending_requests
      },
      queue_timeout: Duration::from_millis(
        policy
          .pending_queue_timeout_ms
          .unwrap_or_else(|| global.timeout.as_millis().min(u128::from(u64::MAX)) as u64),
      ),
      rejection_policy: policy.rejection_policy,
    }
  }
}

#[derive(Clone, Copy, Debug, Default)]
struct PriorityActive {
  reserved: usize,
  shared: usize,
}

impl PriorityActive {
  const fn total(self) -> usize {
    self.reserved.saturating_add(self.shared)
  }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PriorityTicket {
  id: u64,
  class: PriorityClass,
  lane: usize,
  queued_at: Instant,
}

impl PriorityTicket {
  pub(super) const fn queued_at(self) -> Instant {
    self.queued_at
  }
}

#[derive(Clone, Copy, Debug)]
struct PriorityWaiter {
  ticket: PriorityTicket,
}

/// Priority state lives inside the same mutex as ordinary circuit-breaker capacity.
#[derive(Debug)]
pub(super) struct PriorityAdmissionState {
  enabled: bool,
  policies: [ResolvedPriorityPolicy; PriorityClass::COUNT],
  shared_capacity: usize,
  shared_active: usize,
  active: [PriorityActive; PriorityClass::COUNT],
  queued: [usize; PriorityClass::COUNT],
  queues: [[VecDeque<PriorityWaiter>; LANE_COUNT]; PriorityClass::COUNT],
  rejections: [[u64; 4]; PriorityClass::COUNT],
  queue_waits: [u64; PriorityClass::COUNT],
  queue_wait_ms: [u64; PriorityClass::COUNT],
  next_waiter: u64,
}

impl PriorityAdmissionState {
  pub(super) fn from_config(config: &CircuitBreakerPriorityConfig, global: ResourceLimit) -> Self {
    let policies = std::array::from_fn(|index| {
      let class = PriorityClass::ALL[index];
      ResolvedPriorityPolicy::from_config(config.resolved_for_validation(class), global)
    });
    let reserved = policies
      .iter()
      .map(|policy| policy.reserved_requests)
      .sum::<usize>();
    Self {
      enabled: config.enabled,
      policies,
      shared_capacity: global.active.saturating_sub(reserved),
      shared_active: 0,
      active: [PriorityActive::default(); PriorityClass::COUNT],
      queued: [0; PriorityClass::COUNT],
      queues: std::array::from_fn(|_| std::array::from_fn(|_| VecDeque::new())),
      rejections: [[0; 4]; PriorityClass::COUNT],
      queue_waits: [0; PriorityClass::COUNT],
      queue_wait_ms: [0; PriorityClass::COUNT],
      next_waiter: 1,
    }
  }

  pub(super) fn configure(&mut self, config: &CircuitBreakerPriorityConfig, global: ResourceLimit) {
    let replacement = Self::from_config(config, global);
    self.enabled = replacement.enabled;
    self.policies = replacement.policies;
    self.shared_capacity = replacement.shared_capacity;
  }

  pub(super) const fn enabled(&self) -> bool {
    self.enabled
  }

  pub(super) fn lane_empty(&self, class: PriorityClass, reservation_eligible: bool) -> bool {
    self.queues[class.index()][lane(reservation_eligible)].is_empty()
  }

  pub(super) fn can_admit(
    &self,
    class: PriorityClass,
    reservation_eligible: bool,
    global_active: usize,
    global_capacity: usize,
  ) -> Option<PriorityLeaseKind> {
    if global_active >= global_capacity {
      return None;
    }
    let index = class.index();
    let policy = self.policies[index];
    if self.active[index].total() >= policy.max_requests {
      return None;
    }
    if reservation_eligible && self.active[index].reserved < policy.reserved_requests {
      return Some(PriorityLeaseKind::Reserved);
    }
    let untracked_active = global_active.saturating_sub(self.total_active());
    (self.shared_active.saturating_add(untracked_active) < self.shared_capacity)
      .then_some(PriorityLeaseKind::Shared)
  }

  pub(super) fn selected_waiter(
    &self,
    global_active: usize,
    global_capacity: usize,
  ) -> Option<PriorityTicket> {
    let mut reserved = None;
    for class in PriorityClass::ALL {
      let Some(waiter) = self.queues[class.index()][ELIGIBLE_LANE].front() else {
        continue;
      };
      if self.can_admit(class, true, global_active, global_capacity)
        == Some(PriorityLeaseKind::Reserved)
      {
        choose_oldest(&mut reserved, waiter.ticket);
      }
    }
    if reserved.is_some() {
      return reserved;
    }

    let mut shared = None;
    for class in PriorityClass::ALL {
      for lane in 0..LANE_COUNT {
        let Some(waiter) = self.queues[class.index()][lane].front() else {
          continue;
        };
        if self
          .can_admit(class, lane == ELIGIBLE_LANE, global_active, global_capacity)
          .is_some()
        {
          choose_oldest(&mut shared, waiter.ticket);
        }
      }
    }
    shared
  }

  pub(super) fn is_selected(
    &self,
    ticket: PriorityTicket,
    global_active: usize,
    global_capacity: usize,
  ) -> bool {
    self
      .selected_waiter(global_active, global_capacity)
      .is_some_and(|selected| selected.id == ticket.id)
  }

  pub(super) fn queue_rejection_reason(
    &self,
    class: PriorityClass,
  ) -> Option<PriorityRejectionReason> {
    let policy = self.policies[class.index()];
    if policy.rejection_policy == PriorityRejectionPolicy::Reject {
      return Some(
        if self.active[class.index()].total() >= policy.max_requests {
          PriorityRejectionReason::ShareLimit
        } else {
          PriorityRejectionReason::Policy
        },
      );
    }
    (self.queued[class.index()] >= policy.max_pending_requests)
      .then_some(PriorityRejectionReason::QueueFull)
  }

  pub(super) fn queue_timeout(&self, class: PriorityClass) -> Duration {
    self.policies[class.index()].queue_timeout
  }

  pub(super) fn enqueue(
    &mut self,
    class: PriorityClass,
    reservation_eligible: bool,
  ) -> PriorityTicket {
    let ticket = PriorityTicket {
      id: self.next_waiter,
      class,
      lane: lane(reservation_eligible),
      queued_at: Instant::now(),
    };
    self.next_waiter = self.next_waiter.wrapping_add(1).max(1);
    self.queues[class.index()][ticket.lane].push_back(PriorityWaiter { ticket });
    self.queued[class.index()] = self.queued[class.index()].saturating_add(1);
    ticket
  }

  pub(super) fn remove(&mut self, ticket: PriorityTicket) -> Option<PriorityTicket> {
    let queue = &mut self.queues[ticket.class.index()][ticket.lane];
    let position = queue
      .iter()
      .position(|candidate| candidate.ticket.id == ticket.id)?;
    let waiter = queue.remove(position)?;
    self.queued[ticket.class.index()] = self.queued[ticket.class.index()].saturating_sub(1);
    Some(waiter.ticket)
  }

  pub(super) fn admit(&mut self, class: PriorityClass, kind: PriorityLeaseKind) -> PriorityLease {
    let active = &mut self.active[class.index()];
    match kind {
      PriorityLeaseKind::Reserved => active.reserved = active.reserved.saturating_add(1),
      PriorityLeaseKind::Shared => {
        active.shared = active.shared.saturating_add(1);
        self.shared_active = self.shared_active.saturating_add(1);
      }
    }
    PriorityLease::new(class, kind)
  }

  pub(super) fn release(&mut self, lease: PriorityLease) {
    let active = &mut self.active[lease.class.index()];
    match lease.kind {
      PriorityLeaseKind::Reserved => active.reserved = active.reserved.saturating_sub(1),
      PriorityLeaseKind::Shared => {
        active.shared = active.shared.saturating_sub(1);
        self.shared_active = self.shared_active.saturating_sub(1);
      }
    }
  }

  pub(super) fn record_rejection(&mut self, class: PriorityClass, reason: PriorityRejectionReason) {
    let value = &mut self.rejections[class.index()][reason as usize];
    *value = value.saturating_add(1);
  }

  fn total_active(&self) -> usize {
    self.active.iter().map(|value| value.total()).sum()
  }

  pub(super) fn record_queue_wait(&mut self, class: PriorityClass, queued_at: Instant) {
    self.queue_waits[class.index()] = self.queue_waits[class.index()].saturating_add(1);
    self.queue_wait_ms[class.index()] = self.queue_wait_ms[class.index()]
      .saturating_add(queued_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    output.push_str("# TYPE oxibelt_circuit_breaker_priority_active gauge\n");
    output.push_str("# TYPE oxibelt_circuit_breaker_priority_capacity gauge\n");
    output.push_str("# TYPE oxibelt_circuit_breaker_priority_queued gauge\n");
    output.push_str("# TYPE oxibelt_circuit_breaker_priority_rejections_total counter\n");
    output
      .push_str("# TYPE oxibelt_circuit_breaker_priority_queue_wait_milliseconds_total counter\n");
    for class in PriorityClass::ALL {
      let index = class.index();
      let active = self.active[index];
      let policy = self.policies[index];
      let class_name = class.as_str();
      let _ = writeln!(
        output,
        "oxibelt_circuit_breaker_priority_active{{priority=\"{class_name}\",capacity=\"reserved\"}} {}",
        active.reserved
      );
      let _ = writeln!(
        output,
        "oxibelt_circuit_breaker_priority_active{{priority=\"{class_name}\",capacity=\"shared\"}} {}",
        active.shared
      );
      let _ = writeln!(
        output,
        "oxibelt_circuit_breaker_priority_capacity{{priority=\"{class_name}\",capacity=\"reserved\"}} {}",
        policy.reserved_requests
      );
      let _ = writeln!(
        output,
        "oxibelt_circuit_breaker_priority_capacity{{priority=\"{class_name}\",capacity=\"maximum\"}} {}",
        policy.max_requests
      );
      let _ = writeln!(
        output,
        "oxibelt_circuit_breaker_priority_queued{{priority=\"{class_name}\"}} {}",
        self.queued[index]
      );
      for reason in PriorityRejectionReason::ALL {
        let _ = writeln!(
          output,
          "oxibelt_circuit_breaker_priority_rejections_total{{priority=\"{class_name}\",reason=\"{}\"}} {}",
          reason.as_str(),
          self.rejections[index][reason as usize]
        );
      }
      let _ = writeln!(
        output,
        "oxibelt_circuit_breaker_priority_queue_wait_milliseconds_total{{priority=\"{class_name}\"}} {}",
        self.queue_wait_ms[index]
      );
    }
  }
}

fn choose_oldest(candidate: &mut Option<PriorityTicket>, next: PriorityTicket) {
  if candidate.is_none_or(|current| next.queued_at < current.queued_at) {
    *candidate = Some(next);
  }
}

const fn lane(reservation_eligible: bool) -> usize {
  if reservation_eligible {
    ELIGIBLE_LANE
  } else {
    SHARED_LANE
  }
}

/// Removes a queued priority admission if its request future is cancelled.
pub(super) struct PriorityQueuedWaiter {
  runtime: Arc<CircuitBreakerRuntime>,
  ticket: Option<PriorityTicket>,
}

impl PriorityQueuedWaiter {
  pub(super) fn new(runtime: Arc<CircuitBreakerRuntime>) -> Self {
    Self {
      runtime,
      ticket: None,
    }
  }

  pub(super) fn ticket(&self) -> Option<PriorityTicket> {
    self.ticket
  }

  pub(super) fn set(&mut self, ticket: PriorityTicket) {
    debug_assert!(
      self.ticket.is_none(),
      "priority waiter must have one queue entry"
    );
    self.ticket = Some(ticket);
  }

  pub(super) fn take(&mut self) -> Option<PriorityTicket> {
    self.ticket.take()
  }

  pub(super) fn remove(&mut self) {
    self.runtime.remove_priority_waiter(self.ticket.take());
  }
}

impl Drop for PriorityQueuedWaiter {
  fn drop(&mut self) {
    self.remove();
  }
}

impl RuntimeState {
  pub(super) fn remove_priority_waiter(
    &mut self,
    ticket: PriorityTicket,
  ) -> Option<PriorityTicket> {
    let removed = self.priority.remove(ticket)?;
    if let Some(scope) = self.scopes.get_mut(&super::types::ScopeKey::Global) {
      scope.queued[super::types::ResourceKind::Request as usize] =
        scope.queued[super::types::ResourceKind::Request as usize].saturating_sub(1);
    }
    Some(removed)
  }
}

impl CircuitBreakerRuntime {
  /// Admit one downstream request through the priority-aware global capacity boundary.
  pub async fn admit_priority_global_request(
    self: &Arc<Self>,
    class: PriorityClass,
    reservation_eligible: bool,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    if !self.enabled.load(std::sync::atomic::Ordering::Acquire) {
      return Ok(AdmissionLease::disabled());
    }
    let allocations = vec![Allocation {
      scope: ScopeKey::Global,
      resource: ResourceKind::Request,
      limit: None,
    }];
    let mut waiter = PriorityQueuedWaiter::new(self.clone());

    loop {
      let notified = self.notify.notified();
      let mut fallback = false;
      let admission = {
        let mut state = self
          .state
          .lock()
          .expect("circuit-breaker state lock poisoned");
        if !self.enabled.load(std::sync::atomic::Ordering::Acquire) {
          if let Some(ticket) = waiter.take() {
            state.remove_priority_waiter(ticket);
          }
          return Ok(AdmissionLease::disabled());
        }
        if !state.priority.enabled() {
          if let Some(ticket) = waiter.take() {
            state.remove_priority_waiter(ticket);
          }
          fallback = true;
          None
        } else {
          let global = state
            .scopes
            .get(&ScopeKey::Global)
            .expect("global circuit-breaker scope is present");
          let global_limit = global.limits.resource(ResourceKind::Request);
          let global_active = global.active[ResourceKind::Request as usize];
          let selected = state
            .priority
            .selected_waiter(global_active, global_limit.active);
          let ticket = waiter.ticket();
          let selected_waiter = ticket.is_some_and(|ticket| {
            state
              .priority
              .is_selected(ticket, global_active, global_limit.active)
          });
          let allocation_kind = state.priority.can_admit(
            class,
            reservation_eligible,
            global_active,
            global_limit.active,
          );
          let direct_lane_is_empty = state.priority.lane_empty(class, reservation_eligible);
          let may_admit = if ticket.is_some() {
            selected_waiter
          } else {
            direct_lane_is_empty
              && (selected.is_none() || allocation_kind == Some(PriorityLeaseKind::Reserved))
          };
          if may_admit {
            if let Some(allocation_kind) = allocation_kind {
              if let Some(ticket) = waiter.take()
                && let Some(queued) = state.remove_priority_waiter(ticket)
              {
                state.priority.record_queue_wait(class, queued.queued_at());
              }
              state.increment_active(&allocations);
              let priority = state.priority.admit(class, allocation_kind);
              Some(Ok(AdmissionLease::enabled_with_priority(
                self.clone(),
                allocations.clone(),
                priority,
              )))
            } else {
              None
            }
          } else {
            None
          }
        }
      };
      if fallback {
        return self.admit_global_request_unprioritized(deadline).await;
      }
      if let Some(result) = admission {
        return result;
      }

      let fallback_after_queue_lock = if waiter.ticket().is_none() {
        let mut state = self
          .state
          .lock()
          .expect("circuit-breaker state lock poisoned");
        if !state.priority.enabled() {
          true
        } else if let Some(reason) = state.priority.queue_rejection_reason(class) {
          state.priority.record_rejection(class, reason);
          state.reject(AdmissionRejectionReason::ActiveLimit);
          return Err(AdmissionRejection {
            reason: AdmissionRejectionReason::ActiveLimit,
            retry_after: state.capacity_retry_after,
          });
        } else if !state.can_queue(&allocations) {
          state
            .priority
            .record_rejection(class, PriorityRejectionReason::QueueFull);
          let reason = state.queue_rejection_reason(&allocations);
          state.reject(reason);
          return Err(AdmissionRejection {
            reason,
            retry_after: state.capacity_retry_after,
          });
        } else {
          let ticket = state.priority.enqueue(class, reservation_eligible);
          let global = state
            .scopes
            .get_mut(&ScopeKey::Global)
            .expect("global circuit-breaker scope is present");
          global.queued[ResourceKind::Request as usize] =
            global.queued[ResourceKind::Request as usize].saturating_add(1);
          waiter.set(ticket);
          false
        }
      } else {
        false
      };
      if fallback_after_queue_lock {
        return self.admit_global_request_unprioritized(deadline).await;
      }

      let ticket = waiter
        .ticket()
        .expect("queued priority waiter has a ticket");
      let timeout = {
        let state = self
          .state
          .lock()
          .expect("circuit-breaker state lock poisoned");
        let global = state
          .scopes
          .get(&ScopeKey::Global)
          .expect("global circuit-breaker scope is present")
          .limits
          .resource(ResourceKind::Request)
          .timeout;
        let configured = global.min(state.priority.queue_timeout(class));
        let remaining = configured.saturating_sub(ticket.queued_at().elapsed());
        deadline
          .map(|deadline| remaining.min(deadline.saturating_duration_since(Instant::now())))
          .unwrap_or(remaining)
      };
      if timeout.is_zero() {
        waiter.remove();
        return Err(self.priority_timeout_rejection(class));
      }
      if tokio::time::timeout(timeout, notified).await.is_err() {
        waiter.remove();
        return Err(self.priority_timeout_rejection(class));
      }
    }
  }

  pub(super) fn remove_priority_waiter(&self, ticket: Option<PriorityTicket>) {
    if let Some(ticket) = ticket {
      let mut state = self
        .state
        .lock()
        .expect("circuit-breaker state lock poisoned");
      if state.remove_priority_waiter(ticket).is_some() {
        drop(state);
        self.notify.notify_waiters();
      }
    }
  }

  fn priority_timeout_rejection(&self, class: PriorityClass) -> AdmissionRejection {
    let mut state = self
      .state
      .lock()
      .expect("circuit-breaker state lock poisoned");
    state
      .priority
      .record_rejection(class, PriorityRejectionReason::QueueTimeout);
    state.reject(AdmissionRejectionReason::QueueTimeout);
    AdmissionRejection {
      reason: AdmissionRejectionReason::QueueTimeout,
      retry_after: state.capacity_retry_after,
    }
  }
}
