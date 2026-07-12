//! Cancellation-safe composite admission and upstream failure-circuit state.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use crate::config::{CircuitBreakerFailureConfig, Config};

use super::configuration::{
  deduplicate_allocations, elapsed_ms, queue_timeout, resolve_scopes, scoped_allocations,
};
use super::queue::QueuedWaiter;
use super::types::{
  Allocation, CIRCUIT_STATE_COUNT, CircuitState, REJECTION_REASON_COUNT, ResourceKind,
  ResourceLimit, RetryBudget, ScopeKey, ScopeState, Waiter,
};

pub use super::types::{
  AdmissionRejection, AdmissionRejectionReason, CircuitOutcome, CircuitOutcomeFailure,
};

#[derive(Debug)]
pub(super) struct RuntimeState {
  pub(super) scopes: HashMap<ScopeKey, ScopeState>,
  pub(super) waiters: VecDeque<Waiter>,
  pub(super) next_waiter: u64,
  pub(super) retry: RetryBudget,
  pub(super) failure: CircuitBreakerFailureConfig,
  pub(super) response_status: u16,
  pub(super) capacity_retry_after: Duration,
  pub(super) rejections: [u64; REJECTION_REASON_COUNT],
  pub(super) transitions: [[u64; CIRCUIT_STATE_COUNT]; CIRCUIT_STATE_COUNT],
  pub(super) queue_waits: u64,
  pub(super) queue_wait_ms: u64,
  pub(super) attempts: [u64; 5],
  pub(super) transition_sequence: u64,
}

impl RuntimeState {
  fn from_config(config: &Config) -> Self {
    let (scopes, retry) = resolve_scopes(config);
    let breaker = &config.circuit_breakers;
    Self {
      scopes,
      waiters: VecDeque::new(),
      next_waiter: 1,
      retry,
      failure: breaker.failure.clone(),
      response_status: breaker.response_status,
      capacity_retry_after: Duration::from_millis(breaker.capacity_retry_after_ms),
      rejections: [0; REJECTION_REASON_COUNT],
      transitions: [[0; CIRCUIT_STATE_COUNT]; CIRCUIT_STATE_COUNT],
      queue_waits: 0,
      queue_wait_ms: 0,
      attempts: [0; 5],
      transition_sequence: 0,
    }
  }

  fn configure(&mut self, config: &Config) {
    let (configured, retry) = resolve_scopes(config);
    for (key, replacement) in configured {
      let state = self
        .scopes
        .entry(key)
        .or_insert_with(|| ScopeState::new(replacement.limits, replacement.failure_enabled));
      state.limits = replacement.limits;
      state.failure_enabled = replacement.failure_enabled;
      if !state.failure_enabled {
        state.circuit.close();
      }
    }
    let breaker = &config.circuit_breakers;
    self.retry = retry;
    self.failure = breaker.failure.clone();
    self.response_status = breaker.response_status;
    self.capacity_retry_after = Duration::from_millis(breaker.capacity_retry_after_ms);
    if !breaker.enabled || !breaker.failure.enabled {
      for scope in self.scopes.values_mut() {
        scope.circuit.close();
      }
    }
  }

  fn can_admit(&self, allocations: &[Allocation]) -> bool {
    allocations.iter().all(|allocation| {
      self.scopes.get(&allocation.scope).is_some_and(|scope| {
        let limit = allocation.effective_limit(scope);
        scope.active[allocation.resource as usize] < limit.active
      })
    })
  }

  fn can_queue(&self, allocations: &[Allocation]) -> bool {
    allocations.iter().all(|allocation| {
      self.scopes.get(&allocation.scope).is_some_and(|scope| {
        let limit = allocation.effective_limit(scope);
        scope.queued[allocation.resource as usize] < limit.queue
      })
    })
  }

  fn queue_rejection_reason(&self, allocations: &[Allocation]) -> AdmissionRejectionReason {
    if allocations.iter().any(|allocation| {
      self.scopes.get(&allocation.scope).is_some_and(|scope| {
        let limit = allocation.effective_limit(scope);
        limit.queue == 0 && scope.active[allocation.resource as usize] >= limit.active
      })
    }) {
      AdmissionRejectionReason::ActiveLimit
    } else {
      AdmissionRejectionReason::QueueFull
    }
  }

  fn increment_active(&mut self, allocations: &[Allocation]) {
    for allocation in allocations {
      let scope = self
        .scopes
        .get_mut(&allocation.scope)
        .expect("configured circuit-breaker scope is present");
      scope.active[allocation.resource as usize] += 1;
    }
  }

  fn record_attempt(&mut self, allocations: &[Allocation]) {
    if !allocations
      .iter()
      .any(|allocation| allocation.resource == ResourceKind::UpstreamRequest)
    {
      return;
    }
    let kind = usize::from(
      allocations
        .iter()
        .any(|allocation| allocation.resource == ResourceKind::Retry),
    );
    self.attempts[kind] = self.attempts[kind].saturating_add(1);
  }

  fn decrement_active(&mut self, allocations: &[Allocation]) {
    for allocation in allocations {
      if let Some(scope) = self.scopes.get_mut(&allocation.scope) {
        scope.active[allocation.resource as usize] =
          scope.active[allocation.resource as usize].saturating_sub(1);
      }
    }
  }

  fn enqueue(&mut self, waiter: Waiter) {
    for allocation in &waiter.allocations {
      let scope = self
        .scopes
        .get_mut(&allocation.scope)
        .expect("configured circuit-breaker scope is present");
      scope.queued[allocation.resource as usize] += 1;
    }
    self.waiters.push_back(waiter);
  }

  fn remove_waiter(&mut self, id: u64) -> Option<Waiter> {
    let index = self.waiters.iter().position(|waiter| waiter.id == id)?;
    let waiter = self.waiters.remove(index)?;
    for allocation in &waiter.allocations {
      if let Some(scope) = self.scopes.get_mut(&allocation.scope) {
        scope.queued[allocation.resource as usize] =
          scope.queued[allocation.resource as usize].saturating_sub(1);
      }
    }
    Some(waiter)
  }

  fn circuit_admission(
    &mut self,
    allocations: &[Allocation],
    now: Instant,
  ) -> Result<Vec<ScopeKey>, Duration> {
    if !self.failure.enabled {
      return Ok(Vec::new());
    }
    let mut scopes = allocations
      .iter()
      .filter(|allocation| allocation.resource == ResourceKind::UpstreamRequest)
      .map(|allocation| allocation.scope.clone())
      .collect::<Vec<_>>();
    scopes.sort_by(|left, right| {
      left
        .kind()
        .cmp(right.kind())
        .then(left.label().cmp(right.label()))
    });
    scopes.dedup();
    for key in &scopes {
      let scope = self
        .scopes
        .get(key)
        .expect("configured circuit-breaker scope is present");
      if !scope.failure_enabled {
        continue;
      }
      scope.circuit.available(now, &self.failure)?;
    }
    let mut probes = Vec::new();
    for key in scopes {
      let scope = self
        .scopes
        .get_mut(&key)
        .expect("configured circuit-breaker scope is present");
      if !scope.failure_enabled {
        continue;
      }
      if let Some((from, to)) = scope.circuit.begin_probe(now, &self.failure) {
        self.record_transition(from, to);
        probes.push(key);
      } else if scope.circuit.state == CircuitState::HalfOpen {
        probes.push(key);
      }
    }
    Ok(probes)
  }

  fn circuit_available(&self, allocations: &[Allocation], now: Instant) -> Result<(), Duration> {
    if !self.failure.enabled {
      return Ok(());
    }
    let mut scopes = allocations
      .iter()
      .filter(|allocation| allocation.resource == ResourceKind::UpstreamRequest)
      .map(|allocation| allocation.scope.clone())
      .collect::<Vec<_>>();
    scopes.sort_by(|left, right| {
      left
        .kind()
        .cmp(right.kind())
        .then(left.label().cmp(right.label()))
    });
    scopes.dedup();
    for key in scopes {
      let scope = self
        .scopes
        .get(&key)
        .expect("configured circuit-breaker scope is present");
      if scope.failure_enabled {
        scope.circuit.available(now, &self.failure)?;
      }
    }
    Ok(())
  }

  fn finish_circuits(
    &mut self,
    probes: &[ScopeKey],
    allocations: &[Allocation],
    outcome: CircuitOutcome,
  ) {
    if !self.failure.enabled {
      return;
    }
    let now = Instant::now();
    let scopes = allocations
      .iter()
      .filter(|allocation| allocation.resource == ResourceKind::UpstreamRequest)
      .map(|allocation| allocation.scope.clone())
      .collect::<Vec<_>>();
    for key in scopes {
      let probe = probes.iter().any(|candidate| candidate == &key);
      let Some(scope) = self.scopes.get_mut(&key) else {
        continue;
      };
      if !scope.failure_enabled {
        continue;
      }
      self.transition_sequence = self.transition_sequence.wrapping_add(1);
      if let Some((from, to)) =
        scope
          .circuit
          .finish(probe, outcome, now, &self.failure, self.transition_sequence)
      {
        self.record_transition(from, to);
      }
    }
  }

  fn abandon_circuits(&mut self, probes: &[ScopeKey]) {
    for key in probes {
      if let Some(scope) = self.scopes.get_mut(key) {
        scope.circuit.abandon_probe(true);
      }
    }
  }

  fn record_transition(&mut self, from: CircuitState, to: CircuitState) {
    self.transitions[from as usize][to as usize] =
      self.transitions[from as usize][to as usize].saturating_add(1);
  }

  fn reject(&mut self, reason: AdmissionRejectionReason) {
    self.rejections[reason as usize] = self.rejections[reason as usize].saturating_add(1);
  }
}

/// Shared runtime retained across configuration snapshots.
pub struct CircuitBreakerRuntime {
  pub(super) enabled: AtomicBool,
  pub(super) state: Mutex<RuntimeState>,
  notify: Notify,
}

impl std::fmt::Debug for CircuitBreakerRuntime {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("CircuitBreakerRuntime")
      .field("enabled", &self.enabled.load(Ordering::Relaxed))
      .finish_non_exhaustive()
  }
}

impl CircuitBreakerRuntime {
  pub fn new(config: &Config) -> Arc<Self> {
    Arc::new(Self {
      enabled: AtomicBool::new(config.circuit_breakers.enabled),
      state: Mutex::new(RuntimeState::from_config(config)),
      notify: Notify::new(),
    })
  }

  pub fn configure(&self, config: &Config) {
    self
      .enabled
      .store(config.circuit_breakers.enabled, Ordering::Release);
    let mut state = self
      .state
      .lock()
      .expect("circuit-breaker state lock poisoned");
    state.configure(config);
    drop(state);
    self.notify.notify_waiters();
  }

  pub fn enabled(&self) -> bool {
    self.enabled.load(Ordering::Acquire)
  }

  pub fn response_status(&self) -> u16 {
    self
      .state
      .lock()
      .expect("circuit-breaker state lock poisoned")
      .response_status
  }

  pub fn capacity_retry_after(&self) -> Duration {
    self
      .state
      .lock()
      .expect("circuit-breaker state lock poisoned")
      .capacity_retry_after
  }

  pub async fn admit_route_request(
    self: &Arc<Self>,
    route: &str,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    self
      .admit(
        scoped_allocations(Some(route), None, ResourceKind::Request),
        deadline,
        None,
      )
      .await
  }

  pub async fn admit_global_request(
    self: &Arc<Self>,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    self
      .admit(
        vec![Allocation {
          scope: ScopeKey::Global,
          resource: ResourceKind::Request,
          limit: None,
        }],
        deadline,
        None,
      )
      .await
  }

  pub async fn admit_route_scope_request(
    self: &Arc<Self>,
    route: &str,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    self
      .admit(
        vec![Allocation {
          scope: ScopeKey::Route(route.to_string()),
          resource: ResourceKind::Request,
          limit: None,
        }],
        deadline,
        None,
      )
      .await
  }

  pub async fn admit_upstream_attempt(
    self: &Arc<Self>,
    route: &str,
    pool: Option<&str>,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    self
      .admit(
        scoped_allocations(Some(route), pool, ResourceKind::UpstreamRequest),
        deadline,
        None,
      )
      .await
  }

  pub async fn admit_retry_attempt(
    self: &Arc<Self>,
    route: &str,
    pool: Option<&str>,
    deadline: Option<Instant>,
    overload_multiplier: f64,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    if !self.enabled() {
      return Ok(AdmissionLease::disabled());
    }
    let retry_limit = {
      let state = self
        .state
        .lock()
        .expect("circuit-breaker state lock poisoned");
      let originals = state
        .scopes
        .get(&ScopeKey::Global)
        .map(|scope| scope.active[ResourceKind::Request as usize])
        .unwrap_or_default();
      let proportional = (originals as f64 * state.retry.percent).floor() as usize;
      let allowance = proportional.max(state.retry.min).min(state.retry.max);
      let adjusted = (allowance as f64 * overload_multiplier.clamp(0.0, 1.0)).floor() as usize;
      ResourceLimit {
        active: adjusted.max(1),
        queue: state.retry.queue,
        timeout: state.retry.timeout,
      }
    };
    let mut allocations = scoped_allocations(Some(route), pool, ResourceKind::UpstreamRequest);
    allocations.push(Allocation {
      scope: ScopeKey::Global,
      resource: ResourceKind::Retry,
      limit: Some(retry_limit),
    });
    self
      .admit(
        allocations,
        deadline,
        Some(AdmissionRejectionReason::RetryBudget),
      )
      .await
  }

  pub async fn admit_upstream_connection(
    self: &Arc<Self>,
    pool: Option<&str>,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    self
      .admit(
        scoped_allocations(None, pool, ResourceKind::Connection),
        deadline,
        None,
      )
      .await
  }

  pub async fn admit_upstream_stream(
    self: &Arc<Self>,
    route: &str,
    pool: Option<&str>,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    self
      .admit(
        scoped_allocations(Some(route), pool, ResourceKind::Stream),
        deadline,
        None,
      )
      .await
  }

  pub async fn admit_body_inspection(
    self: &Arc<Self>,
    route: &str,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    self
      .admit(
        scoped_allocations(Some(route), None, ResourceKind::BodyInspection),
        deadline,
        None,
      )
      .await
  }

  pub async fn admit_decompression(
    self: &Arc<Self>,
    route: &str,
    deadline: Option<Instant>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    self
      .admit(
        scoped_allocations(Some(route), None, ResourceKind::Decompression),
        deadline,
        None,
      )
      .await
  }

  async fn admit(
    self: &Arc<Self>,
    allocations: Vec<Allocation>,
    deadline: Option<Instant>,
    exhausted_reason: Option<AdmissionRejectionReason>,
  ) -> Result<AdmissionLease, AdmissionRejection> {
    if !self.enabled() {
      return Ok(AdmissionLease::disabled());
    }
    let allocations = deduplicate_allocations(allocations);
    let mut waiter = QueuedWaiter::new(self.clone());
    loop {
      let notified = self.notify.notified();
      let admission = {
        let mut state = self
          .state
          .lock()
          .expect("circuit-breaker state lock poisoned");
        if !self.enabled() {
          if let Some(id) = waiter.take() {
            state.remove_waiter(id);
          }
          return Ok(AdmissionLease::disabled());
        }
        let is_head = waiter
          .id()
          .is_some_and(|id| state.waiters.front().is_some_and(|waiter| waiter.id == id));
        if (waiter.id().is_none() && state.waiters.is_empty()) || is_head {
          match state.circuit_available(&allocations, Instant::now()) {
            Ok(()) if state.can_admit(&allocations) => {
              match state.circuit_admission(&allocations, Instant::now()) {
                Ok(probes) => {
                  if let Some(id) = waiter.take()
                    && let Some(waiter) = state.remove_waiter(id)
                  {
                    state.queue_waits = state.queue_waits.saturating_add(1);
                    state.queue_wait_ms = state
                      .queue_wait_ms
                      .saturating_add(elapsed_ms(waiter.queued_at));
                  }
                  state.record_attempt(&allocations);
                  state.increment_active(&allocations);
                  Some(Ok(AdmissionLease::enabled(
                    self.clone(),
                    allocations.clone(),
                    probes,
                  )))
                }
                Err(retry_after) => {
                  if let Some(id) = waiter.take() {
                    state.remove_waiter(id);
                  }
                  state.reject(AdmissionRejectionReason::CircuitOpen);
                  Some(Err(AdmissionRejection {
                    reason: AdmissionRejectionReason::CircuitOpen,
                    retry_after,
                  }))
                }
              }
            }
            Ok(()) => None,
            Err(retry_after) => {
              if let Some(id) = waiter.take() {
                state.remove_waiter(id);
              }
              state.reject(AdmissionRejectionReason::CircuitOpen);
              Some(Err(AdmissionRejection {
                reason: AdmissionRejectionReason::CircuitOpen,
                retry_after,
              }))
            }
          }
        } else {
          None
        }
      };
      if let Some(result) = admission {
        return result;
      }

      if waiter.id().is_none() {
        let mut state = self
          .state
          .lock()
          .expect("circuit-breaker state lock poisoned");
        if !state.can_queue(&allocations) {
          let reason =
            exhausted_reason.unwrap_or_else(|| state.queue_rejection_reason(&allocations));
          state.reject(reason);
          return Err(AdmissionRejection {
            reason,
            retry_after: state.capacity_retry_after,
          });
        }
        let id = state.next_waiter;
        state.next_waiter = state.next_waiter.wrapping_add(1).max(1);
        state.enqueue(Waiter {
          id,
          allocations: allocations.clone(),
          queued_at: Instant::now(),
        });
        waiter.set(id);
      }

      let timeout = queue_timeout(&self.state, &allocations, deadline);
      if timeout.is_zero() {
        waiter.remove();
        return Err(self.timeout_rejection(exhausted_reason));
      }
      if tokio::time::timeout(timeout, notified).await.is_err() {
        waiter.remove();
        return Err(self.timeout_rejection(exhausted_reason));
      }
    }
  }

  fn timeout_rejection(
    &self,
    exhausted_reason: Option<AdmissionRejectionReason>,
  ) -> AdmissionRejection {
    let mut state = self
      .state
      .lock()
      .expect("circuit-breaker state lock poisoned");
    let reason = exhausted_reason.unwrap_or(AdmissionRejectionReason::QueueTimeout);
    state.reject(reason);
    AdmissionRejection {
      reason,
      retry_after: state.capacity_retry_after,
    }
  }

  pub(super) fn remove_waiter(&self, id: Option<u64>) {
    if let Some(id) = id {
      let mut state = self
        .state
        .lock()
        .expect("circuit-breaker state lock poisoned");
      if state.remove_waiter(id).is_some() {
        drop(state);
        self.notify.notify_waiters();
      }
    }
  }

  fn release(&self, allocations: &[Allocation], probes: &[ScopeKey], outcome: CircuitOutcome) {
    let mut state = self
      .state
      .lock()
      .expect("circuit-breaker state lock poisoned");
    state.decrement_active(allocations);
    if outcome == CircuitOutcome::Neutral {
      state.abandon_circuits(probes);
    } else {
      state.finish_circuits(probes, allocations, outcome);
    }
    drop(state);
    self.notify.notify_waiters();
  }
}

/// RAII admission permit. Dropping it releases every composite resource slot.
pub struct AdmissionLease {
  runtime: Option<Arc<CircuitBreakerRuntime>>,
  allocations: Vec<Allocation>,
  probes: Vec<ScopeKey>,
  outcome: CircuitOutcome,
}

impl std::fmt::Debug for AdmissionLease {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("AdmissionLease")
      .field("enabled", &self.runtime.is_some())
      .finish_non_exhaustive()
  }
}

impl AdmissionLease {
  fn disabled() -> Self {
    Self {
      runtime: None,
      allocations: Vec::new(),
      probes: Vec::new(),
      outcome: CircuitOutcome::Neutral,
    }
  }

  fn enabled(
    runtime: Arc<CircuitBreakerRuntime>,
    allocations: Vec<Allocation>,
    probes: Vec<ScopeKey>,
  ) -> Self {
    Self {
      runtime: Some(runtime),
      allocations,
      probes,
      outcome: CircuitOutcome::Neutral,
    }
  }

  pub fn record_outcome(&mut self, outcome: CircuitOutcome) {
    self.outcome = outcome;
  }
}

impl Drop for AdmissionLease {
  fn drop(&mut self) {
    if let Some(runtime) = self.runtime.take() {
      runtime.release(&self.allocations, &self.probes, self.outcome);
    }
  }
}
