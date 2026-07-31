//! Persistent, bounded Compio direct-H1 worker service.
//!
//! The public surface in this module is intentionally limited to a staged
//! process service. Snapshot construction may start and validate a replacement
//! fleet before publication, while activation itself remains infallible.

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::runtime::Handle;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

use crate::metrics::Metrics;
use crate::metrics::compio_direct_h1::{
  CompioDirectH1SubmissionOutcome, CompioDirectH1WorkerState,
};
use crate::runtime_health::{
  RuntimeHealth, RuntimeSubsystem, RuntimeSubsystemState, RuntimeTaskKind, RuntimeTaskPolicy,
};

mod connection_pool;
mod io;
mod transaction;
mod worker;

pub(super) use transaction::{
  CompioDirectH1Operation, CompioDirectH1OperationResult, CompioDirectH1PredispatchReason,
  CompioDirectH1Visibility,
};
use worker::{CompioDirectH1WorkerEndpoint, CompioDirectH1WorkerJoin, stage_worker};

pub(super) const SERVICE_STAGED: u8 = 0;
pub(super) const SERVICE_ACTIVE: u8 = 1;
pub(super) const SERVICE_DRAINING: u8 = 2;
pub(super) const SERVICE_STOPPED: u8 = 3;
pub(super) const SERVICE_UNHEALTHY: u8 = 4;
const MAX_SERVICE_WORKERS: usize = 256;
const MAX_TOTAL_QUEUED_OPERATIONS: usize = 65_536;
const WORKER_METRIC_STATES: [CompioDirectH1WorkerState; 5] = [
  CompioDirectH1WorkerState::Starting,
  CompioDirectH1WorkerState::Healthy,
  CompioDirectH1WorkerState::Unhealthy,
  CompioDirectH1WorkerState::Draining,
  CompioDirectH1WorkerState::Stopped,
];
const WORKER_STARTING_INDEX: usize = 0;
const WORKER_HEALTHY_INDEX: usize = 1;
const WORKER_UNHEALTHY_INDEX: usize = 2;
const WORKER_DRAINING_INDEX: usize = 3;
const WORKER_STOPPED_INDEX: usize = 4;

pub(super) struct WorkerMetricTracker {
  metrics: Arc<Metrics>,
  counts: Mutex<[usize; WORKER_METRIC_STATES.len()]>,
}

impl WorkerMetricTracker {
  fn new(metrics: Arc<Metrics>, workers: usize) -> Arc<Self> {
    let tracker = Arc::new(Self {
      metrics,
      counts: Mutex::new([0; WORKER_METRIC_STATES.len()]),
    });
    let mut starting = [0; WORKER_METRIC_STATES.len()];
    starting[WORKER_STARTING_INDEX] = workers;
    tracker.transition(starting);
    tracker
  }

  fn transition(&self, next: [usize; WORKER_METRIC_STATES.len()]) {
    let mut current = self
      .counts
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (index, state) in WORKER_METRIC_STATES.into_iter().enumerate() {
      let delta = if next[index] >= current[index] {
        (next[index] - current[index]) as isize
      } else {
        -((current[index] - next[index]) as isize)
      };
      if delta != 0 {
        self
          .metrics
          .adjust_compio_direct_h1_worker_count(state, delta);
      }
    }
    *current = next;
  }

  fn mark_healthy(&self, workers: usize) {
    let mut healthy = [0; WORKER_METRIC_STATES.len()];
    healthy[WORKER_HEALTHY_INDEX] = workers;
    self.transition(healthy);
  }

  fn begin_drain(&self) {
    let mut current = self
      .counts
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    let starting = current[WORKER_STARTING_INDEX];
    let healthy = current[WORKER_HEALTHY_INDEX];
    let moved = starting.saturating_add(healthy);
    if moved == 0 {
      return;
    }
    current[WORKER_STARTING_INDEX] = 0;
    current[WORKER_HEALTHY_INDEX] = 0;
    current[WORKER_DRAINING_INDEX] = current[WORKER_DRAINING_INDEX].saturating_add(moved);
    if starting != 0 {
      self.metrics.adjust_compio_direct_h1_worker_count(
        CompioDirectH1WorkerState::Starting,
        -(starting as isize),
      );
    }
    if healthy != 0 {
      self.metrics.adjust_compio_direct_h1_worker_count(
        CompioDirectH1WorkerState::Healthy,
        -(healthy as isize),
      );
    }
    self
      .metrics
      .adjust_compio_direct_h1_worker_count(CompioDirectH1WorkerState::Draining, moved as isize);
  }

  pub(super) fn mark_one_unhealthy(&self) {
    let mut current = self
      .counts
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(source) = [
      WORKER_HEALTHY_INDEX,
      WORKER_DRAINING_INDEX,
      WORKER_STARTING_INDEX,
    ]
    .into_iter()
    .find(|index| current[*index] != 0) else {
      return;
    };
    current[source] -= 1;
    current[WORKER_UNHEALTHY_INDEX] = current[WORKER_UNHEALTHY_INDEX].saturating_add(1);
    self
      .metrics
      .adjust_compio_direct_h1_worker_count(WORKER_METRIC_STATES[source], -1);
    self
      .metrics
      .adjust_compio_direct_h1_worker_count(CompioDirectH1WorkerState::Unhealthy, 1);
  }

  fn mark_terminal(&self, joined: usize, failures: usize) {
    let mut terminal = [0; WORKER_METRIC_STATES.len()];
    terminal[WORKER_STOPPED_INDEX] = joined;
    terminal[WORKER_UNHEALTHY_INDEX] = failures;
    self.transition(terminal);
  }

  fn release(&self) {
    self.transition([0; WORKER_METRIC_STATES.len()]);
  }
}

/// Immutable resource plan for one persistent worker fleet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompioDirectH1ServicePlan {
  pub(crate) generation: u64,
  pub(crate) worker_count: usize,
  pub(crate) queue_capacity_per_worker: usize,
  pub(crate) max_waiters: usize,
  pub(crate) queue_wait_timeout: Duration,
  pub(crate) max_connections_global: usize,
  pub(crate) max_connections_per_origin: usize,
}

impl CompioDirectH1ServicePlan {
  fn validate(&self) -> anyhow::Result<()> {
    if self.worker_count == 0 {
      bail!("Compio direct-H1 service worker_count must be greater than zero");
    }
    if self.worker_count > MAX_SERVICE_WORKERS {
      bail!(
        "Compio direct-H1 service worker_count exceeds the bounded maximum of {MAX_SERVICE_WORKERS}"
      );
    }
    if self.queue_capacity_per_worker == 0 {
      bail!("Compio direct-H1 service queue capacity must be greater than zero");
    }
    if self.queue_wait_timeout.is_zero() {
      bail!("Compio direct-H1 service queue wait timeout must be greater than zero");
    }
    if self.max_connections_global == 0 || self.max_connections_per_origin == 0 {
      bail!("Compio direct-H1 service connection limits must be greater than zero");
    }
    let total_queue_capacity = self
      .worker_count
      .checked_mul(self.queue_capacity_per_worker)
      .context("Compio direct-H1 worker queue capacity overflow")?;
    if total_queue_capacity > MAX_TOTAL_QUEUED_OPERATIONS {
      bail!(
        "Compio direct-H1 total queue capacity exceeds the bounded maximum of \
         {MAX_TOTAL_QUEUED_OPERATIONS}"
      );
    }
    if self.max_waiters > MAX_TOTAL_QUEUED_OPERATIONS {
      bail!(
        "Compio direct-H1 max_waiters exceeds the bounded maximum of \
         {MAX_TOTAL_QUEUED_OPERATIONS}"
      );
    }
    let combined_capacity = total_queue_capacity
      .checked_add(self.max_waiters)
      .context("Compio direct-H1 combined queue and waiter capacity overflow")?;
    if combined_capacity > MAX_TOTAL_QUEUED_OPERATIONS {
      bail!(
        "Compio direct-H1 combined queue and waiter capacity exceeds the bounded maximum of \
         {MAX_TOTAL_QUEUED_OPERATIONS}"
      );
    }
    Ok(())
  }
}

/// Bounded final diagnostic summary returned after all worker joins.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompioDirectH1ShutdownSummary {
  pub(crate) workers_started: usize,
  pub(crate) workers_joined: usize,
  pub(crate) worker_failures: usize,
  pub(crate) operations_cancelled: usize,
  pub(crate) queued_operations_rejected: usize,
}

/// Cloneable prepublication token for a fully started but non-accepting fleet.
#[derive(Clone)]
pub(crate) struct CompioDirectH1Staged {
  service: Arc<CompioDirectH1Service>,
}

impl CompioDirectH1Staged {
  pub(crate) fn service(&self) -> Arc<CompioDirectH1Service> {
    Arc::clone(&self.service)
  }

  /// Activate the staged fleet. Repeated calls update publication metadata and
  /// return the same service.
  pub(crate) fn activate(
    &self,
    runtime_generation: u64,
    required: bool,
  ) -> Arc<CompioDirectH1Service> {
    self
      .service
      .activate_generation(self.service.plan.generation, runtime_generation, required);
    Arc::clone(&self.service)
  }
}

/// Process service owning the persistent Compio worker fleet.
pub(crate) struct CompioDirectH1Service {
  plan: CompioDirectH1ServicePlan,
  metrics: Arc<Metrics>,
  runtime_health: Arc<RuntimeHealth>,
  state: Arc<AtomicU8>,
  runtime_generation: Arc<AtomicU64>,
  active_plan_generation: AtomicU64,
  required: Arc<AtomicBool>,
  operation_admission: Arc<Semaphore>,
  waiters: AtomicUsize,
  queue_occupancy: Vec<Arc<AtomicUsize>>,
  active_operations: Vec<Arc<AtomicUsize>>,
  cancelled_operations: Arc<AtomicUsize>,
  rejected_queued_operations: Arc<AtomicUsize>,
  worker_metrics: Arc<WorkerMetricTracker>,
  workers: Vec<CompioDirectH1WorkerEndpoint>,
  joins: Mutex<Option<Vec<CompioDirectH1WorkerJoin>>>,
  shutdown_lock: AsyncMutex<()>,
  shutdown_summary: Mutex<Option<CompioDirectH1ShutdownSummary>>,
  shutdown_deadline_origin: std::time::Instant,
  shutdown_deadline_nanos: AtomicU64,
}

impl CompioDirectH1Service {
  /// Start and validate a non-accepting replacement worker fleet.
  pub(crate) fn stage(
    plan: CompioDirectH1ServicePlan,
    metrics: Arc<Metrics>,
    tokio_handle: Handle,
    runtime_health: Arc<RuntimeHealth>,
  ) -> anyhow::Result<CompioDirectH1Staged> {
    plan.validate()?;
    let state = Arc::new(AtomicU8::new(SERVICE_STAGED));
    let runtime_generation = Arc::new(AtomicU64::new(0));
    let required = Arc::new(AtomicBool::new(false));
    let mut queue_occupancy = Vec::with_capacity(plan.worker_count);
    let mut active_operations = Vec::with_capacity(plan.worker_count);
    let cancelled_operations = Arc::new(AtomicUsize::new(0));
    let rejected_queued_operations = Arc::new(AtomicUsize::new(0));
    let connection_budget = Arc::new(connection_pool::GlobalConnectionBudget::new(
      plan.max_connections_global,
      Arc::clone(&metrics),
    ));
    let operation_admission = Arc::new(Semaphore::new(plan.max_connections_global));
    let worker_metrics = WorkerMetricTracker::new(Arc::clone(&metrics), plan.worker_count);
    let mut workers = Vec::with_capacity(plan.worker_count);
    let mut joins = Vec::with_capacity(plan.worker_count);

    for worker_index in 0..plan.worker_count {
      let worker_queue_occupancy = Arc::new(AtomicUsize::new(0));
      let worker_active_operations = Arc::new(AtomicUsize::new(0));
      match stage_worker(
        worker_index,
        &plan,
        Arc::clone(&metrics),
        tokio_handle.clone(),
        Arc::clone(&worker_queue_occupancy),
        Arc::clone(&worker_active_operations),
        Arc::clone(&cancelled_operations),
        Arc::clone(&rejected_queued_operations),
        Arc::clone(&connection_budget),
        Arc::clone(&state),
        Arc::clone(&runtime_generation),
        Arc::clone(&required),
        Arc::clone(&runtime_health),
        Arc::clone(&worker_metrics),
      ) {
        Ok((endpoint, join)) => {
          workers.push(endpoint);
          joins.push(join);
          queue_occupancy.push(worker_queue_occupancy);
          active_operations.push(worker_active_operations);
        }
        Err(error) => {
          for endpoint in &workers {
            endpoint.force_stop();
          }
          for join in joins {
            join.join_blocking();
          }
          worker_metrics.release();
          return Err(error);
        }
      }
    }

    worker_metrics.mark_healthy(plan.worker_count);
    let service = Arc::new(Self {
      active_plan_generation: AtomicU64::new(plan.generation),
      plan,
      metrics,
      runtime_health,
      state,
      runtime_generation,
      required,
      operation_admission,
      waiters: AtomicUsize::new(0),
      queue_occupancy,
      active_operations,
      cancelled_operations,
      rejected_queued_operations,
      worker_metrics,
      workers,
      joins: Mutex::new(Some(joins)),
      shutdown_lock: AsyncMutex::new(()),
      shutdown_summary: Mutex::new(None),
      shutdown_deadline_origin: std::time::Instant::now(),
      shutdown_deadline_nanos: AtomicU64::new(u64::MAX),
    });
    Ok(CompioDirectH1Staged { service })
  }

  pub(crate) fn plan(&self) -> &CompioDirectH1ServicePlan {
    &self.plan
  }

  /// Refresh publication metadata and make a staged service accepting.
  pub(crate) fn activate_generation(
    &self,
    plan_generation: u64,
    runtime_generation: u64,
    required: bool,
  ) {
    self
      .active_plan_generation
      .store(plan_generation, Ordering::Release);
    self
      .runtime_generation
      .store(runtime_generation, Ordering::Release);
    self.required.store(required, Ordering::Release);
    let _ = self.state.compare_exchange(
      SERVICE_STAGED,
      SERVICE_ACTIVE,
      Ordering::AcqRel,
      Ordering::Acquire,
    );
    let healthy = self.state.load(Ordering::Acquire) == SERVICE_ACTIVE
      && self
        .workers
        .iter()
        .all(CompioDirectH1WorkerEndpoint::is_healthy);
    if !healthy {
      self.state.store(SERVICE_UNHEALTHY, Ordering::Release);
    }
    let policy = if required {
      RuntimeTaskPolicy::RestartableCritical
    } else {
      RuntimeTaskPolicy::RestartableOptional
    };
    self.runtime_health.set_subsystem_state(
      runtime_generation,
      RuntimeSubsystem::CompioDirectH1,
      if healthy {
        RuntimeSubsystemState::Healthy
      } else {
        RuntimeSubsystemState::Failed
      },
      required,
    );
    self.runtime_health.set_task_state(
      runtime_generation,
      RuntimeTaskKind::CompioDirectH1Worker,
      policy,
      if healthy {
        RuntimeSubsystemState::Healthy
      } else {
        RuntimeSubsystemState::Failed
      },
    );
  }

  pub(crate) fn is_healthy(&self) -> bool {
    self.state.load(Ordering::Acquire) == SERVICE_ACTIVE
      && self
        .workers
        .iter()
        .all(CompioDirectH1WorkerEndpoint::is_healthy)
  }

  pub(crate) fn is_required(&self) -> bool {
    self.required.load(Ordering::Acquire)
  }

  /// Stop intake. Already admitted work remains bounded by the worker queues.
  pub(crate) fn begin_drain(&self) {
    loop {
      let current = self.state.load(Ordering::Acquire);
      if matches!(current, SERVICE_DRAINING | SERVICE_STOPPED) {
        return;
      }
      if self
        .state
        .compare_exchange_weak(
          current,
          SERVICE_DRAINING,
          Ordering::AcqRel,
          Ordering::Acquire,
        )
        .is_ok()
      {
        break;
      }
    }
    // Closing is the intake fence for both existing and future admission
    // waiters. Owned permits remain charged until predispatch returns or the
    // worker reaches terminal driver ownership.
    self.operation_admission.close();
    self.worker_metrics.begin_drain();
    for worker in &self.workers {
      worker.begin_drain();
    }
  }

  /// Stop intake, wait to the supplied deadline, cancel remaining operations,
  /// and join every worker. Repeated and concurrent calls are idempotent.
  pub(crate) async fn shutdown(
    &self,
    deadline: tokio::time::Instant,
  ) -> CompioDirectH1ShutdownSummary {
    self.tighten_shutdown_deadline(deadline);
    let _shutdown = self.shutdown_lock.lock().await;
    if let Some(summary) = *self
      .shutdown_summary
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
    {
      return summary;
    }
    self.begin_drain();
    while (counters_nonzero(&self.active_operations)
      || counters_nonzero(&self.queue_occupancy)
      || self.operation_admission.available_permits() != self.plan.max_connections_global)
      && !self.shutdown_deadline_expired()
    {
      tokio::time::sleep(Duration::from_millis(2)).await;
    }
    for worker in &self.workers {
      worker.force_stop();
    }

    let joins = self
      .joins
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .take()
      .unwrap_or_default();
    let workers_started = joins.len();
    let mut workers_joined = 0;
    let mut worker_failures = 0;
    for join in joins {
      match tokio::task::spawn_blocking(move || join.join()).await {
        Ok(true) => workers_joined += 1,
        Ok(false) | Err(_) => worker_failures += 1,
      }
    }
    for active in &self.active_operations {
      active.store(0, Ordering::Release);
    }
    let residual_queue = self
      .queue_occupancy
      .iter()
      .map(|queue| queue.swap(0, Ordering::AcqRel))
      .fold(0usize, usize::saturating_add);
    if residual_queue != 0 {
      self
        .metrics
        .adjust_compio_direct_h1_queue_occupancy(-(residual_queue as isize));
      self
        .rejected_queued_operations
        .fetch_add(residual_queue, Ordering::AcqRel);
    }
    self.state.store(
      if worker_failures == 0 {
        SERVICE_STOPPED
      } else {
        SERVICE_UNHEALTHY
      },
      Ordering::Release,
    );
    self
      .worker_metrics
      .mark_terminal(workers_joined, worker_failures);
    self.runtime_health.set_subsystem_state(
      self.runtime_generation.load(Ordering::Acquire),
      RuntimeSubsystem::CompioDirectH1,
      if worker_failures == 0 {
        RuntimeSubsystemState::Healthy
      } else {
        RuntimeSubsystemState::Failed
      },
      false,
    );
    self.runtime_health.set_task_state(
      self.runtime_generation.load(Ordering::Acquire),
      RuntimeTaskKind::CompioDirectH1Worker,
      RuntimeTaskPolicy::Contained,
      if worker_failures == 0 {
        RuntimeSubsystemState::Healthy
      } else {
        RuntimeSubsystemState::Failed
      },
    );
    let summary = CompioDirectH1ShutdownSummary {
      workers_started,
      workers_joined,
      worker_failures,
      operations_cancelled: self.cancelled_operations.load(Ordering::Acquire),
      queued_operations_rejected: self.rejected_queued_operations.load(Ordering::Acquire),
    };
    *self
      .shutdown_summary
      .lock()
      .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(summary);
    summary
  }

  pub(super) async fn execute(
    self: &Arc<Self>,
    mut operation: CompioDirectH1Operation,
  ) -> CompioDirectH1OperationResult {
    match self.state.load(Ordering::Acquire) {
      SERVICE_DRAINING | SERVICE_STOPPED => {
        self
          .metrics
          .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Draining);
        return operation.predispatch(CompioDirectH1PredispatchReason::Draining);
      }
      SERVICE_ACTIVE => {}
      _ => {
        self
          .metrics
          .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Unhealthy);
        return operation.predispatch(CompioDirectH1PredispatchReason::Unhealthy);
      }
    }

    let worker_index = operation.pool.compio_worker_shard(self.workers.len());
    let worker = &self.workers[worker_index];
    if !worker.is_healthy() {
      self
        .metrics
        .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Unhealthy);
      return operation.predispatch(CompioDirectH1PredispatchReason::Unhealthy);
    }

    let queued_at = std::time::Instant::now();
    let mut waited = false;
    let operation_permit = match Arc::clone(&self.operation_admission).try_acquire_owned() {
      Ok(permit) => permit,
      Err(tokio::sync::TryAcquireError::Closed) => {
        let (outcome, reason) = if matches!(
          self.state.load(Ordering::Acquire),
          SERVICE_DRAINING | SERVICE_STOPPED
        ) {
          (
            CompioDirectH1SubmissionOutcome::Draining,
            CompioDirectH1PredispatchReason::Draining,
          )
        } else {
          (
            CompioDirectH1SubmissionOutcome::Unhealthy,
            CompioDirectH1PredispatchReason::Unhealthy,
          )
        };
        self.metrics.record_compio_direct_h1_submission(outcome);
        return operation.predispatch(reason);
      }
      Err(tokio::sync::TryAcquireError::NoPermits) => {
        let Some(_waiter) = WaiterGuard::try_acquire(&self.waiters, self.plan.max_waiters) else {
          self
            .metrics
            .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Full);
          return operation.predispatch(CompioDirectH1PredispatchReason::QueueFull);
        };
        match tokio::time::timeout(
          self.plan.queue_wait_timeout,
          Arc::clone(&self.operation_admission).acquire_owned(),
        )
        .await
        {
          Ok(Ok(permit)) => {
            waited = true;
            permit
          }
          Ok(Err(_)) => {
            let (outcome, reason) = if matches!(
              self.state.load(Ordering::Acquire),
              SERVICE_DRAINING | SERVICE_STOPPED
            ) {
              (
                CompioDirectH1SubmissionOutcome::Draining,
                CompioDirectH1PredispatchReason::Draining,
              )
            } else {
              (
                CompioDirectH1SubmissionOutcome::Unhealthy,
                CompioDirectH1PredispatchReason::Unhealthy,
              )
            };
            self.metrics.record_compio_direct_h1_submission(outcome);
            return operation.predispatch(reason);
          }
          Err(_) => {
            self
              .metrics
              .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Full);
            return operation.predispatch(CompioDirectH1PredispatchReason::QueueFull);
          }
        }
      }
    };

    if self.state.load(Ordering::Acquire) != SERVICE_ACTIVE {
      self
        .metrics
        .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Draining);
      return operation.predispatch(CompioDirectH1PredispatchReason::Draining);
    }
    let handoff = match worker.sender().try_reserve_owned() {
      Ok(handoff) => handoff,
      Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
        let (outcome, reason) = if matches!(
          self.state.load(Ordering::Acquire),
          SERVICE_DRAINING | SERVICE_STOPPED
        ) {
          (
            CompioDirectH1SubmissionOutcome::Draining,
            CompioDirectH1PredispatchReason::Draining,
          )
        } else {
          (
            CompioDirectH1SubmissionOutcome::Unhealthy,
            CompioDirectH1PredispatchReason::Unhealthy,
          )
        };
        self.metrics.record_compio_direct_h1_submission(outcome);
        return operation.predispatch(reason);
      }
      Err(tokio::sync::mpsc::error::TrySendError::Full(sender)) => {
        // The operation permit bounds these handoff waiters together with
        // active operations. Spend only the remainder of the same queue
        // deadline used for admission so no second full timeout is introduced.
        let remaining = self
          .plan
          .queue_wait_timeout
          .saturating_sub(queued_at.elapsed());
        if remaining.is_zero() {
          self
            .metrics
            .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Full);
          return operation.predispatch(CompioDirectH1PredispatchReason::QueueFull);
        }
        let cancellation = operation.cancellation.clone();
        let reserved = tokio::select! {
          biased;
          _ = cancellation.cancelled() => {
            return operation.predispatch(CompioDirectH1PredispatchReason::Cancelled);
          }
          reserved = tokio::time::timeout(remaining, sender.reserve_owned()) => reserved,
        };
        match reserved {
          Ok(Ok(handoff)) => {
            waited = true;
            handoff
          }
          Ok(Err(_)) => {
            let (outcome, reason) = if matches!(
              self.state.load(Ordering::Acquire),
              SERVICE_DRAINING | SERVICE_STOPPED
            ) {
              (
                CompioDirectH1SubmissionOutcome::Draining,
                CompioDirectH1PredispatchReason::Draining,
              )
            } else {
              (
                CompioDirectH1SubmissionOutcome::Unhealthy,
                CompioDirectH1PredispatchReason::Unhealthy,
              )
            };
            self.metrics.record_compio_direct_h1_submission(outcome);
            return operation.predispatch(reason);
          }
          Err(_) => {
            self
              .metrics
              .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Full);
            return operation.predispatch(CompioDirectH1PredispatchReason::QueueFull);
          }
        }
      }
    };
    if self.state.load(Ordering::Acquire) != SERVICE_ACTIVE {
      self
        .metrics
        .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Draining);
      return operation.predispatch(CompioDirectH1PredispatchReason::Draining);
    }
    if waited {
      self
        .metrics
        .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Waited);
      self
        .metrics
        .observe_compio_direct_h1_wait(queued_at.elapsed());
    } else {
      self
        .metrics
        .record_compio_direct_h1_submission(CompioDirectH1SubmissionOutcome::Immediate);
    }
    operation.set_admission_permit(operation_permit);
    let (operation, completion) = operation.with_completion();
    self.queue_occupancy[worker_index].fetch_add(1, Ordering::AcqRel);
    self.metrics.adjust_compio_direct_h1_queue_occupancy(1);
    handoff.send(operation);
    match completion.await {
      Ok(result) => result,
      Err(_) => CompioDirectH1OperationResult::Failed {
        visibility: CompioDirectH1Visibility::WriteSubmitted,
        bytes_written: 0,
        source: anyhow::anyhow!("Compio direct-H1 worker ended without a completion outcome"),
      },
    }
  }

  fn tighten_shutdown_deadline(&self, deadline: tokio::time::Instant) {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let elapsed = self.shutdown_deadline_origin.elapsed();
    let nanos = elapsed
      .checked_add(remaining)
      .map(|duration| duration.as_nanos().min(u128::from(u64::MAX)) as u64)
      .unwrap_or(u64::MAX);
    let _ = self
      .shutdown_deadline_nanos
      .fetch_min(nanos, Ordering::AcqRel);
  }

  fn shutdown_deadline_expired(&self) -> bool {
    let elapsed = self
      .shutdown_deadline_origin
      .elapsed()
      .as_nanos()
      .min(u128::from(u64::MAX)) as u64;
    elapsed >= self.shutdown_deadline_nanos.load(Ordering::Acquire)
  }
}

impl Drop for CompioDirectH1Service {
  fn drop(&mut self) {
    for worker in &self.workers {
      worker.begin_drain();
      worker.force_stop();
    }
    let joins = self
      .joins
      .get_mut()
      .unwrap_or_else(|poisoned| poisoned.into_inner())
      .take()
      .unwrap_or_default();
    for join in joins {
      join.join_blocking();
    }
    self.worker_metrics.release();
  }
}

fn counters_nonzero(counters: &[Arc<AtomicUsize>]) -> bool {
  counters
    .iter()
    .any(|counter| counter.load(Ordering::Acquire) != 0)
}

struct WaiterGuard<'a> {
  waiters: &'a AtomicUsize,
}

impl<'a> WaiterGuard<'a> {
  fn try_acquire(waiters: &'a AtomicUsize, limit: usize) -> Option<Self> {
    let mut current = waiters.load(Ordering::Acquire);
    loop {
      if current >= limit {
        return None;
      }
      match waiters.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
      {
        Ok(_) => return Some(Self { waiters }),
        Err(observed) => current = observed,
      }
    }
  }
}

impl Drop for WaiterGuard<'_> {
  fn drop(&mut self) {
    self.waiters.fetch_sub(1, Ordering::AcqRel);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_plan() -> CompioDirectH1ServicePlan {
    CompioDirectH1ServicePlan {
      generation: 7,
      worker_count: 1,
      queue_capacity_per_worker: 2,
      max_waiters: 1,
      queue_wait_timeout: Duration::from_millis(25),
      max_connections_global: 2,
      max_connections_per_origin: 2,
    }
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn required_post_activation_worker_failure_fails_readiness() -> anyhow::Result<()> {
    let metrics = Metrics::new();
    let runtime_health = Arc::new(RuntimeHealth::default());
    let runtime_generation = runtime_health.allocate_generation();
    runtime_health.activate_generation(runtime_generation);
    let staged = CompioDirectH1Service::stage(
      test_plan(),
      metrics,
      Handle::current(),
      Arc::clone(&runtime_health),
    )?;
    let service = staged.activate(runtime_generation, true);
    assert!(runtime_health.is_ready());

    service.workers[0].fail_for_test();
    tokio::time::timeout(Duration::from_secs(2), async {
      while service.workers[0].is_healthy() {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    assert!(!service.is_healthy());
    assert!(
      !runtime_health.is_ready(),
      "a required activated Compio worker failure must fail readiness"
    );
    let summary = service
      .shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
      .await;
    assert_eq!(summary.worker_failures, 1);
    Ok(())
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn active_operation_admission_uses_the_global_connection_ceiling() -> anyhow::Result<()> {
    let metrics = Metrics::new();
    let runtime_health = Arc::new(RuntimeHealth::default());
    let staged = CompioDirectH1Service::stage(
      test_plan(),
      metrics,
      Handle::current(),
      Arc::clone(&runtime_health),
    )?;
    let service = staged.service();

    let first = Arc::clone(&service.operation_admission).try_acquire_owned()?;
    let second = Arc::clone(&service.operation_admission).try_acquire_owned()?;
    assert_eq!(service.operation_admission.available_permits(), 0);
    assert!(matches!(
      Arc::clone(&service.operation_admission).try_acquire_owned(),
      Err(tokio::sync::TryAcquireError::NoPermits)
    ));

    drop(first);
    let replacement = Arc::clone(&service.operation_admission).try_acquire_owned()?;
    assert_eq!(service.operation_admission.available_permits(), 0);
    drop((second, replacement));
    assert_eq!(service.operation_admission.available_permits(), 2);

    let summary = service
      .shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
      .await;
    assert_eq!(summary.worker_failures, 0);
    Ok(())
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn drain_closes_admission_and_wakes_waiters() -> anyhow::Result<()> {
    let metrics = Metrics::new();
    let runtime_health = Arc::new(RuntimeHealth::default());
    let staged = CompioDirectH1Service::stage(
      test_plan(),
      metrics,
      Handle::current(),
      Arc::clone(&runtime_health),
    )?;
    let service = staged.service();
    let first = Arc::clone(&service.operation_admission).try_acquire_owned()?;
    let second = Arc::clone(&service.operation_admission).try_acquire_owned()?;
    let admission = Arc::clone(&service.operation_admission);
    let waiter = tokio::spawn(async move { admission.acquire_owned().await });
    tokio::task::yield_now().await;

    service.begin_drain();
    let result = tokio::time::timeout(Duration::from_millis(100), waiter).await??;
    assert!(
      result.is_err(),
      "drain must close and wake admission waiters"
    );

    drop((first, second));
    let summary = service
      .shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
      .await;
    assert_eq!(summary.worker_failures, 0);
    Ok(())
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn dropping_unactivated_fleet_releases_worker_metric_ownership() -> anyhow::Result<()> {
    let metrics = Metrics::new();
    let runtime_health = Arc::new(RuntimeHealth::default());
    let staged = CompioDirectH1Service::stage(
      test_plan(),
      Arc::clone(&metrics),
      Handle::current(),
      runtime_health,
    )?;
    assert_eq!(
      metrics.compio_direct_h1_worker_count(CompioDirectH1WorkerState::Healthy),
      1
    );

    drop(staged);

    for state in WORKER_METRIC_STATES {
      assert_eq!(
        metrics.compio_direct_h1_worker_count(state),
        0,
        "dropped fleet retained worker-state metric ownership for {state:?}"
      );
    }
    Ok(())
  }

  #[test]
  fn plan_rejects_zero_and_overflowing_bounded_resources() {
    let mut plan = test_plan();
    plan.worker_count = 0;
    assert!(plan.validate().is_err());

    let mut plan = test_plan();
    plan.worker_count = usize::MAX;
    plan.queue_capacity_per_worker = 2;
    assert!(plan.validate().is_err());

    let mut plan = test_plan();
    plan.worker_count = 2;
    plan.queue_capacity_per_worker = MAX_TOTAL_QUEUED_OPERATIONS / 2;
    plan.max_waiters = 1;
    assert!(
      plan.validate().is_err(),
      "the physical worker queues and external waiters share one hard bound"
    );

    let mut plan = test_plan();
    plan.worker_count = 1;
    plan.queue_capacity_per_worker = MAX_TOTAL_QUEUED_OPERATIONS;
    plan.max_waiters = 0;
    assert!(plan.validate().is_ok());
  }
}
