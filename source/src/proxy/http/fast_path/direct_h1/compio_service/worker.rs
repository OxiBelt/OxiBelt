//! One persistent Compio runtime and bounded submission shard.

use std::cell::RefCell;
use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::thread::{self, JoinHandle};

use anyhow::Context;
use compio_driver::{DriverType, ProactorBuilder};
use futures_util::FutureExt as _;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};

use crate::metrics::Metrics;
use crate::runtime_health::{
  RuntimeHealth, RuntimePanicScope, RuntimeSubsystem, RuntimeSubsystemState, RuntimeTaskKind,
  RuntimeTaskPolicy,
};

use super::super::compio_transport::cancellation::CancellationToken;
use super::connection_pool::{GlobalConnectionBudget, WorkerConnectionPool};
use super::transaction::{CompioDirectH1Operation, CompioDirectH1PredispatchReason, run_operation};
use super::{CompioDirectH1ServicePlan, WorkerMetricTracker};

const WORKER_RUNNING: u8 = 0;
const WORKER_DRAINING: u8 = 1;
const WORKER_STOPPING: u8 = 2;
#[cfg(test)]
const WORKER_FAILING: u8 = 3;

pub(super) struct CompioDirectH1WorkerEndpoint {
  sender: mpsc::Sender<CompioDirectH1Operation>,
  command: watch::Sender<u8>,
  healthy: Arc<AtomicBool>,
}

impl CompioDirectH1WorkerEndpoint {
  pub(super) fn sender(&self) -> mpsc::Sender<CompioDirectH1Operation> {
    self.sender.clone()
  }

  pub(super) fn is_healthy(&self) -> bool {
    self.healthy.load(Ordering::Acquire)
  }

  pub(super) fn begin_drain(&self) {
    self.command.send_if_modified(|current| {
      if *current == WORKER_RUNNING {
        *current = WORKER_DRAINING;
        true
      } else {
        false
      }
    });
  }

  pub(super) fn force_stop(&self) {
    self.command.send_replace(WORKER_STOPPING);
  }

  #[cfg(test)]
  pub(super) fn fail_for_test(&self) {
    self.command.send_replace(WORKER_FAILING);
  }
}

pub(super) struct CompioDirectH1WorkerJoin {
  join: Option<JoinHandle<bool>>,
}

impl CompioDirectH1WorkerJoin {
  pub(super) fn join(mut self) -> bool {
    self
      .join
      .take()
      .is_some_and(|join| join.join().unwrap_or(false))
  }

  pub(super) fn join_blocking(self) {
    let _ = self.join();
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn stage_worker(
  worker_index: usize,
  plan: &CompioDirectH1ServicePlan,
  metrics: Arc<Metrics>,
  tokio_handle: Handle,
  queue_occupancy: Arc<AtomicUsize>,
  active_operations: Arc<AtomicUsize>,
  cancelled_operations: Arc<AtomicUsize>,
  rejected_queued_operations: Arc<AtomicUsize>,
  connection_budget: Arc<GlobalConnectionBudget>,
  service_state: Arc<AtomicU8>,
  runtime_generation: Arc<AtomicU64>,
  required: Arc<AtomicBool>,
  runtime_health: Arc<RuntimeHealth>,
  worker_metrics: Arc<WorkerMetricTracker>,
) -> anyhow::Result<(CompioDirectH1WorkerEndpoint, CompioDirectH1WorkerJoin)> {
  let (sender, receiver) = mpsc::channel(plan.queue_capacity_per_worker);
  let (command, command_receiver) = watch::channel(WORKER_RUNNING);
  let healthy = Arc::new(AtomicBool::new(false));
  let (startup_sender, startup_receiver) = std_mpsc::sync_channel(1);

  let endpoint = CompioDirectH1WorkerEndpoint {
    sender,
    command,
    healthy: Arc::clone(&healthy),
  };
  let worker_plan = plan.clone();
  let thread_name = format!("oxibelt-compio-h1-{worker_index}");
  let join = thread::Builder::new()
    .name(thread_name)
    .spawn(move || {
      let result = catch_unwind(AssertUnwindSafe(|| {
        let runtime = build_worker_runtime();
        let runtime = match runtime {
          Ok(runtime) => {
            healthy.store(true, Ordering::Release);
            let _ = startup_sender.send(Ok(()));
            runtime
          }
          Err(error) => {
            let message = error.to_string();
            let _ = startup_sender.send(Err(anyhow::anyhow!(message)));
            return false;
          }
        };
        let outcome = runtime.block_on(run_worker(
          receiver,
          command_receiver,
          worker_plan,
          metrics,
          tokio_handle,
          queue_occupancy,
          active_operations,
          cancelled_operations,
          rejected_queued_operations,
          connection_budget,
        ));
        if outcome == WorkerExit::Unexpected {
          worker_metrics.mark_one_unhealthy();
          publish_failure(
            &service_state,
            &runtime_generation,
            &required,
            &runtime_health,
            false,
          );
          healthy.store(false, Ordering::Release);
          false
        } else {
          healthy.store(false, Ordering::Release);
          true
        }
      }));
      match result {
        Ok(success) => success,
        Err(_) => {
          worker_metrics.mark_one_unhealthy();
          publish_failure(
            &service_state,
            &runtime_generation,
            &required,
            &runtime_health,
            true,
          );
          healthy.store(false, Ordering::Release);
          false
        }
      }
    })
    .context("failed to spawn persistent Compio direct-H1 worker")?;

  match startup_receiver.recv() {
    Ok(Ok(())) => Ok((endpoint, CompioDirectH1WorkerJoin { join: Some(join) })),
    Ok(Err(error)) => {
      let _ = join.join();
      Err(error)
    }
    Err(_) => {
      let _ = join.join();
      Err(anyhow::anyhow!(
        "Compio direct-H1 worker exited before startup handshake"
      ))
    }
  }
}

fn build_worker_runtime() -> anyhow::Result<compio::runtime::Runtime> {
  match build_worker_runtime_for_driver(DriverType::IoUring, true) {
    Ok(runtime) => Ok(runtime),
    Err(optimized_error) => match build_worker_runtime_for_driver(DriverType::IoUring, false) {
      Ok(runtime) => Ok(runtime),
      Err(conservative_error) => build_worker_runtime_for_driver(DriverType::Poll, false)
        .with_context(|| {
          format!(
            "failed to build persistent Compio direct-H1 runtime after optimized io_uring \
             ({optimized_error}) and conservative io_uring ({conservative_error}) were rejected"
          )
        }),
    },
  }
}

fn build_worker_runtime_for_driver(
  driver_type: DriverType,
  optimized: bool,
) -> anyhow::Result<compio::runtime::Runtime> {
  let mut proactor = ProactorBuilder::new();
  proactor.thread_pool_limit(0);
  proactor.driver_type(driver_type);
  if optimized {
    // Each service worker is the only issuer for its Proactor. These kernel
    // hints reduce task-work interrupts and defer completion work to the
    // worker's existing driver entry. Older kernels can reject the setup, in
    // which case `build_worker_runtime` retries the conservative builder.
    proactor.single_issuer(true);
    proactor.coop_taskrun(true);
    proactor.taskrun_flag(true);
    proactor.defer_taskrun(true);
  }
  let mut runtime_builder = compio::runtime::RuntimeBuilder::new();
  runtime_builder.with_proactor(proactor);
  runtime_builder
    .build()
    .context("failed to build persistent Compio direct-H1 runtime")
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WorkerExit {
  Stopped,
  Unexpected,
}

struct ActiveOperationGuard {
  active_operations: Arc<AtomicUsize>,
}

impl ActiveOperationGuard {
  fn acquire(active_operations: Arc<AtomicUsize>) -> Option<Self> {
    active_operations
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        current.checked_add(1)
      })
      .ok()?;
    Some(Self { active_operations })
  }
}

impl Drop for ActiveOperationGuard {
  fn drop(&mut self) {
    let decremented =
      self
        .active_operations
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
          current.checked_sub(1)
        });
    debug_assert!(
      decremented.is_ok(),
      "Compio direct-H1 active-operation accounting underflowed"
    );
  }
}

#[allow(clippy::too_many_arguments)]
async fn run_worker(
  mut receiver: mpsc::Receiver<CompioDirectH1Operation>,
  mut command: watch::Receiver<u8>,
  plan: CompioDirectH1ServicePlan,
  metrics: Arc<Metrics>,
  tokio_handle: Handle,
  queue_occupancy: Arc<AtomicUsize>,
  active_operations: Arc<AtomicUsize>,
  cancelled_operations: Arc<AtomicUsize>,
  rejected_queued_operations: Arc<AtomicUsize>,
  connection_budget: Arc<GlobalConnectionBudget>,
) -> WorkerExit {
  let pool = Rc::new(RefCell::new(WorkerConnectionPool::new(
    plan.generation,
    plan.max_connections_per_origin,
    connection_budget,
    Arc::clone(&metrics),
  )));
  // Operations are striped across the persistent workers, while physical
  // global and per-origin connection ownership is enforced by the shared
  // process-wide connection budget. Let each worker use the global operation
  // ceiling; dividing it by worker count would cap a temporarily hot shard to
  // one fraction of the configured admission budget.
  let max_inflight = worker_operation_limit(&plan);
  let mut operations: FuturesUnordered<_> = FuturesUnordered::new();
  let mut active_cancellations = HashMap::new();
  let mut next_operation_id = 0usize;
  let mut stopping = false;
  let mut unexpected = false;
  loop {
    if stopping && operations.is_empty() {
      pool.borrow_mut().close_idle();
      return if unexpected {
        WorkerExit::Unexpected
      } else {
        WorkerExit::Stopped
      };
    }
    // Keep ingress and terminal bookkeeping fair when both are continuously
    // ready. A completion-first bias can otherwise convoy a one-slot shard
    // queue, while an ingress-first bias can retain admission permits.
    tokio::select! {
      changed = command.changed() => {
        if changed.is_err() {
          receiver.close();
          let bookkeeping_healthy = reject_queued(
            &mut receiver,
            &metrics,
            &queue_occupancy,
            &rejected_queued_operations,
          );
          cancel_registered(&active_cancellations);
          stopping = true;
          if !bookkeeping_healthy {
            unexpected = true;
          }
          continue;
        }
        let next_command = *command.borrow_and_update();
        match next_command {
          WORKER_DRAINING => receiver.close(),
          WORKER_STOPPING => {
            receiver.close();
            let bookkeeping_healthy = reject_queued(
              &mut receiver,
              &metrics,
              &queue_occupancy,
              &rejected_queued_operations,
            );
            cancel_registered(&active_cancellations);
            stopping = true;
            if !bookkeeping_healthy {
              unexpected = true;
            }
          }
          #[cfg(test)]
          WORKER_FAILING => {
            receiver.close();
            let _ = reject_queued(
              &mut receiver,
              &metrics,
              &queue_occupancy,
              &rejected_queued_operations,
            );
            cancel_registered(&active_cancellations);
            stopping = true;
            unexpected = true;
          }
          _ => {}
        }
      }
      completed = operations.next(), if !operations.is_empty() => {
        let Some((operation_id, cancellation_identity, completed)) = completed else {
          continue;
        };
        // `run_operation` does not finish a cancelled or timed-out socket
        // operation until the Compio driver returns terminal FD/buffer
        // ownership. Keep both worker capacity and active accounting charged
        // through that completion boundary.
        let Some(registered) = active_cancellations.remove(&operation_id) else {
          receiver.close();
          let _ = reject_queued(
            &mut receiver,
            &metrics,
            &queue_occupancy,
            &rejected_queued_operations,
          );
          cancel_registered(&active_cancellations);
          stopping = true;
          unexpected = true;
          continue;
        };
        if registered.identity() != cancellation_identity {
          receiver.close();
          let _ = reject_queued(
            &mut receiver,
            &metrics,
            &queue_occupancy,
            &rejected_queued_operations,
          );
          cancel_registered(&active_cancellations);
          stopping = true;
          unexpected = true;
          continue;
        };
        let Ok(_active_operation) = completed else {
          receiver.close();
          let _ = reject_queued(
            &mut receiver,
            &metrics,
            &queue_occupancy,
            &rejected_queued_operations,
          );
          cancel_registered(&active_cancellations);
          stopping = true;
          unexpected = true;
          continue;
        };
        if let Some(elapsed) = registered.cancellation_elapsed() {
          metrics.observe_compio_direct_h1_cancellation(elapsed);
          cancelled_operations.fetch_add(1, Ordering::AcqRel);
        }
      }
      operation = receiver.recv(),
        if !stopping
          && operations.len() < max_inflight
          && !(receiver.is_closed() && receiver.is_empty()) =>
      {
        let Some(mut operation) = operation else {
          stopping = true;
          continue;
        };
        if !decrement_queue(&metrics, &queue_occupancy) {
          let result = operation.predispatch(CompioDirectH1PredispatchReason::Unhealthy);
          operation.complete(result);
          return WorkerExit::Unexpected;
        }
        let cancellation = operation.cancellation.clone();
        let cancellation_identity = cancellation.identity();
        let operation_id = next_operation_id;
        let Some(next) = next_operation_id.checked_add(1) else {
          let result = operation.predispatch(CompioDirectH1PredispatchReason::Unhealthy);
          operation.complete(result);
          return WorkerExit::Unexpected;
        };
        next_operation_id = next;
        let Some(active_operation) =
          ActiveOperationGuard::acquire(Arc::clone(&active_operations))
        else {
          let result = operation.predispatch(CompioDirectH1PredispatchReason::Unhealthy);
          operation.complete(result);
          return WorkerExit::Unexpected;
        };
        if active_cancellations
          .insert(operation_id, cancellation)
          .is_some()
        {
          let result = operation.predispatch(CompioDirectH1PredispatchReason::Unhealthy);
          operation.complete(result);
          return WorkerExit::Unexpected;
        }
        let pool = Rc::clone(&pool);
        let tokio_handle = tokio_handle.clone();
        let task = AssertUnwindSafe(async move {
          run_operation(&mut operation, &pool, &tokio_handle).await;
          // The worker has reached a terminal ownership boundary. A later
          // downstream body drop no longer has physical I/O to cancel.
          operation.cancellation.disarm();
          active_operation
        })
        .catch_unwind();
        operations.push(async move {
          (
            operation_id,
            cancellation_identity,
            task.await,
          )
        });
      }
    }
    if receiver.is_closed() && receiver.is_empty() {
      stopping = true;
    }
  }
}

fn worker_operation_limit(plan: &CompioDirectH1ServicePlan) -> usize {
  plan.max_connections_global.max(1)
}

fn reject_queued(
  receiver: &mut mpsc::Receiver<CompioDirectH1Operation>,
  metrics: &Metrics,
  queue_occupancy: &AtomicUsize,
  rejected: &AtomicUsize,
) -> bool {
  let mut healthy = true;
  while let Ok(mut operation) = receiver.try_recv() {
    healthy &= decrement_queue(metrics, queue_occupancy);
    rejected.fetch_add(1, Ordering::AcqRel);
    let result = operation.predispatch(CompioDirectH1PredispatchReason::Draining);
    operation.complete(result);
  }
  healthy
}

fn decrement_queue(metrics: &Metrics, queue_occupancy: &AtomicUsize) -> bool {
  if queue_occupancy
    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
      current.checked_sub(1)
    })
    .is_err()
  {
    return false;
  }
  metrics.adjust_compio_direct_h1_queue_occupancy(-1);
  true
}

fn cancel_registered(active: &HashMap<usize, CancellationToken>) {
  for cancellation in active.values() {
    cancellation.cancel();
  }
}

fn publish_failure(
  service_state: &AtomicU8,
  runtime_generation: &AtomicU64,
  required: &AtomicBool,
  runtime_health: &RuntimeHealth,
  panicked: bool,
) {
  service_state.store(super::SERVICE_UNHEALTHY, Ordering::Release);
  let generation = runtime_generation.load(Ordering::Acquire);
  let required = required.load(Ordering::Acquire);
  let policy = if required {
    RuntimeTaskPolicy::RestartableCritical
  } else {
    RuntimeTaskPolicy::RestartableOptional
  };
  runtime_health.set_subsystem_state(
    generation,
    RuntimeSubsystem::CompioDirectH1,
    RuntimeSubsystemState::Failed,
    required,
  );
  runtime_health.set_task_state(
    generation,
    RuntimeTaskKind::CompioDirectH1Worker,
    policy,
    RuntimeSubsystemState::Failed,
  );
  if panicked {
    runtime_health.record_panic(
      RuntimePanicScope::Background,
      RuntimeTaskKind::CompioDirectH1Worker,
    );
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  #[test]
  fn worker_shard_can_use_the_shared_global_connection_ceiling() {
    let plan = CompioDirectH1ServicePlan {
      generation: 1,
      worker_count: 4,
      queue_capacity_per_worker: 1,
      max_waiters: 0,
      queue_wait_timeout: Duration::from_millis(1),
      max_connections_global: 120,
      max_connections_per_origin: 120,
    };
    assert_eq!(worker_operation_limit(&plan), 120);
  }

  #[test]
  fn active_operation_accounting_is_unwind_safe() {
    let active_operations = Arc::new(AtomicUsize::new(0));
    let unwind_active_operations = Arc::clone(&active_operations);
    let result = catch_unwind(AssertUnwindSafe(move || {
      let _active_operation =
        ActiveOperationGuard::acquire(unwind_active_operations).expect("counter must increment");
      panic!("exercise active-operation unwind accounting");
    }));
    assert!(result.is_err());
    assert_eq!(active_operations.load(Ordering::Acquire), 0);
  }
}
