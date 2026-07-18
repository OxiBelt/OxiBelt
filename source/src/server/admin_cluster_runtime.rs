//! Supervised fixed-member Admin mutation workers.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use tracing::warn;

use crate::admin_mutation::{AdminMutationRuntime, MutationRecord, RolloutTarget, TargetState};
use crate::runtime_health::{
  RuntimeHealth, RuntimeTaskKind, RuntimeTaskPolicy, spawn_supervised_task,
};
use crate::state::AppHandle;

use super::admin_cluster_executor::{
  AdminClusterExecutor, PreviousEvidence, RecoveryOutcome, RuntimeSharedPublisher,
};
use super::admin_control::AdminControlHandle;

mod coordinator;
use coordinator::coordinator_loop;
mod bootstrap;
pub(crate) use bootstrap::PreparedAdminClusterRuntime;
mod support;
use support::{current_target, error_code, publish_head, transition};
mod shared_member;
use shared_member::{apply_shared_observation, observe_shared_rollback, recover_shared};
mod startup;
use startup::activate_resource_heads;

const WORK_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Clone)]
pub(super) struct ObservedResourceHead {
  pub(super) resource: &'static str,
  pub(super) revision: String,
  pub(super) digest: String,
}

pub(super) struct AdminClusterRuntimeTasks {
  shutdown: watch::Sender<bool>,
  tasks: Vec<JoinHandle<()>>,
}

impl AdminClusterRuntimeTasks {
  pub(super) fn start(
    state: AppHandle,
    control: AdminControlHandle,
    observed: Vec<ObservedResourceHead>,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> Self {
    let snapshot = state.snapshot();
    let health = snapshot.runtime_health.clone();
    let generation = snapshot.runtime_generation;
    let runtime = snapshot.admin_mutations.clone();
    let audit = snapshot.admin_audit.clone();
    let phase_timeout = snapshot
      .config
      .admin
      .mutations
      .rollout
      .phase_timeout_seconds as i32;
    let rollback_timeout = snapshot
      .config
      .admin
      .mutations
      .rollout
      .rollback_timeout_seconds as i32;
    let publisher = RuntimeSharedPublisher::new(runtime.clone(), state.clone());
    let executor = AdminClusterExecutor::new(state, control);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let member = spawn_worker(
      health.clone(),
      generation,
      RuntimeTaskKind::AdminMutationMember,
      shutdown_rx.clone(),
      fatal_tx.clone(),
      {
        let runtime = runtime.clone();
        let executor = executor.clone();
        let publisher = publisher.clone();
        move |shutdown| {
          member_loop(
            runtime.clone(),
            executor.clone(),
            publisher.clone(),
            observed.clone(),
            shutdown,
          )
        }
      },
    );
    let coordinator = spawn_worker(
      health,
      generation,
      RuntimeTaskKind::AdminMutationCoordinator,
      shutdown_rx,
      fatal_tx,
      move |shutdown| {
        coordinator_loop(
          runtime.clone(),
          executor.clone(),
          publisher.clone(),
          audit.clone(),
          phase_timeout,
          rollback_timeout,
          shutdown,
        )
      },
    );
    Self {
      shutdown,
      tasks: vec![member, coordinator],
    }
  }

  pub(super) async fn shutdown(mut self) {
    let _ = self.shutdown.send(true);
    for task in self.tasks.drain(..) {
      let _ = task.await;
    }
  }
}

fn spawn_worker<F, Fut>(
  health: Arc<RuntimeHealth>,
  generation: u64,
  task: RuntimeTaskKind,
  shutdown: watch::Receiver<bool>,
  fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
  factory: F,
) -> JoinHandle<()>
where
  F: FnMut(watch::Receiver<bool>) -> Fut + Send + 'static,
  Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
  spawn_supervised_task(
    health,
    generation,
    task,
    RuntimeTaskPolicy::RestartableCritical,
    shutdown,
    fatal_tx,
    factory,
  )
}

async fn member_loop(
  runtime: AdminMutationRuntime,
  executor: AdminClusterExecutor,
  publisher: RuntimeSharedPublisher,
  observed: Vec<ObservedResourceHead>,
  mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
  runtime.set_cluster_worker_running(true, true);
  let result = member_loop_running(&runtime, &executor, &publisher, &observed, &mut shutdown).await;
  runtime.set_cluster_worker_running(true, false);
  result
}

async fn member_loop_running(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  observed: &[ObservedResourceHead],
  shutdown: &mut watch::Receiver<bool>,
) -> anyhow::Result<()> {
  activate_resource_heads(&runtime, &executor, publisher, &observed).await?;
  let mut ticker = interval(WORK_INTERVAL);
  ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_err() || *shutdown.borrow() { return Ok(()); }
      }
      _ = ticker.tick() => {
        for work in runtime.cluster_member_work().await? {
          if let Err(error) = process_member_work(&runtime, &executor, publisher, work).await {
            warn!(error = %error, "Admin cluster member work failed");
          }
        }
      }
    }
  }
}

async fn process_member_work(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  work: crate::admin_mutation::MemberWork,
) -> anyhow::Result<()> {
  let record = runtime
    .load_mutation(&work.request_id)
    .await?
    .context("assigned cluster mutation disappeared")?;
  let command = runtime.fetch_cluster_command(&record).await?;
  match work.target.state {
    TargetState::Validating => match executor.validate(&command).await {
      Ok(_) => {
        transition(
          runtime,
          &work.request_id,
          &work.target,
          TargetState::Validated,
          false,
          None,
          None,
          None,
          None,
          None,
        )
        .await
      }
      Err(error) => {
        transition(
          runtime,
          &work.request_id,
          &work.target,
          TargetState::Nacked,
          false,
          None,
          None,
          None,
          None,
          Some(error_code(error.kind)),
        )
        .await
      }
    },
    TargetState::ApplyAssigned => {
      apply_assigned(
        runtime,
        executor,
        publisher,
        &record,
        &command,
        &work.target,
      )
      .await
    }
    TargetState::Applying => {
      recover_applying(
        runtime,
        executor,
        publisher,
        &record,
        &command,
        &work.target,
      )
      .await
    }
    TargetState::RollbackAssigned | TargetState::RollingBack => {
      rollback_assigned(
        runtime,
        executor,
        publisher,
        &record,
        &command,
        &work.target,
      )
      .await
    }
    _ => Ok(()),
  }
}

async fn apply_assigned(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  record: &MutationRecord,
  command: &crate::admin_mutation::ClusterMutationCommand,
  target: &RolloutTarget,
) -> anyhow::Result<()> {
  let operation = executor
    .validate(command)
    .await
    .map_err(anyhow::Error::new)?;
  if operation.is_shared_staged() {
    return apply_shared_observation(runtime, executor, publisher, record, target, &operation)
      .await;
  }
  let logical = runtime
    .cluster_logical_revision(&record.resource)
    .await?
    .context("logical head missing")?;
  let previous = PreviousEvidence {
    revision: record.expected_previous_revision.clone(),
    digest: logical.content_digest,
  };
  let checkpoint = executor
    .checkpoint(&operation, &previous)
    .await
    .map_err(anyhow::Error::new)?;
  let inserted = runtime
    .publish_cluster_checkpoint(
      record,
      target.assignment_epoch,
      &previous.revision,
      &previous.digest,
      checkpoint.encoded_plaintext(),
    )
    .await?;
  let checkpoint = if inserted {
    checkpoint
  } else {
    let encrypted = runtime
      .fetch_cluster_checkpoint(record, target.assignment_epoch)
      .await?;
    executor
      .decode_checkpoint(
        &operation,
        encrypted.plaintext,
        &encrypted.integrity_digest,
        &encrypted.prior_digest,
      )
      .map_err(anyhow::Error::new)?
  };
  publish_head(
    runtime,
    &record.resource,
    Some(&record.new_revision),
    &previous.revision,
    &previous.digest,
    false,
  )
  .await?;
  transition(
    runtime,
    &record.request_id,
    target,
    TargetState::Applying,
    true,
    None,
    None,
    None,
    None,
    None,
  )
  .await?;
  match executor.apply(&operation, &checkpoint).await {
    Ok(evidence) => {
      publish_head(
        runtime,
        &record.resource,
        Some(&record.new_revision),
        &evidence.revision,
        &evidence.digest,
        true,
      )
      .await?;
      let current = current_target(runtime, record, target).await?;
      transition(
        runtime,
        &record.request_id,
        &current,
        TargetState::Acked,
        false,
        Some(evidence.revision),
        Some(evidence.digest),
        None,
        None,
        None,
      )
      .await
    }
    Err(error) => {
      let current = current_target(runtime, record, target).await?;
      transition(
        runtime,
        &record.request_id,
        &current,
        TargetState::Nacked,
        false,
        None,
        None,
        None,
        None,
        Some(error_code(error.kind)),
      )
      .await
    }
  }
}

async fn recover_applying(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  record: &MutationRecord,
  command: &crate::admin_mutation::ClusterMutationCommand,
  target: &RolloutTarget,
) -> anyhow::Result<()> {
  let operation = executor
    .validate(command)
    .await
    .map_err(anyhow::Error::new)?;
  if operation.is_shared_staged() {
    return recover_shared(runtime, executor, publisher, record, target, &operation).await;
  }
  let encrypted = runtime
    .fetch_cluster_checkpoint(record, target.assignment_epoch)
    .await?;
  let checkpoint = executor
    .decode_checkpoint(
      &operation,
      encrypted.plaintext,
      &encrypted.integrity_digest,
      &encrypted.prior_digest,
    )
    .map_err(anyhow::Error::new)?;
  match executor.recover(&checkpoint, command).await {
    RecoveryOutcome::CandidateApplied(evidence) => {
      publish_head(
        runtime,
        &record.resource,
        Some(&record.new_revision),
        &evidence.revision,
        &evidence.digest,
        true,
      )
      .await?;
      transition(
        runtime,
        &record.request_id,
        target,
        TargetState::Acked,
        false,
        Some(evidence.revision),
        Some(evidence.digest),
        None,
        None,
        None,
      )
      .await
    }
    RecoveryOutcome::PreviousRestored(evidence) => {
      publish_head(
        runtime,
        &record.resource,
        Some(&record.new_revision),
        &evidence.revision,
        &evidence.digest,
        true,
      )
      .await?;
      transition(
        runtime,
        &record.request_id,
        target,
        TargetState::Nacked,
        false,
        None,
        None,
        None,
        None,
        Some("recovered_previous"),
      )
      .await
    }
    RecoveryOutcome::SharedStaged(_) | RecoveryOutcome::Indeterminate(_) => {
      transition(
        runtime,
        &record.request_id,
        target,
        TargetState::Nacked,
        false,
        None,
        None,
        None,
        None,
        Some("recovery_indeterminate"),
      )
      .await
    }
  }
}

async fn rollback_assigned(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  record: &MutationRecord,
  command: &crate::admin_mutation::ClusterMutationCommand,
  target: &RolloutTarget,
) -> anyhow::Result<()> {
  if target.effect_started_at.is_none() {
    let logical = runtime
      .cluster_logical_revision(&record.resource)
      .await?
      .context("rollback logical head is unavailable")?;
    let current = if target.state == TargetState::RollbackAssigned {
      transition(
        runtime,
        &record.request_id,
        target,
        TargetState::RollingBack,
        true,
        None,
        None,
        None,
        None,
        None,
      )
      .await?;
      current_target(runtime, record, target).await?
    } else {
      target.clone()
    };
    publish_head(
      runtime,
      &record.resource,
      None,
      &record.expected_previous_revision,
      &logical.content_digest,
      true,
    )
    .await?;
    return transition(
      runtime,
      &record.request_id,
      &current,
      TargetState::RolledBack,
      false,
      None,
      None,
      Some(record.expected_previous_revision.clone()),
      Some(logical.content_digest),
      None,
    )
    .await;
  }
  let operation = executor
    .validate(command)
    .await
    .map_err(anyhow::Error::new)?;
  if operation.is_shared_staged() {
    return observe_shared_rollback(runtime, executor, publisher, record, target, &operation).await;
  }
  let encrypted = runtime
    .fetch_cluster_checkpoint(record, target.assignment_epoch)
    .await?;
  let checkpoint = executor
    .decode_checkpoint(
      &operation,
      encrypted.plaintext,
      &encrypted.integrity_digest,
      &encrypted.prior_digest,
    )
    .map_err(anyhow::Error::new)?;
  let current = if target.state == TargetState::RollbackAssigned {
    transition(
      runtime,
      &record.request_id,
      target,
      TargetState::RollingBack,
      true,
      None,
      None,
      None,
      None,
      None,
    )
    .await?;
    current_target(runtime, record, target).await?
  } else {
    target.clone()
  };
  match executor.rollback(&checkpoint).await {
    Ok(evidence) => {
      publish_head(
        runtime,
        &record.resource,
        None,
        &evidence.revision,
        &evidence.digest,
        true,
      )
      .await?;
      transition(
        runtime,
        &record.request_id,
        &current,
        TargetState::RolledBack,
        false,
        None,
        None,
        Some(evidence.revision),
        Some(evidence.digest),
        None,
      )
      .await
    }
    Err(error) => {
      transition(
        runtime,
        &record.request_id,
        &current,
        TargetState::RollbackFailed,
        false,
        None,
        None,
        None,
        None,
        Some(error_code(error.kind)),
      )
      .await
    }
  }
}
