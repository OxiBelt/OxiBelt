//! Fail-closed orchestration for fixed-member Admin mutation rollouts.
//!
//! The controller deliberately coordinates only durable state.  It never owns
//! or persists mutation artifacts: callers must provide an independently
//! authenticated, encrypted artifact channel before executing a directive.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

use super::ledger::{MutationRecord, MutationState, TerminalMutation, validate_identifier};
use super::rollout_store::{
  self, HeartbeatUpdate, InstanceHeartbeat, RolloutTarget, TargetState, TargetTransition,
};
use super::store::MutationStore;

#[path = "rollout_state.rs"]
mod state;
use state::classify;

const CAPABILITY_VERSION: &str = "admin-mutation-rollout-v1";

#[derive(Debug, Clone)]
pub(crate) struct RolloutSettings {
  pub(crate) cluster_id: String,
  pub(crate) membership_revision: String,
  pub(crate) members: Vec<String>,
  pub(crate) instance_id: String,
  pub(crate) boot_id: String,
  pub(crate) build_version: String,
  pub(crate) heartbeat_interval: Duration,
  pub(crate) stale_after: Duration,
  pub(crate) phase_timeout: Duration,
  pub(crate) rollback_timeout: Duration,
  pub(crate) canary_observation: Duration,
}

impl RolloutSettings {
  fn validate(&self) -> anyhow::Result<()> {
    for (name, value) in [
      ("cluster_id", self.cluster_id.as_str()),
      ("membership_revision", self.membership_revision.as_str()),
      ("instance_id", self.instance_id.as_str()),
      ("boot_id", self.boot_id.as_str()),
      ("build_version", self.build_version.as_str()),
    ] {
      validate_identifier(name, value, 256)?;
    }
    ensure!(
      self.members.len() >= 2,
      "Admin cluster requires at least two members"
    );
    let members = normalized_members(&self.members)?;
    ensure!(
      members.binary_search(&self.instance_id).is_ok(),
      "local instance is not in the fixed Admin cluster membership"
    );
    ensure!(
      !self.heartbeat_interval.is_zero(),
      "heartbeat interval must not be zero"
    );
    ensure!(
      self.stale_after >= self.heartbeat_interval.saturating_mul(2),
      "stale interval must cover at least two heartbeat intervals"
    );
    ensure!(
      self.stale_after <= Duration::from_secs(300),
      "stale interval must not exceed the database lease limit"
    );
    ensure!(
      self.phase_timeout > self.canary_observation && !self.canary_observation.is_zero(),
      "phase timeout must exceed the non-zero canary observation window"
    );
    ensure!(
      !self.rollback_timeout.is_zero(),
      "rollback timeout must not be zero"
    );
    seconds_i32(self.stale_after, "stale interval")?;
    seconds_i32(self.phase_timeout, "phase timeout")?;
    seconds_i32(self.rollback_timeout, "rollback timeout")?;
    Ok(())
  }
}

#[derive(Debug, Clone)]
pub(crate) struct LocalRolloutStatus {
  pub(crate) assigned_revision: Option<String>,
  pub(crate) applied_revision: String,
  pub(crate) applied_digest: String,
  pub(crate) ready: bool,
}

impl LocalRolloutStatus {
  fn validate(&self) -> anyhow::Result<()> {
    if let Some(revision) = self.assigned_revision.as_deref() {
      validate_identifier("assigned_revision", revision, 256)?;
    }
    validate_identifier("applied_revision", &self.applied_revision, 256)?;
    validate_identifier("applied_digest", &self.applied_digest, 256)?;
    ensure!(
      !self.ready
        || self
          .assigned_revision
          .as_deref()
          .is_none_or(|assigned| assigned == self.applied_revision),
      "a ready instance must have applied its assigned revision"
    );
    Ok(())
  }
}

#[derive(Clone)]
pub(crate) struct AdminClusterRolloutController {
  store: MutationStore,
  settings: Arc<RolloutSettings>,
  local_status: Arc<RwLock<LocalRolloutStatus>>,
  ready: Arc<AtomicBool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RolloutDirective {
  Passive,
  AwaitMembership,
  Validate(Vec<String>),
  AwaitValidation,
  ApplyCanary(String),
  ObserveCanary,
  ApplyExpansion(Vec<String>),
  Commit,
  FailBeforeApply(&'static str),
  RollBack(Vec<String>),
  FinishRolledBack,
  FinishRollbackFailed,
  FinishIndeterminate,
  Completed(MutationState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RolloutTerminal {
  Committed,
  Failed,
  RolledBack,
  RollbackFailed,
  Indeterminate,
}

impl AdminClusterRolloutController {
  pub(crate) fn new(
    store: MutationStore,
    mut settings: RolloutSettings,
    initial_status: LocalRolloutStatus,
  ) -> anyhow::Result<Self> {
    settings.members = normalized_members(&settings.members)?;
    settings.validate()?;
    initial_status.validate()?;
    Ok(Self {
      store,
      settings: Arc::new(settings),
      local_status: Arc::new(RwLock::new(initial_status)),
      ready: Arc::new(AtomicBool::new(false)),
    })
  }

  pub(crate) fn ready(&self) -> bool {
    self.ready.load(Ordering::Acquire)
  }

  pub(crate) fn instance_id(&self) -> &str {
    &self.settings.instance_id
  }

  pub(crate) fn boot_id(&self) -> &str {
    &self.settings.boot_id
  }

  pub(crate) fn cluster_id(&self) -> &str {
    &self.settings.cluster_id
  }

  pub(crate) fn membership_revision(&self) -> &str {
    &self.settings.membership_revision
  }

  pub(crate) async fn update_local_status(&self, status: LocalRolloutStatus) -> anyhow::Result<()> {
    status.validate()?;
    *self.local_status.write().await = status;
    Ok(())
  }

  /// Starts DB-time heartbeats. Dropping the returned task stops renewal and
  /// lets the lease expire; callers should abort it during server shutdown.
  pub(crate) fn spawn_heartbeat_task(&self) -> JoinHandle<()> {
    let controller = self.clone();
    tokio::spawn(async move {
      let mut ticker = interval(controller.settings.heartbeat_interval);
      ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
      loop {
        ticker.tick().await;
        let heartbeat_ok = controller.heartbeat_once().await.is_ok();
        let durable_ready = heartbeat_ok && controller.durable_readiness().await.unwrap_or(false);
        controller.ready.store(durable_ready, Ordering::Release);
      }
    })
  }

  pub(crate) async fn heartbeat_once(&self) -> anyhow::Result<()> {
    let status = self.local_status.read().await.clone();
    status.validate()?;
    rollout_store::heartbeat(
      &self.store,
      &HeartbeatUpdate {
        cluster_id: self.settings.cluster_id.clone(),
        instance_id: self.settings.instance_id.clone(),
        boot_id: self.settings.boot_id.clone(),
        build_version: self.settings.build_version.clone(),
        capability_version: CAPABILITY_VERSION.to_string(),
        membership_revision: self.settings.membership_revision.clone(),
        assigned_revision: status.assigned_revision,
        applied_revision: status.applied_revision,
        applied_digest: status.applied_digest,
        ready: status.ready,
        lease_seconds: seconds_i32(self.settings.stale_after, "stale interval")?,
      },
    )
    .await
  }

  /// Registers the exact fixed membership before any coordinator can acquire
  /// the request. This operation is idempotent for the same member set.
  pub(crate) async fn prepare(&self, request_id: &str) -> anyhow::Result<()> {
    rollout_store::register_targets(&self.store, request_id, &self.settings.members).await?;
    Ok(())
  }

  /// Reconciles one durable phase. Every mutating call first renews a DB-time
  /// coordinator lease, so an instance with an expired heartbeat cannot act.
  pub(crate) async fn reconcile(&self, request_id: &str) -> anyhow::Result<RolloutDirective> {
    let initial = self
      .store
      .load_mutation(request_id)
      .await?
      .context("rollout mutation disappeared")?;
    if initial.state.is_terminal() {
      return Ok(RolloutDirective::Completed(initial.state));
    }
    if matches!(
      initial.state,
      MutationState::Claimed | MutationState::Validating
    ) {
      self.prepare(request_id).await?;
    }
    if !rollout_store::acquire_coordinator_lease(
      &self.store,
      request_id,
      &self.settings.instance_id,
      seconds_i32(self.settings.stale_after, "coordinator lease")?,
    )
    .await?
    {
      return Ok(RolloutDirective::Passive);
    }

    let record = self
      .store
      .load_mutation(request_id)
      .await?
      .context("rollout mutation disappeared")?;
    let targets = rollout_store::load_targets(&self.store, request_id).await?;
    let live = rollout_store::load_live_members(
      &self.store,
      &self.settings.cluster_id,
      &self.settings.membership_revision,
    )
    .await?;
    let membership_exact = exact_live_membership(&self.settings, &live);
    let clock = self.phase_clock(request_id, record.state).await?;
    let directive = classify(
      &record,
      &targets,
      membership_exact,
      clock.phase_timed_out,
      clock.rollback_timed_out,
      clock.observation_complete,
      &self.settings.members,
    );
    self.apply_safe_transition(request_id, directive).await
  }

  pub(crate) async fn record_validated(
    &self,
    request_id: &str,
    instance_id: &str,
  ) -> anyhow::Result<()> {
    self.require_member(instance_id)?;
    self
      .transition_target(
        request_id,
        instance_id,
        TargetState::Applying,
        None,
        None,
        None,
        None,
      )
      .await
  }

  pub(crate) async fn record_nack(
    &self,
    request_id: &str,
    instance_id: &str,
    error_code: &str,
  ) -> anyhow::Result<()> {
    self.require_member(instance_id)?;
    self
      .transition_target(
        request_id,
        instance_id,
        TargetState::Nacked,
        None,
        None,
        None,
        Some(error_code),
      )
      .await
  }

  pub(crate) async fn record_ack(
    &self,
    request_id: &str,
    instance_id: &str,
    boot_id: &str,
    applied_revision: &str,
    applied_digest: &str,
  ) -> anyhow::Result<()> {
    self.require_member(instance_id)?;
    self
      .transition_target(
        request_id,
        instance_id,
        TargetState::Acked,
        Some(boot_id),
        Some(applied_revision),
        Some(applied_digest),
        None,
      )
      .await
  }

  pub(crate) async fn record_rollback(
    &self,
    request_id: &str,
    instance_id: &str,
    error_code: Option<&str>,
  ) -> anyhow::Result<()> {
    self.require_member(instance_id)?;
    let next = if error_code.is_some() {
      TargetState::RollbackFailed
    } else {
      TargetState::RolledBack
    };
    self
      .transition_target(request_id, instance_id, next, None, None, None, error_code)
      .await
  }

  pub(crate) async fn finalize(
    &self,
    request_id: &str,
    terminal: RolloutTerminal,
    status: u16,
    safe_response: Option<Value>,
    error_code: Option<String>,
    terminal_audit_record_id: i64,
  ) -> anyhow::Result<MutationRecord> {
    let state = match terminal {
      RolloutTerminal::Committed => MutationState::Committed,
      RolloutTerminal::Failed => MutationState::Failed,
      RolloutTerminal::RolledBack => MutationState::RolledBack,
      RolloutTerminal::RollbackFailed => MutationState::RollbackFailed,
      RolloutTerminal::Indeterminate => MutationState::Indeterminate,
    };
    self
      .store
      .finish(
        request_id,
        &TerminalMutation {
          state,
          http_status: status,
          safe_response,
          error_code,
          terminal_audit_record_id,
        },
      )
      .await
  }

  fn require_member(&self, instance_id: &str) -> anyhow::Result<()> {
    ensure!(
      self
        .settings
        .members
        .binary_search(&instance_id.to_string())
        .is_ok(),
      "instance is not in the configured rollout membership"
    );
    Ok(())
  }

  #[allow(clippy::too_many_arguments)]
  async fn transition_target(
    &self,
    request_id: &str,
    instance_id: &str,
    next: TargetState,
    boot_id: Option<&str>,
    applied_revision: Option<&str>,
    applied_digest: Option<&str>,
    error_code: Option<&str>,
  ) -> anyhow::Result<()> {
    rollout_store::transition_target(
      &self.store,
      request_id,
      instance_id,
      &TargetTransition {
        next,
        boot_id: boot_id.map(str::to_string),
        applied_revision: applied_revision.map(str::to_string),
        applied_digest: applied_digest.map(str::to_string),
        error_code: error_code.map(str::to_string),
      },
    )
    .await?;
    Ok(())
  }

  async fn apply_safe_transition(
    &self,
    request_id: &str,
    directive: RolloutDirective,
  ) -> anyhow::Result<RolloutDirective> {
    match directive {
      RolloutDirective::Validate(ref members) => {
        for member in members {
          self
            .transition_target(
              request_id,
              member,
              TargetState::Validating,
              None,
              None,
              None,
              None,
            )
            .await?;
        }
        let record = self
          .store
          .load_mutation(request_id)
          .await?
          .context("mutation missing")?;
        if record.state == MutationState::Claimed {
          self
            .store
            .transition(request_id, MutationState::Validating)
            .await?;
        }
      }
      RolloutDirective::ApplyCanary(_) => {
        let record = self
          .store
          .load_mutation(request_id)
          .await?
          .context("mutation missing")?;
        if record.state == MutationState::Validating {
          self
            .store
            .transition(request_id, MutationState::CanaryApplying)
            .await?;
        }
      }
      RolloutDirective::ObserveCanary => {
        let record = self
          .store
          .load_mutation(request_id)
          .await?
          .context("mutation missing")?;
        if record.state == MutationState::CanaryApplying {
          self
            .store
            .transition(request_id, MutationState::CanaryHealthy)
            .await?;
        }
      }
      RolloutDirective::ApplyExpansion(_) => {
        let record = self
          .store
          .load_mutation(request_id)
          .await?
          .context("mutation missing")?;
        if record.state == MutationState::CanaryHealthy {
          self
            .store
            .transition(request_id, MutationState::Expanding)
            .await?;
        }
      }
      RolloutDirective::Commit => {
        let record = self
          .store
          .load_mutation(request_id)
          .await?
          .context("mutation missing")?;
        if record.state == MutationState::Expanding {
          self
            .store
            .transition(request_id, MutationState::FullyApplied)
            .await?;
        }
      }
      RolloutDirective::RollBack(ref members) => {
        let record = self
          .store
          .load_mutation(request_id)
          .await?
          .context("mutation missing")?;
        if record.state != MutationState::RollingBack {
          self
            .store
            .transition(request_id, MutationState::RollingBack)
            .await?;
        }
        for member in members {
          let target = rollout_store::load_targets(&self.store, request_id)
            .await?
            .into_iter()
            .find(|target| target.instance_id == *member)
            .context("rollback target disappeared")?;
          if target.state != TargetState::RollingBack {
            self
              .transition_target(
                request_id,
                member,
                TargetState::RollingBack,
                None,
                None,
                None,
                None,
              )
              .await?;
          }
        }
      }
      _ => {}
    }
    Ok(directive)
  }

  async fn phase_clock(
    &self,
    request_id: &str,
    state: MutationState,
  ) -> anyhow::Result<PhaseClock> {
    let phase_seconds = seconds_f64(self.settings.phase_timeout);
    let rollback_seconds = seconds_f64(self.settings.rollback_timeout);
    let observation_seconds = seconds_f64(self.settings.canary_observation);
    let row = sqlx::query(
      "SELECT now() >= updated_at + make_interval(secs => $3::double precision)
                AS phase_timed_out,
              now() >= updated_at + make_interval(secs => $4::double precision)
                AS rollback_timed_out,
              now() >= updated_at + make_interval(secs => $5::double precision)
                AS observation_complete
         FROM oxibelt_admin_mutations
        WHERE namespace = $1 AND request_id = $2 AND state = $6",
    )
    .bind(self.store.namespace())
    .bind(request_id)
    .bind(phase_seconds)
    .bind(rollback_seconds)
    .bind(observation_seconds)
    .bind(state.as_str())
    .fetch_optional(self.store.pool())
    .await?
    .context("mutation phase changed during reconciliation")?;
    Ok(PhaseClock {
      phase_timed_out: row.try_get("phase_timed_out")?,
      rollback_timed_out: row.try_get("rollback_timed_out")?,
      observation_complete: row.try_get("observation_complete")?,
    })
  }

  async fn durable_readiness(&self) -> anyhow::Result<bool> {
    let ready: bool = sqlx::query_scalar(
      "SELECT EXISTS (
         SELECT 1 FROM oxibelt_admin_instance_heartbeats heartbeat
          WHERE heartbeat.namespace = $1 AND heartbeat.cluster_id = $2
            AND heartbeat.membership_revision = $3 AND heartbeat.instance_id = $4
            AND heartbeat.boot_id = $5 AND heartbeat.ready = true
            AND heartbeat.lease_expires_at > now()
            AND (heartbeat.assigned_revision IS NULL
                 OR heartbeat.assigned_revision = heartbeat.applied_revision)
       ) AND NOT EXISTS (
         SELECT 1 FROM oxibelt_admin_mutations mutation
          WHERE mutation.namespace = $1
            AND mutation.state IN ('rollback_failed', 'indeterminate')
       )",
    )
    .bind(self.store.namespace())
    .bind(&self.settings.cluster_id)
    .bind(&self.settings.membership_revision)
    .bind(&self.settings.instance_id)
    .bind(&self.settings.boot_id)
    .fetch_one(self.store.pool())
    .await?;
    Ok(ready)
  }
}

#[derive(Debug, Clone, Copy)]
struct PhaseClock {
  phase_timed_out: bool,
  rollback_timed_out: bool,
  observation_complete: bool,
}

fn exact_live_membership(settings: &RolloutSettings, live: &[InstanceHeartbeat]) -> bool {
  let actual = live
    .iter()
    .filter(|heartbeat| {
      heartbeat.cluster_id == settings.cluster_id
        && heartbeat.membership_revision == settings.membership_revision
        && heartbeat.build_version == settings.build_version
        && heartbeat.capability_version == CAPABILITY_VERSION
    })
    .map(|heartbeat| heartbeat.instance_id.clone())
    .collect::<Vec<_>>();
  actual == settings.members
}

fn normalized_members(members: &[String]) -> anyhow::Result<Vec<String>> {
  let mut unique = BTreeSet::new();
  for member in members {
    validate_identifier("member", member, 256)?;
    ensure!(unique.insert(member.clone()), "duplicate rollout member");
  }
  Ok(unique.into_iter().collect())
}

#[allow(
  clippy::expect_used,
  reason = "rollout settings validation rejects empty fixed membership before selection"
)]
fn deterministic_canary(request_id: &str, members: &[String]) -> String {
  members
    .iter()
    .min_by_key(|member| {
      let mut hasher = Sha256::new();
      hasher.update(b"oxibelt-admin-mutation-canary-v1\0");
      hasher.update(request_id.as_bytes());
      hasher.update(b"\0");
      hasher.update(member.as_bytes());
      hasher.finalize()
    })
    .cloned()
    .expect("validated fixed membership is non-empty")
}

fn seconds_i32(duration: Duration, name: &str) -> anyhow::Result<i32> {
  ensure!(
    duration.subsec_nanos() == 0,
    "{name} must use whole seconds"
  );
  i32::try_from(duration.as_secs()).with_context(|| format!("{name} exceeds the supported range"))
}

fn seconds_f64(duration: Duration) -> f64 {
  duration.as_secs_f64()
}

#[cfg(test)]
#[path = "rollout_tests.rs"]
mod tests;
