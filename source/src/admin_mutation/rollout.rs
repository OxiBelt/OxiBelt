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
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::sync::{RwLock, watch};
use tokio::time::{MissedTickBehavior, interval};

use super::ledger::{MutationRecord, MutationState, validate_identifier};
use super::rollout_store::{self, HeartbeatUpdate, MemberFence, RolloutTarget, TargetState};
use super::store::MutationStore;

#[path = "rollout_state.rs"]
mod state;
use state::classify;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_classify_rollout(data: &[u8]) {
  state::fuzz_classify(data);
}

const CAPABILITY_VERSION: &str = "admin-mutation-rollout-v1";

#[derive(Debug, Clone)]
pub(crate) struct RolloutSettings {
  pub(crate) cluster_id: String,
  pub(crate) membership_revision: String,
  pub(crate) members: Vec<String>,
  pub(crate) instance_id: String,
  pub(crate) boot_id: String,
  pub(crate) build_version: String,
  pub(crate) artifact_key_fingerprint: String,
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
      (
        "artifact_key_fingerprint",
        self.artifact_key_fingerprint.as_str(),
      ),
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
  member_fence: Arc<RwLock<Option<MemberFence>>>,
  ready: Arc<AtomicBool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RolloutDirective {
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
      member_fence: Arc::new(RwLock::new(None)),
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

  pub(crate) async fn member_fence(&self) -> anyhow::Result<MemberFence> {
    self
      .member_fence
      .read()
      .await
      .clone()
      .context("Admin cluster member authority is unavailable")
  }

  pub(crate) fn coordinator_lease_seconds(&self) -> anyhow::Result<i32> {
    seconds_i32(self.settings.stale_after, "coordinator lease")
  }

  pub(crate) async fn update_local_status(&self, status: LocalRolloutStatus) -> anyhow::Result<()> {
    status.validate()?;
    *self.local_status.write().await = status;
    Ok(())
  }

  pub(crate) async fn release(&self) -> anyhow::Result<()> {
    self.ready.store(false, Ordering::Release);
    let fence = self.member_fence.read().await.clone();
    if let Some(fence) = fence {
      ensure!(
        rollout_store::release_member_fence(&self.store, &fence).await?,
        "Admin cluster member release was fenced"
      );
    }
    Ok(())
  }

  pub(crate) async fn heartbeat_until_shutdown(
    &self,
    mut shutdown: watch::Receiver<bool>,
  ) -> anyhow::Result<()> {
    let mut ticker = interval(self.settings.heartbeat_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
      tokio::select! {
        biased;
        changed = shutdown.changed() => {
          if changed.is_err() || *shutdown.borrow() {
            self.ready.store(false, Ordering::Release);
            return Ok(());
          }
        }
        _ = ticker.tick() => {
          if let Err(error) = self.heartbeat_once().await {
            self.ready.store(false, Ordering::Release);
            return Err(error);
          }
          let durable_ready = self.durable_readiness().await.unwrap_or(false);
          self.ready.store(durable_ready, Ordering::Release);
        }
      }
    }
  }

  pub(crate) async fn heartbeat_once(&self) -> anyhow::Result<()> {
    let status = self.local_status.read().await.clone();
    status.validate()?;
    let fence = rollout_store::heartbeat_fenced(
      &self.store,
      &HeartbeatUpdate {
        cluster_id: self.settings.cluster_id.clone(),
        instance_id: self.settings.instance_id.clone(),
        boot_id: self.settings.boot_id.clone(),
        build_version: self.settings.build_version.clone(),
        capability_version: CAPABILITY_VERSION.to_string(),
        artifact_key_fingerprint: self.settings.artifact_key_fingerprint.clone(),
        membership_revision: self.settings.membership_revision.clone(),
        assigned_revision: status.assigned_revision,
        applied_revision: status.applied_revision,
        applied_digest: status.applied_digest,
        ready: status.ready,
        lease_seconds: seconds_i32(self.settings.stale_after, "stale interval")?,
      },
    )
    .await?;
    *self.member_fence.write().await = Some(fence);
    Ok(())
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

  pub(crate) async fn classify_durable(
    &self,
    record: &MutationRecord,
    targets: &[RolloutTarget],
  ) -> anyhow::Result<RolloutDirective> {
    let clock = self.phase_clock(&record.request_id, record.state).await?;
    Ok(classify(
      record,
      targets,
      true,
      clock.phase_timed_out,
      clock.rollback_timed_out,
      clock.observation_complete,
      &self.settings.members,
    ))
  }

  async fn durable_readiness(&self) -> anyhow::Result<bool> {
    for resource in ["config", "ipm", "break-glass"] {
      rollout_store::prove_exact_resource_membership(
        &self.store,
        &self.settings.cluster_id,
        &self.settings.membership_revision,
        &self.settings.members,
        &self.settings.build_version,
        CAPABILITY_VERSION,
        &self.settings.artifact_key_fingerprint,
        resource,
      )
      .await?;
    }
    let ready: bool = sqlx::query_scalar(
      "SELECT NOT EXISTS (
         SELECT 1 FROM oxibelt_admin_mutations mutation
          WHERE mutation.namespace = $1
            AND mutation.state IN ('rollback_failed', 'indeterminate')
       )",
    )
    .bind(self.store.namespace())
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
pub(crate) fn deterministic_canary(request_id: &str, members: &[String]) -> String {
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
