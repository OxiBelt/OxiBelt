//! Runtime signing, submission, recovery, and health policy.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, ensure};
use serde::Serialize;
use sqlx::{Pool, Postgres, Transaction};

use super::{
  AnchorCandidateOutcome, AnchorOutboxEntry, AnchorStreamIdentity, AuditAnchorSink,
  PostgresAnchorSink, assemble_signed_checkpoint, checkpoint_body_digest, load_pending_outbox,
  load_terminal_confirmation_checkpoints, observed_position, pending_usage,
  postgres_database_identity, promote_terminal_confirmations, record_event_in_transaction,
  seal_candidate, seal_due_candidate, sink, verify_checkpoint_signature,
};
use crate::admin_audit::AdminAuditEvent;
use crate::config::{AdminAuditMode, Config};
use crate::metrics::Metrics;
use crate::remote_signer::{AuditCheckpointSigner, AuditCheckpointSignerConfig};
use crate::runtime_health::{
  RuntimeHealth, RuntimeSubsystem, RuntimeSubsystemState, RuntimeTaskKind, RuntimeTaskPolicy,
};

const STATE_HEALTHY: u8 = 1;
const STATE_DEGRADED: u8 = 2;
const STATE_FAILED: u8 = 3;

#[derive(Clone)]
pub(crate) struct AuditAnchorRuntime {
  inner: Option<Arc<AuditAnchorInner>>,
}

struct AuditAnchorInner {
  identity: AnchorStreamIdentity,
  local_pool: Pool<Postgres>,
  sink: Arc<dyn AuditAnchorSink>,
  signer: tokio::sync::Mutex<Option<AuditCheckpointSigner>>,
  signer_config: AuditCheckpointSignerConfig,
  pinned_public_key: [u8; 32],
  required: bool,
  metrics: Arc<Metrics>,
  health: Arc<RuntimeHealth>,
  generation: u64,
  state: AtomicU8,
  last_observed_sequence: AtomicU64,
  last_anchored_sequence: AtomicU64,
  last_observed_chain: std::sync::Mutex<Option<String>>,
  last_anchored_chain: std::sync::Mutex<Option<String>>,
  pending_checkpoints: AtomicU64,
  pending_bytes: AtomicU64,
  submission_lock: tokio::sync::Mutex<()>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuditAnchorStatus {
  pub(crate) enabled: bool,
  pub(crate) policy: &'static str,
  pub(crate) state: &'static str,
  pub(crate) last_anchored_sequence: Option<u64>,
  pub(crate) pending_checkpoints: u64,
  pub(crate) pending_bytes: u64,
}

impl AuditAnchorRuntime {
  pub(crate) fn disabled() -> Self {
    Self { inner: None }
  }

  pub(crate) async fn new(
    config: &Config,
    local_pool: Pool<Postgres>,
    metrics: Arc<Metrics>,
    health: Arc<RuntimeHealth>,
    generation: u64,
  ) -> anyhow::Result<Self> {
    let anchor = &config.admin.audit.anchor;
    if !anchor.enabled {
      return Ok(Self::disabled());
    }
    super::initialize_local_anchor(&local_pool)
      .await
      .context("failed to initialize the local Admin audit anchor outbox")?;
    let sink_backend = config
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == anchor.sink.backend)
      .context("Admin audit anchor PostgreSQL backend is unavailable")?;
    let required = config.admin.audit.mode != AdminAuditMode::BestEffort
      || config.admin.mutations.mode.required();
    let sink_pool = crate::admin_audit::store::connect_lazy_pool(sink_backend)
      .context("failed to configure the external Admin audit anchor authority")?;
    let local_database = postgres_database_identity(&local_pool)
      .await
      .context("failed to identify the local Admin audit PostgreSQL database")?;
    let sink: Arc<dyn AuditAnchorSink> = Arc::new(PostgresAnchorSink::new_with_forbidden_database(
      sink_pool,
      anchor.sink.authority_id.clone(),
      Duration::from_millis(anchor.sink.submit_timeout_ms),
      local_database,
    ));
    let preflight_error = sink.preflight().await.err();
    let preflight_failed = preflight_error.is_some();
    if required && let Some(error) = preflight_error {
      return Err(error).context("required Admin audit anchor authority preflight failed");
    }

    let pinned_public_key: [u8; 32] = std::fs::read(&anchor.signer.public_key_file)
      .with_context(|| {
        format!(
          "failed to read Admin audit anchor public key {}",
          anchor.signer.public_key_file.display()
        )
      })?
      .try_into()
      .map_err(|_| anyhow::anyhow!("Admin audit anchor public key must contain 32 bytes"))?;
    let signer_config = AuditCheckpointSignerConfig {
      socket_path: anchor.signer.socket_path.clone(),
      key_id: anchor.signer.key_id.clone(),
      token_env: anchor.signer.token_env.clone(),
      token_file: anchor.signer.token_file.clone(),
      token_file_reload_base_dir: None,
      token_reload_interval: Duration::from_millis(anchor.signer.token_reload_interval_ms),
      connect_timeout: Duration::from_millis(anchor.signer.connect_timeout_ms),
      sign_timeout: Duration::from_millis(anchor.signer.sign_timeout_ms),
    };
    let signer = match AuditCheckpointSigner::connect(signer_config.clone()).await {
      Ok(signer) => {
        ensure!(
          signer.public_key().as_slice() == pinned_public_key,
          "Admin audit checkpoint signer public key does not match the configured pin"
        );
        Some(signer)
      }
      Err(error) if required => {
        return Err(error).context("failed to activate the Admin audit checkpoint signer");
      }
      Err(error) => {
        tracing::warn!(error = %error, "best-effort Admin audit checkpoint signer is unavailable");
        None
      }
    };
    let signer_unavailable = signer.is_none();

    let instance_id = std::env::var(&config.shared_state.instance_id_env)
      .context("failed to read stable Admin audit anchor instance ID")?;
    let deployment_epoch = std::env::var(&anchor.deployment_epoch_env)
      .context("failed to read Admin audit anchor deployment epoch")?;
    let target = crate::admin_mutation::configured_target(config);
    let cluster_id = config
      .admin
      .mutations
      .rollout
      .mode
      .is_cluster()
      .then_some(target.cluster_id.clone());
    let membership_epoch = if cluster_id.is_some() {
      target.membership_revision
    } else {
      "single_instance".to_string()
    };
    let stream_id = stream_id(
      &config.shared_state.namespace,
      cluster_id.as_deref(),
      &instance_id,
    );
    let identity = AnchorStreamIdentity {
      namespace: config.shared_state.namespace.clone(),
      stream_id,
      instance_id,
      cluster_id,
      membership_epoch,
      deployment_epoch,
      signing_key_id: anchor.signer.key_id.clone(),
      record_interval: anchor.record_interval,
      time_interval_ms: anchor.time_interval_ms,
      max_pending_checkpoints: u64::try_from(anchor.max_pending_checkpoints)
        .context("Admin audit anchor pending checkpoint bound is too large")?,
      max_pending_bytes: anchor.max_pending_bytes,
    };
    let inner = Arc::new(AuditAnchorInner {
      identity,
      local_pool,
      sink,
      signer: tokio::sync::Mutex::new(signer),
      signer_config,
      pinned_public_key,
      required,
      metrics,
      health,
      generation,
      state: AtomicU8::new(STATE_HEALTHY),
      last_observed_sequence: AtomicU64::new(u64::MAX),
      last_anchored_sequence: AtomicU64::new(u64::MAX),
      last_observed_chain: std::sync::Mutex::new(None),
      last_anchored_chain: std::sync::Mutex::new(None),
      pending_checkpoints: AtomicU64::new(0),
      pending_bytes: AtomicU64::new(0),
      submission_lock: tokio::sync::Mutex::new(()),
    });
    if preflight_failed || signer_unavailable {
      inner.failure("preflight_failed", false);
    } else {
      inner.set_health(RuntimeSubsystemState::Healthy);
    }
    let runtime = Self { inner: Some(inner) };
    if let Err(error) = runtime.recover_once().await {
      if required {
        return Err(error).context("required Admin audit anchor recovery failed");
      }
      if let Some(inner) = runtime.inner.as_ref() {
        inner.failure("recovery_failed", false);
      }
      tracing::warn!(error = %error, "Admin audit anchor recovery deferred");
    }
    runtime.spawn_worker();
    Ok(runtime)
  }

  pub(crate) async fn record_event_tx(
    &self,
    tx: &mut Transaction<'_, Postgres>,
    event: &AdminAuditEvent,
    force: bool,
  ) -> anyhow::Result<AnchorCandidateOutcome> {
    let Some(inner) = &self.inner else {
      return Ok(AnchorCandidateOutcome::Pending);
    };
    record_event_in_transaction(tx, &inner.identity, event, force).await
  }

  pub(crate) fn enabled(&self) -> bool {
    self.inner.is_some()
  }

  pub(crate) fn required(&self) -> bool {
    self.inner.as_ref().is_some_and(|inner| inner.required)
  }

  pub(crate) async fn after_event(
    &self,
    event: &AdminAuditEvent,
    outcome: AnchorCandidateOutcome,
    required: bool,
  ) -> anyhow::Result<()> {
    let Some(inner) = &self.inner else {
      return Ok(());
    };
    let sequence = event
      .integrity
      .as_ref()
      .context("anchored event is missing integrity metadata")?
      .sequence;
    let chain_id = &event
      .integrity
      .as_ref()
      .context("anchored event is missing integrity metadata")?
      .chain_id;
    {
      let mut observed = inner
        .last_observed_chain
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
      if observed.as_deref() != Some(chain_id) {
        *observed = Some(chain_id.clone());
        inner
          .last_observed_sequence
          .store(sequence, Ordering::Relaxed);
      }
    }
    inner
      .last_observed_sequence
      .store(sequence, Ordering::Relaxed);
    inner.update_lag();
    if let AnchorCandidateOutcome::CapacityExceeded = outcome {
      inner.failure("capacity_exhausted", true);
      if required {
        anyhow::bail!("Admin audit anchor pending capacity is exhausted");
      }
      return Ok(());
    }
    if let AnchorCandidateOutcome::Sealed(_) = outcome
      && let Err(error) = inner.drain_pending().await
    {
      inner.failure(classify_submission_failure(&error), false);
      if required {
        return Err(error);
      }
    }
    if required {
      inner.ensure_anchored(chain_id, sequence).await?;
    }
    inner.refresh_usage().await?;
    Ok(())
  }

  pub(crate) fn status(&self) -> AuditAnchorStatus {
    let Some(inner) = &self.inner else {
      return AuditAnchorStatus {
        enabled: false,
        policy: "disabled",
        state: "disabled",
        last_anchored_sequence: None,
        pending_checkpoints: 0,
        pending_bytes: 0,
      };
    };
    let last = inner.last_anchored_sequence.load(Ordering::Relaxed);
    let anchored_current_chain = inner
      .last_observed_chain
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .as_ref()
      == inner
        .last_anchored_chain
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref();
    AuditAnchorStatus {
      enabled: true,
      policy: if inner.required {
        "required"
      } else {
        "best_effort"
      },
      state: state_name(inner.state.load(Ordering::Relaxed)),
      last_anchored_sequence: (last != u64::MAX && anchored_current_chain).then_some(last),
      pending_checkpoints: inner.pending_checkpoints.load(Ordering::Relaxed),
      pending_bytes: inner.pending_bytes.load(Ordering::Relaxed),
    }
  }

  async fn recover_once(&self) -> anyhow::Result<()> {
    let Some(inner) = &self.inner else {
      return Ok(());
    };
    let recovery = async {
      inner.drain_pending().await?;
      match seal_candidate(&inner.local_pool, &inner.identity).await? {
        AnchorCandidateOutcome::Sealed(entry) => inner.submit_entry(*entry).await?,
        AnchorCandidateOutcome::CapacityExceeded => {
          anyhow::bail!("Admin audit anchor pending capacity is exhausted during recovery")
        }
        AnchorCandidateOutcome::Pending => {}
      }
      inner.reconcile_terminal_confirmations().await
    }
    .await;
    let usage = inner.refresh_usage().await;
    recovery.and(usage)
  }

  fn spawn_worker(&self) {
    let Some(inner) = self.inner.clone() else {
      return;
    };
    tokio::spawn(async move {
      let period = Duration::from_millis((inner.identity.time_interval_ms / 2).clamp(250, 5_000));
      let mut interval = tokio::time::interval(period);
      interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
      loop {
        interval.tick().await;
        let work = async {
          if inner.state.load(Ordering::Relaxed) != STATE_HEALTHY {
            inner.sink.preflight().await?;
            let _ = inner.signer().await?;
          }
          inner.drain_pending().await?;
          inner.reconcile_terminal_confirmations().await?;
          if let Some(entry) = seal_due_candidate(&inner.local_pool, &inner.identity).await? {
            inner.submit_entry(entry).await?;
          }
          Ok::<_, anyhow::Error>(())
        }
        .await;
        let usage = inner.refresh_usage().await;
        let result = work.and(usage);
        match result {
          Ok(()) => inner.healthy(),
          Err(error) => {
            inner.failure(classify_submission_failure(&error), false);
            tracing::warn!(error = %error, "Admin audit anchor worker iteration failed");
          }
        }
      }
    });
  }
}

impl AuditAnchorInner {
  async fn ensure_anchored(&self, chain_id: &str, sequence: u64) -> anyhow::Result<()> {
    self.drain_pending().await?;
    let (_, _, position) = pending_usage(&self.local_pool, &self.identity).await?;
    if anchor_position_covers(position.as_ref(), chain_id, sequence) {
      self.healthy();
      return Ok(());
    }
    match seal_candidate(&self.local_pool, &self.identity).await? {
      AnchorCandidateOutcome::Sealed(entry) => self.submit_entry(*entry).await?,
      AnchorCandidateOutcome::CapacityExceeded => {
        self.failure("capacity_exhausted", true);
        anyhow::bail!("Admin audit anchor pending capacity is exhausted");
      }
      AnchorCandidateOutcome::Pending => {}
    }
    self.drain_pending().await?;
    let (_, _, position) = pending_usage(&self.local_pool, &self.identity).await?;
    ensure!(
      anchor_position_covers(position.as_ref(), chain_id, sequence),
      "required Admin audit event does not have durable external anchor evidence"
    );
    self.healthy();
    Ok(())
  }

  async fn drain_pending(&self) -> anyhow::Result<()> {
    for entry in load_pending_outbox(&self.local_pool, &self.identity).await? {
      self.submit_entry(entry).await?;
    }
    Ok(())
  }

  async fn submit_entry(&self, entry: AnchorOutboxEntry) -> anyhow::Result<()> {
    let _submission_guard = self.submission_lock.lock().await;
    ensure!(
      entry.body.signing_key_id == self.signer_config.key_id,
      "pending Admin audit checkpoint requires a different signing key"
    );
    let checkpoint = if let Some(checkpoint) = entry.signed {
      self.verify_checkpoint(&checkpoint)?;
      checkpoint
    } else {
      ensure!(
        entry.ordinal == entry.body.checkpoint_ordinal,
        "Admin audit anchor outbox ordinal mismatch"
      );
      let digest = checkpoint_body_digest(&entry.body)?;
      let signer = self.signer().await?;
      let signature = signer.sign_digest(&digest).await?;
      let checkpoint = assemble_signed_checkpoint(entry.body, &signature)?;
      self.verify_checkpoint(&checkpoint)?;
      sink::store_signed_checkpoint(&self.local_pool, &checkpoint).await?;
      checkpoint
    };
    // Sign and persist the predecessor digest before checking the authority so
    // a bounded chain of pending checkpoints can continue during an outage.
    self.sink.preflight().await?;
    let receipt = match self.sink.submit(&checkpoint).await {
      Ok(receipt) => receipt,
      Err(submit_error) => match self
        .sink
        .lookup(
          &checkpoint.body.namespace,
          &checkpoint.body.stream_id,
          checkpoint.body.checkpoint_ordinal,
        )
        .await?
      {
        Some(receipt) if receipt.checkpoint_digest == checkpoint.checkpoint_digest => receipt,
        Some(_) => {
          anyhow::bail!("external Admin audit anchor ordinal contains a conflicting digest")
        }
        None => {
          return Err(submit_error).context("failed to durably submit Admin audit checkpoint");
        }
      },
    };
    ensure!(
      receipt.authority_id == self.sink.authority_id(),
      "Admin audit anchor receipt authority ID changed"
    );
    sink::store_receipt(&self.local_pool, &checkpoint, &receipt).await?;
    promote_terminal_confirmations(&self.local_pool, &checkpoint).await?;
    self
      .metrics
      .record_admin_audit_anchor_submission("persisted");
    self
      .last_anchored_sequence
      .store(checkpoint.body.last_sequence, Ordering::Relaxed);
    *self
      .last_anchored_chain
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(checkpoint.body.chain_id.clone());
    self
      .metrics
      .set_admin_audit_anchor_last_sequence(checkpoint.body.last_sequence);
    self.update_lag();
    Ok(())
  }

  async fn refresh_usage(&self) -> anyhow::Result<()> {
    let (checkpoints, bytes, position) = pending_usage(&self.local_pool, &self.identity).await?;
    let observed = observed_position(&self.local_pool, &self.identity).await?;
    self
      .pending_checkpoints
      .store(checkpoints, Ordering::Relaxed);
    self.pending_bytes.store(bytes, Ordering::Relaxed);
    if let Some((chain_id, sequence)) = position {
      self
        .last_anchored_sequence
        .store(sequence, Ordering::Relaxed);
      *self
        .last_anchored_chain
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(chain_id);
      self.metrics.set_admin_audit_anchor_last_sequence(sequence);
    }
    if let Some((chain_id, sequence)) = observed {
      self
        .last_observed_sequence
        .store(sequence, Ordering::Relaxed);
      *self
        .last_observed_chain
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(chain_id);
    }
    self
      .metrics
      .set_admin_audit_anchor_pending(checkpoints, bytes);
    self.update_lag();
    Ok(())
  }

  async fn reconcile_terminal_confirmations(&self) -> anyhow::Result<()> {
    for checkpoint in load_terminal_confirmation_checkpoints(&self.local_pool).await? {
      self.verify_checkpoint(&checkpoint)?;
      let receipt = self
        .sink
        .lookup(
          &checkpoint.body.namespace,
          &checkpoint.body.stream_id,
          checkpoint.body.checkpoint_ordinal,
        )
        .await?
        .context("external authority is missing a terminal audit checkpoint")?;
      ensure!(
        receipt.authority_id == self.sink.authority_id()
          && receipt.namespace == checkpoint.body.namespace
          && receipt.stream_id == checkpoint.body.stream_id
          && receipt.checkpoint_ordinal == checkpoint.body.checkpoint_ordinal
          && receipt.checkpoint_digest == checkpoint.checkpoint_digest,
        "external authority terminal checkpoint confirmation does not match"
      );
      promote_terminal_confirmations(&self.local_pool, &checkpoint).await?;
    }
    Ok(())
  }

  async fn signer(&self) -> anyhow::Result<AuditCheckpointSigner> {
    let mut signer = self.signer.lock().await;
    if let Some(active) = signer.as_ref() {
      return Ok(active.clone());
    }
    let connected = AuditCheckpointSigner::connect(self.signer_config.clone())
      .await
      .context("failed to reconnect the Admin audit checkpoint signer")?;
    ensure!(
      connected.public_key().as_slice() == self.pinned_public_key,
      "reconnected Admin audit checkpoint signer public key does not match the configured pin"
    );
    *signer = Some(connected.clone());
    Ok(connected)
  }

  fn verify_checkpoint(&self, checkpoint: &super::SignedAuditCheckpointV1) -> anyhow::Result<()> {
    verify_checkpoint_signature(checkpoint, &self.pinned_public_key).inspect_err(|_| {
      self
        .metrics
        .record_admin_audit_anchor_verification_failure("checkpoint_signature");
    })
  }

  fn healthy(&self) {
    self.state.store(STATE_HEALTHY, Ordering::Relaxed);
    self.set_health(RuntimeSubsystemState::Healthy);
  }

  fn update_lag(&self) {
    let observed = self.last_observed_sequence.load(Ordering::Relaxed);
    let anchored = self.last_anchored_sequence.load(Ordering::Relaxed);
    let observed_chain = self
      .last_observed_chain
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .clone();
    let anchored_chain = self
      .last_anchored_chain
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .clone();
    let lag = if observed == u64::MAX {
      0
    } else if anchored == u64::MAX || observed_chain != anchored_chain {
      observed.saturating_add(1)
    } else {
      observed.saturating_sub(anchored)
    };
    self.metrics.set_admin_audit_anchor_lag(lag);
  }

  fn failure(&self, reason: &str, severe: bool) {
    if reason == "continuity_failure" {
      self
        .metrics
        .record_admin_audit_anchor_verification_failure("checkpoint_continuity");
    }
    self
      .metrics
      .record_admin_audit_anchor_submission_failure(reason);
    let state = if severe || self.required {
      STATE_FAILED
    } else {
      STATE_DEGRADED
    };
    self.state.store(state, Ordering::Relaxed);
    self.set_health(if state == STATE_FAILED {
      RuntimeSubsystemState::Failed
    } else {
      RuntimeSubsystemState::Degraded
    });
  }

  fn set_health(&self, state: RuntimeSubsystemState) {
    self.health.set_subsystem_state(
      self.generation,
      RuntimeSubsystem::AdminAudit,
      state,
      self.required,
    );
    self.health.set_task_state(
      self.generation,
      RuntimeTaskKind::AdminAuditAnchor,
      if self.required {
        RuntimeTaskPolicy::RestartableCritical
      } else {
        RuntimeTaskPolicy::RestartableOptional
      },
      state,
    );
  }
}

fn anchor_position_covers(position: Option<&(String, u64)>, chain_id: &str, sequence: u64) -> bool {
  position.is_some_and(|(anchored_chain, anchored_sequence)| {
    anchored_chain == chain_id && *anchored_sequence >= sequence
  })
}

fn classify_submission_failure(error: &anyhow::Error) -> &'static str {
  let message = error.to_string().to_ascii_lowercase();
  if message.contains("signer") || message.contains("signing") {
    "signer_unavailable"
  } else if message.contains("continuity") || message.contains("conflict") {
    "continuity_failure"
  } else {
    "authority_unavailable"
  }
}

fn state_name(value: u8) -> &'static str {
  match value {
    STATE_HEALTHY => "healthy",
    STATE_DEGRADED => "degraded",
    STATE_FAILED => "failed",
    _ => "disabled",
  }
}

fn stream_id(namespace: &str, cluster_id: Option<&str>, instance_id: &str) -> String {
  let mut input = Vec::new();
  input.extend_from_slice(b"oxibelt.admin.audit.anchor.stream/v1\0");
  for value in [namespace, cluster_id.unwrap_or_default(), instance_id] {
    input.extend_from_slice(&(value.len() as u64).to_be_bytes());
    input.extend_from_slice(value.as_bytes());
  }
  format!(
    "sha256:{}",
    crate::admin_audit::event::hex_encode(&crate::crypto::sha256(&input))
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn stream_identity_is_domain_separated_and_cluster_scoped() {
    let standalone = stream_id("oxibelt", None, "edge-0");
    let clustered = stream_id("oxibelt", Some("edge"), "edge-0");
    assert!(standalone.starts_with("sha256:"));
    assert_ne!(standalone, clustered);
    assert_eq!(standalone, stream_id("oxibelt", None, "edge-0"));
  }

  #[test]
  fn an_old_chain_position_never_covers_a_restarted_chain() {
    let old = Some(("old-chain".to_string(), 99));
    assert!(anchor_position_covers(old.as_ref(), "old-chain", 0));
    assert!(!anchor_position_covers(old.as_ref(), "new-chain", 0));
  }
}
