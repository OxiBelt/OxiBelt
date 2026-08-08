//! Runtime trust configuration and durable admission for protected Admin writes.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use aws_lc_rs::agreement::{PrivateKey, X25519};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;
use http::{HeaderMap, Method, StatusCode, Uri};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use zeroize::Zeroizing;

use crate::admin_audit::{AdminAuditHandle, AdminAuditRuntime};
use crate::config::{
  AdminMembershipMode, AdminMutationMode, AdminMutationRolloutMode, AdminMutationSignatureSuite,
  Config,
};

use super::artifact::{ArtifactBinding, MutationArtifactCipher, MutationArtifactPlaintext};
use super::artifact_store;
use super::cluster_command::ClusterMutationCommand;
use super::envelope::{MutationTarget, TranscriptContext};
use super::ledger::{ClaimOutcome, MutationClaim, MutationRecord};
use super::rollout::{AdminClusterRolloutController, LocalRolloutStatus, RolloutSettings};
use super::store::{
  BreakGlassActivation, MAX_STORED_ARTIFACT_BYTES, MutationStore, create_break_glass_activation_tx,
  init_postgres, load_active_break_glass_for_principal, revoke_break_glass_activation_tx,
};
use super::{
  MUTATION_HEADER, MembershipArtifactCiphers, MembershipMember, MembershipReadinessReceipt,
  MutationProtocolError, MutationProtocolErrorKind, SignerBinding, SignerRegistry,
};
pub(crate) use cluster_heartbeat::{ClusterHeartbeatBootstrap, ClusterHeartbeatTask};
pub(crate) use target::configured_target;
use target::{digest_parts, ensure_cluster_member};

const EMPTY_DIGEST: &str =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const ORDINARY_TERMINAL_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct AdminMutationRuntime {
  inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
  mode: AdminMutationMode,
  signers: SignerRegistry,
  store: Option<MutationStore>,
  namespace: String,
  maximum_validity_seconds: u64,
  maximum_clock_skew_seconds: u64,
  retention_seconds: i64,
  rollout_mode: AdminMutationRolloutMode,
  membership_mode: AdminMembershipMode,
  cluster_id: String,
  membership_authority: RwLock<MembershipAuthority>,
  membership_bootstrap_members: Vec<MembershipMember>,
  local_instance_id: Option<String>,
  membership_private_keys: Option<MembershipPrivateKeys>,
  artifact_ciphers: RwLock<MembershipArtifactCiphers>,
  local_membership_heads: RwLock<HashMap<String, LocalMembershipHead>>,
  cluster_controller: OnceLock<AdminClusterRolloutController>,
  cluster_worker_state: AtomicU8,
  winner_responses: Mutex<HashMap<String, Option<zeroize::Zeroizing<Vec<u8>>>>>,
  winner_response_wait: Duration,
}

#[derive(Clone)]
struct MembershipAuthority {
  target: MutationTarget,
  members: Vec<String>,
  artifact_key_fingerprint: String,
}

struct MembershipPrivateKeys {
  readiness_pkcs8: Zeroizing<Vec<u8>>,
  catchup_x25519: Zeroizing<[u8; 32]>,
}

#[derive(Debug)]
pub(crate) enum MutationAdmission {
  Bypass,
  Claimed(MutationExecution),
  Replay(MutationRecord),
  InProgress(MutationRecord),
  PreconditionFailed { active_revision: String },
  Conflict(MutationConflict),
}

#[derive(Debug)]
pub(crate) struct MutationExecution {
  pub(crate) request_id: String,
  pub(crate) new_revision: String,
  winner_response: Option<cluster_checkpoint::SharedWinnerResponseGuard>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct LocalMembershipHead {
  pub(crate) resource: String,
  pub(crate) revision: String,
  pub(crate) digest: String,
}

impl MutationExecution {
  pub(crate) fn expects_winner_response(&self) -> bool {
    self.winner_response.is_some()
  }

  pub(crate) fn take_winner_response(&mut self) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    self.winner_response.as_mut()?.take()
  }
}

#[derive(Debug)]
pub(crate) enum MutationConflict {
  RequestId,
  Expired,
  Revision { actual_revision: Option<String> },
  Busy { request_id: String },
  Target,
}

impl AdminMutationRuntime {
  pub(crate) async fn new(config: &Config, audit: &AdminAuditRuntime) -> anyhow::Result<Self> {
    let mutation_config = &config.admin.mutations;
    if !mutation_config.mode.enabled() {
      let durable_membership_cluster_ids =
        load_disabled_durable_membership_cluster_ids(config).await?;
      validate_durable_membership_configuration(
        false,
        mutation_config.rollout.mode,
        mutation_config.rollout.membership.mode,
        &mutation_config.rollout.cluster_id,
        &durable_membership_cluster_ids,
      )?;
      return Ok(Self::disabled(&config.ipm.namespace));
    }

    let bindings = mutation_config
      .signers
      .iter()
      .map(load_signer)
      .collect::<anyhow::Result<Vec<_>>>()?;
    let signers = SignerRegistry::new(bindings).map_err(anyhow::Error::new)?;
    let pool = audit
      .critical_postgres_pool()
      .context("Admin mutation ledger requires the enforcing Admin audit PostgreSQL pool")?;
    init_postgres(&pool)
      .await
      .context("failed to initialize Admin mutation PostgreSQL tables")?;
    let store = if mutation_config.rollout.mode.is_cluster() {
      MutationStore::new_cluster(pool, config.shared_state.namespace.clone())?
    } else {
      MutationStore::new(pool, config.shared_state.namespace.clone())?
    };
    let durable_membership_cluster_ids =
      super::membership_store::durable_membership_cluster_ids(&store).await?;
    validate_durable_membership_configuration(
      true,
      mutation_config.rollout.mode,
      mutation_config.rollout.membership.mode,
      &mutation_config.rollout.cluster_id,
      &durable_membership_cluster_ids,
    )?;
    let mut target = configured_target(config);
    let mut members = mutation_config.rollout.members.clone();
    members.sort();
    let membership_bootstrap_members: Vec<MembershipMember> = mutation_config
      .rollout
      .membership
      .bootstrap_members
      .iter()
      .map(|member| MembershipMember {
        id: member.id.clone(),
        readiness_ed25519_public_key: member.readiness_ed25519_public_key.clone(),
        catchup_x25519_public_key: member.catchup_x25519_public_key.clone(),
      })
      .collect();
    let local_instance_id = if mutation_config.rollout.mode.is_cluster() {
      Some(
        config
          .rollout
          .instance_id()
          .context("Admin cluster rollout identity is missing its instance ID")?
          .to_string(),
      )
    } else {
      None
    };
    let membership_private_keys = if mutation_config.rollout.membership.mode.is_staged() {
      Some(load_membership_private_keys(
        &mutation_config
          .rollout
          .membership
          .readiness_private_key_file_env,
        &mutation_config
          .rollout
          .membership
          .catchup_private_key_file_env,
        local_instance_id
          .as_deref()
          .context("staged membership requires a local instance ID")?,
        &membership_bootstrap_members,
      )?)
    } else {
      None
    };
    let mut artifact_ciphers = MembershipArtifactCiphers::new();
    let legacy_cipher = if mutation_config.rollout.mode.is_cluster()
      && (!mutation_config.rollout.membership.mode.is_staged()
        || std::env::var_os(&mutation_config.artifact_key_env).is_some())
    {
      Some(Arc::new(MutationArtifactCipher::from_environment(
        &mutation_config.artifact_key_env,
        MAX_STORED_ARTIFACT_BYTES,
      )?))
    } else {
      None
    };
    if let Some(cipher) = legacy_cipher.as_ref() {
      artifact_ciphers.insert(target.membership_revision.clone(), cipher.clone());
    }
    let mut artifact_key_fingerprint = legacy_cipher.as_ref().map_or_else(
      || EMPTY_DIGEST.to_string(),
      |cipher| cipher.key_fingerprint().to_string(),
    );
    if mutation_config.rollout.membership.mode.is_staged() {
      super::membership_store::ensure_membership_head(&store, &mutation_config.rollout.cluster_id)
        .await?;
      let _ = super::membership_store::finalize_committed_membership_activation(
        &store,
        &mutation_config.rollout.cluster_id,
      )
      .await?;
      if let Some(legacy_cipher) = legacy_cipher.as_ref() {
        let local_member = local_instance_id
          .as_deref()
          .context("staged membership requires a local instance ID")?;
        for epoch_digest in super::membership_store::load_member_legacy_epoch_digests(
          &store,
          &mutation_config.rollout.cluster_id,
          local_member,
        )
        .await?
        {
          artifact_ciphers.insert(epoch_digest, legacy_cipher.clone());
        }
      }
      if let Some(active) = super::membership_store::load_active_membership_authority(
        &store,
        &mutation_config.rollout.cluster_id,
      )
      .await?
      {
        target.membership_revision = active.epoch_digest.clone();
        members = active.members.clone();
        if active.epoch_version == 1 {
          let local_member = local_instance_id
            .as_deref()
            .context("staged membership requires a local instance ID")?;
          if members
            .binary_search_by(|member| member.as_str().cmp(local_member))
            .is_ok()
          {
            let cipher = legacy_cipher.as_ref().context(
              "active legacy membership requires the shared artifact key until a v2 transition",
            )?;
            artifact_ciphers.insert(active.epoch_digest, cipher.clone());
            artifact_key_fingerprint = cipher.key_fingerprint().to_string();
          }
        } else {
          artifact_key_fingerprint = active
            .artifact_key_fingerprint
            .clone()
            .context("active membership epoch v2 is missing its artifact-key fingerprint")?;
          let local_member = local_instance_id
            .as_deref()
            .context("staged membership requires a local instance ID")?;
          if members
            .binary_search_by(|member| member.as_str().cmp(local_member))
            .is_ok()
          {
            let private = membership_private_keys
              .as_ref()
              .context("staged membership private keys are missing")?;
            membership_reconciliation::validate_local_epoch_identity(
              &active.epoch,
              local_member,
              &private.readiness_pkcs8,
              private.catchup_x25519.as_ref(),
            )
            .context("active membership epoch local identity is invalid")?;
            let cipher = super::membership_store::load_epoch_artifact_cipher_for_member(
              &store,
              &mutation_config.rollout.cluster_id,
              &active.epoch_digest,
              local_member,
              private.catchup_x25519.as_ref(),
              MAX_STORED_ARTIFACT_BYTES,
            )
            .await?;
            artifact_ciphers.clear();
            artifact_ciphers.insert(active.epoch_digest.clone(), cipher);
            ensure!(
              artifact_ciphers.contains_key(&target.membership_revision),
              "active membership epoch artifact key is unavailable to this member"
            );
          }
        }
      } else {
        let local_member = local_instance_id
          .as_deref()
          .context("staged membership requires a local instance ID")?;
        let local_is_bootstrap_member = members
          .binary_search_by(|member| member.as_str().cmp(local_member))
          .is_ok();
        if local_is_bootstrap_member {
          ensure!(
            legacy_cipher.is_some(),
            "staged membership bootstrap members require the legacy artifact key until v2 initialization"
          );
        }
      }
    }
    let winner_response_wait = cluster_checkpoint::winner_response_wait(
      mutation_config.rollout.phase_timeout_seconds,
      mutation_config.rollout.rollback_timeout_seconds,
      mutation_config.rollout.stale_after_seconds,
    )?;

    Ok(Self {
      inner: Arc::new(RuntimeInner {
        mode: mutation_config.mode,
        signers,
        store: Some(store),
        namespace: config.ipm.namespace.clone(),
        maximum_validity_seconds: mutation_config.max_validity_seconds,
        maximum_clock_skew_seconds: mutation_config.max_clock_skew_seconds,
        retention_seconds: i64::try_from(mutation_config.retention_seconds)
          .context("Admin mutation retention exceeds the supported range")?,
        rollout_mode: mutation_config.rollout.mode,
        membership_mode: mutation_config.rollout.membership.mode,
        cluster_id: mutation_config.rollout.cluster_id.clone(),
        membership_authority: RwLock::new(MembershipAuthority {
          target,
          members,
          artifact_key_fingerprint,
        }),
        membership_bootstrap_members,
        local_instance_id,
        membership_private_keys,
        artifact_ciphers: RwLock::new(artifact_ciphers),
        local_membership_heads: RwLock::new(HashMap::new()),
        cluster_controller: OnceLock::new(),
        cluster_worker_state: AtomicU8::new(0),
        winner_responses: Mutex::new(HashMap::new()),
        winner_response_wait,
      }),
    })
  }

  fn disabled(namespace: &str) -> Self {
    Self {
      inner: Arc::new(RuntimeInner {
        mode: AdminMutationMode::Off,
        signers: SignerRegistry::default(),
        store: None,
        namespace: namespace.to_string(),
        maximum_validity_seconds: 1,
        maximum_clock_skew_seconds: 0,
        retention_seconds: 1,
        rollout_mode: AdminMutationRolloutMode::SingleInstance,
        membership_mode: AdminMembershipMode::Fixed,
        cluster_id: String::new(),
        membership_authority: RwLock::new(MembershipAuthority {
          target: MutationTarget {
            cluster_id: "single".to_string(),
            membership_revision: digest_parts(["single"]),
          },
          members: Vec::new(),
          artifact_key_fingerprint: EMPTY_DIGEST.to_string(),
        }),
        membership_bootstrap_members: Vec::new(),
        local_instance_id: None,
        membership_private_keys: None,
        artifact_ciphers: RwLock::new(MembershipArtifactCiphers::new()),
        local_membership_heads: RwLock::new(HashMap::new()),
        cluster_controller: OnceLock::new(),
        cluster_worker_state: AtomicU8::new(0),
        winner_responses: Mutex::new(HashMap::new()),
        winner_response_wait: ORDINARY_TERMINAL_WAIT,
      }),
    }
  }

  #[cfg(test)]
  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn fixed_cluster_for_dispatch_test(
    pool: sqlx::PgPool,
    namespace: String,
    signers: SignerRegistry,
    target: MutationTarget,
    members: Vec<String>,
    local_instance_id: String,
    artifact_key: [u8; 32],
    baseline_revision: String,
    baseline_digest: String,
  ) -> anyhow::Result<Self> {
    ensure!(
      members.len() >= 2,
      "cluster test requires at least two members"
    );
    let store = MutationStore::new_cluster(pool, namespace.clone())?;
    let cipher = Arc::new(MutationArtifactCipher::new(
      &artifact_key,
      MAX_STORED_ARTIFACT_BYTES,
    )?);
    let artifact_key_fingerprint = cipher.key_fingerprint().to_string();
    let mut artifact_ciphers = MembershipArtifactCiphers::new();
    artifact_ciphers.insert(target.membership_revision.clone(), cipher);
    let runtime = Self {
      inner: Arc::new(RuntimeInner {
        mode: AdminMutationMode::Required,
        signers,
        store: Some(store.clone()),
        namespace,
        maximum_validity_seconds: 900,
        maximum_clock_skew_seconds: 30,
        retention_seconds: 86_400,
        rollout_mode: AdminMutationRolloutMode::AdminCluster,
        membership_mode: AdminMembershipMode::Fixed,
        cluster_id: target.cluster_id.clone(),
        membership_authority: RwLock::new(MembershipAuthority {
          target: target.clone(),
          members: members.clone(),
          artifact_key_fingerprint: artifact_key_fingerprint.clone(),
        }),
        membership_bootstrap_members: Vec::new(),
        local_instance_id: Some(local_instance_id.clone()),
        membership_private_keys: None,
        artifact_ciphers: RwLock::new(artifact_ciphers),
        local_membership_heads: RwLock::new(HashMap::new()),
        cluster_controller: OnceLock::new(),
        cluster_worker_state: AtomicU8::new(0),
        winner_responses: Mutex::new(HashMap::new()),
        winner_response_wait: ORDINARY_TERMINAL_WAIT,
      }),
    };
    for resource in ["config", "ipm", "break-glass"] {
      store
        .initialize_revision(
          resource,
          &baseline_revision,
          &baseline_digest,
          Some(&target.cluster_id),
          Some(&target.membership_revision),
        )
        .await?;
    }
    let controller = AdminClusterRolloutController::new(
      store.clone(),
      RolloutSettings {
        cluster_id: target.cluster_id,
        membership_revision: target.membership_revision,
        members: members.clone(),
        instance_id: local_instance_id.clone(),
        allow_learner: false,
        boot_id: format!("boot-{local_instance_id}"),
        build_version: oxibelt_build_identity::SHORT_VERSION.to_string(),
        artifact_key_fingerprint: artifact_key_fingerprint.clone(),
        heartbeat_interval: Duration::from_secs(1),
        stale_after: Duration::from_secs(30),
        phase_timeout: Duration::from_secs(30),
        rollback_timeout: Duration::from_secs(30),
        canary_observation: Duration::from_secs(1),
      },
      LocalRolloutStatus {
        assigned_revision: None,
        applied_revision: baseline_revision.clone(),
        applied_digest: baseline_digest.clone(),
        ready: true,
      },
    )?;
    controller.heartbeat_once().await?;
    let local_fence = controller.member_fence().await?;
    for resource in ["config", "ipm", "break-glass"] {
      super::rollout_store::publish_resource_head(
        &store,
        &local_fence,
        &super::rollout_store::ResourceHeadUpdate {
          resource: resource.to_string(),
          assigned_revision: None,
          applied_revision: baseline_revision.clone(),
          applied_digest: baseline_digest.clone(),
          ready: true,
        },
      )
      .await?;
    }
    for member in members
      .iter()
      .filter(|member| member.as_str() != local_instance_id.as_str())
    {
      let fence = super::rollout_store::heartbeat_fenced(
        &store,
        &super::rollout_store::HeartbeatUpdate {
          cluster_id: runtime.inner.cluster_id.clone(),
          instance_id: member.clone(),
          boot_id: format!("boot-{member}"),
          build_version: oxibelt_build_identity::SHORT_VERSION.to_string(),
          capability_version: "admin-mutation-rollout-v1".to_string(),
          artifact_key_fingerprint: artifact_key_fingerprint.clone(),
          membership_revision: runtime.membership_authority().target.membership_revision,
          assigned_revision: None,
          applied_revision: baseline_revision.clone(),
          applied_digest: baseline_digest.clone(),
          ready: true,
          lease_seconds: 30,
        },
      )
      .await?;
      for resource in ["config", "ipm", "break-glass"] {
        super::rollout_store::publish_resource_head(
          &store,
          &fence,
          &super::rollout_store::ResourceHeadUpdate {
            resource: resource.to_string(),
            assigned_revision: None,
            applied_revision: baseline_revision.clone(),
            applied_digest: baseline_digest.clone(),
            ready: true,
          },
        )
        .await?;
      }
    }
    runtime
      .inner
      .cluster_controller
      .set(controller.clone())
      .map_err(|_| anyhow::anyhow!("cluster test controller was already installed"))?;
    controller.heartbeat_and_refresh_readiness().await?;
    runtime.set_cluster_worker_running(true, true);
    runtime.set_cluster_worker_running(false, true);
    ensure!(
      runtime.cluster_rollout_ready(),
      "cluster test runtime is not ready"
    );
    Ok(runtime)
  }

  pub(crate) fn enabled(&self) -> bool {
    self.inner.mode.enabled()
  }

  pub(crate) fn required(&self) -> bool {
    self.inner.mode.required()
  }

  pub(crate) fn has_envelope(&self, headers: &HeaderMap) -> bool {
    headers.contains_key(MUTATION_HEADER)
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn admit(
    &self,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    authenticated_principal: &str,
    body: &[u8],
    action: &str,
    resource: &str,
    current_revision: &str,
    precondition_revision: &str,
    audit: &AdminAuditHandle,
    audit_runtime: &AdminAuditRuntime,
  ) -> Result<MutationAdmission, MutationAdmissionError> {
    if !self.enabled() {
      return Ok(MutationAdmission::Bypass);
    }
    if !self.has_envelope(headers) {
      return if self.required() {
        Err(
          MutationProtocolError::new(
            MutationProtocolErrorKind::MissingHeader,
            "mutation envelope header is required",
          )
          .into(),
        )
      } else {
        Ok(MutationAdmission::Bypass)
      };
    }

    let store = self.store()?;
    let now_unix_seconds: i64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::bigint")
      .fetch_one(store.pool())
      .await
      .context("failed to read authoritative mutation time")?;
    let path_and_query = uri
      .path_and_query()
      .map(|value| value.as_str())
      .unwrap_or_else(|| uri.path());
    let verified = self.inner.signers.verify(
      headers,
      &TranscriptContext {
        method,
        path_and_query,
        ipm_namespace: &self.inner.namespace,
        authenticated_principal,
        body,
        precondition_revision,
        now_unix_seconds,
        maximum_validity_seconds: self.inner.maximum_validity_seconds,
        maximum_clock_skew_seconds: self.inner.maximum_clock_skew_seconds,
      },
    )?;
    let authority = self.membership_authority();
    if verified.envelope.unsigned.target != authority.target {
      return Ok(MutationAdmission::Conflict(MutationConflict::Target));
    }

    let unsigned = &verified.envelope.unsigned;
    audit.record_mutation_context(
      &unsigned.signer_id,
      action,
      resource,
      &unsigned.expected_previous_revision,
      &unsigned.new_revision,
      &unsigned.content_digest,
      &unsigned.target.cluster_id,
      &unsigned.target.membership_revision,
    );
    let request_id = &verified.envelope.unsigned.request_id;
    let intent = audit.critical_mutation_event(request_id, StatusCode::ACCEPTED, "attempted", None);
    let audit_record_id = audit_runtime
      .persist_critical_mutation(intent)
      .await
      .context("failed to persist critical mutation audit intent")?;
    if let Err(error) = store.delete_expired_terminal_records(128).await {
      tracing::warn!(error = %error, "failed to prune expired Admin mutation receipts");
    }
    let claim = MutationClaim {
      request_id: unsigned.request_id.clone(),
      fingerprint: verified.fingerprint,
      principal: authenticated_principal.to_string(),
      signer_id: unsigned.signer_id.clone(),
      action: action.to_string(),
      resource: resource.to_string(),
      expected_previous_revision: unsigned.expected_previous_revision.clone(),
      new_revision: unsigned.new_revision.clone(),
      content_digest: unsigned.content_digest.clone(),
      cluster_id: Some(unsigned.target.cluster_id.clone()),
      membership_revision: Some(unsigned.target.membership_revision.clone()),
      issued_at: unsigned.issued_at.clone(),
      expires_at: unsigned.expires_at.clone(),
      allowed_clock_skew_seconds: i64::try_from(self.inner.maximum_clock_skew_seconds)
        .context("Admin mutation clock skew exceeds the supported range")?,
      retention_seconds: self.inner.retention_seconds,
      audit_record_id,
    };
    if let Some(record) = store
      .load_mutation(&claim.request_id)
      .await
      .context("failed to look up existing Admin mutation")?
    {
      return Ok(claim_outcome_admission(
        record.classify_existing_claim(&claim),
        audit,
        None,
      ));
    }
    if precondition_revision != current_revision {
      return Ok(MutationAdmission::PreconditionFailed {
        active_revision: current_revision.to_string(),
      });
    }
    if store
      .load_revision(resource)
      .await
      .context("failed to load Admin mutation logical revision")?
      .is_none()
    {
      store
        .initialize_revision(
          resource,
          current_revision,
          EMPTY_DIGEST,
          Some(&authority.target.cluster_id),
          Some(&authority.target.membership_revision),
        )
        .await
        .context("failed to initialize Admin mutation logical revision")?;
    }
    let outcome = store
      .claim(&claim)
      .await
      .context("failed to claim Admin mutation")?;
    Ok(claim_outcome_admission(outcome, audit, None))
  }

  pub(crate) async fn load_mutation(
    &self,
    request_id: &str,
  ) -> anyhow::Result<Option<MutationRecord>> {
    match &self.inner.store {
      Some(store) => store.load_mutation(request_id).await,
      None => Ok(None),
    }
  }

  pub(crate) fn configured_members(&self) -> Vec<String> {
    self.membership_authority().members
  }

  fn membership_authority(&self) -> MembershipAuthority {
    self
      .inner
      .membership_authority
      .read()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .clone()
  }

  pub(crate) fn cluster_mode(&self) -> bool {
    self.inner.rollout_mode == AdminMutationRolloutMode::AdminCluster
  }

  pub(crate) fn staged_membership(&self) -> bool {
    self.inner.membership_mode.is_staged()
  }

  pub(crate) fn membership_bootstrap_members(&self) -> &[MembershipMember] {
    &self.inner.membership_bootstrap_members
  }

  fn install_local_membership_heads(&self, heads: Vec<LocalMembershipHead>) -> anyhow::Result<()> {
    let mut installed = HashMap::with_capacity(heads.len());
    for head in heads {
      super::ledger::validate_identifier("local membership resource", &head.resource, 256)?;
      super::ledger::validate_identifier("local membership revision", &head.revision, 256)?;
      ensure!(
        super::artifact::is_sha256_digest(&head.digest),
        "local membership resource digest is invalid"
      );
      ensure!(
        installed.insert(head.resource.clone(), head).is_none(),
        "duplicate local membership resource head"
      );
    }
    *self
      .inner
      .local_membership_heads
      .write()
      .unwrap_or_else(std::sync::PoisonError::into_inner) = installed;
    Ok(())
  }

  fn update_local_membership_head(&self, head: LocalMembershipHead) {
    self
      .inner
      .local_membership_heads
      .write()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .insert(head.resource.clone(), head);
  }

  fn local_membership_heads(&self) -> HashMap<String, LocalMembershipHead> {
    self
      .inner
      .local_membership_heads
      .read()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .clone()
  }

  pub(crate) async fn membership_precondition_revision(&self) -> anyhow::Result<String> {
    if !self.staged_membership() {
      return Ok(self.membership_authority().target.membership_revision);
    }
    Ok(
      self
        .store()?
        .load_revision("membership")
        .await?
        .map(|revision| revision.committed_revision)
        .unwrap_or_else(|| "membership-uninitialized".to_string()),
    )
  }

  pub(crate) async fn membership_status(&self) -> anyhow::Result<Value> {
    if !self.staged_membership() {
      return Ok(json!({
        "mode": "fixed",
        "active_epoch": null,
        "pending_transition": null,
        "required_members": self.configured_members(),
      }));
    }
    let status = super::membership_store::load_membership_status(
      self.store()?,
      &self.inner.cluster_id,
      &self.inner.membership_bootstrap_members,
    )
    .await?;
    serde_json::to_value(status).context("failed to encode membership status")
  }

  pub(crate) async fn membership_catchup(&self, transition_id: &str) -> anyhow::Result<Value> {
    ensure!(self.staged_membership(), "staged membership is not enabled");
    let chunks = super::membership_store::load_membership_catchup(
      self.store()?,
      &self.inner.cluster_id,
      transition_id,
    )
    .await?;
    Ok(json!({
      "transition_id": transition_id,
      "chunk_count": chunks.len(),
      "chunks": chunks,
    }))
  }

  pub(crate) async fn submit_membership_readiness(
    &self,
    receipt: &MembershipReadinessReceipt,
  ) -> anyhow::Result<Value> {
    ensure!(self.staged_membership(), "staged membership is not enabled");
    let transition = super::membership_store::submit_membership_readiness(
      self.store()?,
      &self.inner.cluster_id,
      receipt,
    )
    .await?;
    Ok(json!({"ok":true,"transition":transition}))
  }

  #[allow(dead_code)]
  pub(crate) fn initialize_cluster_controller(
    &self,
    config: &Config,
    boot_id: String,
    applied_revision: String,
    applied_digest: String,
  ) -> anyhow::Result<bool> {
    if !self.cluster_mode() {
      return Ok(false);
    }
    let rollout = &config.admin.mutations.rollout;
    let instance_id = config
      .rollout
      .instance_id()
      .context("Admin cluster rollout identity is missing its instance ID")?
      .to_string();
    let authority = self.membership_authority();
    let controller = AdminClusterRolloutController::new(
      self.store()?.clone(),
      RolloutSettings {
        cluster_id: self.inner.cluster_id.clone(),
        membership_revision: authority.target.membership_revision.clone(),
        members: authority.members.clone(),
        instance_id,
        allow_learner: self.staged_membership(),
        boot_id,
        build_version: oxibelt_build_identity::SHORT_VERSION.to_string(),
        artifact_key_fingerprint: authority.artifact_key_fingerprint.clone(),
        heartbeat_interval: Duration::from_secs(rollout.heartbeat_interval_seconds),
        stale_after: Duration::from_secs(rollout.stale_after_seconds),
        phase_timeout: Duration::from_secs(rollout.phase_timeout_seconds),
        rollback_timeout: Duration::from_secs(rollout.rollback_timeout_seconds),
        canary_observation: Duration::from_secs(rollout.canary_observation_seconds),
      },
      LocalRolloutStatus {
        assigned_revision: None,
        applied_revision,
        applied_digest,
        ready: false,
      },
    )?;
    ensure!(
      controller.cluster_id() == authority.target.cluster_id
        && controller.membership_revision() == authority.target.membership_revision,
      "Admin cluster controller target does not match the mutation runtime"
    );
    self
      .inner
      .cluster_controller
      .set(controller)
      .map_err(|_| anyhow::anyhow!("Admin cluster controller is already initialized"))?;
    Ok(true)
  }

  #[allow(dead_code)]
  pub(crate) fn installed_cluster_controller(&self) -> Option<AdminClusterRolloutController> {
    self.inner.cluster_controller.get().cloned()
  }

  pub(crate) fn cluster_rollout_ready(&self) -> bool {
    !self.cluster_mode()
      || (self.inner.cluster_worker_state.load(Ordering::Acquire) == 0b11
        && self
          .inner
          .cluster_controller
          .get()
          .is_some_and(AdminClusterRolloutController::ready))
  }

  pub(crate) fn terminal_wait_timeout(&self, expects_winner_response: bool) -> Duration {
    if expects_winner_response {
      self.inner.winner_response_wait
    } else {
      ORDINARY_TERMINAL_WAIT
    }
  }

  pub(crate) fn set_cluster_worker_running(&self, member: bool, running: bool) {
    let bit = if member { 0b01 } else { 0b10 };
    if running {
      self
        .inner
        .cluster_worker_state
        .fetch_or(bit, Ordering::AcqRel);
    } else {
      self
        .inner
        .cluster_worker_state
        .fetch_and(!bit, Ordering::AcqRel);
    }
  }

  pub(crate) async fn fetch_cluster_artifact(
    &self,
    record: &MutationRecord,
  ) -> anyhow::Result<MutationArtifactPlaintext> {
    let controller = self.cluster_controller_ref()?;
    ensure_cluster_member(self, controller.instance_id())?;
    let binding = self.artifact_binding(record)?;
    let cipher = self.artifact_cipher_for_membership(
      record
        .membership_revision
        .as_deref()
        .context("cluster mutation is missing its membership revision")?,
    )?;
    let stored = artifact_store::fetch_for_member(
      self.store()?,
      controller.instance_id(),
      controller.boot_id(),
      &binding,
      cipher.maximum_plaintext_bytes(),
    )
    .await?;
    cipher.open(&binding, stored)
  }

  pub(crate) async fn fetch_cluster_command(
    &self,
    record: &MutationRecord,
  ) -> anyhow::Result<ClusterMutationCommand> {
    let binding = self.artifact_binding(record)?;
    let plaintext = self.fetch_cluster_artifact(record).await?;
    let command = ClusterMutationCommand::from_plaintext(&plaintext, &binding)?;
    command.reverify(
      &self.inner.signers,
      &self.inner.namespace,
      &binding,
      self.inner.maximum_validity_seconds,
      self.inner.maximum_clock_skew_seconds,
    )?;
    Ok(command)
  }

  #[allow(dead_code)]
  fn artifact_binding(&self, record: &MutationRecord) -> anyhow::Result<ArtifactBinding> {
    ensure!(
      record.cluster_id.as_deref() == Some(self.inner.cluster_id.as_str()),
      "mutation artifact cluster does not match this runtime"
    );
    ArtifactBinding::from_record(self.store()?.namespace(), record)
  }

  #[allow(dead_code)]
  pub(crate) fn artifact_cipher(&self) -> anyhow::Result<Arc<MutationArtifactCipher>> {
    let authority = self.membership_authority();
    self.artifact_cipher_for_membership(&authority.target.membership_revision)
  }

  pub(crate) fn artifact_cipher_for_membership(
    &self,
    membership_revision: &str,
  ) -> anyhow::Result<Arc<MutationArtifactCipher>> {
    self
      .inner
      .artifact_ciphers
      .read()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .get(membership_revision)
      .cloned()
      .with_context(|| {
        format!("artifact key for membership revision {membership_revision} is unavailable")
      })
  }

  pub(crate) fn artifact_ciphers(&self) -> MembershipArtifactCiphers {
    self
      .inner
      .artifact_ciphers
      .read()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .clone()
  }

  pub(crate) fn artifact_key_fingerprint(&self) -> String {
    self.membership_authority().artifact_key_fingerprint
  }

  #[allow(dead_code)]
  fn cluster_controller_ref(&self) -> anyhow::Result<&AdminClusterRolloutController> {
    self
      .inner
      .cluster_controller
      .get()
      .context("Admin cluster controller is not initialized")
  }

  pub(crate) async fn status(&self) -> anyhow::Result<Value> {
    let mut revisions = serde_json::Map::new();
    if let Some(store) = &self.inner.store {
      for resource in ["config", "ipm", "break-glass"] {
        if let Some(revision) = store.load_revision(resource).await? {
          revisions.insert(resource.to_string(), serde_json::to_value(revision)?);
        }
      }
    }
    Ok(json!({
      "enabled": self.enabled(),
      "required": self.required(),
      "target": self.membership_authority().target,
      "logical_revisions": revisions,
    }))
  }

  pub(crate) async fn active_break_glass_activation(
    &self,
    principal: &str,
  ) -> anyhow::Result<Option<BreakGlassActivation>> {
    load_active_break_glass_for_principal(self.store()?, principal).await
  }

  pub(crate) async fn create_break_glass_activation(
    &self,
    mutation_request_id: &str,
    activation_id: &str,
    principal: &str,
    scopes: &[String],
    ttl_seconds: u64,
    maximum_ttl_seconds: u64,
  ) -> anyhow::Result<BreakGlassActivation> {
    if ttl_seconds == 0 || ttl_seconds > maximum_ttl_seconds {
      bail!("break-glass activation TTL is outside the configured bound");
    }
    let ttl = i64::try_from(ttl_seconds).context("break-glass activation TTL is too large")?;
    let store = self.store()?;
    let mut tx = store.pool().begin().await?;
    let expires_at: String =
      sqlx::query_scalar("SELECT (now() + make_interval(secs => $1::double precision))::text")
        .bind(ttl as f64)
        .fetch_one(&mut *tx)
        .await?;
    let activation = create_break_glass_activation_tx(
      &mut tx,
      store.namespace(),
      activation_id,
      principal,
      scopes,
      mutation_request_id,
      &expires_at,
    )
    .await?;
    tx.commit().await?;
    Ok(activation)
  }

  pub(crate) async fn revoke_break_glass_activation(
    &self,
    activation_id: &str,
    principal: &str,
  ) -> anyhow::Result<bool> {
    let store = self.store()?;
    let mut tx = store.pool().begin().await?;
    let revoked =
      revoke_break_glass_activation_tx(&mut tx, store.namespace(), activation_id, principal)
        .await?;
    tx.commit().await?;
    Ok(revoked)
  }

  pub(crate) fn store(&self) -> anyhow::Result<&MutationStore> {
    self
      .inner
      .store
      .as_ref()
      .context("Admin mutation ledger is disabled")
  }
}

fn validate_durable_membership_configuration(
  mutations_enabled: bool,
  rollout_mode: AdminMutationRolloutMode,
  membership_mode: AdminMembershipMode,
  configured_cluster_id: &str,
  durable_cluster_ids: &[String],
) -> anyhow::Result<()> {
  if durable_cluster_ids.is_empty() {
    return Ok(());
  }
  ensure!(
    mutations_enabled,
    "durable staged membership state prevents disabling Admin mutations"
  );
  ensure!(
    rollout_mode.is_cluster() && membership_mode.is_staged(),
    "durable staged-membership state requires admin_cluster rollout with staged membership; restore the durable cluster configuration or complete an explicit supported retirement procedure"
  );
  ensure!(
    durable_cluster_ids.len() == 1 && durable_cluster_ids[0] == configured_cluster_id,
    "configured Admin membership cluster ID does not exactly match the durable staged-membership cluster"
  );
  Ok(())
}

async fn load_disabled_durable_membership_cluster_ids(
  config: &Config,
) -> anyhow::Result<Vec<String>> {
  let Some(backend_name) = config.admin.mutations.backend.as_deref() else {
    return Ok(Vec::new());
  };
  let Some(backend) = config
    .shared_state
    .backends
    .iter()
    .find(|backend| backend.name == backend_name)
  else {
    return Ok(Vec::new());
  };
  if backend.kind != crate::config::SharedStateBackendKind::Postgres {
    return Ok(Vec::new());
  }
  let connection_url =
    backend.connection_url_with_prefix(&format!("shared_state.backends.{}", backend.name))?;
  let mut options = PgConnectOptions::from_str(&connection_url)?
    .application_name("oxibelt-admin-membership-downgrade-guard")
    .ssl_mode(match backend.tls.mode {
      crate::config::DatabaseTlsMode::Off => PgSslMode::Disable,
      crate::config::DatabaseTlsMode::VerifyFull => PgSslMode::VerifyFull,
    });
  if let Some(ca_cert) = &backend.tls.ca_cert {
    options = options.ssl_root_cert(ca_cert);
  }
  if let (Some(client_cert), Some(client_key)) = (&backend.tls.client_cert, &backend.tls.client_key)
  {
    options = options
      .ssl_client_cert(client_cert)
      .ssl_client_key(client_key);
  }
  let pool = PgPoolOptions::new()
    .max_connections(1)
    .acquire_timeout(Duration::from_millis(backend.connect_timeout_ms))
    .connect_with(options)
    .await
    .context("failed to query the disabled Admin mutation membership authority")?;
  let result = super::membership_store::durable_membership_cluster_ids_if_present(
    &pool,
    &config.shared_state.namespace,
  )
  .await;
  pool.close().await;
  result
}

fn claim_outcome_admission(
  outcome: ClaimOutcome,
  audit: &AdminAuditHandle,
  winner_response: Option<cluster_checkpoint::SharedWinnerResponseGuard>,
) -> MutationAdmission {
  match outcome {
    ClaimOutcome::Claimed(record) => {
      audit.mark_critical_mutation_lifecycle_managed();
      MutationAdmission::Claimed(MutationExecution {
        request_id: record.request_id,
        new_revision: record.new_revision,
        winner_response,
      })
    }
    ClaimOutcome::Replay(record) => MutationAdmission::Replay(record),
    ClaimOutcome::InProgress(record) => MutationAdmission::InProgress(record),
    ClaimOutcome::RequestConflict => MutationAdmission::Conflict(MutationConflict::RequestId),
    ClaimOutcome::Expired => MutationAdmission::Conflict(MutationConflict::Expired),
    ClaimOutcome::RevisionConflict { actual_revision } => {
      MutationAdmission::Conflict(MutationConflict::Revision { actual_revision })
    }
    ClaimOutcome::RevisionBusy { request_id } => {
      MutationAdmission::Conflict(MutationConflict::Busy { request_id })
    }
    ClaimOutcome::TargetConflict => MutationAdmission::Conflict(MutationConflict::Target),
  }
}

#[derive(Debug)]
pub(crate) enum MutationAdmissionError {
  Protocol(MutationProtocolError),
  Runtime(anyhow::Error),
}

impl From<MutationProtocolError> for MutationAdmissionError {
  fn from(value: MutationProtocolError) -> Self {
    Self::Protocol(value)
  }
}

impl From<anyhow::Error> for MutationAdmissionError {
  fn from(value: anyhow::Error) -> Self {
    Self::Runtime(value)
  }
}

impl MutationAdmissionError {
  pub(crate) fn status(&self) -> StatusCode {
    match self {
      Self::Protocol(error) => error.http_status(),
      Self::Runtime(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
  }

  pub(crate) fn code(&self) -> &'static str {
    match self {
      Self::Protocol(error) => error.code(),
      Self::Runtime(_) => "mutation_store_unavailable",
    }
  }
}

impl MutationConflict {
  pub(crate) fn status(&self) -> StatusCode {
    match self {
      Self::Expired => StatusCode::BAD_REQUEST,
      _ => StatusCode::CONFLICT,
    }
  }

  pub(crate) fn code(&self) -> &'static str {
    match self {
      Self::RequestId => "mutation_request_id_conflict",
      Self::Expired => "mutation_expired",
      Self::Revision { .. } => "mutation_revision_conflict",
      Self::Busy { .. } => "mutation_in_progress",
      Self::Target => "mutation_target_conflict",
    }
  }

  pub(crate) fn details(&self) -> Value {
    match self {
      Self::Revision { actual_revision } => json!({ "actual_revision": actual_revision }),
      Self::Busy { request_id } => json!({ "blocking_request_id": request_id }),
      _ => json!({}),
    }
  }
}

fn load_membership_private_keys(
  readiness_environment: &str,
  catchup_environment: &str,
  instance_id: &str,
  bootstrap_members: &[MembershipMember],
) -> anyhow::Result<MembershipPrivateKeys> {
  let readiness_path = std::env::var(readiness_environment).with_context(|| {
    format!("failed to read membership readiness key path from {readiness_environment}")
  })?;
  let catchup_path = std::env::var(catchup_environment).with_context(|| {
    format!("failed to read membership catch-up key path from {catchup_environment}")
  })?;
  ensure!(
    readiness_path != catchup_path,
    "membership readiness and catch-up private keys must use different files"
  );
  let readiness_file = read_bounded_membership_private_key(
    Path::new(&readiness_path),
    "membership readiness private key",
    4_096,
  )?;
  let readiness_pkcs8 =
    decode_optional_base64_private_key(readiness_file, "membership readiness private key")?;
  let readiness_pair = Ed25519KeyPair::from_pkcs8(&readiness_pkcs8)
    .map_err(|_| anyhow::anyhow!("membership readiness private key is not Ed25519 PKCS#8"))?;
  let catchup_file = read_bounded_membership_private_key(
    Path::new(&catchup_path),
    "membership catch-up private key",
    256,
  )?;
  let catchup =
    decode_optional_base64_private_key(catchup_file, "membership catch-up private key")?;
  let catchup_x25519: [u8; 32] = catchup
    .as_slice()
    .try_into()
    .map_err(|_| anyhow::anyhow!("membership catch-up private key must contain 32 bytes"))?;
  let catchup_private = PrivateKey::from_private_key(&X25519, &catchup_x25519)
    .map_err(|_| anyhow::anyhow!("membership catch-up X25519 private key is invalid"))?;
  let catchup_public = catchup_private
    .compute_public_key()
    .map_err(|_| anyhow::anyhow!("failed to derive membership catch-up public key"))?;
  if let Some(member) = bootstrap_members
    .iter()
    .find(|member| member.id == instance_id)
  {
    ensure!(
      base64::engine::general_purpose::STANDARD.encode(readiness_pair.public_key().as_ref())
        == member.readiness_ed25519_public_key,
      "membership readiness private key does not match the bootstrap member identity"
    );
    ensure!(
      base64::engine::general_purpose::STANDARD.encode(catchup_public.as_ref())
        == member.catchup_x25519_public_key,
      "membership catch-up private key does not match the bootstrap member identity"
    );
  }
  Ok(MembershipPrivateKeys {
    readiness_pkcs8,
    catchup_x25519: Zeroizing::new(catchup_x25519),
  })
}

fn read_bounded_membership_private_key(
  path: &Path,
  label: &str,
  maximum_bytes: u64,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  ensure!(path.is_absolute(), "{label} path must be absolute");
  let mut options = OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  }
  let file = options
    .open(path)
    .with_context(|| format!("failed to open {label} file"))?;
  let metadata = file
    .metadata()
    .with_context(|| format!("failed to inspect {label} file"))?;
  ensure!(
    metadata.file_type().is_file(),
    "{label} must be a regular file"
  );
  ensure!(
    (1..=maximum_bytes).contains(&metadata.len()),
    "{label} file size is outside its bound"
  );
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt as _;
    ensure!(
      metadata.permissions().mode() & 0o077 == 0,
      "{label} permissions must not grant group or other access"
    );
  }
  let mut value = Zeroizing::new(Vec::with_capacity(
    usize::try_from(metadata.len()).context("membership private-key size exceeds usize")?,
  ));
  file
    .take(maximum_bytes.saturating_add(1))
    .read_to_end(&mut value)
    .with_context(|| format!("failed to read {label}"))?;
  ensure!(
    !value.is_empty() && value.len() as u64 <= maximum_bytes,
    "{label} changed outside its size bound while being read"
  );
  Ok(value)
}

fn decode_optional_base64_private_key(
  value: Zeroizing<Vec<u8>>,
  label: &str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  let Ok(text) = std::str::from_utf8(&value) else {
    return Ok(value);
  };
  let trimmed = text.trim();
  let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) else {
    return Ok(value);
  };
  if base64::engine::general_purpose::STANDARD.encode(&decoded) != trimmed {
    bail!("{label} base64 encoding is not canonical");
  }
  ensure!(!decoded.is_empty(), "{label} must not be empty");
  Ok(Zeroizing::new(decoded))
}

fn load_signer(config: &crate::config::AdminMutationSignerConfig) -> anyhow::Result<SignerBinding> {
  let ed25519 = fs::read(&config.ed25519_public_key_file).with_context(|| {
    format!(
      "failed to read Admin mutation Ed25519 public key {}",
      config.ed25519_public_key_file.display()
    )
  })?;
  match config.suite {
    AdminMutationSignatureSuite::Ed25519 => {
      SignerBinding::ed25519(&config.id, &config.principal, ed25519).map_err(anyhow::Error::new)
    }
    AdminMutationSignatureSuite::Ed25519MlDsa44 => {
      #[cfg(feature = "mutation-pqc")]
      {
        let path = config
          .ml_dsa_44_public_key_file
          .as_ref()
          .context("hybrid Admin mutation signer is missing its ML-DSA-44 public key")?;
        let ml_dsa = fs::read(path).with_context(|| {
          format!(
            "failed to read Admin mutation ML-DSA-44 public key {}",
            path.display()
          )
        })?;
        SignerBinding::ed25519_ml_dsa_44(&config.id, &config.principal, ed25519, ml_dsa)
          .map_err(anyhow::Error::new)
      }
      #[cfg(not(feature = "mutation-pqc"))]
      {
        let _ = ed25519;
        bail!("hybrid Admin mutation signer requires the mutation-pqc feature")
      }
    }
  }
}

#[path = "runtime/cluster_admission.rs"]
mod cluster_admission;
#[path = "runtime/cluster_checkpoint.rs"]
mod cluster_checkpoint;
#[path = "runtime/cluster_diagnostics.rs"]
mod cluster_diagnostics;
#[path = "runtime/cluster_heartbeat.rs"]
mod cluster_heartbeat;
#[path = "runtime/cluster_worker.rs"]
mod cluster_worker;
#[path = "runtime/membership_reconciliation.rs"]
mod membership_reconciliation;
#[path = "runtime/target.rs"]
mod target;
#[path = "runtime/terminal.rs"]
mod terminal;
#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
