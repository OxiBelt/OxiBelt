//! Signed Admin mutation replay-protection and cluster-rollout configuration.
//!
//! This configuration is a control-plane trust root.  Runtime Admin mutations
//! may use it, but may not replace it while finalizing their own request.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use super::{
  AdminAuditMode, Config, IpmBreakGlassAccessMode, SharedStateBackendKind,
  resolve_existing_local_config_file_path_with_logical, validate_optional_non_empty,
  validate_runtime_identifier,
};

const MAX_VALIDITY_SECONDS: u64 = 3_600;
const MAX_CLOCK_SKEW_SECONDS: u64 = 300;
const MAX_RETENTION_SECONDS: u64 = 31_536_000;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminMutationMode {
  #[default]
  Off,
  Optional,
  Required,
}

impl AdminMutationMode {
  pub fn enabled(self) -> bool {
    self != Self::Off
  }

  pub fn required(self) -> bool {
    self == Self::Required
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminMutationRolloutMode {
  #[default]
  SingleInstance,
  AdminCluster,
}

impl AdminMutationRolloutMode {
  pub fn is_cluster(self) -> bool {
    self == Self::AdminCluster
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminMutationSignatureSuite {
  #[default]
  Ed25519,
  Ed25519MlDsa44,
}

impl AdminMutationSignatureSuite {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Ed25519 => "ed25519",
      Self::Ed25519MlDsa44 => "ed25519_ml_dsa_44",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminMutationSignerConfig {
  pub id: String,
  pub principal: String,
  #[serde(default)]
  pub suite: AdminMutationSignatureSuite,
  pub ed25519_public_key_file: PathBuf,
  #[serde(default)]
  pub ml_dsa_44_public_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminMutationRolloutConfig {
  #[serde(default)]
  pub mode: AdminMutationRolloutMode,
  #[serde(default)]
  pub cluster_id: String,
  #[serde(default)]
  pub members: Vec<String>,
  #[serde(default = "default_instance_id_env")]
  pub instance_id_env: String,
  #[serde(default = "default_heartbeat_interval_seconds")]
  pub heartbeat_interval_seconds: u64,
  #[serde(default = "default_stale_after_seconds")]
  pub stale_after_seconds: u64,
  #[serde(default = "default_phase_timeout_seconds")]
  pub phase_timeout_seconds: u64,
  #[serde(default = "default_rollback_timeout_seconds")]
  pub rollback_timeout_seconds: u64,
  #[serde(default = "default_canary_observation_seconds")]
  pub canary_observation_seconds: u64,
}

impl Default for AdminMutationRolloutConfig {
  fn default() -> Self {
    Self {
      mode: AdminMutationRolloutMode::SingleInstance,
      cluster_id: String::new(),
      members: Vec::new(),
      instance_id_env: default_instance_id_env(),
      heartbeat_interval_seconds: default_heartbeat_interval_seconds(),
      stale_after_seconds: default_stale_after_seconds(),
      phase_timeout_seconds: default_phase_timeout_seconds(),
      rollback_timeout_seconds: default_rollback_timeout_seconds(),
      canary_observation_seconds: default_canary_observation_seconds(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminMutationsConfig {
  #[serde(default)]
  pub mode: AdminMutationMode,
  #[serde(default)]
  pub backend: Option<String>,
  #[serde(default = "default_max_validity_seconds")]
  pub max_validity_seconds: u64,
  #[serde(default = "default_max_clock_skew_seconds")]
  pub max_clock_skew_seconds: u64,
  #[serde(default = "default_retention_seconds")]
  pub retention_seconds: u64,
  #[serde(default = "default_max_response_bytes")]
  pub max_response_bytes: usize,
  #[serde(default = "default_artifact_key_env")]
  pub artifact_key_env: String,
  #[serde(default)]
  pub rollout: AdminMutationRolloutConfig,
  #[serde(default)]
  pub signers: Vec<AdminMutationSignerConfig>,
}

impl Default for AdminMutationsConfig {
  fn default() -> Self {
    Self {
      mode: AdminMutationMode::Off,
      backend: None,
      max_validity_seconds: default_max_validity_seconds(),
      max_clock_skew_seconds: default_max_clock_skew_seconds(),
      retention_seconds: default_retention_seconds(),
      max_response_bytes: default_max_response_bytes(),
      artifact_key_env: default_artifact_key_env(),
      rollout: AdminMutationRolloutConfig::default(),
      signers: Vec::new(),
    }
  }
}

impl Config {
  pub(super) fn resolve_admin_mutation_signer_paths(
    &mut self,
    config_dir: &Path,
  ) -> anyhow::Result<()> {
    for (index, signer) in self.admin.mutations.signers.iter_mut().enumerate() {
      let field = format!("admin.mutations.signers[{index}].ed25519_public_key_file");
      let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
        &field,
        config_dir,
        &signer.ed25519_public_key_file,
      )?;
      signer.ed25519_public_key_file = resolved;
      self.source_paths.remember_runtime_file(logical);
      signer.ml_dsa_44_public_key_file = signer
        .ml_dsa_44_public_key_file
        .take()
        .map(|path| {
          let field = format!("admin.mutations.signers[{index}].ml_dsa_44_public_key_file");
          let (resolved, logical) =
            resolve_existing_local_config_file_path_with_logical(&field, config_dir, &path)?;
          self.source_paths.remember_runtime_file(logical);
          Ok::<PathBuf, anyhow::Error>(resolved)
        })
        .transpose()?;
    }
    Ok(())
  }

  pub(super) fn validate_admin_mutations(&self) -> anyhow::Result<()> {
    let mutations = &self.admin.mutations;
    validate_optional_non_empty("admin.mutations.backend", mutations.backend.as_deref())?;
    if !mutations.mode.enabled() {
      if self.rollout.is_admin_cluster() {
        bail!(
          "OXIBELT_CONFIG_ROLLOUT_MODE=admin_cluster requires admin.mutations.mode to be enabled"
        );
      }
      if self.ipm.break_glass.access_mode == IpmBreakGlassAccessMode::TwoFactorActivation {
        bail!(
          "ipm.break_glass.access_mode = \"two_factor_activation\" requires admin.mutations.mode to be enabled"
        );
      }
      if mutations.rollout.mode.is_cluster() {
        bail!(
          "admin.mutations.rollout.mode = \"admin_cluster\" requires admin.mutations.mode to be enabled"
        );
      }
      return Ok(());
    }

    if !self.admin.enabled || !self.ipm.enabled {
      bail!("admin.mutations requires admin.enabled = true and ipm.enabled = true");
    }
    if mutations.max_validity_seconds == 0 || mutations.max_validity_seconds > MAX_VALIDITY_SECONDS
    {
      bail!("admin.mutations.max_validity_seconds must be between 1 and {MAX_VALIDITY_SECONDS}");
    }
    if mutations.max_clock_skew_seconds == 0
      || mutations.max_clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS
      || mutations.max_clock_skew_seconds >= mutations.max_validity_seconds
    {
      bail!(
        "admin.mutations.max_clock_skew_seconds must be between 1 and {MAX_CLOCK_SKEW_SECONDS} and below max_validity_seconds"
      );
    }
    if mutations.retention_seconds
      < mutations
        .max_validity_seconds
        .saturating_add(mutations.max_clock_skew_seconds)
      || mutations.retention_seconds > MAX_RETENTION_SECONDS
    {
      bail!(
        "admin.mutations.retention_seconds must cover the validity and skew windows and be at most {MAX_RETENTION_SECONDS}"
      );
    }
    if mutations.max_response_bytes == 0 || mutations.max_response_bytes > MAX_RESPONSE_BYTES {
      bail!("admin.mutations.max_response_bytes must be between 1 and {MAX_RESPONSE_BYTES}");
    }

    let backend_name = mutations.backend.as_deref().ok_or_else(|| {
      anyhow::anyhow!("admin.mutations.backend is required when mutations are enabled")
    })?;
    if !self.shared_state.enabled {
      bail!("admin.mutations.backend requires shared_state.enabled = true");
    }
    let backend = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
      .ok_or_else(|| {
        anyhow::anyhow!(
          "admin.mutations.backend references unknown shared_state backend {backend_name}"
        )
      })?;
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("admin.mutations.backend {backend_name} must use kind = \"postgres\"");
    }
    if !self.admin.audit.enabled
      || self.admin.audit.mode != AdminAuditMode::Enforcing
      || !self.admin.audit.store.enabled
      || self.admin.audit.store.backend.as_deref() != Some(backend_name)
    {
      bail!(
        "admin.mutations requires enforcing Admin audit storage on the same PostgreSQL backend"
      );
    }

    validate_mutation_signers(&mutations.signers)?;
    if self.rollout.is_admin_cluster() != mutations.rollout.mode.is_cluster() {
      bail!(
        "process and admin.mutations rollout modes must both select admin_cluster or neither may select it"
      );
    }
    if mutations.rollout.mode.is_cluster() {
      self.validate_admin_cluster_rollout()?;
    }
    Ok(())
  }

  fn validate_admin_cluster_rollout(&self) -> anyhow::Result<()> {
    bail!(
      "admin.mutations.rollout.mode = \"admin_cluster\" is reserved and fail-closed; use \"single_instance\""
    )
  }
}

fn validate_mutation_signers(signers: &[AdminMutationSignerConfig]) -> anyhow::Result<()> {
  if signers.is_empty() {
    bail!("admin.mutations.signers must contain at least one signer");
  }
  let mut ids = HashSet::new();
  for signer in signers {
    validate_runtime_identifier("admin.mutations.signers.id", &signer.id)?;
    validate_runtime_identifier("admin.mutations.signers.principal", &signer.principal)?;
    if !ids.insert(signer.id.as_str()) {
      bail!("duplicate admin mutation signer {}", signer.id);
    }
    validate_public_key_file(
      "admin.mutations.signers.ed25519_public_key_file",
      &signer.ed25519_public_key_file,
    )?;
    match signer.suite {
      AdminMutationSignatureSuite::Ed25519 => {
        if signer.ml_dsa_44_public_key_file.is_some() {
          bail!(
            "Ed25519-only mutation signer {} must not set ml_dsa_44_public_key_file",
            signer.id
          );
        }
      }
      AdminMutationSignatureSuite::Ed25519MlDsa44 => {
        if !cfg!(feature = "mutation-pqc") {
          bail!(
            "mutation signer {} requires a build with the mutation-pqc feature",
            signer.id
          );
        }
        let path = signer.ml_dsa_44_public_key_file.as_deref().ok_or_else(|| {
          anyhow::anyhow!(
            "hybrid mutation signer {} requires ml_dsa_44_public_key_file",
            signer.id
          )
        })?;
        validate_public_key_file("admin.mutations.signers.ml_dsa_44_public_key_file", path)?;
      }
    }
  }
  Ok(())
}

fn validate_public_key_file(name: &str, path: &std::path::Path) -> anyhow::Result<()> {
  let metadata = std::fs::metadata(path)
    .with_context(|| format!("failed to inspect {name} {}", path.display()))?;
  if !metadata.is_file() {
    bail!("{name} must point to a regular file");
  }
  Ok(())
}

fn default_instance_id_env() -> String {
  "OXIBELT_INSTANCE_ID".to_string()
}

fn default_artifact_key_env() -> String {
  "OXIBELT_ADMIN_MUTATION_ARTIFACT_KEY".to_string()
}

const fn default_max_validity_seconds() -> u64 {
  600
}

const fn default_max_clock_skew_seconds() -> u64 {
  30
}

const fn default_retention_seconds() -> u64 {
  86_400
}

const fn default_max_response_bytes() -> usize {
  1024 * 1024
}

const fn default_heartbeat_interval_seconds() -> u64 {
  5
}

const fn default_stale_after_seconds() -> u64 {
  15
}

const fn default_phase_timeout_seconds() -> u64 {
  300
}

const fn default_rollback_timeout_seconds() -> u64 {
  300
}

const fn default_canary_observation_seconds() -> u64 {
  30
}
