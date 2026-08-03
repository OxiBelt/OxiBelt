//! Signed Admin mutation replay-protection and cluster-rollout configuration.
//!
//! This configuration is a control-plane trust root.  Runtime Admin mutations
//! may use it, but may not replace it while finalizing their own request.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use base64::Engine as _;
use serde::Deserialize;

use super::{
  ADMIN_AUDIT_PROTECTED_MUTATION_ACTIONS, AdminAuditMode, Config, IpmBreakGlassAccessMode,
  SharedStateBackendKind, resolve_existing_local_config_file_path_with_logical,
  validate_base64_32_byte_env, validate_optional_non_empty, validate_runtime_identifier,
};

const MAX_VALIDITY_SECONDS: u64 = 3_600;
const MAX_CLOCK_SKEW_SECONDS: u64 = 300;
const MAX_RETENTION_SECONDS: u64 = 31_536_000;
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLUSTER_MEMBERS: usize = 1_024;
const MAX_HEARTBEAT_INTERVAL_SECONDS: u64 = 60;
const MAX_STALE_AFTER_SECONDS: u64 = 300;
const MAX_CANARY_OBSERVATION_SECONDS: u64 = 600;
const MAX_PHASE_TIMEOUT_SECONDS: u64 = 3_600;
const MAX_ROLLBACK_TIMEOUT_SECONDS: u64 = 3_600;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminMembershipMode {
  #[default]
  Fixed,
  Staged,
}

impl AdminMembershipMode {
  pub const fn is_staged(self) -> bool {
    matches!(self, Self::Staged)
  }
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminMembershipBootstrapMember {
  pub id: String,
  pub readiness_ed25519_public_key: String,
  pub catchup_x25519_public_key: String,
}

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminMembershipConfig {
  #[serde(default)]
  pub mode: AdminMembershipMode,
  #[serde(default)]
  pub bootstrap_members: Vec<AdminMembershipBootstrapMember>,
  #[serde(default = "default_membership_readiness_key_env")]
  pub readiness_private_key_file_env: String,
  #[serde(default = "default_membership_catchup_key_env")]
  pub catchup_private_key_file_env: String,
}

impl Default for AdminMembershipConfig {
  fn default() -> Self {
    Self {
      mode: AdminMembershipMode::Fixed,
      bootstrap_members: Vec::new(),
      readiness_private_key_file_env: default_membership_readiness_key_env(),
      catchup_private_key_file_env: default_membership_catchup_key_env(),
    }
  }
}

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
  #[serde(default)]
  pub membership: AdminMembershipConfig,
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
      membership: AdminMembershipConfig::default(),
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
    let audit_covers_protected_mutations = self.admin.audit.mode == AdminAuditMode::DurableRequired
      || (self.admin.audit.mode == AdminAuditMode::DurableRequiredForActions
        && ADMIN_AUDIT_PROTECTED_MUTATION_ACTIONS
          .iter()
          .all(|required| {
            self
              .admin
              .audit
              .required_actions
              .iter()
              .any(|configured| configured == required)
          }));
    if !self.admin.audit.enabled
      || !audit_covers_protected_mutations
      || !self.admin.audit.store.enabled
      || self.admin.audit.store.backend.as_deref() != Some(backend_name)
    {
      bail!(
        "admin.mutations requires durable Admin audit coverage for every protected mutation action and storage on the same PostgreSQL backend"
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
    } else if mutations.rollout.membership.mode.is_staged()
      || !mutations.rollout.membership.bootstrap_members.is_empty()
    {
      bail!("staged Admin membership requires admin.mutations.rollout.mode = \"admin_cluster\"");
    }
    Ok(())
  }

  fn validate_admin_cluster_rollout(&self) -> anyhow::Result<()> {
    let mutations = &self.admin.mutations;
    let rollout = &mutations.rollout;
    if !mutations.mode.required() {
      bail!("admin_cluster rollout requires admin.mutations.mode = \"required\"");
    }
    if !self.ipm.enabled || self.ipm_backend_name() != mutations.backend.as_deref() {
      bail!(
        "admin_cluster rollout requires enabled IPM storage on the same PostgreSQL backend as admin.mutations.backend"
      );
    }
    validate_runtime_identifier("admin.mutations.rollout.cluster_id", &rollout.cluster_id)?;
    if rollout.cluster_id.len() > 253 {
      bail!("admin.mutations.rollout.cluster_id must not exceed 253 bytes");
    }
    if !(2..=MAX_CLUSTER_MEMBERS).contains(&rollout.members.len()) {
      bail!(
        "admin.mutations.rollout.members must contain between 2 and {MAX_CLUSTER_MEMBERS} members"
      );
    }
    let mut members = BTreeSet::new();
    for member in &rollout.members {
      validate_runtime_identifier("admin.mutations.rollout.members", member)?;
      if member.len() > 253 {
        bail!("admin.mutations.rollout member {member} must not exceed 253 bytes");
      }
      if !members.insert(member.as_str()) {
        bail!("duplicate admin.mutations.rollout member {member}");
      }
    }
    validate_environment_name(
      "admin.mutations.rollout.instance_id_env",
      &rollout.instance_id_env,
    )?;
    let instance_id = std::env::var(&rollout.instance_id_env).with_context(|| {
      format!(
        "failed to read admin.mutations.rollout.instance_id_env {}",
        rollout.instance_id_env
      )
    })?;
    validate_runtime_identifier("Admin cluster instance ID", &instance_id)?;
    if instance_id.len() > 253
      || (!rollout.membership.mode.is_staged() && !members.contains(instance_id.as_str()))
    {
      bail!(
        "Admin cluster instance ID must be one of admin.mutations.rollout.members unless staged membership learner mode is enabled"
      );
    }
    validate_environment_name(
      "admin.mutations.artifact_key_env",
      &mutations.artifact_key_env,
    )?;
    validate_base64_32_byte_env(
      "admin.mutations.artifact_key_env",
      &mutations.artifact_key_env,
    )?;
    if !(1..=MAX_HEARTBEAT_INTERVAL_SECONDS).contains(&rollout.heartbeat_interval_seconds) {
      bail!(
        "admin.mutations.rollout.heartbeat_interval_seconds must be between 1 and {MAX_HEARTBEAT_INTERVAL_SECONDS}"
      );
    }
    if rollout.stale_after_seconds < rollout.heartbeat_interval_seconds.saturating_mul(2)
      || rollout.stale_after_seconds > MAX_STALE_AFTER_SECONDS
    {
      bail!(
        "admin.mutations.rollout.stale_after_seconds must be at least twice heartbeat_interval_seconds and at most {MAX_STALE_AFTER_SECONDS}"
      );
    }
    if !(1..=MAX_CANARY_OBSERVATION_SECONDS).contains(&rollout.canary_observation_seconds) {
      bail!(
        "admin.mutations.rollout.canary_observation_seconds must be between 1 and {MAX_CANARY_OBSERVATION_SECONDS}"
      );
    }
    if rollout.phase_timeout_seconds <= rollout.canary_observation_seconds
      || rollout.phase_timeout_seconds > MAX_PHASE_TIMEOUT_SECONDS
    {
      bail!(
        "admin.mutations.rollout.phase_timeout_seconds must exceed canary_observation_seconds and be at most {MAX_PHASE_TIMEOUT_SECONDS}"
      );
    }
    if !(1..=MAX_ROLLBACK_TIMEOUT_SECONDS).contains(&rollout.rollback_timeout_seconds) {
      bail!(
        "admin.mutations.rollout.rollback_timeout_seconds must be between 1 and {MAX_ROLLBACK_TIMEOUT_SECONDS}"
      );
    }
    validate_membership_config(rollout)?;
    Ok(())
  }
}

fn validate_membership_config(rollout: &AdminMutationRolloutConfig) -> anyhow::Result<()> {
  let membership = &rollout.membership;
  if !membership.mode.is_staged() {
    if !membership.bootstrap_members.is_empty() {
      bail!(
        "admin.mutations.rollout.membership.bootstrap_members requires membership.mode = \"staged\""
      );
    }
    return Ok(());
  }
  if membership.bootstrap_members.len() != rollout.members.len() {
    bail!(
      "staged Admin membership bootstrap_members must exactly cover admin.mutations.rollout.members"
    );
  }
  let configured = rollout
    .members
    .iter()
    .map(String::as_str)
    .collect::<BTreeSet<_>>();
  let mut bootstrap = BTreeSet::new();
  for member in &membership.bootstrap_members {
    validate_runtime_identifier(
      "admin.mutations.rollout.membership.bootstrap_members.id",
      &member.id,
    )?;
    if !bootstrap.insert(member.id.as_str()) {
      bail!(
        "duplicate staged Admin membership bootstrap member {}",
        member.id
      );
    }
    validate_base64_public_key(
      "admin.mutations.rollout.membership.bootstrap_members.readiness_ed25519_public_key",
      &member.readiness_ed25519_public_key,
    )?;
    validate_base64_public_key(
      "admin.mutations.rollout.membership.bootstrap_members.catchup_x25519_public_key",
      &member.catchup_x25519_public_key,
    )?;
  }
  if bootstrap != configured {
    bail!(
      "staged Admin membership bootstrap member IDs must exactly match admin.mutations.rollout.members"
    );
  }
  validate_environment_name(
    "admin.mutations.rollout.membership.readiness_private_key_file_env",
    &membership.readiness_private_key_file_env,
  )?;
  validate_environment_name(
    "admin.mutations.rollout.membership.catchup_private_key_file_env",
    &membership.catchup_private_key_file_env,
  )?;
  if membership.readiness_private_key_file_env == membership.catchup_private_key_file_env {
    bail!("Admin membership readiness and catch-up keys must use distinct environment variables");
  }
  Ok(())
}

fn validate_base64_public_key(field: &str, value: &str) -> anyhow::Result<()> {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(value)
    .with_context(|| format!("{field} must be canonical base64"))?;
  if decoded.len() != 32 || base64::engine::general_purpose::STANDARD.encode(decoded) != value {
    bail!("{field} must encode exactly 32 bytes using canonical base64");
  }
  Ok(())
}

fn validate_environment_name(field: &str, value: &str) -> anyhow::Result<()> {
  let mut bytes = value.bytes();
  let starts_valid = bytes
    .next()
    .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
  if !starts_valid
    || value.len() > 253
    || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
  {
    bail!("{field} must contain a valid environment variable name");
  }
  Ok(())
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

fn default_membership_readiness_key_env() -> String {
  "OXIBELT_ADMIN_MEMBERSHIP_READINESS_KEY_FILE".to_string()
}

fn default_membership_catchup_key_env() -> String {
  "OXIBELT_ADMIN_MEMBERSHIP_CATCHUP_KEY_FILE".to_string()
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cluster_environment_names_are_shell_safe() {
    for valid in ["OXIBELT_INSTANCE_ID", "_PRIVATE", "KEY2"] {
      validate_environment_name("test", valid).expect("valid environment name");
    }
    for invalid in ["", "2KEY", "KEY-NAME", "KEY.NAME", " PADDED"] {
      assert!(
        validate_environment_name("test", invalid).is_err(),
        "accepted {invalid:?}"
      );
    }
  }

  #[test]
  fn staged_membership_requires_exact_bootstrap_identity_and_distinct_keys() {
    let key = |byte: u8| base64::engine::general_purpose::STANDARD.encode([byte; 32]);
    let mut rollout = AdminMutationRolloutConfig {
      mode: AdminMutationRolloutMode::AdminCluster,
      cluster_id: "cluster-a".to_string(),
      members: vec!["edge-a".to_string(), "edge-b".to_string()],
      membership: AdminMembershipConfig {
        mode: AdminMembershipMode::Staged,
        bootstrap_members: vec![
          AdminMembershipBootstrapMember {
            id: "edge-a".to_string(),
            readiness_ed25519_public_key: key(1),
            catchup_x25519_public_key: key(2),
          },
          AdminMembershipBootstrapMember {
            id: "edge-b".to_string(),
            readiness_ed25519_public_key: key(3),
            catchup_x25519_public_key: key(4),
          },
        ],
        ..AdminMembershipConfig::default()
      },
      ..AdminMutationRolloutConfig::default()
    };
    validate_membership_config(&rollout).expect("valid staged membership");
    rollout.membership.bootstrap_members[1].id = "edge-c".to_string();
    assert!(validate_membership_config(&rollout).is_err());
    rollout.membership.bootstrap_members[1].id = "edge-b".to_string();
    rollout.membership.bootstrap_members[1].catchup_x25519_public_key = key(3);
    assert!(validate_membership_config(&rollout).is_err());
  }
}
