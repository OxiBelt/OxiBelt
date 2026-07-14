//! Kubernetes immutable-rollout identity checks kept outside user TOML.
//! The data plane receives this identity through the Pod environment and proves
//! that the mounted generated include is the exact revision assigned to it.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{Config, ConfigSourcePaths, HotReloadMode};

pub const CONFIG_ROLLOUT_MODE_ENV: &str = "OXIBELT_CONFIG_ROLLOUT_MODE";
pub const CONFIG_REVISION_ENV: &str = "OXIBELT_CONFIG_REVISION";
pub const CONFIG_DIGEST_ENV: &str = "OXIBELT_CONFIG_DIGEST";
pub const CONFIG_REVISION_FILE_ENV: &str = "OXIBELT_CONFIG_REVISION_FILE";
pub const INSTANCE_ID_ENV: &str = "OXIBELT_INSTANCE_ID";

const KUBERNETES_IMMUTABLE_MODE: &str = "kubernetes_immutable";
const ADMIN_CLUSTER_MODE: &str = "admin_cluster";
const MAX_METADATA_VALUE_LEN: usize = 253;
const SHA256_HEX_LEN: usize = 64;

/// The deployment-level configuration authority for this process.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum ConfigRolloutMode {
  /// Existing standalone and mutable-admin behavior.
  #[default]
  Mutable,
  /// Kubernetes replaces Pods from immutable configuration artifacts.
  KubernetesImmutable,
  /// A fixed-member OxiBelt Admin control plane coordinates mutable revisions.
  AdminCluster,
}

impl ConfigRolloutMode {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Mutable => "mutable",
      Self::KubernetesImmutable => KUBERNETES_IMMUTABLE_MODE,
      Self::AdminCluster => ADMIN_CLUSTER_MODE,
    }
  }
}

/// Whether a verified rollout identity has reached an active application snapshot.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum ConfigRolloutApplyState {
  /// No immutable rollout identity was assigned to this process.
  #[default]
  NotConfigured,
  /// The revision was verified but an application snapshot has not been built.
  Pending,
  /// The revision was verified and the complete application snapshot was built.
  Applied,
}

impl ConfigRolloutApplyState {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::NotConfigured => "not_configured",
      Self::Pending => "pending",
      Self::Applied => "applied",
    }
  }
}

/// Immutable revision metadata supplied by the Kubernetes Pod template.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ConfigRolloutIdentity {
  mode: ConfigRolloutMode,
  instance_id: Option<String>,
  desired_revision: Option<String>,
  digest: Option<String>,
  revision_file: Option<PathBuf>,
  apply_state: ConfigRolloutApplyState,
}

impl ConfigRolloutIdentity {
  pub fn from_environment(source_paths: &ConfigSourcePaths) -> anyhow::Result<Self> {
    Self::from_environment_values(EnvironmentValues::read()?, source_paths)
  }

  pub fn mode(&self) -> ConfigRolloutMode {
    self.mode
  }

  pub fn is_immutable(&self) -> bool {
    self.mode == ConfigRolloutMode::KubernetesImmutable
  }

  pub fn is_admin_cluster(&self) -> bool {
    self.mode == ConfigRolloutMode::AdminCluster
  }

  pub fn blocks_per_pod_mutation(&self) -> bool {
    self.is_immutable()
  }

  pub fn is_ready(&self) -> bool {
    !self.is_immutable() || self.apply_state == ConfigRolloutApplyState::Applied
  }

  pub fn mark_applied(&mut self) {
    if self.is_immutable() {
      self.apply_state = ConfigRolloutApplyState::Applied;
    }
  }

  pub fn validate(
    &self,
    source_paths: &ConfigSourcePaths,
    hot_reload_mode: HotReloadMode,
  ) -> anyhow::Result<()> {
    if self.is_admin_cluster() {
      if hot_reload_mode != HotReloadMode::Off {
        bail!(
          "runtime.hot_reload.mode must be \"off\" when {CONFIG_ROLLOUT_MODE_ENV}={ADMIN_CLUSTER_MODE}"
        );
      }
      if self.instance_id.is_none() {
        bail!("{INSTANCE_ID_ENV} is required in admin_cluster rollout mode");
      }
      return Ok(());
    }
    if !self.is_immutable() {
      return Ok(());
    }
    if hot_reload_mode != HotReloadMode::Off {
      bail!(
        "runtime.hot_reload.mode must be \"off\" when {CONFIG_ROLLOUT_MODE_ENV}={KUBERNETES_IMMUTABLE_MODE}"
      );
    }

    let revision_file = self
      .revision_file
      .as_deref()
      .ok_or_else(|| anyhow!("{CONFIG_REVISION_FILE_ENV} is required in immutable rollout mode"))?;
    let digest = self
      .digest
      .as_deref()
      .ok_or_else(|| anyhow!("{CONFIG_DIGEST_ENV} is required in immutable rollout mode"))?;
    let canonical_revision_file = canonical_revision_file(revision_file, source_paths)?;
    if canonical_revision_file != revision_file {
      bail!("{CONFIG_REVISION_FILE_ENV} changed after rollout identity validation");
    }
    if !source_paths.config_files.contains(&canonical_revision_file) {
      bail!("{CONFIG_REVISION_FILE_ENV} must be an included OxiBelt configuration source file");
    }

    let bytes = std::fs::read(&canonical_revision_file).with_context(|| {
      format!(
        "failed to read immutable rollout revision file {}",
        canonical_revision_file.display()
      )
    })?;
    let actual = sha256_hex(&bytes);
    if actual != digest {
      bail!("{CONFIG_DIGEST_ENV} does not match the exact bytes of {CONFIG_REVISION_FILE_ENV}");
    }
    Ok(())
  }

  pub fn status_fields(&self) -> Value {
    json!({
      "instance_id": self.instance_id,
      "rollout_mode": self.mode.as_str(),
      "desired_revision": self.desired_revision,
      "applied_revision": self.is_ready().then_some(self.desired_revision.as_deref()).flatten(),
      "digest": self.digest,
      "apply_state": self.apply_state.as_str(),
    })
  }

  pub fn applied_header_values(&self) -> Option<(&str, &str)> {
    if self.apply_state != ConfigRolloutApplyState::Applied {
      return None;
    }
    Some((self.desired_revision.as_deref()?, self.digest.as_deref()?))
  }

  fn from_environment_values(
    values: EnvironmentValues,
    source_paths: &ConfigSourcePaths,
  ) -> anyhow::Result<Self> {
    match values.mode.as_deref() {
      None => {
        if values.has_immutable_metadata() {
          bail!(
            "{CONFIG_ROLLOUT_MODE_ENV}={KUBERNETES_IMMUTABLE_MODE} is required when immutable rollout metadata is set"
          );
        }
        Ok(Self::default())
      }
      Some(KUBERNETES_IMMUTABLE_MODE) => {
        let instance_id = required_metadata_value(INSTANCE_ID_ENV, values.instance_id)?;
        let desired_revision = required_revision(values.revision)?;
        let digest = required_digest(values.digest)?;
        let revision_file = required_revision_file(values.revision_file, source_paths)?;
        let identity = Self {
          mode: ConfigRolloutMode::KubernetesImmutable,
          instance_id: Some(instance_id),
          desired_revision: Some(desired_revision),
          digest: Some(digest),
          revision_file: Some(revision_file),
          apply_state: ConfigRolloutApplyState::Pending,
        };
        identity.validate(source_paths, HotReloadMode::Off)?;
        Ok(identity)
      }
      Some(ADMIN_CLUSTER_MODE) => {
        if values.revision.is_some() || values.digest.is_some() || values.revision_file.is_some() {
          bail!("immutable rollout revision metadata must not be set in admin_cluster mode");
        }
        Ok(Self {
          mode: ConfigRolloutMode::AdminCluster,
          instance_id: Some(required_metadata_value(
            INSTANCE_ID_ENV,
            values.instance_id,
          )?),
          desired_revision: None,
          digest: None,
          revision_file: None,
          apply_state: ConfigRolloutApplyState::NotConfigured,
        })
      }
      Some(value) => bail!(
        "{CONFIG_ROLLOUT_MODE_ENV} must be unset, {KUBERNETES_IMMUTABLE_MODE}, or {ADMIN_CLUSTER_MODE}, got {value:?}"
      ),
    }
  }
}

impl Config {
  /// Resolves the process-level Kubernetes rollout identity after config paths are known.
  pub fn resolve_rollout_identity_from_environment(&mut self) -> anyhow::Result<()> {
    let identity = ConfigRolloutIdentity::from_environment(&self.source_paths)?;
    identity.validate(&self.source_paths, self.runtime.hot_reload.mode)?;
    self.rollout = identity;
    Ok(())
  }
}

#[derive(Default)]
struct EnvironmentValues {
  mode: Option<String>,
  revision: Option<String>,
  digest: Option<String>,
  revision_file: Option<String>,
  instance_id: Option<String>,
}

impl EnvironmentValues {
  fn read() -> anyhow::Result<Self> {
    Ok(Self {
      mode: read_environment(CONFIG_ROLLOUT_MODE_ENV)?,
      revision: read_environment(CONFIG_REVISION_ENV)?,
      digest: read_environment(CONFIG_DIGEST_ENV)?,
      revision_file: read_environment(CONFIG_REVISION_FILE_ENV)?,
      instance_id: read_environment(INSTANCE_ID_ENV)?,
    })
  }

  fn has_immutable_metadata(&self) -> bool {
    self.revision.is_some() || self.digest.is_some() || self.revision_file.is_some()
  }
}

fn read_environment(name: &str) -> anyhow::Result<Option<String>> {
  match std::env::var(name) {
    Ok(value) => Ok(Some(value)),
    Err(std::env::VarError::NotPresent) => Ok(None),
    Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
  }
}

fn required_metadata_value(name: &str, value: Option<String>) -> anyhow::Result<String> {
  let value = value.ok_or_else(|| anyhow!("{name} is required in immutable rollout mode"))?;
  validate_metadata_value(name, &value)?;
  Ok(value)
}

fn required_revision(value: Option<String>) -> anyhow::Result<String> {
  let value = required_metadata_value(CONFIG_REVISION_ENV, value)?;
  if !is_kubernetes_name(&value) {
    bail!("{CONFIG_REVISION_ENV} must be a lowercase Kubernetes resource name");
  }
  Ok(value)
}

fn required_digest(value: Option<String>) -> anyhow::Result<String> {
  let value =
    value.ok_or_else(|| anyhow!("{CONFIG_DIGEST_ENV} is required in immutable rollout mode"))?;
  if value.len() != SHA256_HEX_LEN
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
  {
    bail!("{CONFIG_DIGEST_ENV} must be a lowercase 64-character SHA-256 digest");
  }
  Ok(value)
}

fn required_revision_file(
  value: Option<String>,
  source_paths: &ConfigSourcePaths,
) -> anyhow::Result<PathBuf> {
  let value = value
    .ok_or_else(|| anyhow!("{CONFIG_REVISION_FILE_ENV} is required in immutable rollout mode"))?;
  if value.is_empty() {
    bail!("{CONFIG_REVISION_FILE_ENV} must not be empty");
  }
  let root = source_paths
    .config_dir
    .as_deref()
    .ok_or_else(|| anyhow!("immutable rollout mode requires a configuration root"))?;
  let candidate = PathBuf::from(value);
  let candidate = if candidate.is_absolute() {
    candidate
  } else {
    root.join(candidate)
  };
  canonical_revision_file(&candidate, source_paths)
}

fn canonical_revision_file(
  candidate: &Path,
  source_paths: &ConfigSourcePaths,
) -> anyhow::Result<PathBuf> {
  let root = source_paths
    .config_dir
    .as_deref()
    .ok_or_else(|| anyhow!("immutable rollout mode requires a configuration root"))?;
  let canonical_root = root
    .canonicalize()
    .with_context(|| format!("failed to resolve configuration root {}", root.display()))?;
  let canonical_file = candidate.canonicalize().with_context(|| {
    format!(
      "failed to resolve {CONFIG_REVISION_FILE_ENV} {}",
      candidate.display()
    )
  })?;
  if !canonical_file.starts_with(&canonical_root) {
    bail!("{CONFIG_REVISION_FILE_ENV} must stay beneath the configuration root");
  }
  let metadata = canonical_file.metadata().with_context(|| {
    format!(
      "failed to inspect {CONFIG_REVISION_FILE_ENV} {}",
      canonical_file.display()
    )
  })?;
  if !metadata.is_file() {
    bail!("{CONFIG_REVISION_FILE_ENV} must point to a regular file");
  }
  Ok(canonical_file)
}

fn validate_metadata_value(name: &str, value: &str) -> anyhow::Result<()> {
  if value.is_empty() || value.len() > MAX_METADATA_VALUE_LEN {
    bail!("{name} must be between 1 and {MAX_METADATA_VALUE_LEN} bytes");
  }
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
  {
    bail!("{name} contains an unsafe metadata character");
  }
  Ok(())
}

fn is_kubernetes_name(value: &str) -> bool {
  value
    .bytes()
    .next()
    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    && value
      .bytes()
      .last()
      .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    && value
      .bytes()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-'))
}

fn sha256_hex(bytes: &[u8]) -> String {
  let digest = Sha256::digest(bytes);
  let mut value = String::with_capacity(SHA256_HEX_LEN);
  for byte in digest {
    use std::fmt::Write as _;
    let _ = write!(value, "{byte:02x}");
  }
  value
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn mutable_mode_is_the_default_without_rollout_environment() {
    let identity = ConfigRolloutIdentity::from_environment_values(
      EnvironmentValues::default(),
      &ConfigSourcePaths::default(),
    )
    .expect("missing rollout environment should preserve mutable behavior");

    assert_eq!(identity.mode(), ConfigRolloutMode::Mutable);
    assert!(identity.is_ready());
    assert_eq!(identity.status_fields()["apply_state"], "not_configured");
  }

  #[test]
  fn mutable_mode_accepts_shared_state_instance_id_without_rollout_mode() {
    let identity = ConfigRolloutIdentity::from_environment_values(
      EnvironmentValues {
        instance_id: Some("proxy-a".to_string()),
        ..EnvironmentValues::default()
      },
      &ConfigSourcePaths::default(),
    )
    .expect("standalone shared-state identity should preserve mutable behavior");

    assert_eq!(identity.mode(), ConfigRolloutMode::Mutable);
    assert!(identity.is_ready());
    assert!(identity.status_fields()["instance_id"].is_null());
  }

  #[test]
  fn mutable_mode_rejects_rollout_metadata_without_rollout_mode() {
    let source_paths = ConfigSourcePaths::default();
    for values in [
      EnvironmentValues {
        revision: Some("gateway-config-test".to_string()),
        ..EnvironmentValues::default()
      },
      EnvironmentValues {
        digest: Some("0".repeat(SHA256_HEX_LEN)),
        ..EnvironmentValues::default()
      },
      EnvironmentValues {
        revision_file: Some("conf.d/gateway-api.generated.toml".to_string()),
        ..EnvironmentValues::default()
      },
    ] {
      let error = ConfigRolloutIdentity::from_environment_values(values, &source_paths)
        .expect_err("rollout metadata without a mode should fail closed");
      assert!(format!("{error:#}").contains(CONFIG_ROLLOUT_MODE_ENV));
    }
  }

  #[test]
  fn immutable_mode_still_requires_instance_id() {
    let error = ConfigRolloutIdentity::from_environment_values(
      EnvironmentValues {
        mode: Some(KUBERNETES_IMMUTABLE_MODE.to_string()),
        ..EnvironmentValues::default()
      },
      &ConfigSourcePaths::default(),
    )
    .expect_err("immutable rollout mode should require an instance ID");

    assert!(format!("{error:#}").contains(INSTANCE_ID_ENV));
  }

  #[test]
  fn immutable_mode_proves_an_included_file_and_its_exact_digest() {
    let fixture = ImmutableFixture::new("[generated]\nvalue = \"expected\"\n");
    let identity =
      ConfigRolloutIdentity::from_environment_values(fixture.values(), &fixture.source_paths)
        .expect("matching immutable rollout metadata should validate");

    assert_eq!(identity.mode(), ConfigRolloutMode::KubernetesImmutable);
    assert!(!identity.is_ready());
    assert_eq!(
      identity.status_fields()["desired_revision"],
      "gateway-config-test"
    );
    assert!(identity.applied_header_values().is_none());

    let mut identity = identity;
    identity.mark_applied();
    assert!(identity.is_ready());
    assert_eq!(
      identity.applied_header_values(),
      Some(("gateway-config-test", fixture.digest.as_str()))
    );
  }

  #[test]
  fn immutable_mode_rejects_an_excluded_or_mismatched_file() {
    let fixture = ImmutableFixture::new("[generated]\nvalue = \"expected\"\n");
    let mut excluded = fixture.source_paths.clone();
    excluded.config_files.clear();
    let error = ConfigRolloutIdentity::from_environment_values(fixture.values(), &excluded)
      .expect_err("an untracked revision file must be rejected");
    assert!(format!("{error:#}").contains("included OxiBelt configuration source"));

    let mut mismatched = fixture.values();
    mismatched.digest = Some("0".repeat(SHA256_HEX_LEN));
    let error = ConfigRolloutIdentity::from_environment_values(mismatched, &fixture.source_paths)
      .expect_err("a mismatched digest must be rejected");
    assert!(format!("{error:#}").contains(CONFIG_DIGEST_ENV));
  }

  #[test]
  fn immutable_mode_rejects_hot_reload_after_runtime_overrides() {
    let fixture = ImmutableFixture::new("[generated]\nvalue = \"expected\"\n");
    let identity =
      ConfigRolloutIdentity::from_environment_values(fixture.values(), &fixture.source_paths)
        .expect("fixture metadata should validate before override");
    let error = identity
      .validate(&fixture.source_paths, HotReloadMode::Full)
      .expect_err("immutable pods must reject hot reload");
    assert!(format!("{error:#}").contains("runtime.hot_reload.mode"));
  }

  struct ImmutableFixture {
    _temp_dir: tempfile::TempDir,
    source_paths: ConfigSourcePaths,
    digest: String,
  }

  impl ImmutableFixture {
    fn new(contents: &str) -> Self {
      let temp_dir = tempfile::tempdir().expect("temporary directory should create");
      let config_root = temp_dir.path().join("config");
      let generated_dir = config_root.join("conf.d");
      std::fs::create_dir_all(&generated_dir).expect("generated include directory should create");
      let revision_file = generated_dir.join("gateway-api.generated.toml");
      std::fs::write(&revision_file, contents).expect("generated include should write");
      let revision_file = revision_file
        .canonicalize()
        .expect("generated include should canonicalize");
      Self {
        _temp_dir: temp_dir,
        source_paths: ConfigSourcePaths {
          config_dir: Some(config_root),
          config_files: vec![revision_file],
          ..ConfigSourcePaths::default()
        },
        digest: sha256_hex(contents.as_bytes()),
      }
    }

    fn values(&self) -> EnvironmentValues {
      EnvironmentValues {
        mode: Some(KUBERNETES_IMMUTABLE_MODE.to_string()),
        revision: Some("gateway-config-test".to_string()),
        digest: Some(self.digest.clone()),
        revision_file: Some("conf.d/gateway-api.generated.toml".to_string()),
        instance_id: Some("f6e8c15f-bf90-45f4-bdfa-ff3cb0f72a57".to_string()),
      }
    }
  }
}
