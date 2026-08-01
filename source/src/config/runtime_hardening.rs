//! Runtime hardening and runtime backend configuration.

use std::path::PathBuf;

use anyhow::bail;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

const MAX_SECCOMP_PROFILE_IDENTITY_LEN: usize = 128;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDirectH1IoMode {
  #[default]
  Auto,
  TokioHyper,
  Compio,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMainRuntimeMode {
  Auto,
  #[default]
  HybridCompio,
  /// Compatibility input for pre-topology configurations.
  Compio,
  TokioHyper,
}

impl RuntimeMainRuntimeMode {
  /// Returns the canonical topology preset without changing legacy behavior.
  pub const fn canonical(self) -> Self {
    match self {
      Self::Compio => Self::HybridCompio,
      mode => mode,
    }
  }

  pub const fn is_legacy_compio_alias(self) -> bool {
    matches!(self, Self::Compio)
  }

  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Auto => "auto",
      Self::HybridCompio => "hybrid_compio",
      Self::Compio => "compio",
      Self::TokioHyper => "tokio_hyper",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTopologyPolicy {
  #[default]
  AllowFallback,
  RequireExact,
}

impl RuntimeTopologyPolicy {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::AllowFallback => "allow_fallback",
      Self::RequireExact => "require_exact",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RuntimeHardeningConfig {
  #[serde(default)]
  pub close_range: HardeningAutoMode,
  #[serde(default)]
  pub seccomp: RuntimeSeccompConfig,
  #[serde(default)]
  pub landlock: RuntimeLandlockConfig,
}

impl Default for RuntimeHardeningConfig {
  fn default() -> Self {
    Self {
      close_range: HardeningAutoMode::Auto,
      seccomp: RuntimeSeccompConfig::default(),
      landlock: RuntimeLandlockConfig::default(),
    }
  }
}

impl RuntimeHardeningConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    self.seccomp.validate()?;
    self.landlock.validate()?;
    #[cfg(not(target_os = "linux"))]
    {
      if self.close_range == HardeningAutoMode::Required {
        bail!("runtime.hardening.close_range = \"required\" is Linux-only");
      }
      if self.seccomp.expectation == RuntimeSeccompExpectation::Required {
        bail!("runtime.hardening.seccomp.expectation = \"required\" is Linux-only");
      }
      if self.landlock.mode != RuntimeLandlockMode::Off {
        bail!("runtime.hardening.landlock.mode is Linux-only");
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HardeningAutoMode {
  #[default]
  Auto,
  Off,
  Required,
}

/// Compatibility input accepted from pre-OB-P1-05 configurations.
#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSeccompMode {
  #[default]
  Off,
  Log,
  Enforce,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSeccompExpectation {
  #[default]
  Off,
  Optional,
  Required,
}

impl RuntimeSeccompExpectation {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Off => "off",
      Self::Optional => "optional",
      Self::Required => "required",
    }
  }

  const fn legacy_projection(self) -> RuntimeSeccompMode {
    match self {
      Self::Off => RuntimeSeccompMode::Off,
      Self::Optional => RuntimeSeccompMode::Log,
      Self::Required => RuntimeSeccompMode::Enforce,
    }
  }
}

impl From<RuntimeSeccompMode> for RuntimeSeccompExpectation {
  fn from(mode: RuntimeSeccompMode) -> Self {
    match mode {
      RuntimeSeccompMode::Off => Self::Off,
      RuntimeSeccompMode::Log => Self::Optional,
      RuntimeSeccompMode::Enforce => Self::Required,
    }
  }
}

#[derive(Debug, Clone)]
pub struct RuntimeSeccompConfig {
  pub expectation: RuntimeSeccompExpectation,
  pub profile_identity: Option<String>,
  pub profile_digest: Option<String>,
  /// Transitional projection for callers that still classify the legacy modes.
  /// New hardening decisions must use `expectation`.
  pub mode: RuntimeSeccompMode,
  pub(crate) legacy_mode: Option<RuntimeSeccompMode>,
}

impl Default for RuntimeSeccompConfig {
  fn default() -> Self {
    Self {
      expectation: RuntimeSeccompExpectation::Off,
      profile_identity: None,
      profile_digest: None,
      mode: RuntimeSeccompMode::Off,
      legacy_mode: None,
    }
  }
}

impl PartialEq for RuntimeSeccompConfig {
  fn eq(&self, other: &Self) -> bool {
    self.expectation == other.expectation
      && self.profile_identity == other.profile_identity
      && self.profile_digest == other.profile_digest
      && self.mode == other.mode
  }
}

#[derive(Debug, Deserialize)]
struct RawRuntimeSeccompConfig {
  #[serde(default)]
  expectation: Option<RuntimeSeccompExpectation>,
  #[serde(default)]
  mode: Option<RuntimeSeccompMode>,
  #[serde(default)]
  profile_identity: Option<String>,
  #[serde(default)]
  profile_digest: Option<String>,
}

impl<'de> Deserialize<'de> for RuntimeSeccompConfig {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let raw = RawRuntimeSeccompConfig::deserialize(deserializer)?;
    if raw.expectation.is_some() && raw.mode.is_some() {
      return Err(D::Error::custom(
        "runtime.hardening.seccomp.expectation cannot be combined with legacy runtime.hardening.seccomp.mode",
      ));
    }
    let legacy_mode = raw.mode;
    let expectation = raw
      .expectation
      .or_else(|| legacy_mode.map(RuntimeSeccompExpectation::from))
      .unwrap_or_default();
    Ok(Self {
      expectation,
      profile_identity: raw.profile_identity,
      profile_digest: raw.profile_digest,
      mode: expectation.legacy_projection(),
      legacy_mode,
    })
  }
}

impl RuntimeSeccompConfig {
  pub const fn legacy_mode(&self) -> Option<RuntimeSeccompMode> {
    self.legacy_mode
  }

  fn validate(&self) -> anyhow::Result<()> {
    if self.mode != self.expectation.legacy_projection() {
      bail!("runtime.hardening.seccomp contains inconsistent in-memory compatibility state");
    }
    if self.expectation == RuntimeSeccompExpectation::Off
      && (self.profile_identity.is_some() || self.profile_digest.is_some())
    {
      bail!(
        "runtime.hardening.seccomp profile assertions require expectation = \"optional\" or \"required\""
      );
    }
    if let Some(identity) = self.profile_identity.as_deref() {
      validate_profile_identity(identity)?;
    }
    if let Some(digest) = self.profile_digest.as_deref() {
      validate_profile_digest(digest)?;
    }
    Ok(())
  }
}

fn validate_profile_identity(identity: &str) -> anyhow::Result<()> {
  if identity.is_empty()
    || identity.len() > MAX_SECCOMP_PROFILE_IDENTITY_LEN
    || !identity.bytes().all(|byte| {
      byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@' | b'+')
    })
  {
    bail!(
      "runtime.hardening.seccomp.profile_identity must be 1..={MAX_SECCOMP_PROFILE_IDENTITY_LEN} safe ASCII characters"
    );
  }
  Ok(())
}

fn validate_profile_digest(digest: &str) -> anyhow::Result<()> {
  let Some(encoded) = digest.strip_prefix("sha256:") else {
    bail!("runtime.hardening.seccomp.profile_digest must use sha256:<lowercase-hex>");
  };
  if encoded.len() != 64
    || !encoded
      .bytes()
      .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
  {
    bail!("runtime.hardening.seccomp.profile_digest must use sha256:<lowercase-hex>");
  }
  Ok(())
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLandlockMode {
  #[default]
  Off,
  Enforce,
  Manifest,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RuntimeLandlockConfig {
  #[serde(default)]
  pub mode: RuntimeLandlockMode,
  #[serde(default)]
  pub read_paths: Vec<PathBuf>,
  #[serde(default)]
  pub read_write_paths: Vec<PathBuf>,
}

impl Default for RuntimeLandlockConfig {
  fn default() -> Self {
    Self {
      mode: RuntimeLandlockMode::Off,
      read_paths: Vec::new(),
      read_write_paths: Vec::new(),
    }
  }
}

impl RuntimeLandlockConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.mode == RuntimeLandlockMode::Enforce
      && self.read_paths.is_empty()
      && self.read_write_paths.is_empty()
    {
      bail!(
        "runtime.hardening.landlock.mode = \"enforce\" requires read_paths or read_write_paths"
      );
    }
    if self
      .read_paths
      .iter()
      .chain(&self.read_write_paths)
      .any(|path| path.as_os_str().is_empty())
    {
      bail!("runtime.hardening.landlock paths must not be empty");
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn parse_seccomp(raw: &str) -> RuntimeSeccompConfig {
    toml::from_str(raw).expect("seccomp configuration should parse")
  }

  #[test]
  fn canonical_seccomp_expectations_preserve_a_legacy_projection() {
    let optional = parse_seccomp("expectation = \"optional\"");
    assert_eq!(optional.expectation, RuntimeSeccompExpectation::Optional);
    assert_eq!(optional.mode, RuntimeSeccompMode::Log);

    let required = parse_seccomp("expectation = \"required\"");
    assert_eq!(required.expectation, RuntimeSeccompExpectation::Required);
    assert_eq!(required.mode, RuntimeSeccompMode::Enforce);
  }

  #[test]
  fn legacy_seccomp_modes_map_to_expectations() {
    for (mode, expectation) in [
      ("off", RuntimeSeccompExpectation::Off),
      ("log", RuntimeSeccompExpectation::Optional),
      ("enforce", RuntimeSeccompExpectation::Required),
    ] {
      let config = parse_seccomp(&format!("mode = \"{mode}\""));
      assert_eq!(config.expectation, expectation);
      assert!(config.legacy_mode().is_some());
    }
  }

  #[test]
  fn mixed_seccomp_fields_are_rejected() {
    let error =
      toml::from_str::<RuntimeSeccompConfig>("expectation = \"required\"\nmode = \"enforce\"")
        .expect_err("mixed canonical and legacy fields must fail");
    assert!(
      error
        .to_string()
        .contains("expectation cannot be combined with legacy")
    );
  }

  #[test]
  fn seccomp_profile_assertions_are_bounded_and_explicit() {
    let valid = parse_seccomp(
      "expectation = \"required\"\nprofile_identity = \"kubernetes/runtime-default\"\nprofile_digest = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
    );
    valid
      .validate()
      .expect("bounded assertions should validate");

    let mut off = RuntimeSeccompConfig {
      profile_identity: Some("runtime-default".to_string()),
      ..RuntimeSeccompConfig::default()
    };
    assert!(off.validate().is_err());
    off.expectation = RuntimeSeccompExpectation::Required;
    off.mode = RuntimeSeccompMode::Enforce;
    off.profile_identity = Some("contains whitespace".to_string());
    assert!(off.validate().is_err());
  }

  #[test]
  fn manifest_landlock_mode_defers_paths_to_the_generated_projection() {
    let config = RuntimeLandlockConfig {
      mode: RuntimeLandlockMode::Manifest,
      read_paths: Vec::new(),
      read_write_paths: Vec::new(),
    };
    config
      .validate()
      .expect("manifest mode may receive all paths from its projection");
  }
}
