//! Runtime hardening and runtime backend configuration.

use std::path::PathBuf;

use anyhow::bail;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDirectH1IoMode {
  #[default]
  Auto,
  TokioHyper,
  Compio,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMainRuntimeMode {
  Auto,
  #[default]
  Compio,
  TokioHyper,
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
    #[cfg(not(target_os = "linux"))]
    {
      if self.close_range == HardeningAutoMode::Required {
        bail!("runtime.hardening.close_range = \"required\" is Linux-only");
      }
      if self.seccomp.mode != RuntimeSeccompMode::Off {
        bail!("runtime.hardening.seccomp.mode is Linux-only");
      }
      if self.landlock.mode != RuntimeLandlockMode::Off {
        bail!("runtime.hardening.landlock.mode is Linux-only");
      }
    }
    if self.landlock.mode == RuntimeLandlockMode::Enforce
      && self.landlock.read_paths.is_empty()
      && self.landlock.read_write_paths.is_empty()
    {
      bail!(
        "runtime.hardening.landlock.mode = \"enforce\" requires read_paths or read_write_paths"
      );
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HardeningAutoMode {
  #[default]
  Auto,
  Off,
  Required,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSeccompMode {
  #[default]
  Off,
  Log,
  Enforce,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RuntimeSeccompConfig {
  #[serde(default)]
  pub mode: RuntimeSeccompMode,
}

impl Default for RuntimeSeccompConfig {
  fn default() -> Self {
    Self {
      mode: RuntimeSeccompMode::Off,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLandlockMode {
  #[default]
  Off,
  Enforce,
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
