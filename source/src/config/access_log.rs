//! Access-log schema and sink configuration.
//! PostgreSQL access-log sinks are intentionally not part of this surface.

use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AccessLogConfig {
  #[serde(default)]
  pub system: AccessLogSourceConfig,
  #[serde(default = "default_waf_source")]
  pub waf: AccessLogSourceConfig,
  #[serde(default)]
  pub admin: AccessLogSourceConfig,
  #[serde(default)]
  pub stdout: AccessLogStdoutConfig,
}

impl Default for AccessLogConfig {
  fn default() -> Self {
    Self {
      system: AccessLogSourceConfig::default(),
      waf: default_waf_source(),
      admin: AccessLogSourceConfig::default(),
      stdout: AccessLogStdoutConfig::default(),
    }
  }
}

impl AccessLogConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    self.stdout.validate()
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct AccessLogSourceConfig {
  #[serde(default)]
  pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AccessLogStdoutConfig {
  #[serde(default = "super::default_true")]
  pub enabled: bool,
  #[serde(default)]
  pub schema: AccessLogSchema,
}

impl Default for AccessLogStdoutConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      schema: AccessLogSchema::default(),
    }
  }
}

impl AccessLogStdoutConfig {
  fn validate(&self) -> anyhow::Result<()> {
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum AccessLogSchema {
  #[default]
  Ocsf,
  Ecs,
}

impl<'de> Deserialize<'de> for AccessLogSchema {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let value = String::deserialize(deserializer)?;
    match value.as_str() {
      "ocsf" => Ok(Self::Ocsf),
      "ecs" => Ok(Self::Ecs),
      other => Err(serde::de::Error::custom(format!(
        "unsupported access_log.stdout.schema {other:?}; use \"ocsf\" or \"ecs\""
      ))),
    }
  }
}

fn default_waf_source() -> AccessLogSourceConfig {
  AccessLogSourceConfig { enabled: true }
}
