//! Access-log schema and sink configuration.
//! PostgreSQL access-log sinks are intentionally not part of this surface.

use anyhow::{Context, bail};
use serde::Deserialize;
use url::Url;

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
  #[serde(default)]
  pub otlp: AccessLogOtlpConfig,
}

impl Default for AccessLogConfig {
  fn default() -> Self {
    Self {
      system: AccessLogSourceConfig::default(),
      waf: default_waf_source(),
      admin: AccessLogSourceConfig::default(),
      stdout: AccessLogStdoutConfig::default(),
      otlp: AccessLogOtlpConfig::default(),
    }
  }
}

impl AccessLogConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    self.stdout.validate()?;
    self.otlp.validate()
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AccessLogOtlpConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_otlp_logs_endpoint")]
  pub endpoint: String,
  #[serde(default = "default_otlp_queue_capacity")]
  pub queue_capacity: usize,
  #[serde(default = "default_otlp_batch_size")]
  pub batch_size: usize,
  #[serde(default = "default_otlp_export_timeout_ms")]
  pub export_timeout_ms: u64,
  #[serde(default = "default_otlp_service_name")]
  pub service_name: String,
}

impl Default for AccessLogOtlpConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      endpoint: default_otlp_logs_endpoint(),
      queue_capacity: default_otlp_queue_capacity(),
      batch_size: default_otlp_batch_size(),
      export_timeout_ms: default_otlp_export_timeout_ms(),
      service_name: default_otlp_service_name(),
    }
  }
}

impl AccessLogOtlpConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.queue_capacity == 0 {
      bail!("access_log.otlp.queue_capacity must be greater than 0");
    }
    if self.batch_size == 0 {
      bail!("access_log.otlp.batch_size must be greater than 0");
    }
    if self.export_timeout_ms == 0 {
      bail!("access_log.otlp.export_timeout_ms must be greater than 0");
    }
    if self.service_name.trim().is_empty() {
      bail!("access_log.otlp.service_name must not be empty");
    }
    if self.enabled {
      let endpoint = Url::parse(&self.endpoint).context("invalid access_log.otlp.endpoint")?;
      if endpoint.scheme() != "http" {
        bail!("access_log.otlp.endpoint currently supports only http:// OTLP endpoints");
      }
      if endpoint.host_str().is_none() {
        bail!("access_log.otlp.endpoint must include a host");
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccessLogSchema {
  #[default]
  Ecs,
  Ocsf,
}

fn default_waf_source() -> AccessLogSourceConfig {
  AccessLogSourceConfig { enabled: true }
}

fn default_otlp_logs_endpoint() -> String {
  "http://127.0.0.1:4318/v1/logs".to_string()
}

fn default_otlp_queue_capacity() -> usize {
  1024
}

fn default_otlp_batch_size() -> usize {
  64
}

fn default_otlp_export_timeout_ms() -> u64 {
  3000
}

fn default_otlp_service_name() -> String {
  "oxibelt".to_string()
}
