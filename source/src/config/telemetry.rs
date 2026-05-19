use anyhow::{Context, bail};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct TelemetryConfig {
  #[serde(default)]
  pub tracing: TelemetryTracingConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TelemetryTracingConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_otlp_endpoint")]
  pub endpoint: String,
  #[serde(default = "default_service_name")]
  pub service_name: String,
  #[serde(default = "default_sample_ratio")]
  pub sample_ratio: f64,
  #[serde(default = "default_export_timeout_ms")]
  pub export_timeout_ms: u64,
  #[serde(default = "super::default_true")]
  pub propagate_trace_context: bool,
}

impl Default for TelemetryTracingConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      endpoint: default_otlp_endpoint(),
      service_name: default_service_name(),
      sample_ratio: default_sample_ratio(),
      export_timeout_ms: default_export_timeout_ms(),
      propagate_trace_context: true,
    }
  }
}

impl TelemetryConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    self.tracing.validate()
  }
}

impl TelemetryTracingConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.service_name.trim().is_empty() {
      bail!("telemetry.tracing.service_name must not be empty");
    }
    if !(0.0..=1.0).contains(&self.sample_ratio) || self.sample_ratio.is_nan() {
      bail!("telemetry.tracing.sample_ratio must be between 0.0 and 1.0");
    }
    if self.export_timeout_ms == 0 {
      bail!("telemetry.tracing.export_timeout_ms must be greater than 0");
    }
    if self.enabled {
      let endpoint = Url::parse(&self.endpoint).context("invalid telemetry.tracing.endpoint")?;
      if endpoint.scheme() != "http" {
        bail!("telemetry.tracing.endpoint currently supports only http:// OTLP endpoints");
      }
      if endpoint.host_str().is_none() {
        bail!("telemetry.tracing.endpoint must include a host");
      }
    }
    Ok(())
  }
}

fn default_otlp_endpoint() -> String {
  "http://127.0.0.1:4318/v1/traces".to_string()
}

fn default_service_name() -> String {
  "oxibelt".to_string()
}

fn default_sample_ratio() -> f64 {
  1.0
}

fn default_export_timeout_ms() -> u64 {
  3000
}
