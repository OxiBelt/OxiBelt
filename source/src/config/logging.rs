//! Logging and access-log configuration defaults.
//! Access-log fields are validated before sinks are initialized.

use anyhow::bail;
use serde::Deserialize;

use super::default_true;
use crate::waf::AccessLogFieldConfig;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LoggingConfig {
  #[serde(default = "default_log_level")]
  pub level: String,
  #[serde(default)]
  pub access_log: LoggingAccessLogConfig,
}

impl Default for LoggingConfig {
  fn default() -> Self {
    Self {
      level: default_log_level(),
      access_log: LoggingAccessLogConfig::default(),
    }
  }
}

impl LoggingConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    if self.level.trim().is_empty() {
      bail!("logging.level must not be empty");
    }
    crate::waf::validate_access_log_field_configs("logging.access_log", &self.access_log.fields)?;
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LoggingAccessLogConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub stdout: bool,
  #[serde(default = "default_system_access_log_field_configs")]
  pub fields: Vec<AccessLogFieldConfig>,
}

impl Default for LoggingAccessLogConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      stdout: true,
      fields: default_system_access_log_field_configs(),
    }
  }
}

fn default_log_level() -> String {
  "info".to_string()
}

fn default_system_access_log_field_configs() -> Vec<AccessLogFieldConfig> {
  [
    ("request_id", "Request.Id"),
    ("response_id", "Response.Id"),
    ("transaction_id", "Context.TransactionId"),
    ("method", "Request.Http.Method"),
    ("uri", "Request.Http.Uri"),
    ("path", "Request.Http.Path"),
    ("query", "Request.Http.Query"),
    ("request_version", "Request.Http.Version"),
    ("host", "Request.Http.Host"),
    ("user_agent", "Request.Headers.getAll('User-Agent')"),
    ("client_ip", "Request.Client.Ip"),
    ("client_port", "Request.Client.Port"),
    ("protocol", "Request.Protocol"),
    ("transport", "Request.Transport.Network"),
    ("tls", "Request.Tls.Enabled"),
    ("route", "Context.RouteName"),
    ("status", "Response.Http.Status"),
    ("reason", "Response.Http.Reason"),
    ("response_body_bytes", "Response.Body.Size"),
    ("upstream", "Response.Upstream.Name"),
    ("upstream_pool", "Response.Upstream.Pool"),
    ("upstream_scheme", "Response.Upstream.Scheme"),
    (
      "upstream_connect_time_ms",
      "Response.Upstream.ConnectTimeMs",
    ),
    (
      "upstream_first_byte_time_ms",
      "Response.Upstream.FirstByteTimeMs",
    ),
    ("request_received_at_unix_ms", "Request.ReceivedAtUnixMs"),
    ("response_received_at_unix_ms", "Response.ReceivedAtUnixMs"),
  ]
  .into_iter()
  .map(|(name, value)| AccessLogFieldConfig {
    name: name.to_string(),
    value: value.to_string(),
  })
  .collect()
}
