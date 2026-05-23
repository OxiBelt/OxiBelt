use std::path::PathBuf;

use anyhow::bail;
use serde::Deserialize;

use crate::waf::RouteWafConfig;

use super::{
  BufferingMode, HttpVersion, RetryCondition, RouteIpmConfig, default_hosts, default_path_prefix,
};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RouteConfig {
  pub name: String,
  #[serde(default = "default_hosts")]
  pub hosts: Vec<String>,
  #[serde(default = "default_path_prefix")]
  pub path_prefix: String,
  #[serde(default)]
  pub replace_prefix_with: Option<String>,
  #[serde(default)]
  pub upstream: Option<String>,
  #[serde(default)]
  pub upstream_pool: Option<String>,
  #[serde(default)]
  pub static_root: Option<PathBuf>,
  #[serde(default)]
  pub upstream_http_version: Option<HttpVersion>,
  #[serde(default)]
  pub generic_http_upgrade: bool,
  #[serde(default)]
  pub connect_tunneling: bool,
  #[serde(default)]
  pub grpc_web: bool,
  #[serde(default)]
  pub external_auth: Option<String>,
  #[serde(default)]
  pub ipm: RouteIpmConfig,
  #[serde(default)]
  pub cache: Option<String>,
  #[serde(default)]
  pub compression: Option<String>,
  #[serde(default)]
  pub buffering: RouteBufferingConfig,
  #[serde(default)]
  pub timeouts: RouteTimeoutConfig,
  #[serde(default)]
  pub retry: Option<RouteRetryConfig>,
  #[serde(default)]
  pub waf: RouteWafConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteBufferingConfig {
  #[serde(default)]
  pub request: Option<BufferingMode>,
  #[serde(default)]
  pub response: Option<BufferingMode>,
  #[serde(default)]
  pub max_memory_body_bytes: Option<usize>,
  #[serde(default)]
  pub max_temp_file_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteTimeoutConfig {
  #[serde(default)]
  pub client_body_timeout_ms: Option<u64>,
  #[serde(default)]
  pub response_send_timeout_ms: Option<u64>,
  #[serde(default)]
  pub websocket_idle_timeout_ms: Option<u64>,
  #[serde(default)]
  pub webtransport_idle_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_connect_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_request_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_first_byte_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_read_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_send_timeout_ms: Option<u64>,
}

impl RouteTimeoutConfig {
  pub(super) fn validate(&self, route_name: &str) -> anyhow::Result<()> {
    for (field, value) in [
      ("client_body_timeout_ms", self.client_body_timeout_ms),
      ("response_send_timeout_ms", self.response_send_timeout_ms),
      ("websocket_idle_timeout_ms", self.websocket_idle_timeout_ms),
      (
        "webtransport_idle_timeout_ms",
        self.webtransport_idle_timeout_ms,
      ),
      (
        "upstream_connect_timeout_ms",
        self.upstream_connect_timeout_ms,
      ),
      (
        "upstream_request_timeout_ms",
        self.upstream_request_timeout_ms,
      ),
      (
        "upstream_first_byte_timeout_ms",
        self.upstream_first_byte_timeout_ms,
      ),
      ("upstream_read_timeout_ms", self.upstream_read_timeout_ms),
      ("upstream_send_timeout_ms", self.upstream_send_timeout_ms),
    ] {
      if value == Some(0) {
        bail!("route {route_name} timeouts.{field} must be greater than 0");
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteRetryConfig {
  #[serde(default)]
  pub enabled: Option<bool>,
  #[serde(default)]
  pub tries: Option<usize>,
  #[serde(default)]
  pub total_budget_ms: Option<u64>,
  #[serde(default)]
  pub per_attempt_timeout_ms: Option<u64>,
  #[serde(default)]
  pub on: Option<Vec<RetryCondition>>,
  #[serde(default)]
  pub retry_non_idempotent: Option<bool>,
  #[serde(default)]
  pub backoff_base_ms: Option<u64>,
  #[serde(default)]
  pub backoff_max_ms: Option<u64>,
  #[serde(default)]
  pub jitter: Option<bool>,
  #[serde(default)]
  pub reselect_pool_on_retry: Option<bool>,
  #[serde(default)]
  pub exclude_failed_pool_upstreams: Option<bool>,
  #[serde(default)]
  pub report_passive_health: Option<bool>,
}

impl RouteRetryConfig {
  pub(super) fn validate(&self, route_name: &str) -> anyhow::Result<()> {
    if self.tries == Some(0) {
      bail!("route {route_name} retry.tries must be greater than 0");
    }
    for (field, value) in [
      ("total_budget_ms", self.total_budget_ms),
      ("per_attempt_timeout_ms", self.per_attempt_timeout_ms),
    ] {
      if value == Some(0) {
        bail!("route {route_name} retry.{field} must be greater than 0");
      }
    }
    if let (Some(base), Some(max)) = (self.backoff_base_ms, self.backoff_max_ms)
      && max > 0
      && base > max
    {
      bail!(
        "route {route_name} retry.backoff_max_ms must be 0 or greater than or equal to retry.backoff_base_ms"
      );
    }
    Ok(())
  }
}
