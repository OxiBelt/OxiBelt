use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use regex::Regex;
use serde::Deserialize;

use super::super::route_header_policy::{
  is_reserved_route_request_header, normalize_route_action_header_name,
};
use super::super::{
  ConfigSourcePaths, OutboundTlsRevocationConfig, UpstreamPoolConfig, UpstreamTlsTrust,
  outbound_revocation, resolve_existing_local_config_file_path_with_logical,
  validate_optional_non_empty,
};

pub const HEALTH_CHECK_PROTOCOL_WIRE_VALUES: &[&str] = &["http", "grpc"];
pub const HEALTH_CHECK_MODE_WIRE_VALUES: &[&str] = &["passive", "active"];
pub const GRPC_HEALTH_SERVING_STATUS_WIRE_VALUES: &[&str] =
  &["UNKNOWN", "SERVING", "NOT_SERVING", "SERVICE_UNKNOWN"];

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolHealthCheckConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub mode: HealthCheckMode,
  #[serde(default)]
  pub protocol: HealthCheckProtocol,
  #[serde(default = "default_health_check_method")]
  pub method: String,
  #[serde(default = "default_health_check_path")]
  pub path: String,
  #[serde(default)]
  pub health_port: Option<u16>,
  #[serde(default)]
  pub health_host: Option<String>,
  #[serde(default)]
  pub headers: Vec<UpstreamPoolHealthCheckHeaderConfig>,
  #[serde(default)]
  pub body: String,
  #[serde(default = "default_health_check_expected_status")]
  pub expected_status: Vec<u16>,
  #[serde(default)]
  pub expected_status_ranges: Vec<UpstreamPoolHealthCheckStatusRangeConfig>,
  #[serde(default)]
  pub expected_body_regex: Option<String>,
  #[serde(default = "default_health_check_body_match_max_bytes")]
  pub body_match_max_bytes: usize,
  #[serde(default = "default_health_check_interval_ms")]
  pub interval_ms: u64,
  #[serde(default = "default_health_check_timeout_ms")]
  pub timeout_ms: u64,
  #[serde(default)]
  pub jitter_ms: u64,
  #[serde(default = "default_health_check_healthy_threshold", alias = "rise")]
  pub healthy_threshold: u32,
  #[serde(default = "default_health_check_unhealthy_threshold", alias = "fall")]
  pub unhealthy_threshold: u32,
  #[serde(default)]
  pub grpc_service: String,
  #[serde(default = "default_grpc_health_expected_statuses")]
  pub grpc_expected_statuses: Vec<GrpcHealthServingStatus>,
  #[serde(default)]
  pub tls: UpstreamPoolHealthCheckTlsConfig,
}

impl Default for UpstreamPoolHealthCheckConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: HealthCheckMode::Passive,
      protocol: HealthCheckProtocol::Http,
      method: default_health_check_method(),
      path: default_health_check_path(),
      health_port: None,
      health_host: None,
      headers: Vec::new(),
      body: String::new(),
      expected_status: default_health_check_expected_status(),
      expected_status_ranges: Vec::new(),
      expected_body_regex: None,
      body_match_max_bytes: default_health_check_body_match_max_bytes(),
      interval_ms: default_health_check_interval_ms(),
      timeout_ms: default_health_check_timeout_ms(),
      jitter_ms: 0,
      healthy_threshold: default_health_check_healthy_threshold(),
      unhealthy_threshold: default_health_check_unhealthy_threshold(),
      grpc_service: String::new(),
      grpc_expected_statuses: default_grpc_health_expected_statuses(),
      tls: UpstreamPoolHealthCheckTlsConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolHealthCheckHeaderConfig {
  pub name: String,
  pub value: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
pub struct UpstreamPoolHealthCheckStatusRangeConfig {
  pub start: u16,
  pub end: u16,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct UpstreamPoolHealthCheckTlsConfig {
  #[serde(default)]
  pub trusted_ca_certs: Vec<PathBuf>,
  #[serde(default)]
  pub upstream_revocation: Option<OutboundTlsRevocationConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckProtocol {
  #[default]
  Http,
  Grpc,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrpcHealthServingStatus {
  Unknown,
  Serving,
  NotServing,
  ServiceUnknown,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckMode {
  #[default]
  Passive,
  Active,
}

pub(crate) fn default_health_check_method() -> String {
  "GET".to_string()
}

pub(crate) fn default_health_check_path() -> String {
  "/healthz".to_string()
}

pub(crate) fn default_health_check_interval_ms() -> u64 {
  5_000
}

pub(crate) fn default_health_check_timeout_ms() -> u64 {
  1_000
}

pub(crate) fn default_health_check_healthy_threshold() -> u32 {
  2
}

pub(crate) fn default_health_check_unhealthy_threshold() -> u32 {
  3
}

pub(crate) fn default_health_check_expected_status() -> Vec<u16> {
  vec![200, 204]
}

pub(crate) fn default_health_check_body_match_max_bytes() -> usize {
  64 * 1024
}

pub(crate) fn default_grpc_health_expected_statuses() -> Vec<GrpcHealthServingStatus> {
  vec![GrpcHealthServingStatus::Serving]
}

impl UpstreamPoolConfig {
  pub(in crate::config) fn resolve_health_check_paths(
    &mut self,
    cert_dir: &Path,
    source_paths: &mut ConfigSourcePaths,
  ) -> anyhow::Result<()> {
    self.health_check.tls.trusted_ca_certs = self
      .health_check
      .tls
      .trusted_ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "upstream_pools.health_check.tls.trusted_ca_certs",
          cert_dir,
          path,
        )?;
        source_paths.remember_runtime_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    if let Some(revocation) = &mut self.health_check.tls.upstream_revocation {
      outbound_revocation::resolve_outbound_crlite_filter_file(
        revocation,
        source_paths,
        cert_dir,
        "upstream_pools.health_check.tls.upstream_revocation.crlite.filter_file",
      )?;
    }
    Ok(())
  }
}

pub(in crate::config) fn validate_pool_health_check(
  pool: &UpstreamPoolConfig,
) -> anyhow::Result<()> {
  let health_check = &pool.health_check;
  if !health_check.tls.trusted_ca_certs.is_empty()
    && pool
      .servers
      .iter()
      .map(|server| server.tls.trust)
      .chain(pool.discovery.iter().map(|discovery| discovery.tls.trust))
      .any(|trust| trust != UpstreamTlsTrust::Inherit)
  {
    bail!(
      "upstream pool {} health_check.tls.trusted_ca_certs cannot augment a server using system or exclusive trust",
      pool.name
    );
  }
  if !health_check.path.starts_with('/') {
    bail!(
      "upstream pool {} health_check.path must start with '/'",
      pool.name
    );
  }
  let method = Method::from_bytes(health_check.method.as_bytes()).with_context(|| {
    format!(
      "upstream pool {} health_check.method is not a valid HTTP method",
      pool.name
    )
  })?;
  if method == Method::CONNECT {
    bail!(
      "upstream pool {} health_check.method must not be CONNECT",
      pool.name
    );
  }
  if let Some(port) = health_check.health_port
    && port == 0
  {
    bail!(
      "upstream pool {} health_check.health_port must be greater than 0",
      pool.name
    );
  }
  if let Some(host) = health_check.health_host.as_deref() {
    validate_optional_non_empty(
      &format!("upstream pool {} health_check.health_host", pool.name),
      Some(host),
    )?;
    HeaderValue::from_str(host).with_context(|| {
      format!(
        "upstream pool {} health_check.health_host is not a valid Host header value",
        pool.name
      )
    })?;
  }
  validate_health_check_headers(pool)?;
  if health_check.enabled {
    if health_check.interval_ms == 0 {
      bail!(
        "upstream pool {} health_check.interval_ms must be greater than 0",
        pool.name
      );
    }
    if health_check.timeout_ms == 0 {
      bail!(
        "upstream pool {} health_check.timeout_ms must be greater than 0",
        pool.name
      );
    }
    if health_check.healthy_threshold == 0 || health_check.unhealthy_threshold == 0 {
      bail!(
        "upstream pool {} health_check thresholds must be greater than 0",
        pool.name
      );
    }
  }
  if health_check.body_match_max_bytes == 0 {
    bail!(
      "upstream pool {} health_check.body_match_max_bytes must be greater than 0",
      pool.name
    );
  }
  for status in &health_check.expected_status {
    StatusCode::from_u16(*status).with_context(|| {
      format!(
        "upstream pool {} has invalid health_check.expected_status {status}",
        pool.name
      )
    })?;
  }
  for range in &health_check.expected_status_ranges {
    StatusCode::from_u16(range.start).with_context(|| {
      format!(
        "upstream pool {} has invalid health_check.expected_status_ranges.start {}",
        pool.name, range.start
      )
    })?;
    StatusCode::from_u16(range.end).with_context(|| {
      format!(
        "upstream pool {} has invalid health_check.expected_status_ranges.end {}",
        pool.name, range.end
      )
    })?;
    if range.start > range.end {
      bail!(
        "upstream pool {} health_check.expected_status_ranges start must be less than or equal to end",
        pool.name
      );
    }
  }
  if health_check.protocol == HealthCheckProtocol::Http
    && health_check.expected_status.is_empty()
    && health_check.expected_status_ranges.is_empty()
  {
    bail!(
      "upstream pool {} health_check must configure expected_status or expected_status_ranges",
      pool.name
    );
  }
  if let Some(pattern) = health_check.expected_body_regex.as_deref() {
    validate_optional_non_empty(
      &format!(
        "upstream pool {} health_check.expected_body_regex",
        pool.name
      ),
      Some(pattern),
    )?;
    Regex::new(pattern).with_context(|| {
      format!(
        "upstream pool {} health_check.expected_body_regex contains invalid regex",
        pool.name
      )
    })?;
    if health_check.protocol == HealthCheckProtocol::Grpc {
      bail!(
        "upstream pool {} health_check.expected_body_regex is only supported for HTTP health checks",
        pool.name
      );
    }
  }
  if health_check.protocol == HealthCheckProtocol::Grpc
    && health_check.grpc_expected_statuses.is_empty()
  {
    bail!(
      "upstream pool {} health_check.grpc_expected_statuses must not be empty",
      pool.name
    );
  }
  if let Some(revocation) = &health_check.tls.upstream_revocation {
    revocation.validate("upstream_pools.health_check.tls.upstream_revocation")?;
  }
  Ok(())
}

fn validate_health_check_headers(pool: &UpstreamPoolConfig) -> anyhow::Result<()> {
  for header in &pool.health_check.headers {
    validate_optional_non_empty(
      &format!("upstream pool {} health_check.headers.name", pool.name),
      Some(&header.name),
    )?;
    validate_optional_non_empty(
      &format!("upstream pool {} health_check.headers.value", pool.name),
      Some(&header.value),
    )?;
    let normalized = normalize_route_action_header_name(&header.name).with_context(|| {
      format!(
        "upstream pool {} health_check header name {} is invalid",
        pool.name, header.name
      )
    })?;
    if is_reserved_route_request_header(&normalized) {
      bail!(
        "upstream pool {} health_check header {} is reserved",
        pool.name,
        header.name
      );
    }
    if pool.health_check.protocol == HealthCheckProtocol::Grpc && normalized == "content-type" {
      bail!(
        "upstream pool {} health_check header content-type is reserved for gRPC health checks",
        pool.name
      );
    }
    HeaderName::from_bytes(header.name.as_bytes()).with_context(|| {
      format!(
        "upstream pool {} health_check header name {} is invalid",
        pool.name, header.name
      )
    })?;
    HeaderValue::from_str(&header.value).with_context(|| {
      format!(
        "upstream pool {} health_check header {} has invalid value",
        pool.name, header.name
      )
    })?;
  }
  Ok(())
}
