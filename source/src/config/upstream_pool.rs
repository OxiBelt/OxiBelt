use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::bail;
use serde::Deserialize;
use url::Url;

use super::{
  DnsDiscoveryRecordType, LoadBalancingAlgorithm, UpstreamDiscoveryProvider, UpstreamPoolConfig,
  validate_optional_non_empty,
};

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesDiscoveryResource {
  #[default]
  Endpoints,
  EndpointSlice,
}

pub(super) fn default_kubernetes_watch_timeout_seconds() -> u64 {
  300
}

pub(super) fn default_discovery_update_debounce_ms() -> u64 {
  250
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolDiscoveryConfig {
  pub provider: UpstreamDiscoveryProvider,
  #[serde(default)]
  pub name: Option<String>,
  #[serde(default)]
  pub endpoint: Option<Url>,
  #[serde(default)]
  pub namespace: Option<String>,
  #[serde(default)]
  pub service: Option<String>,
  #[serde(default)]
  pub port_name: Option<String>,
  #[serde(default)]
  pub key_prefix: Option<String>,
  #[serde(default)]
  pub token_env: Option<String>,
  #[serde(default)]
  pub filter: Option<String>,
  #[serde(default)]
  pub datacenter: Option<String>,
  #[serde(default)]
  pub file: Option<PathBuf>,
  #[serde(default)]
  pub record_type: DnsDiscoveryRecordType,
  #[serde(default)]
  pub scheme: super::DiscoveryUpstreamScheme,
  #[serde(default)]
  pub port: Option<u16>,
  #[serde(default)]
  pub kubernetes_resource: KubernetesDiscoveryResource,
  #[serde(default)]
  pub watch: bool,
  #[serde(default = "default_kubernetes_watch_timeout_seconds")]
  pub watch_timeout_seconds: u64,
  #[serde(default = "default_discovery_update_debounce_ms")]
  pub update_debounce_ms: u64,
  #[serde(default = "super::default_discovery_refresh_interval_ms")]
  pub refresh_interval_ms: u64,
  #[serde(default = "super::default_discovery_min_ttl_ms")]
  pub min_ttl_ms: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolSlowStartConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_pool_slow_start_duration_ms")]
  pub duration_ms: u64,
  #[serde(default = "default_pool_slow_start_min_weight_percent")]
  pub min_weight_percent: u32,
}

impl Default for UpstreamPoolSlowStartConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      duration_ms: default_pool_slow_start_duration_ms(),
      min_weight_percent: default_pool_slow_start_min_weight_percent(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolOutlierEjectionConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_pool_outlier_ejection_consecutive_failures")]
  pub consecutive_failures: u32,
  #[serde(default = "default_pool_outlier_ejection_base_ms")]
  pub base_ejection_ms: u64,
  #[serde(default = "default_pool_outlier_ejection_max_ms")]
  pub max_ejection_ms: u64,
}

impl Default for UpstreamPoolOutlierEjectionConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      consecutive_failures: default_pool_outlier_ejection_consecutive_failures(),
      base_ejection_ms: default_pool_outlier_ejection_base_ms(),
      max_ejection_ms: default_pool_outlier_ejection_max_ms(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolStickyCookieConfig {
  #[serde(default = "default_sticky_cookie_name")]
  pub cookie_name: String,
  #[serde(default = "default_sticky_cookie_ttl_seconds")]
  pub ttl_seconds: u64,
  #[serde(default)]
  pub fallback_algorithm: StickyCookieFallbackAlgorithm,
  #[serde(default = "default_sticky_cookie_secret_env")]
  pub secret_env: String,
  #[serde(default = "super::default_true")]
  pub secure: bool,
  #[serde(default = "super::default_true")]
  pub http_only: bool,
  #[serde(default)]
  pub same_site: StickyCookieSameSite,
  #[serde(default = "super::default_path_prefix")]
  pub path: String,
}

impl Default for UpstreamPoolStickyCookieConfig {
  fn default() -> Self {
    Self {
      cookie_name: default_sticky_cookie_name(),
      ttl_seconds: default_sticky_cookie_ttl_seconds(),
      fallback_algorithm: StickyCookieFallbackAlgorithm::default(),
      secret_env: default_sticky_cookie_secret_env(),
      secure: true,
      http_only: true,
      same_site: StickyCookieSameSite::default(),
      path: super::default_path_prefix(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StickyCookieFallbackAlgorithm {
  #[default]
  PowerOfTwoChoices,
  WeightedLeastConn,
  RendezvousHash,
  RendezvousIpHash,
  Ewma,
  LeastTime,
}

impl From<StickyCookieFallbackAlgorithm> for LoadBalancingAlgorithm {
  fn from(value: StickyCookieFallbackAlgorithm) -> Self {
    match value {
      StickyCookieFallbackAlgorithm::PowerOfTwoChoices => Self::PowerOfTwoChoices,
      StickyCookieFallbackAlgorithm::WeightedLeastConn => Self::WeightedLeastConn,
      StickyCookieFallbackAlgorithm::RendezvousHash => Self::RendezvousHash,
      StickyCookieFallbackAlgorithm::RendezvousIpHash => Self::RendezvousIpHash,
      StickyCookieFallbackAlgorithm::Ewma => Self::Ewma,
      StickyCookieFallbackAlgorithm::LeastTime => Self::LeastTime,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StickyCookieSameSite {
  #[default]
  Lax,
  Strict,
  None,
}

impl StickyCookieSameSite {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Lax => "Lax",
      Self::Strict => "Strict",
      Self::None => "None",
    }
  }
}

pub(super) fn validate_pool_policy(pool: &UpstreamPoolConfig) -> anyhow::Result<()> {
  if pool.slow_start.duration_ms == 0 || pool.slow_start.min_weight_percent == 0 {
    bail!(
      "upstream pool {} slow_start duration_ms and min_weight_percent must be greater than 0",
      pool.name
    );
  }
  if pool.slow_start.min_weight_percent > 100 {
    bail!(
      "upstream pool {} slow_start.min_weight_percent must be at most 100",
      pool.name
    );
  }
  if pool.outlier_ejection.consecutive_failures == 0
    || pool.outlier_ejection.base_ejection_ms == 0
    || pool.outlier_ejection.max_ejection_ms == 0
  {
    bail!(
      "upstream pool {} outlier_ejection values must be greater than 0",
      pool.name
    );
  }
  if pool.outlier_ejection.max_ejection_ms < pool.outlier_ejection.base_ejection_ms {
    bail!(
      "upstream pool {} outlier_ejection.max_ejection_ms must be greater than or equal to base_ejection_ms",
      pool.name
    );
  }
  Ok(())
}

pub(super) fn validate_pool_discovery(pool: &UpstreamPoolConfig) -> anyhow::Result<()> {
  let mut providers = HashSet::new();
  for discovery in &pool.discovery {
    if !providers.insert(discovery.provider) {
      bail!(
        "upstream pool {} must not configure duplicate {:?} discovery providers",
        pool.name,
        discovery.provider
      );
    }
    if discovery.refresh_interval_ms == 0 || discovery.min_ttl_ms == 0 {
      bail!(
        "upstream pool {} discovery refresh_interval_ms and min_ttl_ms must be greater than 0",
        pool.name
      );
    }
    if discovery.watch_timeout_seconds == 0 || discovery.update_debounce_ms == 0 {
      bail!(
        "upstream pool {} discovery watch_timeout_seconds and update_debounce_ms must be greater than 0",
        pool.name
      );
    }
    match discovery.provider {
      UpstreamDiscoveryProvider::Dns => {
        validate_non_kubernetes_discovery_fields(pool, discovery)?;
        let Some(name) = discovery.name.as_deref() else {
          bail!("upstream pool {} DNS discovery requires name", pool.name);
        };
        validate_optional_non_empty("upstream_pools.discovery.name", Some(name))?;
        if discovery.record_type != DnsDiscoveryRecordType::Srv && discovery.port.is_none() {
          bail!(
            "upstream pool {} DNS A/AAAA discovery requires port",
            pool.name
          );
        }
      }
      UpstreamDiscoveryProvider::File => {
        validate_non_kubernetes_discovery_fields(pool, discovery)?;
        if discovery.file.is_none() {
          bail!("upstream pool {} file discovery requires file", pool.name);
        }
      }
      UpstreamDiscoveryProvider::Kubernetes => {
        validate_http_endpoint(
          &format!("upstream pool {} kubernetes discovery endpoint", pool.name),
          discovery.endpoint.as_ref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.namespace",
          discovery.namespace.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.service",
          discovery.service.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.port_name",
          discovery.port_name.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.token_env",
          discovery.token_env.as_deref(),
        )?;
        if discovery.namespace.is_none() || discovery.service.is_none() {
          bail!(
            "upstream pool {} kubernetes discovery requires namespace and service",
            pool.name
          );
        }
        if discovery.port.is_some() == discovery.port_name.is_some() {
          bail!(
            "upstream pool {} kubernetes discovery requires exactly one of port or port_name",
            pool.name
          );
        }
        if discovery.watch
          && discovery.kubernetes_resource != KubernetesDiscoveryResource::EndpointSlice
        {
          bail!(
            "upstream pool {} kubernetes discovery watch requires kubernetes_resource = \"endpoint_slice\"",
            pool.name
          );
        }
      }
      UpstreamDiscoveryProvider::Consul => {
        validate_non_kubernetes_discovery_fields(pool, discovery)?;
        validate_http_endpoint(
          &format!("upstream pool {} consul discovery endpoint", pool.name),
          discovery.endpoint.as_ref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.service",
          discovery.service.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.namespace",
          discovery.namespace.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.datacenter",
          discovery.datacenter.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.filter",
          discovery.filter.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.token_env",
          discovery.token_env.as_deref(),
        )?;
        if discovery.service.is_none() {
          bail!(
            "upstream pool {} consul discovery requires service",
            pool.name
          );
        }
      }
      UpstreamDiscoveryProvider::Etcd => {
        validate_non_kubernetes_discovery_fields(pool, discovery)?;
        validate_http_endpoint(
          &format!("upstream pool {} etcd discovery endpoint", pool.name),
          discovery.endpoint.as_ref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.key_prefix",
          discovery.key_prefix.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.token_env",
          discovery.token_env.as_deref(),
        )?;
        if discovery.key_prefix.is_none() {
          bail!(
            "upstream pool {} etcd discovery requires key_prefix",
            pool.name
          );
        }
      }
      UpstreamDiscoveryProvider::Nomad => {
        validate_nomad_discovery_fields(pool, discovery)?;
        validate_http_endpoint(
          &format!("upstream pool {} nomad discovery endpoint", pool.name),
          discovery.endpoint.as_ref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.service",
          discovery.service.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.namespace",
          discovery.namespace.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.filter",
          discovery.filter.as_deref(),
        )?;
        validate_optional_non_empty(
          "upstream_pools.discovery.token_env",
          discovery.token_env.as_deref(),
        )?;
        if discovery.service.is_none() {
          bail!(
            "upstream pool {} nomad discovery requires service",
            pool.name
          );
        }
      }
    }
  }
  Ok(())
}

fn validate_nomad_discovery_fields(
  pool: &UpstreamPoolConfig,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<()> {
  if discovery.kubernetes_resource != KubernetesDiscoveryResource::Endpoints {
    bail!(
      "upstream pool {} discovery kubernetes_resource is only supported for kubernetes providers",
      pool.name
    );
  }
  if discovery.name.is_some()
    || discovery.port_name.is_some()
    || discovery.key_prefix.is_some()
    || discovery.datacenter.is_some()
    || discovery.file.is_some()
    || discovery.port.is_some()
  {
    bail!(
      "upstream pool {} nomad discovery only supports endpoint, service, namespace, filter, token_env, scheme, refresh_interval_ms, watch, and watch_timeout_seconds",
      pool.name
    );
  }
  Ok(())
}

fn validate_non_kubernetes_discovery_fields(
  pool: &UpstreamPoolConfig,
  discovery: &UpstreamPoolDiscoveryConfig,
) -> anyhow::Result<()> {
  if discovery.kubernetes_resource != KubernetesDiscoveryResource::Endpoints {
    bail!(
      "upstream pool {} discovery kubernetes_resource is only supported for kubernetes providers",
      pool.name
    );
  }
  if discovery.watch {
    bail!(
      "upstream pool {} discovery watch is only supported for kubernetes providers",
      pool.name
    );
  }
  Ok(())
}

pub(super) fn validate_sticky_cookie_pool(pool: &UpstreamPoolConfig) -> anyhow::Result<()> {
  let cookie = &pool.sticky_cookie;
  validate_optional_non_empty(
    &format!("upstream pool {} sticky_cookie.cookie_name", pool.name),
    Some(&cookie.cookie_name),
  )?;
  if !cookie.cookie_name.bytes().all(|byte| {
    byte.is_ascii_alphanumeric()
      || matches!(
        byte,
        b'!'
          | b'#'
          | b'$'
          | b'%'
          | b'&'
          | b'\''
          | b'*'
          | b'+'
          | b'-'
          | b'.'
          | b'^'
          | b'_'
          | b'`'
          | b'|'
          | b'~'
      )
  }) {
    bail!(
      "upstream pool {} sticky_cookie.cookie_name is not a valid cookie token",
      pool.name
    );
  }
  if cookie.ttl_seconds == 0 {
    bail!(
      "upstream pool {} sticky_cookie.ttl_seconds must be greater than 0",
      pool.name
    );
  }
  validate_optional_non_empty(
    &format!("upstream pool {} sticky_cookie.secret_env", pool.name),
    Some(&cookie.secret_env),
  )?;
  if !cookie.path.starts_with('/') {
    bail!(
      "upstream pool {} sticky_cookie.path must start with '/'",
      pool.name
    );
  }
  Ok(())
}

fn validate_http_endpoint(field_name: &str, endpoint: Option<&Url>) -> anyhow::Result<()> {
  let Some(endpoint) = endpoint else {
    bail!("{field_name} is required");
  };
  if endpoint.scheme() != "http" && endpoint.scheme() != "https" {
    bail!("{field_name} must use http:// or https://");
  }
  Ok(())
}

fn default_pool_slow_start_duration_ms() -> u64 {
  30_000
}

fn default_pool_slow_start_min_weight_percent() -> u32 {
  10
}

fn default_pool_outlier_ejection_consecutive_failures() -> u32 {
  5
}

fn default_pool_outlier_ejection_base_ms() -> u64 {
  30_000
}

fn default_pool_outlier_ejection_max_ms() -> u64 {
  300_000
}

fn default_sticky_cookie_name() -> String {
  "oxibelt_sticky".to_string()
}

fn default_sticky_cookie_ttl_seconds() -> u64 {
  3_600
}

fn default_sticky_cookie_secret_env() -> String {
  "OXIBELT_STICKY_COOKIE_SECRET".to_string()
}
