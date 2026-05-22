use std::collections::HashSet;

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
    }
  }
  Ok(())
}

fn validate_non_kubernetes_discovery_fields(
  pool: &UpstreamPoolConfig,
  discovery: &super::UpstreamPoolDiscoveryConfig,
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

fn default_sticky_cookie_name() -> String {
  "oxibelt_sticky".to_string()
}

fn default_sticky_cookie_ttl_seconds() -> u64 {
  3_600
}

fn default_sticky_cookie_secret_env() -> String {
  "OXIBELT_STICKY_COOKIE_SECRET".to_string()
}
