//! Supporting cache configuration sections.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CacheSurrogateConfig {
  #[serde(default = "super::default_true")]
  pub enabled: bool,
  #[serde(default = "super::default_true")]
  pub strip_response_header: bool,
}

impl Default for CacheSurrogateConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      strip_response_header: true,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CacheAdmissionConfig {
  #[serde(default = "default_cache_admission_statuses")]
  pub statuses: Vec<u16>,
  #[serde(default)]
  pub content_types: Vec<String>,
  #[serde(default)]
  pub max_body_bytes: usize,
  #[serde(default = "default_cache_admission_min_hits")]
  pub min_hits: usize,
  #[serde(default = "default_cache_admission_max_tracked_keys")]
  pub max_tracked_keys: usize,
}

impl Default for CacheAdmissionConfig {
  fn default() -> Self {
    Self {
      statuses: default_cache_admission_statuses(),
      content_types: Vec::new(),
      max_body_bytes: 0,
      min_hits: default_cache_admission_min_hits(),
      max_tracked_keys: default_cache_admission_max_tracked_keys(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CacheStaleIfErrorConfig {
  #[serde(default = "super::default_true")]
  pub connect_error: bool,
  #[serde(default = "super::default_true")]
  pub read_timeout: bool,
  #[serde(default)]
  pub statuses: Vec<u16>,
  #[serde(default)]
  pub max_upstream_stale_seconds: u64,
}

impl Default for CacheStaleIfErrorConfig {
  fn default() -> Self {
    Self {
      connect_error: true,
      read_timeout: true,
      statuses: Vec::new(),
      max_upstream_stale_seconds: 0,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CachePolicyRuleConfig {
  #[serde(default)]
  pub mime_types: Vec<String>,
  pub store: super::CacheStore,
}

fn default_cache_admission_statuses() -> Vec<u16> {
  vec![200, 203, 204, 301, 308]
}

fn default_cache_admission_min_hits() -> usize {
  1
}

fn default_cache_admission_max_tracked_keys() -> usize {
  16_384
}
