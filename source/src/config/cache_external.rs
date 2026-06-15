//! External cache handler configuration and validation helpers.

use std::collections::HashSet;

use anyhow::bail;
use serde::Deserialize;
use url::Url;

use super::{CacheConfig, validate_runtime_identifier};

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCacheHandlerKind {
  #[default]
  Http,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCacheHandlerFailPolicy {
  #[default]
  LocalOnly,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ExternalCacheHandlerConfig {
  pub name: String,
  #[serde(default)]
  pub kind: ExternalCacheHandlerKind,
  pub endpoint: Url,
  #[serde(default)]
  pub token_env: Option<String>,
  #[serde(default = "default_external_cache_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_external_cache_request_timeout_ms")]
  pub request_timeout_ms: u64,
  #[serde(default = "default_external_cache_max_metadata_bytes")]
  pub max_metadata_bytes: usize,
  #[serde(default)]
  pub max_body_bytes: Option<usize>,
  #[serde(default = "default_external_cache_max_inflight_requests")]
  pub max_inflight_requests: usize,
  #[serde(default)]
  pub fail_policy: ExternalCacheHandlerFailPolicy,
}

pub(super) fn validate_external_handlers(cache: &CacheConfig) -> anyhow::Result<HashSet<&str>> {
  let mut names = HashSet::new();
  for handler in &cache.external_handlers {
    validate_runtime_identifier("cache external handler name", &handler.name)?;
    if matches!(handler.name.as_str(), "default" | "off") {
      bail!("cache external handler name {} is reserved", handler.name);
    }
    if !names.insert(handler.name.as_str()) {
      bail!("duplicate cache external handler name {}", handler.name);
    }
    if !matches!(handler.endpoint.scheme(), "http" | "https") {
      bail!(
        "cache external handler {} endpoint must use http:// or https://",
        handler.name
      );
    }
    if handler.connect_timeout_ms == 0 {
      bail!(
        "cache external handler {} connect_timeout_ms must be greater than 0",
        handler.name
      );
    }
    if handler.request_timeout_ms == 0 {
      bail!(
        "cache external handler {} request_timeout_ms must be greater than 0",
        handler.name
      );
    }
    if handler.max_metadata_bytes == 0 {
      bail!(
        "cache external handler {} max_metadata_bytes must be greater than 0",
        handler.name
      );
    }
    if handler.max_body_bytes == Some(0) {
      bail!(
        "cache external handler {} max_body_bytes must be greater than 0",
        handler.name
      );
    }
    if handler.max_inflight_requests == 0 {
      bail!(
        "cache external handler {} max_inflight_requests must be greater than 0",
        handler.name
      );
    }
    if let Some(token_env) = handler.token_env.as_deref()
      && (token_env.trim() != token_env || token_env.is_empty())
    {
      bail!(
        "cache external handler {} token_env must not be empty or padded",
        handler.name
      );
    }
  }
  Ok(names)
}

pub(super) fn validate_external_handler_reference(
  field_name: &str,
  value: Option<&str>,
  handler_names: &HashSet<&str>,
  allow_off: bool,
) -> anyhow::Result<()> {
  let Some(value) = value else {
    return Ok(());
  };
  if value == "off" {
    if !allow_off {
      bail!("{field_name} must reference a cache external handler name");
    }
    return Ok(());
  }
  validate_runtime_identifier(field_name, value)?;
  if !handler_names.contains(value) {
    bail!("{field_name} references unknown cache external handler {value}");
  }
  Ok(())
}

fn default_external_cache_connect_timeout_ms() -> u64 {
  250
}

fn default_external_cache_request_timeout_ms() -> u64 {
  30_000
}

fn default_external_cache_max_metadata_bytes() -> usize {
  1_048_576
}

fn default_external_cache_max_inflight_requests() -> usize {
  64
}
