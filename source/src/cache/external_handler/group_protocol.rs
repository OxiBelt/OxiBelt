//! Cache-group authority exchanges for external cache handlers.

use anyhow::{Context, anyhow, bail, ensure};
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::protocol::{CACHE_GROUPS_CAPABILITY, PROTOCOL_VERSION};

pub(crate) const MAX_CACHE_GROUP_STATE_BYTES: usize = 16 * 1024 * 1024;

/// A handler explicitly lacks cache-group protocol support. This is distinct
/// from transport and malformed-response failures, which must keep grouped
/// cache reuse fenced.
#[derive(Debug)]
pub(crate) struct UnsupportedCacheGroups;

impl std::fmt::Display for UnsupportedCacheGroups {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str("external cache handler does not support cache groups")
  }
}

impl std::error::Error for UnsupportedCacheGroups {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalCacheGroupStateMode {
  Read,
  CompareExchange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheGroupStateRequest {
  pub protocol_version: String,
  pub cache_key_version: String,
  pub mode: ExternalCacheGroupStateMode,
  pub key: String,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub expected_base64: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub replacement_base64: Option<String>,
  pub required_capabilities: Vec<String>,
}

impl ExternalCacheGroupStateRequest {
  pub(crate) fn read(key: &str) -> anyhow::Result<Self> {
    validate_key(key)?;
    Ok(Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: crate::cache::key::GROUP_EXTERNAL_CACHE_KEY_VERSION.to_string(),
      mode: ExternalCacheGroupStateMode::Read,
      key: key.to_string(),
      expected_base64: None,
      replacement_base64: None,
      required_capabilities: vec![CACHE_GROUPS_CAPABILITY.to_string()],
    })
  }

  pub(crate) fn compare_exchange(
    key: &str,
    expected: Option<&[u8]>,
    replacement: &[u8],
  ) -> anyhow::Result<Self> {
    validate_key(key)?;
    validate_state("expected cache group state", expected.unwrap_or_default())?;
    validate_state("replacement cache group state", replacement)?;
    Ok(Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: crate::cache::key::GROUP_EXTERNAL_CACHE_KEY_VERSION.to_string(),
      mode: ExternalCacheGroupStateMode::CompareExchange,
      key: key.to_string(),
      expected_base64: expected.map(base64_encode),
      replacement_base64: Some(base64_encode(replacement)),
      required_capabilities: vec![CACHE_GROUPS_CAPABILITY.to_string()],
    })
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheGroupStateResponse {
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub value_base64: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub exchanged: Option<bool>,
  #[serde(default)]
  pub capabilities: Vec<String>,
}

impl ExternalCacheGroupStateResponse {
  pub(crate) fn read_value(&self) -> anyhow::Result<Option<Vec<u8>>> {
    self.validate(ExternalCacheGroupStateMode::Read)?;
    self.value_base64.as_deref().map(base64_decode).transpose()
  }

  pub(crate) fn compare_exchange_outcome(&self) -> anyhow::Result<bool> {
    self.validate(ExternalCacheGroupStateMode::CompareExchange)?;
    self
      .exchanged
      .ok_or_else(|| anyhow!("external cache group compare-exchange response is missing outcome"))
  }

  fn validate(&self, mode: ExternalCacheGroupStateMode) -> anyhow::Result<()> {
    if !self
      .capabilities
      .iter()
      .any(|capability| capability == CACHE_GROUPS_CAPABILITY)
    {
      return Err(UnsupportedCacheGroups.into());
    }
    match mode {
      ExternalCacheGroupStateMode::Read => ensure!(
        self.exchanged.is_none(),
        "external cache group read response carries a compare-exchange outcome"
      ),
      ExternalCacheGroupStateMode::CompareExchange => ensure!(
        self.value_base64.is_none(),
        "external cache group compare-exchange response carries a state value"
      ),
    }
    Ok(())
  }
}

fn validate_key(key: &str) -> anyhow::Result<()> {
  ensure!(
    !key.is_empty() && key.len() <= 256 && !key.bytes().any(|byte| byte.is_ascii_control()),
    "external cache group key is out of bounds"
  );
  Ok(())
}

fn validate_state(name: &str, value: &[u8]) -> anyhow::Result<()> {
  if value.len() > MAX_CACHE_GROUP_STATE_BYTES {
    bail!("{name} exceeds the {MAX_CACHE_GROUP_STATE_BYTES}-byte limit");
  }
  Ok(())
}

fn base64_encode(value: &[u8]) -> String {
  base64::engine::general_purpose::STANDARD.encode(value)
}

fn base64_decode(value: &str) -> anyhow::Result<Vec<u8>> {
  let value = base64::engine::general_purpose::STANDARD
    .decode(value)
    .context("external cache group state is not valid base64")?;
  validate_state("external cache group state", &value)?;
  Ok(value)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn compare_exchange_preserves_absent_and_raw_byte_expectations() {
    let request =
      ExternalCacheGroupStateRequest::compare_exchange("policy-digest", None, b"\0next")
        .expect("request should be bounded");
    assert_eq!(request.mode, ExternalCacheGroupStateMode::CompareExchange);
    assert_eq!(request.expected_base64, None);
    assert_eq!(
      request
        .replacement_base64
        .as_deref()
        .and_then(|value| base64_decode(value).ok()),
      Some(b"\0next".to_vec())
    );
    assert_eq!(request.required_capabilities, vec![CACHE_GROUPS_CAPABILITY]);
  }

  #[test]
  fn responses_require_capability_and_the_matching_shape() {
    let read = ExternalCacheGroupStateResponse {
      value_base64: Some(base64_encode(b"state")),
      exchanged: None,
      capabilities: vec![CACHE_GROUPS_CAPABILITY.to_string()],
    };
    assert_eq!(read.read_value().unwrap(), Some(b"state".to_vec()));
    let unsupported = ExternalCacheGroupStateResponse {
      capabilities: Vec::new(),
      ..read.clone()
    }
    .read_value()
    .expect_err("missing capability must identify a legacy handler");
    assert!(
      unsupported
        .downcast_ref::<UnsupportedCacheGroups>()
        .is_some()
    );
    assert!(
      ExternalCacheGroupStateResponse {
        exchanged: Some(true),
        ..read
      }
      .read_value()
      .is_err()
    );
  }
}
