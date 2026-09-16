//! No-Vary-Search extension messages for external cache handlers.

use serde::{Deserialize, Serialize};

use crate::cache::CacheNvsCandidate;

use super::protocol::{CACHE_KEY_VERSION, PROTOCOL_VERSION};

/// Opt-in capability for response-owned No-Vary-Search discovery and fences.
/// Handlers without it retain established exact-cache behavior.
pub(crate) const NO_VARY_SEARCH_CAPABILITY: &str = "no-vary-search-v1";

/// A target-scoped epoch exchange for No-Vary-Search alias fences. It uses
/// the existing bucket construction but a separate capability so legacy L3
/// handlers cannot accidentally authorize aliases.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheNvsEpochRequest {
  pub protocol_version: String,
  pub cache_key_version: String,
  pub policy: String,
  pub scheme: String,
  pub host: String,
  pub uri: String,
  pub advance: bool,
  pub epoch_bucket: u16,
  pub required_capabilities: Vec<String>,
}

impl ExternalCacheNvsEpochRequest {
  pub(crate) fn new(
    policy: String,
    scheme: String,
    host: String,
    uri: String,
    advance: bool,
  ) -> Self {
    let material = format!("{policy}\n{scheme}\n{host}\n{uri}");
    let digest = crate::crypto::sha256(material.as_bytes());
    Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: CACHE_KEY_VERSION.to_string(),
      policy,
      scheme,
      host,
      uri,
      advance,
      epoch_bucket: u16::from_be_bytes([digest[0], digest[1]]) % crate::cache::QUERY_EPOCH_BUCKETS,
      required_capabilities: vec![NO_VARY_SEARCH_CAPABILITY.to_string()],
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheNvsEpochResponse {
  pub target_epoch: u64,
  #[serde(default)]
  pub capabilities: Vec<String>,
}

impl ExternalCacheNvsEpochResponse {
  pub(crate) fn validates_nvs(&self) -> bool {
    self
      .capabilities
      .iter()
      .any(|item| item == NO_VARY_SEARCH_CAPABILITY)
  }
}

/// Bounded secondary discovery. A returned candidate is never a hit by
/// itself: OxiBelt reloads its exact owner and checks byte-for-byte evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheNvsCandidatesRequest {
  pub protocol_version: String,
  pub cache_key_version: String,
  pub policy: String,
  pub scope: String,
  pub limit: usize,
  pub required_capabilities: Vec<String>,
}

impl ExternalCacheNvsCandidatesRequest {
  pub(crate) fn new(policy: String, scope: String, limit: usize) -> Self {
    Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: CACHE_KEY_VERSION.to_string(),
      policy,
      scope,
      limit: limit.clamp(1, 1024),
      required_capabilities: vec![NO_VARY_SEARCH_CAPABILITY.to_string()],
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExternalCacheNvsCandidatesResponse {
  #[serde(default)]
  pub candidates: Vec<CacheNvsCandidate>,
  #[serde(default)]
  pub capabilities: Vec<String>,
}

impl ExternalCacheNvsCandidatesResponse {
  pub(crate) fn validates_nvs(&self, scope: &str, limit: usize) -> bool {
    self.candidates.len() <= limit
      && self
        .capabilities
        .iter()
        .any(|item| item == NO_VARY_SEARCH_CAPABILITY)
      && self.candidates.iter().all(|candidate| {
        candidate.metadata.valid()
          && candidate.metadata.scope == scope
          && candidate.fields.len() <= 2048
          && candidate
            .fields
            .iter()
            .try_fold(0usize, |size, field| {
              size.checked_add(field.len().checked_add(2)?)
            })
            .is_some_and(|size| size <= 4096)
      })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn epoch_and_candidate_requests_require_the_new_capability() {
    let epoch = ExternalCacheNvsEpochRequest::new(
      "default".to_string(),
      "nvs-v1:https".to_string(),
      "example.test".to_string(),
      "/asset".to_string(),
      true,
    );
    assert_eq!(epoch.cache_key_version, CACHE_KEY_VERSION);
    assert_eq!(
      epoch.required_capabilities,
      vec![NO_VARY_SEARCH_CAPABILITY.to_string()]
    );
    assert!(
      ExternalCacheNvsEpochResponse {
        target_epoch: 1,
        capabilities: vec![NO_VARY_SEARCH_CAPABILITY.to_string()],
      }
      .validates_nvs()
    );

    let candidates =
      ExternalCacheNvsCandidatesRequest::new("default".to_string(), "a".repeat(64), usize::MAX);
    assert_eq!(candidates.limit, 1024);
    assert_eq!(
      candidates.required_capabilities,
      vec![NO_VARY_SEARCH_CAPABILITY.to_string()]
    );
  }

  #[test]
  fn candidates_require_capability_scope_and_bounded_field_evidence() {
    let candidate = CacheNvsCandidate {
      metadata: crate::cache::CacheNvsMetadata {
        version: 1,
        scope: "a".repeat(64),
        owner_uri: "/owner?ignored=one".to_string(),
        effective_uri: "https://origin.test/owner?ignored=one".to_string(),
        epoch: 0,
        policy_epoch: 0,
        candidate_limit: 2,
      },
      fields: vec![b"params=(\"ignored\")".to_vec()],
      date_ms: 1,
    };
    let response = ExternalCacheNvsCandidatesResponse {
      candidates: vec![candidate.clone()],
      capabilities: vec![NO_VARY_SEARCH_CAPABILITY.to_string()],
    };
    assert!(response.validates_nvs(&"a".repeat(64), 2));
    assert!(!response.validates_nvs(&"b".repeat(64), 2));
    assert!(
      !ExternalCacheNvsCandidatesResponse {
        capabilities: Vec::new(),
        ..response.clone()
      }
      .validates_nvs(&"a".repeat(64), 2)
    );
    assert!(
      !ExternalCacheNvsCandidatesResponse {
        candidates: vec![candidate.clone(), candidate],
        ..response
      }
      .validates_nvs(&"a".repeat(64), 1)
    );
  }
}
