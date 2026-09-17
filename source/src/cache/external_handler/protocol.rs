use anyhow::{Context, anyhow, bail};
use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

pub(crate) const PROTOCOL_VERSION: &str = "oxibelt-external-cache-v1";
pub(crate) const CACHE_KEY_VERSION: &str = "oxibelt-cache-key-v1";
/// Required on every Q1 request, entry, and purge.  Q1 peers that do not
/// preserve this epoch are treated as legacy and their results are bypassed.
pub(crate) const QUERY_EPOCH_CAPABILITY: &str = "query-target-epoch-v1";
/// Required for a bounded, best-effort cleanup of Q1 entries older than a
/// completed target epoch. This is deliberately separate from administrative
/// purges so a handler can constrain the operation to one QUERY target.
pub(crate) const QUERY_CLEANUP_BEFORE_EPOCH_CAPABILITY: &str =
  "query-target-cleanup-before-epoch-v1";
/// Required for entries and authority exchanges that participate in RFC 9875
/// cache-group coherence. Handlers must echo it before their state is trusted.
pub(crate) const CACHE_GROUPS_CAPABILITY: &str = "cache-groups-v1";
pub(crate) const FRAME_PREFIX_BYTES: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheHeader {
  pub name: String,
  pub value_base64: String,
}

impl ExternalCacheHeader {
  pub(crate) fn new(name: String, value: &[u8]) -> Self {
    Self {
      name,
      value_base64: base64::engine::general_purpose::STANDARD.encode(value),
    }
  }

  pub(crate) fn value_bytes(&self) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
      .decode(&self.value_base64)
      .with_context(|| format!("invalid base64 header value for {}", self.name))
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheVary {
  pub name: String,
  pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheEntryMetadata {
  pub protocol_version: String,
  pub cache_key_version: String,
  pub policy: String,
  pub partition: String,
  pub base_key: String,
  pub variant_key: String,
  pub scheme: String,
  pub host: String,
  pub uri: String,
  pub status: u16,
  pub headers: Vec<ExternalCacheHeader>,
  #[serde(default)]
  pub security_headers_neutral: bool,
  pub body_len: usize,
  pub stored_at_ms: i64,
  pub expires_at_ms: i64,
  pub stale_if_error_until_ms: Option<i64>,
  pub stale_while_revalidate_until_ms: Option<i64>,
  pub must_revalidate: bool,
  pub vary: Vec<ExternalCacheVary>,
  pub tags: Vec<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub query_target_epoch: Option<u64>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub no_vary_search: Option<crate::cache::CacheNvsMetadata>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub group_stamp: Option<crate::cache::CacheGroupStamp>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub capabilities: Vec<String>,
}

impl ExternalCacheEntryMetadata {
  pub(crate) fn validate_versions(&self, expected_cache_key_version: &str) -> anyhow::Result<()> {
    if self.protocol_version != PROTOCOL_VERSION {
      bail!("unsupported external cache protocol version");
    }
    if !is_supported_cache_key_version(expected_cache_key_version) {
      bail!("unsupported external cache key version");
    }
    if self.cache_key_version != expected_cache_key_version {
      bail!("unsupported external cache key version");
    }
    if query_epoch_required(expected_cache_key_version) && self.query_target_epoch.is_none() {
      bail!("Q1 external cache metadata is missing its target epoch");
    }
    if cache_groups_required(expected_cache_key_version) {
      if !self
        .capabilities
        .iter()
        .any(|capability| capability == CACHE_GROUPS_CAPABILITY)
      {
        bail!("external cache group metadata is missing its capability");
      }
      if !self
        .group_stamp
        .as_ref()
        .is_some_and(crate::cache::CacheGroupStamp::valid)
      {
        bail!("external cache group metadata is missing a valid stamp");
      }
    } else if self.group_stamp.is_some() {
      bail!("external cache group stamp has an incompatible key version");
    }
    if self
      .no_vary_search
      .as_ref()
      .is_some_and(|metadata| !metadata.valid())
    {
      bail!("external cache No-Vary-Search metadata is invalid");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheLookupRequest {
  pub protocol_version: String,
  pub cache_key_version: String,
  pub policy: String,
  pub partition: String,
  pub base_key: String,
  pub scheme: String,
  pub host: String,
  pub uri: String,
  pub method: String,
  pub request_no_cache: bool,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub query_target_epoch: Option<u64>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub required_capabilities: Vec<String>,
}

/// A typed, target-scoped Q1 epoch exchange.  It is separate from cache
/// lookup so the caller can validate its L1 before accepting a hit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheQueryEpochRequest {
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

impl ExternalCacheQueryEpochRequest {
  pub(crate) fn new(
    policy: String,
    scheme: String,
    host: String,
    uri: String,
    advance: bool,
  ) -> Self {
    let material = format!("{policy}\n{scheme}\n{host}\n{uri}");
    let digest = crate::crypto::sha256(material.as_bytes());
    let epoch_bucket =
      u16::from_be_bytes([digest[0], digest[1]]) % crate::cache::QUERY_EPOCH_BUCKETS;
    Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: super::super::key::QUERY_EXTERNAL_CACHE_KEY_VERSION.to_string(),
      policy,
      scheme,
      host,
      uri,
      advance,
      epoch_bucket,
      required_capabilities: vec![QUERY_EPOCH_CAPABILITY.to_string()],
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheQueryEpochResponse {
  pub target_epoch: u64,
  #[serde(default)]
  pub capabilities: Vec<String>,
}

impl ExternalCacheQueryEpochResponse {
  pub(crate) fn validates_q1(&self) -> bool {
    self
      .capabilities
      .iter()
      .any(|capability| capability == QUERY_EPOCH_CAPABILITY)
  }
}

/// A bounded, best-effort request to reclaim Q1 records older than a completed
/// target epoch. It must never be interpreted as the invalidation fence: the
/// epoch exchange remains authoritative.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheQueryCleanupRequest {
  pub protocol_version: String,
  pub cache_key_version: String,
  pub policy: String,
  pub scheme: String,
  pub host: String,
  pub uri: String,
  pub before_epoch: u64,
  pub limit: usize,
  pub required_capabilities: Vec<String>,
}

impl ExternalCacheQueryCleanupRequest {
  pub(crate) fn new(
    policy: String,
    scheme: String,
    host: String,
    uri: String,
    before_epoch: u64,
    limit: usize,
  ) -> Self {
    Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: super::super::key::QUERY_EXTERNAL_CACHE_KEY_VERSION.to_string(),
      policy,
      scheme,
      host,
      uri,
      before_epoch,
      limit: limit.max(1),
      required_capabilities: vec![
        QUERY_EPOCH_CAPABILITY.to_string(),
        QUERY_CLEANUP_BEFORE_EPOCH_CAPABILITY.to_string(),
      ],
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCacheQueryCleanupResponse {
  pub purged: usize,
  pub complete: bool,
  #[serde(default)]
  pub capabilities: Vec<String>,
}

impl ExternalCacheQueryCleanupResponse {
  pub(crate) fn validates_q1_cleanup(&self, limit: usize) -> bool {
    self.purged <= limit
      && self
        .capabilities
        .iter()
        .any(|capability| capability == QUERY_EPOCH_CAPABILITY)
      && self
        .capabilities
        .iter()
        .any(|capability| capability == QUERY_CLEANUP_BEFORE_EPOCH_CAPABILITY)
  }
}

impl ExternalCacheLookupRequest {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    cache_key_version: String,
    policy: String,
    partition: String,
    base_key: String,
    scheme: String,
    host: String,
    uri: String,
    method: String,
    request_no_cache: bool,
    query_target_epoch: Option<u64>,
  ) -> Self {
    let required_capabilities =
      required_capabilities_for_cache_key_version(&cache_key_version, query_target_epoch.is_some());
    Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version,
      policy,
      partition,
      base_key,
      scheme,
      host,
      uri,
      method,
      request_no_cache,
      query_target_epoch,
      required_capabilities,
    }
  }
}

pub(crate) fn required_capabilities_for_cache_key_version(
  cache_key_version: &str,
  query_target_epoch: bool,
) -> Vec<String> {
  let mut capabilities = Vec::new();
  if query_target_epoch {
    capabilities.push(QUERY_EPOCH_CAPABILITY.to_string());
  }
  if cache_groups_required(cache_key_version) {
    capabilities.push(CACHE_GROUPS_CAPABILITY.to_string());
  }
  capabilities
}

fn is_supported_cache_key_version(cache_key_version: &str) -> bool {
  matches!(
    cache_key_version,
    CACHE_KEY_VERSION
      | super::super::key::QUERY_EXTERNAL_CACHE_KEY_VERSION
      | super::super::key::GROUP_EXTERNAL_CACHE_KEY_VERSION
      | super::super::key::GROUP_QUERY_EXTERNAL_CACHE_KEY_VERSION
  )
}

fn query_epoch_required(cache_key_version: &str) -> bool {
  matches!(
    cache_key_version,
    super::super::key::QUERY_EXTERNAL_CACHE_KEY_VERSION
      | super::super::key::GROUP_QUERY_EXTERNAL_CACHE_KEY_VERSION
  )
}

pub(crate) fn cache_groups_required(cache_key_version: &str) -> bool {
  matches!(
    cache_key_version,
    super::super::key::GROUP_EXTERNAL_CACHE_KEY_VERSION
      | super::super::key::GROUP_QUERY_EXTERNAL_CACHE_KEY_VERSION
  )
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalCachePurgeKind {
  Exact,
  Prefix,
  Tag,
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCachePurgeRequest {
  pub protocol_version: String,
  pub cache_key_version: String,
  pub purge_type: ExternalCachePurgeKind,
  pub policy: String,
  pub scheme: Option<String>,
  pub host: Option<String>,
  pub uri: Option<String>,
  pub path_prefix: Option<String>,
  pub tag: Option<String>,
  pub partition: Option<String>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub query_target_epoch: Option<u64>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub required_capabilities: Vec<String>,
}

#[cfg(feature = "admin-runtime")]
impl ExternalCachePurgeRequest {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    purge_type: ExternalCachePurgeKind,
    policy: String,
    scheme: Option<String>,
    host: Option<String>,
    uri: Option<String>,
    path_prefix: Option<String>,
    tag: Option<String>,
    partition: Option<String>,
  ) -> Self {
    Self::with_cache_key_version(
      CACHE_KEY_VERSION.to_string(),
      purge_type,
      policy,
      scheme,
      host,
      uri,
      path_prefix,
      tag,
      partition,
      None,
    )
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) fn with_cache_key_version(
    cache_key_version: String,
    purge_type: ExternalCachePurgeKind,
    policy: String,
    scheme: Option<String>,
    host: Option<String>,
    uri: Option<String>,
    path_prefix: Option<String>,
    tag: Option<String>,
    partition: Option<String>,
    query_target_epoch: Option<u64>,
  ) -> Self {
    Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version,
      purge_type,
      policy,
      scheme,
      host,
      uri,
      path_prefix,
      tag,
      partition,
      query_target_epoch,
      required_capabilities: query_target_epoch
        .map(|_| vec![QUERY_EPOCH_CAPABILITY.to_string()])
        .unwrap_or_default(),
    }
  }
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalCachePurgeResponse {
  #[serde(default)]
  pub purged: Option<usize>,
}

pub(crate) enum ExternalCacheBody {
  Memory(Bytes),
  TemporaryFile(NamedTempFile),
}

pub(crate) fn serialize_metadata(metadata: &ExternalCacheEntryMetadata) -> anyhow::Result<Vec<u8>> {
  metadata.validate_versions(&metadata.cache_key_version)?;
  serde_json::to_vec(metadata).context("failed to serialize external cache metadata")
}

pub(crate) fn external_cache_metadata_frame(
  metadata: &ExternalCacheEntryMetadata,
) -> anyhow::Result<Bytes> {
  let metadata = serialize_metadata(metadata)?;
  let mut frame = BytesMut::with_capacity(FRAME_PREFIX_BYTES + metadata.len());
  frame.put_u64(metadata.len() as u64);
  frame.extend_from_slice(&metadata);
  Ok(frame.freeze())
}

#[cfg(test)]
pub(crate) fn framed_entry_bytes(
  metadata: &ExternalCacheEntryMetadata,
  body: &[u8],
) -> anyhow::Result<Bytes> {
  if metadata.body_len != body.len() {
    bail!("external cache frame body length mismatch");
  }
  let metadata_frame = external_cache_metadata_frame(metadata)?;
  let mut frame = BytesMut::with_capacity(metadata_frame.len() + body.len());
  frame.extend_from_slice(&metadata_frame);
  frame.extend_from_slice(body);
  Ok(frame.freeze())
}

pub(crate) fn parse_metadata(bytes: &[u8]) -> anyhow::Result<ExternalCacheEntryMetadata> {
  let metadata = serde_json::from_slice::<ExternalCacheEntryMetadata>(bytes)
    .map_err(|error| anyhow!("external cache metadata is not valid JSON: {error}"))?;
  metadata.validate_versions(&metadata.cache_key_version)?;
  Ok(metadata)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn legacy_get_lookup_omits_q1_fields() {
    let request = ExternalCacheLookupRequest::new(
      CACHE_KEY_VERSION.to_string(),
      "default".to_string(),
      String::new(),
      "https://example.test/asset".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      "/asset".to_string(),
      "GET".to_string(),
      false,
      None,
    );
    let value = serde_json::to_value(request).expect("GET lookup should serialize");
    assert!(value.get("query_target_epoch").is_none());
    assert!(value.get("required_capabilities").is_none());
  }

  #[test]
  fn group_lookup_requires_its_capability() {
    let request = ExternalCacheLookupRequest::new(
      crate::cache::key::GROUP_EXTERNAL_CACHE_KEY_VERSION.to_string(),
      "default".to_string(),
      String::new(),
      "\0oxibelt-cache-groups-v1\0fixture".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      "/asset".to_string(),
      "GET".to_string(),
      false,
      None,
    );
    assert_eq!(
      request.required_capabilities,
      vec![CACHE_GROUPS_CAPABILITY.to_string()]
    );
  }

  #[test]
  fn query_epoch_request_binds_target_bucket_and_capability() {
    let request = ExternalCacheQueryEpochRequest::new(
      "default".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      "/asset".to_string(),
      true,
    );
    let digest = crate::crypto::sha256(b"default\nhttps\nexample.test\n/asset");
    assert_eq!(
      request.epoch_bucket,
      u16::from_be_bytes([digest[0], digest[1]]) % crate::cache::QUERY_EPOCH_BUCKETS
    );
    assert!(request.advance);
    assert_eq!(
      request.required_capabilities,
      vec![QUERY_EPOCH_CAPABILITY.to_string()]
    );
    let value = serde_json::to_value(request).expect("QUERY epoch request should serialize");
    assert_eq!(
      value["cache_key_version"],
      crate::cache::key::QUERY_EXTERNAL_CACHE_KEY_VERSION
    );
    assert_eq!(value["required_capabilities"][0], QUERY_EPOCH_CAPABILITY);
  }

  #[test]
  fn query_epoch_response_requires_capability() {
    assert!(
      !ExternalCacheQueryEpochResponse {
        target_epoch: 7,
        capabilities: Vec::new(),
      }
      .validates_q1()
    );
    assert!(
      ExternalCacheQueryEpochResponse {
        target_epoch: 7,
        capabilities: vec![QUERY_EPOCH_CAPABILITY.to_string()],
      }
      .validates_q1()
    );
  }

  #[test]
  fn query_cleanup_request_is_q1_scoped_and_bounded() {
    let request = ExternalCacheQueryCleanupRequest::new(
      "default".to_string(),
      "https".to_string(),
      "example.test".to_string(),
      "/asset".to_string(),
      7,
      0,
    );
    assert_eq!(
      request.cache_key_version,
      crate::cache::key::QUERY_EXTERNAL_CACHE_KEY_VERSION
    );
    assert_eq!(request.before_epoch, 7);
    assert_eq!(request.limit, 1);
    assert_eq!(
      request.required_capabilities,
      vec![
        QUERY_EPOCH_CAPABILITY.to_string(),
        QUERY_CLEANUP_BEFORE_EPOCH_CAPABILITY.to_string(),
      ]
    );
  }

  #[test]
  fn query_cleanup_response_requires_capabilities_and_a_bounded_count() {
    let complete = ExternalCacheQueryCleanupResponse {
      purged: 3,
      complete: true,
      capabilities: vec![
        QUERY_EPOCH_CAPABILITY.to_string(),
        QUERY_CLEANUP_BEFORE_EPOCH_CAPABILITY.to_string(),
      ],
    };
    assert!(complete.validates_q1_cleanup(3));

    let partial_without_progress = ExternalCacheQueryCleanupResponse {
      purged: 0,
      complete: false,
      ..complete.clone()
    };
    assert!(partial_without_progress.validates_q1_cleanup(3));

    let missing_capability = ExternalCacheQueryCleanupResponse {
      capabilities: vec![QUERY_EPOCH_CAPABILITY.to_string()],
      ..complete.clone()
    };
    assert!(!missing_capability.validates_q1_cleanup(3));

    let oversized_count = ExternalCacheQueryCleanupResponse {
      purged: 4,
      ..complete
    };
    assert!(!oversized_count.validates_q1_cleanup(3));
  }

  #[test]
  fn q1_metadata_without_epoch_is_rejected() {
    let metadata = ExternalCacheEntryMetadata {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: crate::cache::key::QUERY_EXTERNAL_CACHE_KEY_VERSION.to_string(),
      policy: "default".to_string(),
      partition: String::new(),
      base_key: "\0oxibelt-cache-query-v1\0fixture".to_string(),
      variant_key: "fixture".to_string(),
      scheme: "https".to_string(),
      host: "example.test".to_string(),
      uri: "/asset".to_string(),
      status: 200,
      headers: Vec::new(),
      security_headers_neutral: true,
      body_len: 0,
      stored_at_ms: 1,
      expires_at_ms: 2,
      stale_if_error_until_ms: None,
      stale_while_revalidate_until_ms: None,
      must_revalidate: false,
      vary: Vec::new(),
      tags: Vec::new(),
      query_target_epoch: None,
      no_vary_search: None,
      group_stamp: None,
      capabilities: Vec::new(),
    };
    assert!(
      metadata
        .validate_versions(crate::cache::key::QUERY_EXTERNAL_CACHE_KEY_VERSION)
        .is_err()
    );
  }

  #[test]
  fn framed_entry_round_trips_metadata_and_body() {
    let metadata = ExternalCacheEntryMetadata {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: CACHE_KEY_VERSION.to_string(),
      policy: "default".to_string(),
      partition: String::new(),
      base_key: "https:example.test:/asset".to_string(),
      variant_key: "partition=\nhttps:example.test:/asset".to_string(),
      scheme: "https".to_string(),
      host: "example.test".to_string(),
      uri: "/asset".to_string(),
      status: 200,
      headers: vec![ExternalCacheHeader::new(
        "content-type".to_string(),
        b"text/plain",
      )],
      security_headers_neutral: true,
      body_len: 4,
      stored_at_ms: 1,
      expires_at_ms: 2,
      stale_if_error_until_ms: None,
      stale_while_revalidate_until_ms: None,
      must_revalidate: false,
      vary: Vec::new(),
      tags: vec!["tag".to_string()],
      query_target_epoch: None,
      no_vary_search: None,
      group_stamp: None,
      capabilities: Vec::new(),
    };

    let frame = framed_entry_bytes(&metadata, b"body").expect("frame should encode");
    let len = u64::from_be_bytes(frame[..FRAME_PREFIX_BYTES].try_into().unwrap()) as usize;
    let decoded = parse_metadata(&frame[FRAME_PREFIX_BYTES..FRAME_PREFIX_BYTES + len])
      .expect("metadata should decode");

    assert_eq!(decoded, metadata);
    assert_eq!(&frame[FRAME_PREFIX_BYTES + len..], b"body");
  }

  #[test]
  fn group_metadata_requires_its_key_version_stamp_and_capability() {
    let stamp = crate::cache::CacheGroupStamp {
      policy: "default".to_string(),
      origin: crate::cache::CacheGroupOrigin::new("https", "example.test").unwrap(),
      partition: String::new(),
      incarnation: "a".repeat(64),
      sequence: 0,
      target: "/asset".to_string(),
      groups: Vec::new(),
      tags: Vec::new(),
      equivalent_path: None,
    };
    let metadata = ExternalCacheEntryMetadata {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: crate::cache::key::GROUP_EXTERNAL_CACHE_KEY_VERSION.to_string(),
      policy: "default".to_string(),
      partition: String::new(),
      base_key: "\0oxibelt-cache-groups-v1\0fixture".to_string(),
      variant_key: "fixture".to_string(),
      scheme: "https".to_string(),
      host: "example.test".to_string(),
      uri: "/asset".to_string(),
      status: 200,
      headers: Vec::new(),
      security_headers_neutral: true,
      body_len: 0,
      stored_at_ms: 1,
      expires_at_ms: 2,
      stale_if_error_until_ms: None,
      stale_while_revalidate_until_ms: None,
      must_revalidate: false,
      vary: Vec::new(),
      tags: Vec::new(),
      query_target_epoch: None,
      no_vary_search: None,
      group_stamp: Some(stamp),
      capabilities: vec![CACHE_GROUPS_CAPABILITY.to_string()],
    };
    assert!(
      metadata
        .validate_versions(crate::cache::key::GROUP_EXTERNAL_CACHE_KEY_VERSION)
        .is_ok()
    );
    let mut absolute_stamp = metadata.clone();
    absolute_stamp.group_stamp.as_mut().unwrap().target = "https://example.test/asset".to_string();
    assert!(
      absolute_stamp
        .validate_versions(crate::cache::key::GROUP_EXTERNAL_CACHE_KEY_VERSION)
        .is_err()
    );
    assert!(
      ExternalCacheEntryMetadata {
        capabilities: Vec::new(),
        ..metadata.clone()
      }
      .validate_versions(crate::cache::key::GROUP_EXTERNAL_CACHE_KEY_VERSION)
      .is_err()
    );
    assert!(
      ExternalCacheEntryMetadata {
        group_stamp: None,
        ..metadata
      }
      .validate_versions(crate::cache::key::GROUP_EXTERNAL_CACHE_KEY_VERSION)
      .is_err()
    );
  }
}
