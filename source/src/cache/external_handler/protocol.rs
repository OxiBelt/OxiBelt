use anyhow::{Context, anyhow, bail};
use base64::Engine;
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

pub(crate) const PROTOCOL_VERSION: &str = "oxibelt-external-cache-v1";
pub(crate) const CACHE_KEY_VERSION: &str = "oxibelt-cache-key-v1";
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
}

impl ExternalCacheEntryMetadata {
  pub(crate) fn validate_versions(&self) -> anyhow::Result<()> {
    if self.protocol_version != PROTOCOL_VERSION {
      bail!("unsupported external cache protocol version");
    }
    if self.cache_key_version != CACHE_KEY_VERSION {
      bail!("unsupported external cache key version");
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
}

impl ExternalCacheLookupRequest {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    policy: String,
    partition: String,
    base_key: String,
    scheme: String,
    host: String,
    uri: String,
    method: String,
    request_no_cache: bool,
  ) -> Self {
    Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: CACHE_KEY_VERSION.to_string(),
      policy,
      partition,
      base_key,
      scheme,
      host,
      uri,
      method,
      request_no_cache,
    }
  }
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
    Self {
      protocol_version: PROTOCOL_VERSION.to_string(),
      cache_key_version: CACHE_KEY_VERSION.to_string(),
      purge_type,
      policy,
      scheme,
      host,
      uri,
      path_prefix,
      tag,
      partition,
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
  metadata.validate_versions()?;
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
  metadata.validate_versions()?;
  Ok(metadata)
}

#[cfg(test)]
mod tests {
  use super::*;

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
    };

    let frame = framed_entry_bytes(&metadata, b"body").expect("frame should encode");
    let len = u64::from_be_bytes(frame[..FRAME_PREFIX_BYTES].try_into().unwrap()) as usize;
    let decoded = parse_metadata(&frame[FRAME_PREFIX_BYTES..FRAME_PREFIX_BYTES + len])
      .expect("metadata should decode");

    assert_eq!(decoded, metadata);
    assert_eq!(&frame[FRAME_PREFIX_BYTES + len..], b"body");
  }
}
