use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use http::{HeaderMap, Method};
use ring::{digest, hmac};

use crate::config::AdminCachePurgeSigningConfig;

const SIGNING_VERSION: &str = "OXIBELT-CACHE-PURGE-V1";
const TIMESTAMP_HEADER: &str = "x-oxibelt-cache-timestamp";
const NONCE_HEADER: &str = "x-oxibelt-cache-nonce";
const SIGNATURE_HEADER: &str = "x-oxibelt-cache-signature";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedCachePurgeSignature {
  pub nonce: String,
  pub timestamp_unix_seconds: u64,
}

pub fn verify_cache_purge_signature(
  headers: &HeaderMap,
  method: &Method,
  path_and_query: &str,
  body: &[u8],
  config: &AdminCachePurgeSigningConfig,
  now: SystemTime,
) -> anyhow::Result<VerifiedCachePurgeSignature> {
  if !config.enabled {
    bail!("cache purge signing is disabled");
  }
  let timestamp = header_str(headers, TIMESTAMP_HEADER)?
    .parse::<u64>()
    .context("invalid cache purge signature timestamp")?;
  validate_timestamp(timestamp, config.max_skew_seconds, now)?;
  let nonce = header_str(headers, NONCE_HEADER)?.to_string();
  if nonce.is_empty() || nonce.len() > 128 || nonce.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("invalid cache purge signature nonce");
  }
  let key_bytes = signing_key_bytes(config)?;
  verify_cache_purge_signature_with_key_bytes(
    headers,
    method,
    path_and_query,
    body,
    &key_bytes,
    config.max_skew_seconds,
    now,
  )
}

fn verify_cache_purge_signature_with_key_bytes(
  headers: &HeaderMap,
  method: &Method,
  path_and_query: &str,
  body: &[u8],
  key_bytes: &[u8],
  max_skew_seconds: u64,
  now: SystemTime,
) -> anyhow::Result<VerifiedCachePurgeSignature> {
  if key_bytes.len() != 32 {
    bail!("cache purge signing key must contain exactly 32 bytes");
  }
  let timestamp = header_str(headers, TIMESTAMP_HEADER)?
    .parse::<u64>()
    .context("invalid cache purge signature timestamp")?;
  validate_timestamp(timestamp, max_skew_seconds, now)?;
  let nonce = header_str(headers, NONCE_HEADER)?.to_string();
  if nonce.is_empty() || nonce.len() > 128 || nonce.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("invalid cache purge signature nonce");
  }
  let signature = base64::engine::general_purpose::STANDARD
    .decode(header_str(headers, SIGNATURE_HEADER)?.trim())
    .context("invalid cache purge signature encoding")?;
  let key = hmac::Key::new(hmac::HMAC_SHA256, key_bytes);
  let canonical = canonical_message(method, path_and_query, body, timestamp, &nonce);
  hmac::verify(&key, canonical.as_bytes(), &signature)
    .map_err(|_| anyhow!("cache purge signature mismatch"))?;
  Ok(VerifiedCachePurgeSignature {
    nonce,
    timestamp_unix_seconds: timestamp,
  })
}

pub fn canonical_message(
  method: &Method,
  path_and_query: &str,
  body: &[u8],
  timestamp: u64,
  nonce: &str,
) -> String {
  let body_hash = digest::digest(&digest::SHA256, body);
  format!(
    "{SIGNING_VERSION}\n{}\n{}\n{}\n{}\n{}",
    method.as_str(),
    path_and_query,
    hex(body_hash.as_ref()),
    timestamp,
    nonce
  )
}

fn signing_key_bytes(config: &AdminCachePurgeSigningConfig) -> anyhow::Result<Vec<u8>> {
  let raw = std::env::var(&config.key_env).with_context(|| {
    format!(
      "failed to read admin.cache_purge_signing.key_env {}",
      config.key_env
    )
  })?;
  let bytes = base64::engine::general_purpose::STANDARD
    .decode(raw.trim())
    .context("admin.cache_purge_signing.key_env must contain base64")?;
  if bytes.len() != 32 {
    bail!("admin.cache_purge_signing.key_env must contain exactly 32 bytes");
  }
  Ok(bytes)
}

fn validate_timestamp(
  timestamp: u64,
  max_skew_seconds: u64,
  now: SystemTime,
) -> anyhow::Result<()> {
  let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
  let skew = timestamp.abs_diff(now);
  if skew > max_skew_seconds {
    bail!("cache purge signature timestamp is outside the allowed skew");
  }
  Ok(())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> anyhow::Result<&'a str> {
  headers
    .get(name)
    .ok_or_else(|| anyhow!("missing {name}"))?
    .to_str()
    .with_context(|| format!("{name} is not valid ASCII"))
}

fn hex(bytes: &[u8]) -> String {
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    use std::fmt::Write;
    let _ = write!(&mut output, "{byte:02x}");
  }
  output
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::HeaderValue;
  use std::time::Duration;

  #[test]
  fn verifies_valid_cache_purge_signature() {
    let key = [7u8; 32];
    let timestamp = 1_700_000_000;
    let nonce = "nonce-1";
    let method = Method::POST;
    let path = "/cache/purge?policy=default";
    let body = b"";
    let canonical = canonical_message(&method, path, body, timestamp, nonce);
    let signature = hmac::sign(
      &hmac::Key::new(hmac::HMAC_SHA256, &key),
      canonical.as_bytes(),
    );
    let mut headers = HeaderMap::new();
    headers.insert(TIMESTAMP_HEADER, HeaderValue::from_static("1700000000"));
    headers.insert(NONCE_HEADER, HeaderValue::from_static(nonce));
    headers.insert(
      SIGNATURE_HEADER,
      HeaderValue::from_str(&base64::engine::general_purpose::STANDARD.encode(signature.as_ref()))
        .unwrap(),
    );

    let verified = verify_cache_purge_signature_with_key_bytes(
      &headers,
      &method,
      path,
      body,
      &key,
      300,
      UNIX_EPOCH + Duration::from_secs(timestamp),
    )
    .unwrap();

    assert_eq!(verified.nonce, nonce);
  }
}
