//! Canonical, threshold-signed accepted-root snapshots.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::Engine as _;
use der::Decode as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;

const ROOT_BUNDLE_SCHEMA_VERSION: u32 = 1;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAX_ROOTS: usize = 4096;
const MAX_SIGNATURES: usize = 32;
const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct AcceptedRootTrust {
  pub threshold: usize,
  pub production: bool,
  pub keys: BTreeMap<String, [u8; ED25519_PUBLIC_KEY_BYTES]>,
}

#[derive(Clone, Debug)]
pub struct AcceptedRoot {
  pub der: Vec<u8>,
  pub sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct AcceptedRootBundle {
  pub snapshot_id: String,
  pub serial: u64,
  pub created_at_unix_seconds: i64,
  pub roots: Vec<AcceptedRoot>,
  pub digest: [u8; 32],
  pub verified_signers: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootBundleDocument {
  schema_version: u32,
  snapshot_id: String,
  serial: u64,
  created_at_unix_seconds: i64,
  roots: Vec<RootDocument>,
  signatures: Vec<RootSignatureDocument>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootDocument {
  sha256: String,
  der_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootSignatureDocument {
  key_id: String,
  algorithm: String,
  value_base64: String,
}

#[derive(Serialize)]
struct UnsignedRootBundleDocument<'a> {
  schema_version: u32,
  snapshot_id: &'a str,
  serial: u64,
  created_at_unix_seconds: i64,
  roots: &'a [RootDocument],
}

pub fn load_verified_root_bundle(
  path: &Path,
  expected_digest: &str,
  trust: &AcceptedRootTrust,
) -> anyhow::Result<AcceptedRootBundle> {
  validate_trust(trust)?;
  let bytes = std::fs::read(path)
    .with_context(|| format!("failed to read CT accepted-root bundle {}", path.display()))?;
  if bytes.len() > MAX_BUNDLE_BYTES {
    bail!("CT accepted-root bundle exceeds {MAX_BUNDLE_BYTES} bytes");
  }
  let digest: [u8; 32] = Sha256::digest(&bytes).into();
  let expected_digest = parse_sha256(expected_digest, "accepted-root bundle digest")?;
  if digest != expected_digest {
    bail!("CT accepted-root bundle digest mismatch");
  }

  let document: RootBundleDocument =
    serde_json::from_slice(&bytes).context("failed to parse CT accepted-root bundle")?;
  validate_document_shape(&document)?;
  let canonical_document = canonical_json_bytes(
    &serde_json::to_value(&document).context("failed to encode CT accepted-root bundle")?,
  )?;
  if bytes != canonical_document {
    bail!("CT accepted-root bundle must use canonical JSON without trailing bytes");
  }

  let unsigned = UnsignedRootBundleDocument {
    schema_version: document.schema_version,
    snapshot_id: &document.snapshot_id,
    serial: document.serial,
    created_at_unix_seconds: document.created_at_unix_seconds,
    roots: &document.roots,
  };
  let signed_bytes = canonical_json_bytes(
    &serde_json::to_value(unsigned).context("failed to encode CT root signature payload")?,
  )?;
  let verified_signers = verify_signatures(&document.signatures, &signed_bytes, trust)?;
  let roots = decode_roots(document.roots)?;

  Ok(AcceptedRootBundle {
    snapshot_id: document.snapshot_id,
    serial: document.serial,
    created_at_unix_seconds: document.created_at_unix_seconds,
    roots,
    digest,
    verified_signers,
  })
}

fn validate_trust(trust: &AcceptedRootTrust) -> anyhow::Result<()> {
  if trust.threshold == 0 || trust.threshold > trust.keys.len() {
    bail!("CT accepted-root signature threshold is outside the trusted key set");
  }
  if trust.production && trust.threshold < 2 {
    bail!("production CT accepted-root bundles require at least two signatures");
  }
  if trust.keys.len() > MAX_SIGNATURES {
    bail!("CT accepted-root trusted key set exceeds {MAX_SIGNATURES} keys");
  }
  for key_id in trust.keys.keys() {
    validate_identifier(key_id, "accepted-root key id")?;
  }
  Ok(())
}

fn validate_document_shape(document: &RootBundleDocument) -> anyhow::Result<()> {
  if document.schema_version != ROOT_BUNDLE_SCHEMA_VERSION {
    bail!(
      "unsupported CT accepted-root bundle schema version {}",
      document.schema_version
    );
  }
  validate_identifier(&document.snapshot_id, "accepted-root snapshot id")?;
  if document.serial == 0 {
    bail!("CT accepted-root bundle serial must be greater than zero");
  }
  if document.roots.is_empty() || document.roots.len() > MAX_ROOTS {
    bail!("CT accepted-root bundle root count is outside 1..={MAX_ROOTS}");
  }
  if document.signatures.is_empty() || document.signatures.len() > MAX_SIGNATURES {
    bail!("CT accepted-root bundle signature count is outside 1..={MAX_SIGNATURES}");
  }
  ensure_strictly_sorted_unique(
    document.roots.iter().map(|root| root.sha256.as_str()),
    "root fingerprints",
  )?;
  ensure_strictly_sorted_unique(
    document
      .signatures
      .iter()
      .map(|signature| signature.key_id.as_str()),
    "signature key ids",
  )?;
  Ok(())
}

fn verify_signatures(
  signatures: &[RootSignatureDocument],
  signed_bytes: &[u8],
  trust: &AcceptedRootTrust,
) -> anyhow::Result<Vec<String>> {
  let mut verified = Vec::new();
  for signature in signatures {
    validate_identifier(&signature.key_id, "accepted-root signature key id")?;
    if signature.algorithm != "ed25519" {
      bail!("CT accepted-root signature algorithm must be ed25519");
    }
    let Some(public_key) = trust.keys.get(&signature.key_id) else {
      continue;
    };
    let value = base64::engine::general_purpose::STANDARD
      .decode(&signature.value_base64)
      .context("failed to decode CT accepted-root signature")?;
    if value.len() != ED25519_SIGNATURE_BYTES {
      bail!("CT accepted-root Ed25519 signature must be 64 bytes");
    }
    UnparsedPublicKey::new(&ED25519, public_key)
      .verify(signed_bytes, &value)
      .map_err(|_| {
        anyhow!(
          "invalid CT accepted-root signature for {}",
          signature.key_id
        )
      })?;
    verified.push(signature.key_id.clone());
  }
  if verified.len() < trust.threshold {
    bail!(
      "CT accepted-root bundle has {} trusted signatures but requires {}",
      verified.len(),
      trust.threshold
    );
  }
  Ok(verified)
}

fn decode_roots(documents: Vec<RootDocument>) -> anyhow::Result<Vec<AcceptedRoot>> {
  let mut roots = Vec::with_capacity(documents.len());
  for document in documents {
    let expected = parse_sha256(&document.sha256, "accepted-root fingerprint")?;
    let der = base64::engine::general_purpose::STANDARD
      .decode(&document.der_base64)
      .context("failed to decode accepted-root DER")?;
    if der.is_empty() || der.len() > 1024 * 1024 {
      bail!("CT accepted-root DER length is outside 1..=1048576");
    }
    Certificate::from_der(&der).context("failed to parse accepted-root DER")?;
    let actual: [u8; 32] = Sha256::digest(&der).into();
    if actual != expected {
      bail!("CT accepted-root fingerprint does not match its DER certificate");
    }
    roots.push(AcceptedRoot {
      der,
      sha256: actual,
    });
  }
  Ok(roots)
}

fn validate_identifier(value: &str, label: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value.len() > 128
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
  {
    bail!("CT {label} is not a bounded portable identifier");
  }
  Ok(())
}

fn ensure_strictly_sorted_unique<'a>(
  values: impl Iterator<Item = &'a str>,
  label: &str,
) -> anyhow::Result<()> {
  let mut previous: Option<&str> = None;
  for value in values {
    if previous.is_some_and(|previous| previous >= value) {
      bail!("CT accepted-root bundle {label} must be strictly sorted and unique");
    }
    previous = Some(value);
  }
  Ok(())
}

fn parse_sha256(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
  let Some(hex) = value.strip_prefix("sha256:") else {
    bail!("CT {label} must use sha256:<lowercase-hex>");
  };
  if hex.len() != 64
    || !hex
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    bail!("CT {label} must use 64 lowercase hexadecimal characters");
  }
  let mut digest = [0_u8; 32];
  for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
    let pair = std::str::from_utf8(chunk).context("invalid CT digest encoding")?;
    digest[index] = u8::from_str_radix(pair, 16).context("invalid CT digest encoding")?;
  }
  Ok(digest)
}

fn canonical_json_bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
  let mut output = Vec::new();
  write_canonical_json(value, &mut output)?;
  Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> anyhow::Result<()> {
  match value {
    Value::Null => output.extend_from_slice(b"null"),
    Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
    Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
    Value::String(value) => {
      serde_json::to_writer(output, value).context("failed to encode canonical JSON string")?;
    }
    Value::Array(values) => {
      output.push(b'[');
      for (index, value) in values.iter().enumerate() {
        if index != 0 {
          output.push(b',');
        }
        write_canonical_json(value, output)?;
      }
      output.push(b']');
    }
    Value::Object(values) => {
      output.push(b'{');
      let mut keys = values.keys().collect::<Vec<_>>();
      keys.sort_unstable();
      for (index, key) in keys.into_iter().enumerate() {
        if index != 0 {
          output.push(b',');
        }
        serde_json::to_writer(&mut *output, key).context("failed to encode canonical JSON key")?;
        output.push(b':');
        write_canonical_json(&values[key], output)?;
      }
      output.push(b'}');
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn digest_parser_requires_canonical_lowercase_sha256() {
    assert!(parse_sha256(&format!("sha256:{}", "a".repeat(64)), "test").is_ok());
    assert!(parse_sha256(&format!("sha256:{}", "A".repeat(64)), "test").is_err());
    assert!(parse_sha256(&"a".repeat(64), "test").is_err());
  }

  #[test]
  fn canonical_json_sorts_nested_object_keys() {
    let value = serde_json::json!({"z": 1, "a": {"d": 4, "b": 2}});
    assert_eq!(
      canonical_json_bytes(&value).unwrap(),
      br#"{"a":{"b":2,"d":4},"z":1}"#
    );
  }

  #[test]
  fn production_trust_requires_two_signatures() {
    let trust = AcceptedRootTrust {
      threshold: 1,
      production: true,
      keys: BTreeMap::from([("root-policy".to_string(), [7_u8; 32])]),
    };
    assert!(validate_trust(&trust).is_err());
  }
}
