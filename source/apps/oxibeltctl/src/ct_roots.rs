use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use aws_lc_rs::signature::Ed25519KeyPair;
use base64::Engine as _;
use der::Decode as _;
use oxibelt::ct_runtime::{AcceptedRootTrust, load_verified_root_bundle};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, pem::PemObject as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;
use zeroize::{Zeroize as _, Zeroizing};

use crate::cli::{
  CtRootsBuildArgs, CtRootsDiffArgs, CtRootsSignArgs, CtRootsSubcommand, CtRootsVerifyArgs,
};
use crate::ct_io::{
  MAX_DOCUMENT_BYTES, canonical_json_bytes, encode_hex, read_bounded, read_integrity_bounded,
  validate_identifier, write_new,
};

const MAX_ROOTS: usize = 4096;
const MAX_SIGNATURES: usize = 32;
const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 256 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootBundleDocument {
  schema_version: u32,
  snapshot_id: String,
  serial: u64,
  created_at_unix_seconds: i64,
  roots: Vec<RootDocument>,
  signatures: Vec<SignatureDocument>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootDocument {
  sha256: String,
  der_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignatureDocument {
  key_id: String,
  algorithm: String,
  value_base64: String,
}

#[derive(Serialize)]
struct UnsignedDocument<'a> {
  schema_version: u32,
  snapshot_id: &'a str,
  serial: u64,
  created_at_unix_seconds: i64,
  roots: &'a [RootDocument],
}

pub(crate) fn run(command: &CtRootsSubcommand) -> anyhow::Result<i32> {
  match command {
    CtRootsSubcommand::Build(args) => build(args),
    CtRootsSubcommand::Sign(args) => sign(args),
    CtRootsSubcommand::Verify(args) => verify(args),
    CtRootsSubcommand::Diff(args) => diff(args),
  }
}

fn build(args: &CtRootsBuildArgs) -> anyhow::Result<i32> {
  validate_identifier(&args.snapshot_id, "CT root snapshot id")?;
  if args.created_at < 0 {
    bail!("CT root bundle creation time must not precede the Unix epoch");
  }
  if args.roots.len() > MAX_ROOTS {
    bail!("CT root count exceeds {MAX_ROOTS}");
  }
  let mut roots = Vec::with_capacity(args.roots.len());
  for path in &args.roots {
    let der = read_certificate(path)?;
    let digest = Sha256::digest(&der);
    roots.push(RootDocument {
      sha256: format!("sha256:{}", encode_hex(&digest)),
      der_base64: base64::engine::general_purpose::STANDARD.encode(der),
    });
  }
  roots.sort_by(|left, right| left.sha256.cmp(&right.sha256));
  if roots
    .windows(2)
    .any(|pair| pair[0].sha256 == pair[1].sha256)
  {
    bail!("CT accepted-root inputs contain duplicate certificates");
  }
  let document = RootBundleDocument {
    schema_version: 1,
    snapshot_id: args.snapshot_id.clone(),
    serial: args.serial,
    created_at_unix_seconds: args.created_at,
    roots,
    signatures: Vec::new(),
  };
  validate_document(&document, true)?;
  let bytes = canonical_json_bytes(&serde_json::to_value(document)?)?;
  write_new(&args.output, &bytes, "CT accepted-root bundle")?;
  print_digest(&bytes);
  Ok(0)
}

fn sign(args: &CtRootsSignArgs) -> anyhow::Result<i32> {
  validate_identifier(&args.key_id, "CT root signing key id")?;
  if args.bundle == args.output {
    bail!("CT root signing output must differ from the input bundle");
  }
  let bytes = read_bounded(&args.bundle, MAX_DOCUMENT_BYTES, "CT accepted-root bundle")?;
  let mut document = parse_canonical(&bytes, true)?;
  let unsigned = UnsignedDocument {
    schema_version: document.schema_version,
    snapshot_id: &document.snapshot_id,
    serial: document.serial,
    created_at_unix_seconds: document.created_at_unix_seconds,
    roots: &document.roots,
  };
  let transcript = canonical_json_bytes(&serde_json::to_value(unsigned)?)?;
  let key = load_private_key(&args.private_key)?;
  let signature = key.sign(&transcript);
  let replacement = SignatureDocument {
    key_id: args.key_id.clone(),
    algorithm: "ed25519".to_string(),
    value_base64: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
  };
  match document
    .signatures
    .binary_search_by(|existing| existing.key_id.cmp(&args.key_id))
  {
    Ok(index) => document.signatures[index] = replacement,
    Err(index) => document.signatures.insert(index, replacement),
  }
  validate_document(&document, false)?;
  let output = canonical_json_bytes(&serde_json::to_value(document)?)?;
  write_new(&args.output, &output, "signed CT accepted-root bundle")?;
  print_digest(&output);
  Ok(0)
}

fn verify(args: &CtRootsVerifyArgs) -> anyhow::Result<i32> {
  let bytes = read_bounded(&args.bundle, MAX_DOCUMENT_BYTES, "CT accepted-root bundle")?;
  let digest = format!("sha256:{}", encode_hex(&Sha256::digest(&bytes)));
  let expected = args.expected_digest.as_deref().unwrap_or(&digest);
  let mut keys = BTreeMap::new();
  for binding in &args.trusted_keys {
    let (key_id, path) = binding
      .split_once('=')
      .ok_or_else(|| anyhow!("--trusted-key must use KEY_ID=FILE"))?;
    validate_identifier(key_id, "CT trusted root key id")?;
    let bytes = read_integrity_bounded(Path::new(path), 32, "CT trusted Ed25519 public key")?;
    let key: [u8; 32] = bytes
      .try_into()
      .map_err(|_| anyhow!("CT trusted Ed25519 public key {path} must be exactly 32 bytes"))?;
    if keys.insert(key_id.to_string(), key).is_some() {
      bail!("duplicate CT trusted root key id {key_id}");
    }
  }
  let bundle = load_verified_root_bundle(
    &args.bundle,
    expected,
    &AcceptedRootTrust {
      threshold: args.threshold,
      production: args.production,
      keys,
    },
  )?;
  println!(
    "{}",
    serde_json::to_string_pretty(&serde_json::json!({
      "digest": digest,
      "snapshot_id": bundle.snapshot_id,
      "serial": bundle.serial,
      "root_count": bundle.roots.len(),
      "verified_signers": bundle.verified_signers,
    }))?
  );
  Ok(0)
}

fn diff(args: &CtRootsDiffArgs) -> anyhow::Result<i32> {
  let old = read_document(&args.old)?;
  let new = read_document(&args.new)?;
  let old_roots = old
    .roots
    .into_iter()
    .map(|root| root.sha256)
    .collect::<BTreeSet<_>>();
  let new_roots = new
    .roots
    .into_iter()
    .map(|root| root.sha256)
    .collect::<BTreeSet<_>>();
  println!(
    "{}",
    serde_json::to_string_pretty(&serde_json::json!({
      "old_snapshot_id": old.snapshot_id,
      "old_serial": old.serial,
      "new_snapshot_id": new.snapshot_id,
      "new_serial": new.serial,
      "added": new_roots.difference(&old_roots).collect::<Vec<_>>(),
      "removed": old_roots.difference(&new_roots).collect::<Vec<_>>(),
      "unchanged_count": old_roots.intersection(&new_roots).count(),
    }))?
  );
  Ok(0)
}

fn read_document(path: &Path) -> anyhow::Result<RootBundleDocument> {
  let bytes = read_bounded(path, MAX_DOCUMENT_BYTES, "CT accepted-root bundle")?;
  parse_canonical(&bytes, true)
}

fn parse_canonical(bytes: &[u8], allow_unsigned: bool) -> anyhow::Result<RootBundleDocument> {
  let document: RootBundleDocument =
    serde_json::from_slice(bytes).context("failed to parse CT accepted-root bundle")?;
  validate_document(&document, allow_unsigned)?;
  if canonical_json_bytes(&serde_json::to_value(&document)?)? != bytes {
    bail!("CT accepted-root bundle must use canonical JSON without trailing bytes");
  }
  Ok(document)
}

fn validate_document(document: &RootBundleDocument, allow_unsigned: bool) -> anyhow::Result<()> {
  if document.schema_version != 1 {
    bail!("unsupported CT accepted-root bundle schema version");
  }
  validate_identifier(&document.snapshot_id, "CT root snapshot id")?;
  if document.serial == 0 || document.roots.is_empty() || document.roots.len() > MAX_ROOTS {
    bail!("CT root bundle serial or root count is outside the supported range");
  }
  if (!allow_unsigned && document.signatures.is_empty())
    || document.signatures.len() > MAX_SIGNATURES
  {
    bail!("CT root bundle signature count is outside the supported range");
  }
  strictly_sorted(
    document.roots.iter().map(|root| root.sha256.as_str()),
    "root fingerprints",
  )?;
  strictly_sorted(
    document
      .signatures
      .iter()
      .map(|signature| signature.key_id.as_str()),
    "signature key ids",
  )?;
  for root in &document.roots {
    let expected = crate::ct_io::parse_hex_32(&root.sha256, "CT root fingerprint")?;
    let der = base64::engine::general_purpose::STANDARD
      .decode(&root.der_base64)
      .context("invalid CT root DER base64")?;
    if base64::engine::general_purpose::STANDARD.encode(&der) != root.der_base64 {
      bail!("CT root DER is not canonical base64");
    }
    if der.is_empty() || der.len() > MAX_CERTIFICATE_BYTES as usize {
      bail!("CT root DER length is outside the supported range");
    }
    Certificate::from_der(&der).context("invalid CT root certificate DER")?;
    if expected != <[u8; 32]>::from(Sha256::digest(&der)) {
      bail!("CT root fingerprint does not match its certificate");
    }
  }
  for signature in &document.signatures {
    validate_identifier(&signature.key_id, "CT root signature key id")?;
    if signature.algorithm != "ed25519" {
      bail!("CT root signature algorithm must be ed25519");
    }
    let value = base64::engine::general_purpose::STANDARD
      .decode(&signature.value_base64)
      .context("invalid CT root signature base64")?;
    if base64::engine::general_purpose::STANDARD.encode(&value) != signature.value_base64 {
      bail!("CT root signature is not canonical base64");
    }
    if value.len() != 64 {
      bail!("CT root Ed25519 signature must be 64 bytes");
    }
  }
  Ok(())
}

fn strictly_sorted<'a>(values: impl Iterator<Item = &'a str>, label: &str) -> anyhow::Result<()> {
  let mut previous = None;
  for value in values {
    if previous.is_some_and(|previous| previous >= value) {
      bail!("CT root bundle {label} must be strictly sorted and unique");
    }
    previous = Some(value);
  }
  Ok(())
}

fn read_certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
  let bytes = read_bounded(path, MAX_CERTIFICATE_BYTES, "CT root certificate")?;
  let first = bytes
    .iter()
    .position(|byte| !byte.is_ascii_whitespace())
    .unwrap_or(bytes.len());
  let der = if bytes[first..].starts_with(b"-----BEGIN") {
    let certificates = CertificateDer::pem_slice_iter(&bytes)
      .collect::<Result<Vec<_>, _>>()
      .with_context(|| format!("failed to parse CT root certificate PEM {}", path.display()))?;
    if certificates.len() != 1 {
      bail!(
        "CT root certificate {} must contain exactly one certificate",
        path.display()
      );
    }
    certificates[0].as_ref().to_vec()
  } else {
    bytes
  };
  Certificate::from_der(&der)
    .with_context(|| format!("failed to parse CT root certificate DER {}", path.display()))?;
  Ok(der)
}

fn load_private_key(path: &Path) -> anyhow::Result<Ed25519KeyPair> {
  validate_private_key_permissions(path)?;
  let bytes = Zeroizing::new(read_bounded(
    path,
    MAX_PRIVATE_KEY_BYTES,
    "CT root private key",
  )?);
  let first = bytes
    .iter()
    .position(|byte| !byte.is_ascii_whitespace())
    .unwrap_or(bytes.len());
  if bytes[first..].starts_with(b"-----BEGIN") {
    let mut keys = PrivatePkcs8KeyDer::pem_slice_iter(&bytes)
      .collect::<Result<Vec<_>, _>>()
      .with_context(|| format!("failed to parse CT root private key PEM {}", path.display()))?;
    if keys.len() != 1 {
      keys.iter_mut().for_each(|key| key.zeroize());
      bail!(
        "CT root private key {} must contain exactly one PKCS#8 key",
        path.display()
      );
    }
    let result = Ed25519KeyPair::from_pkcs8(keys[0].secret_pkcs8_der()).map_err(|_| {
      anyhow!(
        "CT root private key {} is not Ed25519 PKCS#8",
        path.display()
      )
    });
    keys.iter_mut().for_each(|key| key.zeroize());
    result
  } else {
    Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| {
      anyhow!(
        "CT root private key {} is not Ed25519 PKCS#8",
        path.display()
      )
    })
  }
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> anyhow::Result<()> {
  use std::os::unix::fs::MetadataExt as _;

  let metadata = std::fs::metadata(path)?;
  if metadata.mode() & 0o077 != 0 {
    bail!(
      "CT root private key {} must not be accessible by group or other",
      path.display()
    );
  }
  Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_permissions(_path: &Path) -> anyhow::Result<()> {
  Ok(())
}

fn print_digest(bytes: &[u8]) {
  println!("sha256:{}", encode_hex(&Sha256::digest(bytes)));
}
