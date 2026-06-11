use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::SignatureType;
use pgp::types::{KeyDetails, KeyVersion, VerifyingKey};

pub(crate) const OPENPGP_KEYRING_ENV: &str = "OXIBELT_RULEPACK_OPENPGP_KEYRING_DIR";
const DEFAULT_OPENPGP_KEYRING_DIR: &str = "/etc/oxibelt/oxirule/trusted-rulepack-publishers";
pub(crate) const MAX_OPENPGP_SIGNATURE_BYTES: usize = 128 * 1024;
const MAX_OPENPGP_KEY_BYTES: usize = 1024 * 1024;
const MAX_OPENPGP_KEYRING_ENTRIES: usize = 64;

#[derive(Debug)]
pub(crate) struct RulepackOpenPgpTrust<'a> {
  pub(crate) key_files: &'a [PathBuf],
  pub(crate) keyring_dirs: &'a [PathBuf],
  pub(crate) fingerprints: &'a [String],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RulepackOpenPgpVerification {
  pub(crate) signer_fingerprint: String,
}

pub(crate) fn read_signature_file(path: &Path) -> anyhow::Result<Vec<u8>> {
  read_bounded_regular_file(
    path,
    "OpenPGP detached signature",
    MAX_OPENPGP_SIGNATURE_BYTES,
  )
}

pub(crate) fn verify_rulepack_signature(
  signature_bytes: &[u8],
  rulepack_bytes: &[u8],
  trust: RulepackOpenPgpTrust<'_>,
) -> anyhow::Result<RulepackOpenPgpVerification> {
  let signature = parse_detached_signature(signature_bytes)?;
  enforce_signature_policy(&signature)?;
  let pinned = normalize_fingerprint_pins(trust.fingerprints)?;
  let keys = load_trusted_public_keys(&trust)?;
  if keys.is_empty() {
    bail!("rulepack OpenPGP signature requires at least one trusted public key");
  }

  let mut matched_pin = false;
  let mut verification_errors = Vec::new();
  for key in &keys {
    if let Some(verification) = try_verify_candidate(
      &signature,
      rulepack_bytes,
      key,
      &pinned,
      &mut matched_pin,
      &mut verification_errors,
    )? {
      return Ok(verification);
    }
    for subkey in &key.public_subkeys {
      if let Some(verification) = try_verify_candidate(
        &signature,
        rulepack_bytes,
        subkey,
        &pinned,
        &mut matched_pin,
        &mut verification_errors,
      )? {
        return Ok(verification);
      }
    }
  }

  if !pinned.is_empty() && !matched_pin {
    bail!("no trusted OpenPGP public key matched --rulepack-openpgp-fingerprint");
  }
  let detail = verification_errors
    .last()
    .map(|error| format!(": {error}"))
    .unwrap_or_default();
  bail!("rulepack OpenPGP signature did not verify with trusted public keys{detail}");
}

fn try_verify_candidate<K>(
  signature: &DetachedSignature,
  rulepack_bytes: &[u8],
  key: &K,
  pinned: &BTreeSet<String>,
  matched_pin: &mut bool,
  verification_errors: &mut Vec<String>,
) -> anyhow::Result<Option<RulepackOpenPgpVerification>>
where
  K: KeyDetails + VerifyingKey,
{
  let fingerprint = normalize_key_fingerprint(key)?;
  if !pinned.is_empty() && !pinned.contains(&fingerprint) {
    return Ok(None);
  }
  *matched_pin = true;
  match signature.verify(key, rulepack_bytes) {
    Ok(()) => Ok(Some(RulepackOpenPgpVerification {
      signer_fingerprint: fingerprint,
    })),
    Err(error) => {
      verification_errors.push(error.to_string());
      Ok(None)
    }
  }
}

fn parse_detached_signature(bytes: &[u8]) -> anyhow::Result<DetachedSignature> {
  let (signature, _) = DetachedSignature::from_reader_single(Cursor::new(bytes))
    .context("failed to parse OpenPGP detached signature")?;
  Ok(signature)
}

fn enforce_signature_policy(signature: &DetachedSignature) -> anyhow::Result<()> {
  match signature.signature.typ() {
    Some(SignatureType::Binary) => {}
    Some(other) => {
      bail!("rulepack OpenPGP signature must be a binary detached signature, got {other:?}")
    }
    None => bail!("rulepack OpenPGP signature has an unsupported signature type"),
  }
  let hash = signature
    .signature
    .hash_alg()
    .context("rulepack OpenPGP signature has an unsupported hash algorithm")?;
  if !matches!(
    hash,
    HashAlgorithm::Sha256
      | HashAlgorithm::Sha384
      | HashAlgorithm::Sha512
      | HashAlgorithm::Sha3_256
      | HashAlgorithm::Sha3_512
  ) {
    bail!("rulepack OpenPGP signature uses unsupported weak hash algorithm {hash}");
  }
  Ok(())
}

fn load_trusted_public_keys(
  trust: &RulepackOpenPgpTrust<'_>,
) -> anyhow::Result<Vec<SignedPublicKey>> {
  let mut keys = Vec::new();
  for path in trust.key_files {
    keys.extend(load_public_key_file(path)?);
  }
  for dir in trust.keyring_dirs {
    keys.extend(load_keyring_dir(dir, true)?);
  }
  if let Some(env_dir) = env_keyring_dir()? {
    keys.extend(load_keyring_dir(&env_dir, true)?);
  }
  let default_dir = Path::new(DEFAULT_OPENPGP_KEYRING_DIR);
  if default_dir.exists() {
    keys.extend(load_keyring_dir(default_dir, true)?);
  }
  Ok(keys)
}

fn env_keyring_dir() -> anyhow::Result<Option<PathBuf>> {
  match std::env::var(OPENPGP_KEYRING_ENV) {
    Ok(value) if value.trim().is_empty() => {
      bail!("{OPENPGP_KEYRING_ENV} must not be empty when set")
    }
    Ok(value) => Ok(Some(PathBuf::from(value))),
    Err(std::env::VarError::NotPresent) => Ok(None),
    Err(std::env::VarError::NotUnicode(_)) => {
      bail!("{OPENPGP_KEYRING_ENV} must be valid Unicode")
    }
  }
}

fn load_keyring_dir(dir: &Path, require_exists: bool) -> anyhow::Result<Vec<SignedPublicKey>> {
  let metadata = match std::fs::symlink_metadata(dir) {
    Ok(metadata) => metadata,
    Err(error) if !require_exists && error.kind() == std::io::ErrorKind::NotFound => {
      return Ok(Vec::new());
    }
    Err(error) => {
      return Err(error).with_context(|| {
        format!(
          "failed to inspect OpenPGP keyring directory {}",
          dir.display()
        )
      });
    }
  };
  if !metadata.file_type().is_dir() {
    bail!(
      "OpenPGP keyring path must be a directory: {}",
      dir.display()
    );
  }
  let mut entries = std::fs::read_dir(dir)
    .with_context(|| format!("failed to read OpenPGP keyring directory {}", dir.display()))?
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to read OpenPGP keyring directory {}", dir.display()))?;
  entries.sort_by_key(|entry| entry.path());
  let mut keys = Vec::new();
  let mut read_entries = 0usize;
  for entry in entries {
    let path = entry.path();
    let metadata = std::fs::symlink_metadata(&path)
      .with_context(|| format!("failed to inspect OpenPGP keyring entry {}", path.display()))?;
    if !metadata.file_type().is_file() || !is_openpgp_key_file(&path) {
      continue;
    }
    read_entries += 1;
    if read_entries > MAX_OPENPGP_KEYRING_ENTRIES {
      bail!(
        "OpenPGP keyring directory {} exceeds {MAX_OPENPGP_KEYRING_ENTRIES} key files",
        dir.display()
      );
    }
    keys.extend(load_public_key_file(&path)?);
  }
  Ok(keys)
}

fn is_openpgp_key_file(path: &Path) -> bool {
  path
    .extension()
    .and_then(|extension| extension.to_str())
    .is_some_and(|extension| matches!(extension, "asc" | "gpg" | "pgp" | "pub"))
}

fn load_public_key_file(path: &Path) -> anyhow::Result<Vec<SignedPublicKey>> {
  let bytes = read_bounded_regular_file(path, "OpenPGP public key", MAX_OPENPGP_KEY_BYTES)?;
  let (keys, _) = SignedPublicKey::from_reader_many(Cursor::new(bytes))
    .with_context(|| format!("failed to parse OpenPGP public key {}", path.display()))?;
  let keys = keys
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse OpenPGP public key {}", path.display()))?;
  if keys.is_empty() {
    bail!(
      "OpenPGP public key file contained no public keys: {}",
      path.display()
    );
  }
  Ok(keys)
}

fn read_bounded_regular_file(
  path: &Path,
  label: &str,
  max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
  let metadata = std::fs::symlink_metadata(path)
    .with_context(|| format!("failed to inspect {label} file {}", path.display()))?;
  if !metadata.file_type().is_file() {
    bail!("{label} file must be a regular file: {}", path.display());
  }
  if metadata.len() > max_bytes as u64 {
    bail!("{label} file {} exceeds {max_bytes} bytes", path.display());
  }
  let mut file =
    File::open(path).with_context(|| format!("failed to open {label} file {}", path.display()))?;
  let mut bytes = Vec::with_capacity(metadata.len() as usize);
  file
    .by_ref()
    .take(max_bytes as u64 + 1)
    .read_to_end(&mut bytes)
    .with_context(|| format!("failed to read {label} file {}", path.display()))?;
  if bytes.len() > max_bytes {
    bail!("{label} file {} exceeds {max_bytes} bytes", path.display());
  }
  Ok(bytes)
}

fn normalize_fingerprint_pins(raw: &[String]) -> anyhow::Result<BTreeSet<String>> {
  raw
    .iter()
    .map(|fingerprint| normalize_fingerprint_pin(fingerprint))
    .collect()
}

fn normalize_fingerprint_pin(raw: &str) -> anyhow::Result<String> {
  let normalized = raw
    .chars()
    .filter(|character| !matches!(character, ' ' | '\t' | '\n' | '\r' | ':'))
    .flat_map(char::to_lowercase)
    .collect::<String>();
  if !matches!(normalized.len(), 40 | 64)
    || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
  {
    bail!("--rulepack-openpgp-fingerprint requires a full 40- or 64-character hex fingerprint");
  }
  Ok(normalized)
}

fn normalize_key_fingerprint(key: &impl KeyDetails) -> anyhow::Result<String> {
  match key.version() {
    KeyVersion::V4 | KeyVersion::V5 | KeyVersion::V6 => {}
    version => bail!("trusted OpenPGP key uses unsupported legacy key version {version:?}"),
  }
  let fingerprint = format!("{:x}", key.fingerprint());
  if !matches!(fingerprint.len(), 40 | 64)
    || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
  {
    bail!("trusted OpenPGP key has unsupported fingerprint length");
  }
  Ok(fingerprint)
}

#[cfg(test)]
mod tests {
  use super::*;
  use pgp::composed::{KeyType, SecretKeyParamsBuilder};
  use pgp::types::{KeyDetails, Password};

  struct SignedFixture {
    rulepack: Vec<u8>,
    signature: Vec<u8>,
    key_file: PathBuf,
    fingerprint: String,
    _temp: tempfile::TempDir,
  }

  fn signed_fixture(content: &[u8], user_id: &str) -> SignedFixture {
    let mut rng = rand::thread_rng();
    let key_params = SecretKeyParamsBuilder::default()
      .key_type(KeyType::Ed25519)
      .can_sign(true)
      .can_certify(true)
      .primary_user_id(user_id.to_string())
      .passphrase(None)
      .build()
      .expect("key params");
    let secret = key_params.generate(&mut rng).expect("generate key");
    let public = secret.to_public_key();
    let fingerprint = format!("{:x}", public.fingerprint());
    let signature = DetachedSignature::sign_binary_data(
      &mut rng,
      &secret.primary_key,
      &Password::empty(),
      HashAlgorithm::Sha256,
      Cursor::new(content),
    )
    .expect("sign");
    let temp = tempfile::tempdir().expect("tempdir");
    let key_file = temp.path().join("publisher.asc");
    std::fs::write(
      &key_file,
      public
        .to_armored_string(None.into())
        .expect("public key armor"),
    )
    .expect("write public key");
    SignedFixture {
      rulepack: content.to_vec(),
      signature: signature
        .to_armored_bytes(None.into())
        .expect("signature armor"),
      key_file,
      fingerprint,
      _temp: temp,
    }
  }

  fn trust_for(fixture: &SignedFixture) -> RulepackOpenPgpTrust<'_> {
    RulepackOpenPgpTrust {
      key_files: std::slice::from_ref(&fixture.key_file),
      keyring_dirs: &[],
      fingerprints: &[],
    }
  }

  #[test]
  fn fingerprint_pins_must_be_full_hex() {
    assert!(normalize_fingerprint_pin("AA BB:cc").is_err());
    let fp = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(
      normalize_fingerprint_pin(fp).expect("fingerprint"),
      fp.to_string()
    );
  }

  #[test]
  fn valid_signature_verifies_with_trusted_public_key() {
    let fixture = signed_fixture(b"[rulepack]\nname = \"demo\"\n", "Rulepack <rulepack@test>");

    let verification =
      verify_rulepack_signature(&fixture.signature, &fixture.rulepack, trust_for(&fixture))
        .expect("signature should verify");

    assert_eq!(verification.signer_fingerprint, fixture.fingerprint);
  }

  #[test]
  fn tampered_rulepack_does_not_verify() {
    let fixture = signed_fixture(b"original bytes", "Rulepack <rulepack@test>");
    let mut tampered = fixture.rulepack.clone();
    tampered.extend_from_slice(b"\nchanged");

    let error = verify_rulepack_signature(&fixture.signature, &tampered, trust_for(&fixture))
      .expect_err("tampered content should not verify");

    assert!(
      error
        .to_string()
        .contains("did not verify with trusted public keys")
    );
  }

  #[test]
  fn wrong_trusted_key_does_not_verify() {
    let fixture = signed_fixture(b"rulepack bytes", "Rulepack <rulepack@test>");
    let other = signed_fixture(b"other bytes", "Other <other@test>");

    let error = verify_rulepack_signature(
      &fixture.signature,
      &fixture.rulepack,
      RulepackOpenPgpTrust {
        key_files: std::slice::from_ref(&other.key_file),
        keyring_dirs: &[],
        fingerprints: &[],
      },
    )
    .expect_err("wrong trusted key should not verify");

    assert!(
      error
        .to_string()
        .contains("did not verify with trusted public keys")
    );
  }

  #[test]
  fn fingerprint_pin_must_match_trusted_signer() {
    let fixture = signed_fixture(b"rulepack bytes", "Rulepack <rulepack@test>");
    let wrong_fingerprint = vec!["0".repeat(40)];

    let error = verify_rulepack_signature(
      &fixture.signature,
      &fixture.rulepack,
      RulepackOpenPgpTrust {
        key_files: std::slice::from_ref(&fixture.key_file),
        keyring_dirs: &[],
        fingerprints: &wrong_fingerprint,
      },
    )
    .expect_err("fingerprint mismatch should fail");

    assert!(
      error
        .to_string()
        .contains("matched --rulepack-openpgp-fingerprint")
    );
  }

  #[test]
  fn missing_trust_material_fails_closed() {
    let fixture = signed_fixture(b"rulepack bytes", "Rulepack <rulepack@test>");

    let error = verify_rulepack_signature(
      &fixture.signature,
      &fixture.rulepack,
      RulepackOpenPgpTrust {
        key_files: &[],
        keyring_dirs: &[],
        fingerprints: &[],
      },
    )
    .expect_err("missing trust should fail");

    assert!(
      error
        .to_string()
        .contains("at least one trusted public key")
    );
  }
}
