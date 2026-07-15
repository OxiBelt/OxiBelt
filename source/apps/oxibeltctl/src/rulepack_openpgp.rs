use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use sequoia_openpgp as openpgp;

use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::parse::stream::{
  DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::types::{HashAlgorithm, SignatureType};

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
  let pinned = normalize_fingerprint_pins(trust.fingerprints)?;
  let certs = load_trusted_public_keys(&trust)?;
  if certs.is_empty() {
    bail!("rulepack OpenPGP signature requires at least one trusted public key");
  }

  let policy = StandardPolicy::new();
  let helper = RulepackVerificationHelper::new(certs, pinned);
  let verifier = DetachedVerifierBuilder::from_bytes(signature_bytes)
    .context("failed to parse OpenPGP detached signature")?;
  let mut verifier = verifier.with_policy(&policy, None, helper)?;
  verifier.verify_bytes(rulepack_bytes)?;
  let helper = verifier.into_helper();
  helper.into_verification()
}

fn load_trusted_public_keys(trust: &RulepackOpenPgpTrust<'_>) -> anyhow::Result<Vec<Cert>> {
  let mut certs = Vec::new();
  for path in trust.key_files {
    certs.extend(load_public_key_file(path)?);
  }
  for dir in trust.keyring_dirs {
    certs.extend(load_keyring_dir(dir, true)?);
  }
  if let Some(env_dir) = env_keyring_dir()? {
    certs.extend(load_keyring_dir(&env_dir, true)?);
  }
  let default_dir = Path::new(DEFAULT_OPENPGP_KEYRING_DIR);
  if default_dir.exists() {
    certs.extend(load_keyring_dir(default_dir, true)?);
  }
  Ok(certs)
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

fn load_keyring_dir(dir: &Path, require_exists: bool) -> anyhow::Result<Vec<Cert>> {
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
  let mut certs = Vec::new();
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
    certs.extend(load_public_key_file(&path)?);
  }
  Ok(certs)
}

fn is_openpgp_key_file(path: &Path) -> bool {
  path
    .extension()
    .and_then(|extension| extension.to_str())
    .is_some_and(|extension| matches!(extension, "asc" | "gpg" | "pgp" | "pub"))
}

fn load_public_key_file(path: &Path) -> anyhow::Result<Vec<Cert>> {
  let bytes = read_bounded_regular_file(path, "OpenPGP public key", MAX_OPENPGP_KEY_BYTES)?;
  let certs = CertParser::from_bytes(&bytes)
    .with_context(|| format!("failed to parse OpenPGP public key {}", path.display()))?;
  let certs = certs
    .collect::<openpgp::Result<Vec<_>>>()
    .with_context(|| format!("failed to parse OpenPGP public key {}", path.display()))?;
  for cert in &certs {
    if cert.keys().secret().next().is_some() {
      bail!("OpenPGP secret keys are not accepted: {}", path.display());
    }
  }
  if certs.is_empty() {
    bail!(
      "OpenPGP public key file contained no public keys: {}",
      path.display()
    );
  }
  Ok(certs)
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

struct RulepackVerificationHelper {
  certs: Vec<Cert>,
  pinned: BTreeSet<String>,
  signer_fingerprint: Option<String>,
}

impl RulepackVerificationHelper {
  fn new(certs: Vec<Cert>, pinned: BTreeSet<String>) -> Self {
    Self {
      certs,
      pinned,
      signer_fingerprint: None,
    }
  }

  fn into_verification(self) -> anyhow::Result<RulepackOpenPgpVerification> {
    let signer_fingerprint = self
      .signer_fingerprint
      .context("rulepack OpenPGP signature did not verify with trusted public keys")?;
    Ok(RulepackOpenPgpVerification { signer_fingerprint })
  }
}

impl VerificationHelper for RulepackVerificationHelper {
  fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
    Ok(self.certs.clone())
  }

  fn check(&mut self, structure: MessageStructure<'_>) -> openpgp::Result<()> {
    let layers = structure.iter().collect::<Vec<_>>();
    let [MessageLayer::SignatureGroup { results }] = layers.as_slice() else {
      bail!("OpenPGP detached signature did not produce a signature group");
    };

    let mut verification_errors = Vec::new();
    for result in results {
      match result {
        Ok(good) => {
          enforce_signature_policy(good.sig)?;
          let fingerprint = good.ka.key().fingerprint().to_hex().to_ascii_lowercase();
          if !self.pinned.is_empty() && !self.pinned.contains(&fingerprint) {
            continue;
          }
          self.signer_fingerprint = Some(fingerprint);
          return Ok(());
        }
        Err(error) => verification_errors.push(error.to_string()),
      }
    }

    if !self.pinned.is_empty() {
      bail!("no trusted OpenPGP public key matched --rulepack-openpgp-fingerprint");
    }
    let detail = verification_errors
      .last()
      .map(|error| format!(": {error}"))
      .unwrap_or_default();
    bail!("rulepack OpenPGP signature did not verify with trusted public keys{detail}");
  }
}

fn enforce_signature_policy(signature: &openpgp::packet::Signature) -> anyhow::Result<()> {
  ensure!(
    signature.typ() == SignatureType::Binary,
    "rulepack OpenPGP signature must be a binary detached signature, got {:?}",
    signature.typ()
  );
  let hash = signature.hash_algo();
  ensure!(
    matches!(
      hash,
      HashAlgorithm::SHA256
        | HashAlgorithm::SHA384
        | HashAlgorithm::SHA512
        | HashAlgorithm::SHA3_256
        | HashAlgorithm::SHA3_512
    ),
    "rulepack OpenPGP signature uses unsupported weak hash algorithm {hash}"
  );
  Ok(())
}

#[cfg(test)]
pub(crate) struct TestSignedRulepackFixture {
  pub(crate) rulepack: Vec<u8>,
  pub(crate) signature: Vec<u8>,
  pub(crate) key_file: PathBuf,
  pub(crate) fingerprint: String,
  _temp: tempfile::TempDir,
}

#[cfg(test)]
pub(crate) fn test_signed_rulepack_fixture(
  content: &[u8],
  user_id: &str,
) -> TestSignedRulepackFixture {
  use std::io::Write;

  use openpgp::armor;
  use openpgp::serialize::Serialize;
  use openpgp::serialize::stream::{Armorer, Message, Signer};

  let policy = StandardPolicy::new();
  let (cert, _revocation) = CertBuilder::new()
    .add_userid(user_id)
    .add_signing_subkey()
    .generate()
    .expect("generate key");
  let signing_key = cert
    .keys()
    .unencrypted_secret()
    .with_policy(&policy, None)
    .supported()
    .alive()
    .revoked(false)
    .for_signing()
    .next()
    .expect("signing key")
    .key()
    .clone();
  let fingerprint = signing_key.fingerprint().to_hex().to_ascii_lowercase();
  let keypair = signing_key.into_keypair().expect("keypair");
  let mut signature = Vec::new();
  {
    let message = Message::new(&mut signature);
    let message = Armorer::new(message)
      .kind(armor::Kind::Signature)
      .build()
      .expect("signature armor");
    let mut signer = Signer::new(message, keypair)
      .expect("signer")
      .hash_algo(HashAlgorithm::SHA256)
      .expect("hash")
      .detached()
      .build()
      .expect("detached signer");
    signer.write_all(content).expect("sign content");
    signer.finalize().expect("finalize signature");
  }
  let temp = tempfile::tempdir().expect("tempdir");
  let key_file = temp.path().join("publisher.asc");
  let mut public_key = Vec::new();
  cert.serialize(&mut public_key).expect("public key");
  std::fs::write(&key_file, public_key).expect("write public key");
  TestSignedRulepackFixture {
    rulepack: content.to_vec(),
    signature,
    key_file,
    fingerprint,
    _temp: temp,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn trust_for(fixture: &TestSignedRulepackFixture) -> RulepackOpenPgpTrust<'_> {
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
    let fixture =
      test_signed_rulepack_fixture(b"[rulepack]\nname = \"demo\"\n", "Rulepack <rulepack@test>");

    let verification =
      verify_rulepack_signature(&fixture.signature, &fixture.rulepack, trust_for(&fixture))
        .expect("signature should verify");

    assert_eq!(verification.signer_fingerprint, fixture.fingerprint);
  }

  #[test]
  fn tampered_rulepack_does_not_verify() {
    let fixture = test_signed_rulepack_fixture(b"original bytes", "Rulepack <rulepack@test>");
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
    let fixture = test_signed_rulepack_fixture(b"rulepack bytes", "Rulepack <rulepack@test>");
    let other = test_signed_rulepack_fixture(b"other bytes", "Other <other@test>");

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
    let fixture = test_signed_rulepack_fixture(b"rulepack bytes", "Rulepack <rulepack@test>");
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
    let fixture = test_signed_rulepack_fixture(b"rulepack bytes", "Rulepack <rulepack@test>");

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
