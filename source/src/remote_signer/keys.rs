//! Private-key loading for the remote signer sidecar.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use rustls::sign::SigningKey;
use rustls::{SignatureAlgorithm, SignatureScheme};

use super::protocol::CtLogProfile;

pub(super) static PREFERRED_SIGNATURE_SCHEMES: &[SignatureScheme] = &[
  SignatureScheme::RSA_PSS_SHA512,
  SignatureScheme::RSA_PSS_SHA384,
  SignatureScheme::RSA_PSS_SHA256,
  SignatureScheme::ECDSA_NISTP521_SHA512,
  SignatureScheme::ECDSA_NISTP384_SHA384,
  SignatureScheme::ECDSA_NISTP256_SHA256,
  SignatureScheme::ED25519,
  SignatureScheme::RSA_PKCS1_SHA512,
  SignatureScheme::RSA_PKCS1_SHA384,
  SignatureScheme::RSA_PKCS1_SHA256,
];

#[derive(Debug)]
pub(super) struct ServerKey {
  pub(super) key: Arc<dyn SigningKey>,
  pub(super) public_key: Vec<u8>,
  pub(super) algorithm: SignatureAlgorithm,
  pub(super) schemes: Vec<SignatureScheme>,
}

#[derive(Debug)]
pub(super) struct AuditCheckpointKey {
  pub(super) key: Arc<dyn SigningKey>,
  pub(super) public_key: [u8; 32],
}

#[derive(Debug)]
pub(super) struct CtLogKey {
  pub(super) key_id: String,
  pub(super) key: Arc<dyn SigningKey>,
  pub(super) public_key: Vec<u8>,
  pub(super) profile: CtLogProfile,
}

pub(super) fn load_server_keys(
  keys: &[(String, PathBuf)],
) -> anyhow::Result<HashMap<String, ServerKey>> {
  let mut loaded = HashMap::new();
  for (key_id, path) in keys {
    if key_id.trim().is_empty() {
      bail!("remote signer key id must not be empty");
    }
    if loaded.contains_key(key_id) {
      bail!("duplicate remote signer key id {key_id}");
    }
    let key = load_signing_key(path)
      .with_context(|| format!("failed to load remote signer key {key_id}"))?;
    let public_key = key
      .public_key()
      .ok_or_else(|| anyhow!("key {key_id} does not expose a public key"))?
      .as_ref()
      .to_vec();
    let schemes = supported_schemes(key.as_ref());
    if schemes.is_empty() {
      bail!("remote signer key {key_id} does not support any TLS signature schemes");
    }
    loaded.insert(
      key_id.clone(),
      ServerKey {
        algorithm: key.algorithm(),
        key,
        public_key,
        schemes,
      },
    );
  }
  Ok(loaded)
}

pub(super) fn load_audit_checkpoint_keys(
  keys: &[(String, PathBuf)],
) -> anyhow::Result<HashMap<String, AuditCheckpointKey>> {
  let mut loaded = HashMap::new();
  for (key_id, path) in keys {
    if key_id.trim().is_empty() {
      bail!("audit checkpoint signer key id must not be empty");
    }
    if loaded.contains_key(key_id) {
      bail!("duplicate audit checkpoint signer key id {key_id}");
    }
    let key = load_signing_key(path)
      .with_context(|| format!("failed to load audit checkpoint signer key {key_id}"))?;
    validate_audit_checkpoint_signing_key(key_id, key.as_ref())?;
    let public_key_spki = key
      .public_key()
      .ok_or_else(|| anyhow!("audit checkpoint signer key {key_id} has no public key"))?
      .as_ref()
      .to_vec();
    let public_key = ed25519_public_key_from_spki(&public_key_spki)
      .with_context(|| format!("audit checkpoint signer key {key_id} public key is invalid"))?;
    loaded.insert(key_id.clone(), AuditCheckpointKey { key, public_key });
  }
  Ok(loaded)
}

pub(super) fn load_ct_log_key(
  key_id: &str,
  profile: CtLogProfile,
  path: &Path,
) -> anyhow::Result<CtLogKey> {
  if key_id.trim().is_empty() {
    bail!("CT log signer key id must not be empty");
  }
  let key =
    load_signing_key(path).with_context(|| format!("failed to load CT log signer key {key_id}"))?;
  validate_ct_log_signing_key(key_id, profile, key.as_ref())?;
  let public_key = key
    .public_key()
    .ok_or_else(|| anyhow!("CT log signer key {key_id} has no public key"))?
    .as_ref()
    .to_vec();
  Ok(CtLogKey {
    key_id: key_id.to_string(),
    key,
    public_key,
    profile,
  })
}

fn validate_audit_checkpoint_signing_key(key_id: &str, key: &dyn SigningKey) -> anyhow::Result<()> {
  if key.algorithm() != SignatureAlgorithm::ED25519
    || key.choose_scheme(&[SignatureScheme::ED25519]).is_none()
  {
    bail!("audit checkpoint signer key {key_id} must be Ed25519");
  }
  Ok(())
}

fn validate_ct_log_signing_key(
  key_id: &str,
  profile: CtLogProfile,
  key: &dyn SigningKey,
) -> anyhow::Result<()> {
  let expected = match profile {
    CtLogProfile::Rfc6962P256Sha256 | CtLogProfile::Rfc9162P256Sha256 => (
      SignatureAlgorithm::ECDSA,
      SignatureScheme::ECDSA_NISTP256_SHA256,
      "P-256 ECDSA/SHA-256",
    ),
    CtLogProfile::Rfc9162Ed25519 => (
      SignatureAlgorithm::ED25519,
      SignatureScheme::ED25519,
      "Ed25519",
    ),
  };
  if key.algorithm() != expected.0 || key.choose_scheme(&[expected.1]).is_none() {
    bail!(
      "CT log signer key {key_id} must support {} for profile {profile:?}",
      expected.2
    );
  }
  Ok(())
}

pub(super) fn ed25519_public_key_from_spki(spki: &[u8]) -> anyhow::Result<[u8; 32]> {
  const ED25519_SPKI_PREFIX: &[u8; 12] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ];
  let Some(public_key) = spki.strip_prefix(ED25519_SPKI_PREFIX) else {
    bail!("expected canonical Ed25519 SubjectPublicKeyInfo");
  };
  public_key
    .try_into()
    .map_err(|_| anyhow!("Ed25519 public key must be exactly 32 bytes"))
}

fn load_signing_key(path: &Path) -> anyhow::Result<Arc<dyn SigningKey>> {
  let bytes = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
  let key = PrivateKeyDer::from_pem_slice(&bytes).map_err(|error| match error {
    rustls::pki_types::pem::Error::NoItemsFound => {
      anyhow!("no private key found in {}", path.display())
    }
    error => anyhow!(
      "failed to parse private key from {}: {error}",
      path.display()
    ),
  })?;
  crate::tls::default_crypto_provider()
    .key_provider
    .load_private_key(private_key_to_static(key))
    .map_err(|error| anyhow!("failed to load private key: {error}"))
}

fn private_key_to_static(key: PrivateKeyDer<'_>) -> PrivateKeyDer<'static> {
  key.clone_key()
}

fn supported_schemes(key: &dyn SigningKey) -> Vec<SignatureScheme> {
  PREFERRED_SIGNATURE_SCHEMES
    .iter()
    .copied()
    .filter(|scheme| key.choose_scheme(&[*scheme]).is_some())
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use rustls::sign::Signer;

  #[derive(Debug)]
  struct RsaOnlyKey;

  impl SigningKey for RsaOnlyKey {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
      None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
      SignatureAlgorithm::RSA
    }
  }

  #[test]
  fn canonical_ed25519_spki_extracts_only_the_raw_key() {
    let mut spki = vec![
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(&[0x5a; 32]);
    assert_eq!(
      ed25519_public_key_from_spki(&spki).expect("canonical SPKI should parse"),
      [0x5a; 32]
    );

    spki.push(0);
    assert!(ed25519_public_key_from_spki(&spki).is_err());
  }

  #[test]
  fn non_ed25519_signing_key_does_not_meet_checkpoint_contract() {
    let key: Arc<dyn SigningKey> = Arc::new(RsaOnlyKey);
    let error = validate_audit_checkpoint_signing_key("rsa-key", key.as_ref())
      .expect_err("non-Ed25519 keys must be rejected");
    assert!(error.to_string().contains("must be Ed25519"));
  }
}
