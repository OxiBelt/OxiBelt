//! Private-key loading for the remote signer sidecar.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use rustls::sign::SigningKey;
use rustls::{SignatureAlgorithm, SignatureScheme};

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
  if loaded.is_empty() {
    bail!("remote signer requires at least one --key entry");
  }
  Ok(loaded)
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
