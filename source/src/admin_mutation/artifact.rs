//! Authenticated encryption for exact fixed-member mutation artifacts.

use std::fmt;

use anyhow::{Context, ensure};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{Aes256GcmKey, random_fill};

use super::ledger::{MutationRecord, validate_identifier};

pub(super) const ARTIFACT_ALGORITHM: &str = "aes-256-gcm-v1";
pub(super) const ARTIFACT_NONCE_BYTES: usize = 12;
pub(super) const ARTIFACT_TAG_BYTES: usize = 16;
pub(super) const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const ARTIFACT_AAD_DOMAIN: &[u8] = b"OXIBELT-ADMIN-MUTATION-ARTIFACT-V1\0";

pub(crate) struct MutationArtifactPlaintext {
  bytes: Zeroizing<Vec<u8>>,
}

impl MutationArtifactPlaintext {
  pub(crate) fn new(bytes: Vec<u8>) -> Self {
    Self {
      bytes: Zeroizing::new(bytes),
    }
  }

  pub(crate) fn as_bytes(&self) -> &[u8] {
    &self.bytes
  }

  pub(crate) fn len(&self) -> usize {
    self.bytes.len()
  }
}

impl fmt::Debug for MutationArtifactPlaintext {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("MutationArtifactPlaintext")
      .field("len", &self.len())
      .finish_non_exhaustive()
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MutationArtifactReceipt {
  pub(crate) published: bool,
  pub(crate) ciphertext_digest: String,
  pub(crate) plaintext_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ArtifactBinding {
  pub(super) namespace: String,
  pub(super) request_id: String,
  pub(super) fingerprint: String,
  pub(super) resource: String,
  pub(super) cluster_id: String,
  pub(super) membership_revision: String,
  pub(super) new_revision: String,
  pub(super) content_digest: String,
}

impl ArtifactBinding {
  pub(super) fn from_record(namespace: &str, record: &MutationRecord) -> anyhow::Result<Self> {
    let cluster_id = record
      .cluster_id
      .clone()
      .context("cluster mutation is missing cluster_id")?;
    let membership_revision = record
      .membership_revision
      .clone()
      .context("cluster mutation is missing membership_revision")?;
    let binding = Self {
      namespace: namespace.to_string(),
      request_id: record.request_id.clone(),
      fingerprint: record.fingerprint.clone(),
      resource: record.resource.clone(),
      cluster_id,
      membership_revision,
      new_revision: record.new_revision.clone(),
      content_digest: record.content_digest.clone(),
    };
    binding.validate()?;
    Ok(binding)
  }

  pub(super) fn validate(&self) -> anyhow::Result<()> {
    for (name, value) in [
      ("namespace", self.namespace.as_str()),
      ("request_id", self.request_id.as_str()),
      ("fingerprint", self.fingerprint.as_str()),
      ("resource", self.resource.as_str()),
      ("cluster_id", self.cluster_id.as_str()),
      ("membership_revision", self.membership_revision.as_str()),
      ("new_revision", self.new_revision.as_str()),
      ("content_digest", self.content_digest.as_str()),
    ] {
      validate_identifier(name, value, 256)?;
    }
    ensure!(
      is_sha256_digest(&self.content_digest),
      "artifact content digest must be canonical SHA-256"
    );
    Ok(())
  }

  fn additional_data(&self) -> anyhow::Result<Vec<u8>> {
    self.validate()?;
    let fields = [
      self.namespace.as_bytes(),
      self.request_id.as_bytes(),
      self.fingerprint.as_bytes(),
      self.resource.as_bytes(),
      self.cluster_id.as_bytes(),
      self.membership_revision.as_bytes(),
      self.new_revision.as_bytes(),
      self.content_digest.as_bytes(),
      ARTIFACT_ALGORITHM.as_bytes(),
    ];
    let capacity = fields
      .iter()
      .try_fold(ARTIFACT_AAD_DOMAIN.len(), |total, field| {
        total.checked_add(4 + field.len())
      })
      .context("artifact binding is too large")?;
    let mut aad = Vec::with_capacity(capacity);
    aad.extend_from_slice(ARTIFACT_AAD_DOMAIN);
    for field in fields {
      let length = u32::try_from(field.len()).context("artifact binding field is too large")?;
      aad.extend_from_slice(&length.to_be_bytes());
      aad.extend_from_slice(field);
    }
    Ok(aad)
  }
}

pub(super) struct SealedArtifact {
  pub(super) nonce: [u8; ARTIFACT_NONCE_BYTES],
  pub(super) ciphertext: Zeroizing<Vec<u8>>,
  pub(super) ciphertext_digest: String,
  pub(super) plaintext_len: usize,
}

pub(super) struct StoredArtifact {
  pub(super) binding: ArtifactBinding,
  pub(super) nonce: Vec<u8>,
  pub(super) ciphertext: Vec<u8>,
  pub(super) ciphertext_digest: String,
  pub(super) plaintext_len: usize,
}

pub(super) struct MutationArtifactCipher {
  key: Aes256GcmKey,
  maximum_plaintext_bytes: usize,
}

impl MutationArtifactCipher {
  pub(super) fn from_environment(
    environment_name: &str,
    maximum_plaintext_bytes: usize,
  ) -> anyhow::Result<Self> {
    validate_limit(maximum_plaintext_bytes)?;
    validate_identifier("artifact_key_env", environment_name, 256)?;
    let encoded =
      Zeroizing::new(std::env::var(environment_name).with_context(|| {
        format!("failed to read Admin mutation artifact key {environment_name}")
      })?);
    let key = Zeroizing::new(
      base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .context("Admin mutation artifact key must contain base64")?,
    );
    Self::new(&key, maximum_plaintext_bytes)
  }

  pub(super) fn new(key: &[u8], maximum_plaintext_bytes: usize) -> anyhow::Result<Self> {
    validate_limit(maximum_plaintext_bytes)?;
    ensure!(
      key.len() == 32,
      "Admin mutation artifact key must contain exactly 32 bytes"
    );
    Ok(Self {
      key: Aes256GcmKey::new_from_slice(key)?,
      maximum_plaintext_bytes,
    })
  }

  pub(super) fn maximum_plaintext_bytes(&self) -> usize {
    self.maximum_plaintext_bytes
  }

  pub(super) fn seal(
    &self,
    binding: &ArtifactBinding,
    plaintext: MutationArtifactPlaintext,
  ) -> anyhow::Result<SealedArtifact> {
    ensure!(
      plaintext.len() <= self.maximum_plaintext_bytes,
      "mutation artifact exceeds the configured size limit"
    );
    ensure!(
      sha256_digest(plaintext.as_bytes()) == binding.content_digest,
      "mutation artifact digest does not match the signed mutation"
    );
    let mut nonce = [0u8; ARTIFACT_NONCE_BYTES];
    random_fill(&mut nonce).context("failed to generate mutation artifact nonce")?;
    self.seal_with_nonce(binding, plaintext, nonce)
  }

  fn seal_with_nonce(
    &self,
    binding: &ArtifactBinding,
    plaintext: MutationArtifactPlaintext,
    nonce: [u8; ARTIFACT_NONCE_BYTES],
  ) -> anyhow::Result<SealedArtifact> {
    ensure!(
      plaintext.len() <= self.maximum_plaintext_bytes,
      "mutation artifact exceeds the configured size limit"
    );
    ensure!(
      sha256_digest(plaintext.as_bytes()) == binding.content_digest,
      "mutation artifact digest does not match the signed mutation"
    );
    let aad = binding.additional_data()?;
    let plaintext_len = plaintext.len();
    let mut ciphertext = plaintext.bytes;
    self
      .key
      .seal_in_place_append_tag(nonce, &aad, &mut ciphertext)
      .map_err(|()| anyhow::anyhow!("failed to encrypt mutation artifact"))?;
    let ciphertext_digest = sha256_digest(&ciphertext);
    Ok(SealedArtifact {
      nonce,
      ciphertext,
      ciphertext_digest,
      plaintext_len,
    })
  }

  pub(super) fn open(
    &self,
    expected_binding: &ArtifactBinding,
    stored: StoredArtifact,
  ) -> anyhow::Result<MutationArtifactPlaintext> {
    ensure!(
      stored.binding == *expected_binding,
      "mutation artifact binding mismatch"
    );
    ensure!(
      stored.plaintext_len <= self.maximum_plaintext_bytes
        && stored.ciphertext.len() == stored.plaintext_len + ARTIFACT_TAG_BYTES,
      "stored mutation artifact exceeds its declared bound"
    );
    ensure!(
      sha256_digest(&stored.ciphertext) == stored.ciphertext_digest,
      "stored mutation artifact ciphertext digest mismatch"
    );
    let nonce: [u8; ARTIFACT_NONCE_BYTES] = stored
      .nonce
      .try_into()
      .map_err(|_| anyhow::anyhow!("stored mutation artifact nonce is invalid"))?;
    let aad = expected_binding.additional_data()?;
    let mut plaintext = Zeroizing::new(stored.ciphertext);
    let opened_len = self
      .key
      .open_in_place(nonce, &aad, &mut plaintext)
      .map_err(|()| anyhow::anyhow!("mutation artifact authentication failed"))?
      .len();
    ensure!(
      opened_len == stored.plaintext_len,
      "stored mutation artifact length mismatch"
    );
    plaintext.truncate(opened_len);
    ensure!(
      sha256_digest(&plaintext) == expected_binding.content_digest,
      "decrypted mutation artifact digest mismatch"
    );
    Ok(MutationArtifactPlaintext { bytes: plaintext })
  }
}

pub(super) fn sha256_digest(bytes: &[u8]) -> String {
  let digest = Sha256::digest(bytes);
  let mut encoded = String::with_capacity(71);
  encoded.push_str("sha256:");
  for byte in digest {
    use std::fmt::Write as _;
    let _ = write!(encoded, "{byte:02x}");
  }
  encoded
}

fn validate_limit(maximum_plaintext_bytes: usize) -> anyhow::Result<()> {
  ensure!(
    (1..=MAX_ARTIFACT_BYTES).contains(&maximum_plaintext_bytes),
    "mutation artifact size limit is outside the supported range"
  );
  Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
  value.len() == 71
    && value.starts_with("sha256:")
    && value.as_bytes()[7..]
      .iter()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(test)]
#[path = "artifact_tests.rs"]
mod tests;
