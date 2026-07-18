//! Authenticated encryption for durable Admin-operation inputs and checkpoints.

use std::fmt;

use anyhow::{Context, ensure};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{Aes256GcmKey, random_fill};

pub(super) const OPERATION_ARTIFACT_ALGORITHM: &str = "aes-256-gcm-v1";
const NONCE_BYTES: usize = 12;
#[allow(
  dead_code,
  reason = "used by restart recovery when sealed artifacts are reopened"
)]
const TAG_BYTES: usize = 16;
const AAD_DOMAIN: &[u8] = b"OXIBELT-ADMIN-OPERATION-ARTIFACT-V1\0";
const KEY_FINGERPRINT_DOMAIN: &[u8] = b"OXIBELT-ADMIN-OPERATION-ARTIFACT-KEY-V1\0";
const IDEMPOTENCY_DERIVATION_DOMAIN: &[u8] = b"OXIBELT-ADMIN-OPERATION-IDEMPOTENCY-KEY-V1\0";
const IDEMPOTENCY_DIGEST_DOMAIN: &[u8] = b"OXIBELT-ADMIN-OPERATION-IDEMPOTENCY-V1\0";
const MAX_CONFIGURED_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::server) struct OperationArtifactBinding {
  pub namespace: String,
  pub operation_id: String,
  pub artifact_id: String,
  pub artifact_kind: String,
  pub operation_kind: String,
  pub schema_version: u16,
  pub principal: String,
  pub permission_action: String,
  pub resource_digest: String,
  pub request_fingerprint: String,
}

impl OperationArtifactBinding {
  fn additional_data(&self) -> anyhow::Result<Vec<u8>> {
    self.validate()?;
    let schema_version = self.schema_version.to_be_bytes();
    let fields: [&[u8]; 11] = [
      self.namespace.as_bytes(),
      self.operation_id.as_bytes(),
      self.artifact_id.as_bytes(),
      self.artifact_kind.as_bytes(),
      self.operation_kind.as_bytes(),
      &schema_version,
      self.principal.as_bytes(),
      self.permission_action.as_bytes(),
      self.resource_digest.as_bytes(),
      self.request_fingerprint.as_bytes(),
      OPERATION_ARTIFACT_ALGORITHM.as_bytes(),
    ];
    let capacity = fields.iter().try_fold(AAD_DOMAIN.len(), |size, field| {
      size.checked_add(4 + field.len())
    });
    let mut aad = Vec::with_capacity(capacity.context("operation artifact AAD is too large")?);
    aad.extend_from_slice(AAD_DOMAIN);
    for field in fields {
      let len = u32::try_from(field.len()).context("operation artifact AAD field is too large")?;
      aad.extend_from_slice(&len.to_be_bytes());
      aad.extend_from_slice(field);
    }
    Ok(aad)
  }

  fn validate(&self) -> anyhow::Result<()> {
    super::id::parse_operation_id(&self.operation_id)?;
    for (name, value, maximum) in [
      ("namespace", self.namespace.as_str(), 256),
      ("operation_id", self.operation_id.as_str(), 256),
      ("artifact_id", self.artifact_id.as_str(), 256),
      ("artifact_kind", self.artifact_kind.as_str(), 64),
      ("operation_kind", self.operation_kind.as_str(), 64),
      ("principal", self.principal.as_str(), 512),
      ("permission_action", self.permission_action.as_str(), 128),
    ] {
      validate_text(name, value, maximum)?;
    }
    ensure!(
      self.schema_version > 0,
      "artifact schema version must be positive"
    );
    ensure!(
      is_sha256_digest(&self.resource_digest),
      "resource_digest must be canonical SHA-256"
    );
    ensure!(
      is_sha256_digest(&self.request_fingerprint),
      "request_fingerprint must be canonical SHA-256"
    );
    Ok(())
  }
}

pub(in crate::server) struct OperationArtifactPlaintext(Zeroizing<Vec<u8>>);

impl OperationArtifactPlaintext {
  pub fn new(bytes: Vec<u8>) -> Self {
    Self(Zeroizing::new(bytes))
  }

  #[allow(
    dead_code,
    reason = "used by restart recovery executors and PostgreSQL tests"
  )]
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  pub fn len(&self) -> usize {
    self.0.len()
  }
}

impl fmt::Debug for OperationArtifactPlaintext {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("OperationArtifactPlaintext")
      .field("len", &self.len())
      .finish_non_exhaustive()
  }
}

pub(in crate::server) struct SealedOperationArtifact {
  pub binding: OperationArtifactBinding,
  pub key_fingerprint: String,
  pub nonce: [u8; NONCE_BYTES],
  pub ciphertext: Zeroizing<Vec<u8>>,
  pub ciphertext_digest: String,
  pub plaintext_len: usize,
}

#[allow(
  dead_code,
  reason = "durable restart recovery consumes stored ciphertext"
)]
pub(in crate::server) struct StoredOperationArtifact {
  pub binding: OperationArtifactBinding,
  pub key_fingerprint: String,
  pub nonce: Vec<u8>,
  pub ciphertext: Vec<u8>,
  pub ciphertext_digest: String,
  pub plaintext_len: usize,
}

pub(in crate::server) struct OperationArtifactCipher {
  key: Aes256GcmKey,
  key_fingerprint: String,
  idempotency_hmac_key: Zeroizing<[u8; 32]>,
  maximum_plaintext_bytes: usize,
}

impl OperationArtifactCipher {
  pub fn from_environment(
    environment_name: &str,
    maximum_plaintext_bytes: usize,
  ) -> anyhow::Result<Self> {
    validate_text("artifact_key_env", environment_name, 256)?;
    let encoded = Zeroizing::new(std::env::var(environment_name).with_context(|| {
      format!("failed to read Admin operation artifact key {environment_name}")
    })?);
    let key = Zeroizing::new(
      base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .context("Admin operation artifact key must contain base64")?,
    );
    Self::new(&key, maximum_plaintext_bytes)
  }

  pub fn new(key: &[u8], maximum_plaintext_bytes: usize) -> anyhow::Result<Self> {
    ensure!(
      (1..=MAX_CONFIGURED_PLAINTEXT_BYTES).contains(&maximum_plaintext_bytes),
      "Admin operation artifact size limit must be between 1 byte and 16 MiB"
    );
    ensure!(
      key.len() == 32,
      "Admin operation artifact key must contain exactly 32 bytes"
    );
    Ok(Self {
      key: Aes256GcmKey::new_from_slice(key)?,
      key_fingerprint: key_fingerprint(key),
      idempotency_hmac_key: Zeroizing::new(crate::crypto::hmac_sha256(
        key,
        IDEMPOTENCY_DERIVATION_DOMAIN,
      )),
      maximum_plaintext_bytes,
    })
  }

  #[allow(
    dead_code,
    reason = "fixed-member capability checks compare key fingerprints"
  )]
  pub fn key_fingerprint(&self) -> &str {
    &self.key_fingerprint
  }

  #[allow(
    dead_code,
    reason = "restart recovery validates configured artifact bounds"
  )]
  pub fn maximum_plaintext_bytes(&self) -> usize {
    self.maximum_plaintext_bytes
  }

  pub fn idempotency_key_digest(&self, key: &[u8]) -> anyhow::Result<String> {
    ensure!(
      (1..=128).contains(&key.len()) && key.iter().all(u8::is_ascii_graphic),
      "Idempotency-Key must contain 1 to 128 visible ASCII bytes"
    );
    let mut input = Vec::with_capacity(IDEMPOTENCY_DIGEST_DOMAIN.len() + 4 + key.len());
    input.extend_from_slice(IDEMPOTENCY_DIGEST_DOMAIN);
    input.extend_from_slice(&u32::try_from(key.len())?.to_be_bytes());
    input.extend_from_slice(key);
    Ok(format!(
      "hmac-sha256:{}",
      encode_hex(&crate::crypto::hmac_sha256(
        self.idempotency_hmac_key.as_ref(),
        &input,
      ))
    ))
  }

  pub fn seal(
    &self,
    binding: OperationArtifactBinding,
    plaintext: OperationArtifactPlaintext,
  ) -> anyhow::Result<SealedOperationArtifact> {
    let mut nonce = [0u8; NONCE_BYTES];
    random_fill(&mut nonce).context("failed to generate Admin operation artifact nonce")?;
    self.seal_with_nonce(binding, plaintext, nonce)
  }

  fn seal_with_nonce(
    &self,
    binding: OperationArtifactBinding,
    plaintext: OperationArtifactPlaintext,
    nonce: [u8; NONCE_BYTES],
  ) -> anyhow::Result<SealedOperationArtifact> {
    ensure!(
      plaintext.len() <= self.maximum_plaintext_bytes,
      "Admin operation artifact exceeds the configured size limit"
    );
    let aad = binding.additional_data()?;
    let plaintext_len = plaintext.len();
    let mut ciphertext = plaintext.0;
    self
      .key
      .seal_in_place_append_tag(nonce, &aad, &mut ciphertext)
      .map_err(|()| anyhow::anyhow!("failed to encrypt Admin operation artifact"))?;
    let ciphertext_digest = sha256_digest(&ciphertext);
    Ok(SealedOperationArtifact {
      binding,
      key_fingerprint: self.key_fingerprint.clone(),
      nonce,
      ciphertext,
      ciphertext_digest,
      plaintext_len,
    })
  }

  #[allow(
    dead_code,
    reason = "used when a future process resumes a sealed command"
  )]
  pub fn open(
    &self,
    stored: StoredOperationArtifact,
  ) -> anyhow::Result<OperationArtifactPlaintext> {
    stored.binding.validate()?;
    ensure!(
      stored.key_fingerprint == self.key_fingerprint,
      "Admin operation artifact key fingerprint mismatch"
    );
    ensure!(
      stored.plaintext_len <= self.maximum_plaintext_bytes
        && stored.ciphertext.len() == stored.plaintext_len + TAG_BYTES,
      "stored Admin operation artifact exceeds its declared bound"
    );
    ensure!(
      sha256_digest(&stored.ciphertext) == stored.ciphertext_digest,
      "stored Admin operation artifact ciphertext digest mismatch"
    );
    let nonce: [u8; NONCE_BYTES] = stored
      .nonce
      .try_into()
      .map_err(|_| anyhow::anyhow!("stored Admin operation artifact nonce is invalid"))?;
    let aad = stored.binding.additional_data()?;
    let mut plaintext = Zeroizing::new(stored.ciphertext);
    let opened = self
      .key
      .open_in_place(nonce, &aad, &mut plaintext)
      .map_err(|()| anyhow::anyhow!("failed to authenticate Admin operation artifact"))?;
    let length = opened.len();
    plaintext.truncate(length);
    Ok(OperationArtifactPlaintext(plaintext))
  }
}

fn key_fingerprint(key: &[u8]) -> String {
  let mut hasher = Sha256::new();
  hasher.update(KEY_FINGERPRINT_DOMAIN);
  hasher.update(key);
  format!("sha256:{}", encode_hex(&hasher.finalize()))
}

pub(super) fn sha256_digest(bytes: &[u8]) -> String {
  format!("sha256:{}", encode_hex(&Sha256::digest(bytes)))
}

fn encode_hex(bytes: &[u8]) -> String {
  let mut encoded = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    use std::fmt::Write as _;
    let _ = write!(encoded, "{byte:02x}");
  }
  encoded
}

pub(super) fn is_sha256_digest(value: &str) -> bool {
  value.len() == 71
    && value.strip_prefix("sha256:").is_some_and(|digest| {
      digest
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn validate_text(name: &str, value: &str, maximum: usize) -> anyhow::Result<()> {
  ensure!(!value.is_empty(), "{name} must not be empty");
  ensure!(value.len() <= maximum, "{name} exceeds {maximum} bytes");
  ensure!(
    value
      .bytes()
      .all(|byte| byte.is_ascii_graphic() || byte == b' '),
    "{name} contains control characters"
  );
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn binding() -> OperationArtifactBinding {
    OperationArtifactBinding {
      namespace: "edge".to_string(),
      operation_id: "op_00000000-0000-4000-8000-000000000001".to_string(),
      artifact_id: "input".to_string(),
      artifact_kind: "command".to_string(),
      operation_kind: "support_bundle".to_string(),
      schema_version: 1,
      principal: "spiffe://example/admin".to_string(),
      permission_action: "operations.write".to_string(),
      resource_digest: sha256_digest(b"support-bundle"),
      request_fingerprint: sha256_digest(b"request"),
    }
  }

  fn stored(sealed: SealedOperationArtifact) -> StoredOperationArtifact {
    StoredOperationArtifact {
      binding: sealed.binding,
      key_fingerprint: sealed.key_fingerprint,
      nonce: sealed.nonce.to_vec(),
      ciphertext: sealed.ciphertext.to_vec(),
      ciphertext_digest: sealed.ciphertext_digest,
      plaintext_len: sealed.plaintext_len,
    }
  }

  #[test]
  fn exact_artifact_round_trips_and_debug_is_redacted() {
    let cipher = OperationArtifactCipher::new(&[7; 32], 1024).expect("cipher");
    let plaintext = OperationArtifactPlaintext::new(b"secret-value".to_vec());
    assert!(!format!("{plaintext:?}").contains("secret-value"));
    let sealed = cipher
      .seal_with_nonce(binding(), plaintext, [3; NONCE_BYTES])
      .expect("seal");
    assert_ne!(sealed.ciphertext.as_slice(), b"secret-value");
    assert_eq!(
      cipher.open(stored(sealed)).expect("open").as_bytes(),
      b"secret-value"
    );
  }

  #[test]
  fn ciphertext_aad_and_key_tampering_fail_closed() {
    let cipher = OperationArtifactCipher::new(&[7; 32], 1024).expect("cipher");
    let sealed = cipher
      .seal_with_nonce(
        binding(),
        OperationArtifactPlaintext::new(b"payload".to_vec()),
        [4; NONCE_BYTES],
      )
      .expect("seal");
    let mut tampered = stored(sealed);
    tampered.ciphertext[0] ^= 0x80;
    tampered.ciphertext_digest = sha256_digest(&tampered.ciphertext);
    assert!(cipher.open(tampered).is_err());

    let sealed = cipher
      .seal_with_nonce(
        binding(),
        OperationArtifactPlaintext::new(b"payload".to_vec()),
        [5; NONCE_BYTES],
      )
      .expect("seal");
    let mut changed = stored(sealed);
    changed.binding.permission_action = "operations.read".to_string();
    assert!(cipher.open(changed).is_err());

    let sealed = cipher
      .seal_with_nonce(
        binding(),
        OperationArtifactPlaintext::new(b"payload".to_vec()),
        [6; NONCE_BYTES],
      )
      .expect("seal");
    let other = OperationArtifactCipher::new(&[8; 32], 1024).expect("other key");
    assert!(other.open(stored(sealed)).is_err());
  }

  #[test]
  fn limits_nonce_uniqueness_and_domain_separated_fingerprint_are_enforced() {
    assert!(OperationArtifactCipher::new(&[1; 31], 1024).is_err());
    let cipher = OperationArtifactCipher::new(&[7; 32], 4).expect("cipher");
    assert!(
      cipher
        .seal(
          binding(),
          OperationArtifactPlaintext::new(b"12345".to_vec())
        )
        .is_err()
    );
    assert_ne!(cipher.key_fingerprint(), sha256_digest(&[7; 32]));
    let first = cipher
      .seal(binding(), OperationArtifactPlaintext::new(b"1234".to_vec()))
      .expect("first");
    let second = cipher
      .seal(binding(), OperationArtifactPlaintext::new(b"1234".to_vec()))
      .expect("second");
    assert_ne!(first.nonce, second.nonce);
  }

  #[test]
  fn idempotency_digests_are_keyed_bounded_and_domain_separated() {
    let first = OperationArtifactCipher::new(&[7; 32], 1024).expect("first");
    let same = OperationArtifactCipher::new(&[7; 32], 1024).expect("same");
    let other = OperationArtifactCipher::new(&[8; 32], 1024).expect("other");
    let digest = first.idempotency_key_digest(b"retry-1").expect("digest");
    assert_eq!(
      digest,
      same
        .idempotency_key_digest(b"retry-1")
        .expect("same digest")
    );
    assert_ne!(
      digest,
      other
        .idempotency_key_digest(b"retry-1")
        .expect("other digest")
    );
    assert_ne!(digest, sha256_digest(b"retry-1"));
    assert!(first.idempotency_key_digest(b"").is_err());
    assert!(first.idempotency_key_digest(&[b'x'; 129]).is_err());
    assert!(first.idempotency_key_digest(b"bad key\n").is_err());
  }

  #[test]
  fn aad_uses_length_delimited_fields() {
    let mut left = binding();
    left.artifact_id = "ab".to_string();
    left.artifact_kind = "c".to_string();
    let mut right = binding();
    right.artifact_id = "a".to_string();
    right.artifact_kind = "bc".to_string();
    assert_ne!(
      left.additional_data().expect("left"),
      right.additional_data().expect("right")
    );
  }
}
