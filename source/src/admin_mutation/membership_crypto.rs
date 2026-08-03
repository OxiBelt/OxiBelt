//! Learner-scoped encryption for bounded membership catch-up artifacts.

use anyhow::{Context, ensure};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::crypto::{Aes256GcmKey, hkdf_sha256, random_fill};

use super::artifact::sha256_digest;

pub(crate) const CATCHUP_ALGORITHM: &str = "x25519-hkdf-sha256-aes-256-gcm-v1";
const CATCHUP_DOMAIN: &[u8] = b"OXIBELT-ADMIN-MEMBERSHIP-CATCHUP-V1\0";
const MAX_CATCHUP_PLAINTEXT_BYTES: usize = 1024 * 1024;

pub(crate) struct CatchupBinding<'a> {
  pub(crate) cluster_id: &'a str,
  pub(crate) transition_id: &'a str,
  pub(crate) member_id: &'a str,
  pub(crate) source_epoch: &'a str,
  pub(crate) target_epoch: &'a str,
  pub(crate) chunk_index: u32,
}

pub(crate) struct SealedCatchupChunk {
  pub(crate) ephemeral_public_key: [u8; 32],
  pub(crate) nonce: [u8; 12],
  pub(crate) ciphertext: Zeroizing<Vec<u8>>,
  pub(crate) ciphertext_digest: String,
  pub(crate) plaintext_digest: String,
  pub(crate) plaintext_len: usize,
}

pub(crate) fn seal_catchup_chunk(
  binding: &CatchupBinding<'_>,
  recipient_public_key_base64: &str,
  plaintext: Zeroizing<Vec<u8>>,
) -> anyhow::Result<SealedCatchupChunk> {
  ensure!(
    !plaintext.is_empty() && plaintext.len() <= MAX_CATCHUP_PLAINTEXT_BYTES,
    "membership catch-up plaintext is outside its bounded size"
  );
  let recipient_public_key = base64::engine::general_purpose::STANDARD
    .decode(recipient_public_key_base64)
    .context("learner X25519 public key is not base64")?;
  ensure!(
    recipient_public_key.len() == 32,
    "learner X25519 public key is not 32 bytes"
  );
  let ephemeral = PrivateKey::generate(&X25519)
    .map_err(|_| anyhow::anyhow!("failed to generate ephemeral X25519 catch-up key"))?;
  let public = ephemeral
    .compute_public_key()
    .map_err(|_| anyhow::anyhow!("failed to derive ephemeral X25519 public key"))?;
  let ephemeral_public_key: [u8; 32] = public
    .as_ref()
    .try_into()
    .map_err(|_| anyhow::anyhow!("ephemeral X25519 public key is not 32 bytes"))?;
  let aad = binding.additional_data()?;
  let mut key = Zeroizing::new([0_u8; 32]);
  agreement::agree(
    &ephemeral,
    UnparsedPublicKey::new(&X25519, &recipient_public_key),
    (),
    |shared| {
      hkdf_sha256(&aad, shared, CATCHUP_DOMAIN, key.as_mut()).map_err(|_| ())?;
      Ok(())
    },
  )
  .map_err(|()| anyhow::anyhow!("X25519 catch-up agreement failed"))?;
  let cipher = Aes256GcmKey::new_from_slice(key.as_ref())?;
  let mut nonce = [0_u8; 12];
  random_fill(&mut nonce).context("failed to generate catch-up nonce")?;
  let plaintext_digest = sha256_digest(&plaintext);
  let plaintext_len = plaintext.len();
  let mut ciphertext = plaintext;
  cipher
    .seal_in_place_append_tag(nonce, &aad, &mut ciphertext)
    .map_err(|()| anyhow::anyhow!("failed to encrypt membership catch-up chunk"))?;
  let ciphertext_digest = sha256_digest(&ciphertext);
  Ok(SealedCatchupChunk {
    ephemeral_public_key,
    nonce,
    ciphertext,
    ciphertext_digest,
    plaintext_digest,
    plaintext_len,
  })
}

impl CatchupBinding<'_> {
  fn additional_data(&self) -> anyhow::Result<Vec<u8>> {
    let fields = [
      self.cluster_id,
      self.transition_id,
      self.member_id,
      self.source_epoch,
      self.target_epoch,
      CATCHUP_ALGORITHM,
    ];
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(CATCHUP_DOMAIN);
    output.extend_from_slice(&self.chunk_index.to_be_bytes());
    for field in fields {
      ensure!(
        !field.is_empty() && field.len() <= 256 && !field.chars().any(char::is_control),
        "membership catch-up binding field is invalid"
      );
      output.extend_from_slice(
        &u32::try_from(field.len())
          .context("membership catch-up binding field is too large")?
          .to_be_bytes(),
      );
      output.extend_from_slice(field.as_bytes());
    }
    Ok(output)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn catchup_ciphertext_is_recipient_and_transition_bound() {
    let learner = PrivateKey::generate(&X25519).expect("learner key");
    let public = learner.compute_public_key().expect("public key");
    let binding = CatchupBinding {
      cluster_id: "cluster-a",
      transition_id: "join-1",
      member_id: "member-c",
      source_epoch: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      target_epoch: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      chunk_index: 0,
    };
    let sealed = seal_catchup_chunk(
      &binding,
      &base64::engine::general_purpose::STANDARD.encode(public.as_ref()),
      Zeroizing::new(b"bounded-state".to_vec()),
    )
    .expect("seal");
    assert_eq!(sealed.plaintext_len, 13);
    assert_eq!(sealed.ciphertext.len(), 29);
    assert_ne!(sealed.ciphertext.as_slice(), b"bounded-state");
  }
}
