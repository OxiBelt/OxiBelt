//! Learner-scoped encryption for bounded membership catch-up artifacts.

use anyhow::{Context, ensure};
use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::crypto::{Aes256GcmKey, hkdf_sha256, random_fill};

use super::artifact::sha256_digest;

pub(crate) const CATCHUP_ALGORITHM: &str = "x25519-hkdf-sha256-aes-256-gcm-v1";
pub(crate) const EPOCH_KEY_WRAP_ALGORITHM: &str = "x25519-hkdf-sha256-aes-256-gcm-key-wrap-v1";
const CATCHUP_DOMAIN: &[u8] = b"OXIBELT-ADMIN-MEMBERSHIP-CATCHUP-V1\0";
const EPOCH_KEY_WRAP_DOMAIN: &[u8] = b"OXIBELT-ADMIN-MEMBERSHIP-EPOCH-KEY-WRAP-V1\0";
const MAX_CATCHUP_PLAINTEXT_BYTES: usize = 1024 * 1024;
const AES_GCM_TAG_BYTES: usize = 16;

#[derive(Clone, Copy)]
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

pub(crate) struct StoredCatchupChunk {
  pub(crate) ephemeral_public_key: Vec<u8>,
  pub(crate) nonce: Vec<u8>,
  pub(crate) ciphertext: Vec<u8>,
  pub(crate) ciphertext_digest: String,
  pub(crate) plaintext_len: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct EpochKeyBinding<'a> {
  pub(crate) cluster_id: &'a str,
  pub(crate) transition_id: &'a str,
  pub(crate) target_epoch: &'a str,
  pub(crate) member_id: &'a str,
  pub(crate) artifact_key_fingerprint: &'a str,
}

pub(crate) struct WrappedEpochKey {
  pub(crate) ephemeral_public_key: [u8; 32],
  pub(crate) nonce: [u8; 12],
  pub(crate) ciphertext: Zeroizing<Vec<u8>>,
  pub(crate) ciphertext_digest: String,
}

pub(crate) struct StoredEpochKeyWrap {
  pub(crate) ephemeral_public_key: Vec<u8>,
  pub(crate) nonce: Vec<u8>,
  pub(crate) ciphertext: Vec<u8>,
  pub(crate) ciphertext_digest: String,
}

struct SealedX25519 {
  ephemeral_public_key: [u8; 32],
  nonce: [u8; 12],
  ciphertext: Zeroizing<Vec<u8>>,
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

pub(crate) fn open_catchup_chunk(
  binding: &CatchupBinding<'_>,
  recipient_private_key: &[u8],
  stored: StoredCatchupChunk,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  ensure!(
    (1..=MAX_CATCHUP_PLAINTEXT_BYTES).contains(&stored.plaintext_len)
      && stored.ciphertext.len() == stored.plaintext_len + AES_GCM_TAG_BYTES,
    "stored membership catch-up chunk exceeds its authenticated bound"
  );
  ensure!(
    sha256_digest(&stored.ciphertext) == stored.ciphertext_digest,
    "stored membership catch-up ciphertext digest mismatch"
  );
  let aad = binding.additional_data()?;
  let mut plaintext = open_x25519(
    recipient_private_key,
    stored.ephemeral_public_key,
    stored.nonce,
    stored.ciphertext,
    &aad,
    CATCHUP_DOMAIN,
    "membership catch-up",
  )?;
  ensure!(
    plaintext.len() == stored.plaintext_len,
    "stored membership catch-up plaintext length mismatch"
  );
  plaintext.truncate(stored.plaintext_len);
  Ok(plaintext)
}

pub(crate) fn wrap_epoch_artifact_key(
  binding: &EpochKeyBinding<'_>,
  recipient_public_key_base64: &str,
  artifact_key: &[u8],
) -> anyhow::Result<WrappedEpochKey> {
  ensure!(
    artifact_key.len() == 32,
    "membership epoch artifact key must contain exactly 32 bytes"
  );
  let aad = binding.additional_data()?;
  let SealedX25519 {
    ephemeral_public_key,
    nonce,
    ciphertext,
  } = seal_x25519(
    recipient_public_key_base64,
    Zeroizing::new(artifact_key.to_vec()),
    &aad,
    EPOCH_KEY_WRAP_DOMAIN,
    "membership epoch artifact key",
  )?;
  let ciphertext_digest = sha256_digest(&ciphertext);
  Ok(WrappedEpochKey {
    ephemeral_public_key,
    nonce,
    ciphertext,
    ciphertext_digest,
  })
}

pub(crate) fn unwrap_epoch_artifact_key(
  binding: &EpochKeyBinding<'_>,
  recipient_private_key: &[u8],
  stored: StoredEpochKeyWrap,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
  ensure!(
    stored.ciphertext.len() == 32 + AES_GCM_TAG_BYTES,
    "stored membership epoch key wrap has an invalid length"
  );
  ensure!(
    sha256_digest(&stored.ciphertext) == stored.ciphertext_digest,
    "stored membership epoch key-wrap digest mismatch"
  );
  let aad = binding.additional_data()?;
  let plaintext = open_x25519(
    recipient_private_key,
    stored.ephemeral_public_key,
    stored.nonce,
    stored.ciphertext,
    &aad,
    EPOCH_KEY_WRAP_DOMAIN,
    "membership epoch artifact key",
  )?;
  let key: [u8; 32] = plaintext
    .as_slice()
    .try_into()
    .map_err(|_| anyhow::anyhow!("unwrapped membership epoch artifact key is not 32 bytes"))?;
  Ok(Zeroizing::new(key))
}

fn seal_x25519(
  recipient_public_key_base64: &str,
  plaintext: Zeroizing<Vec<u8>>,
  aad: &[u8],
  domain: &[u8],
  label: &str,
) -> anyhow::Result<SealedX25519> {
  let recipient_public_key = base64::engine::general_purpose::STANDARD
    .decode(recipient_public_key_base64)
    .with_context(|| format!("{label} recipient X25519 public key is not base64"))?;
  ensure!(
    recipient_public_key.len() == 32,
    "{label} recipient X25519 public key is not 32 bytes"
  );
  ensure!(
    base64::engine::general_purpose::STANDARD.encode(&recipient_public_key)
      == recipient_public_key_base64,
    "{label} recipient X25519 public key is not canonical base64"
  );
  let ephemeral = PrivateKey::generate(&X25519)
    .map_err(|_| anyhow::anyhow!("failed to generate ephemeral {label} X25519 key"))?;
  let public = ephemeral
    .compute_public_key()
    .map_err(|_| anyhow::anyhow!("failed to derive ephemeral {label} X25519 public key"))?;
  let ephemeral_public_key: [u8; 32] = public
    .as_ref()
    .try_into()
    .map_err(|_| anyhow::anyhow!("ephemeral {label} X25519 public key is not 32 bytes"))?;
  let mut key = Zeroizing::new([0_u8; 32]);
  agreement::agree(
    &ephemeral,
    UnparsedPublicKey::new(&X25519, &recipient_public_key),
    (),
    |shared| {
      hkdf_sha256(aad, shared, domain, key.as_mut()).map_err(|_| ())?;
      Ok(())
    },
  )
  .map_err(|()| anyhow::anyhow!("{label} X25519 agreement failed"))?;
  let cipher = Aes256GcmKey::new_from_slice(key.as_ref())?;
  let mut nonce = [0_u8; 12];
  random_fill(&mut nonce).with_context(|| format!("failed to generate {label} nonce"))?;
  let mut ciphertext = plaintext;
  cipher
    .seal_in_place_append_tag(nonce, aad, &mut ciphertext)
    .map_err(|()| anyhow::anyhow!("failed to encrypt {label}"))?;
  Ok(SealedX25519 {
    ephemeral_public_key,
    nonce,
    ciphertext,
  })
}

fn open_x25519(
  recipient_private_key: &[u8],
  ephemeral_public_key: Vec<u8>,
  nonce: Vec<u8>,
  ciphertext: Vec<u8>,
  aad: &[u8],
  domain: &[u8],
  label: &str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  ensure!(
    recipient_private_key.len() == 32,
    "{label} recipient X25519 private key is not 32 bytes"
  );
  ensure!(
    ephemeral_public_key.len() == 32,
    "stored {label} ephemeral X25519 public key is not 32 bytes"
  );
  let nonce: [u8; 12] = nonce
    .try_into()
    .map_err(|_| anyhow::anyhow!("stored {label} nonce is not 12 bytes"))?;
  let private = PrivateKey::from_private_key(&X25519, recipient_private_key)
    .map_err(|_| anyhow::anyhow!("{label} recipient X25519 private key is invalid"))?;
  let mut key = Zeroizing::new([0_u8; 32]);
  agreement::agree(
    &private,
    UnparsedPublicKey::new(&X25519, ephemeral_public_key),
    (),
    |shared| {
      hkdf_sha256(aad, shared, domain, key.as_mut()).map_err(|_| ())?;
      Ok(())
    },
  )
  .map_err(|()| anyhow::anyhow!("{label} X25519 agreement failed"))?;
  let cipher = Aes256GcmKey::new_from_slice(key.as_ref())?;
  let mut plaintext = Zeroizing::new(ciphertext);
  let opened_len = cipher
    .open_in_place(nonce, aad, &mut plaintext)
    .map_err(|()| anyhow::anyhow!("{label} authentication failed"))?
    .len();
  plaintext.truncate(opened_len);
  Ok(plaintext)
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

impl EpochKeyBinding<'_> {
  fn additional_data(&self) -> anyhow::Result<Vec<u8>> {
    let fields = [
      self.cluster_id,
      self.transition_id,
      self.target_epoch,
      self.member_id,
      self.artifact_key_fingerprint,
      EPOCH_KEY_WRAP_ALGORITHM,
    ];
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(EPOCH_KEY_WRAP_DOMAIN);
    for field in fields {
      ensure!(
        !field.is_empty() && field.len() <= 256 && !field.chars().any(char::is_control),
        "membership epoch key binding field is invalid"
      );
      output.extend_from_slice(
        &u32::try_from(field.len())
          .context("membership epoch key binding field is too large")?
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

  fn stored_catchup(sealed: &SealedCatchupChunk) -> StoredCatchupChunk {
    StoredCatchupChunk {
      ephemeral_public_key: sealed.ephemeral_public_key.to_vec(),
      nonce: sealed.nonce.to_vec(),
      ciphertext: sealed.ciphertext.to_vec(),
      ciphertext_digest: sealed.ciphertext_digest.clone(),
      plaintext_len: sealed.plaintext_len,
    }
  }

  fn stored_epoch_key(wrapped: &WrappedEpochKey) -> StoredEpochKeyWrap {
    StoredEpochKeyWrap {
      ephemeral_public_key: wrapped.ephemeral_public_key.to_vec(),
      nonce: wrapped.nonce.to_vec(),
      ciphertext: wrapped.ciphertext.to_vec(),
      ciphertext_digest: wrapped.ciphertext_digest.clone(),
    }
  }

  #[test]
  fn catchup_ciphertext_is_recipient_and_transition_bound() {
    let private = [7_u8; 32];
    let learner = PrivateKey::from_private_key(&X25519, &private).expect("learner key");
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
    let opened = open_catchup_chunk(
      &binding,
      &private,
      StoredCatchupChunk {
        ephemeral_public_key: sealed.ephemeral_public_key.to_vec(),
        nonce: sealed.nonce.to_vec(),
        ciphertext: sealed.ciphertext.to_vec(),
        ciphertext_digest: sealed.ciphertext_digest,
        plaintext_len: sealed.plaintext_len,
      },
    )
    .expect("open");
    assert_eq!(opened.as_slice(), b"bounded-state");
  }

  #[test]
  fn catchup_rejects_the_wrong_recipient_or_binding() {
    let private = [9_u8; 32];
    let learner = PrivateKey::from_private_key(&X25519, &private).expect("learner key");
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
      Zeroizing::new(b"checkpoint".to_vec()),
    )
    .expect("seal");
    assert!(open_catchup_chunk(&binding, &[10_u8; 32], stored_catchup(&sealed)).is_err());

    for changed in [
      CatchupBinding {
        cluster_id: "cluster-b",
        ..binding
      },
      CatchupBinding {
        transition_id: "join-2",
        ..binding
      },
      CatchupBinding {
        member_id: "member-d",
        ..binding
      },
      CatchupBinding {
        source_epoch: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ..binding
      },
      CatchupBinding {
        target_epoch: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ..binding
      },
      CatchupBinding {
        chunk_index: 1,
        ..binding
      },
    ] {
      assert!(open_catchup_chunk(&changed, &private, stored_catchup(&sealed)).is_err());
    }

    let mut ephemeral = stored_catchup(&sealed);
    ephemeral.ephemeral_public_key[0] ^= 1;
    assert!(open_catchup_chunk(&binding, &private, ephemeral).is_err());
    let mut nonce = stored_catchup(&sealed);
    nonce.nonce[0] ^= 1;
    assert!(open_catchup_chunk(&binding, &private, nonce).is_err());
    let mut ciphertext = stored_catchup(&sealed);
    ciphertext.ciphertext[0] ^= 1;
    ciphertext.ciphertext_digest = sha256_digest(&ciphertext.ciphertext);
    assert!(open_catchup_chunk(&binding, &private, ciphertext).is_err());
    let mut tag = stored_catchup(&sealed);
    let last = tag.ciphertext.len() - 1;
    tag.ciphertext[last] ^= 1;
    tag.ciphertext_digest = sha256_digest(&tag.ciphertext);
    assert!(open_catchup_chunk(&binding, &private, tag).is_err());
    let mut digest = stored_catchup(&sealed);
    digest.ciphertext_digest =
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    assert!(open_catchup_chunk(&binding, &private, digest).is_err());
    let mut length = stored_catchup(&sealed);
    length.plaintext_len += 1;
    assert!(open_catchup_chunk(&binding, &private, length).is_err());
    let empty_ciphertext = vec![0_u8; AES_GCM_TAG_BYTES];
    assert!(
      open_catchup_chunk(
        &binding,
        &private,
        StoredCatchupChunk {
          ephemeral_public_key: sealed.ephemeral_public_key.to_vec(),
          nonce: sealed.nonce.to_vec(),
          ciphertext_digest: sha256_digest(&empty_ciphertext),
          ciphertext: empty_ciphertext,
          plaintext_len: 0,
        },
      )
      .is_err()
    );
  }

  #[test]
  fn epoch_artifact_key_wrap_is_recipient_and_epoch_bound() {
    let private = [11_u8; 32];
    let member = PrivateKey::from_private_key(&X25519, &private).expect("member key");
    let public = member.compute_public_key().expect("public key");
    let binding = EpochKeyBinding {
      cluster_id: "cluster-a",
      transition_id: "join-1",
      target_epoch: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      member_id: "member-c",
      artifact_key_fingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    };
    let wrapped = wrap_epoch_artifact_key(
      &binding,
      &base64::engine::general_purpose::STANDARD.encode(public.as_ref()),
      &[42_u8; 32],
    )
    .expect("wrap");
    let opened =
      unwrap_epoch_artifact_key(&binding, &private, stored_epoch_key(&wrapped)).expect("unwrap");
    assert_eq!(opened.as_ref(), &[42_u8; 32]);

    assert!(unwrap_epoch_artifact_key(&binding, &[12_u8; 32], stored_epoch_key(&wrapped)).is_err());
    for changed in [
      EpochKeyBinding {
        cluster_id: "cluster-b",
        ..binding
      },
      EpochKeyBinding {
        transition_id: "join-2",
        ..binding
      },
      EpochKeyBinding {
        target_epoch: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ..binding
      },
      EpochKeyBinding {
        member_id: "member-d",
        ..binding
      },
      EpochKeyBinding {
        artifact_key_fingerprint: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ..binding
      },
    ] {
      assert!(unwrap_epoch_artifact_key(&changed, &private, stored_epoch_key(&wrapped)).is_err());
    }
    let mut ephemeral = stored_epoch_key(&wrapped);
    ephemeral.ephemeral_public_key[0] ^= 1;
    assert!(unwrap_epoch_artifact_key(&binding, &private, ephemeral).is_err());
    let mut nonce = stored_epoch_key(&wrapped);
    nonce.nonce[0] ^= 1;
    assert!(unwrap_epoch_artifact_key(&binding, &private, nonce).is_err());
    let mut ciphertext = stored_epoch_key(&wrapped);
    ciphertext.ciphertext[0] ^= 1;
    ciphertext.ciphertext_digest = sha256_digest(&ciphertext.ciphertext);
    assert!(unwrap_epoch_artifact_key(&binding, &private, ciphertext).is_err());
    let mut tag = stored_epoch_key(&wrapped);
    let last = tag.ciphertext.len() - 1;
    tag.ciphertext[last] ^= 1;
    tag.ciphertext_digest = sha256_digest(&tag.ciphertext);
    assert!(unwrap_epoch_artifact_key(&binding, &private, tag).is_err());
    let mut digest = stored_epoch_key(&wrapped);
    digest.ciphertext_digest =
      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    assert!(unwrap_epoch_artifact_key(&binding, &private, digest).is_err());
    let mut length = stored_epoch_key(&wrapped);
    length.ciphertext.pop();
    length.ciphertext_digest = sha256_digest(&length.ciphertext);
    assert!(unwrap_epoch_artifact_key(&binding, &private, length).is_err());
  }
}
