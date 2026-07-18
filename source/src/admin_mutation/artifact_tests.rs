use super::*;

fn binding(plaintext: &[u8]) -> ArtifactBinding {
  ArtifactBinding {
    namespace: "edge".to_string(),
    request_id: "00000000-0000-4000-8000-000000000001".to_string(),
    fingerprint: sha256_digest(b"signed-transcript"),
    principal: "controller".to_string(),
    signer_id: "controller-1".to_string(),
    action: "config.load".to_string(),
    resource: "config".to_string(),
    cluster_id: "edge-cluster".to_string(),
    membership_revision: sha256_digest(b"edge-a,edge-b"),
    new_revision: "r-2".to_string(),
    expected_previous_revision: "r-1".to_string(),
    content_digest: sha256_digest(plaintext),
  }
}

fn stored(binding: ArtifactBinding, sealed: SealedArtifact) -> StoredArtifact {
  StoredArtifact {
    binding,
    nonce: sealed.nonce.to_vec(),
    ciphertext: sealed.ciphertext.to_vec(),
    ciphertext_digest: sealed.ciphertext_digest,
    plaintext_len: sealed.plaintext_len,
  }
}

#[test]
fn exact_artifact_round_trips_and_debug_output_is_redacted() {
  let bytes = br#"{"secret_reference":"vault://edge/key"}"#;
  let binding = binding(bytes);
  let cipher = MutationArtifactCipher::new(&[7; 32], 1024).expect("test artifact cipher");
  let plaintext = MutationArtifactPlaintext::new(bytes.to_vec());
  assert!(!format!("{plaintext:?}").contains("vault"));
  let sealed = cipher
    .seal_with_nonce(&binding, plaintext, [3; ARTIFACT_NONCE_BYTES])
    .expect("seal exact artifact");
  assert_ne!(sealed.ciphertext.as_slice(), bytes);
  let opened = cipher
    .open(&binding, stored(binding.clone(), sealed))
    .expect("open exact artifact");
  assert_eq!(opened.as_bytes(), bytes);
}

#[test]
fn ciphertext_and_binding_tampering_fail_authentication() {
  let bytes = b"exact mutation bytes";
  let original_binding = binding(bytes);
  let cipher = MutationArtifactCipher::new(&[9; 32], 1024).expect("test artifact cipher");

  let sealed = cipher
    .seal_with_nonce(
      &original_binding,
      MutationArtifactPlaintext::new(bytes.to_vec()),
      [4; ARTIFACT_NONCE_BYTES],
    )
    .expect("seal exact artifact");
  let mut tampered = stored(original_binding.clone(), sealed);
  tampered.ciphertext[0] ^= 0x80;
  tampered.ciphertext_digest = sha256_digest(&tampered.ciphertext);
  assert!(cipher.open(&original_binding, tampered).is_err());

  let sealed = cipher
    .seal_with_nonce(
      &original_binding,
      MutationArtifactPlaintext::new(bytes.to_vec()),
      [5; ARTIFACT_NONCE_BYTES],
    )
    .expect("seal exact artifact");
  let mut changed_binding = original_binding.clone();
  changed_binding.resource = "ipm".to_string();
  assert!(
    cipher
      .open(&changed_binding, stored(changed_binding.clone(), sealed))
      .is_err()
  );
}

#[test]
fn size_and_signed_content_digest_are_enforced_before_encryption() {
  let cipher = MutationArtifactCipher::new(&[11; 32], 4).expect("bounded cipher");
  let oversized = b"12345";
  assert!(
    cipher
      .seal(
        &binding(oversized),
        MutationArtifactPlaintext::new(oversized.to_vec())
      )
      .is_err()
  );

  let mut wrong_digest = binding(b"right");
  wrong_digest.content_digest = sha256_digest(b"wrong");
  assert!(
    cipher
      .seal(
        &wrong_digest,
        MutationArtifactPlaintext::new(b"right".to_vec()),
      )
      .is_err()
  );
}

#[test]
fn artifact_aad_is_unambiguous_across_field_boundaries() {
  let mut left = binding(b"body");
  left.resource = "ab".to_string();
  left.cluster_id = "c".to_string();
  let mut right = left.clone();
  right.resource = "a".to_string();
  right.cluster_id = "bc".to_string();
  assert_ne!(
    left.additional_data().expect("left AAD"),
    right.additional_data().expect("right AAD")
  );
}

#[test]
fn artifact_key_fingerprint_is_stable_and_domain_separated() {
  let first = MutationArtifactCipher::new(&[7; 32], 1024).expect("first cipher");
  let same = MutationArtifactCipher::new(&[7; 32], 1024).expect("same cipher");
  let different = MutationArtifactCipher::new(&[8; 32], 1024).expect("different cipher");
  assert_eq!(first.key_fingerprint(), same.key_fingerprint());
  assert_ne!(first.key_fingerprint(), different.key_fingerprint());
  assert_ne!(first.key_fingerprint(), sha256_digest(&[7; 32]));
}
