use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine;

use super::protocol::{RemoteSignerRequest, RemoteSignerResponse, SignContext};
use super::*;

const TEST_TOKEN: [u8; 32] = [7u8; 32];
const ROTATED_TEST_TOKEN: [u8; 32] = [9u8; 32];

#[test]
fn tls13_server_certificate_verify_detection_is_strict() {
  let mut message = vec![b' '; 64];
  message.extend_from_slice(TLS13_SERVER_CERT_VERIFY_CONTEXT);
  message.extend_from_slice(&[7u8; 32]);
  assert!(is_tls13_server_certificate_verify_message(&message));

  message[0] = b'!';
  assert!(!is_tls13_server_certificate_verify_message(&message));
}

#[test]
fn audit_checkpoint_requests_are_purpose_bound_and_sign_only_domain_bound_digests() {
  crate::tls::install_default_provider().expect("crypto provider should install");
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let tls_key_path = temp_dir.path().join("tls-ed25519.pem");
  let audit_key_path = temp_dir.path().join("audit-ed25519.pem");
  write_test_ed25519_private_key(&tls_key_path);
  write_test_ed25519_private_key(&audit_key_path);
  let tls_keys = load_server_keys(&[("tls-key".to_string(), tls_key_path)])
    .expect("Ed25519 key should load for TLS");
  let audit_keys = load_audit_checkpoint_keys(&[("audit-key".to_string(), audit_key_path)])
    .expect("Ed25519 key should load for audit checkpoints");
  let token_provider = test_token_provider();

  assert!(matches!(
    process_request_with_audit_keys(
      RemoteSignerRequest::DescribeKey {
        token: test_token(),
        key_id: "audit-key".to_string(),
      },
      &tls_keys,
      &audit_keys,
      None,
      &token_provider,
      true,
    ),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_key"
  ));
  assert!(matches!(
    process_request_with_audit_keys(
      RemoteSignerRequest::DescribeAuditCheckpointKey {
        token: test_token(),
        key_id: "tls-key".to_string(),
      },
      &tls_keys,
      &audit_keys,
      None,
      &token_provider,
      true,
    ),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_audit_checkpoint_key"
  ));

  let digest = [0x5au8; 32];
  let response = process_request_with_audit_keys(
    RemoteSignerRequest::SignAuditCheckpointDigest {
      token: test_token(),
      key_id: "audit-key".to_string(),
      digest: base64::engine::general_purpose::STANDARD.encode(digest),
    },
    &tls_keys,
    &audit_keys,
    None,
    &token_provider,
    true,
  );
  let RemoteSignerResponse::SignAuditCheckpointDigest { signature } = response else {
    panic!("valid audit digest should produce a purpose-specific signature");
  };
  let signature = base64::engine::general_purpose::STANDARD
    .decode(signature)
    .expect("signature should decode");
  aws_lc_rs::signature::UnparsedPublicKey::new(
    &aws_lc_rs::signature::ED25519,
    audit_keys["audit-key"].public_key,
  )
  .verify(&audit_checkpoint::signing_message(&digest), &signature)
  .expect("signature must cover the fixed audit domain and digest");
}

#[test]
fn audit_checkpoint_digest_rejects_non_32_byte_inputs() {
  crate::tls::install_default_provider().expect("crypto provider should install");
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let key_path = temp_dir.path().join("audit-ed25519.pem");
  write_test_ed25519_private_key(&key_path);
  let audit_keys = load_audit_checkpoint_keys(&[("audit-key".to_string(), key_path)])
    .expect("Ed25519 key should load for audit checkpoints");
  let token_provider = test_token_provider();

  for digest in [
    "not-base64".to_string(),
    base64::engine::general_purpose::STANDARD.encode([0u8; 31]),
    base64::engine::general_purpose::STANDARD.encode([0u8; 33]),
  ] {
    assert!(matches!(
      process_request_with_audit_keys(
        RemoteSignerRequest::SignAuditCheckpointDigest {
          token: test_token(),
          key_id: "audit-key".to_string(),
          digest,
        },
        &HashMap::new(),
        &audit_keys,
        None,
        &token_provider,
        false,
      ),
      RemoteSignerResponse::Error { code, .. } if code == "invalid_audit_checkpoint_digest"
    ));
  }
}

#[test]
fn ct_log_keys_are_purpose_bound_and_profiles_are_immutable() {
  crate::tls::install_default_provider().expect("crypto provider should install");
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let ct_key_path = temp_dir.path().join("ct-ed25519.pem");
  let tls_key_path = temp_dir.path().join("tls-ed25519.pem");
  write_test_ed25519_private_key(&ct_key_path);
  write_test_ed25519_private_key(&tls_key_path);
  let ct_key = load_ct_log_key("ct-key", CtLogProfile::Rfc9162Ed25519, &ct_key_path)
    .expect("Ed25519 key should load for RFC 9162 CT");
  let tls_keys =
    load_server_keys(&[("tls-key".to_string(), tls_key_path)]).expect("TLS key should load");
  let token_provider = test_token_provider();

  assert!(matches!(
    process_request_with_audit_keys(
      RemoteSignerRequest::DescribeKey { token: test_token(), key_id: "ct-key".to_string() },
      &HashMap::new(), &HashMap::new(), Some(&ct_key), &token_provider, false,
    ),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_key"
  ));
  assert!(matches!(
    process_request_with_audit_keys(
      RemoteSignerRequest::DescribeCtLogKey { token: test_token(), key_id: "tls-key".to_string() },
      &tls_keys, &HashMap::new(), None, &token_provider, false,
    ),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_ct_log_key"
  ));
  assert!(matches!(
    process_request_with_audit_keys(
      RemoteSignerRequest::DescribeCtLogKey { token: token_to_wire(&[0u8; 32]), key_id: "ct-key".to_string() },
      &HashMap::new(), &HashMap::new(), Some(&ct_key), &token_provider, false,
    ),
    RemoteSignerResponse::Error { code, .. } if code == "unauthorized"
  ));

  let mismatch = load_ct_log_key(
    "wrong-profile",
    CtLogProfile::Rfc6962P256Sha256,
    &ct_key_path,
  )
  .expect_err("Ed25519 must not activate a P-256 CT profile");
  assert!(mismatch.to_string().contains("P-256"));
}

#[test]
fn ct_log_signer_accepts_only_canonical_bounded_transcripts_and_signs_ed25519() {
  crate::tls::install_default_provider().expect("crypto provider should install");
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let key_path = temp_dir.path().join("ct-ed25519.pem");
  write_test_ed25519_private_key(&key_path);
  let key =
    load_ct_log_key("ct-key", CtLogProfile::Rfc9162Ed25519, &key_path).expect("CT key should load");
  let token_provider = test_token_provider();
  let transcript = ct_sth_transcript(1, 1);
  let response = process_request_with_audit_keys(
    RemoteSignerRequest::SignCtLogTranscript {
      token: test_token(),
      key_id: "ct-key".to_string(),
      transcript_class: CtTranscriptClass::V2Sth,
      transcript: base64::engine::general_purpose::STANDARD.encode(&transcript),
    },
    &HashMap::new(),
    &HashMap::new(),
    Some(&key),
    &token_provider,
    false,
  );
  let RemoteSignerResponse::SignCtLogTranscript { signature } = response else {
    panic!("valid RFC 9162 STH must be signed");
  };
  let signature = base64::engine::general_purpose::STANDARD
    .decode(signature)
    .expect("signature should decode");
  let raw_public_key =
    keys::ed25519_public_key_from_spki(&key.public_key).expect("Ed25519 SPKI should normalize");
  aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, raw_public_key)
    .verify(&transcript, &signature)
    .expect("signature must verify over the exact CT transcript");

  for (class, transcript) in [
    (CtTranscriptClass::V2Sth, Vec::new()),
    (CtTranscriptClass::V2Sth, vec![1, 1]),
    (CtTranscriptClass::V1Sth, ct_sth_transcript(0, 1)),
    (
      CtTranscriptClass::V2Sth,
      vec![1; MAX_CT_TRANSCRIPT_BYTES + 1],
    ),
  ] {
    assert!(matches!(
      process_request_with_audit_keys(
        RemoteSignerRequest::SignCtLogTranscript {
          token: test_token(), key_id: "ct-key".to_string(), transcript_class: class,
          transcript: base64::engine::general_purpose::STANDARD.encode(transcript),
        },
        &HashMap::new(), &HashMap::new(), Some(&key), &token_provider, false,
      ),
      RemoteSignerResponse::Error { code, .. } if code == "invalid_ct_transcript"
    ));
  }
}

#[test]
fn ct_log_signer_signs_p256_rfc6962_tree_heads() {
  crate::tls::install_default_provider().expect("crypto provider should install");
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let key_path = temp_dir.path().join("ct-p256.pem");
  write_test_p256_private_key(&key_path);
  let key = load_ct_log_key("ct-p256", CtLogProfile::Rfc6962P256Sha256, &key_path)
    .expect("P-256 key should load for RFC 6962 CT");
  let response = process_request_with_audit_keys(
    RemoteSignerRequest::SignCtLogTranscript {
      token: test_token(),
      key_id: "ct-p256".to_string(),
      transcript_class: CtTranscriptClass::V1Sth,
      transcript: base64::engine::general_purpose::STANDARD.encode(ct_sth_transcript(0, 1)),
    },
    &HashMap::new(),
    &HashMap::new(),
    Some(&key),
    &test_token_provider(),
    false,
  );
  let RemoteSignerResponse::SignCtLogTranscript { signature } = response else {
    panic!("valid RFC 6962 STH must be signed by P-256 key");
  };
  let signature = base64::engine::general_purpose::STANDARD
    .decode(signature)
    .expect("P-256 signature should decode");
  assert!(!signature.is_empty() && signature.len() <= 80);
  assert_eq!(key.public_key.len(), 91, "P-256 key must advertise SPKI");
  aws_lc_rs::signature::UnparsedPublicKey::new(
    &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
    &key.public_key[26..],
  )
  .verify(&ct_sth_transcript(0, 1), &signature)
  .expect("P-256 signature must verify over the exact CT transcript");
}

#[test]
fn server_rejects_empty_and_mixed_purpose_keysets() {
  assert!(validate_server_key_sets(&HashMap::new(), &HashMap::new(), None).is_err());

  crate::tls::install_default_provider().expect("crypto provider should install");
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let key_path = temp_dir.path().join("shared-ed25519.pem");
  write_test_ed25519_private_key(&key_path);
  let tls_keys =
    load_server_keys(&[("shared".to_string(), key_path.clone())]).expect("TLS key should load");
  let audit_keys = load_audit_checkpoint_keys(&[("shared".to_string(), key_path.clone())])
    .expect("audit key should load");
  let error = validate_server_key_sets(&tls_keys, &audit_keys, None)
    .expect_err("one authentication boundary must not span purposes");
  assert!(error.to_string().contains("purpose-exclusive"));

  let ct_key =
    load_ct_log_key("ct-key", CtLogProfile::Rfc9162Ed25519, &key_path).expect("CT key should load");
  validate_server_key_sets(&HashMap::new(), &HashMap::new(), Some(&ct_key))
    .expect("one CT purpose should activate");
  let error = validate_server_key_sets(&tls_keys, &HashMap::new(), Some(&ct_key))
    .expect_err("TLS and CT keys require separate daemons");
  assert!(error.to_string().contains("purpose-exclusive"));

  let tls_keys = load_server_keys(&[("tls-key".to_string(), key_path.clone())])
    .expect("TLS key should load under a distinct id");
  let audit_keys = load_audit_checkpoint_keys(&[("audit-key".to_string(), key_path)])
    .expect("audit key should load under a distinct id");
  let error = validate_server_key_sets(&tls_keys, &audit_keys, None)
    .expect_err("distinct key material still requires isolated daemons");
  assert!(error.to_string().contains("purpose-exclusive"));
}

#[tokio::test]
async fn async_audit_client_connects_to_an_audit_only_daemon() {
  crate::tls::install_default_provider().expect("crypto provider should install");
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let socket_path = temp_dir.path().join("audit-signer.sock");
  let key_path = temp_dir.path().join("audit-ed25519.pem");
  let token_path = temp_dir.path().join("token.b64");
  write_test_ed25519_private_key(&key_path);
  write_token_file(&token_path, &TEST_TOKEN);
  let config = SignerServerConfig {
    socket_path: socket_path.clone(),
    socket_mode: 0o600,
    keys: Vec::new(),
    ct_log_key: None,
    token_env: "UNUSED_TOKEN_ENV".to_string(),
    token_file: Some(token_path.clone()),
    token_reload_interval: Duration::from_millis(10),
    max_connections: 4,
    io_timeout: Duration::from_secs(1),
    allow_peer_uids: Vec::new(),
    allow_peer_gids: Vec::new(),
    allow_tls12_unstructured_signing: false,
  };
  let server = tokio::spawn(serve_with_audit_checkpoint_keys(
    config,
    vec![("audit-key".to_string(), key_path)],
  ));
  for _ in 0..100 {
    if socket_path.exists() {
      break;
    }
    assert!(
      !server.is_finished(),
      "audit-only daemon exited before bind"
    );
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(1)).await;
  }
  assert!(
    socket_path.exists(),
    "audit-only daemon must bind its socket"
  );

  let client = AuditCheckpointSigner::connect(AuditCheckpointSignerConfig {
    socket_path,
    key_id: "audit-key".to_string(),
    token_env: "UNUSED_TOKEN_ENV".to_string(),
    token_file: Some(token_path),
    token_file_reload_base_dir: None,
    token_reload_interval: Duration::from_millis(10),
    connect_timeout: Duration::from_secs(1),
    sign_timeout: Duration::from_secs(1),
  })
  .await
  .expect("audit client should activate against an audit-only daemon");
  assert_eq!(client.key_id(), "audit-key");
  assert_eq!(client.public_key().len(), 32);

  let digest = [0xa5; 32];
  let signature = client
    .sign_digest(&digest)
    .await
    .expect("digest signing should succeed");
  aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, client.public_key())
    .verify(&audit_checkpoint::signing_message(&digest), &signature)
    .expect("client signature must verify under the described raw key");

  server.abort();
  let _ = server.await;
}

#[tokio::test]
async fn async_ct_client_connects_to_a_ct_only_daemon_and_signs() {
  crate::tls::install_default_provider().expect("crypto provider should install");
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let socket_path = temp_dir.path().join("ct-signer.sock");
  let key_path = temp_dir.path().join("ct-ed25519.pem");
  let token_path = temp_dir.path().join("token.b64");
  write_test_ed25519_private_key(&key_path);
  write_token_file(&token_path, &TEST_TOKEN);
  let config = SignerServerConfig {
    socket_path: socket_path.clone(),
    socket_mode: 0o600,
    keys: Vec::new(),
    ct_log_key: Some(("ct-key".to_string(), CtLogProfile::Rfc9162Ed25519, key_path)),
    token_env: "UNUSED_TOKEN_ENV".to_string(),
    token_file: Some(token_path.clone()),
    token_reload_interval: Duration::from_millis(10),
    max_connections: 4,
    io_timeout: Duration::from_secs(1),
    allow_peer_uids: Vec::new(),
    allow_peer_gids: Vec::new(),
    allow_tls12_unstructured_signing: false,
  };
  let server = tokio::spawn(serve_with_audit_checkpoint_keys(config, Vec::new()));
  for _ in 0..100 {
    if socket_path.exists() {
      break;
    }
    assert!(!server.is_finished(), "CT-only daemon exited before bind");
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(1)).await;
  }
  assert!(socket_path.exists(), "CT-only daemon must bind its socket");

  let client = CtLogSigner::connect(CtLogSignerConfig {
    socket_path,
    key_id: "ct-key".to_string(),
    profile: CtLogProfile::Rfc9162Ed25519,
    token_env: "UNUSED_TOKEN_ENV".to_string(),
    token_file: Some(token_path),
    token_file_reload_base_dir: None,
    token_reload_interval: Duration::from_millis(10),
    connect_timeout: Duration::from_secs(1),
    sign_timeout: Duration::from_secs(1),
  })
  .await
  .expect("CT client should activate against a CT-only daemon");
  assert_eq!(client.key_id(), "ct-key");
  assert_eq!(client.profile(), CtLogProfile::Rfc9162Ed25519);
  let transcript = ct_sth_transcript(1, 1);
  let signature = client
    .sign_transcript(CtTranscriptClass::V2Sth, &transcript)
    .await
    .expect("canonical RFC 9162 tree-head signing should succeed");
  let raw_public_key = keys::ed25519_public_key_from_spki(client.public_key_spki())
    .expect("CT signer must advertise Ed25519 SPKI");
  aws_lc_rs::signature::UnparsedPublicKey::new(&aws_lc_rs::signature::ED25519, raw_public_key)
    .verify(&transcript, &signature)
    .expect("client signature must verify over the exact CT transcript");
  assert!(
    client
      .sign_transcript(CtTranscriptClass::V1Sth, &ct_sth_transcript(0, 1))
      .await
      .is_err()
  );

  server.abort();
  let _ = server.await;
}

#[test]
fn pooled_client_reuses_socket_for_describe_key_then_sign() {
  let (client, connects) = test_client(1, Duration::from_secs(5));
  let mut request_kinds = Vec::new();

  let describe = client
    .request_with_transport(describe_request(), |_, request| {
      request_kinds.push(request_kind(request).to_string());
      Ok(ok_response())
    })
    .expect("describe_key should complete");
  assert!(matches!(describe, RemoteSignerResponse::Error { .. }));

  let sign = client
    .request_with_transport(sign_request(), |_, request| {
      request_kinds.push(request_kind(request).to_string());
      Ok(ok_response())
    })
    .expect("sign should complete on the pooled socket");
  assert!(matches!(sign, RemoteSignerResponse::Error { .. }));

  assert_eq!(connects.load(Ordering::SeqCst), 1);
  assert_eq!(
    request_kinds,
    vec!["describe_key".to_string(), "sign".to_string()]
  );
}

#[test]
fn pool_max_idle_zero_opens_fresh_socket_per_request() {
  let (client, connects) = test_client(0, Duration::from_secs(5));

  for _ in 0..2 {
    client
      .request_with_transport(describe_request(), |_, _| Ok(ok_response()))
      .expect("describe_key should complete");
  }

  assert_eq!(connects.load(Ordering::SeqCst), 2);
}

#[test]
fn stale_pooled_socket_is_discarded_and_retried_once() {
  let (client, connects) = test_client(1, Duration::from_secs(5));
  let mut attempts = 0usize;

  client
    .request_with_transport(describe_request(), |_, _| {
      attempts += 1;
      Ok(ok_response())
    })
    .expect("first request should complete");
  client
    .request_with_transport(describe_request(), |_, _| {
      attempts += 1;
      if attempts == 2 {
        Err(anyhow::anyhow!("stale pooled socket"))
      } else {
        Ok(ok_response())
      }
    })
    .expect("second request should retry on a fresh socket");

  assert_eq!(attempts, 3);
  assert_eq!(connects.load(Ordering::SeqCst), 2);
}

#[test]
fn pool_discards_sockets_idle_longer_than_sign_timeout() {
  let pool = RemoteSignerConnectionPool::new(1);
  let (stream, _peer) = UnixStream::pair().expect("Unix stream pair should create");
  pool.put(stream);
  std::thread::sleep(Duration::from_millis(5));

  assert!(pool.take(Duration::from_millis(1)).is_none());
}

#[test]
fn socket_mode_allows_private_modes_and_rejects_world_access() {
  validate_socket_mode(0o600).expect("0600 should be accepted");
  validate_socket_mode(0o660).expect("0660 should be accepted");
  let error = validate_socket_mode(0o666).expect_err("world-accessible sockets must be rejected");
  assert!(
    error.to_string().contains("0600 or 0660"),
    "unexpected error: {error}"
  );
}

#[test]
fn peer_uid_or_gid_allowlist_controls_socket_access() {
  assert!(peer_credentials_are_allowed(10001, 10001, &[10001], &[]));
  assert!(peer_credentials_are_allowed(10001, 10002, &[], &[10002]));
  assert!(!peer_credentials_are_allowed(
    10001,
    10001,
    &[10002],
    &[10003]
  ));
}

#[test]
fn token_file_provider_reloads_and_preserves_last_good_token() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  write_token_file(&token_file, &TEST_TOKEN);
  let provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    None,
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
  )
  .expect("initial token file should load");

  assert_eq!(provider.current_token(), TEST_TOKEN);

  write_token_file(&token_file, &ROTATED_TEST_TOKEN);
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(provider.current_token(), ROTATED_TEST_TOKEN);

  std::fs::write(&token_file, b"not-base64").expect("invalid token should write");
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(
    provider.current_token(),
    ROTATED_TEST_TOKEN,
    "invalid rotations should preserve the last good token"
  );
}

#[test]
fn pinned_token_file_is_verified_at_the_consumer_read() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  write_token_file(&token_file, &TEST_TOKEN);
  let raw = std::fs::read(&token_file).expect("token fixture should be readable");
  let expected = crate::crypto::sha256(&raw)
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
  let provider = RemoteSignerTokenProvider::from_sources_with_reload(
    Some(PathBuf::from("keysigner-token.b64")),
    Some(temp_dir.path().to_path_buf()),
    Some(&expected),
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
    false,
  )
  .expect("matching token pin should load");
  assert_eq!(provider.current_token(), TEST_TOKEN);
  assert!(!provider.reloadable());

  let error = RemoteSignerTokenProvider::from_sources_with_reload(
    Some(token_file),
    None,
    Some(&"0".repeat(64)),
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
    false,
  )
  .expect_err("mismatched token pin must fail before activation");
  assert!(error.to_string().contains("digest"));
}

#[test]
fn token_file_provider_follows_symlink_retargets_with_base_guard() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  let first_target = temp_dir.path().join("token-a.b64");
  let rotated_target = temp_dir.path().join("token-b.b64");
  write_token_file(&first_target, &TEST_TOKEN);
  write_token_file(&rotated_target, &ROTATED_TEST_TOKEN);
  replace_symlink("token-a.b64", &token_file);
  let provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    Some(temp_dir.path().to_path_buf()),
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
  )
  .expect("initial symlinked token file should load");

  assert_eq!(provider.current_token(), TEST_TOKEN);

  replace_symlink("token-b.b64", &token_file);
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(provider.current_token(), ROTATED_TEST_TOKEN);
}

#[test]
fn token_file_provider_preserves_last_good_token_for_unsafe_symlink_retargets() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_dir = temp_dir.path().join("tokens");
  let outside_dir = temp_dir.path().join("outside");
  std::fs::create_dir_all(&token_dir).expect("token dir should create");
  std::fs::create_dir_all(&outside_dir).expect("outside dir should create");
  let token_file = token_dir.join("keysigner-token.b64");
  let first_target = token_dir.join("token-a.b64");
  let invalid_target = token_dir.join("token-invalid.b64");
  let outside_target = outside_dir.join("token-outside.b64");
  write_token_file(&first_target, &TEST_TOKEN);
  std::fs::write(&invalid_target, b"not-base64").expect("invalid token should write");
  write_token_file(&outside_target, &ROTATED_TEST_TOKEN);
  replace_symlink("token-a.b64", &token_file);
  let provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    Some(token_dir.clone()),
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
  )
  .expect("initial symlinked token file should load");

  replace_symlink("token-invalid.b64", &token_file);
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(
    provider.current_token(),
    TEST_TOKEN,
    "invalid symlink retargets should preserve the last good token"
  );

  replace_symlink(&outside_target, &token_file);
  std::thread::sleep(Duration::from_millis(2));
  assert_eq!(
    provider.current_token(),
    TEST_TOKEN,
    "outside-base symlink retargets should preserve the last good token"
  );
}

#[test]
fn client_retries_once_after_token_file_rotation_unauthorized() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  write_token_file(&token_file, &TEST_TOKEN);
  let token_provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    None,
    "UNUSED_TOKEN_ENV",
    Duration::from_secs(60),
  )
  .expect("initial token file should load");
  let (client, _connects) =
    test_client_with_token_provider(0, Duration::from_secs(5), token_provider);
  write_token_file(&token_file, &ROTATED_TEST_TOKEN);
  let mut observed_tokens = Vec::new();
  let mut attempts = 0usize;
  let response = client
    .request_authenticated_with_transport(
      |token| RemoteSignerRequest::DescribeKey {
        token: token_to_wire(&token),
        key_id: "edge-default".to_string(),
      },
      |_, request| {
        attempts += 1;
        observed_tokens.push(decode_wire_token(request.token()));
        if attempts == 1 {
          Ok(RemoteSignerResponse::Error {
            code: "unauthorized".to_string(),
            message: "invalid signer token".to_string(),
          })
        } else {
          Ok(ok_response())
        }
      },
    )
    .expect("request should retry with the rotated token");
  assert!(matches!(response, RemoteSignerResponse::Error { code, .. } if code == "ok"));
  assert_eq!(observed_tokens, vec![TEST_TOKEN, ROTATED_TEST_TOKEN]);

  observed_tokens.clear();
  client
    .request_authenticated_with_transport(
      |token| RemoteSignerRequest::DescribeKey {
        token: token_to_wire(&token),
        key_id: "edge-default".to_string(),
      },
      |_, request| {
        observed_tokens.push(decode_wire_token(request.token()));
        Ok(ok_response())
      },
    )
    .expect("second request should use rotated cached token");
  assert_eq!(observed_tokens, vec![ROTATED_TEST_TOKEN]);
}

#[test]
fn token_file_startup_rejects_missing_or_invalid_files() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let missing = temp_dir.path().join("missing.b64");
  let error = RemoteSignerTokenProvider::from_sources(
    Some(missing),
    None,
    "UNUSED",
    Duration::from_millis(1),
  )
  .expect_err("missing token file should fail startup");
  assert!(
    error.to_string().contains("failed to read"),
    "unexpected error: {error}"
  );

  let invalid = temp_dir.path().join("invalid.b64");
  std::fs::write(&invalid, b"short").expect("invalid token should write");
  let error = RemoteSignerTokenProvider::from_sources(
    Some(invalid),
    None,
    "UNUSED",
    Duration::from_millis(1),
  )
  .expect_err("invalid token file should fail startup");
  assert!(
    error.to_string().contains("exactly 32 bytes") || error.to_string().contains("base64"),
    "unexpected error: {error}"
  );
}

#[test]
fn process_request_uses_latest_token_file_value() {
  let temp_dir = tempfile::tempdir().expect("temp dir should create");
  let token_file = temp_dir.path().join("keysigner-token.b64");
  write_token_file(&token_file, &TEST_TOKEN);
  let provider = RemoteSignerTokenProvider::from_sources(
    Some(token_file.clone()),
    None,
    "UNUSED_TOKEN_ENV",
    Duration::from_millis(1),
  )
  .expect("initial token file should load");
  let keys = HashMap::new();

  assert!(matches!(
    process_request(describe_request(), &keys, &provider, false),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_key"
  ));

  write_token_file(&token_file, &ROTATED_TEST_TOKEN);
  std::thread::sleep(Duration::from_millis(2));
  assert!(matches!(
    process_request(describe_request(), &keys, &provider, false),
    RemoteSignerResponse::Error { code, .. } if code == "unauthorized"
  ));
  assert!(matches!(
    process_request(rotated_describe_request(), &keys, &provider, false),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_key"
  ));

  std::fs::write(&token_file, b"not-base64").expect("invalid token should write");
  std::thread::sleep(Duration::from_millis(2));
  assert!(matches!(
    process_request(rotated_describe_request(), &keys, &provider, false),
    RemoteSignerResponse::Error { code, .. } if code == "unknown_key"
  ));
}

fn test_client(max_idle: usize, sign_timeout: Duration) -> (RemoteSignerClient, Arc<AtomicUsize>) {
  test_client_with_token_provider(max_idle, sign_timeout, test_token_provider())
}

fn test_client_with_token_provider(
  max_idle: usize,
  sign_timeout: Duration,
  token_provider: RemoteSignerTokenProvider,
) -> (RemoteSignerClient, Arc<AtomicUsize>) {
  let connects = Arc::new(AtomicUsize::new(0));
  let connect_counter = connects.clone();
  let connect_override: Arc<dyn Fn() -> anyhow::Result<UnixStream> + Send + Sync> =
    Arc::new(move || {
      connect_counter.fetch_add(1, Ordering::SeqCst);
      let (stream, _peer) = UnixStream::pair()
        .map_err(|error| anyhow::anyhow!("mock signer Unix stream pair should create: {error}"))?;
      Ok(stream)
    });
  (
    RemoteSignerClient {
      socket_path: PathBuf::from("/unused/test.sock"),
      token_provider,
      connect_timeout: Duration::from_secs(5),
      sign_timeout,
      pool: Arc::new(RemoteSignerConnectionPool::new(max_idle)),
      connect_override: Some(connect_override),
      allow_tls12_unstructured_signing: false,
    },
    connects,
  )
}

fn test_token_provider() -> RemoteSignerTokenProvider {
  RemoteSignerTokenProvider::from_static_token(decode_wire_token(&test_token()))
}

fn test_token() -> String {
  token_to_wire(&TEST_TOKEN)
}

fn describe_request() -> RemoteSignerRequest {
  RemoteSignerRequest::DescribeKey {
    token: test_token(),
    key_id: "edge-default".to_string(),
  }
}

fn rotated_describe_request() -> RemoteSignerRequest {
  RemoteSignerRequest::DescribeKey {
    token: token_to_wire(&ROTATED_TEST_TOKEN),
    key_id: "edge-default".to_string(),
  }
}

fn sign_request() -> RemoteSignerRequest {
  RemoteSignerRequest::Sign {
    token: test_token(),
    key_id: "edge-default".to_string(),
    scheme: u16::from(SignatureScheme::RSA_PSS_SHA256),
    context: SignContext::Tls12Unstructured,
    message: base64::engine::general_purpose::STANDARD.encode(b"message"),
  }
}

fn ok_response() -> RemoteSignerResponse {
  RemoteSignerResponse::Error {
    code: "ok".to_string(),
    message: "mock response".to_string(),
  }
}

fn write_token_file(path: &std::path::Path, token: &[u8; 32]) {
  std::fs::write(path, token_to_wire(token)).expect("token file should write");
}

fn replace_symlink<P: AsRef<std::path::Path>>(target: P, link: &std::path::Path) {
  let _ = std::fs::remove_file(link);
  std::os::unix::fs::symlink(target, link).expect("token symlink should create");
}

fn decode_wire_token(raw: &str) -> [u8; 32] {
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(raw)
    .expect("wire token should decode");
  decoded
    .as_slice()
    .try_into()
    .expect("wire token should be 32 bytes")
}

fn request_kind(request: &RemoteSignerRequest) -> &'static str {
  match request {
    RemoteSignerRequest::DescribeKey { .. } => "describe_key",
    RemoteSignerRequest::Sign { .. } => "sign",
    RemoteSignerRequest::DescribeAuditCheckpointKey { .. } => "describe_audit_checkpoint_key",
    RemoteSignerRequest::SignAuditCheckpointDigest { .. } => "sign_audit_checkpoint_digest",
    RemoteSignerRequest::DescribeCtLogKey { .. } => "describe_ct_log_key",
    RemoteSignerRequest::SignCtLogTranscript { .. } => "sign_ct_log_transcript",
  }
}

fn write_test_ed25519_private_key(path: &std::path::Path) {
  let mut der = vec![
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ];
  let mut seed = [0u8; 32];
  getrandom::fill(&mut seed).expect("test Ed25519 seed should generate");
  der.extend_from_slice(&seed);
  let encoded = base64::engine::general_purpose::STANDARD.encode(der);
  std::fs::write(
    path,
    format!("-----BEGIN PRIVATE KEY-----\n{encoded}\n-----END PRIVATE KEY-----\n"),
  )
  .expect("test Ed25519 private key should write");
}

fn ct_sth_transcript(version: u8, signature_type: u8) -> Vec<u8> {
  if version == 1 {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&1_u64.to_be_bytes());
    transcript.extend_from_slice(&1_u64.to_be_bytes());
    transcript.push(32);
    transcript.extend_from_slice(&[0x5a; 32]);
    transcript.extend_from_slice(&0_u16.to_be_bytes());
    return transcript;
  }
  let mut transcript = vec![version, signature_type];
  transcript.extend_from_slice(&1_u64.to_be_bytes());
  transcript.extend_from_slice(&1_u64.to_be_bytes());
  transcript.extend_from_slice(&[0x5a; 32]);
  transcript
}

fn write_test_p256_private_key(path: &std::path::Path) {
  const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBco0bhesYtJK1VUe\npe7kkvKM1v1xaccBdoVgBF6n+kOhRANCAATTAU7hHHok4jFOBvcM1PuOsgTA3fSf\n7b/DC3GFw/s/yGf2LC0DAWv/EvoX5J/sVwMyhDdAyPl9TfwPzWxUQeAI\n-----END PRIVATE KEY-----\n";
  std::fs::write(path, PEM).expect("test P-256 private key should write");
}
