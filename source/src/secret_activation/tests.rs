use super::*;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[test]
fn request_debug_redacts_reference_and_digest() {
  let request = SecretReferenceUpdateRequest {
    schema_version: 1,
    field: "tls.remote_signer.token_file".to_string(),
    reference: "private/provider-token".to_string(),
    sha256: Some("a".repeat(64)),
  };
  let debug = format!("{request:?}");
  assert!(!debug.contains("private/provider-token"));
  assert!(!debug.contains(&"a".repeat(64)));
  assert!(debug.contains("[REDACTED]"));
}

#[test]
fn typed_allowlist_excludes_control_plane_backends() {
  assert_eq!(
    SecretReferenceField::parse("tls.remote_signer.token_env"),
    Ok(SecretReferenceField::TlsRemoteSignerTokenEnv)
  );
  for field in [
    "admin.mutations.backend/connection_url_env",
    "admin.audit.backend/connection_url_env",
    "shared_state.backends/replay/connection_url_env",
  ] {
    assert_eq!(
      SecretReferenceField::parse(field),
      Err(SecretActivationError::FieldNotAllowlisted)
    );
  }
}

#[test]
fn candidate_error_classification_is_redacted_and_stable() {
  assert_eq!(
    SecretActivationError::classify_candidate_error("certificate and private key mismatch"),
    SecretActivationError::CertificateKeyMismatch
  );
  assert_eq!(
    SecretActivationError::classify_candidate_error("certificate expired at a sensitive path"),
    SecretActivationError::CertificateExpired
  );
  assert_eq!(
    SecretActivationError::CandidateInvalid.code(),
    "secret_material_invalid_format"
  );
  assert_eq!(
    SecretActivationError::classify_candidate_error("TLS handshake failed for private host"),
    SecretActivationError::UpstreamTlsPreflightFailed
  );
}

#[test]
fn contained_file_provider_denies_symlink_references() {
  use std::os::unix::fs::symlink;

  let temp_dir = common::TempDir::new("secret-reference-symlink");
  let base = temp_dir.path().join("secrets");
  std::fs::create_dir_all(&base).expect("secret directory should be created");
  let target = temp_dir.path().join("outside-token");
  std::fs::write(&target, b"not-secret-test-material").expect("target should be written");
  symlink(&target, base.join("token")).expect("symlink should be created");

  assert_eq!(
    resolver::resolve_contained_file_path(&base, std::path::Path::new("token")),
    Err(SecretActivationError::ReferenceUnauthorized)
  );
  assert_eq!(
    resolver::resolve_contained_file_path(&base, std::path::Path::new("missing")),
    Err(SecretActivationError::ReferenceMissing)
  );
}

#[test]
fn certificate_time_and_ca_preflight_fail_with_stable_errors() {
  let metadata = crate::tls::ParsedCertificateMetadata {
    not_before_unix_seconds: 100,
    not_after_unix_seconds: 200,
    ..Default::default()
  };
  assert_eq!(
    preflight::validate_certificate_metadata(&metadata, &[], 99),
    Err(SecretActivationError::CertificateNotYetValid)
  );
  assert_eq!(
    preflight::validate_certificate_metadata(&metadata, &[], 201),
    Err(SecretActivationError::CertificateExpired)
  );

  let temp_dir = common::TempDir::new("secret-invalid-ca");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "secret-invalid-ca");
  let raw = common::minimal_config_toml(&cert_path, &key_path);
  let mut config: Config = toml::from_str(&raw).expect("base config should parse");
  let invalid_ca = temp_dir.path().join("invalid-ca.pem");
  std::fs::write(&invalid_ca, b"not a certificate").expect("invalid CA fixture should be written");
  config.proxy.trusted_ca_certs.push(invalid_ca);
  assert_eq!(
    preflight::preflight_certificate_material(&config),
    Err(SecretActivationError::CaBundleInvalid)
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activation_candidate_is_atomic_fenced_reversible_and_redacted() {
  const TEST_NAME: &str =
    "secret_activation::tests::activation_candidate_is_atomic_fenced_reversible_and_redacted";
  let variables = [
    ("OXIBELT_SECRET_OLD_ID", "old-id"),
    ("OXIBELT_SECRET_OLD_VALUE", "old-value-private"),
    ("OXIBELT_SECRET_NEXT_VALUE", "next-value-private"),
    ("OXIBELT_SECRET_COMPETING_VALUE", "competing-value-private"),
    ("OXIBELT_SECRET_WRONG_VALUE", "line-one\nline-two"),
  ];
  if common::run_test_in_subprocess_with_env(TEST_NAME, &variables) {
    return;
  }

  let temp_dir = common::TempDir::new("secret-reference-atomic");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "secret-reference-atomic");
  let raw = format!(
    "{}\n{}",
    common::minimal_config_toml(&cert_path, &key_path),
    r#"
[[external_auth]]
name = "oidc"
provider = "o_auth2"
endpoint = "http://127.0.0.1:9/introspect"
client_id_env = "OXIBELT_SECRET_OLD_ID"
client_secret_env = "OXIBELT_SECRET_OLD_VALUE"
"#
  );
  let config: Config = toml::from_str(&raw).expect("secret activation config should parse");
  config
    .validate()
    .expect("secret activation config should validate");
  let active = AppSnapshot::new(config)
    .await
    .expect("initial secret snapshot should build");
  let handle = crate::state::AppHandle::new(active);
  let original = handle.snapshot();

  let request = |reference: &str| SecretReferenceUpdateRequest {
    schema_version: SECRET_REFERENCE_SCHEMA_VERSION,
    field: "external_auth/oidc/client_secret_env".to_string(),
    reference: reference.to_string(),
    sha256: None,
  };
  let next = build_candidate_snapshot(
    original.as_ref(),
    &request("OXIBELT_SECRET_NEXT_VALUE"),
    "request-next".to_string(),
    "config-2".to_string(),
    "instance:test:2".to_string(),
    None,
  )
  .await
  .expect("valid secret rotation should preflight");
  let competing = build_candidate_snapshot(
    original.as_ref(),
    &request("OXIBELT_SECRET_COMPETING_VALUE"),
    "request-competing".to_string(),
    "config-2".to_string(),
    "instance:test:2".to_string(),
    None,
  )
  .await
  .expect("competing secret rotation should preflight independently");
  assert_ne!(
    next.secret_references.reference_set_digest(),
    original.secret_references.reference_set_digest()
  );

  let readers_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
  let reader_failure = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
  let readers = (0..4)
    .map(|_| {
      let handle = handle.clone();
      let running = readers_running.clone();
      let failed = reader_failure.clone();
      std::thread::spawn(move || {
        while running.load(std::sync::atomic::Ordering::Acquire) {
          let snapshot = handle.snapshot();
          let reference = snapshot.config.external_auth[0]
            .client_secret_env
            .as_deref();
          if !matches!(
            reference,
            Some("OXIBELT_SECRET_OLD_VALUE" | "OXIBELT_SECRET_NEXT_VALUE")
          ) {
            failed.store(true, std::sync::atomic::Ordering::Release);
            break;
          }
        }
      })
    })
    .collect::<Vec<_>>();

  assert!(handle.replace_if_current(&original, next));
  assert!(
    !handle.replace_if_current(&original, competing),
    "only one candidate built from the same snapshot may commit"
  );
  let installed = handle.snapshot();
  let binding = installed
    .secret_references
    .binding()
    .expect("installed snapshot should carry activation binding");
  assert_eq!(binding.mutation_request_id, "request-next");
  assert_eq!(binding.config_logical_revision, "config-2");
  assert!(handle.replace_if_current(&installed, original.as_ref().clone()));
  readers_running.store(false, std::sync::atomic::Ordering::Release);
  for reader in readers {
    reader.join().expect("snapshot reader should finish");
  }
  assert!(!reader_failure.load(std::sync::atomic::Ordering::Acquire));
  assert_eq!(
    handle.snapshot().secret_references.reference_set_digest(),
    original.secret_references.reference_set_digest()
  );

  let missing = build_candidate_snapshot(
    original.as_ref(),
    &request("OXIBELT_SECRET_MISSING_VALUE"),
    "request-missing".to_string(),
    "config-3".to_string(),
    "instance:test:3".to_string(),
    None,
  )
  .await;
  let Err(missing) = missing else {
    panic!("missing reference must fail closed");
  };
  assert_eq!(missing, SecretActivationError::ReferenceMissing);
  let wrong_type = build_candidate_snapshot(
    original.as_ref(),
    &request("OXIBELT_SECRET_WRONG_VALUE"),
    "request-wrong".to_string(),
    "config-3".to_string(),
    "instance:test:3".to_string(),
    None,
  )
  .await;
  let Err(wrong_type) = wrong_type else {
    panic!("wrong secret type must fail closed");
  };
  assert_eq!(wrong_type, SecretActivationError::WrongMaterialType);

  let (_, mismatched_key) =
    common::create_self_signed_cert(temp_dir.path(), "secret-reference-other-key");
  std::fs::copy(&mismatched_key, &key_path).expect("mismatched key fixture should be installed");
  let key_mismatch = build_candidate_snapshot(
    original.as_ref(),
    &request("OXIBELT_SECRET_NEXT_VALUE"),
    "request-key-mismatch".to_string(),
    "config-4".to_string(),
    "instance:test:4".to_string(),
    None,
  )
  .await;
  let Err(key_mismatch) = key_mismatch else {
    panic!("certificate/key mismatch must reject activation");
  };
  assert_eq!(key_mismatch, SecretActivationError::CertificateKeyMismatch);

  installed
    .metrics
    .record_secret_reference_activation("applied");
  installed
    .metrics
    .record_secret_reference_activation("rejected");
  installed
    .metrics
    .record_secret_reference_activation("rollback");
  let prometheus = installed.metrics.prometheus(
    &installed.config.metrics,
    crate::cache::CacheStats::default(),
    crate::tls::TlsServerSessionStorageStats::default(),
  );
  assert!(prometheus.contains("oxibelt_secret_reference_activation_applied_total 1"));
  assert!(prometheus.contains("oxibelt_secret_reference_activation_rejected_total 1"));
  assert!(prometheus.contains("oxibelt_secret_reference_activation_rollback_total 1"));

  let observable = format!("{binding:?} {:?} {prometheus}", original.secret_references);
  for plaintext in [
    "old-value-private",
    "next-value-private",
    "competing-value-private",
  ] {
    assert!(!observable.contains(plaintext));
  }
}

#[tokio::test]
async fn configured_https_target_must_complete_tls_preflight() {
  const TEST_NAME: &str =
    "secret_activation::tests::configured_https_target_must_complete_tls_preflight";
  let variables = [
    ("OXIBELT_TLS_PREFLIGHT_ID", "client-id"),
    ("OXIBELT_TLS_PREFLIGHT_OLD", "old-private"),
    ("OXIBELT_TLS_PREFLIGHT_NEXT", "next-private"),
  ];
  if common::run_test_in_subprocess_with_env(TEST_NAME, &variables) {
    return;
  }
  let temp_dir = common::TempDir::new("secret-tls-preflight");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "secret-tls-preflight");
  let raw = format!(
    "{}\n{}",
    common::minimal_config_toml(&cert_path, &key_path),
    r#"
[[external_auth]]
name = "oidc"
provider = "o_auth2"
endpoint = "https://127.0.0.1:9/introspect"
timeout_ms = 25
client_id_env = "OXIBELT_TLS_PREFLIGHT_ID"
client_secret_env = "OXIBELT_TLS_PREFLIGHT_OLD"
"#
  );
  let config: Config = toml::from_str(&raw).expect("TLS preflight config should parse");
  config
    .validate()
    .expect("TLS preflight config should validate");
  let active = AppSnapshot::new(config)
    .await
    .expect("initial TLS preflight snapshot should build");
  let result = build_candidate_snapshot(
    &active,
    &SecretReferenceUpdateRequest {
      schema_version: 1,
      field: "external_auth/oidc/client_secret_env".to_string(),
      reference: "OXIBELT_TLS_PREFLIGHT_NEXT".to_string(),
      sha256: None,
    },
    "request-tls".to_string(),
    "config-2".to_string(),
    "instance:test:2".to_string(),
    None,
  )
  .await;
  let Err(error) = result else {
    panic!("unreachable TLS target must reject activation");
  };
  assert_eq!(error, SecretActivationError::UpstreamTlsPreflightFailed);
  assert_eq!(
    active.config.external_auth[0].client_secret_env.as_deref(),
    Some("OXIBELT_TLS_PREFLIGHT_OLD")
  );
}
