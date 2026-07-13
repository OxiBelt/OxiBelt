use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::UnixTime;

use super::*;

#[allow(dead_code)]
mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[test]
fn shared_admin_client_auth_verifier_rejects_unknown_ca_and_expired_client_chains() {
  let temp_dir = common::TempDir::new("admin-client-auth-verifier");
  let (trusted_ca, trusted_ca_key) =
    common::create_self_signed_cert(temp_dir.path(), "trusted-client-ca");
  let (trusted_client, _trusted_client_key) = common::create_ca_signed_client_cert(
    temp_dir.path(),
    "trusted-client.example.test",
    &trusted_ca,
    &trusted_ca_key,
  );
  let (untrusted_ca, untrusted_ca_key) =
    common::create_self_signed_cert(temp_dir.path(), "untrusted-client-ca");
  let (untrusted_client, _untrusted_client_key) = common::create_ca_signed_client_cert(
    temp_dir.path(),
    "untrusted-client.example.test",
    &untrusted_ca,
    &untrusted_ca_key,
  );
  let client_auth = TlsClientAuthConfig {
    mode: TlsClientAuthMode::Require,
    ca_certs: vec![trusted_ca],
    verify_depth: 4,
  };
  let provider = Arc::new(
    provider::crypto_provider(&CryptoConfig::default())
      .expect("default TLS provider should initialize"),
  );
  let verifier = downstream_client_cert_verifier(&client_auth, provider)
    .expect("client-auth verifier should build")
    .expect("required client auth should install a verifier");
  let trusted = load_certs(&trusted_client).expect("trusted client certificate should load");
  let untrusted = load_certs(&untrusted_client).expect("untrusted client certificate should load");

  verifier
    .verify_client_cert(&trusted[0], &[], UnixTime::now())
    .expect("trusted client certificate should verify at the current time");
  assert!(
    verifier
      .verify_client_cert(&untrusted[0], &[], UnixTime::now())
      .is_err(),
    "client certificate from an unknown CA must fail before Admin authorization"
  );
  assert!(
    verifier
      .verify_client_cert(
        &trusted[0],
        &[],
        UnixTime::since_unix_epoch(Duration::from_secs(4_102_444_800)),
      )
      .is_err(),
    "expired client certificate chains must fail before Admin authorization"
  );
}
