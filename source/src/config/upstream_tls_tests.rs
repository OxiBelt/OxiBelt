//! Focused validation coverage for per-upstream TLS trust boundaries.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use super::upstream_tls::hex_lower;
use super::{UpstreamTlsConfig, UpstreamTlsSubjectAltName, UpstreamTlsTrust};

fn ca_file(label: &str, bytes: &[u8]) -> PathBuf {
  let path = std::env::temp_dir().join(format!(
    "oxibelt-upstream-tls-{label}-{}-{}",
    std::process::id(),
    std::thread::current().name().unwrap_or("test")
  ));
  std::fs::write(&path, bytes).expect("test CA file should be written");
  path
}

#[test]
fn exclusive_trust_requires_and_verifies_exact_ca_bytes() {
  let path = ca_file("exclusive", b"deterministic-public-ca-bundle");
  let digest = hex_lower(&Sha256::digest(b"deterministic-public-ca-bundle"));
  let policy = UpstreamTlsConfig {
    server_name: Some("backend.example.test".to_string()),
    trust: UpstreamTlsTrust::Exclusive,
    trusted_ca_certs: vec![path.clone()],
    trusted_ca_sha256: vec![digest],
    ..UpstreamTlsConfig::default()
  };

  policy
    .validate("test")
    .expect("an exact exclusive trust policy should validate");
  std::fs::remove_file(path).expect("test CA file should be removed");
}

#[test]
fn exclusive_trust_rejects_stale_ca_bytes() {
  let path = ca_file("stale", b"rotated-public-ca-bundle");
  let policy = UpstreamTlsConfig {
    trust: UpstreamTlsTrust::Exclusive,
    trusted_ca_certs: vec![path.clone()],
    trusted_ca_sha256: vec!["0".repeat(64)],
    ..UpstreamTlsConfig::default()
  };

  let error = policy
    .validate("test")
    .expect_err("a stale CA digest must fail closed");
  assert!(error.to_string().contains("digest mismatch"));
  std::fs::remove_file(path).expect("test CA file should be removed");
}

#[test]
fn system_trust_rejects_custom_ca_material() {
  let policy = UpstreamTlsConfig {
    trust: UpstreamTlsTrust::System,
    trusted_ca_certs: vec![PathBuf::from("unused.pem")],
    trusted_ca_sha256: vec!["0".repeat(64)],
    ..UpstreamTlsConfig::default()
  };

  let error = policy
    .validate("test")
    .expect_err("system trust must never be augmented");
  assert!(error.to_string().contains("must be empty"));
}

#[test]
fn tls_server_name_rejects_ambiguous_whitespace() {
  let policy = UpstreamTlsConfig {
    server_name: Some(" backend.example.test".to_string()),
    ..UpstreamTlsConfig::default()
  };

  let error = policy
    .validate("test")
    .expect_err("server names must be exact values");
  assert!(error.to_string().contains("non-empty exact value"));
}

#[test]
fn subject_alt_names_accept_bounded_exact_dns_and_uri_identities() {
  let policy = UpstreamTlsConfig {
    server_name: Some("sni.example.test".to_string()),
    subject_alt_names: vec![
      UpstreamTlsSubjectAltName::Dns("identity.example.test".to_string()),
      UpstreamTlsSubjectAltName::Uri("spiffe://example.test/ns/backend/sa/service".to_string()),
      UpstreamTlsSubjectAltName::Uri("SPIFFE://Example.TEST/ns/backend/sa/Other".to_string()),
      UpstreamTlsSubjectAltName::Uri("urn:example:backend#workload".to_string()),
    ],
    ..UpstreamTlsConfig::default()
  };

  policy
    .validate("test")
    .expect("bounded exact SAN identities should validate");
}

#[test]
fn subject_alt_names_reject_excess_duplicate_or_ambiguous_identities() {
  let too_many = UpstreamTlsConfig {
    subject_alt_names: (0..6)
      .map(|index| UpstreamTlsSubjectAltName::Dns(format!("backend-{index}.example.test")))
      .collect(),
    ..UpstreamTlsConfig::default()
  };
  let error = too_many
    .validate("test")
    .expect_err("more than five SAN identities must fail closed");
  assert!(error.to_string().contains("at most 5 entries"));

  for invalid in [
    UpstreamTlsSubjectAltName::Dns("*.example.test".to_string()),
    UpstreamTlsSubjectAltName::Dns("UPPER.example.test".to_string()),
    UpstreamTlsSubjectAltName::Dns("127.0.0.1".to_string()),
    UpstreamTlsSubjectAltName::Uri("relative/path".to_string()),
    UpstreamTlsSubjectAltName::Uri("https://example.test/a b".to_string()),
    UpstreamTlsSubjectAltName::Uri("https:\\example.test\\backend".to_string()),
    UpstreamTlsSubjectAltName::Uri("https://example.test/%zz".to_string()),
  ] {
    let policy = UpstreamTlsConfig {
      subject_alt_names: vec![invalid],
      ..UpstreamTlsConfig::default()
    };
    policy
      .validate("test")
      .expect_err("ambiguous SAN identity must fail closed");
  }

  let duplicate = UpstreamTlsConfig {
    subject_alt_names: vec![
      UpstreamTlsSubjectAltName::Dns("backend.example.test".to_string()),
      UpstreamTlsSubjectAltName::Dns("backend.example.test".to_string()),
    ],
    ..UpstreamTlsConfig::default()
  };
  let error = duplicate
    .validate("test")
    .expect_err("duplicate SAN identities must fail closed");
  assert!(error.to_string().contains("must be unique"));
}
