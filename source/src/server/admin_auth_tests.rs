use std::collections::HashMap;
use std::path::Path;

use super::*;
use crate::ipm::{
  IpmCredentialRuntime, IpmEntrySource, IpmPrincipalRuntime, IpmSnapshot, IpmSnapshotCounts,
};

#[allow(dead_code)]
mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[tokio::test]
async fn workload_binding_allows_certificate_only_when_configured_optional() {
  let temp_dir = common::TempDir::new("admin-workload-binding-auth");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-workload-binding-auth");
  let config = workload_binding_config(&cert_path, &key_path);
  config.validate().expect("test config should validate");
  let ipm = IpmRuntime::new(&config)
    .await
    .expect("IPM runtime should initialize");
  let request = request_with_workload_certificate(
    "spiffe://example.test/ns/edge/sa/controller",
    "a".repeat(64),
  );

  let authentication = admin_authentication(&request, &config, &ipm)
    .await
    .expect("matching mTLS identity should authenticate in optional bearer mode");

  assert_eq!(authentication.actor.name, "controller");
  assert_eq!(authentication.actor.principal, "controller");
}

#[tokio::test]
async fn workload_binding_rejects_wrong_san_and_revoked_certificate() {
  let temp_dir = common::TempDir::new("admin-workload-binding-negative");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-workload-binding-negative");
  let config = workload_binding_config(&cert_path, &key_path);
  let ipm = IpmRuntime::new(&config)
    .await
    .expect("IPM runtime should initialize");

  let wrong_san =
    request_with_workload_certificate("spiffe://example.test/ns/edge/sa/other", "b".repeat(64));
  let error = admin_authentication(&wrong_san, &config, &ipm)
    .await
    .expect_err("wrong SAN must not map to an IPM principal");
  assert_eq!(error.reason(), "unmapped_workload_identity");

  let mut revoked_config = config.clone();
  revoked_config
    .admin
    .workload_identity
    .revoked_certificate_fingerprints_sha256
    .push("a".repeat(64));
  let revoked = request_with_workload_certificate(
    "spiffe://example.test/ns/edge/sa/controller",
    "a".repeat(64),
  );
  let error = admin_authentication(&revoked, &revoked_config, &ipm)
    .await
    .expect_err("denylisted certificate must be rejected");
  assert_eq!(error.reason(), "revoked_certificate");
}

#[tokio::test]
async fn workload_binding_rejects_a_bearer_for_a_different_principal() {
  let temp_dir = common::TempDir::new("admin-workload-binding-mismatch");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-workload-binding-mismatch");
  let config = workload_binding_config(&cert_path, &key_path);
  let ipm = runtime_with_bearer("deployer", "deployer-secret");
  let mut request = request_with_workload_certificate(
    "spiffe://example.test/ns/edge/sa/controller",
    "a".repeat(64),
  );
  request.headers_mut().insert(
    ::http::header::AUTHORIZATION,
    "Bearer deployer-secret"
      .parse()
      .expect("header should parse"),
  );

  let error = admin_authentication(&request, &config, &ipm)
    .await
    .expect_err("bearer for another principal must be rejected");

  assert_eq!(error.reason(), "principal_mismatch");
}

fn request_with_workload_certificate(
  spiffe_id: &str,
  fingerprint_sha256: String,
) -> hyper::Request<()> {
  let mut request = hyper::Request::builder()
    .method("GET")
    .uri("/admin/v1/config/status")
    .body(())
    .expect("request should build");
  request
    .extensions_mut()
    .insert(VerifiedClientCertificate::Parsed(
      crate::tls::VerifiedClientCertificateIdentity {
        fingerprint_sha256,
        san_dns_names: Vec::new(),
        san_uri_names: vec![spiffe_id.to_string()],
        spiffe_ids: vec![spiffe_id.to_string()],
      },
    ));
  request
}

fn runtime_with_bearer(principal: &str, bearer: &str) -> IpmRuntime {
  let mut principals = HashMap::new();
  for id in ["controller", "deployer"] {
    principals.insert(
      id.to_string(),
      IpmPrincipalRuntime {
        actor: IpmActor {
          name: id.to_string(),
          principal: id.to_string(),
          subject: format!("{id}@example.test"),
          groups: Vec::new(),
        },
        enabled: true,
        source: IpmEntrySource::Config,
      },
    );
  }
  let snapshot = IpmSnapshot {
    generation: 0,
    fingerprint: 0,
    credentials: vec![IpmCredentialRuntime {
      name: "deployer-token".to_string(),
      principal: principal.to_string(),
      source: IpmEntrySource::Config,
      bearer_token_env: String::new(),
      break_glass_access_token_hash: None,
      enabled: true,
      revoked: false,
      expires_at: None,
      expires_at_unix: None,
      token_prefix: None,
      token_hash: Some(test_token_hash(bearer)),
      token_hash_alg: Some("sha256-v1".to_string()),
      previous_token_prefix: None,
      previous_token_hash: None,
      previous_token_overlap_until: None,
      previous_token_overlap_until_unix: None,
    }],
    principals,
    policies: HashMap::new(),
    principal_bindings: HashMap::new(),
    group_bindings: HashMap::new(),
    bindings: Vec::new(),
    counts: IpmSnapshotCounts::default(),
  };
  IpmRuntime::test_with_snapshot(snapshot)
}

fn test_token_hash(token: &str) -> String {
  crate::crypto::sha256(token.as_bytes())
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

fn workload_binding_config(cert_path: &Path, key_path: &Path) -> Config {
  let raw = format!(
    r#"{}

[admin]
enabled = true
transport = "tls"

[admin.audit]
enabled = true
mode = "best_effort"

[admin.tls]
enabled = true

[admin.tls.client_auth]
mode = "require"
ca_certs = ["{}"]

[[admin.tls.certificates]]
server_names = ["admin.example.test"]
cert_chain = "{}"
private_key = "{}"
default = true

[admin.workload_identity]
enabled = true
bearer_mode = "optional"

[ipm]
enabled = true

[[ipm.principals]]
id = "controller"
subject = "spiffe://example.test/ns/edge/sa/controller"

[[ipm.trust]]
source = "mtls"
claim = "spiffe_id"
value = "spiffe://example.test/ns/edge/sa/controller"
principal = "controller"
"#,
    common::minimal_config_toml(cert_path, key_path),
    cert_path.display(),
    cert_path.display(),
    key_path.display(),
  );
  toml::from_str(&raw).expect("test config should parse")
}
