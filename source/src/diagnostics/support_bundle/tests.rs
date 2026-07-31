use super::*;
use crate::config::Config;
use crate::state::AppSnapshot;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[test]
fn sanitize_url_removes_userinfo_query_and_fragment() {
  let redacted = sanitize_url("https://user:secret@example.test/private?token=secret#frag");
  assert_eq!(redacted, "https://example.test/private");
}

#[tokio::test]
async fn runtime_snapshot_redacts_upstream_origin_credentials_and_queries() {
  let temp_dir = common::TempDir::new("support-bundle-redacted-upstream");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "support-bundle-redacted-upstream");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "origin = \"https://app.internal.example\"",
    "origin = \"https://user:secret@app.internal.example/private?token=secret#frag\"",
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let value = serde_json::to_string(&build_runtime_snapshot(&snapshot))
    .expect("runtime snapshot should serialize");

  let runtime_backend = snapshot.runtime_topology.legacy_backend_snapshot();
  assert!(value.contains("https://app.internal.example/private"));
  assert!(
    value.contains(&format!(
      "\"target_runtime\":\"{}\"",
      runtime_backend.target_runtime
    )),
    "runtime snapshot should include target runtime: {value}"
  );
  assert!(
    value.contains(&format!(
      "\"active_runtime\":\"{}\"",
      runtime_backend.active_runtime
    )),
    "runtime snapshot should include active runtime: {value}"
  );
  assert!(
    value.contains(&format!(
      "\"compatibility_runtime\":\"{}\"",
      runtime_backend.compatibility_runtime
    )),
    "runtime snapshot should include compatibility runtime: {value}"
  );
  assert!(value.contains("\"failure_policy\":\"drop_stale\""));
  assert!(value.contains("\"runtime_topology\""));
  assert!(value.contains("\"resolved_preset\":\"external\""));
  assert!(!value.contains("user:secret"));
  assert!(!value.contains("token=secret"));
}

#[test]
fn redacted_dynamic_policy_record_omits_subject_body_reason_and_signature_values() {
  let record = RedactedDynamicPolicyRecord {
    id: 7,
    enabled: true,
    priority: 100,
    source: "automation".to_string(),
    action: "reject".to_string(),
    subject_type: "client_ip".to_string(),
    subject_redacted: true,
    mode: "enforce".to_string(),
    rate_configured: false,
    burst_configured: false,
    status: Some(403),
    body_configured: true,
    reason_configured: true,
    signature_present: true,
    expires_at: Some("2026-05-25T00:00:00Z".to_string()),
  };
  let value = serde_json::to_string(&record).expect("record should serialize");

  assert!(value.contains("\"subject_redacted\":true"));
  assert!(value.contains("\"body_configured\":true"));
  assert!(value.contains("\"signature_present\":true"));
  assert!(!value.contains("203.0.113.10"));
  assert!(!value.contains("row_signature"));
  assert!(!value.contains("blocked because"));
  assert!(!value.contains("secret response body"));
}
