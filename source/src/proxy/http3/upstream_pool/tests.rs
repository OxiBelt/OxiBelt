use super::connection::H3PoolStreamTracker;
use super::*;

#[test]
fn attempt_generation_and_operation_must_both_match() {
  let generation = H3ClientGeneration::new();
  let first = H3PoolAttempt::new(generation.clone());
  let same = first.clone();
  let other_operation = H3PoolAttempt::new(generation);
  let other_generation = H3PoolAttempt::new(H3ClientGeneration::new());
  assert!(first.same_as(&same));
  assert!(!first.same_as(&other_operation));
  assert!(!first.same_as(&other_generation));
}

#[test]
fn stream_reservation_reports_the_last_release() {
  let streams = H3PoolStreamTracker::default();
  streams.acquire();
  streams.acquire();
  assert!(!streams.release());
  assert!(streams.release());
  assert!(!streams.is_active());
}

#[test]
fn logical_origin_rejects_tls_trust_and_routing_identity_changes() {
  let original: UpstreamConfig = toml::from_str(
    r#"
name = "api"
origin = "https://api.example.test:443"
max_http_version = "h3"

[tls]
server_name = "verify.example.test"
"#,
  )
  .unwrap();
  let inherited_roots = vec![std::path::PathBuf::from("/trust/global.pem")];
  let logical = LogicalH3Origin::new(&original, inherited_roots.clone()).unwrap();
  assert!(logical.matches(&original, &inherited_roots));

  let mut changed_server_name = original.clone();
  changed_server_name.tls.server_name = Some("other.example.test".to_string());
  assert!(!logical.matches(&changed_server_name, &inherited_roots));

  let mut changed_subject_alt_names = original.clone();
  changed_subject_alt_names.tls.subject_alt_names =
    vec![crate::config::UpstreamTlsSubjectAltName::Dns(
      "verify.example.test".to_string(),
    )];
  assert!(!logical.matches(&changed_subject_alt_names, &inherited_roots));

  let mut changed_trust = original.clone();
  changed_trust
    .tls
    .trusted_ca_sha256
    .push("opaque-test-digest".to_string());
  assert!(!logical.matches(&changed_trust, &inherited_roots));

  let changed_global_roots = vec![std::path::PathBuf::from("/trust/rotated.pem")];
  assert!(!logical.matches(&original, &changed_global_roots));

  let mut changed_routing_option = original.clone();
  changed_routing_option.idle_timeout_ms = changed_routing_option.idle_timeout_ms.saturating_add(1);
  assert!(!logical.matches(&changed_routing_option, &inherited_roots));
}
