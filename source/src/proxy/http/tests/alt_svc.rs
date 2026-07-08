use pretty_assertions::assert_eq;

use super::*;

#[tokio::test]
async fn app_snapshot_precomputes_alt_svc_header_value() {
  let temp_dir = common::TempDir::new("alt-svc-precompute");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "alt-svc-precompute");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "http3 = false",
    "http3 = true\n\n[quic.alt_svc]\nenabled = true\nmax_age_seconds = 60\npersist = true\n\n[quic.socket]\nworkers = \"auto\"\nreuse_port = true",
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");

  assert_eq!(
    state.alt_svc_header_values.default_value().unwrap(),
    "h3=\":8443\"; ma=60; persist=1"
  );
}

#[tokio::test]
async fn app_snapshot_precomputes_alt_svc_port_overrides_per_listener_bind() {
  let temp_dir = common::TempDir::new("alt-svc-port-overrides");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "alt-svc-port-overrides");
  let raw = common::minimal_config_toml(&cert_path, &key_path)
    .replace(
      r#"https_bind = "127.0.0.1:8443""#,
      r#"https_binds = ["127.0.0.1:8443", "[::1]:9443"]"#,
    )
    .replace(
      "http3 = false",
      "http3 = true\n\n[quic.alt_svc]\nenabled = true\nmax_age_seconds = 60\npersist = false\n\n[[quic.alt_svc.port_overrides]]\nbind = \"127.0.0.1:8443\"\nadvertised_port = 443\n\n[[quic.alt_svc.port_overrides]]\nbind = \"[::1]:9443\"\nadvertised_port = 443\n\n[quic.socket]\nworkers = \"auto\"\nreuse_port = true",
    );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");

  assert_eq!(
    state
      .alt_svc_header_values
      .for_listener_bind(Some("127.0.0.1:8443".parse().unwrap()))
      .unwrap(),
    "h3=\":443\"; ma=60"
  );
  assert_eq!(
    state
      .alt_svc_header_values
      .for_listener_bind(Some("[::1]:9443".parse().unwrap()))
      .unwrap(),
    "h3=\":443\"; ma=60"
  );
  let mut headers = http::HeaderMap::new();
  apply_alt_svc_header(
    &mut headers,
    StatusCode::OK,
    &state,
    "https",
    http::Version::HTTP_2,
    Some("127.0.0.1:8443".parse().unwrap()),
  );
  assert_eq!(
    headers.get(http::header::ALT_SVC).unwrap(),
    "h3=\":443\"; ma=60"
  );
}

#[tokio::test]
async fn alt_svc_applies_only_to_https_h1_h2_non_switching_responses() {
  let temp_dir = common::TempDir::new("alt-svc-helper");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "alt-svc-helper");
  let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
    "http3 = false",
    "http3 = true\n\n[quic.alt_svc]\nenabled = true\nmax_age_seconds = 120\npersist = false\n\n[quic.socket]\nworkers = \"auto\"\nreuse_port = true",
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");

  assert!(should_add_alt_svc(
    StatusCode::OK,
    &state,
    "https",
    http::Version::HTTP_2
  ));
  assert!(!should_add_alt_svc(
    StatusCode::OK,
    &state,
    "https",
    http::Version::HTTP_3
  ));
  assert!(!should_add_alt_svc(
    StatusCode::OK,
    &state,
    "http",
    http::Version::HTTP_2
  ));
  assert!(!should_add_alt_svc(
    StatusCode::SWITCHING_PROTOCOLS,
    &state,
    "https",
    http::Version::HTTP_11
  ));
}
