use super::*;
use crate::config::Config;
use crate::proxy::http::response::{silent_close_response, text_response};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[tokio::test]
async fn prepare_fast_proxy_request_rejects_tls_policy_mismatch() {
  let temp_dir = common::TempDir::new("h1-fast-proxy-route-tls-policy");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "h1-fast-proxy-route-tls-policy");
  let base = common::minimal_config_toml(&cert_path, &key_path)
    .replace(
      "hosts = [\"example.com\"]",
      "hosts = [\"secure.example.com\"]",
    )
    .replace(
      "origin = \"https://app.internal.example\"\nmax_http_version = \"h2\"",
      "origin = \"http://app.internal.example\"\nmax_http_version = \"h1\"",
    )
    .replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    );
  let raw = format!(
    r#"{base}

[[routes]]
name = "legacy-root"
hosts = ["legacy.example.com"]
path_prefix = "/"
upstream = "app"

[routes.tls]
min_version = "tls1.2"
max_version = "tls1.2"
"#
  );
  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let peer_addr = "203.0.113.10:49152".parse().unwrap();
  let legacy_tls = WafTlsMetadata {
    enabled: true,
    sni: Some("legacy.example.com".to_string()),
    ..WafTlsMetadata::default()
  };
  let secure_tls = WafTlsMetadata {
    enabled: true,
    sni: Some("secure.example.com".to_string()),
    ..WafTlsMetadata::default()
  };

  assert!(
    prepare_fast_proxy_request(
      &parsed_get("secure.example.com"),
      &snapshot,
      peer_addr,
      &legacy_tls
    )
    .is_none()
  );
  assert!(
    prepare_fast_proxy_request(
      &parsed_get("secure.example.com"),
      &snapshot,
      peer_addr,
      &secure_tls
    )
    .is_some()
  );
}

#[test]
fn silent_close_response_stops_before_h1_fast_writer() {
  let response = silent_close_response();

  assert!(
    response_write_plan(&response, &Method::GET, false, Duration::from_secs(1)).is_none(),
    "silent_close sentinel must close before serializing a 204 response"
  );
}

#[test]
fn ordinary_no_content_response_is_still_serialized_without_body() {
  let response = text_response(StatusCode::NO_CONTENT, "");

  let write_plan = response_write_plan(&response, &Method::GET, false, Duration::from_secs(1))
    .expect("ordinary 204 should still be serialized");

  assert!(write_plan.keep_alive);
  assert!(write_plan.skip_body);
  assert_eq!(write_plan.response_send_timeout, Duration::from_secs(1));
}

fn parsed_get(host: &str) -> ParsedPlainRequest {
  let mut headers = HeaderMap::new();
  headers.insert(HOST, HeaderValue::from_str(host).unwrap());
  ParsedPlainRequest {
    method: Method::GET,
    target: "/".to_string(),
    version: 1,
    headers,
    raw: Vec::new(),
    remaining: Vec::new(),
  }
}
