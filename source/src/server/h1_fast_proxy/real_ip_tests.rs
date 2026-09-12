use super::*;

use crate::config::Config;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn scoped_parsed_get(host: &str) -> ParsedPlainRequest {
  let mut headers = HeaderMap::new();
  headers.insert(
    HOST,
    HeaderValue::from_str(host).expect("host header should parse"),
  );
  ParsedPlainRequest {
    method: Method::GET,
    target: "/".to_string(),
    version: 1,
    headers,
    raw: Vec::new(),
    remaining: Vec::new(),
  }
}

#[tokio::test]
async fn h1_fast_proxy_uses_received_sni_for_scoped_real_ip_before_route_matching() {
  let temp_dir = common::TempDir::new("h1-fast-scoped-real-ip");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "h1-scoped-real-ip");
  let raw = format!(
    r#"{}

[routes.match]
source_cidrs = ["203.0.113.0/24"]

[[proxy.real_ip.rules]]
name = "h1-edge"
hosts = ["example.com"]
server_names = ["edge.example.test"]
enabled = true
trusted_proxies = ["10.0.0.0/8"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = true
"#,
    common::minimal_config_toml(&cert_path, &key_path)
      .replace(
        "origin = \"https://app.internal.example\"",
        "origin = \"http://app.internal.example\"",
      )
      .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"")
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      )
  );
  let config: Config = toml::from_str(&raw).expect("H1 scoped Real-IP config should parse");
  config
    .validate()
    .expect("H1 scoped Real-IP config should validate");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  let peer = "10.0.0.7:443".parse().unwrap();
  let mut parsed = scoped_parsed_get("example.com");
  parsed
    .headers
    .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.24"));
  let selected_sni = WafTlsMetadata {
    enabled: true,
    sni: Some("edge.example.test".to_string()),
    ..WafTlsMetadata::default()
  };

  assert!(prepare_fast_proxy_request(&parsed, &snapshot, peer, &selected_sni).is_some());

  let different_sni = WafTlsMetadata {
    enabled: true,
    sni: Some("other.example.test".to_string()),
    ..WafTlsMetadata::default()
  };
  assert!(
    prepare_fast_proxy_request(&parsed, &snapshot, peer, &different_sni).is_none(),
    "a nonmatching SNI must leave the source-CIDR route unmatched"
  );
}
