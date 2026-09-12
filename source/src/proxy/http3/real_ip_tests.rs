use super::*;
use std::sync::Arc;
use tokio::sync::watch;

use crate::config::Config;
use crate::state::AppSnapshot;
use crate::waf::WafTlsMetadata;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

#[tokio::test]
async fn h3_inline_fast_path_uses_scoped_real_ip_before_source_cidr_route_matching() {
  let temp_dir = common::TempDir::new("h3-inline-scoped-real-ip");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "h3-scoped-real-ip");
  let raw = format!(
    r#"{}

[proxy.http3]
inline_bodyless_fast_path = true

[routes.match]
source_cidrs = ["203.0.113.0/24"]

[[proxy.real_ip.rules]]
name = "h3-edge"
hosts = ["example.com"]
server_names = ["edge.example.test"]
enabled = true
trusted_proxies = ["10.0.0.0/8"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = true
"#,
    common::minimal_config_toml(&cert_path, &key_path).replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    )
  );
  let config: Config = toml::from_str(&raw).expect("H3 scoped Real-IP config should parse");
  config
    .validate()
    .expect("H3 scoped Real-IP config should validate");
  let state = Arc::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  );
  let (_listener_tx, listener_rx) = watch::channel(false);
  let (_lifecycle_tx, lifecycle_rx) = watch::channel(false);
  let context = H3DownstreamRequestContext {
    peer_addr: "10.0.0.7:443".parse().unwrap(),
    udp_connection_id: Arc::from("h3-scoped-real-ip"),
    tls_metadata: Arc::new(WafTlsMetadata {
      enabled: true,
      sni: Some("edge.example.test".to_string()),
      ..WafTlsMetadata::default()
    }),
    connection_limit_context: None,
    state,
    drain: ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO),
  };
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_3)
    .uri("https://example.com/read")
    .header("x-forwarded-for", "203.0.113.24")
    .body(())
    .unwrap();

  assert!(h3_inline_fast_path_candidate(&request, &context));

  let no_sni = H3DownstreamRequestContext {
    tls_metadata: Arc::new(WafTlsMetadata::default()),
    ..context
  };
  assert!(
    !h3_inline_fast_path_candidate(&request, &no_sni),
    "an SNI-scoped policy must not be selected when no received SNI is available"
  );
}
