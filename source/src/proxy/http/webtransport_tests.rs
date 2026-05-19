mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use http::header::HOST;
use http::{Method, Request, StatusCode};
use pretty_assertions::assert_eq;

use super::prepare_webtransport;
use crate::config::Config;
use crate::state::AppSnapshot;
use crate::waf::{WafTlsMetadata, WafTransportMetadataInput};

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

fn webtransport_request() -> Request<()> {
  Request::builder()
    .method(Method::CONNECT)
    .version(http::Version::HTTP_3)
    .uri("https://example.com/session?token=1")
    .header(HOST, "example.com")
    .header("wt-available-protocols", "\"chat\", data")
    .body(())
    .expect("request should build")
}

#[tokio::test]
async fn prepare_webtransport_selects_direct_upstream() {
  let temp_dir = common::TempDir::new("direct-webtransport");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "direct-webtransport");
  let raw = format!(
    r#"
[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = true

[runtime.accept]
workers = "auto"
reuse_port = true

[quic.socket]
workers = "auto"
reuse_port = true

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[proxy.auto_upgrade]
enabled = true
max_http_version = "h3"

[[upstreams]]
name = "app"
origin = "https://app.example/origin"
max_http_version = "h3"
webtransport = true

[[routes]]
name = "direct-route"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#,
    cert = cert_path.display(),
    key = key_path.display(),
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");

  let prepared = prepare_webtransport(
    &webtransport_request(),
    "203.0.113.10:45678".parse().unwrap(),
    WafTransportMetadataInput::default(),
    &WafTlsMetadata::default(),
    &state,
  )
  .await
  .expect("direct WebTransport route should prepare");

  assert_eq!(prepared.upstream.name, "app");
  assert_eq!(
    prepared.target_url.as_str(),
    "https://app.example/origin/session?token=1"
  );
  assert_eq!(prepared.protocols, vec!["chat", "data"]);
}

#[tokio::test]
async fn prepare_webtransport_pool_route_returns_bad_gateway_without_panicking() {
  let temp_dir = common::TempDir::new("pool-webtransport");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "pool-webtransport");
  let raw = format!(
    r#"
[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = true

[runtime.accept]
workers = "auto"
reuse_port = true

[quic.socket]
workers = "auto"
reuse_port = true

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[[upstream_pools]]
name = "app-pool"
algorithm = "round_robin"

[[upstream_pools.servers]]
origin = "https://app-a.example/origin"

[[routes]]
name = "pool-route"
hosts = ["example.com"]
path_prefix = "/"
upstream_pool = "app-pool"
"#,
    cert = cert_path.display(),
    key = key_path.display(),
  );
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");

  let response = match prepare_webtransport(
    &webtransport_request(),
    "203.0.113.10:45678".parse().unwrap(),
    WafTransportMetadataInput::default(),
    &WafTlsMetadata::default(),
    &state,
  )
  .await
  {
    Ok(_) => panic!("pool route should be rejected with a response, not panic"),
    Err(response) => response,
  };

  assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}
