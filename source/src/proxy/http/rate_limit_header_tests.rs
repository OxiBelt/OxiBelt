mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use std::sync::Arc;
use std::time::Duration;

use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use pretty_assertions::assert_eq;

use super::*;
use crate::config::Config;

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

#[tokio::test]
async fn public_request_advertises_checked_pre_route_and_route_policies_on_allow_and_deny() {
  let (state, _temp_dir) = state_with_static_route(
    r#"
[[rate_limits]]
name = "client-wide"
policy_id = "client-wide"
key = "client_ip"
rate = "1r/h"
burst = 10
status = 429

[[rate_limits]]
name = "route-specific"
policy_id = "route-specific"
key = "client_ip_route"
routes = ["app-root"]
rate = "1r/h"
burst = 1
status = 429
"#,
  )
  .await;

  let allowed = public_request(state.clone()).await;
  assert_eq!(allowed.status(), StatusCode::OK);
  assert_eq!(
    allowed.headers().get_all("ratelimit-policy").iter().count(),
    1,
    "both checked policies should be serialized in one field value"
  );
  assert_eq!(
    allowed.headers()["ratelimit-policy"],
    "\"oxibelt/client-wide\";q=10, \"oxibelt/route-specific\";q=1"
  );
  assert_eq!(
    allowed.headers()["ratelimit"],
    "\"oxibelt/client-wide\";r=9, \"oxibelt/route-specific\";r=0;t=3600"
  );
  assert!(
    allowed.headers()[http::header::CACHE_CONTROL]
      .to_str()
      .expect("cache control should be text")
      .contains("private")
  );

  let denied = public_request(state).await;
  assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
  assert_eq!(
    denied.headers()["ratelimit-policy"],
    "\"oxibelt/client-wide\";q=10, \"oxibelt/route-specific\";q=1"
  );
  assert_eq!(
    denied.headers()["ratelimit"],
    "\"oxibelt/client-wide\";r=8, \"oxibelt/route-specific\";r=0;t=3600"
  );
}

#[tokio::test]
async fn top_level_rate_limits_are_silent_without_policy_id_opt_in() {
  let (state, _temp_dir) = state_with_static_route(
    r#"
[[rate_limits]]
name = "legacy-limit"
key = "client_ip"
rate = "1r/h"
burst = 1
status = 429
"#,
  )
  .await;

  let allowed = public_request(state.clone()).await;
  assert_eq!(allowed.status(), StatusCode::OK);
  assert!(!allowed.headers().contains_key("ratelimit-policy"));
  assert!(!allowed.headers().contains_key("ratelimit"));

  let denied = public_request(state).await;
  assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
  assert!(!denied.headers().contains_key("ratelimit-policy"));
  assert!(!denied.headers().contains_key("ratelimit"));
}

#[tokio::test]
async fn http2_and_http3_requests_keep_their_downstream_version_and_rate_limit_fields() {
  for (version, network) in [
    (http::Version::HTTP_2, WafTransportNetwork::Tcp),
    (http::Version::HTTP_3, WafTransportNetwork::Udp),
  ] {
    let (state, _temp_dir) = state_with_static_route(
      r#"
[[rate_limits]]
name = "protocol-policy"
policy_id = "protocol-policy"
key = "client_ip"
rate = "1r/h"
burst = 2
status = 429
"#,
    )
    .await;

    let response = public_request_with_version(state, version, network).await;
    assert_eq!(response.status(), StatusCode::OK, "downstream {version:?}");
    assert_eq!(response.version(), version, "downstream {version:?}");
    assert_eq!(
      response.headers()["ratelimit-policy"],
      "\"oxibelt/protocol-policy\";q=2",
      "downstream {version:?}"
    );
    assert_eq!(
      response.headers()["ratelimit"],
      "\"oxibelt/protocol-policy\";r=1",
      "downstream {version:?}"
    );
  }
}

async fn state_with_static_route(rate_limits: &str) -> (Arc<AppSnapshot>, common::TempDir) {
  let temp_dir = common::TempDir::new("rate-limit-header-wire");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "rate-limit-header-wire");
  let static_root = temp_dir.path().join("public");
  std::fs::create_dir(&static_root).expect("static root should be created");
  std::fs::write(static_root.join("ok.txt"), "ok").expect("static fixture should be written");
  let config = common::minimal_config_toml(&cert_path, &key_path).replace(
    "upstream = \"app\"",
    &format!("static_root = \"{}\"", static_root.display()),
  );
  let raw = format!("{config}\n{rate_limits}");
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  (Arc::new(state), temp_dir)
}

async fn public_request(state: Arc<AppSnapshot>) -> Response<ProxyBody> {
  public_request_with_version(state, http::Version::HTTP_11, WafTransportNetwork::Tcp).await
}

async fn public_request_with_version(
  state: Arc<AppSnapshot>,
  version: http::Version,
  network: WafTransportNetwork,
) -> Response<ProxyBody> {
  let request = Request::builder()
    .method(Method::GET)
    .uri("/ok.txt")
    .version(version)
    .header(http::header::HOST, "example.com")
    .body(
      Full::new(bytes::Bytes::new())
        .map_err(|never| -> body::BoxError { match never {} })
        .boxed(),
    )
    .expect("request should build");
  handle_inner(
    request,
    "203.0.113.10:49152".parse().unwrap(),
    None,
    WafTransportMetadataInput::default(),
    Arc::new(WafTlsMetadata::default()),
    None,
    None,
    state,
    WafProtocol::Http,
    network,
    version != http::Version::HTTP_3,
    "https",
    test_drain(),
  )
  .await
}

fn test_drain() -> ConnectionDrain {
  let (_listener_tx, listener_rx) = tokio::sync::watch::channel(false);
  let (_lifecycle_tx, lifecycle_rx) = tokio::sync::watch::channel(false);
  ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO)
}
