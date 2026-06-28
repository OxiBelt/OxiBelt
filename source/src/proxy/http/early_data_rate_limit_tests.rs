mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use pretty_assertions::assert_eq;

use super::*;
use crate::config::Config;

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

#[tokio::test]
async fn early_data_no_route_consumes_pre_route_rate_limit() {
  let state = rate_limited_state("").await;

  assert_eq!(
    handler_status(
      state.clone(),
      Method::GET,
      "missing.example.com",
      "/missing",
    )
    .await,
    StatusCode::NOT_FOUND
  );
  assert_eq!(
    handler_status(state, Method::GET, "missing.example.com", "/missing").await,
    StatusCode::TOO_MANY_REQUESTS
  );
}

#[tokio::test]
async fn early_data_method_rejection_consumes_pre_route_rate_limit() {
  let state = rate_limited_state(
    r#"

[routes.tls]
ssl_early_data = "safe_methods"
"#,
  )
  .await;

  assert_eq!(
    handler_status(state.clone(), Method::POST, "example.com", "/").await,
    StatusCode::TOO_EARLY
  );
  assert_eq!(
    handler_status(state, Method::POST, "example.com", "/").await,
    StatusCode::TOO_MANY_REQUESTS
  );
}

#[tokio::test]
async fn early_data_post_to_sensitive_static_route_returns_too_early() {
  let (state, _temp_dir) = static_early_data_state("off").await;

  assert_eq!(
    handler_status_with_version(
      state,
      Method::POST,
      "example.com",
      "/ok.txt",
      http::Version::HTTP_3,
    )
    .await,
    StatusCode::TOO_EARLY
  );
}

#[tokio::test]
async fn early_data_get_to_allowed_static_route_passes() {
  let (state, _temp_dir) = static_early_data_state("safe_methods").await;

  assert_eq!(
    handler_status_with_version(
      state,
      Method::GET,
      "example.com",
      "/ok.txt",
      http::Version::HTTP_3,
    )
    .await,
    StatusCode::OK
  );
}

async fn rate_limited_state(extra: &str) -> Arc<AppSnapshot> {
  let temp_dir = common::TempDir::new("early-data-rate-limit");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "early-data-rate-limit");
  let raw = format!(
    r#"
{}{}

[[rate_limits]]
name = "per-ip"
key = "client_ip"
rate = "1r/h"
burst = 1
status = 429
"#,
    common::minimal_config_toml(&cert_path, &key_path),
    extra
  );
  Arc::new(
    AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize"),
  )
}

async fn static_early_data_state(mode: &str) -> (Arc<AppSnapshot>, common::TempDir) {
  let temp_dir = common::TempDir::new("early-data-static-route");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "early-data-static-route");
  let static_root = temp_dir.path().join("public");
  std::fs::create_dir(&static_root).expect("static root should be created");
  std::fs::write(static_root.join("ok.txt"), "ok").expect("static fixture should be written");
  let raw = format!(
    r#"
{}

[routes.tls]
ssl_early_data = "{mode}"
"#,
    common::minimal_config_toml(&cert_path, &key_path).replace(
      "upstream = \"app\"",
      &format!("static_root = \"{}\"", static_root.display()),
    ),
  );
  let state = Arc::new(
    AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize"),
  );
  (state, temp_dir)
}

async fn handler_status(
  state: Arc<AppSnapshot>,
  method: Method,
  host: &str,
  uri: &str,
) -> StatusCode {
  handler_status_with_version(state, method, host, uri, http::Version::HTTP_11).await
}

async fn handler_status_with_version(
  state: Arc<AppSnapshot>,
  method: Method,
  host: &str,
  uri: &str,
  version: http::Version,
) -> StatusCode {
  let mut request = Request::builder()
    .method(method)
    .uri(uri)
    .version(version)
    .header(http::header::HOST, host)
    .body(empty_body())
    .expect("request should build");
  early_data::mark_verified(&mut request);

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
    if version == http::Version::HTTP_3 {
      WafTransportNetwork::Udp
    } else {
      WafTransportNetwork::Tcp
    },
    true,
    "https",
    test_drain(),
  )
  .await
  .status()
}

fn empty_body()
-> impl Body<Data = bytes::Bytes, Error = body::BoxError> + Send + Sync + Unpin + 'static {
  Full::new(bytes::Bytes::new()).map_err(|never| -> body::BoxError { match never {} })
}

fn test_drain() -> ConnectionDrain {
  let (_listener_tx, listener_rx) = tokio::sync::watch::channel(false);
  let (_lifecycle_tx, lifecycle_rx) = tokio::sync::watch::channel(false);
  ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO)
}
