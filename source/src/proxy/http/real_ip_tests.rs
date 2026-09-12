use super::*;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};

use crate::config::{Config, ConnectionLimitIdentityMode, ForwardedHeaderMode, PriorityClass};
use crate::lifecycle::ConnectionDrain;
use crate::limits::ConnectionLimitContext;
use crate::state::AppSnapshot;
use crate::waf::{WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

async fn scoped_real_ip_snapshot() -> Arc<AppSnapshot> {
  scoped_real_ip_snapshot_with_options(true, false).await
}

async fn scoped_real_ip_snapshot_with_waf(waf_enabled: bool) -> Arc<AppSnapshot> {
  scoped_real_ip_snapshot_with_options(waf_enabled, false).await
}

async fn scoped_first_request_real_ip_snapshot() -> Arc<AppSnapshot> {
  scoped_real_ip_snapshot_with_options(true, true).await
}

async fn scoped_real_ip_snapshot_with_options(
  waf_enabled: bool,
  first_request_real_ip: bool,
) -> Arc<AppSnapshot> {
  let temp_dir = common::TempDir::new("http-scoped-real-ip");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "scoped-real-ip");
  let base_config = common::minimal_config_toml(&cert_path, &key_path);
  let base_config = if waf_enabled {
    base_config
  } else {
    base_config.replace("max_http_version = \"h2\"", "max_http_version = \"h3\"")
  };
  let raw = format!(
    r#"{}

[[routes]]
name = "tenant-route"
hosts = ["tenant.example.test"]
path_prefix = "/"
upstream = "app"
priority_class = "interactive"

[routes.match]
source_cidrs = ["203.0.113.0/24"]

[[proxy.real_ip.rules]]
name = "tenant-edge"
hosts = ["tenant.example.test"]
server_names = ["edge.example.test"]
enabled = true
trusted_proxies = ["10.0.0.0/8"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = true

[waf]
enabled = {waf_enabled}

[[waf.rules]]
name = "block-scoped-client"
phase = "request"
priority = 10
when = "Request.Client.Ip.inCidr('203.0.113.0/24')"

[[waf.rules.actions]]
type = "reject"
status = 451
"#,
    base_config
  );
  let mut config: Config = toml::from_str(&raw).expect("scoped Real-IP config should parse");
  if first_request_real_ip {
    config.limits.connection_limit_identity = ConnectionLimitIdentityMode::FirstRequestRealIp;
    config.limits.max_connections_per_ip = 1;
  }
  config
    .validate()
    .expect("scoped Real-IP config should validate");
  Arc::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  )
}

#[tokio::test]
async fn scoped_real_ip_reaches_source_cidr_routes_and_priority_admission() {
  let state = scoped_real_ip_snapshot().await;
  let peer = "10.0.0.7:443".parse().unwrap();
  let tls = WafTlsMetadata {
    enabled: true,
    sni: Some("edge.example.test".to_string()),
    ..WafTlsMetadata::default()
  };
  let request = Request::builder()
    .method(Method::GET)
    .uri("https://tenant.example.test/")
    .header("x-forwarded-for", "203.0.113.24")
    .body(())
    .unwrap();

  let client = state
    .resolve_client_addr(
      request.headers(),
      peer,
      "tenant.example.test",
      tls.sni.as_deref(),
    )
    .expect("matching Host and SNI should select the tenant identity policy");
  assert_eq!(client.ip().to_string(), "203.0.113.24");

  let admission = priority_admission::classify(
    &request,
    peer,
    &tls,
    state.as_ref(),
    WafProtocol::Http,
    WafTransportNetwork::Tcp,
  );
  assert_eq!(admission.class, PriorityClass::Interactive);
}

#[tokio::test]
async fn scoped_real_ip_requires_every_present_selector_before_overriding_fallback() {
  let state = scoped_real_ip_snapshot().await;
  let peer = "10.0.0.7:443".parse().unwrap();
  let mut headers = HeaderMap::new();
  headers.insert("x-forwarded-for", "203.0.113.24".parse().unwrap());

  let matched = state
    .resolve_client_addr(
      &headers,
      peer,
      "tenant.example.test",
      Some("edge.example.test"),
    )
    .expect("matching selectors should resolve the forwarded address");
  assert_eq!(matched.ip().to_string(), "203.0.113.24");

  let different_sni = state
    .resolve_client_addr(
      &headers,
      peer,
      "tenant.example.test",
      Some("other.example.test"),
    )
    .expect("nonmatching SNI should use the global fallback policy");
  assert_eq!(different_sni, peer);
}

fn proxy_request(
  forwarded_ip: &str,
) -> Request<impl Body<Data = bytes::Bytes, Error = body::BoxError> + Send + Sync + Unpin + 'static>
{
  Request::builder()
    .method(Method::GET)
    .uri("https://tenant.example.test/")
    .header(http::header::HOST, "tenant.example.test")
    .header("x-forwarded-for", forwarded_ip)
    .body(Full::new(bytes::Bytes::new()).map_err(|never| -> body::BoxError { match never {} }))
    .expect("proxy request should build")
}

fn test_drain() -> ConnectionDrain {
  let (_listener_tx, listener_rx) = tokio::sync::watch::channel(false);
  let (_lifecycle_tx, lifecycle_rx) = tokio::sync::watch::channel(false);
  ConnectionDrain::new(listener_rx, lifecycle_rx, std::time::Duration::ZERO)
}

#[tokio::test]
async fn scoped_real_ip_reaches_waf_and_forwarded_headers() {
  let state = scoped_real_ip_snapshot().await;
  let peer = "10.0.0.7:443".parse().unwrap();
  let tls = Arc::new(WafTlsMetadata {
    enabled: true,
    sni: Some("edge.example.test".to_string()),
    ..WafTlsMetadata::default()
  });
  let request = proxy_request("203.0.113.24");
  let client = state
    .resolve_client_addr(
      request.headers(),
      peer,
      "tenant.example.test",
      tls.sni.as_deref(),
    )
    .expect("selected rule should resolve the forwarded identity");
  let mut forwarded = HeaderMap::new();
  headers::add_forwarded_headers(
    &mut forwarded,
    client,
    "tenant.example.test",
    "https",
    443,
    ForwardedHeaderMode::Overwrite,
    None,
  );
  assert_eq!(forwarded["x-forwarded-for"], "203.0.113.24");

  let response = entry::handle_inner(
    request,
    peer,
    None,
    WafTransportMetadataInput::default(),
    tls,
    None,
    None,
    state,
    WafProtocol::Http,
    WafTransportNetwork::Tcp,
    true,
    "https",
    test_drain(),
  )
  .await;
  assert_eq!(response.status(), StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS);
}

#[tokio::test]
async fn per_request_real_ip_is_reselected_while_first_request_context_stays_bound() {
  let state = scoped_first_request_real_ip_snapshot().await;
  let peer = "10.0.0.7:443".parse().unwrap();
  let tls = Arc::new(WafTlsMetadata {
    enabled: true,
    sni: Some("edge.example.test".to_string()),
    ..WafTlsMetadata::default()
  });
  let context = ConnectionLimitContext::default();

  let first_request = proxy_request("203.0.113.24");
  let first = state
    .resolve_client_addr(
      first_request.headers(),
      peer,
      "tenant.example.test",
      tls.sni.as_deref(),
    )
    .expect("first request identity should resolve");
  let first_response = entry::handle_inner(
    first_request,
    peer,
    None,
    WafTransportMetadataInput::default(),
    tls.clone(),
    Some(context.clone()),
    None,
    state.clone(),
    WafProtocol::Http,
    WafTransportNetwork::Tcp,
    true,
    "https",
    test_drain(),
  )
  .await;
  assert_eq!(
    first_response.status(),
    StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
  );

  let later = state
    .resolve_client_addr(
      proxy_request("198.51.100.25").headers(),
      peer,
      "tenant.example.test",
      tls.sni.as_deref(),
    )
    .expect("later request identity should resolve independently");
  assert_eq!(later.ip().to_string(), "198.51.100.25");
  let later_response = entry::handle_inner(
    proxy_request("198.51.100.25"),
    peer,
    None,
    WafTransportMetadataInput::default(),
    tls,
    Some(context.clone()),
    None,
    state.clone(),
    WafProtocol::Http,
    WafTransportNetwork::Tcp,
    true,
    "https",
    test_drain(),
  )
  .await;
  assert_eq!(later_response.status(), StatusCode::NOT_FOUND);
  assert_eq!(
    context.bind_or_get_first_request_ip(later.ip()).await,
    first.ip(),
    "first_request_real_ip must retain the connection's initial identity"
  );
  assert_eq!(
    state
      .limits
      .acquire_ip_connection(
        first.ip(),
        &state.config.limits,
        &state.config.connection_limits
      )
      .err(),
    Some(StatusCode::TOO_MANY_REQUESTS),
    "the connection context must keep the first scoped client permit"
  );
}

#[tokio::test]
async fn webtransport_preparation_uses_scoped_client_identity() {
  let state = scoped_real_ip_snapshot_with_waf(false).await;
  let request = Request::builder()
    .method(Method::CONNECT)
    .version(http::Version::HTTP_3)
    .uri("https://tenant.example.test/session")
    .header(http::header::HOST, "tenant.example.test")
    .header("wt-available-protocols", "chat")
    .header("x-forwarded-for", "203.0.113.24")
    .body(())
    .expect("WebTransport request should build");
  let tls = WafTlsMetadata {
    enabled: true,
    sni: Some("edge.example.test".to_string()),
    ..WafTlsMetadata::default()
  };

  let prepared = webtransport::prepare_webtransport(
    &request,
    "10.0.0.7:443".parse().unwrap(),
    WafTransportMetadataInput::default(),
    &tls,
    state.as_ref(),
  )
  .await
  .expect("source-CIDR WebTransport route should use the scoped identity");
  assert_eq!(prepared.client_addr.ip().to_string(), "203.0.113.24");
  assert_eq!(prepared.headers["x-forwarded-for"], "203.0.113.24");
}
