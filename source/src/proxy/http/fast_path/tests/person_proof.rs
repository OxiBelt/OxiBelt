use std::sync::Arc;
use std::time::Duration;

use http::{Request, StatusCode};
use http_body_util::BodyExt;

use super::{
  common, empty_proxy_body, parse_config, plain_proxy_fast_path_eligible, resolved_route,
};
use crate::lifecycle::ConnectionDrain;
use crate::state::AppSnapshot;
use crate::waf::{WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork};

fn upstream_pool_person_proof_config(
  cert_path: &std::path::Path,
  key_path: &std::path::Path,
  upstream_origin: &str,
) -> String {
  format!(
    "{}{}",
    common::minimal_config_toml(cert_path, key_path)
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      )
      .replace("upstream = \"app\"\n", "upstream_pool = \"app-pool\"\n"),
    format_args!(
      r#"

[waf]
enabled = true
mode = "enforcing"
fail_policy = "closed"

[[waf.rules]]
name = "require-person-proof"
phase = "request"
priority = 10
when = "Request.Http.Path == '/protected'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
clearance.cookie.key = "__test_person_proof"
openapi_path = "/custom/person-proof/openapi.json"

[[upstream_pools]]
name = "app-pool"
algorithm = "power_of_two_choices"

[[upstream_pools.servers]]
origin = "{upstream_origin}"
"#
    )
  )
}

#[tokio::test]
async fn person_proof_api_paths_skip_upstream_pool_plain_proxy_fast_path() {
  let temp_dir = common::TempDir::new("plain-fast-path-person-proof-api");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-person-proof-api");
  let raw =
    upstream_pool_person_proof_config(&cert_path, &key_path, "https://app.internal.example");
  let state = AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize");
  let resolved = resolved_route(&state);

  assert!(resolved.execution_plan.fast_path.plain_proxy_h1);
  assert!(
    state
      .waf
      .has_person_proof_api_path("/.oxibelt/person-proof/verify")
  );
  assert!(
    state
      .waf
      .has_person_proof_api_path("/custom/person-proof/openapi.json")
  );

  let protected = Request::builder()
    .uri("https://example.com/protected")
    .body(empty_proxy_body())
    .expect("request should build");
  assert!(plain_proxy_fast_path_eligible(
    &protected, &state, &resolved
  ));

  for path in [
    "/.oxibelt/person-proof/verify",
    "/custom/person-proof/openapi.json",
  ] {
    let api_request = Request::builder()
      .uri(format!("https://example.com{path}"))
      .body(empty_proxy_body())
      .expect("request should build");
    assert!(!plain_proxy_fast_path_eligible(
      &api_request,
      &state,
      &resolved
    ));
  }
}

#[tokio::test]
async fn person_proof_api_handler_wins_over_upstream_pool_fast_path() {
  let temp_dir = common::TempDir::new("plain-fast-path-person-proof-handler");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-person-proof-handler");
  let raw = upstream_pool_person_proof_config(&cert_path, &key_path, "http://127.0.0.1:9");
  let state = Arc::new(
    AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize"),
  );
  let request = Request::builder()
    .uri("http://example.com/.oxibelt/person-proof/verify")
    .body(empty_proxy_body())
    .expect("request should build");
  let peer_addr = "127.0.0.1:12345".parse().unwrap();
  let (_listener_tx, listener_rx) = tokio::sync::watch::channel(false);
  let (_lifecycle_tx, lifecycle_rx) = tokio::sync::watch::channel(false);
  let response = super::super::super::handle_inner(
    request,
    peer_addr,
    None,
    WafTransportMetadataInput::default(),
    Arc::new(WafTlsMetadata::default()),
    None,
    None,
    state,
    WafProtocol::Http,
    WafTransportNetwork::Tcp,
    true,
    "http",
    ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO),
  )
  .await;

  assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
  let body = response
    .into_body()
    .collect()
    .await
    .expect("response body should collect")
    .to_bytes();
  assert_eq!(&body[..], b"method not allowed");
}
