use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::Method;
use hyper::body::{Body, Frame, SizeHint};

use super::super::{
  DownstreamDirectH1RequestBuild, DownstreamDirectH1RequestOptions,
  fast_path_request_body_empty_probe_allowed, fast_path_request_body_with_metrics,
  request_body_definitely_empty, select_compiled_proxy_action,
  try_build_downstream_direct_h1_request,
};
use super::{common, parse_config};
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body;
use crate::proxy::http::headers::ForwardedRequestHeaderValues;
use crate::state::AppSnapshot;
use crate::waf::RequestWafDecision;

#[derive(Debug)]
struct ProbeEofBody;

impl Body for ProbeEofBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    Poll::Ready(None)
  }

  fn is_end_stream(&self) -> bool {
    false
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

async fn state_with_plain_upstream(origin: &str, metrics_detail: &str) -> AppSnapshot {
  let temp_dir = common::TempDir::new("plain-fast-path-local-upstream");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "plain-fast-path-local-upstream");
  let config = common::minimal_config_toml(&cert_path, &key_path)
    .replace(
      "[compression]\nenabled = true",
      "[compression]\nenabled = false",
    )
    .replace(
      "origin = \"https://app.internal.example\"\nmax_http_version = \"h2\"",
      &format!("origin = \"{origin}\"\nmax_http_version = \"h1\""),
    );
  let raw = format!(
    r#"{config}

[metrics]
enabled = true
detail = "{metrics_detail}"
"#
  );
  AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize")
}

async fn assert_probe_empty_request_uses_direct_h1_build(
  request_version: http::Version,
  path_protocol: &str,
) -> anyhow::Result<()> {
  let state = state_with_plain_upstream("http://app.internal.example", "detailed").await;
  let request_uri = format!("https://example.com/perf/{path_protocol}?body=ok");
  let request = http::Request::builder()
    .method(Method::GET)
    .version(request_version)
    .uri(&request_uri)
    .body(ProbeEofBody)
    .expect("request should build");
  assert!(!request_body_definitely_empty(&request));
  let resolved = state
    .route_table
    .resolve(
      "example.com",
      &format!("/perf/{path_protocol}"),
      &state.upstreams,
    )
    .expect("route should resolve");
  let actions = state
    .compiled_fast_path_actions(resolved.route_index)
    .expect("compiled action should exist");
  let compiled =
    select_compiled_proxy_action(&state, Some(actions), &request, request_version, false)?
      .expect("compiled proxy action should select");
  let (parts, body) = request.into_parts();
  let request_body = fast_path_request_body_with_metrics(
    body,
    resolved
      .route
      .effective_max_request_body_bytes(&state.config.limits) as usize,
    EffectiveTimeouts::route_body_only(&state.config, resolved.route),
    false,
    fast_path_request_body_empty_probe_allowed(&parts.method, request_version, &parts.headers),
    None,
  )
  .await;
  assert!(request_body.proven_empty());
  let forwarded_values = ForwardedRequestHeaderValues::new("example.com", 443);
  let built = try_build_downstream_direct_h1_request(
    parts,
    DownstreamDirectH1RequestOptions {
      selected: &compiled,
      downstream_version: request_version,
      forwarded_client_addr: "203.0.113.10:5443".parse().unwrap(),
      downstream_scheme: "https",
      downstream_host: "example.com",
      downstream_port: 443,
      forwarded_header_cache: None,
      forwarded_request_header_values: &forwarded_values,
      compression_enabled: state.config.compression.enabled,
      request_body_definitely_empty: request_body.proven_empty(),
      request_waf_context_disabled: true,
      request_waf: &RequestWafDecision::default(),
      verified_early_data: false,
    },
  )?;
  let DownstreamDirectH1RequestBuild::Built(request) = built else {
    panic!("probe-proven empty {path_protocol} request should build direct-H1 request");
  };
  assert_eq!(request.version(), http::Version::HTTP_11);
  assert_eq!(
    request.uri().to_string(),
    format!("/perf/{path_protocol}?body=ok")
  );
  assert!(request.body().is_end_stream());
  assert!(!request.headers().contains_key(http::header::CONNECTION));
  Ok(())
}

#[tokio::test]
async fn h2_empty_probe_request_uses_post_probe_direct_h1_build() -> anyhow::Result<()> {
  assert_probe_empty_request_uses_direct_h1_build(http::Version::HTTP_2, "h2").await
}

#[tokio::test]
async fn h3_empty_probe_request_uses_post_probe_direct_h1_build() -> anyhow::Result<()> {
  assert_probe_empty_request_uses_direct_h1_build(http::Version::HTTP_3, "h3").await
}
