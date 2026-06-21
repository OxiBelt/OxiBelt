//! Downstream HTTP/2 or HTTP/3 to upstream HTTP/1.1 direct request preparation.
//! This keeps the benchmark-safe empty-body path out of the generic rebuild helper.

use std::net::SocketAddr;

use anyhow::Context;
use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, HOST};
use http::{Method, Request, Uri, request};
use http_body_util::{BodyExt, Empty};

use crate::config::{HttpVersion, ProxyProtocolEgressMode};
use crate::proxy::http::body::{self, ProxyBody};
use crate::proxy::http::headers::{
  ForwardedHeaderCache, ForwardedRequestHeaderValues, add_forwarded_headers_with_values,
  set_effective_host_header_value, strip_hop_by_hop_headers,
};
use crate::proxy::http::semantics;
use crate::waf::RequestWafDecision;

use super::compiled::SelectedCompiledProxyAction;
use super::helpers::apply_fast_path_priority_policy;

pub(super) enum DownstreamDirectH1RequestBuild {
  Built(Request<ProxyBody>),
  Fallback(request::Parts),
}

pub(super) enum DownstreamDirectH1Preparation<B> {
  DirectH1(Request<ProxyBody>),
  Generic(request::Parts, B),
}

pub(super) struct DownstreamDirectH1RequestOptions<'a, 'state> {
  pub(super) selected: &'a SelectedCompiledProxyAction<'state>,
  pub(super) downstream_version: http::Version,
  pub(super) forwarded_client_addr: SocketAddr,
  pub(super) downstream_scheme: &'static str,
  pub(super) downstream_host: &'a str,
  pub(super) downstream_port: u16,
  pub(super) forwarded_header_cache: Option<&'a ForwardedHeaderCache>,
  pub(super) forwarded_request_header_values: &'a ForwardedRequestHeaderValues,
  pub(super) compression_enabled: bool,
  pub(super) request_body_definitely_empty: bool,
  pub(super) request_waf_context_disabled: bool,
  pub(super) request_waf: &'a RequestWafDecision,
}

pub(super) fn prepare_downstream_direct_h1_or_generic<B>(
  parts: request::Parts,
  body: B,
  options: Option<DownstreamDirectH1RequestOptions<'_, '_>>,
) -> anyhow::Result<DownstreamDirectH1Preparation<B>> {
  let Some(options) = options else {
    return Ok(DownstreamDirectH1Preparation::Generic(parts, body));
  };
  match try_build_downstream_direct_h1_request(parts, options)? {
    DownstreamDirectH1RequestBuild::Built(outbound) => {
      Ok(DownstreamDirectH1Preparation::DirectH1(outbound))
    }
    DownstreamDirectH1RequestBuild::Fallback(parts) => {
      Ok(DownstreamDirectH1Preparation::Generic(parts, body))
    }
  }
}

pub(super) fn try_build_downstream_direct_h1_request(
  mut parts: request::Parts,
  options: DownstreamDirectH1RequestOptions<'_, '_>,
) -> anyhow::Result<DownstreamDirectH1RequestBuild> {
  if !eligible(&parts, &options) {
    return Ok(DownstreamDirectH1RequestBuild::Fallback(parts));
  }

  let path_and_query = options.selected.target_path_and_query(&parts.uri)?;
  let mut uri_parts = http::uri::Parts::default();
  uri_parts.path_and_query = Some(path_and_query);
  parts.uri = Uri::from_parts(uri_parts)
    .context("failed to build direct downstream-to-H1 origin-form URI")?;
  parts.version = http::Version::HTTP_11;

  strip_hop_by_hop_headers(&mut parts.headers);
  if options.selected.preserve_host {
    set_effective_host_header_value(
      &mut parts.headers,
      options.forwarded_request_header_values.host(),
    );
  } else {
    parts.headers.remove(HOST);
  }

  add_forwarded_headers_with_values(
    &mut parts.headers,
    options.forwarded_client_addr,
    options.downstream_host,
    options.downstream_scheme,
    options.downstream_port,
    options.selected.forwarded_header_mode,
    options.forwarded_header_cache,
    Some(options.forwarded_request_header_values),
  );

  if options.compression_enabled {
    parts.headers.remove(ACCEPT_ENCODING);
  }

  semantics::strip_accepted_expect(&mut parts.headers);
  apply_fast_path_priority_policy(&mut parts.headers, options.selected.priority);

  Ok(DownstreamDirectH1RequestBuild::Built(Request::from_parts(
    parts,
    empty_body(),
  )))
}

fn eligible(parts: &request::Parts, options: &DownstreamDirectH1RequestOptions<'_, '_>) -> bool {
  matches!(
    options.downstream_version,
    http::Version::HTTP_2 | http::Version::HTTP_3
  ) && parts.version == options.downstream_version
    && matches!(parts.method, Method::GET | Method::HEAD)
    && options.request_body_definitely_empty
    && options.request_waf_context_disabled
    && options.request_waf.request_header_mutations.is_empty()
    && options.request_waf.response_header_mutations.is_empty()
    && !options.selected.response_waf_enabled
    && options.selected.upstream_version == HttpVersion::H1
    && options.selected.upstream.origin.scheme() == "http"
    && options.selected.upstream.proxy_protocol_egress == ProxyProtocolEgressMode::Off
}

fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}

#[cfg(test)]
mod tests {
  use std::future::Future;

  use http::header::{ACCEPT_ENCODING, CONNECTION, HOST, HeaderValue};
  use http_body_util::Full;
  use hyper::body::Body;

  use super::*;
  use crate::config::Config;
  use crate::proxy::http::fast_path::compiled::select_compiled_proxy_action;
  use crate::state::AppSnapshot;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  async fn state(extra: &str) -> AppSnapshot {
    state_with_preserve_host(extra, false).await
  }

  async fn state_with_preserve_host(extra: &str, preserve_host: bool) -> AppSnapshot {
    let temp_dir = common::TempDir::new("downstream-direct-h1-request");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "downstream-direct-h1-request");
    let mut raw = common::minimal_config_toml(&cert_path, &key_path)
      .replace(
        "[compression]\nenabled = true",
        "[compression]\nenabled = false",
      )
      .replace(
        "origin = \"https://app.internal.example\"\nmax_http_version = \"h2\"",
        "origin = \"http://app.internal.example\"\nmax_http_version = \"h1\"",
      );
    if preserve_host {
      raw = raw.replace("preserve_host = false", "preserve_host = true");
    }
    raw.push_str(extra);
    AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize")
  }

  async fn build(
    state: &AppSnapshot,
    request_version: http::Version,
    mut request: Request<ProxyBody>,
    request_body_definitely_empty: bool,
    request_waf: &RequestWafDecision,
  ) -> anyhow::Result<DownstreamDirectH1RequestBuild> {
    *request.version_mut() = request_version;
    let resolved = state
      .route_table
      .resolve("example.com", request.uri().path(), &state.upstreams)
      .expect("route should resolve");
    let actions = state
      .compiled_fast_path_actions(resolved.route_index)
      .expect("compiled actions should exist");
    let Some(selected) =
      select_compiled_proxy_action(state, Some(actions), &request, request_version, false)?
    else {
      let (parts, _) = request.into_parts();
      return Ok(DownstreamDirectH1RequestBuild::Fallback(parts));
    };
    let (parts, _) = request.into_parts();
    let forwarded_values = ForwardedRequestHeaderValues::new("example.com", 443);
    try_build_downstream_direct_h1_request(
      parts,
      DownstreamDirectH1RequestOptions {
        selected: &selected,
        downstream_version: request_version,
        forwarded_client_addr: "203.0.113.10:5443".parse().unwrap(),
        downstream_scheme: "https",
        downstream_host: "example.com",
        downstream_port: 443,
        forwarded_header_cache: None,
        forwarded_request_header_values: &forwarded_values,
        compression_enabled: state.config.compression.enabled,
        request_body_definitely_empty,
        request_waf_context_disabled: true,
        request_waf,
      },
    )
  }

  fn request(method: Method, uri: &str) -> Request<ProxyBody> {
    Request::builder()
      .method(method)
      .uri(uri)
      .header(CONNECTION, "keep-alive")
      .header(ACCEPT_ENCODING, "gzip")
      .body(
        Full::new(Bytes::new())
          .map_err(|never| -> body::BoxError { match never {} })
          .boxed(),
      )
      .expect("request should build")
  }

  fn run_async_on_larger_stack<F, Fut>(name: &str, test: F)
  where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
  {
    std::thread::Builder::new()
      .name(name.to_owned())
      .stack_size(32 * 1024 * 1024)
      .spawn(move || {
        tokio::runtime::Builder::new_current_thread()
          .enable_all()
          .build()
          .expect("runtime should build")
          .block_on(test());
      })
      .expect("test thread should spawn")
      .join()
      .expect("test thread should finish");
  }

  #[test]
  fn builds_origin_form_h1_request_for_empty_h2_get() {
    run_async_on_larger_stack("h2-direct-h1-origin-form", || async {
      builds_origin_form_h1_request_for_empty_h2_get_inner(http::Version::HTTP_2, "h2")
        .await
        .expect("H2 direct-H1 request should build");
    });
  }

  #[test]
  fn builds_origin_form_h1_request_for_empty_h3_get() {
    run_async_on_larger_stack("h3-direct-h1-origin-form", || async {
      builds_origin_form_h1_request_for_empty_h2_get_inner(http::Version::HTTP_3, "h3")
        .await
        .expect("H3 direct-H1 request should build");
    });
  }

  async fn builds_origin_form_h1_request_for_empty_h2_get_inner(
    request_version: http::Version,
    path_protocol: &str,
  ) -> anyhow::Result<()> {
    let state = state("").await;
    let built = match build(
      &state,
      request_version,
      request(
        Method::GET,
        &format!("https://example.com/perf/{path_protocol}?body=ok"),
      ),
      true,
      &RequestWafDecision::default(),
    )
    .await?
    {
      DownstreamDirectH1RequestBuild::Built(request) => request,
      DownstreamDirectH1RequestBuild::Fallback(_) => {
        panic!("request should use downstream direct-H1 build")
      }
    };

    assert_eq!(built.version(), http::Version::HTTP_11);
    assert_eq!(
      built.uri().to_string(),
      format!("/perf/{path_protocol}?body=ok")
    );
    assert!(!built.headers().contains_key(CONNECTION));
    assert!(!built.headers().contains_key(HOST));
    assert_eq!(
      built.headers()["x-forwarded-host"],
      HeaderValue::from_static("example.com")
    );
    assert_eq!(
      built.headers()["x-forwarded-proto"],
      HeaderValue::from_static("https")
    );
    assert!(built.body().is_end_stream());
    Ok(())
  }

  #[test]
  fn preserves_host_when_upstream_requires_it() {
    run_async_on_larger_stack("h2-direct-h1-preserve-host", || async {
      preserves_host_when_upstream_requires_it_inner()
        .await
        .expect("H2 direct-H1 preserve-host request should build");
    });
  }

  async fn preserves_host_when_upstream_requires_it_inner() -> anyhow::Result<()> {
    let state = state_with_preserve_host("", true).await;
    let built = match build(
      &state,
      http::Version::HTTP_2,
      request(Method::HEAD, "https://example.com/preserve"),
      true,
      &RequestWafDecision::default(),
    )
    .await?
    {
      DownstreamDirectH1RequestBuild::Built(request) => request,
      DownstreamDirectH1RequestBuild::Fallback(_) => {
        panic!("request should use downstream direct-H1 build")
      }
    };

    assert_eq!(
      built.headers()[HOST],
      HeaderValue::from_static("example.com")
    );
    Ok(())
  }

  #[test]
  fn falls_back_for_non_empty_or_mutated_requests() {
    run_async_on_larger_stack("h2-direct-h1-fallback-mutated", || async {
      falls_back_for_non_empty_or_mutated_requests_inner()
        .await
        .expect("H2 direct-H1 fallback checks should run");
    });
  }

  async fn falls_back_for_non_empty_or_mutated_requests_inner() -> anyhow::Result<()> {
    let state = state("").await;
    assert!(matches!(
      build(
        &state,
        http::Version::HTTP_3,
        request(Method::GET, "https://example.com/streaming"),
        false,
        &RequestWafDecision::default(),
      )
      .await?,
      DownstreamDirectH1RequestBuild::Fallback(_)
    ));

    let waf = RequestWafDecision {
      request_header_mutations: vec![crate::waf::HeaderMutation::Set {
        name: "x-test".parse().unwrap(),
        value: "mutated".parse().unwrap(),
      }],
      ..RequestWafDecision::default()
    };
    assert!(matches!(
      build(
        &state,
        http::Version::HTTP_3,
        request(Method::GET, "https://example.com/mutated"),
        true,
        &waf,
      )
      .await?,
      DownstreamDirectH1RequestBuild::Fallback(_)
    ));
    Ok(())
  }

  #[test]
  fn falls_back_for_non_safe_method() {
    run_async_on_larger_stack("h2-direct-h1-fallback-method", || async {
      falls_back_for_non_safe_method_inner()
        .await
        .expect("H2 direct-H1 method fallback should run");
    });
  }

  async fn falls_back_for_non_safe_method_inner() -> anyhow::Result<()> {
    let state = state("").await;
    assert!(matches!(
      build(
        &state,
        http::Version::HTTP_3,
        request(Method::POST, "https://example.com/post"),
        true,
        &RequestWafDecision::default(),
      )
      .await?,
      DownstreamDirectH1RequestBuild::Fallback(_)
    ));
    Ok(())
  }
}
