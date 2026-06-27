//! Request rebuild helpers for upstream forwarding.
//! Authority and encoding headers are set in one place to avoid route-specific drift.

use http::header::{ACCEPT_ENCODING, AUTHORIZATION, COOKIE, HOST, PROXY_AUTHORIZATION};
use http::{Request, Uri, request};
use http_body_util::BodyExt;
use hyper::body::Body;

use crate::config::{
  CompressionConfig, CompressionUpstreamAcceptEncodingMode, ForwardedHeaderMode, HttpVersion,
};
use crate::waf::{HeaderMutation, apply_header_mutations};

use super::body::{BoxError, ProxyBody};
use super::headers::{
  ForwardedHeaderCache, ForwardedRequestHeaderValues, add_forwarded_headers_with_values,
  set_effective_host_header, set_effective_host_header_value, strip_hop_by_hop_headers,
};
use super::version::upstream_request_version;

pub(crate) struct RebuildRequestOptions<'a> {
  pub(crate) target_uri: Uri,
  pub(crate) compression: &'a CompressionConfig,
  pub(crate) route_compression: Option<&'a str>,
  pub(crate) forwarded_client_addr: std::net::SocketAddr,
  pub(crate) downstream_host: &'a str,
  pub(crate) downstream_scheme: &'a str,
  pub(crate) downstream_port: u16,
  pub(crate) forwarded_header_mode: ForwardedHeaderMode,
  pub(crate) forwarded_header_cache: Option<&'a ForwardedHeaderCache>,
  pub(crate) forwarded_request_header_values: Option<&'a ForwardedRequestHeaderValues>,
  pub(crate) preserve_host: bool,
  pub(crate) upstream_version: HttpVersion,
  pub(crate) waf_mutations: &'a [HeaderMutation],
  pub(crate) route_mutations: &'a [HeaderMutation],
  pub(crate) force_strip_accept_encoding: bool,
}

pub(crate) fn rebuild_request<B>(
  request: Request<B>,
  options: RebuildRequestOptions<'_>,
) -> Request<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<BoxError> + Send + Sync + 'static,
{
  let (mut parts, body) = request.into_parts();
  rebuild_request_parts(&mut parts, options);
  Request::from_parts(parts, proxy_body(body))
}

pub(crate) fn rebuild_request_parts(
  parts: &mut request::Parts,
  options: RebuildRequestOptions<'_>,
) {
  let accept_encoding_decision = upstream_accept_encoding_decision(parts, &options);
  parts.uri = options.target_uri;
  parts.version = upstream_request_version(options.upstream_version);
  strip_hop_by_hop_headers(&mut parts.headers);

  if options.preserve_host {
    if let Some(values) = options.forwarded_request_header_values {
      set_effective_host_header_value(&mut parts.headers, values.host());
    } else {
      set_effective_host_header(&mut parts.headers, options.downstream_host);
    }
  } else {
    parts.headers.remove(HOST);
  }

  add_forwarded_headers_with_values(
    &mut parts.headers,
    options.forwarded_client_addr,
    options.downstream_host,
    options.downstream_scheme,
    options.downstream_port,
    options.forwarded_header_mode,
    options.forwarded_header_cache,
    options.forwarded_request_header_values,
  );

  apply_header_mutations(&mut parts.headers, options.waf_mutations);
  apply_header_mutations(&mut parts.headers, options.route_mutations);
  let accept_encoding_decision = if request_has_sensitive_credentials(&parts.headers) {
    UpstreamAcceptEncodingDecision::Strip
  } else {
    accept_encoding_decision
  };
  apply_accept_encoding_decision(&mut parts.headers, accept_encoding_decision);
}

pub(crate) fn proxy_body<B>(body: B) -> ProxyBody
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<BoxError> + Send + Sync + 'static,
{
  body.map_err(Into::into).boxed()
}

enum UpstreamAcceptEncodingDecision {
  Strip,
  Preserve(Vec<http::HeaderValue>),
  Set(http::HeaderValue),
}

fn upstream_accept_encoding_decision(
  parts: &request::Parts,
  options: &RebuildRequestOptions<'_>,
) -> UpstreamAcceptEncodingDecision {
  let original = parts
    .headers
    .get_all(ACCEPT_ENCODING)
    .iter()
    .cloned()
    .collect::<Vec<_>>();
  if options.force_strip_accept_encoding || request_has_sensitive_credentials(&parts.headers) {
    return UpstreamAcceptEncodingDecision::Strip;
  }
  if !options.compression.enabled {
    return UpstreamAcceptEncodingDecision::Preserve(original);
  }
  if options.route_compression == Some("off") {
    return UpstreamAcceptEncodingDecision::Strip;
  }
  match options
    .compression
    .upstream_accept_encoding_for_route(options.route_compression)
    .unwrap_or(CompressionUpstreamAcceptEncodingMode::Strip)
  {
    CompressionUpstreamAcceptEncodingMode::Strip => UpstreamAcceptEncodingDecision::Strip,
    CompressionUpstreamAcceptEncodingMode::Preserve => {
      UpstreamAcceptEncodingDecision::Preserve(original)
    }
    CompressionUpstreamAcceptEncodingMode::Configured => {
      configured_accept_encoding(&parts.headers, options)
        .map(UpstreamAcceptEncodingDecision::Set)
        .unwrap_or(UpstreamAcceptEncodingDecision::Strip)
    }
  }
}

fn request_has_sensitive_credentials(headers: &http::HeaderMap) -> bool {
  headers.contains_key(COOKIE)
    || headers.contains_key(AUTHORIZATION)
    || headers.contains_key(PROXY_AUTHORIZATION)
}

fn configured_accept_encoding(
  headers: &http::HeaderMap,
  options: &RebuildRequestOptions<'_>,
) -> Option<http::HeaderValue> {
  let value = options
    .compression
    .accept_encoding_value_for_route(options.route_compression)?;
  let encodings = value
    .split(", ")
    .filter(|encoding| super::compression::accepted_encoding_quality(headers, encoding) > 0.0)
    .collect::<Vec<_>>();
  if encodings.is_empty() {
    return None;
  }
  http::HeaderValue::from_str(&encodings.join(", ")).ok()
}

fn apply_accept_encoding_decision(
  headers: &mut http::HeaderMap,
  decision: UpstreamAcceptEncodingDecision,
) {
  headers.remove(ACCEPT_ENCODING);
  match decision {
    UpstreamAcceptEncodingDecision::Strip => {}
    UpstreamAcceptEncodingDecision::Preserve(values) => {
      for value in values {
        headers.append(ACCEPT_ENCODING, value);
      }
    }
    UpstreamAcceptEncodingDecision::Set(value) => {
      headers.insert(ACCEPT_ENCODING, value);
    }
  }
}

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use http_body_util::Full;
  use pretty_assertions::assert_eq;

  use super::*;

  fn empty_proxy_body() -> ProxyBody {
    Full::new(Bytes::new())
      .map_err(|never| -> BoxError { match never {} })
      .boxed()
  }

  fn rebuild_options<'a>(
    target_uri: Uri,
    compression: &'a CompressionConfig,
    downstream_host: &'a str,
    preserve_host: bool,
  ) -> RebuildRequestOptions<'a> {
    RebuildRequestOptions {
      target_uri,
      compression,
      route_compression: None,
      forwarded_client_addr: "203.0.113.10:5443".parse().unwrap(),
      downstream_host,
      downstream_scheme: "https",
      downstream_port: 443,
      forwarded_header_mode: ForwardedHeaderMode::Overwrite,
      forwarded_header_cache: None,
      forwarded_request_header_values: None,
      preserve_host,
      upstream_version: HttpVersion::H1,
      waf_mutations: &[],
      route_mutations: &[],
      force_strip_accept_encoding: false,
    }
  }

  #[test]
  fn rebuild_request_does_not_forward_absolute_form_authority_as_host_by_default() {
    let request = Request::builder()
      .uri("http://absolute.example/app?q=1")
      .header(HOST, "header.example")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig::default();

    let rebuilt = rebuild_request(
      request,
      rebuild_options(
        "http://upstream.internal/base/app?q=1".parse().unwrap(),
        &compression,
        "absolute.example",
        false,
      ),
    );

    assert_eq!(
      rebuilt.uri().to_string(),
      "http://upstream.internal/base/app?q=1"
    );
    assert!(!rebuilt.headers().contains_key(HOST));
    assert_eq!(rebuilt.headers()["x-forwarded-host"], "absolute.example");
    assert_eq!(rebuilt.headers()["x-forwarded-port"], "443");
  }

  #[test]
  fn rebuild_request_preserves_effective_host_when_configured() {
    let request = Request::builder()
      .uri("http://absolute.example/app?q=1")
      .header(HOST, "header.example")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig::default();

    let rebuilt = rebuild_request(
      request,
      rebuild_options(
        "http://upstream.internal/base/app?q=1".parse().unwrap(),
        &compression,
        "absolute.example",
        true,
      ),
    );

    assert_eq!(rebuilt.headers()[HOST], "absolute.example");
    assert_eq!(rebuilt.headers()["x-forwarded-host"], "absolute.example");
  }

  #[test]
  fn rebuild_request_reuses_precomputed_forwarded_header_values() {
    let request = Request::builder()
      .uri("/app?q=1")
      .header(HOST, "header.example")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig::default();
    let values = ForwardedRequestHeaderValues::new("example.test", 8443);
    let mut options = rebuild_options(
      "http://upstream.internal/app?q=1".parse().unwrap(),
      &compression,
      "bad\nhost",
      true,
    );
    options.forwarded_request_header_values = Some(&values);

    let rebuilt = rebuild_request(request, options);

    assert_eq!(rebuilt.headers()[HOST], "example.test");
    assert_eq!(rebuilt.headers()["x-forwarded-host"], "example.test");
    assert_eq!(rebuilt.headers()["x-forwarded-port"], "8443");
  }

  #[test]
  fn rebuild_request_strips_accept_encoding_by_default_when_compression_is_enabled() {
    let request = Request::builder()
      .uri("/app")
      .header(HOST, "example.test")
      .header(ACCEPT_ENCODING, "gzip")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig::default();

    let rebuilt = rebuild_request(
      request,
      rebuild_options(
        "http://upstream.internal/app".parse().unwrap(),
        &compression,
        "example.test",
        false,
      ),
    );

    assert!(!rebuilt.headers().contains_key(ACCEPT_ENCODING));
  }

  #[test]
  fn rebuild_request_preserves_original_accept_encoding_after_route_mutations() {
    let request = Request::builder()
      .uri("/app")
      .header(HOST, "example.test")
      .header(ACCEPT_ENCODING, "gzip")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig {
      upstream_accept_encoding: CompressionUpstreamAcceptEncodingMode::Preserve,
      ..CompressionConfig::default()
    };
    let route_mutations = [HeaderMutation::Set {
      name: ACCEPT_ENCODING,
      value: http::HeaderValue::from_static("br"),
    }];
    let mut options = rebuild_options(
      "http://upstream.internal/app".parse().unwrap(),
      &compression,
      "example.test",
      false,
    );
    options.route_mutations = &route_mutations;

    let rebuilt = rebuild_request(request, options);

    assert_eq!(rebuilt.headers()[ACCEPT_ENCODING], "gzip");
  }

  #[test]
  fn rebuild_request_configured_accept_encoding_uses_enabled_client_intersection() {
    let request = Request::builder()
      .uri("/app")
      .header(HOST, "example.test")
      .header(ACCEPT_ENCODING, "gzip;q=1.0, br;q=0, zstd;q=0.5")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig {
      upstream_accept_encoding: CompressionUpstreamAcceptEncodingMode::Configured,
      ..CompressionConfig::default()
    };

    let rebuilt = rebuild_request(
      request,
      rebuild_options(
        "http://upstream.internal/app".parse().unwrap(),
        &compression,
        "example.test",
        false,
      ),
    );

    assert_eq!(rebuilt.headers()[ACCEPT_ENCODING], "zstd, gzip");
  }

  #[test]
  fn rebuild_request_strips_preserved_accept_encoding_when_route_mutation_adds_credentials() {
    let request = Request::builder()
      .uri("/app")
      .header(HOST, "example.test")
      .header(ACCEPT_ENCODING, "gzip")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig {
      upstream_accept_encoding: CompressionUpstreamAcceptEncodingMode::Preserve,
      ..CompressionConfig::default()
    };
    let route_mutations = [HeaderMutation::Set {
      name: AUTHORIZATION,
      value: http::HeaderValue::from_static("Bearer injected-by-route"),
    }];
    let mut options = rebuild_options(
      "http://upstream.internal/app".parse().unwrap(),
      &compression,
      "example.test",
      false,
    );
    options.route_mutations = &route_mutations;

    let rebuilt = rebuild_request(request, options);

    assert_eq!(rebuilt.headers()[AUTHORIZATION], "Bearer injected-by-route");
    assert!(!rebuilt.headers().contains_key(ACCEPT_ENCODING));
  }

  #[test]
  fn rebuild_request_strips_configured_accept_encoding_when_waf_mutation_adds_cookie() {
    let request = Request::builder()
      .uri("/app")
      .header(HOST, "example.test")
      .header(ACCEPT_ENCODING, "gzip;q=1.0, zstd;q=0.5")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig {
      upstream_accept_encoding: CompressionUpstreamAcceptEncodingMode::Configured,
      ..CompressionConfig::default()
    };
    let waf_mutations = [HeaderMutation::Set {
      name: COOKIE,
      value: http::HeaderValue::from_static("session=injected-by-waf"),
    }];
    let mut options = rebuild_options(
      "http://upstream.internal/app".parse().unwrap(),
      &compression,
      "example.test",
      false,
    );
    options.waf_mutations = &waf_mutations;

    let rebuilt = rebuild_request(request, options);

    assert_eq!(rebuilt.headers()[COOKIE], "session=injected-by-waf");
    assert!(!rebuilt.headers().contains_key(ACCEPT_ENCODING));
  }

  #[test]
  fn rebuild_request_strips_accept_encoding_for_credentials_and_forced_waf_boundary() {
    let compression = CompressionConfig {
      upstream_accept_encoding: CompressionUpstreamAcceptEncodingMode::Preserve,
      ..CompressionConfig::default()
    };
    let credentialed = Request::builder()
      .uri("/app")
      .header(HOST, "example.test")
      .header(ACCEPT_ENCODING, "gzip")
      .header(AUTHORIZATION, "Bearer secret")
      .body(empty_proxy_body())
      .expect("request should build");

    let rebuilt = rebuild_request(
      credentialed,
      rebuild_options(
        "http://upstream.internal/app".parse().unwrap(),
        &compression,
        "example.test",
        false,
      ),
    );
    assert!(!rebuilt.headers().contains_key(ACCEPT_ENCODING));

    let request = Request::builder()
      .uri("/app")
      .header(HOST, "example.test")
      .header(ACCEPT_ENCODING, "gzip")
      .body(empty_proxy_body())
      .expect("request should build");
    let route_mutations = [HeaderMutation::Set {
      name: ACCEPT_ENCODING,
      value: http::HeaderValue::from_static("br"),
    }];
    let mut options = rebuild_options(
      "http://upstream.internal/app".parse().unwrap(),
      &compression,
      "example.test",
      false,
    );
    options.route_mutations = &route_mutations;
    options.force_strip_accept_encoding = true;

    let rebuilt = rebuild_request(request, options);
    assert!(!rebuilt.headers().contains_key(ACCEPT_ENCODING));
  }
}
