use http::header::{
  ACCEPT_ENCODING, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
  COOKIE, EXPIRES, PROXY_AUTHORIZATION, SET_COOKIE,
};
use http_body_util::Full;
use tokio::io::AsyncReadExt;

use crate::proxy::http::body::BoxError;

use super::*;

fn default_policy() -> EffectiveCompressionPolicy<'static> {
  let config = Box::leak(Box::new(CompressionConfig::default()));
  EffectiveCompressionPolicy::from_default(config)
}

fn eligible_response() -> Response<ProxyBody> {
  let body = Bytes::from("compressible ".repeat(200));
  let proxy_body = Full::new(body.clone())
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(proxy_body);
  response.headers_mut().insert(
    CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
  );
  response.headers_mut().insert(
    CONTENT_LENGTH,
    HeaderValue::from_str(&body.len().to_string()).unwrap(),
  );
  response
}

fn gzip_request_headers() -> HeaderMap {
  let mut request_headers = HeaderMap::new();
  request_headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
  request_headers
}

#[test]
fn request_header_subset_keeps_only_compression_inputs() {
  let mut headers = HeaderMap::new();
  headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
  headers.insert(COOKIE, HeaderValue::from_static("session=1"));
  headers.insert("via", HeaderValue::from_static("1.1 proxy.example"));
  headers.insert("x-unrelated", HeaderValue::from_static("ignored"));

  let subset = request_header_subset(&headers);

  assert_eq!(subset[ACCEPT_ENCODING], "gzip");
  assert_eq!(subset[COOKIE], "session=1");
  assert_eq!(subset["via"], "1.1 proxy.example");
  assert!(!subset.contains_key("x-unrelated"));
}

fn assert_response_is_not_compressed(response: &Response<ProxyBody>) {
  assert!(!response.headers().contains_key(CONTENT_ENCODING));
  assert!(response.headers().contains_key(CONTENT_LENGTH));
}

#[test]
fn negotiation_prefers_best_quality_then_server_order() {
  let mut headers = HeaderMap::new();
  headers.insert(
    ACCEPT_ENCODING,
    HeaderValue::from_static("gzip;q=1.0, zstd;q=0.6, br;q=1.0"),
  );

  assert_eq!(
    negotiate_encoding(&headers, &default_policy()),
    Some(CompressionEncoding::Br)
  );
}

#[test]
fn negotiation_uses_wildcard_without_overriding_exact_zero() {
  let mut headers = HeaderMap::new();
  headers.insert(
    ACCEPT_ENCODING,
    HeaderValue::from_static("br;q=0, zstd;q=0, *;q=0.7"),
  );

  assert_eq!(
    negotiate_encoding(&headers, &default_policy()),
    Some(CompressionEncoding::Gzip)
  );
}

#[test]
fn response_eligibility_rejects_no_transform_and_missing_content_type() {
  let policy = default_policy();
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("private, no-transform"),
  );
  assert!(!response_is_eligible(&headers, StatusCode::OK, &policy));

  headers.remove(CACHE_CONTROL);
  headers.remove(CONTENT_TYPE);
  assert!(!response_is_eligible(&headers, StatusCode::OK, &policy));
}

#[test]
fn response_eligibility_rejects_secret_bearing_headers() {
  let policy = default_policy();
  let mut headers = HeaderMap::new();
  headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
  headers.insert(CONTENT_LENGTH, HeaderValue::from_static("2048"));
  assert!(response_is_eligible(&headers, StatusCode::OK, &policy));

  headers.insert(SET_COOKIE, HeaderValue::from_static("session=present"));
  assert!(!response_is_eligible(&headers, StatusCode::OK, &policy));

  headers.remove(SET_COOKIE);
  headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("public, max-age=60"),
  );
  assert!(response_is_eligible(&headers, StatusCode::OK, &policy));

  headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static("private=\"set-cookie\""),
  );
  assert!(!response_is_eligible(&headers, StatusCode::OK, &policy));

  headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
  assert!(!response_is_eligible(&headers, StatusCode::OK, &policy));
}

#[test]
fn mime_patterns_match_suffix_and_tree_wildcards() {
  assert!(mime_pattern_matches("text/*", "text/plain"));
  assert!(mime_pattern_matches(
    "application/*+json",
    "application/problem+json"
  ));
  assert!(mime_pattern_matches("image/svg+xml", "image/svg+xml"));
  assert!(!mime_pattern_matches("application/json", "text/json"));
}

#[test]
fn vary_append_is_case_insensitive() {
  let mut headers = HeaderMap::new();
  headers.insert(VARY, HeaderValue::from_static("Origin, accept-encoding"));

  append_vary_accept_encoding(&mut headers);

  assert_eq!(headers.get_all(VARY).iter().count(), 1);
}

#[test]
fn strong_etags_are_weakened() {
  let mut headers = HeaderMap::new();
  headers.insert(ETAG, HeaderValue::from_static("\"abc\""));

  weaken_strong_etag(&mut headers);

  assert_eq!(headers.get(ETAG).unwrap(), "W/\"abc\"");
}

#[test]
fn proxied_gate_requires_configured_predicate_for_via_requests() {
  let mut request_headers = gzip_request_headers();
  request_headers.insert("via", HeaderValue::from_static("1.1 proxy.example"));
  let response = eligible_response();
  let policy = default_policy();

  assert!(!proxied_response_allowed(
    &request_headers,
    response.headers(),
    &policy
  ));

  let mut response = eligible_response();
  response
    .headers_mut()
    .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
  assert!(proxied_response_allowed(
    &request_headers,
    response.headers(),
    &policy
  ));

  let mut response = eligible_response();
  response.headers_mut().insert(
    EXPIRES,
    HeaderValue::from_str(&httpdate::fmt_http_date(std::time::SystemTime::UNIX_EPOCH)).unwrap(),
  );
  assert!(proxied_response_allowed(
    &request_headers,
    response.headers(),
    &policy
  ));
}

#[test]
fn proxied_auth_predicate_does_not_override_sensitive_request_skip() {
  let config = CompressionConfig {
    proxied: vec![CompressionProxiedPredicate::Any],
    ..CompressionConfig::default()
  };
  let state = CompressionState::new(&config);
  let mut request_headers = gzip_request_headers();
  request_headers.insert("via", HeaderValue::from_static("1.1 proxy.example"));
  request_headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));

  let response = maybe_compress_response(
    eligible_response(),
    &Method::GET,
    &request_headers,
    None,
    &config,
    &state,
  );

  assert_response_is_not_compressed(&response);
}

#[test]
fn vary_is_added_to_eligible_identity_response_when_negotiation_is_absent() {
  let config = CompressionConfig::default();
  let state = CompressionState::new(&config);
  let request_headers = HeaderMap::new();

  let response = maybe_compress_response(
    eligible_response(),
    &Method::GET,
    &request_headers,
    None,
    &config,
    &state,
  );

  assert_response_is_not_compressed(&response);
  assert_eq!(response.headers().get(VARY).unwrap(), "Accept-Encoding");
}

#[test]
fn vary_false_suppresses_dynamic_compression_vary_header() {
  let config = CompressionConfig {
    vary: false,
    ..CompressionConfig::default()
  };
  let state = CompressionState::new(&config);

  let response = maybe_compress_response(
    eligible_response(),
    &Method::GET,
    &gzip_request_headers(),
    None,
    &config,
    &state,
  );

  assert_eq!(response.headers().get(CONTENT_ENCODING).unwrap(), "gzip");
  assert!(!response.headers().contains_key(VARY));
}

#[test]
fn compression_skips_authenticated_requests() {
  let config = CompressionConfig::default();
  let state = CompressionState::new(&config);

  let mut cookie_headers = gzip_request_headers();
  cookie_headers.insert(COOKIE, HeaderValue::from_static("session=secret"));
  let response = maybe_compress_response(
    eligible_response(),
    &Method::GET,
    &cookie_headers,
    None,
    &config,
    &state,
  );
  assert_response_is_not_compressed(&response);

  let mut authorization_headers = gzip_request_headers();
  authorization_headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
  let response = maybe_compress_response(
    eligible_response(),
    &Method::GET,
    &authorization_headers,
    None,
    &config,
    &state,
  );
  assert_response_is_not_compressed(&response);

  let mut proxy_authorization_headers = gzip_request_headers();
  proxy_authorization_headers.insert(
    PROXY_AUTHORIZATION,
    HeaderValue::from_static("Basic secret"),
  );
  let response = maybe_compress_response(
    eligible_response(),
    &Method::GET,
    &proxy_authorization_headers,
    None,
    &config,
    &state,
  );
  assert_response_is_not_compressed(&response);
}

#[tokio::test]
async fn gzip_compression_encodes_body_and_updates_headers() {
  let body = "compressible ".repeat(200);
  let original = Bytes::from(body.clone());
  let proxy_body = Full::new(original)
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let mut response = Response::new(proxy_body);
  response.headers_mut().insert(
    CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
  );
  response.headers_mut().insert(
    CONTENT_LENGTH,
    HeaderValue::from_str(&body.len().to_string()).unwrap(),
  );
  response
    .headers_mut()
    .insert(ETAG, HeaderValue::from_static("\"strong\""));
  response.extensions_mut().insert(KnownSmallResponseBody);
  let stale = InlinedKnownSmallResponseBody::new(Bytes::from_static(b"stale"), None);
  response.extensions_mut().insert(stale);

  let mut request_headers = HeaderMap::new();
  request_headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
  let config = CompressionConfig::default();
  let state = CompressionState::new(&config);

  let response = maybe_compress_response(
    response,
    &Method::GET,
    &request_headers,
    None,
    &config,
    &state,
  );

  assert_eq!(response.headers().get(CONTENT_ENCODING).unwrap(), "gzip");
  assert!(!response.headers().contains_key(CONTENT_LENGTH));
  assert_eq!(response.headers().get(ETAG).unwrap(), "W/\"strong\"");
  let extensions = response.extensions();
  assert!(extensions.get::<KnownSmallResponseBody>().is_none());
  assert!(extensions.get::<InlinedKnownSmallResponseBody>().is_none());

  let compressed = response
    .into_body()
    .collect()
    .await
    .expect("compressed body should collect")
    .to_bytes();
  let reader = BufReader::new(compressed.as_ref());
  let mut decoder = async_compression::tokio::bufread::GzipDecoder::new(reader);
  let mut decoded = Vec::new();
  decoder
    .read_to_end(&mut decoded)
    .await
    .expect("gzip body should decode");
  assert_eq!(decoded, body.as_bytes());
}
