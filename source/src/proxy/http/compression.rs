//! HTTP response compression state and body wrappers.
//! Compression eligibility is kept separate from upstream semantics and WAF decisions.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use async_compression::Level as CompressionLevel;
use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder, ZlibEncoder, ZstdEncoder};
use bytes::Bytes;
use futures_util::StreamExt;
use http::header::{
  ACCEPT_ENCODING, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
  CONTENT_TYPE, COOKIE, ETAG, EXPIRES, HeaderMap, HeaderName, HeaderValue, LAST_MODIFIED,
  PROXY_AUTHORIZATION, RANGE, SET_COOKIE, TRAILER, VARY,
};
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body, Frame};
use tokio::io::{AsyncRead, BufReader, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::io::ReaderStream;

use crate::config::{CompressionConfig, CompressionPolicyConfig, CompressionProxiedPredicate};

use super::body::{InlinedKnownSmallResponseBody, KnownSmallResponseBody, ProxyBody, boxed_error};

const ENCODING_PREFERENCE: [CompressionEncoding; 4] = [
  CompressionEncoding::Br,
  CompressionEncoding::Zstd,
  CompressionEncoding::Gzip,
  CompressionEncoding::Deflate,
];

#[derive(Debug)]
pub(crate) struct CompressionState {
  semaphore: Arc<Semaphore>,
}

impl CompressionState {
  pub(crate) fn new(config: &CompressionConfig) -> Arc<Self> {
    let limit = if config.max_concurrent_responses == 0 {
      std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().saturating_mul(2))
        .unwrap_or(2)
    } else {
      config.max_concurrent_responses
    }
    .max(1);

    Arc::new(Self {
      semaphore: Arc::new(Semaphore::new(limit)),
    })
  }

  fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
    self.semaphore.clone().try_acquire_owned().ok()
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompressionEncoding {
  Br,
  Zstd,
  Gzip,
  Deflate,
}

impl CompressionEncoding {
  fn content_encoding(self) -> &'static str {
    match self {
      Self::Br => "br",
      Self::Zstd => "zstd",
      Self::Gzip => "gzip",
      Self::Deflate => "deflate",
    }
  }
}

struct EffectiveCompressionPolicy<'a> {
  enabled: bool,
  gzip: bool,
  deflate: bool,
  zstd: bool,
  br: bool,
  min_size_bytes: u64,
  level: u8,
  vary: bool,
  proxied: &'a [CompressionProxiedPredicate],
  statuses: &'a [u16],
  mime_types: &'a [String],
}

impl<'a> EffectiveCompressionPolicy<'a> {
  fn from_default(config: &'a CompressionConfig) -> Self {
    Self {
      enabled: config.enabled,
      gzip: config.gzip,
      deflate: config.deflate,
      zstd: config.zstd,
      br: config.br,
      min_size_bytes: config.min_size_bytes,
      level: config.level,
      vary: config.vary,
      proxied: &config.proxied,
      statuses: &config.statuses,
      mime_types: &config.mime_types,
    }
  }

  fn from_named(policy: &'a CompressionPolicyConfig) -> Self {
    Self {
      enabled: policy.enabled,
      gzip: policy.gzip,
      deflate: policy.deflate,
      zstd: policy.zstd,
      br: policy.br,
      min_size_bytes: policy.min_size_bytes,
      level: policy.level,
      vary: policy.vary,
      proxied: &policy.proxied,
      statuses: &policy.statuses,
      mime_types: &policy.mime_types,
    }
  }

  fn allows_encoding(&self, encoding: CompressionEncoding) -> bool {
    match encoding {
      CompressionEncoding::Br => self.br,
      CompressionEncoding::Zstd => self.zstd,
      CompressionEncoding::Gzip => self.gzip,
      CompressionEncoding::Deflate => self.deflate,
    }
  }

  fn has_enabled_encoding(&self) -> bool {
    self.br || self.zstd || self.gzip || self.deflate
  }
}

pub(crate) fn maybe_compress_response(
  response: Response<ProxyBody>,
  request_method: &Method,
  request_headers: &HeaderMap,
  route_compression: Option<&str>,
  config: &CompressionConfig,
  state: &CompressionState,
) -> Response<ProxyBody> {
  if !config.enabled {
    return response;
  }
  let Some(policy) = policy_for_route(config, route_compression) else {
    return response;
  };
  if !policy.enabled {
    return response;
  }
  if request_headers.contains_key(RANGE) {
    return response;
  }
  if request_has_sensitive_credentials(request_headers) {
    return response;
  }
  let (mut parts, body) = response.into_parts();
  if !response_is_eligible(&parts.headers, parts.status, &policy) {
    return Response::from_parts(parts, body);
  }
  if !proxied_response_allowed(request_headers, &parts.headers, &policy) {
    return Response::from_parts(parts, body);
  }
  if policy.vary && policy.has_enabled_encoding() {
    append_vary_accept_encoding(&mut parts.headers);
  }
  if request_method == Method::HEAD {
    return Response::from_parts(parts, body);
  }
  let Some(encoding) = negotiate_encoding(request_headers, &policy) else {
    return Response::from_parts(parts, body);
  };
  let Some(permit) = state.try_acquire() else {
    return Response::from_parts(parts, body);
  };

  parts.extensions.remove::<KnownSmallResponseBody>();
  parts.extensions.remove::<InlinedKnownSmallResponseBody>();

  parts.headers.insert(
    CONTENT_ENCODING,
    HeaderValue::from_static(encoding.content_encoding()),
  );
  parts.headers.remove(CONTENT_LENGTH);
  weaken_strong_etag(&mut parts.headers);

  Response::from_parts(parts, compress_body(body, encoding, policy.level, permit))
}

pub(crate) fn request_header_subset(headers: &HeaderMap) -> HeaderMap {
  let mut subset = HeaderMap::new();
  append_all(&mut subset, headers, RANGE);
  append_all(&mut subset, headers, COOKIE);
  append_all(&mut subset, headers, AUTHORIZATION);
  append_all(&mut subset, headers, PROXY_AUTHORIZATION);
  append_all(&mut subset, headers, ACCEPT_ENCODING);
  append_all(&mut subset, headers, HeaderName::from_static("via"));
  subset
}

fn append_all(subset: &mut HeaderMap, headers: &HeaderMap, name: HeaderName) {
  for value in headers.get_all(&name) {
    subset.append(name.clone(), value.clone());
  }
}

fn policy_for_route<'a>(
  config: &'a CompressionConfig,
  route_compression: Option<&str>,
) -> Option<EffectiveCompressionPolicy<'a>> {
  match route_compression {
    Some("off") => None,
    None | Some("default") => Some(EffectiveCompressionPolicy::from_default(config)),
    Some(name) => config
      .policies
      .iter()
      .find(|policy| policy.name == name)
      .map(EffectiveCompressionPolicy::from_named),
  }
}

fn response_is_eligible(
  headers: &HeaderMap,
  status: StatusCode,
  policy: &EffectiveCompressionPolicy<'_>,
) -> bool {
  if !policy.statuses.iter().any(|item| *item == status.as_u16()) {
    return false;
  }
  if has_non_identity_content_encoding(headers) {
    return false;
  }
  if headers.contains_key(CONTENT_RANGE) || headers.contains_key(TRAILER) {
    return false;
  }
  if has_no_transform(headers) || response_has_sensitive_context(headers) {
    return false;
  }
  if known_content_length(headers).is_some_and(|length| length < policy.min_size_bytes) {
    return false;
  }
  let Some(content_type) = normalized_content_type(headers) else {
    return false;
  };
  policy
    .mime_types
    .iter()
    .any(|pattern| mime_pattern_matches(pattern, &content_type))
}

fn proxied_response_allowed(
  request_headers: &HeaderMap,
  response_headers: &HeaderMap,
  policy: &EffectiveCompressionPolicy<'_>,
) -> bool {
  if !request_headers.contains_key("via") {
    return true;
  }
  if policy.proxied.contains(&CompressionProxiedPredicate::Off) {
    return false;
  }
  if policy.proxied.contains(&CompressionProxiedPredicate::Any) {
    return true;
  }
  policy
    .proxied
    .iter()
    .any(|predicate| proxied_predicate_matches(*predicate, request_headers, response_headers))
}

fn proxied_predicate_matches(
  predicate: CompressionProxiedPredicate,
  request_headers: &HeaderMap,
  response_headers: &HeaderMap,
) -> bool {
  match predicate {
    CompressionProxiedPredicate::Off | CompressionProxiedPredicate::Any => false,
    CompressionProxiedPredicate::Expired => response_is_expired(response_headers),
    CompressionProxiedPredicate::NoCache => {
      has_cache_control_directive(response_headers, "no-cache")
    }
    CompressionProxiedPredicate::NoStore => {
      has_cache_control_directive(response_headers, "no-store")
    }
    CompressionProxiedPredicate::Private => {
      has_cache_control_directive(response_headers, "private")
    }
    CompressionProxiedPredicate::NoLastModified => !response_headers.contains_key(LAST_MODIFIED),
    CompressionProxiedPredicate::NoEtag => !response_headers.contains_key(ETAG),
    CompressionProxiedPredicate::Auth => request_headers.contains_key(AUTHORIZATION),
  }
}

fn response_is_expired(headers: &HeaderMap) -> bool {
  headers
    .get(EXPIRES)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| httpdate::parse_http_date(value).ok())
    .is_some_and(|expires| expires <= SystemTime::now())
}

fn request_has_sensitive_credentials(headers: &HeaderMap) -> bool {
  headers.contains_key(COOKIE)
    || headers.contains_key(AUTHORIZATION)
    || headers.contains_key(PROXY_AUTHORIZATION)
}

fn response_has_sensitive_context(headers: &HeaderMap) -> bool {
  headers.contains_key(SET_COOKIE)
    || has_cache_control_directive(headers, "private")
    || has_cache_control_directive(headers, "no-store")
}

fn negotiate_encoding(
  request_headers: &HeaderMap,
  policy: &EffectiveCompressionPolicy<'_>,
) -> Option<CompressionEncoding> {
  let accept_encoding = request_headers.get_all(ACCEPT_ENCODING);
  accept_encoding.iter().next()?;

  let mut best = None;
  let mut best_q = 0.0f32;
  for encoding in ENCODING_PREFERENCE {
    if !policy.allows_encoding(encoding) {
      continue;
    }
    let q = accepted_encoding_quality(request_headers, encoding.content_encoding());
    if q > 0.0 && (q > best_q || best.is_none()) {
      best = Some(encoding);
      best_q = q;
    }
  }
  best
}

pub(crate) fn accepted_encoding_quality(headers: &HeaderMap, encoding: &str) -> f32 {
  let mut exact = None;
  let mut wildcard = None;

  for value in headers.get_all(ACCEPT_ENCODING) {
    let Ok(value) = value.to_str() else {
      continue;
    };
    for item in value.split(',') {
      let mut parts = item.split(';').map(str::trim);
      let token = parts.next().unwrap_or_default();
      if token.is_empty() {
        continue;
      }
      let mut q = 1.0f32;
      for parameter in parts {
        let Some((name, value)) = parameter.split_once('=') else {
          continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
          q = value.trim().parse::<f32>().unwrap_or(0.0).clamp(0.0, 1.0);
        }
      }
      if token.eq_ignore_ascii_case(encoding) {
        exact = Some(q);
      } else if token == "*" {
        wildcard = Some(q);
      }
    }
  }

  exact.or(wildcard).unwrap_or(0.0)
}

fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
  headers.get_all(CONTENT_ENCODING).iter().any(|value| {
    value
      .to_str()
      .map(|value| !value.trim().eq_ignore_ascii_case("identity"))
      .unwrap_or(true)
  })
}

fn has_no_transform(headers: &HeaderMap) -> bool {
  has_cache_control_directive(headers, "no-transform")
}

fn has_cache_control_directive(headers: &HeaderMap, name: &str) -> bool {
  headers
    .get_all(CACHE_CONTROL)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .any(|directive| {
      directive
        .split_once('=')
        .map(|(name, _)| name.trim())
        .unwrap_or(directive)
        .eq_ignore_ascii_case(name)
    })
}

fn known_content_length(headers: &HeaderMap) -> Option<u64> {
  headers
    .get(CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse().ok())
}

fn normalized_content_type(headers: &HeaderMap) -> Option<String> {
  headers
    .get(CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.split(';').next())
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(str::to_ascii_lowercase)
}

fn mime_pattern_matches(pattern: &str, content_type: &str) -> bool {
  let pattern = pattern.to_ascii_lowercase();
  if pattern == "*/*" || pattern == content_type {
    return true;
  }

  let Some((pattern_type, pattern_subtype)) = pattern.split_once('/') else {
    return false;
  };
  let Some((content_type_part, content_subtype)) = content_type.split_once('/') else {
    return false;
  };

  if pattern_type != content_type_part {
    return false;
  }
  if pattern_subtype == "*" {
    return true;
  }
  if let Some(suffix) = pattern_subtype.strip_prefix("*+") {
    return content_subtype.ends_with(&format!("+{suffix}"));
  }
  false
}

fn append_vary_accept_encoding(headers: &mut HeaderMap) {
  let already_varies = headers
    .get_all(VARY)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .any(|item| item == "*" || item.eq_ignore_ascii_case("accept-encoding"));
  if !already_varies {
    headers.append(VARY, HeaderValue::from_static("Accept-Encoding"));
  }
}

fn weaken_strong_etag(headers: &mut HeaderMap) {
  let Some(etag) = headers.get(ETAG).and_then(|value| value.to_str().ok()) else {
    return;
  };
  if !etag.starts_with('"') {
    return;
  }
  let weak = format!("W/{etag}");
  if let Ok(value) = HeaderValue::from_str(&weak) {
    headers.insert(ETAG, value);
  }
}

fn compress_body(
  body: ProxyBody,
  encoding: CompressionEncoding,
  level: u8,
  permit: OwnedSemaphorePermit,
) -> ProxyBody {
  let reader = BufReader::new(ProxyBodyReader::new(body, permit));
  let level = CompressionLevel::Precise(i32::from(level));
  match encoding {
    CompressionEncoding::Br => reader_body(BrotliEncoder::with_quality(reader, level)),
    CompressionEncoding::Zstd => reader_body(ZstdEncoder::with_quality(reader, level)),
    CompressionEncoding::Gzip => reader_body(GzipEncoder::with_quality(reader, level)),
    CompressionEncoding::Deflate => reader_body(ZlibEncoder::with_quality(reader, level)),
  }
}

fn reader_body<R>(reader: R) -> ProxyBody
where
  R: AsyncRead + Unpin + Send + Sync + 'static,
{
  let stream = ReaderStream::new(reader).map(|result| result.map(Frame::data).map_err(boxed_error));
  BodyExt::boxed(StreamBody::new(stream))
}

struct ProxyBodyReader {
  body: ProxyBody,
  current: Bytes,
  _permit: OwnedSemaphorePermit,
}

impl ProxyBodyReader {
  fn new(body: ProxyBody, permit: OwnedSemaphorePermit) -> Self {
    Self {
      body,
      current: Bytes::new(),
      _permit: permit,
    }
  }
}

impl Unpin for ProxyBodyReader {}

impl AsyncRead for ProxyBodyReader {
  fn poll_read(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    if buf.remaining() == 0 {
      return Poll::Ready(Ok(()));
    }

    loop {
      if !self.current.is_empty() {
        let length = self.current.len().min(buf.remaining());
        let chunk = self.current.split_to(length);
        buf.put_slice(&chunk);
        return Poll::Ready(Ok(()));
      }

      match Pin::new(&mut self.body).poll_frame(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
          Ok(data) => {
            self.current = data;
          }
          Err(frame) => {
            if frame.into_trailers().is_ok() {
              continue;
            }
          }
        },
        Poll::Ready(Some(Err(error))) => {
          return Poll::Ready(Err(std::io::Error::other(error.to_string())));
        }
        Poll::Ready(None) => return Poll::Ready(Ok(())),
      }
    }
  }
}

#[cfg(test)]
mod tests {
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
}
