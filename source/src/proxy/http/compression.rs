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
use crate::overload::{OverloadRuntime, WorkKind, WorkLease};

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
  overload: Option<Arc<OverloadRuntime>>,
}

impl CompressionState {
  #[cfg(test)]
  pub(crate) fn new(config: &CompressionConfig) -> Arc<Self> {
    Self::new_with_overload(config, None)
  }

  pub(crate) fn new_with_runtime(
    config: &CompressionConfig,
    overload: Arc<OverloadRuntime>,
  ) -> Arc<Self> {
    Self::new_with_overload(config, Some(overload))
  }

  fn new_with_overload(
    config: &CompressionConfig,
    overload: Option<Arc<OverloadRuntime>>,
  ) -> Arc<Self> {
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
      overload,
    })
  }

  fn level_cap(&self) -> Option<u8> {
    self
      .overload
      .as_ref()
      .and_then(|runtime| runtime.compression_level_cap())
  }

  fn try_acquire(&self) -> Option<CompressionPermit> {
    if self.level_cap() == Some(0) {
      return None;
    }
    Some(CompressionPermit {
      _semaphore: self.semaphore.clone().try_acquire_owned().ok()?,
      _overload: self
        .overload
        .as_ref()
        .map(|runtime| runtime.lease(WorkKind::CompressionJobs, 1)),
    })
  }
}

struct CompressionPermit {
  _semaphore: OwnedSemaphorePermit,
  _overload: Option<WorkLease>,
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
  let Some(mut policy) = policy_for_route(config, route_compression) else {
    return response;
  };
  if !policy.enabled {
    return response;
  }
  if let Some(cap) = state.level_cap() {
    if cap == 0 {
      return response;
    }
    policy.level = policy.level.min(cap);
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
  permit: CompressionPermit,
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
  _permit: CompressionPermit,
}

impl ProxyBodyReader {
  fn new(body: ProxyBody, permit: CompressionPermit) -> Self {
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
#[path = "compression_tests.rs"]
mod tests;
