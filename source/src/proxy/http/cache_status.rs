//! Cache-status header helpers.
//! Header values describe cache decisions without exposing internal keys.

use std::io::{Seek, SeekFrom};
use std::time::SystemTime;

use futures_util::StreamExt;
use http::header::{
  CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, EXPIRES, IF_MODIFIED_SINCE, IF_NONE_MATCH,
  LAST_MODIFIED, VARY,
};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::cache::CacheEntry;
use crate::config::RouteConfig;
use crate::proxy::http::body::ProxyBody;
use crate::state::AppSnapshot;
use crate::waf::WafTransportNetwork;

use super::{EffectiveTimeouts, body, compression, full_body, with_downstream_response_timeout};

const CACHE_HEADER: &str = "x-oxibelt-cache";
const CACHE_REASON_HEADER: &str = "x-oxibelt-cache-reason";
const AGE_HEADER: &str = "age";
const UNAVAILABLE_CACHE_BODY: &[u8] = b"cached response body is unavailable";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum CacheHeaderOutcome {
  Miss,
  Hit,
  Stale,
  Revalidated,
}

impl CacheHeaderOutcome {
  fn as_header(self) -> HeaderValue {
    match self {
      Self::Miss => HeaderValue::from_static("miss"),
      Self::Hit => HeaderValue::from_static("hit"),
      Self::Stale => HeaderValue::from_static("stale"),
      Self::Revalidated => HeaderValue::from_static("revalidated"),
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum CacheHeaderReason {
  Stored,
  Fresh,
  BackgroundRefresh,
  StaleIfError,
  StaleWithoutValidators,
  NotModified,
  NotCacheable,
  AdmissionWarming,
  AdmissionRejected,
  TooLarge,
  VaryRejected,
  StoreFailed,
  StoreNotAllowed,
}

impl CacheHeaderReason {
  fn as_header(self) -> HeaderValue {
    match self {
      Self::Stored => HeaderValue::from_static("stored"),
      Self::Fresh => HeaderValue::from_static("fresh"),
      Self::BackgroundRefresh => HeaderValue::from_static("background_refresh"),
      Self::StaleIfError => HeaderValue::from_static("stale_if_error"),
      Self::StaleWithoutValidators => HeaderValue::from_static("stale_without_validators"),
      Self::NotModified => HeaderValue::from_static("not_modified"),
      Self::NotCacheable => HeaderValue::from_static("not_cacheable"),
      Self::AdmissionWarming => HeaderValue::from_static("admission_warming"),
      Self::AdmissionRejected => HeaderValue::from_static("admission_rejected"),
      Self::TooLarge => HeaderValue::from_static("too_large"),
      Self::VaryRejected => HeaderValue::from_static("vary_rejected"),
      Self::StoreFailed => HeaderValue::from_static("store_failed"),
      Self::StoreNotAllowed => HeaderValue::from_static("store_not_allowed"),
    }
  }

  pub(crate) fn from_rejection(reason: crate::cache::CacheFillSuppressionReason) -> Self {
    match reason {
      crate::cache::CacheFillSuppressionReason::AdmissionRejected => Self::AdmissionRejected,
      crate::cache::CacheFillSuppressionReason::TooLarge => Self::TooLarge,
      crate::cache::CacheFillSuppressionReason::VaryRejected => Self::VaryRejected,
      crate::cache::CacheFillSuppressionReason::StoreFailed => Self::StoreFailed,
      crate::cache::CacheFillSuppressionReason::ResponseNoStore
      | crate::cache::CacheFillSuppressionReason::ResponsePrivate
      | crate::cache::CacheFillSuppressionReason::SetCookie
      | crate::cache::CacheFillSuppressionReason::Unknown => Self::NotCacheable,
    }
  }
}

pub(crate) fn strip_headers(headers: &mut HeaderMap) {
  headers.remove(CACHE_HEADER);
  headers.remove(CACHE_REASON_HEADER);
}

pub(crate) fn apply<B>(
  response: &mut Response<B>,
  outcome: CacheHeaderOutcome,
  reason: CacheHeaderReason,
) {
  strip_headers(response.headers_mut());
  response
    .headers_mut()
    .insert(CACHE_HEADER, outcome.as_header());
  response
    .headers_mut()
    .insert(CACHE_REASON_HEADER, reason.as_header());
}

pub(crate) fn cached_entry_response(
  entry: CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
) -> Response<ProxyBody> {
  if let Some(response) = conditional_not_modified_response(&entry, method, request_headers) {
    return response;
  }
  let entry = crate::cache::range_entry(entry, method, request_headers);
  let body_len = entry.body_len();
  let Some(body) = body_from_entry(&entry) else {
    return unavailable_cached_body_response();
  };
  let mut response = Response::new(body);
  *response.status_mut() = entry.status;
  *response.headers_mut() = entry.headers;
  apply_age_header(response.headers_mut(), entry.stored_at);
  if body::is_known_small_response_body_len(body_len) {
    response
      .extensions_mut()
      .insert(body::KnownSmallResponseBody);
  }
  response
}

pub(crate) fn cached_status_response(
  entry: CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
  outcome: CacheHeaderOutcome,
  reason: CacheHeaderReason,
) -> Response<ProxyBody> {
  let mut response = cached_entry_response(entry, method, request_headers);
  apply(&mut response, outcome, reason);
  response
}

pub(crate) fn stale_if_error_response(
  entry: CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
) -> Response<ProxyBody> {
  cached_status_response(
    entry,
    method,
    request_headers,
    CacheHeaderOutcome::Stale,
    CacheHeaderReason::StaleIfError,
  )
}

pub(crate) fn store_failed_response(mut response: Response<ProxyBody>) -> Response<ProxyBody> {
  apply(
    &mut response,
    CacheHeaderOutcome::Miss,
    CacheHeaderReason::StoreFailed,
  );
  response
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cached_downstream_response(
  state: &AppSnapshot,
  route: &RouteConfig,
  entry: CacheEntry,
  request_method: &Method,
  request_headers: &HeaderMap,
  timeouts: EffectiveTimeouts,
  transport_network: WafTransportNetwork,
  outcome: CacheHeaderOutcome,
  reason: CacheHeaderReason,
) -> Response<ProxyBody> {
  let response = cached_status_response(entry, request_method, request_headers, outcome, reason);
  let response = compression::maybe_compress_response(
    response,
    request_method,
    request_headers,
    route.compression.as_deref(),
    &state.config.compression,
    &state.compression,
  );
  with_downstream_response_timeout(response, timeouts.response_send, transport_network)
}

fn body_from_entry(entry: &CacheEntry) -> Option<ProxyBody> {
  let Some(file) = &entry.body_file else {
    return Some(full_body(entry.body.clone()));
  };
  let Ok(mut std_file) = std::fs::File::open(&file.path) else {
    return None;
  };
  if std_file.seek(SeekFrom::Start(file.offset)).is_err() {
    return None;
  }
  let reader = tokio::fs::File::from_std(std_file).take(file.len as u64);
  let stream = ReaderStream::with_capacity(reader, 64 * 1024)
    .map(|result| result.map(Frame::data).map_err(body::boxed_error));
  Some(BodyExt::boxed(StreamBody::new(stream)))
}

fn unavailable_cached_body_response() -> Response<ProxyBody> {
  let body = bytes::Bytes::from_static(UNAVAILABLE_CACHE_BODY);
  let mut response = Response::new(full_body(body.clone()));
  *response.status_mut() = StatusCode::BAD_GATEWAY;
  response.headers_mut().insert(
    CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
  );
  response.headers_mut().insert(
    CONTENT_LENGTH,
    HeaderValue::from_str(&body.len().to_string())
      .unwrap_or_else(|_| HeaderValue::from_static("0")),
  );
  apply(
    &mut response,
    CacheHeaderOutcome::Miss,
    CacheHeaderReason::StoreFailed,
  );
  response
}

fn conditional_not_modified_response(
  entry: &CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
) -> Option<Response<ProxyBody>> {
  if method != Method::GET && method != Method::HEAD {
    return None;
  }
  let not_modified = if_none_match_matches(entry, request_headers)
    || (request_headers.get(IF_NONE_MATCH).is_none()
      && if_modified_since_matches(entry, request_headers));
  if !not_modified {
    return None;
  }
  let mut headers = HeaderMap::new();
  for name in [CACHE_CONTROL, ETAG, EXPIRES, LAST_MODIFIED, VARY] {
    for value in entry.headers.get_all(&name) {
      headers.append(name.clone(), value.clone());
    }
  }
  apply_age_header(&mut headers, entry.stored_at);
  let mut response = Response::new(full_body(bytes::Bytes::new()));
  *response.status_mut() = StatusCode::NOT_MODIFIED;
  *response.headers_mut() = headers;
  Some(response)
}

fn if_none_match_matches(entry: &CacheEntry, request_headers: &HeaderMap) -> bool {
  let Some(entry_etag) = entry
    .headers
    .get(ETAG)
    .and_then(|value| value.to_str().ok())
  else {
    return false;
  };
  request_headers
    .get_all(IF_NONE_MATCH)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(str::trim)
    .any(|candidate| candidate == "*" || weak_etag_eq(candidate, entry_etag))
}

fn weak_etag_eq(left: &str, right: &str) -> bool {
  left.trim_start_matches("W/") == right.trim_start_matches("W/")
}

fn if_modified_since_matches(entry: &CacheEntry, request_headers: &HeaderMap) -> bool {
  let Some(last_modified) = entry
    .headers
    .get(LAST_MODIFIED)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| httpdate::parse_http_date(value).ok())
  else {
    return false;
  };
  let Some(if_modified_since) = request_headers
    .get(IF_MODIFIED_SINCE)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| httpdate::parse_http_date(value).ok())
  else {
    return false;
  };
  last_modified <= if_modified_since
}

fn apply_age_header(headers: &mut HeaderMap, stored_at: SystemTime) {
  let existing_age = headers
    .get(AGE_HEADER)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok())
    .unwrap_or_default();
  let elapsed = SystemTime::now()
    .duration_since(stored_at)
    .unwrap_or_default()
    .as_secs();
  let age = existing_age.saturating_add(elapsed);
  if let Ok(value) = HeaderValue::from_str(&age.to_string()) {
    headers.insert(AGE_HEADER, value);
  }
}
