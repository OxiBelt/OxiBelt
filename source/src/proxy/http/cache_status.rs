//! Cache-status header helpers.
//! Header values describe cache decisions without exposing internal keys.

use std::io::{Seek, SeekFrom};
use std::time::SystemTime;

use futures_util::StreamExt;
use http::header::{
  CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, EXPIRES, IF_MODIFIED_SINCE, IF_NONE_MATCH,
  LAST_MODIFIED, VARY,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::cache::CacheEntry;
use crate::config::RouteConfig;
use crate::proxy::http::body::ProxyBody;
use crate::state::AppSnapshot;
use crate::waf::WafTransportNetwork;

use super::{
  EffectiveTimeouts, body, compression, full_body, response::reconcile_route_security_headers,
  with_downstream_response_timeout,
};

const CACHE_HEADER: &str = "x-oxibelt-cache";
const CACHE_REASON_HEADER: &str = "x-oxibelt-cache-reason";
const AGE_HEADER: &str = "age";
const UNAVAILABLE_CACHE_BODY: &[u8] = b"cached response body is unavailable";

/// Facts about this response that the local cache can establish.
///
/// The response finalizer turns these into an RFC 9211 Cache-Status member.
/// Missing fields deliberately stay unknown instead of being inferred from
/// the legacy OxiBelt diagnostic labels.
#[derive(Debug, Clone, Default)]
pub(crate) struct StandardCacheStatus {
  pub hit: bool,
  pub forwarded: Option<&'static str>,
  pub forwarded_status: Option<u16>,
  pub stored: Option<bool>,
  pub collapsed: Option<bool>,
  pub expires_at: Option<SystemTime>,
  pub detail: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UnavailableCachedBody;

pub(crate) fn attach_standard_status<B>(response: &mut Response<B>, status: StandardCacheStatus) {
  response.extensions_mut().insert(status);
}

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
  let representation = available_digest_representation(&entry);
  let entry = crate::cache::range_entry(entry, method, request_headers);
  let partial = entry.status == StatusCode::PARTIAL_CONTENT;
  let body_len = entry.body_len();
  let Some(body) = body_from_entry(&entry) else {
    return unavailable_cached_body_response();
  };
  let mut response = Response::new(body);
  if entry.body_file.is_none() && body::is_known_small_response_body_len(entry.body.len()) {
    response
      .extensions_mut()
      .insert(body::InlinedKnownSmallResponseBody::new(
        entry.body.clone(),
        None,
      ));
  }
  *response.status_mut() = entry.status;
  *response.headers_mut() = entry.headers;
  if method == Method::HEAD || partial || response.status() == StatusCode::RANGE_NOT_SATISFIABLE {
    super::integrity_digest::invalidate_content(response.headers_mut());
  }
  response.extensions_mut().insert(if partial {
    super::integrity_digest::Representation::Partial
  } else {
    super::integrity_digest::Representation::Complete
  });
  if let Some(representation) = representation {
    response.extensions_mut().insert(representation);
  }
  super::status_headers::capture_cached(&mut response);
  apply_age_header(response.headers_mut(), entry.stored_at);
  if body::is_known_small_response_body_len(body_len) {
    response
      .extensions_mut()
      .insert(body::KnownSmallResponseBody);
  }
  response
}

fn available_digest_representation(
  entry: &CacheEntry,
) -> Option<super::integrity_digest::AvailableRepresentation> {
  (entry.body_file.is_none()
    && entry.status == StatusCode::OK
    && !entry.headers.contains_key(http::header::CONTENT_RANGE)
    && body::is_known_small_response_body_len(entry.body.len()))
  .then(|| super::integrity_digest::AvailableRepresentation(entry.body.clone()))
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
  state: &AppSnapshot,
  route: &RouteConfig,
  entry: CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
) -> Response<ProxyBody> {
  let expires_at = entry.expires_at;
  let mut response = cached_status_response(
    entry,
    method,
    request_headers,
    CacheHeaderOutcome::Stale,
    CacheHeaderReason::StaleIfError,
  );
  if response
    .extensions()
    .get::<UnavailableCachedBody>()
    .is_none()
  {
    attach_standard_status(
      &mut response,
      StandardCacheStatus {
        expires_at,
        detail: Some("stale-if-error"),
        ..StandardCacheStatus::default()
      },
    );
  }
  reconcile_cached_security(&mut response, state, route);
  response
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
  certificate_authenticated: bool,
) -> Response<ProxyBody> {
  let mut response =
    cached_status_response(entry, request_method, request_headers, outcome, reason);
  reconcile_cached_security(&mut response, state, route);
  let response = if certificate_authenticated {
    response
  } else {
    compression::maybe_compress_response(
      response,
      request_method,
      request_headers,
      route.compression.as_deref(),
      &state.config.compression,
      &state.compression,
    )
  };
  with_downstream_response_timeout(response, timeouts.response_send, transport_network, true)
}

pub(crate) fn reconcile_cached_security(
  response: &mut Response<ProxyBody>,
  state: &AppSnapshot,
  route: &RouteConfig,
) {
  reconcile_route_security_headers(response.headers_mut(), &state.config.security, route);
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
  response.extensions_mut().insert(UnavailableCachedBody);
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
  if method != Method::GET && method != Method::HEAD && !super::query::is_query(method) {
    return None;
  }
  let not_modified = if super::query::is_query(method) {
    super::query::conditional::not_modified(entry, request_headers).unwrap_or(false)
  } else {
    if_none_match_matches(entry, request_headers)
      || (request_headers.get(IF_NONE_MATCH).is_none()
        && if_modified_since_matches(entry, request_headers))
  };
  if !not_modified {
    return None;
  }
  let mut headers = HeaderMap::new();
  for name in [
    CACHE_CONTROL,
    ETAG,
    EXPIRES,
    LAST_MODIFIED,
    VARY,
    HeaderName::from_static("cache-status"),
    HeaderName::from_static("proxy-status"),
    HeaderName::from_static("repr-digest"),
    HeaderName::from_static("unencoded-digest"),
    http::header::CONTENT_ENCODING,
  ] {
    for value in entry.headers.get_all(&name) {
      headers.append(name.clone(), value.clone());
    }
  }
  apply_age_header(&mut headers, entry.stored_at);
  let mut response = Response::new(full_body(bytes::Bytes::new()));
  *response.status_mut() = StatusCode::NOT_MODIFIED;
  *response.headers_mut() = headers;
  if let Some(representation) = available_digest_representation(entry) {
    response.extensions_mut().insert(representation);
  }
  super::status_headers::capture_cached(&mut response);
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

#[cfg(test)]
#[path = "cache_digest_tests.rs"]
mod digest_tests;
