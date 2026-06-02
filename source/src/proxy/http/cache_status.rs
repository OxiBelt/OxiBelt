use http::{HeaderMap, HeaderValue, Method, Response};

use crate::config::RouteConfig;
use crate::proxy::http::body::ProxyBody;
use crate::state::AppSnapshot;
use crate::waf::WafTransportNetwork;

use super::{EffectiveTimeouts, body, compression, full_body, with_downstream_response_timeout};

const CACHE_HEADER: &str = "x-oxibelt-cache";
const CACHE_REASON_HEADER: &str = "x-oxibelt-cache-reason";

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
  entry: crate::cache::CacheEntry,
  method: &Method,
  request_headers: &HeaderMap,
) -> Response<ProxyBody> {
  let entry = crate::cache::range_entry(entry, method, request_headers);
  let body_len = entry.body.len();
  let mut response = Response::new(full_body(entry.body));
  *response.status_mut() = entry.status;
  *response.headers_mut() = entry.headers;
  if body::is_known_small_response_body_len(body_len) {
    response
      .extensions_mut()
      .insert(body::KnownSmallResponseBody);
  }
  response
}

pub(crate) fn cached_status_response(
  entry: crate::cache::CacheEntry,
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
  entry: crate::cache::CacheEntry,
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
  entry: crate::cache::CacheEntry,
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
