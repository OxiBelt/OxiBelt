//! Background refresh helpers for cache stale-while-revalidate entries.

use std::sync::Arc;

use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Body;
use tracing::warn;

use crate::config::{HttpVersion, ProxyProtocolEgressMode, UpstreamConfig};
use crate::state::AppSnapshot;

use super::body::{self, BodyTimeoutKind, ProxyBody, boxed_error};
use super::headers::strip_hop_by_hop_headers;
use super::response::{
  apply_effective_security_headers_with_snapshot, neutralize_applied_route_security_headers,
};
use super::retry::{EffectiveRetryPolicy, send_with_retry};
use super::{EffectiveTimeouts, full_body, semantics};

pub(super) fn can_background_refresh(
  waf: crate::routes::RouteWafExecutionPlan,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
) -> bool {
  upstream_version != HttpVersion::H3
    && upstream.proxy_protocol_egress == ProxyProtocolEgressMode::Off
    && !waf.response.enabled()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_background_refresh(
  state: Arc<AppSnapshot>,
  outbound: &Request<ProxyBody>,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  route_cache: Option<&str>,
  route_security_headers: Option<&str>,
  scheme: &'static str,
  host: String,
  method: Method,
  uri: http::Uri,
  request_headers: HeaderMap,
  stale: crate::cache::StaleEntry,
) -> bool {
  let Some(permit) = state.cache.try_background_refresh_permit(route_cache) else {
    state.metrics.record_cache_background_refresh_skip();
    return false;
  };
  let Some(fill_permit) = state.cache.begin_fill(crate::cache::CacheLookupContext {
    policy_name: route_cache,
    scheme,
    host: &host,
    method: &method,
    uri: &uri,
    request_headers: &request_headers,
  }) else {
    state.metrics.record_cache_background_refresh_skip();
    return false;
  };
  let guard = match fill_permit {
    crate::cache::CacheFillPermit::Leader(guard) => guard,
    crate::cache::CacheFillPermit::Follower(_) => {
      state.metrics.record_cache_background_refresh_skip();
      return false;
    }
    crate::cache::CacheFillPermit::SharedConflict => {
      state.metrics.record_cache_fill_lock_conflict();
      state.metrics.record_cache_background_refresh_skip();
      return false;
    }
  };
  let route_cache = route_cache.map(str::to_string);
  let route_security_headers = route_security_headers.map(str::to_string);
  let upstream = upstream.clone();
  let mut outbound = empty_request_from(outbound);
  for (name, value) in &stale.request_headers {
    outbound.headers_mut().insert(name.clone(), value.clone());
  }
  tokio::spawn(async move {
    let _guard = guard;
    let _permit = permit;
    if let Err(error) = background_refresh(
      state.clone(),
      outbound,
      upstream,
      upstream_version,
      timeouts,
      route_cache,
      route_security_headers,
      scheme,
      host,
      method,
      uri,
      request_headers,
      stale.entry,
    )
    .await
    {
      state.metrics.record_cache_background_refresh_error();
      warn!(error = %error, "cache background refresh failed");
    }
  });
  true
}

#[allow(clippy::too_many_arguments)]
async fn background_refresh(
  state: Arc<AppSnapshot>,
  outbound: Request<ProxyBody>,
  upstream: UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  route_cache: Option<String>,
  route_security_headers: Option<String>,
  scheme: &'static str,
  host: String,
  method: Method,
  uri: http::Uri,
  request_headers: HeaderMap,
  cached_entry: crate::cache::CacheEntry,
) -> anyhow::Result<()> {
  let Some(client) =
    state
      .clients
      .for_upstream_version(&upstream.name, upstream.origin.scheme(), upstream_version)
  else {
    state.metrics.record_cache_background_refresh_skip();
    return Ok(());
  };
  let retry_policy = EffectiveRetryPolicy::disabled_direct();
  let response = send_with_retry(client, outbound, timeouts, &state, &retry_policy).await?;
  let (mut parts, body) = response.into_parts();
  if parts.status == StatusCode::NOT_MODIFIED {
    state.cache.update_from_not_modified(
      crate::cache::CacheInsertContext {
        policy_name: route_cache.as_deref(),
        scheme,
        host: &host,
        method: &method,
        uri: &uri,
        request_headers: &request_headers,
      },
      &cached_entry,
      &parts.headers,
    );
    state.metrics.record_cache_background_refresh_success();
    return Ok(());
  }
  strip_hop_by_hop_headers(&mut parts.headers);
  semantics::apply_priority_policy(&mut parts.headers, state.config.proxy.http.priority);
  let applied_route_security_headers = apply_effective_security_headers_with_snapshot(
    &mut parts.headers,
    &state.config.security,
    route_security_headers.as_deref(),
  );
  if body
    .size_hint()
    .upper()
    .is_none_or(|upper| upper as usize > state.config.proxy.buffering.max_memory_body_bytes)
  {
    state.metrics.record_cache_background_refresh_skip();
    return Ok(());
  }
  let body = body::with_read_timeout(
    body.map_err(boxed_error).boxed(),
    timeouts.upstream_read,
    BodyTimeoutKind::UpstreamResponseRead,
  );
  let bytes = body
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("failed to read background refresh body: {error}"))?
    .to_bytes();
  let mut cache_headers = parts.headers.clone();
  neutralize_applied_route_security_headers(&mut cache_headers, &applied_route_security_headers);
  match state.cache.insert(
    crate::cache::CacheInsertContext {
      policy_name: route_cache.as_deref(),
      scheme,
      host: &host,
      method: &method,
      uri: &uri,
      request_headers: &request_headers,
    },
    crate::cache::CacheEntry::memory(parts.status, cache_headers, bytes),
  ) {
    crate::cache::CacheInsertOutcome::Stored => {
      state.metrics.record_cache_background_refresh_success();
    }
    crate::cache::CacheInsertOutcome::Rejected => {
      state.metrics.record_cache_admission_rejection();
      state.metrics.record_cache_background_refresh_skip();
    }
    crate::cache::CacheInsertOutcome::AdmissionWarming => {
      state.metrics.record_cache_admission_rejection();
      state.metrics.record_cache_background_refresh_skip();
    }
    crate::cache::CacheInsertOutcome::StoreFailed => {
      state.metrics.record_cache_fill_error();
      state.metrics.record_cache_background_refresh_error();
    }
    crate::cache::CacheInsertOutcome::NotCacheable => {
      state.metrics.record_cache_background_refresh_skip();
    }
  }
  Ok(())
}

fn empty_request_from<B>(request: &Request<B>) -> Request<ProxyBody> {
  let mut builder = Request::builder()
    .method(request.method().clone())
    .uri(request.uri().clone())
    .version(request.version());
  *builder.headers_mut().expect("request builder headers") = request.headers().clone();
  builder
    .body(full_body(bytes::Bytes::new()))
    .expect("request clone builds")
}
