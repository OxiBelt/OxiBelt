//! Background refresh helpers for cache stale-while-revalidate entries.

use std::sync::Arc;

use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Body;
use tracing::warn;

use crate::config::{HttpVersion, ProxyProtocolEgressMode, RouteConfig, UpstreamConfig};
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
  method: &Method,
) -> bool {
  (upstream_version != HttpVersion::H3 || super::query::is_query(method))
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
  route: &RouteConfig,
  scheme: &'static str,
  host: String,
  method: Method,
  uri: http::Uri,
  request_headers: HeaderMap,
  stale: crate::cache::StaleEntry,
) -> bool {
  let certificate_identity = super::client_certificate::cache_identity(outbound).cloned();
  let mut query_identity = outbound
    .extensions()
    .get::<crate::cache::CacheQueryIdentity>()
    .cloned();
  let nvs_metadata = stale.entry.no_vary_search.as_ref();
  let no_vary_search = nvs_metadata.and_then(|metadata| {
    outbound
      .extensions()
      .get::<crate::cache::CacheNvsRequest>()
      .and_then(|request| request.for_owner(metadata))
  });
  let uri = nvs_metadata
    .and_then(|metadata| metadata.owner_uri.parse::<http::Uri>().ok())
    .unwrap_or(uri);
  if stale.entry.nvs_alias
    && let Some(metadata) = nvs_metadata
    && let Some(identity) = query_identity.as_ref()
  {
    query_identity = Some(identity.for_nvs_owner(metadata));
  }
  let query_snapshot = outbound
    .extensions()
    .get::<super::query::capture::QueryReplaySnapshot>()
    .cloned();
  if super::query::is_query(&method) && (query_identity.is_none() || query_snapshot.is_none()) {
    state.metrics.record_cache_background_refresh_skip();
    return false;
  }
  let Some(permit) = state.cache.try_background_refresh_permit(route_cache) else {
    state.metrics.record_cache_background_refresh_skip();
    return false;
  };
  let route_cache = route_cache.map(str::to_string);
  let route_security_headers = route_security_headers.map(str::to_string);
  let route = route.clone();
  let upstream = upstream.clone();
  // The outbound URI and Host now identify the upstream after request
  // rebuilding. Refreshes remain scoped to the original downstream origin,
  // but take a fresh group snapshot so they cannot reuse a stale generation.
  let group_request = outbound
    .extensions()
    .get::<crate::cache::CacheGroupRequest>()
    .map(|request| crate::cache::CacheGroupRequest::new(request.origin.clone()));
  let mut outbound = empty_request_from(outbound);
  if stale.entry.nvs_alias
    && let Some(metadata) = nvs_metadata
    && let Ok(owner_effective_uri) = metadata.effective_uri.parse()
  {
    *outbound.uri_mut() = owner_effective_uri;
  }
  if let Some(identity) = query_identity.as_ref() {
    outbound.extensions_mut().insert(identity.clone());
  }
  for (name, value) in &stale.request_headers {
    outbound.headers_mut().insert(name.clone(), value.clone());
  }
  tokio::spawn(async move {
    if let Some(snapshot) = query_snapshot {
      match snapshot.body().await {
        Ok(body) => *outbound.body_mut() = body,
        Err(_) => {
          state.metrics.record_cache_background_refresh_error();
          return;
        }
      }
    }
    let group_context = || crate::cache::CacheLookupContext {
      group_request: group_request.as_ref(),
      no_vary_search: no_vary_search.as_ref(),
      query_identity: query_identity.as_ref(),
      proxy_protocol_identity: None,
      certificate_identity: certificate_identity.as_ref(),
      policy_name: route_cache.as_deref(),
      scheme,
      host: &host,
      method: &method,
      uri: &uri,
      request_headers: &request_headers,
    };
    if !state.cache.bind_group_request(group_context()).await {
      state.metrics.record_cache_background_refresh_skip();
      return;
    }
    let Some(fill_permit) = state.cache.begin_fill_async(group_context()).await else {
      state.metrics.record_cache_background_refresh_skip();
      return;
    };
    let guard = match fill_permit {
      crate::cache::CacheFillPermit::Leader(guard) => guard,
      crate::cache::CacheFillPermit::Follower(_) => {
        state.metrics.record_cache_background_refresh_skip();
        return;
      }
      crate::cache::CacheFillPermit::SharedConflict => {
        state.metrics.record_cache_fill_lock_conflict();
        state.metrics.record_cache_background_refresh_skip();
        return;
      }
    };
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
      route,
      scheme,
      host,
      method,
      uri,
      request_headers,
      certificate_identity,
      query_identity,
      no_vary_search,
      group_request,
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
  route: RouteConfig,
  scheme: &'static str,
  host: String,
  method: Method,
  uri: http::Uri,
  request_headers: HeaderMap,
  certificate_identity: Option<crate::cache::CacheCertificateIdentity>,
  query_identity: Option<crate::cache::CacheQueryIdentity>,
  no_vary_search: Option<crate::cache::CacheNvsRequest>,
  group_request: Option<crate::cache::CacheGroupRequest>,
  cached_entry: crate::cache::CacheEntry,
) -> anyhow::Result<()> {
  let retry_policy = EffectiveRetryPolicy::disabled_direct();
  let response = if upstream_version == HttpVersion::H3 {
    super::retry::send_h3_with_retry(outbound, &upstream, timeouts, &state, &retry_policy, None)
      .await?
  } else {
    let Some(client) = state.clients.for_upstream_version(
      &upstream.name,
      upstream.origin.scheme(),
      upstream_version,
    ) else {
      state.metrics.record_cache_background_refresh_skip();
      return Ok(());
    };
    send_with_retry(client, outbound, timeouts, &state, &retry_policy, None)
      .await?
      .map(|body| body.map_err(boxed_error).boxed())
  };
  if super::incremental::response_marked(&response) {
    state.metrics.record_cache_background_refresh_skip();
    return Ok(());
  }
  let (mut parts, body) = response.into_parts();
  if let Some(no_vary_search) = no_vary_search.as_ref() {
    no_vary_search.capture_origin(&parts.headers);
  }
  super::status_headers::capture_upstream_parts(&mut parts);
  super::status_headers::restore_received_headers(&mut parts);
  if state.cache.nvs_policy_changed(
    &cached_entry,
    &parts.headers,
    parts.status == StatusCode::NOT_MODIFIED,
  ) && !state
    .cache
    .replace_nvs_policy(
      crate::cache::CacheLookupContext {
        group_request: group_request.as_ref(),
        no_vary_search: no_vary_search.as_ref(),
        query_identity: query_identity.as_ref(),
        proxy_protocol_identity: None,
        certificate_identity: certificate_identity.as_ref(),
        policy_name: route_cache.as_deref(),
        scheme,
        host: &host,
        method: &method,
        uri: &uri,
        request_headers: &request_headers,
      },
      &cached_entry,
    )
    .await
  {
    state.metrics.record_cache_background_refresh_skip();
    return Ok(());
  }
  if parts.status == StatusCode::NOT_MODIFIED {
    if !state
      .cache
      .update_from_not_modified_async(
        crate::cache::CacheInsertContext {
          group_request: group_request.as_ref(),
          no_vary_search: no_vary_search.as_ref(),
          query_identity: query_identity.as_ref(),
          proxy_protocol_identity: None,
          certificate_identity: certificate_identity.as_ref(),
          policy_name: route_cache.as_deref(),
          scheme,
          host: &host,
          method: &method,
          uri: &uri,
          request_headers: &request_headers,
        },
        &cached_entry,
        &parts.headers,
      )
      .await
    {
      state.metrics.record_cache_background_refresh_skip();
      return Ok(());
    }
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
  super::route_runtime::apply_response_actions(&mut parts.headers, &route, &request_headers);
  if body
    .size_hint()
    .upper()
    .is_none_or(|upper| upper as usize > state.config.proxy.buffering.max_memory_body_bytes)
  {
    state.metrics.record_cache_background_refresh_skip();
    return Ok(());
  }
  let body = body::with_read_timeout(
    body,
    timeouts.upstream_read,
    BodyTimeoutKind::UpstreamResponseRead,
  );
  let body: ProxyBody =
    http_body_util::Limited::new(body, state.config.proxy.buffering.max_memory_body_bytes).boxed();
  let bytes = body
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("failed to read background refresh body: {error}"))?
    .to_bytes();
  let mut cache_headers = parts.headers.clone();
  neutralize_applied_route_security_headers(&mut cache_headers, &applied_route_security_headers);
  match state
    .cache
    .insert_async(
      crate::cache::CacheInsertContext {
        group_request: group_request.as_ref(),
        no_vary_search: no_vary_search.as_ref(),
        query_identity: query_identity.as_ref(),
        proxy_protocol_identity: None,
        certificate_identity: certificate_identity.as_ref(),
        policy_name: route_cache.as_deref(),
        scheme,
        host: &host,
        method: &method,
        uri: &uri,
        request_headers: &request_headers,
      },
      crate::cache::CacheEntry::memory(parts.status, cache_headers, bytes),
    )
    .await
  {
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

#[allow(
  clippy::expect_used,
  reason = "all request builder inputs are cloned from an existing valid request"
)]
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

#[cfg(test)]
mod tests {
  use http::{HeaderValue, Response};

  #[test]
  fn background_refresh_restores_the_captured_upstream_status_chain() {
    let response = Response::builder()
      .header("proxy-status", "upstream; error=connection_timeout")
      .header("cache-status", "upstream-cache; hit")
      .body(())
      .expect("valid test response");
    let (mut parts, _) = response.into_parts();

    super::super::status_headers::capture_upstream_parts(&mut parts);
    parts.headers.insert(
      "proxy-status",
      HeaderValue::from_static("forged; error=dns_error"),
    );
    super::super::status_headers::restore_received_headers(&mut parts);

    assert_eq!(
      parts.headers["proxy-status"],
      "upstream; error=connection_timeout"
    );
    assert_eq!(parts.headers["cache-status"], "upstream-cache; hit");
  }
}
