//! Waiting helpers for cache fill coordination across shared backends.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{HeaderMap, Method, Request, Response};

use crate::cache::{CacheEntry, CacheLookupContext};
use crate::config::{HttpVersion, UpstreamConfig};
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::waf::WafTransportNetwork;

use super::body::ProxyBody;
use super::{
  EffectiveTimeouts, handle_cache_lookup_result, record_route_cache_event,
  record_route_cache_fill_stage,
};

const SHARED_FILL_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[allow(clippy::too_many_arguments)]
pub(super) async fn wait_for_shared_fill(
  state: &Arc<AppSnapshot>,
  resolved: &ResolvedRoute<'_>,
  outbound: &mut Request<ProxyBody>,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  timeouts: EffectiveTimeouts,
  downstream_scheme: &'static str,
  host: &str,
  request_method: &Method,
  request_uri: &http::Uri,
  request_headers: &HeaderMap,
  request_version: http::Version,
  listener_bind: Option<SocketAddr>,
  transport_network: WafTransportNetwork,
  stale_on_error: &mut Option<CacheEntry>,
  revalidation_entry: &mut Option<CacheEntry>,
) -> Option<Response<ProxyBody>> {
  state.metrics.record_cache_fill_lock_conflict();
  record_route_cache_event(state, resolved.route, "miss", "shared_lock_conflict");
  let started = Instant::now();
  let timeout = state
    .cache
    .lock_wait_timeout(resolved.route.cache.as_deref());
  loop {
    let elapsed = started.elapsed();
    if elapsed >= timeout {
      record_route_cache_fill_stage(state, resolved.route, "lock_wait", "timeout", started);
      state.metrics.record_cache_fill_lock_timeout();
      record_route_cache_event(state, resolved.route, "miss", "fill_lock_timeout");
      return None;
    }
    tokio::time::sleep(SHARED_FILL_POLL_INTERVAL.min(timeout - elapsed)).await;
    let Some(lookup) = state
      .cache
      .lookup_async(CacheLookupContext {
        policy_name: resolved.route.cache.as_deref(),
        scheme: downstream_scheme,
        host,
        method: request_method,
        uri: request_uri,
        request_headers,
      })
      .await
    else {
      continue;
    };
    record_route_cache_fill_stage(state, resolved.route, "lock_wait", "shared_lookup", started);
    return handle_cache_lookup_result(
      state,
      resolved,
      lookup,
      outbound,
      upstream,
      upstream_version,
      timeouts,
      downstream_scheme,
      host,
      request_method,
      request_uri,
      request_headers,
      request_version,
      listener_bind,
      transport_network,
      stale_on_error,
      revalidation_entry,
      false,
    );
  }
}
