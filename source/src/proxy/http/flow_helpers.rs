//! Small HTTP flow helpers kept out of the main forwarding loop.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Instant;

use http::Response;

use super::{ProxyBody, SystemAccessLogContext};
use crate::config::{ForwardedClientIpSource, RouteConfig};
use crate::state::AppSnapshot;

static EMPTY_TAGS: LazyLock<HashMap<String, String>> = LazyLock::new(HashMap::new);

pub(super) fn elapsed_ms(started_at: Instant) -> u64 {
  started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

pub(super) fn tags_ref(tags: &Option<HashMap<String, String>>) -> &HashMap<String, String> {
  tags.as_ref().unwrap_or(&EMPTY_TAGS)
}

pub(super) fn select_forwarded_client_addr(
  peer_addr: std::net::SocketAddr,
  client_addr: std::net::SocketAddr,
  source: ForwardedClientIpSource,
) -> std::net::SocketAddr {
  match source {
    ForwardedClientIpSource::Resolved => client_addr,
    ForwardedClientIpSource::DirectPeer => peer_addr,
  }
}

pub(super) fn record_route_cache_event(
  state: &AppSnapshot,
  route: &RouteConfig,
  outcome: &str,
  reason: &str,
) {
  state
    .metrics
    .record_cache_event(&route.name, route.cache.as_deref(), outcome, reason);
}

pub(super) fn record_route_cache_fill_stage(
  state: &AppSnapshot,
  route: &RouteConfig,
  stage: &str,
  outcome: &str,
  started: Instant,
) {
  state.metrics.record_cache_fill_stage(
    &state.config.metrics,
    &route.name,
    route.cache.as_deref(),
    stage,
    outcome,
    elapsed_ms(started),
  );
}

pub(super) fn emit_system_access_log(
  state: &AppSnapshot,
  context: &mut SystemAccessLogContext<'_>,
  response: &Response<ProxyBody>,
) {
  if !state.request_path_features.system_access_log {
    return;
  }
  if let Some(input) = context.response_input(response) {
    state.system_access_log.emit(&state.waf, input);
  }
}
