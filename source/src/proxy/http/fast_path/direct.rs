use http::Method;

use crate::config::{HttpVersion, ProxyProtocolEgressMode, RouteConfig, UpstreamConfig};
use crate::proxy::http::EffectiveRetryPolicy;
use crate::proxy::http::version::select_upstream_http_version;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::waf::RequestWafDecision;

pub(super) struct DirectFastPathSelection<'a> {
  pub(super) upstream: &'a UpstreamConfig,
  pub(super) upstream_index: usize,
  pub(super) upstream_version: HttpVersion,
}

pub(super) fn direct_http_retry_enabled(
  state: &AppSnapshot,
  route: &RouteConfig,
  method: &Method,
) -> bool {
  EffectiveRetryPolicy::http_retry_enabled(&state.config, route, method)
}

pub(super) fn select_direct_fast_path_upstream<'a>(
  state: &'a AppSnapshot,
  resolved: &ResolvedRoute<'a>,
  request_waf: &RequestWafDecision,
  direct_retry_enabled: bool,
) -> Option<DirectFastPathSelection<'a>> {
  if direct_retry_enabled
    || request_waf.upstream_override.is_some()
    || request_waf.upstream_pool_override.is_some()
    || resolved.route.upstream_pool.is_some()
  {
    return None;
  }

  let upstream = resolved.upstream?;
  let upstream_index = resolved.upstream_index?;
  if state
    .upstreams
    .get(upstream_index)
    .is_none_or(|candidate| candidate.name != upstream.name)
  {
    return None;
  }

  let upstream_version = resolved.route.upstream_http_version.unwrap_or_else(|| {
    select_upstream_http_version(
      state.config.proxy.auto_upgrade.enabled,
      state.config.proxy.auto_upgrade.max_http_version,
      upstream.max_http_version,
    )
  });
  if upstream_version == HttpVersion::H3
    || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return None;
  }

  Some(DirectFastPathSelection {
    upstream,
    upstream_index,
    upstream_version,
  })
}
