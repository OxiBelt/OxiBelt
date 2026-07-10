//! Upstream selection for direct routes and pools.
//! Selection errors stay explicit so callers can distinguish policy denial from transport failure.

use http::HeaderValue;

use crate::config::UpstreamConfig;
use crate::pools::PoolSelection;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::waf::RequestWafDecision;

pub(crate) struct SelectedUpstream<'a> {
  pub(crate) upstream: &'a UpstreamConfig,
  pub(crate) upstream_index: usize,
  pub(crate) pool_selection: Option<PoolSelection>,
}

impl SelectedUpstream<'_> {
  pub(crate) fn sticky_cookie(&self) -> Option<HeaderValue> {
    self
      .pool_selection
      .as_ref()
      .and_then(PoolSelection::sticky_cookie)
  }

  pub(crate) fn pool_name(&self) -> Option<&str> {
    self
      .pool_selection
      .as_ref()
      .map(|selection| selection.pool_name.as_str())
  }

  pub(crate) fn into_pool_selection(self) -> Option<PoolSelection> {
    self.pool_selection
  }
}

#[derive(Debug)]
pub(crate) enum UpstreamSelectionError {
  UnknownWafUpstream(String),
  PoolUnavailable { pool_name: String, message: String },
  MissingRouteUpstream,
  MissingSyntheticUpstream(String),
}

pub(crate) async fn select_request_upstream<'a>(
  state: &'a AppSnapshot,
  resolved: &ResolvedRoute<'a>,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  uri: &http::Uri,
  cookie_header: Option<&HeaderValue>,
  request_waf: &RequestWafDecision,
) -> Result<SelectedUpstream<'a>, UpstreamSelectionError> {
  if let Some(upstream_name) = request_waf.upstream_override.as_deref() {
    return find_upstream_by_name(state, upstream_name)
      .map(|(upstream_index, upstream)| SelectedUpstream {
        upstream,
        upstream_index,
        pool_selection: None,
      })
      .ok_or_else(|| UpstreamSelectionError::UnknownWafUpstream(upstream_name.to_string()));
  }

  if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    return select_pool_upstream(
      state,
      pool_name,
      client_addr,
      &format!("{downstream_host}{uri}"),
      request_waf.load_balancing_policy.as_deref(),
      cookie_header,
    )
    .await;
  }

  let upstream = resolved
    .upstream
    .ok_or(UpstreamSelectionError::MissingRouteUpstream)?;
  let upstream_index = resolved
    .upstream_index
    .or_else(|| state.clients.upstream_index(&upstream.name))
    .ok_or(UpstreamSelectionError::MissingRouteUpstream)?;
  Ok(SelectedUpstream {
    upstream,
    upstream_index,
    pool_selection: None,
  })
}

pub(crate) async fn select_pool_upstream<'a>(
  state: &'a AppSnapshot,
  pool_name: &str,
  client_addr: std::net::SocketAddr,
  hash_key: &str,
  policy_override: Option<&str>,
  cookie_header: Option<&HeaderValue>,
) -> Result<SelectedUpstream<'a>, UpstreamSelectionError> {
  select_pool_upstream_excluding(
    state,
    pool_name,
    client_addr,
    hash_key,
    policy_override,
    cookie_header,
    &[],
  )
  .await
}

pub(crate) async fn select_pool_upstream_excluding<'a>(
  state: &'a AppSnapshot,
  pool_name: &str,
  client_addr: std::net::SocketAddr,
  hash_key: &str,
  policy_override: Option<&str>,
  cookie_header: Option<&HeaderValue>,
  excluded_upstreams: &[String],
) -> Result<SelectedUpstream<'a>, UpstreamSelectionError> {
  let selection = state
    .pools
    .select_with_cookie_header_excluding_async(
      pool_name,
      client_addr.ip(),
      hash_key,
      policy_override,
      cookie_header,
      excluded_upstreams,
    )
    .await
    .map_err(|error| UpstreamSelectionError::PoolUnavailable {
      pool_name: pool_name.to_string(),
      message: error.to_string(),
    })?;
  let upstream_name = selection.upstream_name.clone();
  let (upstream_index, upstream) = find_upstream_by_name(state, &upstream_name)
    .ok_or_else(|| UpstreamSelectionError::MissingSyntheticUpstream(upstream_name.clone()))?;
  Ok(SelectedUpstream {
    upstream,
    upstream_index,
    pool_selection: Some(selection),
  })
}

fn find_upstream_by_name<'a>(
  state: &'a AppSnapshot,
  upstream_name: &str,
) -> Option<(usize, &'a UpstreamConfig)> {
  state
    .clients
    .upstream_index(upstream_name)
    .and_then(|upstream_index| {
      state
        .upstreams
        .get(upstream_index)
        .filter(|upstream| upstream.name == upstream_name)
        .map(|upstream| (upstream_index, upstream))
    })
    .or_else(|| {
      state
        .upstreams
        .iter()
        .enumerate()
        .find(|(_, upstream)| upstream.name == upstream_name)
    })
}
