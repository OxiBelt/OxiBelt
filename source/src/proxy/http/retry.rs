use http::{HeaderValue, Request, Response};
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};

use crate::config::{HttpVersion, RouteConfig, UpstreamConfig};
use crate::pools::PoolSelection;
use crate::state::{AppSnapshot, UpstreamClientRef};

use super::body::ProxyBody;
use super::upstream::select_pool_upstream;
use super::uri::rewrite_uri;
use super::version::{select_upstream_http_version, upstream_request_version};
use super::{
  EffectiveTimeouts, UpstreamFirstByteTimeout, full_body, parts_clone, retryable_status,
};

pub(super) async fn send_with_retry(
  client: UpstreamClientRef<'_>,
  request: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  state: &AppSnapshot,
  retry_enabled: bool,
) -> anyhow::Result<Response<Incoming>> {
  if retry_enabled
    && request
      .body()
      .size_hint()
      .upper()
      .is_some_and(|upper| upper <= state.config.proxy.buffering.max_memory_body_bytes as u64)
  {
    let (parts, body) = request.into_parts();
    let body = body
      .collect()
      .await
      .map_err(|error| anyhow::anyhow!("failed to buffer retryable request body: {error}"))?
      .to_bytes();
    let tries = state.config.proxy.retry.tries.max(1);
    let mut last_error = None;
    for _ in 0..tries {
      let outbound = Request::from_parts(parts_clone(&parts), full_body(body.clone()));
      match tokio::time::timeout(timeouts.upstream_first_byte, client.request(outbound)).await {
        Ok(Ok(response)) if retryable_status(response.status(), state) => {
          last_error = Some(anyhow::anyhow!(
            "upstream returned retryable status {}",
            response.status()
          ));
        }
        Ok(Ok(response)) => return Ok(response),
        Ok(Err(error)) => last_error = Some(error.into()),
        Err(_) => {
          last_error = Some(UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte).into());
        }
      }
    }
    return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream retry failed")));
  }
  match tokio::time::timeout(timeouts.upstream_first_byte, client.request(request)).await {
    Ok(result) => Ok(result?),
    Err(_) => Err(UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte).into()),
  }
}

pub(super) struct PoolRetrySuccess {
  pub(super) response: Response<Incoming>,
  pub(super) upstream_index: usize,
  pub(super) pool_selection: PoolSelection,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_pool_with_retry(
  state: &AppSnapshot,
  request: Request<ProxyBody>,
  initial_upstream_index: usize,
  initial_pool_selection: PoolSelection,
  route: &RouteConfig,
  original_uri: &http::Uri,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  cookie_header: Option<&HeaderValue>,
  request_waf: &crate::waf::RequestWafDecision,
  timeouts: EffectiveTimeouts,
  retry_enabled: bool,
) -> anyhow::Result<PoolRetrySuccess> {
  let Some(initial_upstream) = state.upstreams.get(initial_upstream_index) else {
    anyhow::bail!("selected upstream index is not configured");
  };
  let initial_version = selected_upstream_http_version(state, route, initial_upstream);
  let Some(initial_client) = state.clients.for_upstream_index(
    initial_upstream_index,
    initial_upstream.origin.scheme(),
    initial_version,
  ) else {
    anyhow::bail!("upstream client is not configured");
  };

  if !retry_enabled
    || request
      .body()
      .size_hint()
      .upper()
      .is_none_or(|upper| upper > state.config.proxy.buffering.max_memory_body_bytes as u64)
  {
    return match tokio::time::timeout(
      timeouts.upstream_first_byte,
      initial_client.request(request),
    )
    .await
    {
      Ok(Ok(response)) => Ok(PoolRetrySuccess {
        response,
        upstream_index: initial_upstream_index,
        pool_selection: initial_pool_selection,
      }),
      Ok(Err(error)) => {
        state.pools.report_failure(&initial_upstream.name);
        Err(error.into())
      }
      Err(_) => {
        state.pools.report_failure(&initial_upstream.name);
        Err(UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte).into())
      }
    };
  }

  let (parts, body) = request.into_parts();
  let body = body
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("failed to buffer retryable request body: {error}"))?
    .to_bytes();
  let tries = state.config.proxy.retry.tries.max(1);
  let mut current_upstream_index = initial_upstream_index;
  let mut current_selection = Some(initial_pool_selection);
  let mut last_error = None;
  let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(route.upstream_pool.as_deref())
  else {
    anyhow::bail!("pool retry requires an upstream pool route");
  };
  let hash_key = format!("{downstream_host}{original_uri}");

  for attempt in 0..tries {
    if attempt > 0 {
      let selected = select_pool_upstream(
        state,
        pool_name,
        client_addr,
        &hash_key,
        request_waf.load_balancing_policy.as_deref(),
        cookie_header,
      )
      .map_err(|error| anyhow::anyhow!("failed to reselect upstream pool server: {error:?}"))?;
      current_upstream_index = selected.upstream_index;
      current_selection = selected.into_pool_selection();
    }

    let Some(upstream) = state.upstreams.get(current_upstream_index) else {
      last_error = Some(anyhow::anyhow!("selected upstream index is not configured"));
      continue;
    };
    let upstream_version = selected_upstream_http_version(state, route, upstream);
    let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
      last_error = Some(anyhow::anyhow!("upstream URI is not configured"));
      report_pool_attempt_failure(state, upstream, &mut current_selection);
      continue;
    };
    let target_uri = rewrite_uri(
      upstream_uri,
      route.path_prefix.as_str(),
      route.replace_prefix_with.as_deref(),
      original_uri,
    )?;
    let Some(client) = state.clients.for_upstream_index(
      current_upstream_index,
      upstream.origin.scheme(),
      upstream_version,
    ) else {
      last_error = Some(anyhow::anyhow!("upstream client is not configured"));
      report_pool_attempt_failure(state, upstream, &mut current_selection);
      continue;
    };

    let mut attempt_parts = parts_clone(&parts);
    attempt_parts.uri = target_uri;
    attempt_parts.version = upstream_request_version(upstream_version);
    let outbound = Request::from_parts(attempt_parts, full_body(body.clone()));
    match tokio::time::timeout(timeouts.upstream_first_byte, client.request(outbound)).await {
      Ok(Ok(response)) if retryable_status(response.status(), state) => {
        last_error = Some(anyhow::anyhow!(
          "upstream returned retryable status {}",
          response.status()
        ));
        report_pool_attempt_failure(state, upstream, &mut current_selection);
      }
      Ok(Ok(response)) => {
        let Some(pool_selection) = current_selection.take() else {
          anyhow::bail!("upstream pool retry lost the active selection");
        };
        return Ok(PoolRetrySuccess {
          response,
          upstream_index: current_upstream_index,
          pool_selection,
        });
      }
      Ok(Err(error)) => {
        last_error = Some(error.into());
        report_pool_attempt_failure(state, upstream, &mut current_selection);
      }
      Err(_) => {
        last_error = Some(UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte).into());
        report_pool_attempt_failure(state, upstream, &mut current_selection);
      }
    }
  }

  Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream retry failed")))
}

fn report_pool_attempt_failure(
  state: &AppSnapshot,
  upstream: &UpstreamConfig,
  current_selection: &mut Option<PoolSelection>,
) {
  state.pools.report_failure(&upstream.name);
  drop(current_selection.take());
}

fn selected_upstream_http_version(
  state: &AppSnapshot,
  route: &RouteConfig,
  upstream: &UpstreamConfig,
) -> HttpVersion {
  route.upstream_http_version.unwrap_or_else(|| {
    select_upstream_http_version(
      state.config.proxy.auto_upgrade.enabled,
      state.config.proxy.auto_upgrade.max_http_version,
      upstream.max_http_version,
    )
  })
}
