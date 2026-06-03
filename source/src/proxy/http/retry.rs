//! Upstream retry planning and dispatch.
//! Retry decisions preserve request safety, pool health accounting, and body replay limits.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};

use crate::config::{Config, HttpVersion, RetryCondition, RouteConfig, UpstreamConfig};
use crate::pools::PoolSelection;
use crate::state::{AppSnapshot, UpstreamClientRef};

use super::body::ProxyBody;
use super::upstream::select_pool_upstream_excluding;
use super::uri::rewrite_uri;
use super::version::{select_upstream_http_version, upstream_request_version};
use super::{EffectiveTimeouts, UpstreamFirstByteTimeout, full_body, is_idempotent, parts_clone};

#[derive(Clone, Debug)]
pub(super) struct EffectiveRetryPolicy {
  pub(super) enabled: bool,
  tries: usize,
  total_budget: Duration,
  per_attempt_timeout: Option<Duration>,
  on: Vec<RetryCondition>,
  retry_non_idempotent: bool,
  backoff_base: Duration,
  backoff_max: Duration,
  jitter: bool,
  pub(super) reselect_pool_on_retry: bool,
  pub(super) exclude_failed_pool_upstreams: bool,
  pub(super) report_passive_health: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AttemptFailure {
  ConnectError,
  ReadTimeout,
  Status(StatusCode),
}

impl EffectiveRetryPolicy {
  pub(super) fn disabled_direct() -> Self {
    Self {
      enabled: false,
      tries: 1,
      total_budget: Duration::ZERO,
      per_attempt_timeout: None,
      on: Vec::new(),
      retry_non_idempotent: false,
      backoff_base: Duration::ZERO,
      backoff_max: Duration::ZERO,
      jitter: false,
      reselect_pool_on_retry: false,
      exclude_failed_pool_upstreams: false,
      report_passive_health: false,
    }
  }

  pub(super) fn for_route(config: &Config, route: &RouteConfig) -> Self {
    let retry = &config.proxy.retry;
    let route_retry = route.retry.as_ref();
    Self {
      enabled: route_retry
        .and_then(|config| config.enabled)
        .unwrap_or(retry.enabled),
      tries: route_retry
        .and_then(|config| config.tries)
        .unwrap_or(retry.tries)
        .max(1),
      total_budget: Duration::from_millis(
        route_retry
          .and_then(|config| config.total_budget_ms)
          .or(retry.total_budget_ms)
          .unwrap_or(retry.timeout_ms),
      ),
      per_attempt_timeout: route_retry
        .and_then(|config| config.per_attempt_timeout_ms)
        .or(retry.per_attempt_timeout_ms)
        .map(Duration::from_millis),
      on: route_retry
        .and_then(|config| config.on.clone())
        .unwrap_or_else(|| retry.on.clone()),
      retry_non_idempotent: route_retry
        .and_then(|config| config.retry_non_idempotent)
        .unwrap_or(retry.retry_non_idempotent),
      backoff_base: Duration::from_millis(
        route_retry
          .and_then(|config| config.backoff_base_ms)
          .unwrap_or(retry.backoff_base_ms),
      ),
      backoff_max: Duration::from_millis(
        route_retry
          .and_then(|config| config.backoff_max_ms)
          .unwrap_or(retry.backoff_max_ms),
      ),
      jitter: route_retry
        .and_then(|config| config.jitter)
        .unwrap_or(retry.jitter),
      reselect_pool_on_retry: route_retry
        .and_then(|config| config.reselect_pool_on_retry)
        .unwrap_or(retry.reselect_pool_on_retry),
      exclude_failed_pool_upstreams: route_retry
        .and_then(|config| config.exclude_failed_pool_upstreams)
        .unwrap_or(retry.exclude_failed_pool_upstreams),
      report_passive_health: route_retry
        .and_then(|config| config.report_passive_health)
        .unwrap_or(retry.report_passive_health),
    }
  }

  pub(super) fn for_http_request(config: &Config, route: &RouteConfig, method: &Method) -> Self {
    let mut policy = Self::for_route(config, route);
    policy.enabled &= is_idempotent(method) || policy.retry_non_idempotent;
    policy
  }

  pub(super) fn for_direct_http_request(
    config: &Config,
    route: &RouteConfig,
    method: &Method,
  ) -> Self {
    // Pool routes keep disabled retry metadata for passive-health status reporting.
    // Direct upstream sends only need retry details when retry can actually run.
    if !Self::http_retry_enabled(config, route, method) {
      return Self::disabled_direct();
    }
    Self::for_http_request(config, route, method)
  }

  pub(super) fn for_grpc_request(config: &Config, route: &RouteConfig, enabled: bool) -> Self {
    let mut policy = Self::for_route(config, route);
    policy.enabled = enabled;
    policy
  }

  pub(super) fn http_retry_enabled(config: &Config, route: &RouteConfig, method: &Method) -> bool {
    let retry = &config.proxy.retry;
    let route_retry = route.retry.as_ref();
    let enabled = route_retry
      .and_then(|config| config.enabled)
      .unwrap_or(retry.enabled);
    if !enabled {
      return false;
    }
    is_idempotent(method)
      || route_retry
        .and_then(|config| config.retry_non_idempotent)
        .unwrap_or(retry.retry_non_idempotent)
  }

  pub(super) fn matches_failure(&self, failure: AttemptFailure) -> bool {
    self.on.iter().any(|condition| match (condition, failure) {
      (RetryCondition::ConnectError, AttemptFailure::ConnectError) => true,
      (RetryCondition::ReadTimeout, AttemptFailure::ReadTimeout) => true,
      (RetryCondition::Status502, AttemptFailure::Status(status)) => {
        status == StatusCode::BAD_GATEWAY
      }
      (RetryCondition::Status503, AttemptFailure::Status(status)) => {
        status == StatusCode::SERVICE_UNAVAILABLE
      }
      (RetryCondition::Status504, AttemptFailure::Status(status)) => {
        status == StatusCode::GATEWAY_TIMEOUT
      }
      _ => false,
    })
  }

  fn attempt_timeout(&self, upstream_first_byte: Duration, deadline: Instant) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
      return None;
    }
    Some(
      self
        .per_attempt_timeout
        .unwrap_or(upstream_first_byte)
        .min(upstream_first_byte)
        .min(remaining),
    )
  }

  fn backoff_for_attempt(&self, attempt: usize) -> Duration {
    if self.backoff_base.is_zero() || self.backoff_max.is_zero() {
      return Duration::ZERO;
    }
    let multiplier = 1_u32
      .checked_shl(attempt.min(31) as u32)
      .unwrap_or(u32::MAX);
    let base = self.backoff_base.saturating_mul(multiplier);
    let capped = base.min(self.backoff_max);
    if !self.jitter || capped.is_zero() {
      return capped;
    }
    let half = capped / 2;
    half.saturating_add(random_jitter(half))
  }
}

pub(super) async fn send_with_retry(
  client: UpstreamClientRef<'_>,
  request: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  state: &AppSnapshot,
  policy: &EffectiveRetryPolicy,
) -> anyhow::Result<Response<Incoming>> {
  if !policy.enabled || !retry_body_can_be_buffered(&request, state) {
    return send_one_shot(client, request, timeouts).await;
  }

  let (parts, body) = request.into_parts();
  let body = body
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("failed to buffer retryable request body: {error}"))?
    .to_bytes();
  let deadline = retry_deadline(policy);
  let mut last_error = None;
  for attempt in 0..policy.tries {
    let Some(attempt_timeout) = policy.attempt_timeout(timeouts.upstream_first_byte, deadline)
    else {
      break;
    };
    let outbound = Request::from_parts(parts_clone(&parts), full_body(body.clone()));
    match tokio::time::timeout(attempt_timeout, client.request(outbound)).await {
      Ok(Ok(response)) => {
        let failure = AttemptFailure::Status(response.status());
        if policy.matches_failure(failure) {
          last_error = Some(retryable_status_error(response.status()));
          if !has_remaining_attempt(policy, attempt) {
            break;
          }
          sleep_before_retry(policy, attempt, deadline).await;
          continue;
        }
        return Ok(response);
      }
      Ok(Err(error)) => {
        last_error = Some(error.into());
        if !policy.matches_failure(AttemptFailure::ConnectError)
          || !has_remaining_attempt(policy, attempt)
        {
          break;
        }
      }
      Err(_) => {
        last_error = Some(UpstreamFirstByteTimeout::new(attempt_timeout).into());
        if !policy.matches_failure(AttemptFailure::ReadTimeout)
          || !has_remaining_attempt(policy, attempt)
        {
          break;
        }
      }
    }
    sleep_before_retry(policy, attempt, deadline).await;
  }

  Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream retry budget exhausted")))
}

pub(super) async fn send_one_shot(
  client: UpstreamClientRef<'_>,
  request: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<Incoming>> {
  match tokio::time::timeout(timeouts.upstream_first_byte, client.request(request)).await {
    Ok(Ok(response)) => Ok(response),
    Ok(Err(error)) => Err(error.into()),
    Err(_) => Err(UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte).into()),
  }
}

pub(super) struct PoolRetrySuccess {
  pub(super) response: Response<Incoming>,
  pub(super) upstream_index: usize,
  pub(super) pool_selection: PoolSelection,
  pub(super) report_success: bool,
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
  policy: &EffectiveRetryPolicy,
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

  if !policy.enabled || !retry_body_can_be_buffered(&request, state) {
    return match tokio::time::timeout(
      timeouts.upstream_first_byte,
      initial_client.request(request),
    )
    .await
    {
      Ok(Ok(response)) => {
        let report_success = should_report_pool_response_success(policy, response.status());
        Ok(PoolRetrySuccess {
          response,
          upstream_index: initial_upstream_index,
          pool_selection: initial_pool_selection,
          report_success,
        })
      }
      Ok(Err(error)) => Err(error.into()),
      Err(_) => Err(UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte).into()),
    };
  }

  let (parts, body) = request.into_parts();
  let body = body
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("failed to buffer retryable request body: {error}"))?
    .to_bytes();
  let deadline = retry_deadline(policy);
  let mut current_upstream_index = initial_upstream_index;
  let mut current_selection = Some(initial_pool_selection);
  let mut failed_upstreams = Vec::new();
  let mut last_error = None;
  let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(route.upstream_pool.as_deref())
  else {
    anyhow::bail!("pool retry requires an upstream pool route");
  };
  let hash_key = format!("{downstream_host}{original_uri}");

  for attempt in 0..policy.tries {
    if attempt > 0 && policy.reselect_pool_on_retry {
      let selected = match select_pool_upstream_excluding(
        state,
        pool_name,
        client_addr,
        &hash_key,
        request_waf.load_balancing_policy.as_deref(),
        cookie_header,
        if policy.exclude_failed_pool_upstreams {
          &failed_upstreams
        } else {
          &[]
        },
      ) {
        Ok(selected) => selected,
        Err(error) => {
          if last_error.is_none() {
            last_error = Some(anyhow::anyhow!(
              "failed to reselect upstream pool server: {error:?}"
            ));
          }
          break;
        }
      };
      current_upstream_index = selected.upstream_index;
      current_selection = selected.into_pool_selection();
    }

    let Some(attempt_timeout) = policy.attempt_timeout(timeouts.upstream_first_byte, deadline)
    else {
      break;
    };
    let Some(upstream) = state.upstreams.get(current_upstream_index) else {
      last_error = Some(anyhow::anyhow!("selected upstream index is not configured"));
      continue;
    };
    let upstream_version = selected_upstream_http_version(state, route, upstream);
    let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
      last_error = Some(anyhow::anyhow!("upstream URI is not configured"));
      report_pool_attempt_failure(
        state,
        upstream,
        &mut current_selection,
        &mut failed_upstreams,
        policy,
      );
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
      report_pool_attempt_failure(
        state,
        upstream,
        &mut current_selection,
        &mut failed_upstreams,
        policy,
      );
      continue;
    };

    let mut attempt_parts = parts_clone(&parts);
    attempt_parts.uri = target_uri;
    attempt_parts.version = upstream_request_version(upstream_version);
    let outbound = Request::from_parts(attempt_parts, full_body(body.clone()));
    match tokio::time::timeout(attempt_timeout, client.request(outbound)).await {
      Ok(Ok(response)) => {
        let failure = AttemptFailure::Status(response.status());
        if policy.matches_failure(failure) {
          last_error = Some(retryable_status_error(response.status()));
          report_pool_attempt_failure(
            state,
            upstream,
            &mut current_selection,
            &mut failed_upstreams,
            policy,
          );
          if !has_remaining_attempt(policy, attempt) {
            break;
          }
          sleep_before_retry(policy, attempt, deadline).await;
          continue;
        }
        let Some(pool_selection) = current_selection.take() else {
          anyhow::bail!("upstream pool retry lost the active selection");
        };
        return Ok(PoolRetrySuccess {
          response,
          upstream_index: current_upstream_index,
          pool_selection,
          report_success: true,
        });
      }
      Ok(Err(error)) => {
        last_error = Some(error.into());
        let failure = AttemptFailure::ConnectError;
        let retryable = policy.matches_failure(failure);
        if retryable {
          report_pool_attempt_failure(
            state,
            upstream,
            &mut current_selection,
            &mut failed_upstreams,
            policy,
          );
        }
        if !retryable || !has_remaining_attempt(policy, attempt) {
          break;
        }
      }
      Err(_) => {
        last_error = Some(UpstreamFirstByteTimeout::new(attempt_timeout).into());
        let failure = AttemptFailure::ReadTimeout;
        let retryable = policy.matches_failure(failure);
        if retryable {
          report_pool_attempt_failure(
            state,
            upstream,
            &mut current_selection,
            &mut failed_upstreams,
            policy,
          );
        }
        if !retryable || !has_remaining_attempt(policy, attempt) {
          break;
        }
      }
    }
    sleep_before_retry(policy, attempt, deadline).await;
  }

  Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream retry budget exhausted")))
}

fn report_pool_attempt_failure(
  state: &AppSnapshot,
  upstream: &UpstreamConfig,
  current_selection: &mut Option<PoolSelection>,
  failed_upstreams: &mut Vec<String>,
  policy: &EffectiveRetryPolicy,
) {
  report_pool_passive_failure(state, upstream, policy);
  if policy.reselect_pool_on_retry
    && !failed_upstreams
      .iter()
      .any(|failed| failed == &upstream.name)
  {
    failed_upstreams.push(upstream.name.clone());
  }
  if policy.reselect_pool_on_retry {
    drop(current_selection.take());
  }
}

fn report_pool_passive_failure(
  state: &AppSnapshot,
  upstream: &UpstreamConfig,
  policy: &EffectiveRetryPolicy,
) {
  if should_report_pool_passive_failure(policy) {
    state.pools.report_failure(&upstream.name);
  }
}

fn should_report_pool_passive_failure(policy: &EffectiveRetryPolicy) -> bool {
  policy.enabled && policy.report_passive_health
}

fn should_report_pool_response_success(policy: &EffectiveRetryPolicy, status: StatusCode) -> bool {
  !policy.matches_failure(AttemptFailure::Status(status))
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

fn retry_body_can_be_buffered(request: &Request<ProxyBody>, state: &AppSnapshot) -> bool {
  request
    .body()
    .size_hint()
    .upper()
    .is_some_and(|upper| upper <= state.config.proxy.buffering.max_memory_body_bytes as u64)
}

fn retry_deadline(policy: &EffectiveRetryPolicy) -> Instant {
  Instant::now()
    .checked_add(policy.total_budget)
    .unwrap_or_else(Instant::now)
}

fn has_remaining_attempt(policy: &EffectiveRetryPolicy, attempt: usize) -> bool {
  attempt + 1 < policy.tries
}

async fn sleep_before_retry(policy: &EffectiveRetryPolicy, attempt: usize, deadline: Instant) {
  let backoff = policy
    .backoff_for_attempt(attempt)
    .min(deadline.saturating_duration_since(Instant::now()));
  if !backoff.is_zero() {
    tokio::time::sleep(backoff).await;
  }
}

fn retryable_status_error(status: StatusCode) -> anyhow::Error {
  anyhow::anyhow!("upstream returned retryable status {status}")
}

fn random_jitter(max: Duration) -> Duration {
  if max.is_zero() {
    return Duration::ZERO;
  }
  let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .subsec_nanos();
  let max_nanos = max.as_nanos().min(u128::from(u64::MAX)) as u64;
  Duration::from_nanos(u64::from(nanos) % max_nanos.saturating_add(1))
}

#[cfg(test)]
mod tests;
