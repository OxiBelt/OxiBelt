use std::sync::Arc;
use std::time::Instant;

use http::{Method, Request};
use hyper::body::Body;

use crate::circuit_breakers::{CircuitBreakerRuntime, CircuitOutcome, CircuitOutcomeFailure};
use crate::config::{HttpVersion, ProxyProtocolEgressMode, UpstreamConfig};
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{
  DirectH2PoolEvent, FastPathMetricProtocol, FastPathTransportMissReason,
};
use crate::overload::OverloadRuntime;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{self, ProxyBody};

use super::super::helpers::fast_path_metric_protocol;
use super::super::request_body::FastPathRequestBodyMode;
use super::super::stage_timing as timing;
use super::metrics as metric_record;
use super::pool::DirectH2DrainReason;
use super::request::{PreparedDirectH2Request, restore_fallback_version};
use super::{DirectH2Lease, DirectH2Pool, DirectH2Pools, DirectH2Response, DirectH2Sender};

pub(in crate::proxy::http::fast_path) enum DirectH2SendResult {
  Fallback {
    request: Request<ProxyBody>,
    deadline: Instant,
  },
  Sent(Result<DirectH2Response, anyhow::Error>),
}

enum DirectH2DispatchResult {
  Response(DirectH2Response),
  Recovered {
    request: Request<ProxyBody>,
    reused: bool,
  },
  Failed(anyhow::Error),
}

#[allow(clippy::too_many_arguments)]
pub(in crate::proxy::http::fast_path) async fn try_send_direct_h2(
  pools: &DirectH2Pools,
  metrics: &Arc<Metrics>,
  circuit_breakers: &Arc<CircuitBreakerRuntime>,
  overload: &Arc<OverloadRuntime>,
  route_name: &str,
  pool_name: Option<&str>,
  upstream_index: usize,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_mode: FastPathRequestBodyMode,
  outbound: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  hot_path_metrics: bool,
  timing_enabled: bool,
) -> DirectH2SendResult {
  let protocol = fast_path_metric_protocol(request_version);
  let request_budget = timeouts.upstream_first_byte.min(timeouts.upstream_request);
  let Some(request_deadline) = Instant::now().checked_add(request_budget) else {
    return direct_h2_send_error(
      metrics,
      protocol,
      anyhow::anyhow!("direct H2 upstream request deadline overflow"),
      hot_path_metrics,
    );
  };
  if let Some(reason) = direct_h2_guard_miss(
    upstream,
    upstream_version,
    request_version,
    direct_selection_used,
    request_body_mode,
    &outbound,
  ) {
    metric_record::transport_miss(metrics.as_ref(), hot_path_metrics, protocol, reason);
    return DirectH2SendResult::Fallback {
      request: outbound,
      deadline: request_deadline,
    };
  }

  let Some(pool) = pools.for_upstream_index(upstream_index) else {
    metric_record::transport_miss(
      metrics.as_ref(),
      hot_path_metrics,
      protocol,
      FastPathTransportMissReason::UnsupportedUpstream,
    );
    return DirectH2SendResult::Fallback {
      request: outbound,
      deadline: request_deadline,
    };
  };

  let prepared = match PreparedDirectH2Request::from_request(outbound) {
    Ok(prepared) => prepared,
    Err(error) => {
      metric_record::transport_miss(
        metrics.as_ref(),
        hot_path_metrics,
        protocol,
        FastPathTransportMissReason::UnsupportedRequest,
      );
      return DirectH2SendResult::Sent(Err(error));
    }
  };

  send_prepared_request(
    pool,
    metrics,
    circuit_breakers,
    overload,
    route_name,
    pool_name,
    protocol,
    prepared,
    timeouts,
    request_deadline,
    hot_path_metrics,
    timing_enabled,
  )
  .await
}

pub(super) fn direct_h2_guard_miss(
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_mode: FastPathRequestBodyMode,
  outbound: &Request<ProxyBody>,
) -> Option<FastPathTransportMissReason> {
  if !matches!(
    request_version,
    http::Version::HTTP_11 | http::Version::HTTP_2 | http::Version::HTTP_3
  ) || !direct_selection_used
    || !matches!(outbound.method(), &Method::GET | &Method::HEAD)
  {
    return Some(FastPathTransportMissReason::UnsupportedRequest);
  }
  if upstream_version != HttpVersion::H2
    || !matches!(upstream.origin.scheme(), "http" | "https")
    || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return Some(FastPathTransportMissReason::UnsupportedUpstream);
  }
  if request_body_mode != FastPathRequestBodyMode::Empty || !outbound.body().is_end_stream() {
    return Some(FastPathTransportMissReason::RequestBody);
  }
  None
}

#[allow(clippy::too_many_arguments)]
async fn send_prepared_request(
  pool: Arc<DirectH2Pool>,
  metrics: &Arc<Metrics>,
  circuit_breakers: &Arc<CircuitBreakerRuntime>,
  overload: &Arc<OverloadRuntime>,
  route_name: &str,
  pool_name: Option<&str>,
  protocol: FastPathMetricProtocol,
  prepared: PreparedDirectH2Request,
  timeouts: EffectiveTimeouts,
  request_deadline: Instant,
  hot_path_metrics: bool,
  timing_enabled: bool,
) -> DirectH2SendResult {
  metric_record::upstream_request(&pool, metrics, hot_path_metrics);
  let (mut request, fallback_version) = prepared.into_parts();
  let mut reconnects = 0;
  loop {
    let pool_take_started = timing::start(timing_enabled);
    let direct_sender_result = pool
      .sender(
        metrics,
        hot_path_metrics,
        request_deadline,
        timeouts.upstream_connect,
        || overload.state(),
        protocol,
        timing_enabled,
      )
      .await;
    timing::record_metrics_plain_result(
      metrics,
      protocol,
      timing::STAGE_DIRECT_H2_POOL_TAKE,
      matches!(&direct_sender_result, Ok(Some(_))),
      pool_take_started,
    );
    let direct_sender = match direct_sender_result {
      Ok(Some(sender)) => sender,
      Ok(None) => {
        return saturated_fallback(
          metrics,
          protocol,
          restore_fallback_version(request, fallback_version),
          request_deadline,
          hot_path_metrics,
        );
      }
      Err(error) => return direct_h2_send_error(metrics, protocol, error, hot_path_metrics),
    };

    match dispatch_once(
      &pool,
      direct_sender,
      request,
      circuit_breakers,
      route_name,
      pool_name,
      request_deadline,
      metrics,
      protocol,
      hot_path_metrics,
      timing_enabled,
    )
    .await
    {
      DirectH2DispatchResult::Response(response) => {
        metric_record::transport_hit(metrics, hot_path_metrics, protocol);
        return DirectH2SendResult::Sent(Ok(response));
      }
      DirectH2DispatchResult::Recovered {
        request: recovered,
        reused,
      } if reused
        && reconnects == 0
        && overload.state() == crate::overload::OverloadState::Normal =>
      {
        reconnects += 1;
        metric_record::pool_event(metrics, hot_path_metrics, DirectH2PoolEvent::Reconnect);
        request = recovered;
      }
      DirectH2DispatchResult::Recovered {
        request: recovered, ..
      } => {
        if Instant::now() >= request_deadline {
          return direct_h2_send_error(
            metrics,
            protocol,
            anyhow::anyhow!("direct H2 upstream first-byte timed out"),
            hot_path_metrics,
          );
        }
        return DirectH2SendResult::Fallback {
          request: restore_fallback_version(recovered, fallback_version),
          deadline: request_deadline,
        };
      }
      DirectH2DispatchResult::Failed(error) => {
        return direct_h2_send_error(metrics, protocol, error, hot_path_metrics);
      }
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_once(
  pool: &Arc<DirectH2Pool>,
  mut direct_sender: DirectH2Sender,
  request: Request<ProxyBody>,
  circuit_breakers: &Arc<CircuitBreakerRuntime>,
  route_name: &str,
  pool_name: Option<&str>,
  request_deadline: Instant,
  metrics: &Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  _hot_path_metrics: bool,
  timing_enabled: bool,
) -> DirectH2DispatchResult {
  let mut attempt_admission = match circuit_breakers
    .admit_upstream_attempt(route_name, pool_name, Some(request_deadline))
    .await
  {
    Ok(admission) => admission,
    Err(error) => return DirectH2DispatchResult::Failed(anyhow::Error::new(error)),
  };
  let stream_admission = match circuit_breakers
    .admit_upstream_stream(route_name, pool_name, Some(request_deadline))
    .await
  {
    Ok(admission) => admission,
    Err(error) => return DirectH2DispatchResult::Failed(anyhow::Error::new(error)),
  };
  if Instant::now() >= request_deadline {
    attempt_admission.record_outcome(CircuitOutcome::Failure(
      CircuitOutcomeFailure::FirstByteTimeout,
    ));
    return DirectH2DispatchResult::Failed(anyhow::anyhow!(
      "direct H2 upstream first-byte timed out"
    ));
  }
  direct_sender.lease.set_stream_admission(stream_admission);
  let reused = direct_sender.reused;
  let send_started = timing::start(timing_enabled);
  let result = tokio::time::timeout_at(
    request_deadline.into(),
    direct_sender.sender.try_send_request(request),
  )
  .await;
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H2_SEND_REQUEST,
    matches!(result, Ok(Ok(_))),
    send_started,
  );
  match result {
    Ok(Ok(response)) => {
      attempt_admission.record_outcome(CircuitOutcome::Failure(CircuitOutcomeFailure::Status(
        response.status().as_u16(),
      )));
      DirectH2DispatchResult::Response(DirectH2Response::new(response, direct_sender.lease))
    }
    Ok(Err(mut error)) => {
      let recovered = error.take_message();
      let error = error.into_error();
      attempt_admission
        .record_outcome(CircuitOutcome::Failure(CircuitOutcomeFailure::ConnectError));
      pool.mark_unhealthy(&direct_sender.lease, DirectH2DrainReason::SendError);
      drop(direct_sender.lease);
      match recovered {
        Some(request) => DirectH2DispatchResult::Recovered { request, reused },
        None => DirectH2DispatchResult::Failed(
          anyhow::Error::new(error).context("direct H2 upstream request failed after dispatch"),
        ),
      }
    }
    Err(_) => {
      attempt_admission.record_outcome(CircuitOutcome::Failure(
        CircuitOutcomeFailure::FirstByteTimeout,
      ));
      drop(direct_sender.lease);
      DirectH2DispatchResult::Failed(anyhow::anyhow!("direct H2 upstream first-byte timed out"))
    }
  }
}

#[cfg(test)]
pub(super) async fn dispatch_expired_for_test(
  pool: &Arc<DirectH2Pool>,
  sender: DirectH2Sender,
  request: Request<ProxyBody>,
  circuit_breakers: &Arc<CircuitBreakerRuntime>,
  deadline: Instant,
  metrics: &Arc<Metrics>,
) {
  let result = dispatch_once(
    pool,
    sender,
    request,
    circuit_breakers,
    "test-route",
    None,
    deadline,
    metrics,
    FastPathMetricProtocol::H2,
    false,
    false,
  )
  .await;
  assert!(matches!(result, DirectH2DispatchResult::Failed(_)));
}

fn saturated_fallback(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  request: Request<ProxyBody>,
  deadline: Instant,
  hot_path_metrics: bool,
) -> DirectH2SendResult {
  metric_record::transport_miss(
    metrics,
    hot_path_metrics,
    protocol,
    FastPathTransportMissReason::PoolFull,
  );
  DirectH2SendResult::Fallback { request, deadline }
}

fn direct_h2_send_error(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  error: anyhow::Error,
  hot_path_metrics: bool,
) -> DirectH2SendResult {
  let reason = if error.to_string().contains("timed out") {
    FastPathTransportMissReason::ConnectError
  } else {
    FastPathTransportMissReason::SendError
  };
  metric_record::transport_miss(metrics, hot_path_metrics, protocol, reason);
  DirectH2SendResult::Sent(Err(error))
}

pub(in crate::proxy::http::fast_path) fn release_response_body(
  body: ProxyBody,
  lease: DirectH2Lease,
  body_consumed: bool,
) -> ProxyBody {
  if body_consumed {
    drop(lease);
    return body;
  }
  body::with_drop_guard(body, lease)
}
