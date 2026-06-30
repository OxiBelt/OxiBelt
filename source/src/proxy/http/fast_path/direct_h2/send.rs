use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use http::{Method, Request};
use hyper::body::Body;
use tracing::debug;

use crate::config::{HttpVersion, ProxyProtocolEgressMode, UpstreamConfig};
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{FastPathMetricProtocol, FastPathTransportMissReason};
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{self, ProxyBody};

use super::super::helpers::fast_path_metric_protocol;
use super::super::stage_timing as timing;
use super::metrics as metric_record;
use super::request::PreparedDirectH2Request;
use super::{DirectH2Lease, DirectH2Pool, DirectH2Pools, DirectH2Response, DirectH2Sender};

pub(in crate::proxy::http::fast_path) enum DirectH2SendResult {
  Fallback(Request<ProxyBody>),
  Sent(Result<DirectH2Response, anyhow::Error>),
}

#[allow(clippy::too_many_arguments)]
pub(in crate::proxy::http::fast_path) async fn try_send_direct_h2(
  pools: &DirectH2Pools,
  metrics: &Arc<Metrics>,
  upstream_index: usize,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  outbound: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
  hot_path_metrics: bool,
  timing_enabled: bool,
) -> DirectH2SendResult {
  let protocol = fast_path_metric_protocol(request_version);
  if let Some(reason) = direct_h2_guard_miss(
    upstream,
    upstream_version,
    request_version,
    direct_selection_used,
    request_body_proven_empty,
    &outbound,
  ) {
    metric_record::transport_miss(metrics.as_ref(), hot_path_metrics, protocol, reason);
    return DirectH2SendResult::Fallback(outbound);
  }

  let Some(pool) = pools.for_upstream_index(upstream_index) else {
    metric_record::transport_miss(
      metrics.as_ref(),
      hot_path_metrics,
      protocol,
      FastPathTransportMissReason::UnsupportedUpstream,
    );
    return DirectH2SendResult::Fallback(outbound);
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
    protocol,
    prepared,
    timeouts,
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
  request_body_proven_empty: bool,
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
  if !request_body_proven_empty || !outbound.body().is_end_stream() {
    return Some(FastPathTransportMissReason::RequestBody);
  }
  None
}

async fn send_prepared_request(
  pool: Arc<DirectH2Pool>,
  metrics: &Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  prepared: PreparedDirectH2Request,
  timeouts: EffectiveTimeouts,
  hot_path_metrics: bool,
  timing_enabled: bool,
) -> DirectH2SendResult {
  metric_record::upstream_request(&pool, metrics, hot_path_metrics);

  let direct_sender = match sender_with_first_byte_timeout(
    pool.sender(metrics, hot_path_metrics),
    timeouts.upstream_first_byte,
  )
  .await
  {
    Ok(Some(direct_sender)) => direct_sender,
    Ok(None) => {
      return saturated_fallback(
        metrics,
        protocol,
        prepared.into_fallback_request(),
        hot_path_metrics,
      );
    }
    Err(error) => return direct_h2_send_error(metrics, protocol, error, hot_path_metrics),
  };
  let reused = direct_sender.reused;
  let mut sender = direct_sender.sender;
  let lease = direct_sender.lease;
  let mut retry = reused.then(|| prepared.retry_request());
  let send_started = timing::start(timing_enabled);
  let send_result = tokio::time::timeout(
    timeouts.upstream_first_byte,
    sender.send_request(prepared.into_request()),
  )
  .await;
  timing::record_metrics_plain_result(
    metrics,
    protocol,
    timing::STAGE_DIRECT_H2_SEND_REQUEST,
    matches!(send_result, Ok(Ok(_))),
    send_started,
  );
  match send_result {
    Ok(Ok(response)) => {
      metric_record::transport_hit(metrics, hot_path_metrics, protocol);
      DirectH2SendResult::Sent(Ok(DirectH2Response {
        response,
        lease: Some(lease),
      }))
    }
    Ok(Err(error)) if reused => {
      debug!(error = %error, "direct H2 upstream sender failed; reconnecting once");
      metric_record::pool_event(metrics, hot_path_metrics, "reconnect");
      pool.clear_connection(&lease.connection).await;
      drop(lease);
      retry_reused_request(
        pool,
        metrics,
        protocol,
        retry
          .take()
          .expect("reused direct H2 sends should retain one retry request"),
        timeouts,
        hot_path_metrics,
        timing_enabled,
      )
      .await
    }
    Ok(Err(error)) => {
      pool.clear_connection(&lease.connection).await;
      drop(lease);
      direct_h2_send_error(metrics, protocol, error.into(), hot_path_metrics)
    }
    Err(_) => {
      pool.clear_connection(&lease.connection).await;
      drop(lease);
      direct_h2_send_error(
        metrics,
        protocol,
        anyhow::anyhow!("direct H2 upstream first-byte timed out"),
        hot_path_metrics,
      )
    }
  }
}

async fn retry_reused_request(
  pool: Arc<DirectH2Pool>,
  metrics: &Arc<Metrics>,
  protocol: FastPathMetricProtocol,
  retry: super::request::RetryDirectH2Request,
  timeouts: EffectiveTimeouts,
  hot_path_metrics: bool,
  timing_enabled: bool,
) -> DirectH2SendResult {
  let direct_sender = match sender_with_first_byte_timeout(
    pool.sender(metrics, hot_path_metrics),
    timeouts.upstream_first_byte,
  )
  .await
  {
    Ok(Some(direct_sender)) => direct_sender,
    Ok(None) => {
      return saturated_fallback(
        metrics,
        protocol,
        retry.into_fallback_request(),
        hot_path_metrics,
      );
    }
    Err(error) => return direct_h2_send_error(metrics, protocol, error, hot_path_metrics),
  };
  let mut sender = direct_sender.sender;
  let lease = direct_sender.lease;
  let send_started = timing::start(timing_enabled);
  match tokio::time::timeout(
    timeouts.upstream_first_byte,
    sender.send_request(retry.into_request()),
  )
  .await
  {
    Ok(Ok(response)) => {
      timing::record_metrics_plain_result(
        metrics,
        protocol,
        timing::STAGE_DIRECT_H2_SEND_REQUEST,
        true,
        send_started,
      );
      metric_record::transport_hit(metrics, hot_path_metrics, protocol);
      DirectH2SendResult::Sent(Ok(DirectH2Response {
        response,
        lease: Some(lease),
      }))
    }
    Ok(Err(error)) => {
      timing::record_metrics_plain_result(
        metrics,
        protocol,
        timing::STAGE_DIRECT_H2_SEND_REQUEST,
        false,
        send_started,
      );
      pool.clear_connection(&lease.connection).await;
      drop(lease);
      direct_h2_send_error(
        metrics,
        protocol,
        anyhow::Error::new(error).context("direct H2 upstream retry request failed"),
        hot_path_metrics,
      )
    }
    Err(_) => {
      timing::record_metrics_plain_result(
        metrics,
        protocol,
        timing::STAGE_DIRECT_H2_SEND_REQUEST,
        false,
        send_started,
      );
      pool.clear_connection(&lease.connection).await;
      drop(lease);
      direct_h2_send_error(
        metrics,
        protocol,
        anyhow::anyhow!("direct H2 upstream first-byte timed out"),
        hot_path_metrics,
      )
    }
  }
}

fn saturated_fallback(
  metrics: &Metrics,
  protocol: FastPathMetricProtocol,
  outbound: Request<ProxyBody>,
  hot_path_metrics: bool,
) -> DirectH2SendResult {
  metric_record::transport_miss(
    metrics,
    hot_path_metrics,
    protocol,
    FastPathTransportMissReason::PoolFull,
  );
  DirectH2SendResult::Fallback(outbound)
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

pub(super) async fn sender_with_first_byte_timeout<F>(
  sender: F,
  timeout: Duration,
) -> anyhow::Result<Option<DirectH2Sender>>
where
  F: Future<Output = anyhow::Result<Option<DirectH2Sender>>>,
{
  match tokio::time::timeout(timeout, sender).await {
    Ok(result) => result,
    Err(_) => anyhow::bail!("direct H2 upstream first-byte timed out"),
  }
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
