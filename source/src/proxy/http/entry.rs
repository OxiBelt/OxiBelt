//! Listener-facing HTTP entrypoints and process-wide request admission.

use std::sync::Arc;

use http::Request;
use hyper::body::{Body, Incoming};

use crate::bandwidth::BandwidthDirection;
use crate::lifecycle::ConnectionDrain;
use crate::limits::ConnectionLimitContext;
use crate::state::AppSnapshot;
use crate::waf::{
  WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork, request_protocol,
};

use super::*;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  transport_metadata: WafTransportMetadataInput<'static>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
) -> Response<ProxyBody> {
  handle_with_forwarded_header_cache(
    request,
    peer_addr,
    tcp_max_hop,
    transport_metadata,
    tls,
    connection_limit_context,
    None,
    state,
    downstream_scheme,
    drain,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_with_forwarded_header_cache(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  transport_metadata: WafTransportMetadataInput<'static>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  forwarded_header_cache: Option<headers::ForwardedHeaderCache>,
  state: Arc<AppSnapshot>,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
) -> Response<ProxyBody> {
  let protocol = request_protocol(request.headers());
  handle_inner(
    request,
    peer_addr,
    tcp_max_hop,
    transport_metadata,
    tls,
    connection_limit_context,
    forwarded_header_cache,
    state,
    protocol,
    WafTransportNetwork::Tcp,
    true,
    downstream_scheme,
    drain,
  )
  .await
}

pub(crate) async fn handle_http3(
  request: Request<ProxyBody>,
  peer_addr: std::net::SocketAddr,
  udp_connection_id: &str,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  drain: ConnectionDrain,
) -> Response<ProxyBody> {
  handle_inner(
    request,
    peer_addr,
    None,
    WafTransportMetadataInput {
      udp_connection_id: Some(udp_connection_id),
      ..WafTransportMetadataInput::default()
    },
    tls,
    connection_limit_context,
    None,
    state,
    WafProtocol::Http,
    WafTransportNetwork::Udp,
    false,
    "https",
    drain,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_inner<B>(
  mut request: Request<B>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  transport_metadata: WafTransportMetadataInput<'_>,
  tls: Arc<WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  forwarded_header_cache: Option<headers::ForwardedHeaderCache>,
  state: Arc<AppSnapshot>,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  reject_connect: bool,
  downstream_scheme: &'static str,
  drain: ConnectionDrain,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  let request_version = request.version();
  let downstream_receive_started =
    fast_path::stage_timing::start(state.request_path_features.stage_timing_metrics);
  early_data::strip_untrusted_header(request.headers_mut());
  if transport_network != WafTransportNetwork::Udp {
    fast_path::stage_timing::record(
      state.as_ref(),
      fast_path::stage_timing::PATH_PLAIN_PROXY,
      fast_path::stage_timing::protocol(request_version),
      fast_path::stage_timing::STAGE_DOWNSTREAM_PROTOCOL_RECEIVE,
      fast_path::stage_timing::OUTCOME_OK,
      downstream_receive_started,
    );
  }
  let system_access_log_enabled = state.request_path_features.system_access_log;
  let trace_context = if state.request_path_features.telemetry {
    state.telemetry.context_from_headers(request.headers())
  } else {
    None
  };
  let telemetry_start = request_observability_start(&state, trace_context);
  let access_log_metadata_enabled = system_access_log_enabled || telemetry_start.is_some();
  let mut access_log = SystemAccessLogContext::new(
    &request,
    peer_addr,
    tcp_max_hop,
    system_access_log_enabled.then(|| tls.clone()),
    protocol,
    transport_network,
    transport_metadata,
    downstream_scheme,
    access_log_metadata_enabled,
    system_access_log_enabled,
  );
  let overload_request_lease = match state.overload.try_admit_request(request_version) {
    Ok(lease) => lease,
    Err(_) => {
      let response = overload_response(state.as_ref(), request_version);
      emit_system_access_log(state.as_ref(), &mut access_log, &response).await;
      record_request_observability(
        &state,
        &access_log,
        &response,
        trace_context,
        telemetry_start,
      );
      return response;
    }
  };
  let priority_admission = priority_admission::classify(
    &request,
    peer_addr,
    tls.as_ref(),
    state.as_ref(),
    protocol,
    transport_network,
  );
  let circuit_breaker_request_lease = match state
    .circuit_breakers
    .admit_priority_global_request(
      priority_admission.class,
      priority_admission.reservation_eligible,
      None,
    )
    .await
  {
    Ok(lease) => lease,
    Err(rejection) => {
      let response = circuit_breaker_rejection_response(state.as_ref(), rejection);
      emit_system_access_log(state.as_ref(), &mut access_log, &response).await;
      record_request_observability(
        &state,
        &access_log,
        &response,
        trace_context,
        telemetry_start,
      );
      return response;
    }
  };
  let mut request_connection_permit = None;
  let mut selected_bandwidth = None;
  let response = handle_inner_impl(
    request,
    peer_addr,
    tcp_max_hop,
    transport_metadata,
    tls,
    connection_limit_context,
    forwarded_header_cache,
    &state,
    protocol,
    transport_network,
    reject_connect,
    downstream_scheme,
    drain,
    &mut access_log,
    &mut request_connection_permit,
    &mut selected_bandwidth,
    trace_context,
  )
  .await;
  let response = if let Some(limiter) = selected_bandwidth {
    with_final_response_bandwidth(response, limiter, state.metrics.clone(), transport_network)
  } else {
    response
  };
  let response = if let Some(permit) = request_connection_permit {
    with_connection_permit(response, permit)
  } else {
    response
  };
  let response = with_circuit_breaker_request_lease(response, circuit_breaker_request_lease);
  let response = with_overload_request_lease(response, overload_request_lease);
  emit_system_access_log(state.as_ref(), &mut access_log, &response).await;
  record_request_observability(
    &state,
    &access_log,
    &response,
    trace_context,
    telemetry_start,
  );
  response
}

pub(crate) fn with_final_response_bandwidth(
  response: Response<ProxyBody>,
  limiter: Arc<RouteBandwidthLimiter>,
  metrics: Arc<crate::metrics::Metrics>,
  transport_network: WafTransportNetwork,
) -> Response<ProxyBody> {
  let backpressure_timeout = (transport_network == WafTransportNetwork::Tcp)
    .then(|| downstream_response_send_timeout(&response))
    .flatten();
  let (mut parts, response_body) = response.into_parts();
  let response_body = if let Some(inlined) = parts
    .extensions
    .remove::<body::InlinedKnownSmallResponseBody>()
  {
    let (data, trailers) = inlined.into_parts();
    body::materialized_known_small_body(data, trailers)
  } else {
    response_body
  };
  parts.extensions.remove::<body::KnownSmallResponseBody>();
  parts
    .extensions
    .remove::<body::CompiledKnownSmallNoopResponse>();
  Response::from_parts(
    parts,
    body::with_bandwidth(
      response_body,
      limiter,
      BandwidthDirection::Download,
      metrics,
      crate::metrics::BandwidthTrafficClass::Http,
      backpressure_timeout,
    ),
  )
}

pub(crate) fn with_final_tcp_response_bandwidth(
  response: Response<ProxyBody>,
  limiter: Arc<RouteBandwidthLimiter>,
  metrics: Arc<crate::metrics::Metrics>,
) -> Response<ProxyBody> {
  with_final_response_bandwidth(response, limiter, metrics, WafTransportNetwork::Tcp)
}

#[cfg(test)]
mod tests {
  use http_body_util::BodyExt;

  use super::*;
  use crate::bandwidth::BandwidthPolicy;

  #[tokio::test]
  async fn final_response_bandwidth_materializes_inlined_h3_body() {
    let placeholder = http_body_util::Empty::<bytes::Bytes>::new()
      .map_err(|never| -> body::BoxError { match never {} })
      .boxed();
    let mut response = Response::new(placeholder);
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-upstream-trailer", "kept".parse().unwrap());
    response
      .extensions_mut()
      .insert(body::KnownSmallResponseBody);
    response
      .extensions_mut()
      .insert(body::CompiledKnownSmallNoopResponse);
    response
      .extensions_mut()
      .insert(body::InlinedKnownSmallResponseBody::new(
        bytes::Bytes::from_static(b"proxied body"),
        Some(trailers),
      ));

    let response = with_final_response_bandwidth(
      response,
      RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED),
      crate::metrics::Metrics::new(),
      WafTransportNetwork::Udp,
    );

    assert!(
      response
        .extensions()
        .get::<body::KnownSmallResponseBody>()
        .is_none()
    );
    assert!(
      response
        .extensions()
        .get::<body::CompiledKnownSmallNoopResponse>()
        .is_none()
    );
    assert!(
      response
        .extensions()
        .get::<body::InlinedKnownSmallResponseBody>()
        .is_none()
    );
    let collected = response
      .into_body()
      .collect()
      .await
      .expect("bandwidth-shaped response should collect");
    assert_eq!(
      collected
        .trailers()
        .expect("inlined response trailers should survive bandwidth shaping")["x-upstream-trailer"],
      "kept"
    );
    assert_eq!(collected.to_bytes().as_ref(), b"proxied body");
  }
}
