//! Listener-facing HTTP entrypoints and process-wide request admission.

use std::sync::Arc;

use http::{Request, Version};
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
  transport_metadata: WafTransportMetadataInput<'_>,
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
  transport_metadata: WafTransportMetadataInput<'_>,
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
  // Capture the downstream request before forwarding or request-side policy
  // can change headers. The context also lets compression preserve a source
  // Unencoded-Digest when no new field was negotiated. CONNECT and upgrades
  // leave the HTTP response data plane after their handshake.
  let digest_request =
    (!is_upgrade_request(&request) && request.method() != Method::CONNECT).then(|| {
      integrity_digest::DigestRequest::new(
        request.method(),
        request_version,
        request.headers(),
        state.config.proxy.http.trailers,
      )
    });
  if let Some(digest_request) = digest_request.as_ref() {
    request.extensions_mut().insert(digest_request.clone());
  }
  let incremental_request = incremental::request_marked(&request);
  let downstream_receive_started =
    fast_path::stage_timing::start(state.request_path_features.stage_timing_metrics);
  early_data::strip_untrusted_header(request.headers_mut());
  client_certificate::strip_reserved(request.headers_mut(), &state);
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
      let response = super::status_headers::finalize(response, &state.config.proxy.status_headers);
      let response = if let Some(context) = digest_request.as_ref() {
        integrity_digest::finalize(response, context)
      } else {
        response
      };
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
      let mut response = circuit_breaker_rejection_response(state.as_ref(), rejection);
      incremental::adapt_admission_rejection(&mut response, incremental_request, request_version);
      let response = super::status_headers::finalize(response, &state.config.proxy.status_headers);
      let response = if let Some(context) = digest_request.as_ref() {
        integrity_digest::finalize(response, context)
      } else {
        response
      };
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
  let mut rate_limit_report = super::rate_limit_headers::Report::default();
  let request_is_head = request.method() == Method::HEAD;
  let mut response = handle_inner_impl(
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
    &mut rate_limit_report,
  )
  .await;
  incremental::adapt_admission_rejection(&mut response, incremental_request, request_version);
  // Upstream HTTP versions are useful to exchange/WAF policy, but the final
  // response must describe the protocol of the downstream writer. In
  // particular, Hyper's H1 encoder cannot serialize an HTTP/3 response head.
  let response = super::status_headers::finalize(response, &state.config.proxy.status_headers);
  let response = normalize_downstream_response_version(response, request_version);
  let mut response = if let Some(context) = digest_request.as_ref() {
    integrity_digest::finalize(response, context)
  } else {
    response
  };
  super::rate_limit_headers::apply(&mut response, &rate_limit_report);
  let response = if let Some(limiter) = selected_bandwidth {
    with_final_response_bandwidth(response, limiter, state.metrics.clone(), transport_network)
  } else {
    response
  };
  let response = with_incremental_response_lifetime(response, request_is_head, request_version);
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

fn normalize_downstream_response_version(
  mut response: Response<ProxyBody>,
  downstream_version: Version,
) -> Response<ProxyBody> {
  *response.version_mut() = downstream_version;
  response
}

fn with_incremental_response_lifetime(
  response: Response<ProxyBody>,
  request_is_head: bool,
  request_version: Version,
) -> Response<ProxyBody> {
  // Track completion outside producer channels: producer EOF can precede
  // downstream consumption of queued response frames.
  if let Some(exchange) = response
    .extensions()
    .get::<incremental_exchange::IncrementalExchange>()
    .cloned()
    .filter(|_| {
      response
        .extensions()
        .get::<incremental::LocalTerminalResponse>()
        .is_none()
    })
  {
    let bodyless = request_is_head
      || response.status() == StatusCode::NO_CONTENT
      || response.status() == StatusCode::NOT_MODIFIED;
    let h1_length_framed =
      !bodyless && matches!(request_version, Version::HTTP_10 | Version::HTTP_11);
    let response_headers = response.headers().clone();
    response.map(|body| {
      let body = if bodyless {
        // HTTP/1 may never poll a semantically forbidden body. Finish the
        // downstream half at this final handoff without cancelling its upload.
        // Retain transformed source guards until that upload also terminates.
        exchange.retain(body);
        body::known_small_no_trailers_body(bytes::Bytes::new())
      } else {
        body
      };
      // Match Hyper's H1 dispatcher: it selects an exact body size before
      // header framing, and a supplied Content-Length otherwise. At a known
      // boundary Hyper may drop without polling source EOF.
      let expected_length = h1_length_framed
        .then(|| h1_expected_response_length(&body, &response_headers, request_version))
        .flatten();
      if let Some(length) = expected_length {
        incremental_exchange::wrap_response_body_with_length(body, exchange, Some(length))
      } else {
        incremental_exchange::wrap_response_body(body, exchange)
      }
    })
  } else {
    response
  }
}

fn h1_expected_response_length(
  body: &ProxyBody,
  headers: &http::HeaderMap,
  version: Version,
) -> Option<u64> {
  if version == Version::HTTP_11 && headers.contains_key(http::header::TRANSFER_ENCODING) {
    None
  } else {
    body
      .size_hint()
      .exact()
      .or_else(|| h1_header_content_length(headers))
  }
}

fn h1_header_content_length(headers: &http::HeaderMap) -> Option<u64> {
  let mut values = headers.get_all(http::header::CONTENT_LENGTH).iter();
  let content_length = h1_content_length_digits(values.next()?.as_bytes())?;
  for value in values {
    if h1_content_length_digits(value.as_bytes())? != content_length {
      return None;
    }
  }
  Some(content_length)
}

fn h1_content_length_digits(bytes: &[u8]) -> Option<u64> {
  if bytes.is_empty() {
    return None;
  }
  bytes.iter().try_fold(0_u64, |length, byte| match byte {
    b'0'..=b'9' => length.checked_mul(10)?.checked_add(u64::from(*byte - b'0')),
    _ => None,
  })
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

  #[test]
  fn final_response_uses_the_downstream_protocol_version() {
    for downstream_version in [
      Version::HTTP_10,
      Version::HTTP_11,
      Version::HTTP_2,
      Version::HTTP_3,
    ] {
      let mut response = Response::new(body::known_small_no_trailers_body(bytes::Bytes::new()));
      *response.version_mut() = Version::HTTP_3;
      assert_eq!(
        normalize_downstream_response_version(response, downstream_version).version(),
        downstream_version
      );
    }
  }

  #[test]
  fn final_response_normalizes_upgrade_heads_for_h1() {
    let mut response = Response::new(body::known_small_no_trailers_body(bytes::Bytes::new()));
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *response.version_mut() = Version::HTTP_3;
    let response = normalize_downstream_response_version(response, Version::HTTP_11);
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(response.version(), Version::HTTP_11);
  }

  #[test]
  fn h1_final_handoff_boundary_matches_hyper_length_selection() {
    let no_headers = http::HeaderMap::new();
    let exact_body = body::known_small_no_trailers_body(bytes::Bytes::from_static(b"exact"));
    assert_eq!(
      h1_expected_response_length(&exact_body, &no_headers, Version::HTTP_11),
      Some(5),
      "Hyper uses the final body's exact size even without Content-Length"
    );

    let (_, unknown_body) = body::channel_body(1);
    let mut trailer_headers = http::HeaderMap::new();
    trailer_headers.insert(http::header::CONTENT_LENGTH, "3".parse().unwrap());
    trailer_headers.insert(http::header::TRAILER, "x-upstream-trailer".parse().unwrap());
    assert_eq!(unknown_body.size_hint().exact(), None);
    assert_eq!(
      h1_expected_response_length(&unknown_body, &trailer_headers, Version::HTTP_11),
      Some(3)
    );

    let mut duplicate_headers = http::HeaderMap::new();
    duplicate_headers.append(http::header::CONTENT_LENGTH, "7".parse().unwrap());
    duplicate_headers.append(http::header::CONTENT_LENGTH, "7".parse().unwrap());
    assert_eq!(
      h1_expected_response_length(&unknown_body, &duplicate_headers, Version::HTTP_11),
      Some(7)
    );

    let mut chunked_headers = http::HeaderMap::new();
    chunked_headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    assert_eq!(
      h1_expected_response_length(&exact_body, &chunked_headers, Version::HTTP_11),
      None
    );
    assert_eq!(
      h1_expected_response_length(&exact_body, &chunked_headers, Version::HTTP_10),
      Some(5),
      "Hyper ignores Transfer-Encoding for HTTP/1.0"
    );
  }

  #[tokio::test]
  async fn incremental_bodyless_handoff_keeps_upload_and_source_guards_alive() {
    for (status, request_is_head) in [
      (StatusCode::NO_CONTENT, false),
      (StatusCode::NOT_MODIFIED, false),
      (StatusCode::OK, true),
    ] {
      let exchange = incremental_exchange::IncrementalExchange::new();
      let (source_tx, source_body) = body::channel_body(1);
      let source = body::with_bandwidth(
        source_body,
        RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED),
        BandwidthDirection::Download,
        crate::metrics::Metrics::new(),
        crate::metrics::BandwidthTrafficClass::Http,
        None,
      );
      let mut response = Response::new(source);
      *response.status_mut() = status;
      response.extensions_mut().insert(exchange.clone());
      let response =
        with_incremental_response_lifetime(response, request_is_head, Version::HTTP_11);
      assert!(response.body().is_end_stream());
      drop(response); // Hyper H1 is allowed to suppress body polling entirely.
      assert!(!exchange.is_cancelled());
      assert!(!exchange.is_complete());
      assert!(!source_tx.is_closed());
      exchange.mark_upload_complete();
      assert!(exchange.is_complete());
      tokio::time::timeout(std::time::Duration::from_secs(1), source_tx.closed())
        .await
        .unwrap();
    }
  }

  #[tokio::test]
  async fn incremental_completion_waits_for_final_bandwidth_channel() {
    struct SourceDropped(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for SourceDropped {
      fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
          let _ = sender.send(());
        }
      }
    }
    let exchange = incremental_exchange::IncrementalExchange::new();
    exchange.mark_upload_complete();
    let (dropped, source_done) = tokio::sync::oneshot::channel();
    let source = body::with_drop_guard(
      body::known_small_no_trailers_body(bytes::Bytes::from_static(b"queued")),
      SourceDropped(Some(dropped)),
    );
    let mut response = Response::new(source);
    response.extensions_mut().insert(exchange.clone());
    let response = with_incremental_response_lifetime(
      with_final_response_bandwidth(
        response,
        RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED),
        crate::metrics::Metrics::new(),
        WafTransportNetwork::Tcp,
      ),
      false,
      Version::HTTP_11,
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), source_done)
      .await
      .unwrap()
      .unwrap();
    assert!(
      !exchange.is_complete(),
      "queued data still belongs to the exchange"
    );
    assert_eq!(
      response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .as_ref(),
      b"queued"
    );
    assert!(exchange.is_complete());
  }

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
