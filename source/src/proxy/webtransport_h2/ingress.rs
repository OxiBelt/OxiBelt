//! Public HTTP/2 WebTransport CONNECT admission.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ::http as http_types;
use bytes::Bytes;
use http_types::{HeaderValue, Request, Response, StatusCode};
#[cfg(feature = "admin-runtime")]
use tokio::sync::mpsc;

use super::bridge;
use crate::lifecycle::ConnectionDrain;
use crate::limits::ConnectionLimitContext;
use crate::proxy::http::{self, body::ProxyBody, response::text_response};
use crate::proxy::http3::{self, UpstreamWebTransportSession};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::AppSnapshot;

struct SessionCount(Arc<AtomicUsize>);
impl Drop for SessionCount {
  fn drop(&mut self) {
    self.0.fetch_sub(1, Ordering::AcqRel);
  }
}

/// H2 WebTransport is identified by the typed extended-CONNECT protocol rather
/// than a user-controlled header spelling.
pub(crate) fn is_webtransport_request<B>(request: &Request<B>) -> bool {
  request.method() == http_types::Method::CONNECT
    && request
      .extensions()
      .get::<hyper::ext::Protocol>()
      .is_some_and(|protocol| protocol.as_str() == "webtransport")
}

/// SETTINGS sent only on TLS 1.3 HTTP/2 connections. All credit begins at zero,
/// so a later configuration reload cannot leave new sessions on an old
/// connection committed to a larger stream buffer than their reservation.
pub(crate) fn server_settings() -> hyper::ext::WebTransportSettings {
  hyper::ext::WebTransportSettings {
    enabled: true,
    initial_max_data: Some(0),
    initial_max_stream_data_uni: Some(0),
    initial_max_stream_data_bidi_local: Some(0),
    initial_max_stream_data_bidi_remote: Some(0),
    initial_max_streams_uni: Some(0),
    initial_max_streams_bidi: Some(0),
  }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_request(
  mut request: Request<hyper::body::Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  transport_metadata: crate::waf::WafTransportMetadataInput<'_>,
  tls: Arc<crate::waf::WafTlsMetadata>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  tls13: bool,
  drain: ConnectionDrain,
  sessions: Arc<AtomicUsize>,
) -> Response<ProxyBody> {
  if !tls13 {
    return text_response(
      StatusCode::MISDIRECTED_REQUEST,
      "WebTransport over HTTP/2 requires TLS 1.3",
    );
  }
  if let Err(error) = crate::webtransport::handshake::validate_request(&request) {
    return text_response(
      StatusCode::BAD_REQUEST,
      &format!("invalid WebTransport CONNECT: {error}"),
    );
  }
  if drain.is_draining() {
    return text_response(StatusCode::SERVICE_UNAVAILABLE, "draining");
  }
  if let Some(verifier) = state.web_bot_auth.as_ref() {
    let result = verifier
      .verify(&request, "https", &state.config.web_bot_auth, false)
      .await;
    state.metrics.record_web_bot_auth(result.status);
    request.extensions_mut().insert(result);
  }
  let on_session = hyper::ext::on_webtransport(&mut request);
  let (parts, _) = request.into_parts();
  let request = Request::from_parts(parts, ());
  let mut prepared = match http::prepare_webtransport(
    &request,
    peer_addr,
    tcp_max_hop,
    transport_metadata,
    tls.as_ref(),
    state.as_ref(),
  )
  .await
  {
    Ok(prepared) => prepared,
    Err(response) => return prepared_error(*response, &state),
  };
  #[cfg(feature = "admin-runtime")]
  let registration = crate::webtransport_admin::WebTransportSessionRegistration {
    route: prepared.route_name.clone(),
    upstream: prepared.upstream.name.clone(),
    peer_ip: peer_addr.ip(),
    client_ip: prepared.client_addr.ip(),
  };
  #[cfg(feature = "admin-runtime")]
  if state.webtransport_admin.is_draining(&registration) {
    return prepared_response_error(
      text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "WebTransport session is draining",
      ),
      &prepared,
      state.as_ref(),
    );
  }
  let mut options = crate::webtransport::SessionOptions::proxy(
    state.config.proxy.http2.webtransport,
    crate::webtransport::Role::Server,
  );
  options.peer_stream_limits =
    match crate::webtransport::handshake::peer_stream_limits(request.headers()) {
      Ok(limits) => limits,
      Err(_) => {
        return prepared_response_error(
          text_response(StatusCode::BAD_REQUEST, "invalid WebTransport-Init header"),
          &prepared,
          state.as_ref(),
        );
      }
    };
  let reservation =
    match crate::webtransport::Session::reserve(options, state.webtransport_h2_budget.clone()) {
      Ok(reservation) => reservation,
      Err(_) => {
        return prepared_response_error(
          text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "WebTransport buffer capacity exhausted",
          ),
          &prepared,
          state.as_ref(),
        );
      }
    };
  let permits = match http3::acquire_webtransport_session_permits(
    prepared.client_addr.ip(),
    connection_limit_context.as_ref(),
    state.as_ref(),
  )
  .await
  {
    Ok(permits) => permits,
    Err(status) => {
      return prepared_response_error(
        text_response(status, "connection limit exceeded"),
        &prepared,
        state.as_ref(),
      );
    }
  };
  let previous = sessions.fetch_add(1, Ordering::AcqRel);
  if previous >= state.config.limits.max_webtransport_sessions_per_connection {
    sessions.fetch_sub(1, Ordering::AcqRel);
    return prepared_response_error(
      text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "too many active WebTransport sessions",
      ),
      &prepared,
      state.as_ref(),
    );
  }
  let session_count = SessionCount(sessions.clone());
  let (upstream, upstream_guard, upstream_certificate) =
    match http3::connect_upstream_webtransport(&prepared, state.as_ref()).await {
      Ok(value) => value,
      Err(error) => {
        return prepared_response_error(
          http::status_headers::transport_error(
            text_response(
              StatusCode::BAD_GATEWAY,
              "upstream WebTransport CONNECT failed",
            ),
            error.as_ref(),
          ),
          &prepared,
          state.as_ref(),
        );
      }
    };
  let stream_waf = prepared
    .stream_waf
    .take()
    .map(|context| context.with_upstream_certificate(upstream_certificate));
  let stream_waf_state = stream_waf.as_ref().map(|_| state.clone());
  let route_name = prepared.route_name.clone();
  let upstream_name = prepared.upstream.name.clone();
  let time_started = crate::telemetry::TelemetryRuntime::start();
  state.metrics.record_webtransport_session_start(
    &state.config.metrics,
    &route_name,
    &upstream_name,
  );
  let response = accepted_response(&prepared, state.as_ref(), &upstream);
  tokio::spawn(run_after_accept(
    on_session,
    reservation,
    options,
    Arc::new(upstream),
    upstream_guard,
    permits,
    stream_waf_state,
    stream_waf,
    prepared.bandwidth.clone(),
    prepared.timeouts.webtransport_idle,
    state,
    route_name,
    upstream_name,
    time_started,
    drain,
    session_count,
    #[cfg(feature = "admin-runtime")]
    registration,
  ));
  response
}

#[allow(clippy::too_many_arguments)]
async fn run_after_accept(
  on_session: hyper::ext::OnWebTransport,
  reservation: crate::webtransport::Reservation,
  options: crate::webtransport::SessionOptions,
  upstream: Arc<UpstreamWebTransportSession>,
  mut upstream_guard: http3::UpstreamWebTransportConnectionGuard,
  _permits: http3::WebTransportSessionPermits,
  stream_waf_state: Option<Arc<AppSnapshot>>,
  stream_waf: Option<crate::proxy::stream_waf::StreamWafRequestContext>,
  bandwidth: Arc<crate::bandwidth::RouteBandwidthLimiter>,
  idle_timeout: std::time::Duration,
  state: Arc<AppSnapshot>,
  route_name: String,
  upstream_name: String,
  started_at: crate::telemetry::TelemetryStart,
  mut drain: ConnectionDrain,
  _session_count: SessionCount,
  #[cfg(feature = "admin-runtime")]
  registration: crate::webtransport_admin::WebTransportSessionRegistration,
) {
  let _guard = state.runtime_introspection_guard(RuntimeCounter::WebTransportSession);
  #[cfg(feature = "admin-runtime")]
  let (command_tx, mut command_rx) = mpsc::unbounded_channel();
  #[cfg(feature = "admin-runtime")]
  let admin_guard = match state.webtransport_admin.register(registration, command_tx) {
    Ok(guard) => guard,
    Err(error) => {
      tracing::warn!(error = %error, "failed to register HTTP/2 WebTransport session");
      upstream.silent_close();
      upstream_guard.finish_http2().await;
      return;
    }
  };
  let carrier = match on_session.await {
    Ok(carrier) => carrier,
    Err(error) => {
      tracing::debug!(error = %error, "HTTP/2 WebTransport CONNECT ended before handoff");
      upstream.silent_close();
      upstream_guard.finish_http2().await;
      return;
    }
  };
  let (downstream, mut actor) =
    match crate::webtransport::Session::start_reserved(carrier, options, reservation) {
      Ok((session, actor)) => (session, actor),
      Err(error) => {
        tracing::warn!(error = %error, "HTTP/2 WebTransport settings rejected after CONNECT");
        upstream.silent_close();
        upstream_guard.finish_http2().await;
        return;
      }
    };
  let session = downstream.clone();
  let activity = bridge::Activity::new();
  let bridge = bridge::run(
    downstream,
    upstream.clone(),
    stream_waf_state,
    stream_waf,
    bandwidth,
    state.metrics.clone(),
    activity.clone(),
  );
  let drain_force = async {
    drain.wait_for_lifecycle_drain_transition().await;
    session.drain();
    upstream.drain();
    tokio::time::sleep(std::time::Duration::from_millis(
      state.config.runtime.drain.graceful_timeout_ms,
    ))
    .await;
  };
  #[cfg(feature = "admin-runtime")]
  let result = tokio::select! {
    result = bridge => result,
    closed = session.closed() => match closed { Ok((code, reason)) => { upstream.close(code, &reason); Ok(()) }, Err(error) => Err(error.into()) },
    closed = upstream.closed() => match closed { Ok((code, reason)) => { session.close(code, &reason); Ok(()) }, Err(error) => Err(error) },
    _ = activity.wait_for_idle(idle_timeout) => { session.close(0, b"WebTransport idle timeout"); upstream.close(0, b"WebTransport idle timeout"); Ok(()) },
    _ = drain_force => {
      session.close(0, b"WebTransport draining"); upstream.close(0, b"WebTransport draining"); Ok(())
    },
    command = command_rx.recv() => {
      if let Some(command) = command { session.close(command.close_code, command.reason.as_bytes()); upstream.close(command.close_code, command.reason.as_bytes()); }
      Ok(())
    },
  };
  #[cfg(not(feature = "admin-runtime"))]
  let result = tokio::select! {
    result = bridge => result,
    closed = session.closed() => match closed { Ok((code, reason)) => { upstream.close(code, &reason); Ok(()) }, Err(error) => Err(error.into()) },
    closed = upstream.closed() => match closed { Ok((code, reason)) => { session.close(code, &reason); Ok(()) }, Err(error) => Err(error) },
    _ = activity.wait_for_idle(idle_timeout) => { session.close(0, b"WebTransport idle timeout"); upstream.close(0, b"WebTransport idle timeout"); Ok(()) },
    _ = drain_force => {
      session.close(0, b"WebTransport draining"); upstream.close(0, b"WebTransport draining"); Ok(())
    },
  };
  #[cfg(feature = "admin-runtime")]
  drop(admin_guard);
  if let Err(error) = result {
    if crate::proxy::stream_waf::blocked_silent_close(&error) {
      session.silent_close();
      upstream.silent_close();
    } else if let Some(close) = crate::proxy::stream_waf::blocked_close(&error) {
      session.close(close.webtransport_code, close.reason.as_bytes());
      upstream.close(close.webtransport_code, close.reason.as_bytes());
    } else {
      session.close(0, b"WebTransport bridge failed");
      upstream.close(0, b"WebTransport bridge failed");
    }
    tracing::debug!(error = %error, "HTTP/2 WebTransport bridge ended");
  }
  if tokio::time::timeout(std::time::Duration::from_secs(1), &mut actor)
    .await
    .is_err()
  {
    actor.abort();
    let _ = actor.await;
  }
  upstream_guard.finish_http2().await;
  state.metrics.record_webtransport_session_end(
    &state.config.metrics,
    &route_name,
    &upstream_name,
    "closed",
    started_at.elapsed_ms(),
  );
}

fn accepted_response(
  prepared: &http::PreparedWebTransport,
  state: &AppSnapshot,
  upstream: &UpstreamWebTransportSession,
) -> Response<ProxyBody> {
  let body = http::body::materialized_known_small_body(Bytes::new(), None);
  let mut response = Response::new(body);
  *response.status_mut() = StatusCode::OK;
  response
    .headers_mut()
    .insert("capsule-protocol", HeaderValue::from_static("?1"));
  http3::append_upstream_response_headers(response.headers_mut(), upstream.response_headers());
  if let Some(protocol) = upstream.selected_protocol()
    && let Ok(serialized) = http3::selected_protocol_header(protocol)
    && let Ok(value) = HeaderValue::from_str(&serialized)
  {
    response.headers_mut().insert("wt-protocol", value);
  }
  crate::proxy::http::client_certificate::finalize_response(
    &mut response,
    prepared.client_certificate_forwarding,
    state,
  );
  http::status_headers::finalize_head(&mut response, &prepared.status_headers);
  // RFC 9297 CONNECT capsules do not carry an HTTP payload body. Route status
  // headers may be configured globally, so remove body framing after those
  // mutations rather than inheriting ordinary HTTP response metadata.
  response
    .headers_mut()
    .remove(http_types::header::CONTENT_LENGTH);
  response
    .headers_mut()
    .remove(http_types::header::CONTENT_TYPE);
  response
    .headers_mut()
    .remove(http_types::header::TRANSFER_ENCODING);
  response
}

fn prepared_error(response: Response<ProxyBody>, state: &AppSnapshot) -> Response<ProxyBody> {
  http::shape_webtransport_response(response, None, state.metrics.clone())
}

fn prepared_response_error(
  response: Response<ProxyBody>,
  prepared: &http::PreparedWebTransport,
  state: &AppSnapshot,
) -> Response<ProxyBody> {
  let mut response = http::shape_webtransport_response(
    response,
    Some(prepared.bandwidth.clone()),
    state.metrics.clone(),
  );
  crate::proxy::http::client_certificate::finalize_response(
    &mut response,
    prepared.client_certificate_forwarding,
    state,
  );
  http::status_headers::finalize(response, &prepared.status_headers)
}
