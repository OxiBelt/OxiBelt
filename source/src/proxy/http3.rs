//! HTTP/3 downstream and upstream handling.
//! QUIC session state stays explicit because stream lifetimes differ from TCP request lifetimes.

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use ::http::{Method, Request, Response, StatusCode};
use anyhow::Context;
use bytes::Bytes;
use h3::ext::Protocol;
use http_body_util::BodyExt;
use tokio::task::JoinHandle;

use crate::config::{ConnectionLimitIdentityMode, UpstreamConfig};
use crate::lifecycle::ConnectionDrain;
use crate::limits::ConnectionLimitContext;
use crate::proxy::http as http_proxy;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::fast_path::stage_timing as timing;
use crate::proxy::http::response::{is_silent_close_response, text_response};
use crate::proxy_protocol_egress::tls::{
  ConnectionTlsEvidence, local_capture_needed, local_certificate_capture_needed,
};
use crate::routes::{RouteMatchContext, RouteRequestProtocol};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::AppSnapshot;
use crate::waf::WafProtocol;

type H3BidiStream = crate::quic::h3::BidiStream<Bytes>;
type H3RequestStream = h3::server::RequestStream<H3BidiStream, Bytes>;
type H3RequestSendStream =
  h3::server::RequestStream<<H3BidiStream as h3::quic::BidiStream<Bytes>>::SendStream, Bytes>;
type H3RequestRecvStream =
  h3::server::RequestStream<<H3BidiStream as h3::quic::BidiStream<Bytes>>::RecvStream, Bytes>;
type H3ServerConnection = h3::server::Connection<crate::quic::h3::Connection, Bytes>;
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
const H3_MAX_FIELD_SECTION_SIZE: u64 = (1_u64 << 62) - 1;

mod fast_response;
mod request_body;
mod request_tasks;
mod response_body;
#[cfg(test)]
mod tests;
mod tls_metadata;
mod upstream_connection;
mod upstream_endpoints;
mod upstream_pool;
mod webtransport_bridge;

use tls_metadata::{downstream_quic_forwarded_client_certificate, downstream_quic_tls_metadata};
pub(crate) use upstream_connection::{
  UpstreamWebTransportConnectionGuard, connect_upstream_webtransport, forward_request,
};
pub(crate) use upstream_pool::UpstreamH3Pools;
pub(crate) use webtransport_bridge::{
  UpstreamWebTransportRecvStream, UpstreamWebTransportSendStream, UpstreamWebTransportSession,
  WebTransportSessionPermits, acquire_webtransport_session_permits,
};

#[cfg(test)]
use crate::proxy::http::body::{InlinedKnownSmallResponseBody, KNOWN_SMALL_BODY_MAX_BYTES};
#[cfg(test)]
use fast_response::{
  H3KnownSmallBodyPlan, collect_h3_known_small_body, take_h3_known_small_body_plan,
  use_h3_known_small_body_path,
};

#[derive(Clone)]
pub(super) struct H3DownstreamRequestContext {
  peer_addr: SocketAddr,
  udp_connection_id: Arc<str>,
  tls_metadata: Arc<crate::waf::WafTlsMetadata>,
  proxy_tls_evidence: Option<ConnectionTlsEvidence>,
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  drain: ConnectionDrain,
}

pub(crate) async fn handle_downstream_connection(
  connection: h3_quinn::quinn::Connection,
  listener_bind: SocketAddr,
  snapshot: Arc<AppSnapshot>,
  mut shutdown: tokio::sync::watch::Receiver<bool>,
  mut data_plane_drain: tokio::sync::watch::Receiver<bool>,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let peer_addr = connection.remote_address();
  let udp_connection_id: Arc<str> = format!("quinn-stable:{}", connection.stable_id()).into();
  let _global_permit = snapshot
    .limits
    .acquire_global_connection_async(&snapshot.config.limits)
    .await
    .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))?;
  let _http3_connection_guard =
    snapshot.runtime_introspection_guard(RuntimeCounter::Http3Connection);
  let connection_limit_identity = snapshot.config.limits.connection_limit_identity;
  let _ip_permit = if connection_limit_identity == ConnectionLimitIdentityMode::ProxyProtocol {
    Some(
      snapshot
        .limits
        .acquire_ip_connection_async(
          peer_addr.ip(),
          &snapshot.config.limits,
          &snapshot.config.connection_limits,
        )
        .await
        .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))?,
    )
  } else {
    None
  };
  let connection_limit_context = (connection_limit_identity
    == ConnectionLimitIdentityMode::FirstRequestRealIp)
    .then(ConnectionLimitContext::default);
  let max_webtransport_sessions_per_connection = snapshot
    .config
    .limits
    .max_webtransport_sessions_per_connection;
  let max_field_section_size = h3_field_section_size(snapshot.config.limits.max_total_header_bytes);
  let tls_metadata = Arc::new(downstream_quic_tls_metadata(&connection));
  let proxy_tls_evidence = downstream_proxy_tls_evidence(&connection, listener_bind, &snapshot);
  // The connection pins this snapshot; do not capture certificate DER when no route in it can use it.
  let forwarded_client_certificate = (!snapshot.client_certificate_forwarding_headers.is_empty())
    .then(|| downstream_quic_forwarded_client_certificate(&connection))
    .flatten();
  let early_data = crate::quic::h3::EarlyDataTracker::default();
  let downstream_connection = connection.clone();
  let quic_connection = crate::quic::h3::Connection::new(connection, early_data.clone());
  let mut request_admission = request_tasks::RequestAdmission::new(&snapshot.config);
  let mut request_tasks = request_tasks::RequestTaskSet::new(&snapshot.config);
  let graceful_timeout = Duration::from_millis(snapshot.config.runtime.drain.graceful_timeout_ms);
  let mut lifecycle_drain = drain.clone();
  let metric_protocol = timing::protocol(::http::Version::HTTP_3);
  let timing_enabled = snapshot.request_path_features.stage_timing_metrics;
  let request_task_timing = request_tasks::RequestTaskTiming::new(snapshot.clone(), timing_enabled);
  let downstream_request_context = H3DownstreamRequestContext {
    peer_addr,
    udp_connection_id: udp_connection_id.clone(),
    tls_metadata: tls_metadata.clone(),
    proxy_tls_evidence: proxy_tls_evidence.clone(),
    connection_limit_context: connection_limit_context.clone(),
    state: snapshot.clone(),
    drain: drain.clone(),
  };
  let mut h3_connection = h3::server::builder()
    // This applies to every H3 field section, including trailers decoded after
    // request admission. Keep it aligned with the configured HTTP header cap.
    .max_field_section_size(max_field_section_size)
    .enable_extended_connect(true)
    .enable_datagram(true)
    .enable_webtransport(true)
    .max_webtransport_sessions(max_webtransport_sessions_per_connection as u64)
    .build(quic_connection)
    .await
    .context("failed to establish downstream HTTP/3 connection")?;

  loop {
    let reap_started = timing::start(timing_enabled);
    request_tasks.reap_completed();
    if timing_enabled {
      timing::record(
        snapshot.as_ref(),
        timing::PATH_H3_DOWNSTREAM,
        metric_protocol,
        timing::STAGE_H3_REQUEST_TASK_REAP,
        timing::OUTCOME_OK,
        reap_started,
      );
    }
    if *shutdown.borrow() || *data_plane_drain.borrow() {
      return graceful_h3_shutdown(
        &mut h3_connection,
        &downstream_connection,
        &mut request_tasks,
        graceful_timeout,
      )
      .await;
    }
    if lifecycle_drain.has_lifecycle_drain_transition() {
      return graceful_h3_shutdown(
        &mut h3_connection,
        &downstream_connection,
        &mut request_tasks,
        graceful_timeout,
      )
      .await;
    }
    let receive_started = timing::start(timing_enabled);
    let resolver = tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          return graceful_h3_shutdown(
            &mut h3_connection,
            &downstream_connection,
            &mut request_tasks,
            graceful_timeout,
          )
          .await;
        }
        continue;
      }
      changed = data_plane_drain.changed() => {
        if changed.is_ok() && *data_plane_drain.borrow() {
          return graceful_h3_shutdown(
            &mut h3_connection,
            &downstream_connection,
            &mut request_tasks,
            graceful_timeout,
          )
          .await;
        }
        continue;
      }
      _ = lifecycle_drain.wait_for_lifecycle_drain_transition() => {
        return graceful_h3_shutdown(
          &mut h3_connection,
          &downstream_connection,
          &mut request_tasks,
          graceful_timeout,
        )
        .await;
      }
      accepted = h3_connection.accept() => {
        match accepted {
          Ok(resolver) => resolver,
          Err(error) if downstream_h3_accept_closed_normally(&error) => {
            request_tasks.wait_all().await;
            return Ok(());
          }
          Err(error) => {
            request_tasks.abort_all().await;
            return Err(error).context("failed to accept downstream HTTP/3 request");
          }
        }
      }
    };
    let Some(resolver) = resolver else {
      request_tasks.wait_all().await;
      return Ok(());
    };

    let (mut request, stream) = match resolver.resolve_request().await {
      Ok(resolved) => {
        if timing_enabled {
          timing::record(
            snapshot.as_ref(),
            timing::PATH_H3_DOWNSTREAM,
            metric_protocol,
            timing::STAGE_DOWNSTREAM_PROTOCOL_RECEIVE,
            timing::OUTCOME_OK,
            receive_started,
          );
        }
        resolved
      }
      Err(error) => {
        if timing_enabled {
          timing::record(
            snapshot.as_ref(),
            timing::PATH_H3_DOWNSTREAM,
            metric_protocol,
            timing::STAGE_DOWNSTREAM_PROTOCOL_RECEIVE,
            timing::OUTCOME_ERROR,
            receive_started,
          );
        }
        request_tasks.abort_all().await;
        return Err(error).context("failed to resolve downstream HTTP/3 request");
      }
    };
    let is_early_data = early_data.take(stream.id());
    if is_early_data {
      http_proxy::early_data::mark_verified(&mut request);
    }
    http_proxy::early_data::strip_untrusted_header(request.headers_mut());
    if let Some(certificate) = &forwarded_client_certificate {
      request.extensions_mut().insert(certificate.clone());
    }

    if is_webtransport_request(&request) {
      let _overload_request = match snapshot.overload.try_admit_request(::http::Version::HTTP_3) {
        Ok(lease) => lease,
        Err(_) => {
          let mut response = text_response(snapshot.overload.response_status(), "overloaded");
          if let Ok(value) =
            ::http::HeaderValue::from_str(&snapshot.overload.retry_after_seconds().to_string())
          {
            response
              .headers_mut()
              .insert(::http::header::RETRY_AFTER, value);
          }
          let response =
            http_proxy::status_headers::finalize(response, &snapshot.config.proxy.status_headers);
          respond_to_h3_request(stream, response).await?;
          continue;
        }
      };
      if let Some(verifier) = snapshot.web_bot_auth.as_ref() {
        let result = verifier
          .verify(&request, "https", &snapshot.config.web_bot_auth, false)
          .await;
        snapshot.metrics.record_web_bot_auth(result.status);
        request.extensions_mut().insert(result);
      }
      request_tasks.wait_all().await;
      webtransport_bridge::serve_webtransport_connection(
        h3_connection,
        request,
        stream,
        peer_addr,
        udp_connection_id.clone(),
        tls_metadata,
        proxy_tls_evidence,
        forwarded_client_certificate,
        connection_limit_context.clone(),
        snapshot,
        early_data.clone(),
        shutdown,
        drain.clone(),
        request_admission,
      )
      .await?;
      return Ok(());
    }

    if !request_admission.try_admit() {
      // This response is emitted before the shared HTTP request entrypoint.
      // Capture the original H3 negotiation here so admission rejection has
      // the same digest behavior as an ordinary data-plane response.
      let response = http_proxy::status_headers::finalize(
        request_tasks::too_many_requests_response(),
        &snapshot.config.proxy.status_headers,
      );
      let response = if http_proxy::integrity_digest::DigestRequest::requested(request.headers()) {
        let digest_request = http_proxy::integrity_digest::DigestRequest::new(
          request.method(),
          request.version(),
          request.headers(),
          snapshot.config.proxy.http.trailers,
        );
        http_proxy::integrity_digest::finalize(response, &digest_request)
      } else {
        response
      };
      respond_to_h3_request(stream, response).await?;
      continue;
    }

    let permit_started = timing::start(timing_enabled);
    let request_task_permit = if let Some(permit) = request_tasks.try_acquire_permit() {
      permit
    } else {
      match request_tasks::acquire_permit_or_stop(
        &mut request_tasks,
        &mut shutdown,
        &mut data_plane_drain,
        Some(&request_task_timing),
      )
      .await
      {
        Ok(Some(permit)) => permit,
        Ok(None) => {
          return graceful_h3_shutdown(
            &mut h3_connection,
            &downstream_connection,
            &mut request_tasks,
            graceful_timeout,
          )
          .await;
        }
        Err(error) => {
          if timing_enabled {
            timing::record(
              snapshot.as_ref(),
              timing::PATH_H3_DOWNSTREAM,
              metric_protocol,
              timing::STAGE_H3_REQUEST_PERMIT_ACQUIRE,
              timing::OUTCOME_ERROR,
              permit_started,
            );
          }
          return Err(error);
        }
      }
    };
    if timing_enabled {
      timing::record(
        snapshot.as_ref(),
        timing::PATH_H3_DOWNSTREAM,
        metric_protocol,
        timing::STAGE_H3_REQUEST_PERMIT_ACQUIRE,
        timing::OUTCOME_OK,
        permit_started,
      );
    }

    if h3_inline_fast_path_candidate(&request, &downstream_request_context) {
      let (send_stream, recv_stream) = stream.split();
      let ingress_started = timing::start(timing_enabled);
      let prepared =
        request_body::prepare_h3_request_body_with_verification(request, recv_stream).await;
      timing::record(
        snapshot.as_ref(),
        timing::PATH_H3_DOWNSTREAM,
        metric_protocol,
        timing::STAGE_H3_INGRESS_PREPARE,
        timing::OUTCOME_OK,
        ingress_started,
      );
      let inline_ready = prepared.verified_empty
        && prepared.inline_readiness == request_body::PreparedH3RequestBodyReadiness::InlineReady;
      debug_assert!(
        prepared.inline_readiness != request_body::PreparedH3RequestBodyReadiness::InlineReady
          || prepared.verified_empty,
        "the HTTP/3 inline path requires a fully verified empty request body"
      );
      let inline_spawn_started = timing::start(timing_enabled);
      if !inline_ready {
        request_tasks.spawn_prepared(
          prepared.request,
          send_stream,
          downstream_request_context.clone(),
          request_task_permit,
        );
        if timing_enabled {
          timing::record(
            snapshot.as_ref(),
            timing::PATH_H3_DOWNSTREAM,
            metric_protocol,
            timing::STAGE_H3_REQUEST_TASK_SPAWN,
            timing::OUTCOME_OK,
            inline_spawn_started,
          );
        }
        continue;
      }
      if timing_enabled {
        timing::record(
          snapshot.as_ref(),
          timing::PATH_H3_DOWNSTREAM,
          metric_protocol,
          timing::STAGE_H3_REQUEST_TASK_SPAWN,
          timing::OUTCOME_FALLBACK,
          inline_spawn_started,
        );
      }
      let inline = request_tasks::handle_inline_prepared(
        prepared.request,
        send_stream,
        downstream_request_context.clone(),
        request_task_permit,
      );
      if !run_h3_inline_until_blocked_or_stop(
        inline,
        &mut request_tasks,
        &mut shutdown,
        &mut data_plane_drain,
      )
      .await
      {
        return graceful_h3_shutdown(
          &mut h3_connection,
          &downstream_connection,
          &mut request_tasks,
          graceful_timeout,
        )
        .await;
      }
      continue;
    }

    let spawn_started = timing::start(timing_enabled);
    request_tasks.spawn(
      request,
      stream,
      downstream_request_context.clone(),
      request_task_permit,
    );
    if timing_enabled {
      timing::record(
        snapshot.as_ref(),
        timing::PATH_H3_DOWNSTREAM,
        metric_protocol,
        timing::STAGE_H3_REQUEST_TASK_SPAWN,
        timing::OUTCOME_OK,
        spawn_started,
      );
    }
  }
}

async fn graceful_h3_shutdown(
  h3_connection: &mut H3ServerConnection,
  downstream_connection: &h3_quinn::quinn::Connection,
  request_tasks: &mut request_tasks::RequestTaskSet,
  graceful_timeout: Duration,
) -> anyhow::Result<()> {
  let deadline = tokio::time::Instant::now() + graceful_timeout;
  match tokio::time::timeout_at(deadline, h3_connection.shutdown(0)).await {
    Ok(result) => result.context("failed to send HTTP/3 graceful shutdown")?,
    Err(_) => {
      request_tasks.abort_all().await;
      return Ok(());
    }
  }
  wait_for_h3_request_tasks(request_tasks, deadline).await;
  wait_for_h3_transport_close(downstream_connection.closed(), deadline).await;
  Ok(())
}

async fn wait_for_h3_transport_close<F, T>(closed: F, deadline: tokio::time::Instant)
where
  F: Future<Output = T>,
{
  let _ = tokio::time::timeout_at(deadline, closed).await;
}

async fn wait_for_h3_request_tasks(
  request_tasks: &mut request_tasks::RequestTaskSet,
  deadline: tokio::time::Instant,
) {
  if tokio::time::timeout_at(deadline, request_tasks.wait_all())
    .await
    .is_err()
  {
    request_tasks.abort_all().await;
  }
}

async fn run_h3_inline_until_blocked_or_stop<F>(
  inline: F,
  request_tasks: &mut request_tasks::RequestTaskSet,
  shutdown: &mut tokio::sync::watch::Receiver<bool>,
  data_plane_drain: &mut tokio::sync::watch::Receiver<bool>,
) -> bool
where
  F: Future<Output = ()> + Send + 'static,
{
  let mut inline = Box::pin(inline);
  enum InlinePollOutcome {
    Complete,
    Blocked,
    Stop,
  }

  let outcome = tokio::select! {
    biased;
    changed = shutdown.changed() => {
      if changed.is_ok() && *shutdown.borrow() {
        InlinePollOutcome::Stop
      } else {
        InlinePollOutcome::Blocked
      }
    }
    changed = data_plane_drain.changed() => {
      if changed.is_ok() && *data_plane_drain.borrow() {
        InlinePollOutcome::Stop
      } else {
        InlinePollOutcome::Blocked
      }
    }
    completed_inline = poll_fn(|cx| {
      match inline.as_mut().poll(cx) {
        Poll::Ready(()) => Poll::Ready(true),
        Poll::Pending => Poll::Ready(false),
      }
    }) => {
      if completed_inline {
        InlinePollOutcome::Complete
      } else {
        InlinePollOutcome::Blocked
      }
    }
  };
  match outcome {
    InlinePollOutcome::Complete => true,
    InlinePollOutcome::Blocked => {
      request_tasks.spawn_inline_future(inline);
      true
    }
    InlinePollOutcome::Stop => false,
  }
}

fn h3_field_section_size(max_total_header_bytes: usize) -> u64 {
  (max_total_header_bytes as u64).min(H3_MAX_FIELD_SECTION_SIZE)
}

fn h3_inline_fast_path_candidate(
  request: &Request<()>,
  context: &H3DownstreamRequestContext,
) -> bool {
  if context.state.config.web_bot_auth.enabled {
    return false;
  }
  // The H3 inline path does not own the explicit TCP upstream transport. Keep
  // it out of TLS-TLV egress routes until that transport can consume the
  // connection-owned evidence without an extension boundary.
  if context
    .state
    .config
    .upstreams
    .iter()
    .any(|upstream| upstream.proxy_protocol_tls.is_some())
  {
    return false;
  }
  if !context.state.config.proxy.http3.inline_bodyless_fast_path {
    return false;
  }
  if request.version() != ::http::Version::HTTP_3 {
    return false;
  }
  if !http_proxy::request_framing::h2_or_h3_safe_method_empty_probe_allowed(
    request.method(),
    ::http::Version::HTTP_3,
    request.headers(),
  ) {
    return false;
  }
  if http_proxy::headers::validate_authority_host_consistency(request).is_err() {
    return false;
  }
  let path = request.uri().path();
  if http_proxy::validate_request_limits(request, &context.state.config.limits).is_err()
    || http_proxy::uri::validate_downstream_path(path).is_err()
  {
    return false;
  }
  let host_snapshot = http_proxy::headers::extract_host_snapshot(request);
  let host = host_snapshot.as_str();
  let client_addr = match context.state.resolve_client_addr(
    request.headers(),
    context.peer_addr,
    host,
    context
      .tls_metadata
      .sni
      .as_deref()
      .filter(|_| context.tls_metadata.enabled),
  ) {
    Ok(client_addr) => client_addr,
    Err(_) => return false,
  };
  let resolved = context
    .state
    .route_table
    .try_resolve_simple_exact_host(host, path, &context.state.upstreams)
    .or_else(|| {
      context
        .state
        .route_table
        .resolve_normalized_host_with_context(
          host,
          RouteMatchContext {
            path,
            method: Some(request.method()),
            headers: Some(request.headers()),
            query: request.uri().query(),
            source_ip: Some(client_addr.ip()),
            protocol: Some(RouteRequestProtocol::from_http(
              ::http::Version::HTTP_3,
              WafProtocol::Http,
            )),
            tls: Some(context.tls_metadata.as_ref()),
          },
          &context.state.upstreams,
        )
    });
  let Some(resolved) = resolved else {
    return false;
  };
  http_proxy::fast_path::plain_proxy_fast_path_decision(request, context.state.as_ref(), &resolved)
    .is_ok()
}

fn downstream_proxy_tls_evidence(
  connection: &h3_quinn::quinn::Connection,
  listener_bind: SocketAddr,
  snapshot: &AppSnapshot,
) -> Option<ConnectionTlsEvidence> {
  if !local_capture_needed(&snapshot.config) {
    return None;
  }
  let mut evidence = ConnectionTlsEvidence::default();
  let destination = connection
    .local_ip()
    .or_else(|| (!listener_bind.ip().is_unspecified()).then_some(listener_bind.ip()));
  let Some(destination) = destination.map(|ip| SocketAddr::new(ip, listener_bind.port())) else {
    evidence.local_capture_failed = true;
    return Some(evidence);
  };
  let certificates = connection.peer_identity().and_then(|identity| {
    identity
      .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
      .ok()
  });
  let certificates = certificates
    .as_deref()
    .map(Vec::as_slice)
    .unwrap_or_default();
  match crate::tls::proxy_protocol_metadata::capture_authenticated_session(
    connection.remote_address(),
    destination,
    "TLSv1.3",
    certificates,
    false,
    local_certificate_capture_needed(&snapshot.config),
  ) {
    Ok(local) => evidence.local = Some(local),
    Err(_) => evidence.local_capture_failed = true,
  }
  Some(evidence)
}

async fn handle_h3_request(
  request: Request<()>,
  stream: H3RequestStream,
  context: H3DownstreamRequestContext,
) -> anyhow::Result<StatusCode> {
  let (send_stream, recv_stream) = stream.split();
  let state = context.state.clone();
  let metric_protocol = timing::protocol(::http::Version::HTTP_3);
  let timing_enabled = state.request_path_features.stage_timing_metrics;
  let ingress_started = timing::start(timing_enabled);
  let request = request_body::prepare_h3_request_body(request, recv_stream).await;
  timing::record(
    state.as_ref(),
    timing::PATH_H3_DOWNSTREAM,
    metric_protocol,
    timing::STAGE_H3_INGRESS_PREPARE,
    timing::OUTCOME_OK,
    ingress_started,
  );
  handle_prepared_h3_request(request, send_stream, context).await
}

async fn handle_prepared_h3_request(
  mut request: Request<ProxyBody>,
  mut send_stream: H3RequestSendStream,
  context: H3DownstreamRequestContext,
) -> anyhow::Result<StatusCode> {
  let state = context.state.clone();
  let metric_protocol = timing::protocol(::http::Version::HTTP_3);
  let timing_enabled = state.request_path_features.stage_timing_metrics;
  if let Some(evidence) = &context.proxy_tls_evidence {
    request.extensions_mut().insert(evidence.clone());
  }
  let mut informational = http_proxy::informational::install_h3(request.extensions_mut());
  let response = http_proxy::handle_http3(
    request,
    context.peer_addr,
    context.udp_connection_id.as_ref(),
    context.tls_metadata,
    context.connection_limit_context,
    context.state,
    context.drain,
  );
  tokio::pin!(response);
  let mut informational_closed = false;
  let response = loop {
    tokio::select! {
      response = &mut response => break response,
      interim = informational.recv(), if !informational_closed => {
        match interim {
          Some(interim) => send_stream
            .send_response(interim)
            .await
            .context("failed to send downstream HTTP/3 informational response")?,
          None => informational_closed = true,
        }
      }
    }
  };
  // `select!` may observe the completed final future after an earlier poll of
  // the informational receiver returned Pending. Drain the bounded FIFO once
  // more before committing final HEADERS so same-poll 104 responses retain
  // their required ordering.
  while let Some(interim) = informational.try_recv() {
    send_stream
      .send_response(interim)
      .await
      .context("failed to send downstream HTTP/3 informational response")?;
  }
  if is_silent_close_response(&response) {
    reset_silent_h3_request(send_stream);
    return Ok(StatusCode::NO_CONTENT);
  }
  let status = response.status();
  let send_started = timing::start(timing_enabled);
  let response_timing = timing_enabled.then(|| fast_response::H3ResponseTiming::from_state(&state));
  let send_result =
    fast_response::respond_to_h3_request_with_timing(send_stream, response, response_timing).await;
  timing::record(
    state.as_ref(),
    timing::PATH_H3_DOWNSTREAM,
    metric_protocol,
    timing::STAGE_H3_DOWNSTREAM_SEND,
    if send_result.is_ok() {
      timing::OUTCOME_OK
    } else {
      timing::OUTCOME_ERROR
    },
    send_started,
  );
  send_result?;
  Ok(status)
}

fn reset_silent_h3_request<S>(mut stream: h3::server::RequestStream<S, Bytes>)
where
  S: h3::quic::SendStream<Bytes>,
{
  stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
}

pub(crate) async fn respond_to_h3_request<S>(
  stream: h3::server::RequestStream<S, Bytes>,
  response: Response<ProxyBody>,
) -> anyhow::Result<()>
where
  S: h3::quic::SendStream<Bytes>,
{
  fast_response::respond_to_h3_request(stream, response).await
}

pub(crate) fn is_webtransport_request(request: &Request<()>) -> bool {
  request.method() == Method::CONNECT
    && request
      .extensions()
      .get::<Protocol>()
      .is_some_and(|protocol| protocol == &Protocol::WEB_TRANSPORT)
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn rejects_unsafe_early_data(
  request: &Request<()>,
  zero_rtt: crate::config::QuicZeroRttMode,
  is_early_data: bool,
) -> bool {
  zero_rtt == crate::config::QuicZeroRttMode::SafeMethods
    && is_early_data
    && !matches!(request.method(), &Method::GET | &Method::HEAD)
}

fn downstream_h3_accept_closed_normally(error: &h3::error::ConnectionError) -> bool {
  error.is_h3_no_error() || downstream_h3_accept_message_is_normal_close(&error.to_string())
}

fn downstream_h3_accept_message_is_normal_close(message: &str) -> bool {
  let message = message.to_ascii_lowercase();
  [
    "closed before request headers completed",
    "closed by peer",
    "connection closed",
    "graceful shutdown",
    "h3_no_error",
  ]
  .iter()
  .any(|needle| message.contains(needle))
}

#[cfg(test)]
mod real_ip_tests;
