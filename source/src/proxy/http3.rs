//! HTTP/3 downstream and upstream handling.
//! QUIC session state stays explicit because stream lifetimes differ from TCP request lifetimes.

use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

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
use crate::routes::{RouteMatchContext, RouteRequestProtocol};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::server::downstream_quic_tls_metadata;
use crate::state::AppSnapshot;
use crate::tls;
use crate::waf::WafProtocol;

type H3BidiStream = crate::quic::h3::BidiStream<Bytes>;
type H3RequestStream = h3::server::RequestStream<H3BidiStream, Bytes>;
type H3RequestSendStream =
  h3::server::RequestStream<<H3BidiStream as h3::quic::BidiStream<Bytes>>::SendStream, Bytes>;
type H3RequestRecvStream =
  h3::server::RequestStream<<H3BidiStream as h3::quic::BidiStream<Bytes>>::RecvStream, Bytes>;
type H3ServerConnection = h3::server::Connection<crate::quic::h3::Connection, Bytes>;
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
const H3_POOL_SELECTION_RETRIES: usize = 4;
const H3_MAX_FIELD_SECTION_SIZE: u64 = (1_u64 << 62) - 1;

mod fast_response;
mod request_body;
mod request_tasks;
mod response_body;
#[cfg(test)]
mod tests;
mod upstream_connection;
mod upstream_pool;
mod webtransport_bridge;

pub(crate) use upstream_connection::forward_request;
use upstream_connection::{
  connect_h3_upstream, connect_upstream_webtransport, resolve_upstream_addr, send_h3_request,
};
pub(crate) use upstream_pool::UpstreamH3Pools;

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
  connection_limit_context: Option<ConnectionLimitContext>,
  state: Arc<AppSnapshot>,
  drain: ConnectionDrain,
}

pub(crate) async fn handle_downstream_connection(
  connection: h3_quinn::quinn::Connection,
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
          respond_to_h3_request(stream, response).await?;
          continue;
        }
      };
      request_tasks.wait_all().await;
      webtransport_bridge::serve_webtransport_connection(
        h3_connection,
        request,
        stream,
        peer_addr,
        udp_connection_id.clone(),
        tls_metadata,
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
      respond_to_h3_request(stream, request_tasks::too_many_requests_response()).await?;
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
  let client_addr = match crate::identity::resolve_client_addr(
    request.headers(),
    context.peer_addr,
    &context.state.config.proxy.real_ip,
  ) {
    Ok(client_addr) => client_addr,
    Err(_) => return false,
  };
  let host_snapshot = http_proxy::headers::extract_host_snapshot(request);
  let host = host_snapshot.as_str();
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
  request: Request<ProxyBody>,
  send_stream: H3RequestSendStream,
  context: H3DownstreamRequestContext,
) -> anyhow::Result<StatusCode> {
  let state = context.state.clone();
  let metric_protocol = timing::protocol(::http::Version::HTTP_3);
  let timing_enabled = state.request_path_features.stage_timing_metrics;
  let response = http_proxy::handle_http3(
    request,
    context.peer_addr,
    context.udp_connection_id.as_ref(),
    context.tls_metadata,
    context.connection_limit_context,
    context.state,
    context.drain,
  )
  .await;
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
