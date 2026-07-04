//! Plain HTTP listener fast path.
//! This path parses enough HTTP/1 to enforce configured proxy and WAF policy before forwarding.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ::http::header::{CONNECTION, HOST, TRANSFER_ENCODING, UPGRADE};
use ::http::{Method, StatusCode, Uri};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, trace, warn};

use crate::config::{ConnectionLimitIdentityMode, HttpListenerMode};
use crate::lifecycle::{ConnectionDrain, wait_for_listener_or_data_plane_drain};
use crate::limits::ConnectionLimitContext;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::proxy::http;
use crate::proxy::http::fast_path::stage_timing;
use crate::proxy::http::response::{
  SilentClose, apply_route_security_headers, is_silent_close_response, text_response,
};
use crate::proxy::http::static_files::{
  self, StaticBodyPlan, StaticResponseHeadBytes, StaticResponsePlan,
};
use crate::routes::{RouteMatchContext, RouteRequestProtocol, normalize_host};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::AppSnapshot;
use crate::tcp_hop;
use crate::waf::{WafTlsMetadata, WafTransportMetadataInput};

pub(in crate::server) mod parse;
mod plain_io;
pub(in crate::server) mod response_head;
mod sendfile;
mod static_access_log;
mod static_helpers;
mod static_waf;
mod static_write;
use self::parse::{ParsedPlainRequest, ReadRequestOutcome, header_has_token, read_request};
use self::plain_io::PlainHttpIo;
use self::static_access_log::{StaticFastPathContext, emit_system_access_log};
use self::static_helpers::{
  compiled_static_hot_object_response, sendfile_disabled_reason, static_body_source_label,
  static_fast_path_request_has_body,
};
#[cfg(test)]
use self::static_write::advance_vectored_write;
use self::static_write::write_static_plan;

struct TimedStaticResponsePlan {
  response: StaticResponsePlan,
  response_send_timeout: Duration,
  access_log: Option<StaticFastPathContext>,
  silent_close: bool,
}

enum SendfilePreflight {
  Done,
  Continue {
    io: PlainHttpIo,
    served_requests: usize,
  },
}

impl SendfilePreflight {
  fn into_continue(self) -> Option<(PlainHttpIo, usize)> {
    match self {
      Self::Done => None,
      Self::Continue {
        io,
        served_requests,
      } => Some((io, served_requests)),
    }
  }
}

pub(super) async fn handle_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  snapshot: Arc<AppSnapshot>,
  mut shutdown: watch::Receiver<bool>,
  mut data_plane_drain: watch::Receiver<bool>,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let _global_permit = super::acquire_global_connection_permit(&snapshot)?;
  let _plain_connection_guard =
    snapshot.runtime_introspection_guard(RuntimeCounter::PlainHttpConnection);
  let _http1_connection_guard =
    snapshot.runtime_introspection_guard(RuntimeCounter::Http1Connection);
  let connection_limit_identity = snapshot.config.limits.connection_limit_identity;
  let proxy_mode = snapshot.config.listeners.http_mode == HttpListenerMode::Proxy;
  let _ip_permit =
    if connection_limit_identity == ConnectionLimitIdentityMode::ProxyProtocol || !proxy_mode {
      Some(super::acquire_ip_connection_permit(&snapshot, peer_addr)?)
    } else {
      None
    };
  let connection_limit_context =
    (connection_limit_identity == ConnectionLimitIdentityMode::FirstRequestRealIp && proxy_mode)
      .then(ConnectionLimitContext::default);
  let tcp_metadata = tcp_hop::transport_metadata(&stream);
  let transport_metadata = WafTransportMetadataInput {
    tcp_mss: tcp_metadata.mss,
    tcp_rtt_ms: tcp_metadata.rtt_ms,
    ..WafTransportMetadataInput::default()
  };
  let Some((io, served_requests)) = try_sendfile_fast_path(
    stream,
    peer_addr,
    &snapshot,
    transport_metadata,
    &mut shutdown,
    &mut data_plane_drain,
  )
  .await?
  .into_continue() else {
    return Ok(());
  };
  let request_count = Arc::new(AtomicUsize::new(served_requests));
  let request_state = snapshot.clone();
  let tls_metadata = Arc::new(WafTlsMetadata::default());
  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = request_state.clone();
    let request_index = if state.config.listeners.http_mode == HttpListenerMode::Proxy {
      Some(request_count.fetch_add(1, Ordering::Relaxed))
    } else {
      None
    };
    let connection_limit_context = connection_limit_context.clone();
    let tls_metadata = tls_metadata.clone();
    let drain = drain.clone();
    async move {
      let _request_guard = state.runtime_introspection_guard(RuntimeCounter::Http1Request);
      match state.config.listeners.http_mode {
        HttpListenerMode::RedirectToHttps => Ok(super::redirect_to_https(&request)),
        HttpListenerMode::Proxy => {
          if request_index.unwrap_or(usize::MAX) >= state.config.limits.max_requests_per_connection
          {
            Ok(text_response(
              StatusCode::TOO_MANY_REQUESTS,
              "too many requests on this connection",
            ))
          } else {
            let response = http::handle(
              request,
              peer_addr,
              None,
              transport_metadata,
              tls_metadata,
              connection_limit_context.clone(),
              state,
              "http",
              drain,
            )
            .await;
            if is_silent_close_response(&response) {
              Err(SilentClose)
            } else {
              Ok(response)
            }
          }
        }
        HttpListenerMode::Off => Ok(text_response(
          StatusCode::NOT_FOUND,
          "HTTP listener is disabled",
        )),
      }
    }
  });
  let mut builder = hyper::server::conn::http1::Builder::new();
  builder
    .timer(TokioTimer::new())
    .header_read_timeout(Duration::from_millis(
      snapshot.config.limits.client_header_timeout_ms,
    ))
    .max_headers(snapshot.config.limits.max_headers)
    .max_buf_size(snapshot.config.limits.max_total_header_bytes.max(8192))
    .keep_alive(true);
  let io = super::http_io::InstrumentedDownstreamIo::new(io, snapshot.metrics.clone(), "h1", "tcp");
  let connection = builder.serve_connection(TokioIo::new(io), service);
  let result = if snapshot.http1_upgrades_possible {
    let connection = connection.with_upgrades();
    tokio::pin!(connection);
    if *shutdown.borrow() || *data_plane_drain.borrow() {
      connection.as_mut().graceful_shutdown();
    }
    tokio::select! {
      result = &mut connection => result,
      _ = wait_for_listener_or_data_plane_drain(&mut shutdown, &mut data_plane_drain) => {
        connection.as_mut().graceful_shutdown();
        (&mut connection).await
      }
    }
  } else {
    tokio::pin!(connection);
    if *shutdown.borrow() || *data_plane_drain.borrow() {
      connection.as_mut().graceful_shutdown();
    }
    tokio::select! {
      result = &mut connection => result,
      _ = wait_for_listener_or_data_plane_drain(&mut shutdown, &mut data_plane_drain) => {
        connection.as_mut().graceful_shutdown();
        (&mut connection).await
      }
    }
  };
  result.map_err(|error| anyhow::anyhow!(error))?;
  Ok(())
}

async fn try_sendfile_fast_path(
  stream: TcpStream,
  peer_addr: SocketAddr,
  snapshot: &Arc<AppSnapshot>,
  transport_metadata: WafTransportMetadataInput<'_>,
  shutdown: &mut watch::Receiver<bool>,
  data_plane_drain: &mut watch::Receiver<bool>,
) -> anyhow::Result<SendfilePreflight> {
  try_sendfile_fast_path_inner(
    stream,
    peer_addr,
    snapshot,
    transport_metadata,
    shutdown,
    data_plane_drain,
    sendfile::kernel_sendfile_available(),
  )
  .await
}

async fn try_sendfile_fast_path_inner(
  mut stream: TcpStream,
  peer_addr: SocketAddr,
  snapshot: &Arc<AppSnapshot>,
  transport_metadata: WafTransportMetadataInput<'_>,
  shutdown: &mut watch::Receiver<bool>,
  data_plane_drain: &mut watch::Receiver<bool>,
  kernel_sendfile_available: bool,
) -> anyhow::Result<SendfilePreflight> {
  if let Some(reason) = sendfile_disabled_reason(snapshot.as_ref(), kernel_sendfile_available) {
    trace!(reason, "plain HTTP static sendfile fast path skipped");
    return Ok(SendfilePreflight::Continue {
      io: PlainHttpIo::new(stream, Vec::new()),
      served_requests: 0,
    });
  }

  let mut buffer = Vec::new();
  let mut response_head_buffer = Vec::with_capacity(512);
  let mut served_requests = 0_usize;
  loop {
    if served_requests >= snapshot.config.limits.max_requests_per_connection {
      trace!("plain HTTP static sendfile fast path reached request limit");
      return Ok(SendfilePreflight::Done);
    }
    if *shutdown.borrow() || *data_plane_drain.borrow() {
      return Ok(SendfilePreflight::Done);
    }

    let request = match read_request(
      &mut stream,
      buffer,
      snapshot.config.limits.max_total_header_bytes.max(8192),
      snapshot.config.limits.max_headers,
      Duration::from_millis(snapshot.config.limits.client_header_timeout_ms),
      &|target| {
        snapshot
          .route_table
          .static_sendfile_target_can_match(target)
      },
      shutdown,
      data_plane_drain,
    )
    .await?
    {
      ReadRequestOutcome::Closed => return Ok(SendfilePreflight::Done),
      ReadRequestOutcome::Fallback { prefix, reason } => {
        trace!(reason, "plain HTTP static sendfile parser fell back");
        return Ok(SendfilePreflight::Continue {
          io: PlainHttpIo::new(stream, prefix),
          served_requests,
        });
      }
      ReadRequestOutcome::Request(request) => request,
    };
    let plan_started_at = stage_timing::start(snapshot.request_path_features.stage_timing_metrics);
    let plan =
      eligible_static_plan(&request, snapshot.as_ref(), peer_addr, transport_metadata).await;
    stage_timing::record_metrics(
      &snapshot.metrics,
      stage_timing::PATH_STATIC_FILES,
      FastPathMetricProtocol::H1,
      stage_timing::STAGE_STATIC_PLAN,
      if plan.is_some() {
        stage_timing::OUTCOME_OK
      } else {
        stage_timing::OUTCOME_FALLBACK
      },
      plan_started_at,
    );
    let Some(mut plan) = plan else {
      let mut prefix = request.raw;
      prefix.extend_from_slice(&request.remaining);
      trace!("plain HTTP static sendfile request fell back");
      return Ok(SendfilePreflight::Continue {
        io: PlainHttpIo::new(stream, prefix),
        served_requests,
      });
    };
    let _request_guard = snapshot.runtime_introspection_guard(RuntimeCounter::Http1Request);

    if plan.silent_close {
      return Ok(SendfilePreflight::Done);
    }
    let close_after_response = header_has_token(&request.headers, CONNECTION, "close");
    emit_system_access_log(&request, snapshot.as_ref(), transport_metadata, &mut plan);
    buffer = request.remaining;
    let status = plan.response.status;
    if let Err(error) = write_static_plan(
      &mut stream,
      &plan,
      !close_after_response,
      &mut response_head_buffer,
      snapshot.as_ref(),
    )
    .await
    {
      debug!(error = %error, peer = %peer_addr, "plain HTTP static sendfile response failed");
      return Ok(SendfilePreflight::Done);
    }
    served_requests += 1;
    snapshot.record_hot_path_response(status);
    snapshot
      .metrics
      .record_static_fast_path_response(static_body_source_label(&plan.response.body), "served");
    if matches!(plan.response.body, StaticBodyPlan::File(_)) {
      snapshot
        .metrics
        .record_fast_path_selection("static_sendfile_like", "h1", "selected", "used");
    }
    if close_after_response {
      return Ok(SendfilePreflight::Done);
    }
  }
}

async fn eligible_static_plan(
  request: &ParsedPlainRequest,
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
  transport_metadata: WafTransportMetadataInput<'_>,
) -> Option<TimedStaticResponsePlan> {
  if request.version != 1
    || (request.method != Method::GET && request.method != Method::HEAD)
    || !request.target.starts_with('/')
    || request.target.starts_with("//")
    || request.target.contains("://")
  {
    return None;
  }
  if request.header_count(HOST) != 1
    || static_fast_path_request_has_body(&request.headers)
    || request.header_count(TRANSFER_ENCODING) != 0
    || request.header_count(UPGRADE) != 0
    || header_has_token(&request.headers, CONNECTION, "upgrade")
  {
    return None;
  }
  let host = request
    .headers
    .get(HOST)
    .and_then(|value| value.to_str().ok())
    .map(normalize_host)?;
  let (request_path, request_query) = request
    .target
    .split_once('?')
    .map_or((request.target.as_str(), None), |(path, query)| {
      (path, Some(query))
    });
  let client_addr = match crate::identity::resolve_client_addr(
    &request.headers,
    peer_addr,
    &snapshot.config.proxy.real_ip,
  ) {
    Ok(addr) => addr,
    Err(error) => {
      warn!(error = %error, peer = %peer_addr, "rejected untrusted real IP metadata");
      return Some(TimedStaticResponsePlan {
        response: static_files::text_plan(
          StatusCode::BAD_REQUEST,
          "untrusted forwarded client IP metadata",
        ),
        response_send_timeout: Duration::from_millis(
          snapshot.config.limits.response_send_timeout_ms,
        ),
        access_log: None,
        silent_close: false,
      });
    }
  };
  let resolved = snapshot
    .route_table
    .try_resolve_simple_exact_host(&host, request_path, &snapshot.upstreams)
    .or_else(|| {
      snapshot.route_table.resolve_normalized_host_with_context(
        &host,
        RouteMatchContext {
          path: request_path,
          method: Some(&request.method),
          headers: Some(&request.headers),
          query: request_query,
          source_ip: Some(client_addr.ip()),
          protocol: Some(RouteRequestProtocol::Http1),
          tls: None,
        },
        &snapshot.upstreams,
      )
    })?;
  if !resolved.execution_plan.fast_path.static_sendfile_like {
    return None;
  }
  let static_root = resolved.route.static_root.as_deref()?;
  if resolved
    .route
    .compression
    .as_deref()
    .is_some_and(|value| value != "off")
  {
    return None;
  }
  let hot_object_started_at =
    stage_timing::start(snapshot.request_path_features.stage_timing_metrics);
  let compiled_static_response =
    compiled_static_hot_object_response(request, request_path, snapshot, &resolved);
  stage_timing::record_metrics(
    &snapshot.metrics,
    stage_timing::PATH_STATIC_FILES,
    FastPathMetricProtocol::H1,
    stage_timing::STAGE_STATIC_HOT_OBJECT_REVALIDATE,
    if compiled_static_response.is_some() {
      stage_timing::OUTCOME_OK
    } else {
      stage_timing::OUTCOME_FALLBACK
    },
    hot_object_started_at,
  );
  let response_send_timeout = compiled_static_response.as_ref().map_or_else(
    || static_files::static_response_send_timeout(snapshot, resolved.route),
    |(_, timeout)| *timeout,
  );
  let access_log_needed = snapshot.request_path_features.system_access_log
    || resolved.execution_plan.waf.request.enabled()
    || resolved.execution_plan.waf.response.enabled();
  let mut access_log = if access_log_needed {
    let request_uri: Uri = request.target.parse().ok()?;
    Some(StaticFastPathContext::new(
      request_uri,
      peer_addr,
      host.clone(),
      resolved.route.name.clone(),
    ))
  } else {
    None
  };
  if let Some(access_log) = access_log.as_mut() {
    access_log.client_addr = client_addr;
  }
  let mut plan = match compiled_static_response {
    Some((plan, _)) => plan,
    None => {
      static_files::plan_response(
        &request.method,
        &request.headers,
        request_path,
        &resolved.route.name,
        resolved.route.effective_path_prefix(),
        static_root,
        &resolved.route.static_files,
        &snapshot.static_files,
      )
      .await
    }
  };
  if !matches!(
    &plan.body,
    StaticBodyPlan::Empty | StaticBodyPlan::Bytes { .. } | StaticBodyPlan::File(_)
  ) {
    return None;
  }
  let security_headers_enabled = snapshot
    .config
    .security
    .response_headers_enabled_for_route(resolved.route.security_headers.as_deref());
  apply_route_security_headers(&mut plan.headers, &snapshot.config.security, resolved.route);
  if !resolved.execution_plan.waf.request.enabled()
    && !resolved.execution_plan.waf.response.enabled()
  {
    attach_cached_static_response_heads(&mut plan, security_headers_enabled);
    return Some(TimedStaticResponsePlan {
      response: plan,
      response_send_timeout,
      access_log,
      silent_close: false,
    });
  }
  clear_cached_static_response_heads(&mut plan);
  Some(
    static_waf::apply_static_waf(
      request,
      snapshot,
      resolved.execution_plan.waf,
      client_addr,
      transport_metadata,
      access_log.expect("static WAF should create fast-path access-log context"),
      response_send_timeout,
      plan,
    )
    .await,
  )
}

fn attach_cached_static_response_heads(plan: &mut StaticResponsePlan, force_recompute: bool) {
  if plan.response_heads.is_some() && !force_recompute {
    return;
  }
  let cached_heads = StaticResponseHeadBytes::new(plan.status, &plan.headers);
  plan.response_heads = Some(cached_heads.clone());
  if let StaticBodyPlan::Bytes { response_heads, .. } = &mut plan.body {
    *response_heads = Some(cached_heads);
  }
}

fn clear_cached_static_response_heads(plan: &mut StaticResponsePlan) {
  plan.response_heads = None;
  if let StaticBodyPlan::Bytes { response_heads, .. } = &mut plan.body {
    *response_heads = None;
  }
}

#[cfg(test)]
mod tests;
