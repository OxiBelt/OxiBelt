//! Plain HTTP listener fast path.
//! This path parses enough HTTP/1 to enforce configured proxy and WAF policy before forwarding.

use std::convert::Infallible;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ::http::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE};
use ::http::{HeaderMap, Method, StatusCode, Uri};
use anyhow::{Context as AnyhowContext, bail};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, trace, warn};

use crate::config::{ConnectionLimitIdentityMode, HttpListenerMode, StaticFilesSendfileMode};
use crate::lifecycle::{ConnectionDrain, wait_for_listener_or_data_plane_drain};
use crate::limits::ConnectionLimitContext;
use crate::proxy::http;
use crate::proxy::http::body::{BodyTimeoutError, BodyTimeoutKind};
use crate::proxy::http::response::{apply_security_headers, text_response};
use crate::proxy::http::static_files::{self, StaticBodyPlan, StaticResponsePlan};
use crate::routes::{RouteMatchContext, RouteRequestProtocol, normalize_host};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::AppSnapshot;
use crate::tcp_hop;
use crate::waf::{WafTlsMetadata, WafTransportMetadataInput};

mod parse;
mod plain_io;
mod sendfile;
mod static_access_log;
mod static_waf;
use self::parse::{ParsedPlainRequest, ReadRequestOutcome, header_has_token, read_request};
use self::plain_io::PlainHttpIo;
use self::static_access_log::{StaticFastPathContext, emit_system_access_log};

const SENDFILE_CHUNK_BYTES: usize = 1024 * 1024;

struct TimedStaticResponsePlan {
  response: StaticResponsePlan,
  response_send_timeout: Duration,
  access_log: Option<StaticFastPathContext>,
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
      let response = match state.config.listeners.http_mode {
        HttpListenerMode::RedirectToHttps => super::redirect_to_https(&request),
        HttpListenerMode::Proxy => {
          if request_index.unwrap_or(usize::MAX) >= state.config.limits.max_requests_per_connection
          {
            text_response(
              StatusCode::TOO_MANY_REQUESTS,
              "too many requests on this connection",
            )
          } else {
            http::handle(
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
            .await
          }
        }
        HttpListenerMode::Off => text_response(StatusCode::NOT_FOUND, "HTTP listener is disabled"),
      };
      Ok::<_, Infallible>(response)
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
    let Some(mut plan) =
      eligible_static_plan(&request, snapshot.as_ref(), peer_addr, transport_metadata).await
    else {
      let mut prefix = request.raw;
      prefix.extend_from_slice(&request.remaining);
      trace!("plain HTTP static sendfile request fell back");
      return Ok(SendfilePreflight::Continue {
        io: PlainHttpIo::new(stream, prefix),
        served_requests,
      });
    };
    let _request_guard = snapshot.runtime_introspection_guard(RuntimeCounter::Http1Request);

    let close_after_response = header_has_token(&request.headers, CONNECTION, "close");
    emit_system_access_log(&request, snapshot.as_ref(), transport_metadata, &mut plan);
    buffer = request.remaining;
    let status = plan.response.status;
    if let Err(error) = write_static_plan(
      &mut stream,
      &plan,
      !close_after_response,
      &mut response_head_buffer,
    )
    .await
    {
      debug!(error = %error, peer = %peer_addr, "plain HTTP static sendfile response failed");
      return Ok(SendfilePreflight::Done);
    }
    served_requests += 1;
    snapshot.record_hot_path_response(status);
    if close_after_response {
      return Ok(SendfilePreflight::Done);
    }
  }
}

fn sendfile_disabled_reason(
  snapshot: &AppSnapshot,
  kernel_sendfile_available: bool,
) -> Option<&'static str> {
  let config = &snapshot.config;
  if config.listeners.http_mode != HttpListenerMode::Proxy {
    return Some("plain listener is not proxy mode");
  }
  if config.proxy.static_files.sendfile != StaticFilesSendfileMode::Auto {
    return Some("proxy.static_files.sendfile is not auto");
  }
  if !snapshot.route_table.has_static_sendfile_candidates() {
    return Some("no static sendfile routes are configured");
  }
  if !kernel_sendfile_available {
    return Some("Linux kernel sendfile is not available");
  }
  if snapshot.request_path_features.rate_limits {
    return Some("rate limits are configured");
  }
  if snapshot.request_path_features.dynamic_policy {
    return Some("dynamic policy is enabled");
  }
  if snapshot.request_path_features.compression {
    return Some("compression is enabled");
  }
  if config.limits.connection_limit_identity != ConnectionLimitIdentityMode::ProxyProtocol {
    return Some("Real-IP connection limit identity requires general path");
  }
  None
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
  let request_path = request
    .target
    .split_once('?')
    .map_or(request.target.as_str(), |(path, _)| path);
  let request_uri: Uri = request.target.parse().ok()?;
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
      });
    }
  };
  let resolved = snapshot.route_table.resolve_normalized_host_with_context(
    &host,
    RouteMatchContext {
      path: request_path,
      method: Some(&request.method),
      headers: Some(&request.headers),
      query: request_uri.query(),
      source_ip: Some(client_addr.ip()),
      protocol: Some(RouteRequestProtocol::Http1),
      tls: None,
    },
    &snapshot.upstreams,
  )?;
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
  let response_send_timeout = static_files::static_response_send_timeout(snapshot, resolved.route);
  let access_log_needed = snapshot.request_path_features.system_access_log
    || resolved.execution_plan.waf.request.enabled()
    || resolved.execution_plan.waf.response.enabled();
  let mut access_log = access_log_needed.then(|| {
    StaticFastPathContext::new(
      request_uri,
      peer_addr,
      host.clone(),
      resolved.route.name.clone(),
    )
  });
  if let Some(access_log) = access_log.as_mut() {
    access_log.client_addr = client_addr;
  }
  let mut plan = static_files::plan_response(
    &request.method,
    &request.headers,
    request_path,
    &resolved.route.name,
    resolved.route.effective_path_prefix(),
    static_root,
    &resolved.route.static_files,
    &snapshot.static_files,
  )
  .await;
  if !matches!(
    &plan.body,
    StaticBodyPlan::Empty | StaticBodyPlan::Bytes(_) | StaticBodyPlan::File(_)
  ) {
    return None;
  }
  apply_security_headers(&mut plan.headers, &snapshot.config.security.headers);
  if !resolved.execution_plan.waf.request.enabled()
    && !resolved.execution_plan.waf.response.enabled()
  {
    return Some(TimedStaticResponsePlan {
      response: plan,
      response_send_timeout,
      access_log,
    });
  }
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

fn static_fast_path_request_has_body(headers: &HeaderMap) -> bool {
  let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
  let Some(value) = content_lengths.next() else {
    return false;
  };
  if content_lengths.next().is_some() {
    return true;
  }
  value
    .to_str()
    .map(|value| value.trim() != "0")
    .unwrap_or(true)
}

async fn write_static_plan(
  stream: &mut TcpStream,
  plan: &TimedStaticResponsePlan,
  keep_alive: bool,
  head_buffer: &mut Vec<u8>,
) -> anyhow::Result<()> {
  let TimedStaticResponsePlan {
    response,
    response_send_timeout,
    ..
  } = plan;
  let StaticResponsePlan {
    status,
    headers,
    body,
  } = response;
  let response_send_timeout = *response_send_timeout;
  match body {
    StaticBodyPlan::Empty => {
      response_head_bytes(*status, headers, keep_alive, head_buffer);
      write_all_tcp(
        stream,
        head_buffer,
        response_send_timeout,
        "static sendfile response head write failed",
      )
      .await?;
    }
    StaticBodyPlan::Text(message) => {
      response_head_bytes(*status, headers, keep_alive, head_buffer);
      write_all_tcp_vectored(
        stream,
        head_buffer,
        message.as_bytes(),
        response_send_timeout,
        "static fast-path text response write failed",
      )
      .await?;
    }
    StaticBodyPlan::Bytes(bytes) => {
      response_head_bytes(*status, headers, keep_alive, head_buffer);
      write_all_tcp_vectored(
        stream,
        head_buffer,
        bytes.as_ref(),
        response_send_timeout,
        "static fast-path bytes response write failed",
      )
      .await?;
    }
    StaticBodyPlan::File(file) => {
      write_response_head(
        stream,
        *status,
        headers,
        keep_alive,
        response_send_timeout,
        head_buffer,
      )
      .await?;
      sendfile_all(
        stream,
        &file.file,
        file.offset,
        file.len,
        response_send_timeout,
      )
      .await?;
      debug!(
        path = %file.path.display(),
        bytes = file.len,
        "plain HTTP static fast-path response sent"
      );
    }
  }
  if !keep_alive {
    downstream_send_timeout(
      response_send_timeout,
      stream.shutdown(),
      "static sendfile response shutdown failed",
    )
    .await?;
  }
  Ok(())
}

async fn write_response_head(
  stream: &mut TcpStream,
  status: StatusCode,
  headers: &HeaderMap,
  keep_alive: bool,
  response_send_timeout: Duration,
  head_buffer: &mut Vec<u8>,
) -> anyhow::Result<()> {
  response_head_bytes(status, headers, keep_alive, head_buffer);
  write_all_tcp(
    stream,
    head_buffer,
    response_send_timeout,
    "static sendfile response head write failed",
  )
  .await
}

fn response_head_bytes(
  status: StatusCode,
  headers: &HeaderMap,
  keep_alive: bool,
  output: &mut Vec<u8>,
) {
  let reason = status.canonical_reason().unwrap_or("");
  output.clear();
  output.reserve(256 + headers.len() * 48);
  output.extend_from_slice(b"HTTP/1.1 ");
  append_u16_decimal(output, status.as_u16());
  output.push(b' ');
  output.extend_from_slice(reason.as_bytes());
  output.extend_from_slice(b"\r\n");
  for (name, value) in headers {
    output.extend_from_slice(name.as_str().as_bytes());
    output.extend_from_slice(b": ");
    output.extend_from_slice(value.as_bytes());
    output.extend_from_slice(b"\r\n");
  }
  if keep_alive {
    output.extend_from_slice(b"Connection: keep-alive\r\n");
  } else {
    output.extend_from_slice(b"Connection: close\r\n");
  }
  output.extend_from_slice(b"\r\n");
}

fn append_u16_decimal(output: &mut Vec<u8>, value: u16) {
  let mut buf = [0_u8; 5];
  let mut value = value;
  let mut index = buf.len();
  loop {
    index -= 1;
    buf[index] = b'0' + (value % 10) as u8;
    value /= 10;
    if value == 0 {
      break;
    }
  }
  output.extend_from_slice(&buf[index..]);
}

#[cfg(target_os = "linux")]
async fn sendfile_all(
  stream: &mut TcpStream,
  file: &tokio::fs::File,
  offset: u64,
  len: u64,
  response_send_timeout: Duration,
) -> anyhow::Result<()> {
  let mut remaining = len;
  let mut offset = libc::off64_t::try_from(offset).context("static file offset is too large")?;
  while remaining > 0 {
    let count = remaining.min(SENDFILE_CHUNK_BYTES as u64) as usize;
    let stream_ref: &TcpStream = &*stream;
    match sendfile::sendfile_once(stream_ref, file, &mut offset, count) {
      Ok(0) => bail!("static sendfile wrote zero bytes"),
      Ok(sent) => remaining = remaining.saturating_sub(sent as u64),
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        downstream_send_timeout(
          response_send_timeout,
          stream.writable(),
          "static sendfile socket wait failed",
        )
        .await?;
        let stream_ref: &TcpStream = &*stream;
        match stream_ref.try_io(Interest::WRITABLE, || {
          sendfile::sendfile_once(stream_ref, file, &mut offset, count)
        }) {
          Ok(0) => bail!("static sendfile wrote zero bytes"),
          Ok(sent) => remaining = remaining.saturating_sub(sent as u64),
          Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
          Err(error) => return Err(error).context("static sendfile syscall failed"),
        }
      }
      Err(error) => return Err(error).context("static sendfile syscall failed"),
    }
  }
  Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn sendfile_all(
  _stream: &mut TcpStream,
  _file: &tokio::fs::File,
  _offset: u64,
  _len: u64,
  _response_send_timeout: Duration,
) -> anyhow::Result<()> {
  bail!("kernel sendfile is not available on this platform")
}

async fn write_all_tcp(
  stream: &mut TcpStream,
  mut bytes: &[u8],
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  while !bytes.is_empty() {
    match stream.try_write(bytes) {
      Ok(0) => bail!("{context}"),
      Ok(written) => bytes = &bytes[written..],
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        downstream_send_timeout(response_send_timeout, stream.writable(), context).await?;
      }
      Err(error) => return Err(error).context(context),
    }
  }
  Ok(())
}

async fn write_all_tcp_vectored(
  stream: &mut TcpStream,
  mut head: &[u8],
  mut body: &[u8],
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  while !head.is_empty() || !body.is_empty() {
    let written = match stream.try_write_vectored(&[IoSlice::new(head), IoSlice::new(body)]) {
      Ok(0) => bail!("{context}"),
      Ok(written) => written,
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
        downstream_send_timeout(response_send_timeout, stream.writable(), context).await?;
        continue;
      }
      Err(error) => return Err(error).context(context),
    };
    advance_vectored_write(&mut head, &mut body, written);
  }
  Ok(())
}

fn advance_vectored_write<'a>(head: &mut &'a [u8], body: &mut &'a [u8], written: usize) {
  if written < head.len() {
    *head = &head[written..];
    return;
  }
  let body_written = written.saturating_sub(head.len());
  *head = &[];
  *body = &body[body_written.min(body.len())..];
}

async fn downstream_send_timeout<T>(
  timeout: Duration,
  operation: impl Future<Output = io::Result<T>>,
  context: &'static str,
) -> anyhow::Result<T> {
  match tokio::time::timeout(timeout, operation).await {
    Ok(result) => result.context(context),
    Err(_) => Err(BodyTimeoutError::new(BodyTimeoutKind::DownstreamResponseSend).into()),
  }
}

#[cfg(test)]
mod tests;
