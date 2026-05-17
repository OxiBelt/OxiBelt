use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ::http::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE};
use ::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use anyhow::{Context as AnyhowContext, bail};
use httparse::Status;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
#[cfg(not(target_env = "musl"))]
use nix::errno::Errno;
#[cfg(target_env = "musl")]
use tokio::io::AsyncSeekExt;
#[cfg(not(target_env = "musl"))]
use tokio::io::Interest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, trace};

use crate::config::{
  Config, ConnectionLimitIdentityMode, HttpListenerMode, StaticFilesSendfileMode,
};
use crate::lifecycle::{ConnectionDrain, wait_for_listener_or_data_plane_drain};
use crate::limits::ConnectionLimitContext;
use crate::proxy::http;
use crate::proxy::http::body::{BodyTimeoutError, BodyTimeoutKind};
use crate::proxy::http::response::text_response;
use crate::proxy::http::static_files::{self, StaticBodyPlan, StaticResponsePlan};
use crate::routes::normalize_host;
use crate::state::AppSnapshot;
use crate::tcp_hop;
use crate::waf::{WafTlsMetadata, WafTransportMetadataInput};

mod plain_io;
mod static_waf;
use self::plain_io::PlainHttpIo;

const READ_CHUNK_BYTES: usize = 4096;
const SENDFILE_CHUNK_BYTES: usize = 1024 * 1024;

struct TimedStaticResponsePlan {
  response: StaticResponsePlan,
  response_send_timeout: Duration,
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
  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = request_state.clone();
    let request_count = request_count.clone();
    let connection_limit_context = connection_limit_context.clone();
    let drain = drain.clone();
    async move {
      let response = match state.config.listeners.http_mode {
        HttpListenerMode::RedirectToHttps => super::redirect_to_https(&request),
        HttpListenerMode::Proxy => {
          if request_count.fetch_add(1, Ordering::Relaxed)
            >= state.config.limits.max_requests_per_connection
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
              Arc::new(WafTlsMetadata::default()),
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
  let connection = builder
    .serve_connection(TokioIo::new(io), service)
    .with_upgrades();
  tokio::pin!(connection);
  if *shutdown.borrow() || *data_plane_drain.borrow() {
    connection.as_mut().graceful_shutdown();
  }
  let result = tokio::select! {
    result = &mut connection => result,
    _ = wait_for_listener_or_data_plane_drain(&mut shutdown, &mut data_plane_drain) => {
      connection.as_mut().graceful_shutdown();
      (&mut connection).await
    }
  };
  result.map_err(|error| anyhow::anyhow!(error))?;
  Ok(())
}

async fn try_sendfile_fast_path(
  mut stream: TcpStream,
  peer_addr: SocketAddr,
  snapshot: &Arc<AppSnapshot>,
  transport_metadata: WafTransportMetadataInput<'_>,
  shutdown: &mut watch::Receiver<bool>,
  data_plane_drain: &mut watch::Receiver<bool>,
) -> anyhow::Result<SendfilePreflight> {
  if let Some(reason) = sendfile_disabled_reason(snapshot.as_ref()) {
    trace!(reason, "plain HTTP static sendfile fast path skipped");
    return Ok(SendfilePreflight::Continue {
      io: PlainHttpIo::new(stream, Vec::new()),
      served_requests: 0,
    });
  }

  let mut buffer = Vec::new();
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
    let next_buffer = request.remaining.clone();

    let Some(plan) =
      eligible_static_plan(&request, snapshot.as_ref(), peer_addr, transport_metadata).await
    else {
      let mut prefix = request.raw;
      prefix.extend_from_slice(&next_buffer);
      trace!("plain HTTP static sendfile request fell back");
      return Ok(SendfilePreflight::Continue {
        io: PlainHttpIo::new(stream, prefix),
        served_requests,
      });
    };
    buffer = next_buffer;

    let close_after_response = header_has_token(&request.headers, CONNECTION, "close");
    let status = plan.response.status;
    if let Err(error) = write_static_plan(&mut stream, plan, !close_after_response).await {
      debug!(error = %error, peer = %peer_addr, "plain HTTP static sendfile response failed");
      return Ok(SendfilePreflight::Done);
    }
    served_requests += 1;
    snapshot.metrics.record_response(status);
    if close_after_response {
      return Ok(SendfilePreflight::Done);
    }
  }
}

fn sendfile_disabled_reason(snapshot: &AppSnapshot) -> Option<&'static str> {
  let config = &snapshot.config;
  if config.listeners.http_mode != HttpListenerMode::Proxy {
    return Some("plain listener is not proxy mode");
  }
  if config.proxy.static_files.sendfile != StaticFilesSendfileMode::Auto {
    return Some("proxy.static_files.sendfile is not auto");
  }
  if !config.rate_limits.is_empty() {
    return Some("rate limits are configured");
  }
  if config.dynamic_policy.enabled {
    return Some("dynamic policy is enabled");
  }
  if config.compression.enabled {
    return Some("compression is enabled");
  }
  if !security_headers_disabled(config) {
    return Some("security response headers are configured");
  }
  if snapshot.system_access_log.enabled() {
    return Some("system access log is enabled");
  }
  if config.limits.connection_limit_identity != ConnectionLimitIdentityMode::ProxyProtocol {
    return Some("Real-IP connection limit identity requires general path");
  }
  None
}

fn security_headers_disabled(config: &Config) -> bool {
  let headers = &config.security.headers;
  !headers.hsts
    && headers.x_content_type_options.is_none()
    && headers.referrer_policy.is_none()
    && headers.permissions_policy.is_none()
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
  let resolved = snapshot
    .route_table
    .resolve(&host, request_path, &snapshot.upstreams)?;
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
  let plan = static_files::plan_response(
    &request.method,
    &request.headers,
    request_path,
    &resolved.route.name,
    &resolved.route.path_prefix,
    static_root,
  )
  .await;
  if !matches!(&plan.body, StaticBodyPlan::Empty | StaticBodyPlan::File(_)) {
    return None;
  }
  let request_uri: Uri = request.target.parse().ok()?;
  Some(
    static_waf::apply_static_waf(
      request,
      &request_uri,
      snapshot,
      peer_addr,
      transport_metadata,
      &host,
      &resolved.route.name,
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
  plan: TimedStaticResponsePlan,
  keep_alive: bool,
) -> anyhow::Result<()> {
  let TimedStaticResponsePlan {
    response,
    response_send_timeout,
  } = plan;
  let StaticResponsePlan {
    status,
    headers,
    body,
  } = response;
  write_response_head(stream, status, &headers, keep_alive, response_send_timeout).await?;
  match body {
    StaticBodyPlan::Empty => {}
    StaticBodyPlan::Text(message) => {
      write_all_tcp(
        stream,
        message.as_bytes(),
        response_send_timeout,
        "static fast-path text response body write failed",
      )
      .await?;
    }
    StaticBodyPlan::File(file) => {
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
) -> anyhow::Result<()> {
  let reason = status.canonical_reason().unwrap_or("");
  let mut head = Vec::with_capacity(256 + headers.len() * 48);
  head.extend_from_slice(format!("HTTP/1.1 {} {reason}\r\n", status.as_u16()).as_bytes());
  for (name, value) in headers {
    head.extend_from_slice(name.as_str().as_bytes());
    head.extend_from_slice(b": ");
    head.extend_from_slice(value.as_bytes());
    head.extend_from_slice(b"\r\n");
  }
  if keep_alive {
    head.extend_from_slice(b"Connection: keep-alive\r\n");
  } else {
    head.extend_from_slice(b"Connection: close\r\n");
  }
  head.extend_from_slice(b"\r\n");
  write_all_tcp(
    stream,
    &head,
    response_send_timeout,
    "static sendfile response head write failed",
  )
  .await
}

#[cfg(target_env = "musl")]
async fn sendfile_all(
  stream: &mut TcpStream,
  file: &tokio::fs::File,
  offset: u64,
  len: u64,
  response_send_timeout: Duration,
) -> anyhow::Result<()> {
  let mut file = file
    .try_clone()
    .await
    .context("failed to clone static file for fast-path response")?;
  file
    .seek(std::io::SeekFrom::Start(offset))
    .await
    .context("failed to seek static file for fast-path response")?;
  let mut remaining = len;
  let mut buffer = vec![0_u8; SENDFILE_CHUNK_BYTES.min(64 * 1024)];
  while remaining > 0 {
    let to_read = remaining.min(buffer.len() as u64) as usize;
    let read = file
      .read(&mut buffer[..to_read])
      .await
      .context("failed to read static file for fast-path response")?;
    if read == 0 {
      bail!("static fast-path file ended before expected length");
    }
    write_all_tcp(
      stream,
      &buffer[..read],
      response_send_timeout,
      "static fast-path response body write failed",
    )
    .await?;
    remaining = remaining.saturating_sub(read as u64);
  }
  Ok(())
}

#[cfg(not(target_env = "musl"))]
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
    downstream_send_timeout(
      response_send_timeout,
      stream.writable(),
      "static sendfile socket wait failed",
    )
    .await?;
    let count = remaining.min(SENDFILE_CHUNK_BYTES as u64) as usize;
    let stream_ref: &TcpStream = &*stream;
    match stream_ref.try_io(Interest::WRITABLE, || {
      nix::sys::sendfile::sendfile64(stream_ref, file, Some(&mut offset), count).map_err(|error| {
        if error == Errno::EAGAIN {
          io::Error::from(io::ErrorKind::WouldBlock)
        } else {
          io::Error::from_raw_os_error(error as i32)
        }
      })
    }) {
      Ok(0) => bail!("static sendfile wrote zero bytes"),
      Ok(sent) => remaining = remaining.saturating_sub(sent as u64),
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
      Err(error) => return Err(error).context("static sendfile syscall failed"),
    }
  }
  Ok(())
}

async fn write_all_tcp(
  stream: &mut TcpStream,
  mut bytes: &[u8],
  response_send_timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()> {
  while !bytes.is_empty() {
    downstream_send_timeout(response_send_timeout, stream.writable(), context).await?;
    match stream.try_write(bytes) {
      Ok(0) => bail!("{context}"),
      Ok(written) => bytes = &bytes[written..],
      Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
      Err(error) => return Err(error).context(context),
    }
  }
  Ok(())
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

enum ReadRequestOutcome {
  Closed,
  Fallback {
    prefix: Vec<u8>,
    reason: &'static str,
  },
  Request(ParsedPlainRequest),
}

struct ParsedPlainRequest {
  method: Method,
  target: String,
  version: u8,
  headers: HeaderMap,
  raw: Vec<u8>,
  remaining: Vec<u8>,
}

impl ParsedPlainRequest {
  fn header_count(&self, name: HeaderName) -> usize {
    self.headers.get_all(name).iter().count()
  }
}

async fn read_request(
  stream: &mut TcpStream,
  mut buffer: Vec<u8>,
  max_header_bytes: usize,
  max_headers: usize,
  header_timeout: Duration,
  shutdown: &mut watch::Receiver<bool>,
  data_plane_drain: &mut watch::Receiver<bool>,
) -> anyhow::Result<ReadRequestOutcome> {
  let started = tokio::time::Instant::now();
  loop {
    match parse_buffered_request(&buffer, max_headers) {
      ParseResult::Complete {
        header_len,
        request,
      } => {
        let raw = buffer[..header_len].to_vec();
        let remaining = buffer[header_len..].to_vec();
        return Ok(ReadRequestOutcome::Request(ParsedPlainRequest {
          method: request.method,
          target: request.target,
          version: request.version,
          headers: request.headers,
          raw,
          remaining,
        }));
      }
      ParseResult::Partial => {}
      ParseResult::Fallback(reason) => {
        return Ok(ReadRequestOutcome::Fallback {
          prefix: buffer,
          reason,
        });
      }
    }
    if buffer.len() >= max_header_bytes {
      return Ok(ReadRequestOutcome::Fallback {
        prefix: buffer,
        reason: "header block exceeded configured limit",
      });
    }
    let remaining_timeout = match header_timeout.checked_sub(started.elapsed()) {
      Some(value) if !value.is_zero() => value,
      _ => bail!("plain HTTP static sendfile header read timed out"),
    };
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES.min(max_header_bytes - buffer.len())];
    let read = tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          return Ok(ReadRequestOutcome::Closed);
        }
        continue;
      }
      changed = data_plane_drain.changed() => {
        if changed.is_ok() && *data_plane_drain.borrow() {
          return Ok(ReadRequestOutcome::Closed);
        }
        continue;
      }
      result = tokio::time::timeout(remaining_timeout, stream.read(&mut chunk)) => {
        result.context("plain HTTP static sendfile header read timed out")??
      }
    };
    if read == 0 {
      if buffer.is_empty() {
        return Ok(ReadRequestOutcome::Closed);
      }
      return Ok(ReadRequestOutcome::Fallback {
        prefix: buffer,
        reason: "connection closed during header parse",
      });
    }
    buffer.extend_from_slice(&chunk[..read]);
  }
}

enum ParseResult {
  Complete {
    header_len: usize,
    request: ParsedPlainRequestSeed,
  },
  Partial,
  Fallback(&'static str),
}

struct ParsedPlainRequestSeed {
  method: Method,
  target: String,
  version: u8,
  headers: HeaderMap,
}

fn parse_buffered_request(buffer: &[u8], max_headers: usize) -> ParseResult {
  let mut parsed_headers = vec![httparse::EMPTY_HEADER; max_headers];
  let mut request = httparse::Request::new(&mut parsed_headers);
  let header_len = match request.parse(buffer) {
    Ok(Status::Complete(len)) => len,
    Ok(Status::Partial) => return ParseResult::Partial,
    Err(_) => return ParseResult::Fallback("HTTP/1.1 parser rejected request"),
  };
  let Some(method) = request.method else {
    return ParseResult::Fallback("HTTP/1.1 request is missing method");
  };
  let method = match Method::from_bytes(method.as_bytes()) {
    Ok(method) => method,
    Err(_) => return ParseResult::Fallback("HTTP/1.1 request method is invalid"),
  };
  let Some(target) = request.path else {
    return ParseResult::Fallback("HTTP/1.1 request is missing target");
  };
  let Some(version) = request.version else {
    return ParseResult::Fallback("HTTP/1.1 request is missing version");
  };
  let mut headers = HeaderMap::new();
  for header in request.headers {
    let name = match HeaderName::from_bytes(header.name.as_bytes()) {
      Ok(name) => name,
      Err(_) => return ParseResult::Fallback("HTTP/1.1 header name is invalid"),
    };
    let value = match HeaderValue::from_bytes(header.value) {
      Ok(value) => value,
      Err(_) => return ParseResult::Fallback("HTTP/1.1 header value is invalid"),
    };
    headers.append(name, value);
  }
  ParseResult::Complete {
    header_len,
    request: ParsedPlainRequestSeed {
      method,
      target: target.to_string(),
      version,
      headers,
    },
  }
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
  headers.get_all(name).iter().any(|value| {
    value.to_str().ok().is_some_and(|value| {
      value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate.eq_ignore_ascii_case(token))
    })
  })
}

#[cfg(test)]
mod tests;
