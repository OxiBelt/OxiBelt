//! Guarded pre-Hyper HTTP/1.1 proxy loop for the benchmark-safe keep-alive path.
//! Unsupported requests are replayed into Hyper with their already-read bytes intact.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ::http::header::{
  CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, EXPECT, HOST, TRANSFER_ENCODING, UPGRADE,
};
use ::http::{
  HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
};
use anyhow::Context as AnyhowContext;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Body;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;
use tracing::{debug, trace, warn};

use crate::config::{ConnectionLimitIdentityMode, ForwardedClientIpSource, HttpListenerMode};
use crate::proxy::http as proxy_http;
use crate::proxy::http::SystemAccessLogContext;
use crate::proxy::http::body::{BoxError, ProxyBody};
use crate::proxy::http::headers::{ForwardedHeaderCache, extract_downstream_port};
use crate::proxy::http::request_framing::{
  RequestBodyFraming, VerifiedContentLengthZeroBody, request_body_framing,
};
use crate::proxy::http::response::is_silent_close_response;
use crate::routes::{RouteMatchContext, RouteRequestProtocol, normalize_host};
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::AppSnapshot;
use crate::waf::{WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork};

use super::plain_http::parse::{ParsedPlainRequest, ReadRequestOutcome, header_has_token};
use super::plain_http::response_head::response_head_bytes;
use super::prefixed_io::PrefixedIo;

pub(super) enum H1FastProxyPreflight {
  Done,
  Continue {
    io: Box<PrefixedIo<TlsStream<TcpStream>>>,
    served_requests: usize,
  },
}

impl H1FastProxyPreflight {
  pub(super) fn into_continue(self) -> Option<(PrefixedIo<TlsStream<TcpStream>>, usize)> {
    match self {
      Self::Done => None,
      Self::Continue {
        io,
        served_requests,
      } => Some((*io, served_requests)),
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn try_handle_connection(
  mut stream: TlsStream<TcpStream>,
  peer_addr: SocketAddr,
  snapshot: &Arc<AppSnapshot>,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  transport_metadata: WafTransportMetadataInput<'static>,
  forwarded_header_cache: Option<&ForwardedHeaderCache>,
  shutdown: &mut watch::Receiver<bool>,
  data_plane_drain: &mut watch::Receiver<bool>,
) -> anyhow::Result<H1FastProxyPreflight> {
  if let Some(reason) = fast_proxy_preflight_disabled_reason(snapshot.as_ref()) {
    trace!(reason, "TLS H1 pre-Hyper proxy fast path skipped");
    return Ok(H1FastProxyPreflight::Continue {
      io: Box::new(PrefixedIo::new(stream, Vec::new())),
      served_requests: 0,
    });
  }

  let mut buffer = Vec::new();
  let mut head_buffer = Vec::with_capacity(512);
  let mut served_requests = 0_usize;
  loop {
    if served_requests >= snapshot.config.limits.max_requests_per_connection {
      trace!("TLS H1 pre-Hyper proxy fast path reached request limit");
      return Ok(H1FastProxyPreflight::Continue {
        io: Box::new(PrefixedIo::new(stream, buffer)),
        served_requests,
      });
    }
    if *shutdown.borrow() || *data_plane_drain.borrow() {
      return Ok(H1FastProxyPreflight::Done);
    }

    let parsed = match super::plain_http::parse::read_request(
      &mut stream,
      buffer,
      snapshot.config.limits.max_total_header_bytes.max(8192),
      snapshot.config.limits.max_headers,
      Duration::from_millis(snapshot.config.limits.client_header_timeout_ms),
      &|_| true,
      shutdown,
      data_plane_drain,
    )
    .await?
    {
      ReadRequestOutcome::Closed => return Ok(H1FastProxyPreflight::Done),
      ReadRequestOutcome::Fallback { prefix, reason } => {
        trace!(reason, "TLS H1 pre-Hyper proxy parser fell back");
        return Ok(H1FastProxyPreflight::Continue {
          io: Box::new(PrefixedIo::new(stream, prefix)),
          served_requests,
        });
      }
      ReadRequestOutcome::Request(request) => request,
    };

    let Some(prepared) =
      prepare_fast_proxy_request(&parsed, snapshot.as_ref(), peer_addr, tls.as_ref())
    else {
      trace!("TLS H1 pre-Hyper proxy request fell back");
      return Ok(H1FastProxyPreflight::Continue {
        io: Box::new(PrefixedIo::new(stream, replay_prefix(parsed))),
        served_requests,
      });
    };
    if snapshot.lifecycle.is_draining() {
      return Ok(H1FastProxyPreflight::Continue {
        io: Box::new(PrefixedIo::new(stream, replay_prefix(parsed))),
        served_requests,
      });
    }

    let _request_guard = snapshot.runtime_introspection_guard(RuntimeCounter::Http1Request);
    snapshot.record_hot_path_request();
    let close_after_request = header_has_token(&parsed.headers, CONNECTION, "close");
    let request_method = prepared.request.method().clone();
    let timeout = Duration::from_millis(snapshot.config.limits.response_send_timeout_ms);
    let mut access_log = SystemAccessLogContext::new(
      &prepared.request,
      peer_addr,
      tcp_max_hop,
      None,
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
      transport_metadata,
      "https",
      false,
      false,
    );

    let next_buffer = parsed.remaining.clone();
    let fallback_prefix = replay_prefix(parsed);
    let response = match proxy_http::fast_path::try_handle_plain_proxy(
      prepared.request,
      snapshot,
      &prepared.resolved,
      prepared.forwarded_client_addr,
      forwarded_header_cache,
      prepared.client_addr,
      &prepared.host,
      prepared.downstream_port,
      tcp_max_hop,
      tls.as_ref(),
      WafProtocol::Http,
      "https",
      Version::HTTP_11,
      WafTransportNetwork::Tcp,
      transport_metadata,
      &mut access_log,
      None,
    )
    .await
    {
      Ok(response) => response,
      Err(_) => {
        trace!("TLS H1 pre-Hyper proxy fast-path decision fell back");
        return Ok(H1FastProxyPreflight::Continue {
          io: Box::new(PrefixedIo::new(stream, fallback_prefix)),
          served_requests,
        });
      }
    };

    let Some(write_plan) =
      response_write_plan(&response, &request_method, close_after_request, timeout)
    else {
      return Ok(H1FastProxyPreflight::Done);
    };
    if let Err(error) = write_response(
      &mut stream,
      response,
      write_plan.keep_alive,
      write_plan.skip_body,
      write_plan.response_send_timeout,
      &mut head_buffer,
    )
    .await
    {
      debug!(error = %error, peer = %peer_addr, "TLS H1 pre-Hyper proxy response failed");
      return Ok(H1FastProxyPreflight::Done);
    }
    served_requests += 1;
    if !write_plan.keep_alive {
      return Ok(H1FastProxyPreflight::Done);
    }
    buffer = next_buffer;
  }
}

fn fast_proxy_preflight_disabled_reason(snapshot: &AppSnapshot) -> Option<&'static str> {
  if snapshot.config.listeners.http_mode != HttpListenerMode::Proxy {
    return Some("HTTPS listener is not in proxy mode");
  }
  if snapshot.config.limits.connection_limit_identity != ConnectionLimitIdentityMode::ProxyProtocol
  {
    return Some("connection limit identity needs per-request real IP accounting");
  }
  let features = snapshot.request_path_features;
  if features.system_access_log {
    return Some("system access log is enabled");
  }
  if features.telemetry {
    return Some("telemetry is enabled");
  }
  if features.detailed_metrics {
    return Some("detailed metrics are enabled");
  }
  if features.rate_limits {
    return Some("rate limits are enabled");
  }
  if features.dynamic_policy {
    return Some("dynamic policy is enabled");
  }
  if features.person_proof_api {
    return Some("person proof API routing is enabled");
  }
  if features.runtime_introspection {
    return Some("runtime introspection is enabled");
  }
  None
}

struct PreparedFastProxyRequest<'a> {
  request: Request<ProxyBody>,
  resolved: crate::routes::ResolvedRoute<'a>,
  client_addr: SocketAddr,
  forwarded_client_addr: SocketAddr,
  host: String,
  downstream_port: u16,
}

fn prepare_fast_proxy_request<'a>(
  parsed: &ParsedPlainRequest,
  snapshot: &'a AppSnapshot,
  peer_addr: SocketAddr,
  tls: &WafTlsMetadata,
) -> Option<PreparedFastProxyRequest<'a>> {
  if parsed.version != 1 || (parsed.method != Method::GET && parsed.method != Method::HEAD) {
    return None;
  }
  let (request_path, request_query) = origin_form_target(parsed.target.as_str())?;
  if parsed.header_count(HOST) != 1
    || parsed.header_count(TRANSFER_ENCODING) != 0
    || parsed.header_count(UPGRADE) != 0
    || parsed.header_count(EXPECT) != 0
    || header_has_token(&parsed.headers, CONNECTION, "upgrade")
    || content_type_looks_grpc(&parsed.headers)
  {
    return None;
  }
  match request_body_framing(&parsed.headers) {
    RequestBodyFraming::NoBodyHeaders | RequestBodyFraming::ContentLength(0) => {}
    RequestBodyFraming::ContentLength(_)
    | RequestBodyFraming::TransferEncoding
    | RequestBodyFraming::InvalidContentLength
    | RequestBodyFraming::Ambiguous => return None,
  }

  let host = parsed
    .headers
    .get(HOST)
    .and_then(|value| value.to_str().ok())
    .map(normalize_host)?;
  if host.is_empty() {
    return None;
  }
  let uri = parsed.target.parse::<Uri>().ok()?;
  let mut builder = Request::builder()
    .method(parsed.method.clone())
    .uri(uri)
    .version(Version::HTTP_11);
  *builder.headers_mut()? = parsed.headers.clone();
  let mut request = builder.body(empty_proxy_body()).ok()?;
  if matches!(
    request_body_framing(request.headers()),
    RequestBodyFraming::ContentLength(0)
  ) {
    request
      .extensions_mut()
      .insert(VerifiedContentLengthZeroBody);
  }
  if proxy_http::validate_request_limits(&request, &snapshot.config.limits).is_err() {
    return None;
  }
  if proxy_http::uri::validate_downstream_path(request_path).is_err() {
    return None;
  }

  let client_addr = match crate::identity::resolve_client_addr(
    request.headers(),
    peer_addr,
    &snapshot.config.proxy.real_ip,
  ) {
    Ok(addr) => addr,
    Err(error) => {
      warn!(error = %error, peer = %peer_addr, "rejected untrusted real IP metadata");
      return None;
    }
  };
  let forwarded_client_addr = select_forwarded_client_addr(
    peer_addr,
    client_addr,
    snapshot.config.proxy.forwarded_headers.client_ip_source,
  );
  let resolved = snapshot
    .route_table
    .try_resolve_simple_exact_host(&host, request_path, &snapshot.upstreams)
    .or_else(|| {
      snapshot.route_table.resolve_normalized_host_with_context(
        &host,
        RouteMatchContext {
          path: request_path,
          method: Some(&parsed.method),
          headers: Some(&parsed.headers),
          query: request_query,
          source_ip: Some(client_addr.ip()),
          protocol: Some(RouteRequestProtocol::Http1),
          tls: None,
        },
        &snapshot.upstreams,
      )
    })?;
  if !proxy_http::route_matches_selected_tls_negotiation_policy(snapshot, tls, resolved.route) {
    return None;
  }
  if resolved.execution_plan.features.ipm || resolved.execution_plan.features.cache {
    return None;
  }
  snapshot
    .compiled_fast_path_actions(resolved.route_index)
    .and_then(|actions| actions.proxy_for_version(Version::HTTP_11))?;
  let downstream_port = extract_downstream_port(&request, "https");
  Some(PreparedFastProxyRequest {
    request,
    resolved,
    client_addr,
    forwarded_client_addr,
    host,
    downstream_port,
  })
}

fn replay_prefix(mut request: ParsedPlainRequest) -> Vec<u8> {
  request.raw.extend_from_slice(&request.remaining);
  request.raw
}

fn origin_form_target(target: &str) -> Option<(&str, Option<&str>)> {
  if !target.starts_with('/') || target.starts_with("//") || target.contains("://") {
    return None;
  }
  let (path, query) = target
    .split_once('?')
    .map_or((target, None), |(path, query)| (path, Some(query)));
  Some((path, query))
}

fn content_type_looks_grpc(headers: &HeaderMap) -> bool {
  headers.get(CONTENT_TYPE).is_some_and(|value| {
    value
      .to_str()
      .ok()
      .is_some_and(|value| value.starts_with("application/grpc"))
  })
}

fn select_forwarded_client_addr(
  peer_addr: SocketAddr,
  client_addr: SocketAddr,
  source: ForwardedClientIpSource,
) -> SocketAddr {
  match source {
    ForwardedClientIpSource::Resolved => client_addr,
    ForwardedClientIpSource::DirectPeer => peer_addr,
  }
}

fn empty_proxy_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

struct ResponseWritePlan {
  keep_alive: bool,
  skip_body: bool,
  response_send_timeout: Duration,
}

fn response_write_plan(
  response: &Response<ProxyBody>,
  request_method: &Method,
  close_after_request: bool,
  default_timeout: Duration,
) -> Option<ResponseWritePlan> {
  if is_silent_close_response(response) {
    return None;
  }
  let close_after_response = header_has_token(response.headers(), CONNECTION, "close");
  Some(ResponseWritePlan {
    keep_alive: !close_after_request && !close_after_response,
    skip_body: request_method == Method::HEAD || response_status_has_no_body(response.status()),
    response_send_timeout: proxy_http::downstream_response_send_timeout(response)
      .unwrap_or(default_timeout),
  })
}

async fn write_response<I>(
  stream: &mut I,
  response: Response<ProxyBody>,
  keep_alive: bool,
  skip_body: bool,
  response_send_timeout: Duration,
  head_buffer: &mut Vec<u8>,
) -> anyhow::Result<()>
where
  I: AsyncWrite + Unpin,
{
  let (mut parts, body) = response.into_parts();
  let body_is_end_stream = body.is_end_stream();
  parts.headers.remove(CONNECTION);
  parts.headers.remove(TRANSFER_ENCODING);
  let content_length = single_content_length(&parts.headers);
  let chunked = !skip_body && !body_is_end_stream && content_length.is_none();
  if chunked {
    parts.headers.remove(CONTENT_LENGTH);
    parts
      .headers
      .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
  } else if !skip_body && body_is_end_stream && content_length.is_none() {
    parts
      .headers
      .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
  }

  response_head_bytes(parts.status, &parts.headers, keep_alive, head_buffer);
  write_all_timeout(
    stream,
    head_buffer.as_slice(),
    response_send_timeout,
    "TLS H1 pre-Hyper response head write failed",
  )
  .await?;
  if skip_body {
    if !keep_alive {
      shutdown_timeout(stream, response_send_timeout).await?;
    }
    return Ok(());
  }

  if chunked {
    write_chunked_body(stream, body, response_send_timeout).await?;
  } else {
    write_content_length_body(stream, body, content_length, response_send_timeout).await?;
  }
  if !keep_alive {
    shutdown_timeout(stream, response_send_timeout).await?;
  }
  Ok(())
}

fn response_status_has_no_body(status: StatusCode) -> bool {
  status.is_informational()
    || status == StatusCode::NO_CONTENT
    || status == StatusCode::NOT_MODIFIED
}

fn single_content_length(headers: &HeaderMap) -> Option<u64> {
  let mut values = headers.get_all(CONTENT_LENGTH).iter();
  let first = values.next()?;
  if values.next().is_some() {
    return None;
  }
  first.to_str().ok()?.trim().parse::<u64>().ok()
}

async fn write_content_length_body<I>(
  stream: &mut I,
  mut body: ProxyBody,
  content_length: Option<u64>,
  response_send_timeout: Duration,
) -> anyhow::Result<()>
where
  I: AsyncWrite + Unpin,
{
  let mut written = 0_u64;
  while let Some(frame) = body.frame().await {
    let frame =
      frame.map_err(|error| anyhow::anyhow!("TLS H1 pre-Hyper response body failed: {error}"))?;
    let Ok(data) = frame.into_data() else {
      continue;
    };
    if data.is_empty() {
      continue;
    }
    written = written.saturating_add(data.len() as u64);
    if content_length.is_some_and(|expected| written > expected) {
      anyhow::bail!("TLS H1 pre-Hyper response body exceeded content-length");
    }
    write_all_timeout(
      stream,
      data.as_ref(),
      response_send_timeout,
      "TLS H1 pre-Hyper response body write failed",
    )
    .await?;
  }
  if let Some(expected) = content_length
    && written != expected
  {
    anyhow::bail!("TLS H1 pre-Hyper response body length mismatch");
  }
  Ok(())
}

async fn write_chunked_body<I>(
  stream: &mut I,
  mut body: ProxyBody,
  response_send_timeout: Duration,
) -> anyhow::Result<()>
where
  I: AsyncWrite + Unpin,
{
  let mut trailers = None;
  while let Some(frame) = body.frame().await {
    let frame =
      frame.map_err(|error| anyhow::anyhow!("TLS H1 pre-Hyper response body failed: {error}"))?;
    match frame.into_data() {
      Ok(data) => {
        if data.is_empty() {
          continue;
        }
        let prefix = format!("{:x}\r\n", data.len());
        write_all_timeout(
          stream,
          prefix.as_bytes(),
          response_send_timeout,
          "TLS H1 pre-Hyper chunk prefix write failed",
        )
        .await?;
        write_all_timeout(
          stream,
          data.as_ref(),
          response_send_timeout,
          "TLS H1 pre-Hyper chunk data write failed",
        )
        .await?;
        write_all_timeout(
          stream,
          b"\r\n",
          response_send_timeout,
          "TLS H1 pre-Hyper chunk suffix write failed",
        )
        .await?;
      }
      Err(frame) => {
        if let Ok(frame_trailers) = frame.into_trailers() {
          trailers = Some(frame_trailers);
        }
      }
    }
  }
  write_all_timeout(
    stream,
    b"0\r\n",
    response_send_timeout,
    "TLS H1 pre-Hyper final chunk write failed",
  )
  .await?;
  if let Some(trailers) = trailers {
    write_trailers(stream, &trailers, response_send_timeout).await?;
  }
  write_all_timeout(
    stream,
    b"\r\n",
    response_send_timeout,
    "TLS H1 pre-Hyper final chunk terminator write failed",
  )
  .await?;
  Ok(())
}

async fn write_trailers<I>(
  stream: &mut I,
  trailers: &HeaderMap,
  response_send_timeout: Duration,
) -> anyhow::Result<()>
where
  I: AsyncWrite + Unpin,
{
  for (name, value) in trailers {
    if !trailer_name_allowed(name) {
      continue;
    }
    write_all_timeout(
      stream,
      name.as_str().as_bytes(),
      response_send_timeout,
      "TLS H1 pre-Hyper trailer name write failed",
    )
    .await?;
    write_all_timeout(
      stream,
      b": ",
      response_send_timeout,
      "TLS H1 pre-Hyper trailer separator write failed",
    )
    .await?;
    write_all_timeout(
      stream,
      value.as_bytes(),
      response_send_timeout,
      "TLS H1 pre-Hyper trailer value write failed",
    )
    .await?;
    write_all_timeout(
      stream,
      b"\r\n",
      response_send_timeout,
      "TLS H1 pre-Hyper trailer line write failed",
    )
    .await?;
  }
  Ok(())
}

fn trailer_name_allowed(name: &HeaderName) -> bool {
  !matches!(
    name.as_str(),
    "connection" | "content-length" | "transfer-encoding" | "upgrade"
  )
}

async fn write_all_timeout<I>(
  stream: &mut I,
  bytes: &[u8],
  timeout: Duration,
  context: &'static str,
) -> anyhow::Result<()>
where
  I: AsyncWrite + Unpin,
{
  tokio::time::timeout(timeout, stream.write_all(bytes))
    .await
    .context(context)??;
  Ok(())
}

async fn shutdown_timeout<I>(stream: &mut I, timeout: Duration) -> anyhow::Result<()>
where
  I: AsyncWrite + Unpin,
{
  tokio::time::timeout(timeout, stream.shutdown())
    .await
    .context("TLS H1 pre-Hyper response shutdown failed")??;
  Ok(())
}

#[cfg(test)]
mod tests;
