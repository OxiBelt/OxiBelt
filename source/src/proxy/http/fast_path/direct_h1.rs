//! Direct upstream HTTP/1.1 transport for the plain-proxy fast path.
//! It bypasses the legacy pooled client only for tightly guarded empty-body H1 requests.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use http::header::{CONNECTION, HOST};
use http::{HeaderMap, HeaderValue, Method, Request, Response, Uri, request};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{debug, warn};
use url::{Position, Url};

use crate::config::{HttpVersion, ProxyProtocolEgressMode, UpstreamConfig};
use crate::metrics::Metrics;
use crate::proxy::http::EffectiveTimeouts;
use crate::proxy::http::body::{BoxError, ProxyBody};

#[derive(Clone, Default)]
pub(crate) struct DirectH1Pools {
  pools: Vec<Option<Arc<DirectH1Pool>>>,
}

impl DirectH1Pools {
  pub(crate) fn new(upstreams: &[UpstreamConfig]) -> Self {
    Self {
      pools: upstreams
        .iter()
        .map(|upstream| DirectH1Pool::new(upstream).map(Arc::new))
        .collect(),
    }
  }

  fn for_upstream_index(&self, upstream_index: usize) -> Option<Arc<DirectH1Pool>> {
    self
      .pools
      .get(upstream_index)
      .and_then(|pool| pool.as_ref())
      .cloned()
  }
}

struct DirectH1Pool {
  origin: DirectH1Origin,
  connect_timeout: Duration,
  idle_timeout: Duration,
  max_idle: usize,
  idle: Mutex<VecDeque<DirectH1IdleConnection>>,
}

struct DirectH1TakeSender {
  sender: Option<SendRequest<ProxyBody>>,
  stale_pruned: usize,
}

impl DirectH1Pool {
  fn new(upstream: &UpstreamConfig) -> Option<Self> {
    let origin = DirectH1Origin::from_url(&upstream.origin)?;
    Some(Self {
      origin,
      connect_timeout: Duration::from_millis(upstream.connect_timeout_ms),
      idle_timeout: Duration::from_millis(upstream.idle_timeout_ms),
      max_idle: upstream.pool_max_idle_per_host,
      idle: Mutex::new(VecDeque::new()),
    })
  }

  fn take_sender(&self) -> DirectH1TakeSender {
    let now = Instant::now();
    let mut idle = self.idle.lock().expect("direct H1 idle pool lock poisoned");
    let mut stale_pruned = 0;
    while let Some(connection) = idle.pop_front() {
      if now.duration_since(connection.idle_since) <= self.idle_timeout {
        return DirectH1TakeSender {
          sender: Some(connection.sender),
          stale_pruned,
        };
      }
      stale_pruned += 1;
    }
    DirectH1TakeSender {
      sender: None,
      stale_pruned,
    }
  }

  fn put_sender(&self, sender: SendRequest<ProxyBody>) -> Result<(), SendRequest<ProxyBody>> {
    if self.max_idle == 0 {
      return Err(sender);
    }

    let now = Instant::now();
    let mut idle = self.idle.lock().expect("direct H1 idle pool lock poisoned");
    idle.retain(|connection| now.duration_since(connection.idle_since) <= self.idle_timeout);
    if idle.len() >= self.max_idle {
      return Err(sender);
    }
    idle.push_back(DirectH1IdleConnection {
      sender,
      idle_since: now,
    });
    Ok(())
  }
}

struct DirectH1Origin {
  host: String,
  port: u16,
  authority: String,
}

impl DirectH1Origin {
  fn from_url(origin: &Url) -> Option<Self> {
    if origin.scheme() != "http" {
      return None;
    }
    let host = origin.host_str()?.to_owned();
    let port = origin.port_or_known_default()?;
    let authority = match origin.port() {
      Some(_) => origin[Position::BeforeHost..Position::AfterPort].to_owned(),
      None => host.clone(),
    };
    Some(Self {
      host,
      port,
      authority,
    })
  }
}

struct DirectH1IdleConnection {
  sender: SendRequest<ProxyBody>,
  idle_since: Instant,
}

pub(super) enum DirectH1SendResult {
  Fallback(Request<ProxyBody>),
  Sent(Result<DirectH1Response, anyhow::Error>),
}

pub(super) struct DirectH1Response {
  pub(super) response: Response<Incoming>,
  lease: Option<DirectH1Lease>,
}

impl DirectH1Response {
  pub(super) fn take_lease(&mut self) -> Option<DirectH1Lease> {
    self.lease.take()
  }
}

pub(super) struct DirectH1Lease {
  pool: Arc<DirectH1Pool>,
  metrics: Arc<Metrics>,
  sender: SendRequest<ProxyBody>,
  reusable_by_headers: bool,
}

impl DirectH1Lease {
  pub(super) async fn recycle_if_reusable(self, body_consumed: bool) {
    if body_consumed && self.reusable_by_headers {
      if self.pool.put_sender(self.sender).is_err() {
        self.metrics.record_direct_h1_pool_event("drop");
      }
    } else {
      self.metrics.record_direct_h1_pool_event("drop");
    }
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn try_send_direct_h1(
  pools: &DirectH1Pools,
  metrics: &Arc<Metrics>,
  upstream_index: usize,
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  outbound: Request<ProxyBody>,
  timeouts: EffectiveTimeouts,
) -> DirectH1SendResult {
  let protocol = fast_path_metric_protocol(request_version);
  if let Some(reason) = direct_h1_guard_miss(
    upstream,
    upstream_version,
    request_version,
    direct_selection_used,
    request_body_proven_empty,
    &outbound,
  ) {
    metrics.record_fast_path_transport(protocol, "miss", reason);
    return DirectH1SendResult::Fallback(outbound);
  }

  let Some(pool) = pools.for_upstream_index(upstream_index) else {
    metrics.record_fast_path_transport(protocol, "miss", "unsupported_upstream");
    return DirectH1SendResult::Fallback(outbound);
  };

  let prepared = match PreparedDirectH1Request::from_request(outbound, &pool.origin) {
    Ok(prepared) => prepared,
    Err(error) => {
      metrics.record_fast_path_transport(protocol, "miss", "unsupported_request");
      return DirectH1SendResult::Sent(Err(error));
    }
  };

  let result = send_prepared_request(pool, metrics, prepared, timeouts).await;
  match &result {
    Ok(_) => metrics.record_fast_path_transport(protocol, "hit", "used"),
    Err(error) if error.to_string().contains("timed out") => {
      metrics.record_fast_path_transport(protocol, "miss", "connect_error");
    }
    Err(_) => metrics.record_fast_path_transport(protocol, "miss", "send_error"),
  }
  DirectH1SendResult::Sent(result)
}

fn direct_h1_guard_miss(
  upstream: &UpstreamConfig,
  upstream_version: HttpVersion,
  request_version: http::Version,
  direct_selection_used: bool,
  request_body_proven_empty: bool,
  outbound: &Request<ProxyBody>,
) -> Option<&'static str> {
  if !matches!(
    request_version,
    http::Version::HTTP_11 | http::Version::HTTP_2 | http::Version::HTTP_3
  ) || !direct_selection_used
    || !matches!(outbound.method(), &Method::GET | &Method::HEAD)
  {
    return Some("unsupported_request");
  }
  if upstream_version != HttpVersion::H1
    || upstream.origin.scheme() != "http"
    || upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
  {
    return Some("unsupported_upstream");
  }
  if !request_body_proven_empty || !outbound.body().is_end_stream() {
    return Some("request_body");
  }
  None
}

async fn send_prepared_request(
  pool: Arc<DirectH1Pool>,
  metrics: &Arc<Metrics>,
  prepared: PreparedDirectH1Request,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<DirectH1Response> {
  metrics.record_http_upstream_client_request("h1", "http", "primary");

  let reused_sender = pool.take_sender();
  record_stale_direct_h1_senders(metrics, reused_sender.stale_pruned);
  let reused = reused_sender.sender.is_some();
  if reused {
    metrics.record_direct_h1_pool_event("hit");
  } else {
    metrics.record_direct_h1_pool_event("miss");
  }
  let mut sender = match reused_sender.sender {
    Some(sender) => sender,
    None => connect_sender(&pool, metrics).await?,
  };

  let mut retry = reused.then(|| prepared.retry_request());
  let response = match tokio::time::timeout(
    timeouts.upstream_first_byte,
    sender.send_request(prepared.into_request()),
  )
  .await
  {
    Ok(Ok(response)) => response,
    Ok(Err(error)) if reused => {
      debug!(error = %error, "direct H1 upstream sender failed; reconnecting once");
      metrics.record_direct_h1_pool_event("reconnect");
      sender = connect_sender(&pool, metrics).await?;
      let retry = retry
        .take()
        .expect("reused direct H1 sends should retain one retry request");
      tokio::time::timeout(
        timeouts.upstream_first_byte,
        sender.send_request(retry.into_request()),
      )
      .await
      .context("direct H1 upstream first-byte timeout")??
    }
    Ok(Err(error)) => return Err(error.into()),
    Err(_) => anyhow::bail!("direct H1 upstream first-byte timed out"),
  };

  let reusable_by_headers = h1_response_allows_reuse(response.headers());
  Ok(DirectH1Response {
    response,
    lease: Some(DirectH1Lease {
      pool,
      metrics: metrics.clone(),
      sender,
      reusable_by_headers,
    }),
  })
}

fn record_stale_direct_h1_senders(metrics: &Metrics, stale_pruned: usize) {
  for _ in 0..stale_pruned {
    metrics.record_direct_h1_pool_event("stale");
  }
}

async fn connect_sender(
  pool: &Arc<DirectH1Pool>,
  metrics: &Arc<Metrics>,
) -> anyhow::Result<SendRequest<ProxyBody>> {
  metrics.record_http_upstream_client_pool_miss("h1", "http", "primary");
  let stream = tokio::time::timeout(
    pool.connect_timeout,
    TcpStream::connect((pool.origin.host.as_str(), pool.origin.port)),
  )
  .await
  .context("direct H1 upstream connect timed out")?
  .with_context(|| {
    format!(
      "failed to connect direct H1 upstream {}:{}",
      pool.origin.host, pool.origin.port
    )
  })?;
  stream
    .set_nodelay(true)
    .context("failed to enable TCP_NODELAY for direct H1 upstream")?;
  let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
    .await
    .context("failed to establish direct H1 upstream connection")?;
  metrics.record_http_upstream_client_connection_created("h1", "http", "primary");
  tokio::spawn(async move {
    if let Err(error) = connection.await {
      warn!(error = %error, "direct H1 upstream connection closed with error");
    }
  });
  Ok(sender)
}

struct PreparedDirectH1Request {
  method: Method,
  uri: Uri,
  headers: HeaderMap,
}

struct RetryDirectH1Request {
  method: Method,
  uri: Uri,
  headers: HeaderMap,
}

impl PreparedDirectH1Request {
  fn from_request(request: Request<ProxyBody>, origin: &DirectH1Origin) -> anyhow::Result<Self> {
    let (mut parts, _body) = request.into_parts();
    ensure_host_header(&mut parts, origin)?;
    let path_and_query = parts
      .uri
      .path_and_query()
      .cloned()
      .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
    let mut uri_parts = http::uri::Parts::default();
    uri_parts.path_and_query = Some(path_and_query);
    let uri = Uri::from_parts(uri_parts).context("failed to build direct H1 origin-form URI")?;
    Ok(Self {
      method: parts.method,
      uri,
      headers: parts.headers,
    })
  }

  fn retry_request(&self) -> RetryDirectH1Request {
    RetryDirectH1Request {
      method: self.method.clone(),
      uri: self.uri.clone(),
      headers: self.headers.clone(),
    }
  }

  fn into_request(self) -> Request<ProxyBody> {
    let mut request = Request::builder()
      .method(self.method)
      .version(http::Version::HTTP_11)
      .uri(self.uri)
      .body(empty_body())
      .expect("direct H1 request parts should be valid");
    *request.headers_mut() = self.headers;
    request
  }
}

impl RetryDirectH1Request {
  fn into_request(self) -> Request<ProxyBody> {
    let mut request = Request::builder()
      .method(self.method)
      .version(http::Version::HTTP_11)
      .uri(self.uri)
      .body(empty_body())
      .expect("direct H1 retry request parts should be valid");
    *request.headers_mut() = self.headers;
    request
  }
}

fn ensure_host_header(parts: &mut request::Parts, origin: &DirectH1Origin) -> anyhow::Result<()> {
  if parts.headers.contains_key(HOST) {
    return Ok(());
  }
  let authority = parts
    .uri
    .authority()
    .map(|authority| authority.as_str())
    .unwrap_or(origin.authority.as_str());
  let value =
    HeaderValue::from_str(authority).context("upstream authority is not a header value")?;
  parts.headers.insert(HOST, value);
  Ok(())
}

fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

fn h1_response_allows_reuse(headers: &HeaderMap) -> bool {
  !connection_header_contains(headers, "close")
}

fn connection_header_contains(headers: &HeaderMap, token: &str) -> bool {
  headers.get_all(CONNECTION).iter().any(|value| {
    value
      .as_bytes()
      .split(|byte| *byte == b',')
      .filter_map(|part| std::str::from_utf8(part).ok())
      .any(|part| part.trim().eq_ignore_ascii_case(token))
  })
}

fn fast_path_metric_protocol(version: http::Version) -> &'static str {
  match version {
    http::Version::HTTP_10 | http::Version::HTTP_11 => "h1",
    http::Version::HTTP_2 => "h2",
    http::Version::HTTP_3 => "h3",
    _ => "other",
  }
}

#[cfg(test)]
mod tests;
