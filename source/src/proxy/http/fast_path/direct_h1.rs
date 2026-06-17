//! Direct upstream HTTP/1.1 transport for the plain-proxy fast path.
//! It bypasses the legacy pooled client only for tightly guarded empty-body H1 requests.

use std::collections::VecDeque;
use std::sync::Arc;
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
use tokio::sync::Mutex;
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

  async fn take_sender(&self) -> Option<SendRequest<ProxyBody>> {
    let now = Instant::now();
    let mut idle = self.idle.lock().await;
    while let Some(connection) = idle.pop_front() {
      if now.duration_since(connection.idle_since) <= self.idle_timeout {
        return Some(connection.sender);
      }
    }
    None
  }

  async fn put_sender(&self, sender: SendRequest<ProxyBody>) -> Result<(), SendRequest<ProxyBody>> {
    if self.max_idle == 0 {
      return Err(sender);
    }

    let now = Instant::now();
    let mut idle = self.idle.lock().await;
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
  sender: SendRequest<ProxyBody>,
  reusable_by_headers: bool,
}

impl DirectH1Lease {
  pub(super) async fn recycle_if_reusable(self, body_consumed: bool) {
    if body_consumed && self.reusable_by_headers {
      let _ = self.pool.put_sender(self.sender).await;
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
    http::Version::HTTP_11 | http::Version::HTTP_2
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

  let reused_sender = pool.take_sender().await;
  let reused = reused_sender.is_some();
  let mut sender = match reused_sender {
    Some(sender) => sender,
    None => connect_sender(&pool, metrics).await?,
  };

  let response = match tokio::time::timeout(
    timeouts.upstream_first_byte,
    sender.send_request(prepared.request()),
  )
  .await
  {
    Ok(Ok(response)) => response,
    Ok(Err(error)) if reused => {
      debug!(error = %error, "direct H1 upstream sender failed; reconnecting once");
      sender = connect_sender(&pool, metrics).await?;
      tokio::time::timeout(
        timeouts.upstream_first_byte,
        sender.send_request(prepared.request()),
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
      sender,
      reusable_by_headers,
    }),
  })
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

#[derive(Clone)]
struct PreparedDirectH1Request {
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

  fn request(&self) -> Request<ProxyBody> {
    let mut request = Request::builder()
      .method(self.method.clone())
      .version(http::Version::HTTP_11)
      .uri(self.uri.clone())
      .body(empty_body())
      .expect("direct H1 request parts should be valid");
    *request.headers_mut() = self.headers.clone();
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
mod tests {
  use std::sync::atomic::{AtomicUsize, Ordering};

  use http::header::{CONNECTION, HOST};
  use http::{HeaderValue, Request};
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpListener;

  use super::*;

  #[test]
  fn guard_accepts_direct_empty_http11_get_to_plain_h1_upstream() {
    let upstream = upstream("http://backend.internal:18080");
    let request = Request::builder()
      .method(Method::GET)
      .uri("http://backend.internal/perf/h1?body=ok")
      .body(empty_body())
      .unwrap();

    assert_eq!(
      direct_h1_guard_miss(
        &upstream,
        HttpVersion::H1,
        http::Version::HTTP_11,
        true,
        true,
        &request,
      ),
      None
    );
  }

  #[test]
  fn guard_accepts_direct_empty_http2_get_to_plain_h1_upstream() {
    let upstream = upstream("http://backend.internal:18080");
    let request = Request::builder()
      .method(Method::GET)
      .uri("http://backend.internal/perf/h2?body=ok")
      .body(empty_body())
      .unwrap();

    assert_eq!(
      direct_h1_guard_miss(
        &upstream,
        HttpVersion::H1,
        http::Version::HTTP_2,
        true,
        true,
        &request,
      ),
      None
    );
  }

  #[test]
  fn guard_rejects_http2_when_empty_body_is_not_proven() {
    let upstream = upstream("http://backend.internal:18080");
    let request = Request::builder()
      .method(Method::GET)
      .uri("http://backend.internal/perf/h2?body=ok")
      .body(empty_body())
      .unwrap();

    assert_eq!(
      direct_h1_guard_miss(
        &upstream,
        HttpVersion::H1,
        http::Version::HTTP_2,
        true,
        false,
        &request,
      ),
      Some("request_body")
    );
  }

  #[test]
  fn guard_rejects_non_get_head_or_non_plain_upstream() {
    let plain = upstream("http://backend.internal:18080");
    let post = Request::builder()
      .method(Method::POST)
      .uri("http://backend.internal/perf/h1?body=ok")
      .body(empty_body())
      .unwrap();
    assert_eq!(
      direct_h1_guard_miss(
        &plain,
        HttpVersion::H1,
        http::Version::HTTP_11,
        true,
        true,
        &post,
      ),
      Some("unsupported_request")
    );

    let https = upstream("https://backend.internal:18443");
    let get = Request::builder()
      .method(Method::GET)
      .uri("https://backend.internal/perf/h1?body=ok")
      .body(empty_body())
      .unwrap();
    assert_eq!(
      direct_h1_guard_miss(
        &https,
        HttpVersion::H1,
        http::Version::HTTP_11,
        true,
        true,
        &get,
      ),
      Some("unsupported_upstream")
    );
  }

  #[test]
  fn prepared_request_uses_origin_form_and_synthesizes_host() {
    let origin = DirectH1Origin::from_url(&Url::parse("http://backend.internal:18080").unwrap())
      .expect("origin should be direct-H1 eligible");
    let request = Request::builder()
      .method(Method::GET)
      .uri("http://backend.internal:18080/perf/h1?body=ok")
      .body(empty_body())
      .unwrap();

    let prepared = PreparedDirectH1Request::from_request(request, &origin).unwrap();
    let request = prepared.request();

    assert_eq!(request.uri().to_string(), "/perf/h1?body=ok");
    assert_eq!(request.headers()[HOST], "backend.internal:18080");
  }

  #[test]
  fn prepared_request_preserves_existing_host() {
    let origin = DirectH1Origin::from_url(&Url::parse("http://backend.internal").unwrap())
      .expect("origin should be direct-H1 eligible");
    let request = Request::builder()
      .method(Method::GET)
      .uri("http://backend.internal/perf/h1?body=ok")
      .header(HOST, "public.example")
      .body(empty_body())
      .unwrap();

    let prepared = PreparedDirectH1Request::from_request(request, &origin).unwrap();
    let request = prepared.request();

    assert_eq!(request.headers()[HOST], "public.example");
  }

  #[test]
  fn connection_close_disables_reuse() {
    let mut headers = HeaderMap::new();
    assert!(h1_response_allows_reuse(&headers));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, close"));
    assert!(!h1_response_allows_reuse(&headers));
  }

  #[tokio::test]
  async fn reconnect_recycles_replacement_sender_after_stale_reuse() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(serve_keepalive_listener(
      listener,
      accepted_connections.clone(),
    ));

    let mut upstream = upstream(&origin);
    upstream.connect_timeout_ms = 1_000;
    upstream.first_byte_timeout_ms = 1_000;
    upstream.idle_timeout_ms = 30_000;
    let pool = Arc::new(DirectH1Pool::new(&upstream).expect("loopback origin should be eligible"));
    let stale_sender = closed_direct_h1_sender().await?;
    assert!(
      pool.put_sender(stale_sender).await.is_ok(),
      "test sender should fit in the idle pool"
    );

    let metrics = Metrics::new();
    let timeouts = direct_h1_test_timeouts();
    send_and_recycle_direct_get(pool.clone(), &metrics, "/after-stale-reconnect", timeouts).await?;
    send_and_recycle_direct_get(pool, &metrics, "/replacement-should-be-reused", timeouts).await?;

    assert_eq!(
      accepted_connections.load(Ordering::SeqCst),
      1,
      "the live replacement sender should be recycled instead of the stale sender"
    );
    server.abort();
    Ok(())
  }

  async fn send_and_recycle_direct_get(
    pool: Arc<DirectH1Pool>,
    metrics: &Arc<Metrics>,
    path: &str,
    timeouts: EffectiveTimeouts,
  ) -> anyhow::Result<()> {
    let request = Request::builder()
      .method(Method::GET)
      .uri(path)
      .body(empty_body())
      .expect("test request should be valid");
    let prepared = PreparedDirectH1Request::from_request(request, &pool.origin)?;
    let mut direct = send_prepared_request(pool, metrics, prepared, timeouts).await?;
    let lease = direct
      .take_lease()
      .expect("direct H1 response should retain its lease");
    direct.response.into_body().collect().await?;
    lease.recycle_if_reusable(true).await;
    Ok(())
  }

  async fn closed_direct_h1_sender() -> anyhow::Result<SendRequest<ProxyBody>> {
    let (client_io, server_io) = tokio::io::duplex(64);
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
      .await
      .context("test direct H1 handshake should succeed")?;
    drop(server_io);
    let connection = tokio::spawn(connection);
    let _ = tokio::time::timeout(Duration::from_secs(1), connection)
      .await
      .context("test direct H1 connection should close")?
      .context("test direct H1 connection task should join")?;
    Ok(sender)
  }

  async fn serve_keepalive_listener(listener: TcpListener, accepted_connections: Arc<AtomicUsize>) {
    loop {
      let Ok((stream, _)) = listener.accept().await else {
        return;
      };
      accepted_connections.fetch_add(1, Ordering::SeqCst);
      tokio::spawn(async move {
        let _ = serve_keepalive_connection(stream).await;
      });
    }
  }

  async fn serve_keepalive_connection(mut stream: TcpStream) -> std::io::Result<()> {
    while read_request_head(&mut stream).await? {
      stream
        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
        .await?;
    }
    Ok(())
  }

  async fn read_request_head(stream: &mut TcpStream) -> std::io::Result<bool> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
      let read = stream.read(&mut buffer).await?;
      if read == 0 {
        return Ok(false);
      }
      request.extend_from_slice(&buffer[..read]);
      if request.windows(4).any(|window| window == b"\r\n\r\n") {
        return Ok(true);
      }
      if request.len() > 8192 {
        return Err(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          "test request head exceeded limit",
        ));
      }
    }
  }

  fn direct_h1_test_timeouts() -> EffectiveTimeouts {
    let timeout = Duration::from_secs(1);
    EffectiveTimeouts {
      response_send: timeout,
      websocket_idle: timeout,
      webtransport_idle: timeout,
      upstream_connect: timeout,
      upstream_first_byte: timeout,
      upstream_read: timeout,
      upstream_send: timeout,
    }
  }

  fn upstream(origin: &str) -> UpstreamConfig {
    UpstreamConfig {
      name: "backend".to_string(),
      origin: Url::parse(origin).unwrap(),
      max_http_version: HttpVersion::H1,
      connect_timeout_ms: 100,
      request_timeout_ms: 100,
      first_byte_timeout_ms: 100,
      read_timeout_ms: 100,
      send_timeout_ms: 100,
      idle_timeout_ms: 100,
      pool_max_idle_per_host: 1,
      preserve_host: false,
      websocket: false,
      webrtc: false,
      webtransport: false,
      proxy_protocol_egress: ProxyProtocolEgressMode::Off,
      tls: Default::default(),
      extra_trusted_ca_certs: Vec::new(),
    }
  }
}
