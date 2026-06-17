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
fn guard_accepts_direct_empty_http3_get_to_plain_h1_upstream() {
  let upstream = upstream("http://backend.internal:18080");
  let request = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/perf/h3?body=ok")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h1_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_3,
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
fn guard_rejects_http3_when_empty_body_is_not_proven() {
  let upstream = upstream("http://backend.internal:18080");
  let request = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/perf/h3?body=ok")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h1_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_3,
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
  let request = prepared.into_request();

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
  let request = prepared.into_request();

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
    pool.put_sender(stale_sender).is_ok(),
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
