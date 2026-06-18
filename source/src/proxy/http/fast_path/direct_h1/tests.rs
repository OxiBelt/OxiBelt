use std::sync::atomic::{AtomicUsize, Ordering};

use http::header::{CONNECTION, HOST};
use http::{HeaderValue, Request};
use http_body_util::Full;
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

#[tokio::test]
async fn pool_keeps_exact_max_idle_across_shards() -> anyhow::Result<()> {
  let mut upstream = upstream("http://backend.internal:18080");
  upstream.pool_max_idle_per_host = 2;
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");

  assert!(pool.put_sender(closed_direct_h1_sender().await?).is_ok());
  assert!(pool.put_sender(closed_direct_h1_sender().await?).is_ok());
  assert!(
    pool.put_sender(closed_direct_h1_sender().await?).is_err(),
    "pool should preserve the configured total idle cap"
  );
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 2);
  Ok(())
}

#[tokio::test]
async fn pool_prunes_stale_senders_on_take() -> anyhow::Result<()> {
  let mut upstream = upstream("http://backend.internal:18080");
  upstream.idle_timeout_ms = 1;
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let sender = closed_direct_h1_sender().await?;
  {
    let mut shard = pool.idle_shards[0]
      .lock()
      .expect("test idle shard should lock");
    shard.push(DirectH1IdleConnection {
      sender,
      idle_since: Instant::now() - Duration::from_secs(1),
    });
    pool.idle_count.store(1, Ordering::Release);
  }

  let taken = pool.take_sender();

  assert!(taken.sender.is_none());
  assert_eq!(taken.stale_pruned, 1);
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 0);
  Ok(())
}

#[tokio::test]
async fn pool_take_skips_contended_shard() -> anyhow::Result<()> {
  let mut upstream = upstream("http://backend.internal:18080");
  upstream.pool_max_idle_per_host = 2;
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let first_sender = closed_direct_h1_sender().await?;
  let second_sender = closed_direct_h1_sender().await?;
  {
    let mut first = pool.idle_shards[0]
      .lock()
      .expect("test idle shard should lock");
    first.push(DirectH1IdleConnection {
      sender: first_sender,
      idle_since: Instant::now(),
    });
  }
  {
    let mut second = pool.idle_shards[1]
      .lock()
      .expect("test idle shard should lock");
    second.push(DirectH1IdleConnection {
      sender: second_sender,
      idle_since: Instant::now(),
    });
  }
  pool.idle_count.store(2, Ordering::Release);
  pool.next_shard.store(0, Ordering::Release);

  let _locked = pool.idle_shards[0]
    .lock()
    .expect("test idle shard should lock");
  let taken = pool.take_sender();

  assert!(
    taken.sender.is_some(),
    "take should scan another shard instead of blocking"
  );
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 1);
  Ok(())
}

#[tokio::test]
async fn pool_take_scans_all_shards_before_missing() -> anyhow::Result<()> {
  let mut upstream = upstream("http://backend.internal:18080");
  upstream.pool_max_idle_per_host = DIRECT_H1_SHARD_SCAN_LIMIT + 2;
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let sender = closed_direct_h1_sender().await?;
  let target_shard = DIRECT_H1_SHARD_SCAN_LIMIT + 1;
  {
    let mut shard = pool.idle_shards[target_shard]
      .lock()
      .expect("test idle shard should lock");
    shard.push(DirectH1IdleConnection {
      sender,
      idle_since: Instant::now(),
    });
  }
  pool.idle_count.store(1, Ordering::Release);
  pool.next_shard.store(0, Ordering::Release);

  let taken = pool.take_sender();

  assert!(
    taken.sender.is_some(),
    "take should not report a miss while a later shard has an idle sender"
  );
  assert_eq!(taken.miss_reason, DirectH1TakeMissReason::None);
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 0);
  Ok(())
}

#[tokio::test]
async fn pool_take_reports_locked_miss_when_idle_sender_is_contended() -> anyhow::Result<()> {
  let upstream = upstream("http://backend.internal:18080");
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let sender = closed_direct_h1_sender().await?;
  {
    let mut shard = pool.idle_shards[0]
      .lock()
      .expect("test idle shard should lock");
    shard.push(DirectH1IdleConnection {
      sender,
      idle_since: Instant::now(),
    });
  }
  pool.idle_count.store(1, Ordering::Release);
  pool.next_shard.store(0, Ordering::Release);

  let _locked = pool.idle_shards[0]
    .lock()
    .expect("test idle shard should lock");
  let taken = pool.take_sender();

  assert!(taken.sender.is_none());
  assert_eq!(taken.miss_reason, DirectH1TakeMissReason::Locked);
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 1);
  Ok(())
}

#[tokio::test]
async fn pool_put_scans_all_shards_before_dropping() -> anyhow::Result<()> {
  let mut upstream = upstream("http://backend.internal:18080");
  upstream.pool_max_idle_per_host = DIRECT_H1_SHARD_SCAN_LIMIT + 2;
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let sender = closed_direct_h1_sender().await?;
  let _locks = (0..DIRECT_H1_SHARD_SCAN_LIMIT)
    .map(|index| {
      pool.idle_shards[index]
        .lock()
        .expect("test idle shard should lock")
    })
    .collect::<Vec<_>>();
  pool.next_shard.store(0, Ordering::Release);

  assert!(
    pool.put_sender(sender).is_ok(),
    "put should use a later available shard instead of dropping"
  );
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 1);
  Ok(())
}

#[tokio::test]
async fn pool_put_drops_when_only_shard_is_contended() -> anyhow::Result<()> {
  let upstream = upstream("http://backend.internal:18080");
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let sender = closed_direct_h1_sender().await?;
  let _locked = pool.idle_shards[0]
    .lock()
    .expect("test idle shard should lock");

  assert!(
    pool.put_sender(sender).is_err(),
    "put should avoid blocking behind a contended shard"
  );
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 0);
  Ok(())
}

#[tokio::test]
async fn streamed_body_recycles_direct_h1_sender_on_eof() -> anyhow::Result<()> {
  let upstream = upstream("http://backend.internal:18080");
  let pool =
    Arc::new(DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible"));
  let lease = DirectH1Lease {
    pool: pool.clone(),
    metrics: Metrics::new(),
    sender: closed_direct_h1_sender().await?,
    reusable_by_headers: true,
  };
  let body = Full::new(Bytes::from_static(b"ok"))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let collected = recycle_body_on_eof(body, lease)
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!(error))?
    .to_bytes();

  assert_eq!(collected.as_ref(), b"ok");
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 1);
  Ok(())
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
  lease.recycle_if_reusable(true);
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
