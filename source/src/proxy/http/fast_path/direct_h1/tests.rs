use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::header::{CONNECTION, HOST};
use http::{HeaderValue, Request};
use http_body_util::Full;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use super::*;

mod runtime_backend;
mod streaming;
mod transport_error;
mod upgrade_guard;

const OLD_DIRECT_H1_SHARD_SCAN_LIMIT: usize = 4;

#[cfg(target_os = "linux")]
#[test]
fn cancelled_compio_predispatch_never_restarts_the_request_on_hyper() {
  assert!(!compio_predispatch_allows_hyper_fallback(
    CompioDirectH1PredispatchReason::Cancelled
  ));
  for reason in [
    CompioDirectH1PredispatchReason::QueueFull,
    CompioDirectH1PredispatchReason::Unhealthy,
    CompioDirectH1PredispatchReason::Draining,
    CompioDirectH1PredispatchReason::ConnectionLimit,
    CompioDirectH1PredispatchReason::Resolve,
    CompioDirectH1PredispatchReason::Connect,
  ] {
    assert!(compio_predispatch_allows_hyper_fallback(reason));
  }
}

#[test]
fn direct_h1_pools_share_process_connection_admission() {
  let config: crate::config::Config =
    toml::from_str(include_str!("../../../../../config/oxibelt.toml"))
      .expect("example configuration should parse");
  let circuit_breakers = crate::circuit_breakers::CircuitBreakerRuntime::new(&config);
  let pools = DirectH1Pools::new(
    &[upstream("http://backend.internal:18080")],
    circuit_breakers.clone(),
  );
  let pool = pools
    .for_upstream_index(0)
    .expect("plain upstream should create a direct-H1 pool");

  assert!(
    pool
      .circuit_breakers
      .as_ref()
      .is_some_and(|runtime| Arc::ptr_eq(runtime, &circuit_breakers)),
    "Compio connection ownership must use the process-wide circuit-breaker runtime"
  );
}

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
      FastPathRequestBodyMode::Empty,
      false,
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
      FastPathRequestBodyMode::Empty,
      false,
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
      FastPathRequestBodyMode::Empty,
      false,
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
      FastPathRequestBodyMode::Streaming,
      false,
      &request,
    ),
    Some(FastPathTransportMissReason::RequestBody)
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
      FastPathRequestBodyMode::Streaming,
      false,
      &request,
    ),
    Some(FastPathTransportMissReason::RequestBody)
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
      FastPathRequestBodyMode::Empty,
      false,
      &post,
    ),
    Some(FastPathTransportMissReason::UnsupportedRequest)
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
      FastPathRequestBodyMode::Empty,
      false,
      &get,
    ),
    Some(FastPathTransportMissReason::UnsupportedUpstream)
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
fn prevalidated_prepared_request_preserves_origin_form_and_synthesizes_host() {
  let origin = DirectH1Origin::from_url(&Url::parse("http://backend.internal:18080").unwrap())
    .expect("origin should be direct-H1 eligible");
  let mut request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_11)
    .uri("/perf/h2?body=ok")
    .body(empty_body())
    .unwrap();
  mark_prevalidated_direct_h1_request(&mut request);

  let prepared = PreparedDirectH1Request::from_request(request, &origin).unwrap();
  let request = prepared.into_request();

  assert_eq!(request.uri().to_string(), "/perf/h2?body=ok");
  assert_eq!(request.version(), http::Version::HTTP_11);
  assert_eq!(request.headers()[HOST], "backend.internal:18080");
  assert!(
    request
      .extensions()
      .get::<PrevalidatedDirectH1Request>()
      .is_none()
  );
}

#[cfg(target_os = "linux")]
#[test]
fn compio_worker_sharding_stripes_one_origin_across_the_fleet() {
  let upstream = upstream("http://backend.internal:18080");
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let mut shards = (0..4)
    .map(|_| pool.compio_worker_shard(4))
    .collect::<Vec<_>>();
  shards.sort_unstable();
  shards.dedup();
  assert_eq!(shards, vec![0, 1, 2, 3]);
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
  upstream.pool_max_idle_per_host = DIRECT_H1_MAX_SHARDS;
  upstream.idle_timeout_ms = 30_000;
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let target_shard = OLD_DIRECT_H1_SHARD_SCAN_LIMIT + 1;
  for shard_index in 0..target_shard {
    let sender = closed_direct_h1_sender().await?;
    let mut shard = pool.idle_shards[shard_index]
      .lock()
      .expect("test idle shard should lock");
    shard.push(DirectH1IdleConnection {
      sender,
      idle_since: Instant::now() - Duration::from_secs(60),
    });
  }
  {
    let sender = closed_direct_h1_sender().await?;
    let mut shard = pool.idle_shards[target_shard]
      .lock()
      .expect("test idle shard should lock");
    shard.push(DirectH1IdleConnection {
      sender,
      idle_since: Instant::now(),
    });
  }
  pool.idle_count.store(target_shard + 1, Ordering::Release);
  pool.next_shard.store(0, Ordering::Release);

  let taken = pool.take_sender();

  assert!(
    taken.sender.is_some(),
    "take should not report a miss while a later shard has an idle sender"
  );
  assert_eq!(taken.stale_pruned, target_shard);
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
  upstream.pool_max_idle_per_host = DIRECT_H1_MAX_SHARDS;
  let pool = DirectH1Pool::new(&upstream).expect("plain origin should be direct-H1 eligible");
  let sender = closed_direct_h1_sender().await?;
  for shard_index in OLD_DIRECT_H1_SHARD_SCAN_LIMIT + 1..=OLD_DIRECT_H1_SHARD_SCAN_LIMIT + 5 {
    let idle_sender = closed_direct_h1_sender().await?;
    let mut shard = pool.idle_shards[shard_index]
      .lock()
      .expect("test idle shard should lock");
    shard.push(DirectH1IdleConnection {
      sender: idle_sender,
      idle_since: Instant::now(),
    });
  }
  pool
    .idle_count
    .store(OLD_DIRECT_H1_SHARD_SCAN_LIMIT + 1, Ordering::Release);
  let _locks = (0..OLD_DIRECT_H1_SHARD_SCAN_LIMIT)
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
  assert_eq!(
    pool.idle_count.load(Ordering::Acquire),
    OLD_DIRECT_H1_SHARD_SCAN_LIMIT + 2
  );
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
    diagnostic_metrics: false,
    reusable_by_headers: true,
  };
  let body = Full::new(Bytes::from_static(b"ok"))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let collected = recycle_response_body(body, lease, false)
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
  send_and_recycle_direct_get(
    pool.clone(),
    &metrics,
    "/after-stale-reconnect",
    timeouts,
    false,
  )
  .await?;
  send_and_recycle_direct_get(
    pool,
    &metrics,
    "/replacement-should-be-reused",
    timeouts,
    false,
  )
  .await?;

  assert_eq!(
    accepted_connections.load(Ordering::SeqCst),
    1,
    "the live replacement sender should be recycled instead of the stale sender"
  );
  server.abort();
  Ok(())
}

#[tokio::test]
async fn successful_send_records_direct_h1_split_stage_timing() -> anyhow::Result<()> {
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
  let pool = Arc::new(DirectH1Pool::new(&upstream).expect("loopback origin should be eligible"));
  let metrics = Metrics::new();

  send_and_recycle_direct_get(
    pool,
    &metrics,
    "/split-stage-timing",
    direct_h1_test_timeouts(),
    true,
  )
  .await?;

  let body = metrics_prometheus(&metrics);
  assert!(body.contains("stage=\"direct_h1_sender_ready\",outcome=\"ok\"} 1"));
  assert!(body.contains("stage=\"direct_h1_request_submit\",outcome=\"ok\"} 1"));
  assert!(body.contains("stage=\"direct_h1_response_head\",outcome=\"ok\"} 1"));
  assert!(body.contains("stage=\"direct_h1_send_request\",outcome=\"ok\"} 1"));
  server.abort();
  Ok(())
}

#[tokio::test]
async fn huge_first_byte_timeout_does_not_panic_before_sender_error() -> anyhow::Result<()> {
  let mut sender = closed_direct_h1_sender().await?;
  let request = Request::builder()
    .method(Method::GET)
    .uri("/huge-timeout")
    .body(empty_body())
    .expect("test request should be valid");
  let metrics = Metrics::new();

  let result = send_request_with_timing(
    &mut sender,
    request,
    &metrics,
    FastPathMetricProtocol::H1,
    Duration::from_millis(u64::MAX),
    false,
  )
  .await;

  assert!(
    matches!(result, Err(DirectH1SendAttemptError::Hyper(_))),
    "huge timeout should reach sender error without panicking"
  );
  Ok(())
}

async fn send_and_recycle_direct_get(
  pool: Arc<DirectH1Pool>,
  metrics: &Arc<Metrics>,
  path: &str,
  timeouts: EffectiveTimeouts,
  timing_enabled: bool,
) -> anyhow::Result<()> {
  let request = Request::builder()
    .method(Method::GET)
    .uri(path)
    .body(empty_body())
    .expect("test request should be valid");
  let prepared = PreparedDirectH1Request::from_request(request, &pool.origin)?;
  let mut direct = send_prepared_request(
    pool,
    None,
    metrics,
    FastPathMetricProtocol::H1,
    prepared,
    timeouts,
    DirectH1RuntimeBackend::TokioHyper,
    true,
    None,
    crate::config::EarlyHintsMode::Drop,
    DirectH1SendMetricOptions {
      hot_path_metrics: true,
      diagnostic_metrics: false,
      timing_enabled,
    },
  )
  .await?;
  let lease = direct
    .take_lease()
    .expect("direct H1 response should retain its lease");
  direct
    .response
    .into_body()
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?;
  lease.recycle_if_reusable(true);
  Ok(())
}

fn metrics_prometheus(metrics: &Metrics) -> String {
  metrics.prometheus(
    &crate::config::MetricsConfig::default(),
    crate::cache::CacheStats::default(),
    crate::tls::TlsServerSessionStorageStats::default(),
  )
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
    upstream_request: timeout,
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
    max_lifetime_ms: 3_600_000,
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
