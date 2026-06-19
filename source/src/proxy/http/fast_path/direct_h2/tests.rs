use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};

use http::Request;
use hyper::service::service_fn;
use tokio::io::ReadBuf;
use tokio::sync::{Barrier, oneshot, watch};

use super::*;

#[test]
fn guard_accepts_direct_empty_get_to_h2c_upstream() {
  let upstream = upstream("http://backend.internal:18082");
  let request = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      true,
      &request,
    ),
    None
  );
}

#[test]
fn guard_accepts_direct_empty_head_to_tls_h2_upstream() {
  let upstream = upstream("https://backend.internal:18444");
  let request = Request::builder()
    .method(Method::HEAD)
    .uri("https://backend.internal/perf/h2?body=ok")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_3,
      true,
      true,
      &request,
    ),
    None
  );
}

#[test]
fn guard_rejects_non_h2_upstream_or_unproven_body() {
  let mut upstream = upstream("http://backend.internal:18082");
  let request = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();

  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_2,
      true,
      true,
      &request,
    ),
    Some("unsupported_upstream")
  );
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      false,
      &request,
    ),
    Some("request_body")
  );

  upstream.proxy_protocol_egress = ProxyProtocolEgressMode::V1;
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      true,
      &request,
    ),
    Some("unsupported_upstream")
  );
}

#[test]
fn guard_rejects_method_or_non_direct_selection() {
  let upstream = upstream("http://backend.internal:18082");
  let post = Request::builder()
    .method(Method::POST)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      true,
      &post,
    ),
    Some("unsupported_request")
  );

  let get = Request::builder()
    .method(Method::GET)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      false,
      true,
      &get,
    ),
    Some("unsupported_request")
  );
}

#[test]
fn prepared_request_requires_absolute_uri_and_sets_h2_version() {
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_11)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  let prepared = PreparedDirectH2Request::from_request(request).unwrap();
  assert_eq!(prepared.request.version(), http::Version::HTTP_2);
  assert_eq!(
    prepared.request.uri().to_string(),
    "http://backend.internal/perf/h2c?body=ok"
  );

  let relative = Request::builder()
    .method(Method::GET)
    .uri("/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  assert!(PreparedDirectH2Request::from_request(relative).is_err());
}

#[tokio::test]
async fn sender_single_flights_cold_pool_connection_creation() {
  let connect_attempts = Arc::new(AtomicUsize::new(0));
  let (first_connect_tx, first_connect_rx) = oneshot::channel();
  let first_connect_tx = Arc::new(Mutex::new(Some(first_connect_tx)));
  let (release_tx, release_rx) = watch::channel(false);

  let pool = Arc::new(DirectH2Pool {
    origin: DirectH2Origin {
      scheme: "http",
      host: "127.0.0.1".to_string(),
      port: 80,
    },
    connect_timeout: Duration::from_secs(1),
    idle_timeout: Duration::from_secs(30),
    http2_config: ProxyHttp2Config::default(),
    tls_config: None,
    entry: RwLock::new(None),
  });
  let metrics = Metrics::new();
  let request_count = 8;
  let start = Arc::new(Barrier::new(request_count + 1));
  let mut handles = Vec::with_capacity(request_count);
  for _ in 0..request_count {
    let pool = pool.clone();
    let metrics = metrics.clone();
    let start = start.clone();
    let connect_attempts = connect_attempts.clone();
    let first_connect_tx = first_connect_tx.clone();
    let release_rx = release_rx.clone();
    handles.push(tokio::spawn(async move {
      start.wait().await;
      pool
        .sender_with(&metrics, move || async move {
          let attempt = connect_attempts.fetch_add(1, Ordering::SeqCst) + 1;
          if attempt == 1
            && let Some(sender) = first_connect_tx.lock().unwrap().take()
          {
            let _ = sender.send(());
          }

          let (client_io, server_io) = tokio::io::duplex(1024 * 64);
          let mut release_rx = release_rx;
          tokio::spawn(async move {
            while !*release_rx.borrow() {
              if release_rx.changed().await.is_err() {
                return;
              }
            }

            let service =
              service_fn(|_request| async { Ok::<_, Infallible>(Response::new(empty_body())) });
            let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
            let http2_config = ProxyHttp2Config::default();
            crate::h2_tuning::apply_server_defaults(&mut builder, &http2_config);
            let _ = builder
              .serve_connection(TokioIo::new(server_io), service)
              .await;
          });
          let http2_config = ProxyHttp2Config::default();
          h2_handshake(client_io, &http2_config).await
        })
        .await
    }));
  }
  start.wait().await;

  tokio::time::timeout(Duration::from_secs(1), first_connect_rx)
    .await
    .expect("direct H2 pool should start the first upstream connector")
    .expect("connector should signal the first upstream attempt");
  for _ in 0..10 {
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
      connect_attempts.load(Ordering::SeqCst),
      1,
      "cold direct H2 pool must not start redundant upstream connectors"
    );
  }

  release_tx.send(true).unwrap();
  for handle in handles {
    handle
      .await
      .expect("sender task should not panic")
      .expect("sender task should complete after the server handshake is released");
  }
  assert_eq!(connect_attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sender_timeout_bounds_single_flight_wait() {
  let pool = Arc::new(direct_h2_test_pool(Duration::from_secs(5)));
  let metrics = Metrics::new();
  let (leader_started_tx, leader_started_rx) = oneshot::channel();
  let leader_started_tx = Arc::new(Mutex::new(Some(leader_started_tx)));
  let (release_tx, release_rx) = watch::channel(false);
  let leader = {
    let pool = pool.clone();
    let metrics = metrics.clone();
    let leader_started_tx = leader_started_tx.clone();
    let release_rx = release_rx.clone();
    tokio::spawn(async move {
      pool
        .sender_with(&metrics, move || async move {
          if let Some(sender) = leader_started_tx.lock().unwrap().take() {
            let _ = sender.send(());
          }
          let mut release_rx = release_rx;
          while !*release_rx.borrow() {
            if release_rx.changed().await.is_err() {
              anyhow::bail!("test connector release channel closed");
            }
          }
          successful_test_sender().await
        })
        .await
    })
  };

  tokio::time::timeout(Duration::from_secs(1), leader_started_rx)
    .await
    .expect("leader should start the single-flight connector")
    .expect("single-flight connector should signal startup");

  let result = tokio::time::timeout(Duration::from_secs(1), {
    let pool = pool.clone();
    let metrics = metrics.clone();
    async move {
      sender_with_first_byte_timeout(
        pool.sender_with(&metrics, successful_test_sender),
        Duration::from_millis(100),
      )
      .await
    }
  })
  .await
  .expect("waiter should return within its first-byte budget");
  let error = result.expect_err("waiter should time out while queued behind single-flight");
  assert!(
    error.to_string().contains("first-byte timed out"),
    "unexpected waiter error: {error:#}"
  );

  let _ = release_tx.send(true);
  leader
    .await
    .expect("leader task should not panic")
    .expect("leader sender should complete after release");
}

#[tokio::test]
async fn h2_handshake_uses_connect_timeout() {
  let http2_config = ProxyHttp2Config::default();
  let result = tokio::time::timeout(
    Duration::from_secs(1),
    h2_handshake_with_timeout(PendingIo, &http2_config, Duration::from_millis(100)),
  )
  .await
  .expect("stalled H2 handshake should be bounded by connect timeout");
  let error = result.expect_err("stalled H2 handshake should fail");
  assert!(
    error.to_string().contains("HTTP/2 handshake timed out"),
    "unexpected handshake error: {error:#}"
  );
}

#[tokio::test]
async fn sender_acquisition_timeout_releases_pool_lock() {
  let pool = Arc::new(direct_h2_test_pool(Duration::from_secs(5)));
  let metrics = Metrics::new();
  let (connector_started_tx, connector_started_rx) = oneshot::channel();
  let connector_started_tx = Arc::new(Mutex::new(Some(connector_started_tx)));
  let (_release_tx, release_rx) = watch::channel(false);

  let result = tokio::time::timeout(Duration::from_secs(1), {
    let pool = pool.clone();
    let metrics = metrics.clone();
    let connector_started_tx = connector_started_tx.clone();
    let release_rx = release_rx.clone();
    async move {
      sender_with_first_byte_timeout(
        pool.sender_with(&metrics, move || async move {
          if let Some(sender) = connector_started_tx.lock().unwrap().take() {
            let _ = sender.send(());
          }
          let mut release_rx = release_rx;
          while !*release_rx.borrow() {
            if release_rx.changed().await.is_err() {
              anyhow::bail!("test connector release channel closed");
            }
          }
          successful_test_sender().await
        }),
        Duration::from_millis(100),
      )
      .await
    }
  })
  .await
  .expect("sender acquisition timeout should complete promptly");
  let error = result.expect_err("sender acquisition should time out");
  assert!(
    error.to_string().contains("first-byte timed out"),
    "unexpected sender acquisition error: {error:#}"
  );

  tokio::time::timeout(Duration::from_secs(1), connector_started_rx)
    .await
    .expect("connector should have entered the write-locked section")
    .expect("connector should signal startup");

  let successful = tokio::time::timeout(Duration::from_secs(1), {
    let pool = pool.clone();
    let metrics = metrics.clone();
    async move { pool.sender_with(&metrics, successful_test_sender).await }
  })
  .await
  .expect("pool lock should be available after handshake timeout")
  .expect("successful test sender should be stored in the pool");
  assert!(!successful.1);
}

struct PendingIo;

impl AsyncRead for PendingIo {
  fn poll_read(
    self: Pin<&mut Self>,
    _cx: &mut TaskContext<'_>,
    _buf: &mut ReadBuf<'_>,
  ) -> Poll<std::io::Result<()>> {
    Poll::Pending
  }
}

impl AsyncWrite for PendingIo {
  fn poll_write(
    self: Pin<&mut Self>,
    _cx: &mut TaskContext<'_>,
    _buf: &[u8],
  ) -> Poll<std::io::Result<usize>> {
    Poll::Pending
  }

  fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
    Poll::Pending
  }

  fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
    Poll::Pending
  }
}

async fn successful_test_sender() -> anyhow::Result<SendRequest<ProxyBody>> {
  let (client_io, server_io) = tokio::io::duplex(1024 * 64);
  tokio::spawn(async move {
    let service = service_fn(|_request| async { Ok::<_, Infallible>(Response::new(empty_body())) });
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    let http2_config = ProxyHttp2Config::default();
    crate::h2_tuning::apply_server_defaults(&mut builder, &http2_config);
    let _ = builder
      .serve_connection(TokioIo::new(server_io), service)
      .await;
  });
  let http2_config = ProxyHttp2Config::default();
  h2_handshake(client_io, &http2_config).await
}

fn direct_h2_test_pool(connect_timeout: Duration) -> DirectH2Pool {
  let origin = DirectH2Origin {
    scheme: "http",
    host: "127.0.0.1".to_string(),
    port: 80,
  };
  DirectH2Pool {
    origin,
    connect_timeout,
    idle_timeout: Duration::from_secs(30),
    http2_config: ProxyHttp2Config::default(),
    tls_config: None,
    entry: RwLock::new(None),
  }
}

fn upstream(origin: &str) -> UpstreamConfig {
  UpstreamConfig {
    name: "backend".to_string(),
    origin: Url::parse(origin).unwrap(),
    max_http_version: HttpVersion::H2,
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
