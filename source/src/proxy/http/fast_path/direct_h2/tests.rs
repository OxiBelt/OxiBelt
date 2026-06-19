use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::Request;
use hyper::service::service_fn;
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
