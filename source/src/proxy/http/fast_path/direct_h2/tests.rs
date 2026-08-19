use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use http::{Request, Response};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Barrier, oneshot, watch};
use url::Url;

use crate::cache::CacheStats;
use crate::circuit_breakers::CircuitBreakerRuntime;
use crate::config::{Config, MetricsConfig, ProxyHttp2Config, UpstreamConfig};
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::FastPathMetricProtocol;
use crate::overload::{OverloadRuntime, OverloadState};
use crate::proxy::http::body::ProxyBody;
use crate::tls::TlsServerSessionStorageStats;

use super::connection::{DirectH2Connected, h2_handshake, h2_handshake_until};
use super::pool::{DirectH2Pool, TestConnector};
use super::send::dispatch_expired_for_test;
use super::*;

const TEST_REQUEST_BUDGET: Duration = Duration::from_secs(1);

#[test]
fn guard_accepts_direct_empty_safe_requests_to_h2_upstreams() {
  let h2c = upstream("http://backend.internal:18082");
  let get = request(Method::GET, http::Version::HTTP_2);
  assert_eq!(
    direct_h2_guard_miss(
      &h2c,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      FastPathRequestBodyMode::Empty,
      &get,
    ),
    None
  );

  let tls_h2 = upstream("https://backend.internal:18444");
  let head = request(Method::HEAD, http::Version::HTTP_3);
  assert_eq!(
    direct_h2_guard_miss(
      &tls_h2,
      HttpVersion::H2,
      http::Version::HTTP_3,
      true,
      FastPathRequestBodyMode::Empty,
      &head,
    ),
    None
  );
}

#[test]
fn guard_rejects_unsafe_or_incompatible_requests() {
  let mut upstream = upstream("http://backend.internal:18082");
  let get = request(Method::GET, http::Version::HTTP_2);
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H1,
      http::Version::HTTP_2,
      true,
      FastPathRequestBodyMode::Empty,
      &get,
    ),
    Some(FastPathTransportMissReason::UnsupportedUpstream)
  );
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      FastPathRequestBodyMode::Streaming,
      &get,
    ),
    Some(FastPathTransportMissReason::RequestBody)
  );
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      false,
      FastPathRequestBodyMode::Empty,
      &get,
    ),
    Some(FastPathTransportMissReason::UnsupportedRequest)
  );

  upstream.proxy_protocol_egress = ProxyProtocolEgressMode::V1;
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      FastPathRequestBodyMode::Empty,
      &get,
    ),
    Some(FastPathTransportMissReason::UnsupportedUpstream)
  );

  let post = request(Method::POST, http::Version::HTTP_2);
  assert_eq!(
    direct_h2_guard_miss(
      &upstream,
      HttpVersion::H2,
      http::Version::HTTP_2,
      true,
      FastPathRequestBodyMode::Empty,
      &post,
    ),
    Some(FastPathTransportMissReason::UnsupportedRequest)
  );
}

#[test]
fn prepared_request_restores_the_original_fallback_version() {
  let request = request(Method::GET, http::Version::HTTP_11);
  let prepared = PreparedDirectH2Request::from_request(request).unwrap();
  assert_eq!(prepared.request.version(), http::Version::HTTP_2);
  assert!(prepared.request.uri().scheme().is_some());
  assert_eq!(
    prepared.into_fallback_request().version(),
    http::Version::HTTP_11
  );

  let relative = Request::builder()
    .method(Method::GET)
    .uri("/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap();
  assert!(PreparedDirectH2Request::from_request(relative).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_start_coalesces_64_callers_without_holding_the_slot_mutex() {
  let attempts = Arc::new(AtomicUsize::new(0));
  let (started_tx, started_rx) = oneshot::channel();
  let started_tx = Arc::new(Mutex::new(Some(started_tx)));
  let (release_tx, release_rx) = watch::channel(false);
  let connector = connector({
    let attempts = attempts.clone();
    move |_| {
      let attempts = attempts.clone();
      let started_tx = started_tx.clone();
      let mut release_rx = release_rx.clone();
      async move {
        attempts.fetch_add(1, Ordering::SeqCst);
        if let Some(started_tx) = started_tx.lock().unwrap().take() {
          let _ = started_tx.send(());
        }
        while !*release_rx.borrow() {
          release_rx.changed().await?;
        }
        successful_test_connection(None, None).await
      }
    }
  });
  let (pool, _) = test_pool(1, 64, 64, connector);
  let metrics = Metrics::new();
  let callers = 64;
  let barrier = Arc::new(Barrier::new(callers + 1));
  let mut tasks = Vec::with_capacity(callers);
  for _ in 0..callers {
    let pool = pool.clone();
    let metrics = metrics.clone();
    let barrier = barrier.clone();
    tasks.push(tokio::spawn(async move {
      barrier.wait().await;
      acquire(&pool, &metrics, TEST_REQUEST_BUDGET).await
    }));
  }
  barrier.wait().await;
  started_rx.await.unwrap();

  assert_eq!(pool.test_slot_snapshot(0).0, "connecting");
  assert_eq!(attempts.load(Ordering::SeqCst), 1);
  tokio::time::sleep(Duration::from_millis(25)).await;
  assert_eq!(
    attempts.load(Ordering::SeqCst),
    1,
    "cold waiters must share one connection attempt"
  );

  release_tx.send(true).unwrap();
  let mut senders = Vec::with_capacity(callers);
  for task in tasks {
    senders.push(
      task
        .await
        .unwrap()
        .unwrap()
        .expect("coalesced caller should acquire a sender"),
    );
  }
  assert_eq!(attempts.load(Ordering::SeqCst), 1);
  assert_eq!(pool.test_slot_snapshot(0).2, callers);
  drop(senders);
  assert_eq!(pool.test_slot_snapshot(0).2, 0);
  let output = metrics_text(&metrics);
  assert!(output.contains("event=\"connect_coalesced\"} 63"));
  assert!(output.contains("event=\"miss_saturated\"} 0"));
}

#[tokio::test]
async fn capacity_wait_is_short_and_wakes_on_indexed_release() {
  let (pool, _) = test_pool(1, 1, 1, successful_connector(None));
  let metrics = Metrics::new();
  let held = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();

  let started = Instant::now();
  assert!(
    acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
      .await
      .unwrap()
      .is_none()
  );
  let waited = started.elapsed();
  assert!(waited >= Duration::from_millis(15));
  assert!(waited < Duration::from_millis(250));

  let waiter = {
    let pool = pool.clone();
    let metrics = metrics.clone();
    tokio::spawn(async move { acquire(&pool, &metrics, TEST_REQUEST_BUDGET).await })
  };
  tokio::time::sleep(Duration::from_millis(5)).await;
  drop(held);
  let acquired = waiter.await.unwrap().unwrap().unwrap();
  assert_eq!(pool.test_release_slot_visits(), 1);
  drop(acquired);
  assert_eq!(pool.test_release_slot_visits(), 2);
}

#[tokio::test]
async fn capacity_wait_never_exceeds_the_request_deadline() {
  let (pool, _) = test_pool(1, 1, 1, successful_connector(None));
  let metrics = Metrics::new();
  let held = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();
  let budget = Duration::from_millis(8);
  let started = Instant::now();
  let error = match acquire(&pool, &metrics, budget).await {
    Ok(_) => panic!("capacity wait should exhaust the request deadline"),
    Err(error) => error,
  };
  assert!(error.to_string().contains("first-byte timed out"));
  assert!(started.elapsed() < Duration::from_millis(150));
  drop(held);
}

#[tokio::test]
async fn overload_refuses_capacity_wait_and_new_connections() {
  let (pool, _) = test_pool(1, 1, 1, successful_connector(None));
  let metrics = Metrics::new();
  let started = Instant::now();
  let result = pool
    .sender(
      &metrics,
      true,
      Instant::now() + TEST_REQUEST_BUDGET,
      TEST_REQUEST_BUDGET,
      || OverloadState::Soft,
      FastPathMetricProtocol::H2,
      false,
    )
    .await
    .unwrap();
  assert!(result.is_none());
  assert!(started.elapsed() < Duration::from_millis(100));
  assert_eq!(pool.test_slot_snapshot(0).0, "empty");
}

#[tokio::test]
async fn overload_refuses_to_wait_for_an_existing_connection_attempt() {
  let (started_tx, started_rx) = oneshot::channel();
  let started_tx = Arc::new(Mutex::new(Some(started_tx)));
  let (release_tx, release_rx) = watch::channel(false);
  let connector = connector(move |_| {
    let started_tx = started_tx.clone();
    let mut release_rx = release_rx.clone();
    async move {
      if let Some(started_tx) = started_tx.lock().unwrap().take() {
        let _ = started_tx.send(());
      }
      while !*release_rx.borrow() {
        release_rx.changed().await?;
      }
      successful_test_connection(None, None).await
    }
  });
  let (pool, _) = test_pool(1, 1, 1, connector);
  let metrics = Metrics::new();
  let leader = {
    let pool = pool.clone();
    let metrics = metrics.clone();
    tokio::spawn(async move { acquire(&pool, &metrics, TEST_REQUEST_BUDGET).await })
  };
  started_rx.await.unwrap();

  let started = Instant::now();
  let overloaded = pool
    .sender(
      &metrics,
      true,
      Instant::now() + TEST_REQUEST_BUDGET,
      TEST_REQUEST_BUDGET,
      || OverloadState::Hard,
      FastPathMetricProtocol::H2,
      false,
    )
    .await
    .unwrap();
  assert!(overloaded.is_none());
  assert!(started.elapsed() < Duration::from_millis(100));

  release_tx.send(true).unwrap();
  assert!(leader.await.unwrap().unwrap().is_some());
}

#[tokio::test]
async fn stale_connect_completion_cannot_publish_after_retirement() {
  let attempts = Arc::new(AtomicUsize::new(0));
  let (started_tx, started_rx) = oneshot::channel();
  let started_tx = Arc::new(Mutex::new(Some(started_tx)));
  let (release_tx, release_rx) = watch::channel(false);
  let connector = connector({
    let attempts = attempts.clone();
    move |_| {
      let attempts = attempts.clone();
      let started_tx = started_tx.clone();
      let mut release_rx = release_rx.clone();
      async move {
        attempts.fetch_add(1, Ordering::SeqCst);
        if let Some(started_tx) = started_tx.lock().unwrap().take() {
          let _ = started_tx.send(());
        }
        while !*release_rx.borrow() {
          release_rx.changed().await?;
        }
        successful_test_connection(None, None).await
      }
    }
  });
  let (pool, _) = test_pool(1, 1, 1, connector);
  let metrics = Metrics::new();
  let sender_task = {
    let pool = pool.clone();
    let metrics = metrics.clone();
    tokio::spawn(async move { acquire(&pool, &metrics, TEST_REQUEST_BUDGET).await })
  };
  started_rx.await.unwrap();
  pool.test_retire();
  assert!(sender_task.await.unwrap().unwrap().is_none());
  release_tx.send(true).unwrap();

  for _ in 0..50 {
    if metrics_text(&metrics).contains("event=\"stale_generation\"} 1") {
      break;
    }
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
  assert_eq!(attempts.load(Ordering::SeqCst), 1);
  assert_eq!(pool.test_slot_snapshot(0).0, "empty");
  assert!(metrics_text(&metrics).contains("event=\"stale_generation\"} 1"));
}

#[tokio::test]
async fn stale_indexed_lease_cannot_release_a_reused_slot() {
  let (pool, _) = test_pool(1, 1, 1, successful_connector(None));
  let metrics = Metrics::new();
  let stale = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();
  let stale_epoch = pool.test_slot_snapshot(0).1;

  pool.test_abandon_slot(0);
  let current = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();
  let current_snapshot = pool.test_slot_snapshot(0);
  assert_eq!(current_snapshot.0, "ready");
  assert!(current_snapshot.1 > stale_epoch);
  assert_eq!(current_snapshot.2, 1);

  drop(stale);
  assert_eq!(
    pool.test_slot_snapshot(0),
    current_snapshot,
    "a stale lease must not decrement or clear the reused slot"
  );
  assert!(metrics_text(&metrics).contains("event=\"stale_generation\"} 1"));
  drop(current);
  assert_eq!(pool.test_slot_snapshot(0).2, 0);
}

#[tokio::test]
async fn connection_failure_enters_cooldown_without_retry_storm() {
  let attempts = Arc::new(AtomicUsize::new(0));
  let connector = connector({
    let attempts = attempts.clone();
    move |_| {
      let attempts = attempts.clone();
      async move {
        attempts.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("synthetic handshake failure")
      }
    }
  });
  let (pool, _) = test_pool(1, 1, 1, connector);
  let metrics = Metrics::new();
  assert!(
    acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
      .await
      .unwrap()
      .is_none()
  );
  assert_eq!(pool.test_slot_snapshot(0).0, "cooling_down");
  assert!(
    acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
      .await
      .unwrap()
      .is_none()
  );
  assert_eq!(attempts.load(Ordering::SeqCst), 1);
  let output = metrics_text(&metrics);
  assert!(output.contains("event=\"connect_error\"} 1"));
  assert!(output.contains("event=\"cooldown_entered\"} 1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_close_drains_in_flight_lease_before_clearing_slot() {
  let (shutdown_tx, shutdown_rx) = oneshot::channel();
  let shutdown_rx = Arc::new(Mutex::new(Some(shutdown_rx)));
  let (dispatched_tx, dispatched_rx) = oneshot::channel();
  let dispatched_tx = Arc::new(Mutex::new(Some(dispatched_tx)));
  let (response_release_tx, response_release_rx) = watch::channel(false);
  let connector = connector(move |_| {
    let shutdown_rx = shutdown_rx
      .lock()
      .unwrap()
      .take()
      .expect("test connector should run once");
    let dispatched_tx = dispatched_tx.clone();
    let response_release_rx = response_release_rx.clone();
    async move {
      let (client_io, server_io) = tokio::io::duplex(1024 * 64);
      tokio::spawn(async move {
        let service = service_fn(move |_request| {
          let mut response_release_rx = response_release_rx.clone();
          let dispatched_tx = dispatched_tx.clone();
          async move {
            if let Some(dispatched_tx) = dispatched_tx.lock().unwrap().take() {
              let _ = dispatched_tx.send(());
            }
            while !*response_release_rx.borrow() {
              response_release_rx.changed().await.unwrap();
            }
            Ok::<_, Infallible>(Response::new(empty_body()))
          }
        });
        let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        crate::h2_tuning::apply_server_defaults(&mut builder, &ProxyHttp2Config::default());
        let mut connection = Box::pin(builder.serve_connection(TokioIo::new(server_io), service));
        tokio::select! {
          _ = shutdown_rx => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
          }
          _ = &mut connection => {}
        }
      });
      h2_handshake(client_io, &ProxyHttp2Config::default()).await
    }
  });
  let (pool, _) = test_pool(1, 1, 1, connector);
  let metrics = Metrics::new();
  let held = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();
  let mut request_sender = held.sender.clone();
  let request_task = tokio::spawn(async move {
    request_sender
      .send_request(request(Method::GET, http::Version::HTTP_2))
      .await
  });
  dispatched_rx.await.unwrap();
  shutdown_tx.send(()).unwrap();
  response_release_tx.send(true).unwrap();
  assert!(
    request_task.await.unwrap().is_ok(),
    "the permitted in-flight stream should finish after graceful shutdown"
  );

  for _ in 0..100 {
    if held.sender.is_closed() {
      break;
    }
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
  assert!(
    held.sender.is_closed(),
    "server GOAWAY should close the sender"
  );
  assert!(
    acquire(&pool, &metrics, Duration::from_millis(100))
      .await
      .unwrap()
      .is_none()
  );
  assert_eq!(pool.test_slot_snapshot(0).0, "draining");
  assert_eq!(pool.test_slot_snapshot(0).2, 1);
  drop(held);
  assert_eq!(pool.test_slot_snapshot(0).0, "empty");
  let output = metrics_text(&metrics);
  assert!(output.contains("event=\"graceful_close\"} 1"));
  assert!(output.contains("event=\"drain_completed\"} 1"));
}

#[tokio::test]
async fn abrupt_connection_close_cools_down_without_reconnect_storm() {
  let attempts = Arc::new(AtomicUsize::new(0));
  let (shutdown_tx, shutdown_rx) = oneshot::channel();
  let shutdown_rx = Arc::new(Mutex::new(Some(shutdown_rx)));
  let connector = connector({
    let attempts = attempts.clone();
    move |_| {
      let attempts = attempts.clone();
      let shutdown_rx = shutdown_rx
        .lock()
        .unwrap()
        .take()
        .expect("test connector should run once");
      async move {
        attempts.fetch_add(1, Ordering::SeqCst);
        let (client_io, server_io) = tokio::io::duplex(1024 * 64);
        tokio::spawn(async move {
          let service =
            service_fn(|_request| async { Ok::<_, Infallible>(Response::new(empty_body())) });
          let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
          crate::h2_tuning::apply_server_defaults(&mut builder, &ProxyHttp2Config::default());
          let mut connection = Box::pin(builder.serve_connection(TokioIo::new(server_io), service));
          tokio::select! {
            _ = shutdown_rx => {}
            _ = &mut connection => {}
          }
        });
        h2_handshake(client_io, &ProxyHttp2Config::default()).await
      }
    }
  });
  let (pool, _) = test_pool(1, 1, 1, connector);
  let metrics = Metrics::new();
  let held = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();
  shutdown_tx.send(()).unwrap();

  assert!(
    acquire(&pool, &metrics, Duration::from_millis(100))
      .await
      .unwrap()
      .is_none(),
    "an acquisition racing abrupt EOF must not reuse the closed sender"
  );
  wait_for_slot_state(&pool, "draining").await;
  drop(held);
  assert_eq!(pool.test_slot_snapshot(0).0, "cooling_down");
  assert!(
    acquire(&pool, &metrics, Duration::from_millis(100))
      .await
      .unwrap()
      .is_none()
  );
  assert_eq!(attempts.load(Ordering::SeqCst), 1);
  let output = metrics_text(&metrics);
  assert!(output.contains("event=\"cooldown_entered\"} 1"));
  assert!(!output.contains("event=\"graceful_close\"} 1"));
}

#[tokio::test]
async fn idle_timeout_retires_an_unused_connection_without_new_traffic() {
  let pool = test_pool_with_lifecycle(
    Duration::from_millis(20),
    Duration::from_secs(1),
    successful_connector(None),
  );
  let metrics = Metrics::new();
  let sender = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();
  drop(sender);

  wait_for_slot_state(&pool, "empty").await;
  let output = metrics_text(&metrics);
  assert!(output.contains("event=\"drain_started\"} 1"));
  assert!(output.contains("event=\"drain_completed\"} 1"));
}

#[tokio::test]
async fn absolute_lifetime_stops_new_streams_while_an_existing_lease_drains() {
  let pool = test_pool_with_lifecycle(
    Duration::from_secs(1),
    Duration::from_millis(20),
    successful_connector(None),
  );
  let metrics = Metrics::new();
  let held = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();

  wait_for_slot_state(&pool, "draining").await;
  assert_eq!(pool.test_slot_snapshot(0).2, 1);
  drop(held);
  assert_eq!(pool.test_slot_snapshot(0).0, "empty");
}

#[tokio::test]
async fn saturated_pre_dispatch_fallback_does_not_send_through_both_pools() {
  let dispatched = Arc::new(AtomicUsize::new(0));
  let (pool, circuit_breakers) = test_pool(1, 1, 1, successful_connector(Some(dispatched.clone())));
  let metrics = Metrics::new();
  let held = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();
  let pools = DirectH2Pools::for_test(pool.clone());
  let config = test_config();
  let overload = OverloadRuntime::new(&config.overload);
  let result = try_send_direct_h2(
    &pools,
    &metrics,
    &circuit_breakers,
    &overload,
    "test-route",
    None,
    0,
    &upstream("http://backend.internal:18082"),
    HttpVersion::H2,
    http::Version::HTTP_2,
    true,
    FastPathRequestBodyMode::Empty,
    request(Method::GET, http::Version::HTTP_2),
    test_timeouts(),
    true,
    false,
  )
  .await;
  match result {
    DirectH2SendResult::Fallback { request, deadline } => {
      assert_eq!(request.version(), http::Version::HTTP_2);
      assert!(deadline > Instant::now());
    }
    DirectH2SendResult::Sent(Ok(_)) => panic!("saturated pool must not dispatch directly"),
    DirectH2SendResult::Sent(Err(error)) => panic!("saturation must fall back: {error:#}"),
  }
  assert_eq!(dispatched.load(Ordering::SeqCst), 0);
  drop(held);
}

#[tokio::test]
async fn expired_deadline_never_polls_the_upstream_dispatch_future() {
  let dispatched = Arc::new(AtomicUsize::new(0));
  let (pool, circuit_breakers) = test_pool(1, 1, 1, successful_connector(Some(dispatched.clone())));
  let metrics = Metrics::new();
  let sender = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
    .await
    .unwrap()
    .unwrap();

  dispatch_expired_for_test(
    &pool,
    sender,
    request(Method::GET, http::Version::HTTP_2),
    &circuit_breakers,
    Instant::now() - Duration::from_millis(1),
    &metrics,
  )
  .await;
  assert_eq!(dispatched.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_slots_survive_lock_contention_stress() {
  let attempts = Arc::new(AtomicUsize::new(0));
  let connector = connector({
    let attempts = attempts.clone();
    move |_| {
      let attempts = attempts.clone();
      async move {
        attempts.fetch_add(1, Ordering::SeqCst);
        successful_test_connection(None, None).await
      }
    }
  });
  let (pool, _) = test_pool(1, 64, 64, connector);
  let metrics = Metrics::new();
  let barrier = Arc::new(Barrier::new(65));
  let mut tasks = Vec::new();
  for _ in 0..64 {
    let pool = pool.clone();
    let metrics = metrics.clone();
    let barrier = barrier.clone();
    tasks.push(tokio::spawn(async move {
      barrier.wait().await;
      for _ in 0..50 {
        let sender = acquire(&pool, &metrics, TEST_REQUEST_BUDGET)
          .await?
          .ok_or_else(|| anyhow::anyhow!("unexpected stress fallback"))?;
        tokio::task::yield_now().await;
        drop(sender);
      }
      anyhow::Ok(())
    }));
  }
  barrier.wait().await;
  for task in tasks {
    task.await.unwrap().unwrap();
  }
  assert_eq!(attempts.load(Ordering::SeqCst), 1);
  assert_eq!(pool.test_slot_snapshot(0).0, "ready");
  assert_eq!(pool.test_slot_snapshot(0).2, 0);
  assert_eq!(pool.test_release_slot_visits(), 64 * 50);
}

#[tokio::test]
async fn h2_handshake_obeys_one_absolute_deadline() {
  let result = h2_handshake_until(
    PendingIo,
    &ProxyHttp2Config::default(),
    Instant::now() + Duration::from_millis(50),
  )
  .await;
  let error = match result {
    Ok(_) => panic!("stalled H2 handshake must time out"),
    Err(error) => error,
  };
  assert!(error.to_string().contains("HTTP/2 handshake timed out"));
}

async fn acquire(
  pool: &Arc<DirectH2Pool>,
  metrics: &Arc<Metrics>,
  budget: Duration,
) -> anyhow::Result<Option<DirectH2Sender>> {
  pool
    .sender(
      metrics,
      true,
      Instant::now() + budget,
      budget,
      || OverloadState::Normal,
      FastPathMetricProtocol::H2,
      false,
    )
    .await
}

fn test_pool(
  slot_count: usize,
  target_streams_per_slot: usize,
  max_streams_per_slot: usize,
  connector: TestConnector,
) -> (Arc<DirectH2Pool>, Arc<CircuitBreakerRuntime>) {
  let circuit_breakers = CircuitBreakerRuntime::new(&test_config());
  let pool = DirectH2Pool::for_test(
    slot_count,
    target_streams_per_slot,
    max_streams_per_slot,
    TEST_REQUEST_BUDGET,
    Duration::from_secs(30),
    Duration::from_secs(60 * 60),
    circuit_breakers.clone(),
    connector,
  );
  (pool, circuit_breakers)
}

fn test_pool_with_lifecycle(
  idle_timeout: Duration,
  max_lifetime: Duration,
  connector: TestConnector,
) -> Arc<DirectH2Pool> {
  DirectH2Pool::for_test(
    1,
    1,
    1,
    TEST_REQUEST_BUDGET,
    idle_timeout,
    max_lifetime,
    CircuitBreakerRuntime::new(&test_config()),
    connector,
  )
}

async fn wait_for_slot_state(pool: &DirectH2Pool, expected: &str) {
  for _ in 0..100 {
    if pool.test_slot_snapshot(0).0 == expected {
      return;
    }
    tokio::time::sleep(Duration::from_millis(5)).await;
  }
  panic!(
    "direct H2 slot did not reach {expected}; final state was {}",
    pool.test_slot_snapshot(0).0
  );
}

fn connector<F, Fut>(connector: F) -> TestConnector
where
  F: Fn(Instant) -> Fut + Send + Sync + 'static,
  Fut: Future<Output = anyhow::Result<DirectH2Connected>> + Send + 'static,
{
  Arc::new(move |deadline| Box::pin(connector(deadline)))
}

fn successful_connector(dispatched: Option<Arc<AtomicUsize>>) -> TestConnector {
  connector(move |_| successful_test_connection(None, dispatched.clone()))
}

async fn successful_test_connection(
  shutdown: Option<oneshot::Receiver<()>>,
  dispatched: Option<Arc<AtomicUsize>>,
) -> anyhow::Result<DirectH2Connected> {
  let (client_io, server_io) = tokio::io::duplex(1024 * 64);
  tokio::spawn(async move {
    let service = service_fn(move |_request| {
      let dispatched = dispatched.clone();
      async move {
        if let Some(dispatched) = dispatched {
          dispatched.fetch_add(1, Ordering::SeqCst);
        }
        Ok::<_, Infallible>(Response::new(empty_body()))
      }
    });
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    crate::h2_tuning::apply_server_defaults(&mut builder, &ProxyHttp2Config::default());
    let mut connection = Box::pin(builder.serve_connection(TokioIo::new(server_io), service));
    if let Some(shutdown) = shutdown {
      tokio::select! {
        _ = shutdown => {
          connection.as_mut().graceful_shutdown();
          let _ = connection.await;
        }
        _ = &mut connection => {}
      }
    } else {
      let _ = connection.await;
    }
  });
  h2_handshake(client_io, &ProxyHttp2Config::default()).await
}

fn request(method: Method, version: http::Version) -> Request<ProxyBody> {
  Request::builder()
    .method(method)
    .version(version)
    .uri("http://backend.internal/perf/h2c?body=ok")
    .body(empty_body())
    .unwrap()
}

fn test_timeouts() -> EffectiveTimeouts {
  EffectiveTimeouts {
    response_send: TEST_REQUEST_BUDGET,
    websocket_idle: TEST_REQUEST_BUDGET,
    webtransport_idle: TEST_REQUEST_BUDGET,
    upstream_connect: TEST_REQUEST_BUDGET,
    upstream_request: TEST_REQUEST_BUDGET,
    upstream_first_byte: TEST_REQUEST_BUDGET,
    upstream_read: TEST_REQUEST_BUDGET,
    upstream_send: TEST_REQUEST_BUDGET,
    upstream_deadline: None,
  }
}

fn metrics_text(metrics: &Metrics) -> String {
  metrics.prometheus(
    &MetricsConfig::default(),
    CacheStats::default(),
    TlsServerSessionStorageStats::default(),
  )
}

fn test_config() -> Config {
  toml::from_str(include_str!("../../../../../config/oxibelt.toml"))
    .expect("example configuration should parse")
}

fn upstream(origin: &str) -> UpstreamConfig {
  UpstreamConfig {
    name: "backend".to_owned(),
    origin: Url::parse(origin).unwrap(),
    max_http_version: HttpVersion::H2,
    happy_eyeballs_mode: Default::default(),
    svcb_allowed_ports: Vec::new(),
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
