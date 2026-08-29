use std::num::NonZeroU64;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::bandwidth::{BandwidthPolicy, BandwidthRate};

fn test_drain() -> (
  ConnectionDrain,
  tokio::sync::watch::Sender<bool>,
  tokio::sync::watch::Sender<bool>,
) {
  let (listener_tx, listener_rx) = tokio::sync::watch::channel(false);
  let (lifecycle_tx, lifecycle_rx) = tokio::sync::watch::channel(false);
  (
    ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO),
    listener_tx,
    lifecycle_tx,
  )
}

#[test]
fn websocket_extension_negotiation_is_removed_before_framed_bridging() {
  let mut headers = HeaderMap::new();
  headers.insert(
    "sec-websocket-extensions",
    "permessage-deflate".parse().unwrap(),
  );
  headers.insert("x-preserved", "value".parse().unwrap());

  remove_websocket_extensions(&mut headers);

  assert!(!headers.contains_key("sec-websocket-extensions"));
  assert_eq!(headers.get("x-preserved").unwrap(), "value");
}

#[test]
fn websocket_upgrade_classification_accepts_comma_and_repeated_tokens() {
  let comma = Request::builder()
    .header(http::header::UPGRADE, "h2c, WebSocket")
    .body(())
    .unwrap();
  assert!(is_websocket_upgrade(&comma));

  let mut repeated = Request::new(());
  repeated
    .headers_mut()
    .append(http::header::UPGRADE, "h2c".parse().unwrap());
  repeated
    .headers_mut()
    .append(http::header::UPGRADE, "websocket".parse().unwrap());
  assert!(is_websocket_upgrade(&repeated));

  let other = Request::builder()
    .header(http::header::UPGRADE, "h2c")
    .body(())
    .unwrap();
  assert!(!is_websocket_upgrade(&other));
}

#[tokio::test(start_paused = true)]
async fn tunnel_idle_timeout_pauses_during_deliberate_bandwidth_wait() {
  let (mut client, downstream) = tokio::io::duplex(64);
  let (upstream, mut server) = tokio::io::duplex(64);
  let upload = BandwidthRate::BytesPerSecond(NonZeroU64::new(4).unwrap());
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(upload, BandwidthRate::Unlimited));
  let (drain, _listener_tx, _lifecycle_tx) = test_drain();
  client.write_all(b"abcdefgh").await.unwrap();
  let bridge = tokio::spawn(copy_bidirectional_with_idle_and_bandwidth(
    downstream,
    upstream,
    Duration::from_millis(100),
    drain,
    Some(limiter),
    Some(crate::metrics::Metrics::new()),
    crate::metrics::BandwidthTrafficClass::Tunnel,
    TunnelProtocol::Opaque,
  ));

  let mut first = [0u8; 4];
  server.read_exact(&mut first).await.unwrap();
  assert_eq!(&first, b"abcd");

  tokio::time::advance(Duration::from_millis(500)).await;
  tokio::task::yield_now().await;
  assert!(
    !bridge.is_finished(),
    "idle expiry must pause during shaping"
  );

  tokio::time::advance(Duration::from_millis(500)).await;
  let mut second = [0u8; 4];
  server.read_exact(&mut second).await.unwrap();
  assert_eq!(&second, b"efgh");
  drop(client);
  bridge.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn active_tunnel_observes_unlimited_to_limited_policy_updates() {
  let (mut client, downstream) = tokio::io::duplex(64);
  let (upstream, mut server) = tokio::io::duplex(64);
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED);
  let (drain, _listener_tx, _lifecycle_tx) = test_drain();
  let bridge = tokio::spawn(copy_bidirectional_with_idle_and_bandwidth(
    downstream,
    upstream,
    Duration::from_secs(10),
    drain,
    Some(limiter.clone()),
    Some(crate::metrics::Metrics::new()),
    crate::metrics::BandwidthTrafficClass::Tunnel,
    TunnelProtocol::Opaque,
  ));

  client.write_all(b"open").await.unwrap();
  let mut open = [0u8; 4];
  server.read_exact(&mut open).await.unwrap();
  assert_eq!(&open, b"open");

  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(4).unwrap());
  limiter
    .update(BandwidthPolicy::new(rate, BandwidthRate::Unlimited))
    .unwrap();
  client.write_all(b"slow").await.unwrap();
  let first = server.read_u8();
  tokio::pin!(first);
  assert!(futures_util::poll!(first.as_mut()).is_pending());
  tokio::time::advance(Duration::from_millis(249)).await;
  assert!(futures_util::poll!(first.as_mut()).is_pending());
  tokio::time::advance(Duration::from_millis(1)).await;
  assert_eq!(first.await.unwrap(), b's');

  drop(client);
  bridge.abort();
}
