use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use super::{
  BodyTimeoutKind, BoxError, TIMEOUT_BODY_CHANNEL_CAPACITY, capture_prefix, channel_body,
  error_is_timeout, known_small_no_trailers_body, with_backpressure_send_timeout, with_bandwidth,
  with_drop_guard, with_poll_send_timeout, with_read_timeout,
};
use crate::bandwidth::{BandwidthDirection, BandwidthPolicy, BandwidthRate, RouteBandwidthLimiter};
use crate::metrics::{BandwidthTrafficClass, Metrics};

#[tokio::test]
async fn capture_prefix_replays_full_body_after_truncation() {
  let request = Request::builder()
    .body(
      Full::new(Bytes::from_static(b"abcdef"))
        .map_err(|never| -> BoxError { match never {} })
        .boxed(),
    )
    .expect("request should build");

  let (request, captured) = capture_prefix(request, 3)
    .await
    .expect("body capture should succeed");
  assert_eq!(captured.bytes.as_ref(), b"abc");
  assert!(captured.is_truncated);

  let replayed = request
    .into_body()
    .collect()
    .await
    .expect("replayed body should collect")
    .to_bytes();
  assert_eq!(replayed.as_ref(), b"abcdef");
}

#[tokio::test]
async fn known_small_no_trailers_body_yields_one_exact_data_frame() {
  let mut body = known_small_no_trailers_body(Bytes::from_static(b"ok"));
  assert_eq!(body.size_hint().exact(), Some(2));
  assert!(!body.is_end_stream());

  let frame = body
    .frame()
    .await
    .expect("body should yield one frame")
    .expect("known-small body should not fail");
  assert_eq!(
    frame
      .into_data()
      .expect("frame should contain data")
      .as_ref(),
    b"ok"
  );
  assert!(body.is_end_stream());
  assert_eq!(body.size_hint().exact(), Some(0));
  assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn known_small_no_trailers_body_preserves_empty_end_stream() {
  let mut body = known_small_no_trailers_body(Bytes::new());
  assert!(body.is_end_stream());
  assert_eq!(body.size_hint().exact(), Some(0));
  assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn drop_guard_preserves_inner_end_stream_state() {
  let mut body = with_drop_guard(known_small_no_trailers_body(Bytes::new()), ());
  assert!(body.is_end_stream());
  assert_eq!(body.size_hint().exact(), Some(0));
  assert!(body.frame().await.is_none());

  let mut body = with_drop_guard(known_small_no_trailers_body(Bytes::from_static(b"ok")), ());
  assert!(!body.is_end_stream());
  assert!(body.frame().await.is_some());
  assert!(body.is_end_stream());
}

#[tokio::test]
async fn capture_prefix_marks_complete_body_as_not_truncated() {
  let request = Request::builder()
    .body(
      Full::new(Bytes::from_static(b"abc"))
        .map_err(|never| -> BoxError { match never {} })
        .boxed(),
    )
    .expect("request should build");

  let (request, captured) = capture_prefix(request, 8)
    .await
    .expect("body capture should succeed");
  assert_eq!(captured.bytes.as_ref(), b"abc");
  assert!(!captured.is_truncated);

  let replayed = request
    .into_body()
    .collect()
    .await
    .expect("replayed body should collect")
    .to_bytes();
  assert_eq!(replayed.as_ref(), b"abc");
}

#[tokio::test]
async fn read_timeout_body_returns_typed_timeout_error() {
  let (_sender, pending_body) = channel_body(1);
  let timed_body = with_read_timeout(
    pending_body,
    Duration::from_millis(5),
    BodyTimeoutKind::DownstreamRequestRead,
  );

  let error = timed_body
    .collect()
    .await
    .expect_err("pending body should time out");
  assert!(error_is_timeout(
    &error,
    BodyTimeoutKind::DownstreamRequestRead
  ));
}

#[tokio::test]
async fn read_timeout_body_times_out_zero_size_hint_pending_body() {
  let (_sender, pending_body) = super::channel_body_with_size_hint(1, exact_zero_size_hint());
  let timed_body = with_read_timeout(
    pending_body,
    Duration::from_millis(5),
    BodyTimeoutKind::DownstreamRequestRead,
  );

  let error = timed_body
    .collect()
    .await
    .expect_err("zero-size-hint pending body should time out");
  assert!(error_is_timeout(
    &error,
    BodyTimeoutKind::DownstreamRequestRead
  ));
}

#[tokio::test]
async fn capture_prefix_times_out_zero_size_hint_pending_body() {
  let (_sender, pending_body) = super::channel_body_with_size_hint(1, exact_zero_size_hint());
  let timed_body = with_read_timeout(
    pending_body,
    Duration::from_millis(5),
    BodyTimeoutKind::DownstreamRequestRead,
  );
  let request = Request::builder()
    .body(timed_body)
    .expect("request should build");

  let error = capture_prefix(request, 8)
    .await
    .expect_err("WAF-style capture should inherit body read timeout");
  assert!(error_is_timeout(
    &error,
    BodyTimeoutKind::DownstreamRequestRead
  ));
}

#[tokio::test]
async fn backpressure_send_timeout_body_returns_typed_timeout_after_buffered_frames() {
  let (sender, pending_body) = channel_body(TIMEOUT_BODY_CHANNEL_CAPACITY + 1);
  for _ in 0..=TIMEOUT_BODY_CHANNEL_CAPACITY {
    sender
      .send(Ok(Frame::data(Bytes::from_static(b"x"))))
      .await
      .expect("source body should accept queued frame");
  }
  drop(sender);

  let timed_body = with_backpressure_send_timeout(
    pending_body,
    Duration::from_millis(5),
    BodyTimeoutKind::UpstreamRequestSend,
  );
  tokio::time::sleep(Duration::from_millis(25)).await;

  let error = timed_body
    .collect()
    .await
    .expect_err("send timeout should propagate after buffered frames");
  assert!(error_is_timeout(
    &error,
    BodyTimeoutKind::UpstreamRequestSend
  ));
}

#[tokio::test]
async fn backpressure_send_timeout_body_applies_to_zero_size_hint_source_body() {
  let (sender, pending_body) =
    super::channel_body_with_size_hint(TIMEOUT_BODY_CHANNEL_CAPACITY + 1, exact_zero_size_hint());
  for _ in 0..=TIMEOUT_BODY_CHANNEL_CAPACITY {
    sender
      .send(Ok(Frame::data(Bytes::from_static(b"x"))))
      .await
      .expect("source body should accept queued frame");
  }
  drop(sender);

  let timed_body = with_backpressure_send_timeout(
    pending_body,
    Duration::from_millis(5),
    BodyTimeoutKind::UpstreamRequestSend,
  );
  tokio::time::sleep(Duration::from_millis(25)).await;

  let error = timed_body
    .collect()
    .await
    .expect_err("send timeout should apply even when size hint is exact zero");
  assert!(error_is_timeout(
    &error,
    BodyTimeoutKind::UpstreamRequestSend
  ));
}

#[tokio::test]
async fn poll_send_timeout_body_returns_typed_timeout_error() {
  let (_sender, pending_body) = channel_body(1);
  let timed_body = with_poll_send_timeout(
    pending_body,
    Duration::from_millis(5),
    BodyTimeoutKind::UpstreamRequestSend,
  );

  let error = timed_body
    .collect()
    .await
    .expect_err("pending body should time out");
  assert!(error_is_timeout(
    &error,
    BodyTimeoutKind::UpstreamRequestSend
  ));
}

#[tokio::test]
async fn poll_send_timeout_body_collects_ready_body() {
  let body = Full::new(Bytes::from_static(b"abc"))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let timed_body = with_poll_send_timeout(
    body,
    Duration::from_secs(1),
    BodyTimeoutKind::DownstreamResponseSend,
  );

  let collected = timed_body
    .collect()
    .await
    .expect("ready body should collect")
    .to_bytes();
  assert_eq!(collected.as_ref(), b"abc");
}

#[tokio::test]
async fn poll_send_timeout_body_does_not_spawn_background_poller() {
  let poll_count = Arc::new(AtomicUsize::new(0));
  let body = CountingPendingBody {
    poll_count: Arc::clone(&poll_count),
  }
  .boxed();
  let mut timed_body = with_poll_send_timeout(
    body,
    Duration::from_secs(1),
    BodyTimeoutKind::UpstreamRequestSend,
  );

  tokio::time::sleep(Duration::from_millis(20)).await;
  assert_eq!(
    poll_count.load(Ordering::SeqCst),
    0,
    "poll-based send timeout must not install the spawned mpsc wrapper"
  );

  let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
  assert!(
    Pin::new(&mut timed_body)
      .poll_frame(&mut context)
      .is_pending()
  );
  assert_eq!(poll_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn timeout_wrappers_allow_completed_empty_bodies() {
  let read_body = Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let read_body = with_read_timeout(
    read_body,
    Duration::from_millis(5),
    BodyTimeoutKind::DownstreamRequestRead,
  );
  let read_bytes = read_body
    .collect()
    .await
    .expect("empty read body should collect")
    .to_bytes();
  assert!(read_bytes.is_empty());

  let send_body = Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let send_body = with_poll_send_timeout(
    send_body,
    Duration::from_millis(5),
    BodyTimeoutKind::DownstreamResponseSend,
  );
  assert!(send_body.is_end_stream());
  let send_bytes = send_body
    .collect()
    .await
    .expect("empty send body should collect")
    .to_bytes();
  assert!(send_bytes.is_empty());
}

#[tokio::test]
async fn timeout_body_preserves_size_hint() {
  let body = Full::new(Bytes::from_static(b"abc"))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let timed_body = with_read_timeout(
    body,
    Duration::from_secs(1),
    BodyTimeoutKind::UpstreamResponseRead,
  );

  let size_hint = timed_body.size_hint();
  assert_eq!(size_hint.lower(), 3);
  assert_eq!(size_hint.upper(), Some(3));
}

#[tokio::test(start_paused = true)]
async fn bandwidth_body_splits_payload_and_excludes_shaping_from_inner_read_timeout() {
  let rate = BandwidthRate::BytesPerSecond(std::num::NonZeroU64::new(4).unwrap());
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(BandwidthRate::Unlimited, rate));
  let source = Full::new(Bytes::from_static(b"abcdefgh"))
    .map_err(|never| -> BoxError { match never {} })
    .boxed();
  let source = with_read_timeout(
    source,
    Duration::from_millis(100),
    BodyTimeoutKind::UpstreamResponseRead,
  );
  let mut shaped = with_bandwidth(
    source,
    limiter,
    BandwidthDirection::Download,
    Metrics::new(),
    BandwidthTrafficClass::Http,
    Some(Duration::from_millis(100)),
  );

  let first = shaped
    .frame()
    .await
    .expect("first grant should produce a frame")
    .expect("first grant should succeed")
    .into_data()
    .expect("first frame should contain data");
  assert_eq!(first.as_ref(), b"abcd");

  let second = shaped.frame();
  tokio::pin!(second);
  assert!(futures_util::poll!(second.as_mut()).is_pending());
  tokio::time::advance(Duration::from_millis(999)).await;
  assert!(futures_util::poll!(second.as_mut()).is_pending());
  tokio::time::advance(Duration::from_millis(1)).await;
  let second = second
    .await
    .expect("refill should produce the second frame")
    .expect("shaping delay must not trigger the inner read timeout")
    .into_data()
    .expect("second frame should contain data");
  assert_eq!(second.as_ref(), b"efgh");
  assert!(shaped.frame().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn bandwidth_body_observes_unlimited_to_limited_policy_updates() {
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED);
  let (source_tx, source) = channel_body(1);
  let mut shaped = with_bandwidth(
    source,
    limiter.clone(),
    BandwidthDirection::Download,
    Metrics::new(),
    BandwidthTrafficClass::Http,
    None,
  );

  source_tx
    .send(Ok(Frame::data(Bytes::from_static(b"open"))))
    .await
    .unwrap();
  let open = shaped.frame().await.unwrap().unwrap().into_data().unwrap();
  assert_eq!(open.as_ref(), b"open");

  let rate = BandwidthRate::BytesPerSecond(std::num::NonZeroU64::new(4).unwrap());
  limiter
    .update(BandwidthPolicy::new(BandwidthRate::Unlimited, rate))
    .unwrap();
  source_tx
    .send(Ok(Frame::data(Bytes::from_static(b"slow"))))
    .await
    .unwrap();
  let limited = shaped.frame();
  tokio::pin!(limited);
  assert!(futures_util::poll!(limited.as_mut()).is_pending());
  tokio::time::advance(Duration::from_millis(249)).await;
  assert!(futures_util::poll!(limited.as_mut()).is_pending());
  tokio::time::advance(Duration::from_millis(1)).await;
  let first = limited.await.unwrap().unwrap().into_data().unwrap();
  assert_eq!(first.as_ref(), b"s");
}

#[test]
fn known_small_response_body_threshold_is_bounded() {
  assert!(super::is_known_small_response_body_len(
    super::KNOWN_SMALL_BODY_MAX_BYTES
  ));
  assert!(!super::is_known_small_response_body_len(
    super::KNOWN_SMALL_BODY_MAX_BYTES + 1
  ));
}

fn exact_zero_size_hint() -> SizeHint {
  let mut size_hint = SizeHint::new();
  size_hint.set_exact(0);
  size_hint
}

struct CountingPendingBody {
  poll_count: Arc<AtomicUsize>,
}

impl Body for CountingPendingBody {
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.poll_count.fetch_add(1, Ordering::SeqCst);
    Poll::Pending
  }
}
