use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};

use crate::proxy::http::body;

use super::super::{
  fast_path_empty_request_body, fast_path_request_body, fast_path_request_body_empty_probe_allowed,
  fast_path_request_body_is_definitely_empty, fast_path_small_exact_request_body,
  fast_path_small_request_body_options,
};

fn small_post_body_options(
  content_length: usize,
  max_body_bytes: usize,
  small_body_max_bytes: usize,
) -> super::super::request_body::FastPathSmallRequestBodyOptions {
  let mut headers = http::HeaderMap::new();
  headers.insert(
    http::header::CONTENT_LENGTH,
    content_length.to_string().parse().unwrap(),
  );
  fast_path_small_request_body_options(
    &http::Method::POST,
    true,
    false,
    &headers,
    max_body_bytes,
    small_body_max_bytes,
  )
  .expect("small POST body options should be selected")
}

struct EndStreamPanicBody;

impl Body for EndStreamPanicBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    panic!("end-stream body should not be polled");
  }

  fn is_end_stream(&self) -> bool {
    true
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::with_exact(0)
  }
}

struct TrailerOnlyBody {
  yielded: bool,
}

impl Body for TrailerOnlyBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.yielded {
      return Poll::Ready(None);
    }
    self.yielded = true;
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-trailer", "kept".parse().unwrap());
    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::with_exact(0)
  }
}

struct ZeroSizeHintDataBody {
  yielded: bool,
}

impl Body for ZeroSizeHintDataBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.yielded {
      return Poll::Ready(None);
    }
    self.yielded = true;
    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"data")))))
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::with_exact(0)
  }
}

struct PendingThenDataBody {
  pending: bool,
  yielded: bool,
}

struct PendingThenEndBody {
  pending: bool,
}

struct PendingMarksEndBody {
  pending: bool,
  poll_count: Arc<AtomicUsize>,
}

struct PendingTwiceThenDataBody {
  pending_count: usize,
  yielded: bool,
}

struct PendingThenTrailerBody {
  pending: bool,
  yielded: bool,
}

struct PendingThenErrorBody {
  pending: bool,
}

impl Body for PendingThenDataBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.pending {
      self.pending = false;
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    if self.yielded {
      return Poll::Ready(None);
    }
    self.yielded = true;
    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"data")))))
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

impl Body for PendingThenEndBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.pending {
      self.pending = false;
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    Poll::Ready(None)
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

impl Body for PendingMarksEndBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    self.poll_count.fetch_add(1, Ordering::SeqCst);
    if self.pending {
      self.pending = false;
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    Poll::Ready(None)
  }

  fn is_end_stream(&self) -> bool {
    !self.pending
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

impl Body for PendingTwiceThenDataBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.pending_count > 0 {
      self.pending_count -= 1;
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    if self.yielded {
      return Poll::Ready(None);
    }
    self.yielded = true;
    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"late-data")))))
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

impl Body for PendingThenTrailerBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.pending {
      self.pending = false;
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    if self.yielded {
      return Poll::Ready(None);
    }
    self.yielded = true;
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-trailer", "late".parse().unwrap());
    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

impl Body for PendingThenErrorBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.pending {
      self.pending = false;
      cx.waker().wake_by_ref();
      return Poll::Pending;
    }
    Poll::Ready(Some(Err(std::io::Error::other("late body error").into())))
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

#[tokio::test]
async fn classified_empty_request_body_shortcut_collects_empty_body() {
  let body = fast_path_empty_request_body()
    .collect()
    .await
    .expect("classified empty fast-path body should collect");
  assert!(body.to_bytes().is_empty());
}

#[tokio::test]
async fn actual_end_stream_request_body_shortcut_does_not_poll_body() {
  let body = fast_path_request_body(
    EndStreamPanicBody,
    1024,
    Duration::from_millis(100),
    false,
    false,
  )
  .await;
  assert!(body.proven_empty());
  let body = body
    .collect()
    .await
    .expect("end-stream fast-path body should collect");
  assert!(body.to_bytes().is_empty());
}

#[tokio::test]
async fn small_post_request_body_uses_exact_body_shortcut() {
  let bytes = Bytes::from_static(br#"{"ok":true}"#);
  let body = fast_path_small_exact_request_body(
    Full::new(bytes.clone()).map_err(|never| -> body::BoxError { match never {} }),
    16 * 1024,
    Duration::from_millis(100),
    small_post_body_options(bytes.len(), 16 * 1024, 16 * 1024),
    None,
  )
  .await
  .expect("small POST body should collect");

  assert!(!body.proven_empty());
  assert!(body.is_small_exact());
  assert_eq!(body.size_hint().exact(), Some(bytes.len() as u64));
  let collected = body
    .collect()
    .await
    .expect("small exact body should collect");
  assert_eq!(collected.to_bytes(), bytes);
}

#[tokio::test]
async fn small_post_request_body_with_trailers_remains_streaming() {
  let mut trailers = http::HeaderMap::new();
  trailers.insert("x-trailer", "kept".parse().unwrap());
  let bytes = Bytes::from_static(b"data");
  let source = Full::new(bytes.clone())
    .with_trailers(std::future::ready(Some(Ok::<_, std::convert::Infallible>(
      trailers,
    ))))
    .map_err(|never| -> body::BoxError { match never {} });
  let body = fast_path_small_exact_request_body(
    source,
    16 * 1024,
    Duration::from_millis(100),
    small_post_body_options(bytes.len(), 16 * 1024, 16 * 1024),
    None,
  )
  .await
  .expect("small POST body with trailers should collect");

  assert!(!body.proven_empty());
  assert!(!body.is_small_exact());
  let collected = body
    .collect()
    .await
    .expect("materialized streaming body should collect");
  assert_eq!(collected.trailers().unwrap()["x-trailer"], "kept");
  assert_eq!(collected.to_bytes(), bytes);
}

#[test]
fn small_post_request_body_options_are_strictly_guarded() {
  let mut headers = http::HeaderMap::new();
  headers.insert(http::header::CONTENT_LENGTH, "1024".parse().unwrap());
  assert!(
    fast_path_small_request_body_options(
      &http::Method::POST,
      true,
      false,
      &headers,
      16 * 1024,
      16 * 1024
    )
    .is_some()
  );

  assert!(
    fast_path_small_request_body_options(
      &http::Method::POST,
      true,
      true,
      &headers,
      16 * 1024,
      16 * 1024
    )
    .is_none(),
    "retry replay keeps bodyful direct-H1 out of the small exact shortcut"
  );
  assert!(
    fast_path_small_request_body_options(
      &http::Method::POST,
      false,
      false,
      &headers,
      16 * 1024,
      16 * 1024
    )
    .is_none(),
    "only direct-H1 candidates should use the small exact shortcut"
  );
  assert!(
    fast_path_small_request_body_options(
      &http::Method::PUT,
      true,
      false,
      &headers,
      16 * 1024,
      16 * 1024
    )
    .is_none(),
    "the shortcut is scoped to the small POST benchmark path"
  );

  let mut trailer_headers = headers.clone();
  trailer_headers.insert(http::header::TRAILER, "x-trailer".parse().unwrap());
  assert!(
    fast_path_small_request_body_options(
      &http::Method::POST,
      true,
      false,
      &trailer_headers,
      16 * 1024,
      16 * 1024
    )
    .is_none()
  );

  let mut large_headers = http::HeaderMap::new();
  large_headers.insert(http::header::CONTENT_LENGTH, "32768".parse().unwrap());
  assert!(
    fast_path_small_request_body_options(
      &http::Method::POST,
      true,
      false,
      &large_headers,
      64 * 1024,
      16 * 1024
    )
    .is_none(),
    "large request bodies must continue to stream"
  );
}

#[tokio::test]
async fn large_post_request_body_stays_streaming() {
  let bytes = Bytes::from(vec![b'x'; 32 * 1024]);
  let body = fast_path_request_body(
    Full::new(bytes.clone()).map_err(|never| -> body::BoxError { match never {} }),
    64 * 1024,
    Duration::from_millis(100),
    false,
    false,
  )
  .await;

  assert!(!body.proven_empty());
  assert!(!body.is_small_exact());
  let collected = body
    .collect()
    .await
    .expect("large streaming request body should collect");
  assert_eq!(collected.to_bytes(), bytes);
}

#[tokio::test]
async fn h2_h3_actual_end_stream_request_body_shortcut_does_not_poll_body() {
  for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
    let request = http::Request::builder()
      .version(version)
      .body(EndStreamPanicBody)
      .expect("request should build");
    let body = fast_path_request_body(
      request.into_body(),
      1024,
      Duration::from_millis(100),
      false,
      false,
    )
    .await;
    assert!(body.proven_empty());
    let body = body
      .collect()
      .await
      .expect("end-stream h2/h3 fast-path body should collect");

    assert!(body.to_bytes().is_empty());
  }
}

#[test]
fn h2_h3_safe_methods_without_body_headers_allow_empty_probe() {
  for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
    for method in [http::Method::GET, http::Method::HEAD] {
      let request = http::Request::builder()
        .method(method)
        .version(version)
        .body(())
        .expect("request should build");

      assert!(fast_path_request_body_empty_probe_allowed(
        request.method(),
        request.version(),
        request.headers()
      ));
    }

    let post = http::Request::builder()
      .method(http::Method::POST)
      .version(version)
      .body(())
      .expect("request should build");
    assert!(!fast_path_request_body_empty_probe_allowed(
      post.method(),
      post.version(),
      post.headers()
    ));

    let content_length_zero = http::Request::builder()
      .method(http::Method::GET)
      .version(version)
      .header(http::header::CONTENT_LENGTH, "0")
      .body(())
      .expect("request should build");
    assert!(!fast_path_request_body_empty_probe_allowed(
      content_length_zero.method(),
      content_length_zero.version(),
      content_length_zero.headers()
    ));
  }

  let http1_get = http::Request::builder()
    .method(http::Method::GET)
    .version(http::Version::HTTP_11)
    .body(())
    .expect("request should build");
  assert!(!fast_path_request_body_empty_probe_allowed(
    http1_get.method(),
    http1_get.version(),
    http1_get.headers()
  ));
}

#[test]
fn h2_h3_empty_probe_uses_final_outbound_headers_after_mutation() {
  for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
    let request = http::Request::builder()
      .method(http::Method::GET)
      .version(version)
      .body(())
      .expect("request should build");
    assert!(fast_path_request_body_empty_probe_allowed(
      request.method(),
      request.version(),
      request.headers()
    ));

    let mut content_length_headers = request.headers().clone();
    content_length_headers.insert(http::header::CONTENT_LENGTH, "7".parse().unwrap());
    assert!(!fast_path_request_body_empty_probe_allowed(
      request.method(),
      request.version(),
      &content_length_headers
    ));

    let mut transfer_encoding_headers = request.headers().clone();
    transfer_encoding_headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    assert!(!fast_path_request_body_empty_probe_allowed(
      request.method(),
      request.version(),
      &transfer_encoding_headers
    ));
  }
}

#[tokio::test]
async fn h2_h3_empty_probe_preserves_data_and_trailers() {
  let h2_content_length_zero = http::Request::builder()
    .version(http::Version::HTTP_2)
    .header(http::header::CONTENT_LENGTH, "0")
    .body(())
    .expect("request should build");
  assert!(!fast_path_request_body_is_definitely_empty(
    h2_content_length_zero.version(),
    h2_content_length_zero.headers()
  ));

  let data_body = fast_path_request_body(
    ZeroSizeHintDataBody { yielded: false },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .await;
  assert!(!data_body.proven_empty());
  assert_ne!(data_body.size_hint().upper(), Some(0));
  let data = data_body
    .collect()
    .await
    .expect("zero-size-hint data body should collect");
  assert_eq!(data.to_bytes(), Bytes::from_static(b"data"));

  let trailers = fast_path_request_body(
    TrailerOnlyBody { yielded: false },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .await;
  assert!(!trailers.proven_empty());
  let trailers = trailers
    .collect()
    .await
    .expect("zero-size-hint trailer-only body should collect");
  assert_eq!(trailers.trailers().unwrap()["x-trailer"], "kept");
}

#[tokio::test]
async fn h2_h3_empty_probe_keeps_pending_body_on_limited_timeout_path() {
  let data = fast_path_request_body(
    PendingThenDataBody {
      pending: true,
      yielded: false,
    },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .await;
  assert!(!data.proven_empty());
  let data = data
    .collect()
    .await
    .expect("pending body should stay readable after empty probe");

  assert_eq!(data.to_bytes(), Bytes::from_static(b"data"));
}

#[tokio::test]
async fn h2_h3_empty_probe_shortcuts_pending_then_eof() {
  let body = fast_path_request_body(
    PendingThenEndBody { pending: true },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .await;
  assert!(body.proven_empty());
  let body = body
    .collect()
    .await
    .expect("pending then EOF body should collect");

  assert!(body.to_bytes().is_empty());
}

#[tokio::test]
async fn h2_h3_empty_probe_skips_repoll_when_pending_marks_end_stream() {
  let poll_count = Arc::new(AtomicUsize::new(0));
  let body = fast_path_request_body(
    PendingMarksEndBody {
      pending: true,
      poll_count: Arc::clone(&poll_count),
    },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .await;
  assert!(body.proven_empty());
  let body = body
    .collect()
    .await
    .expect("pending body that marks end-stream should collect");

  assert_eq!(poll_count.load(Ordering::SeqCst), 1);
  assert!(body.to_bytes().is_empty());
}

#[tokio::test]
async fn h2_h3_empty_probe_preserves_late_data_trailers_and_errors() {
  let data = fast_path_request_body(
    PendingTwiceThenDataBody {
      pending_count: 2,
      yielded: false,
    },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .await;
  assert!(!data.proven_empty());
  let data = data
    .collect()
    .await
    .expect("body that stays pending through the probe should remain readable");
  assert_eq!(data.to_bytes(), Bytes::from_static(b"late-data"));

  let trailers = fast_path_request_body(
    PendingThenTrailerBody {
      pending: true,
      yielded: false,
    },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .await;
  assert!(!trailers.proven_empty());
  let trailers = trailers
    .collect()
    .await
    .expect("late trailer body should collect");
  assert_eq!(trailers.trailers().unwrap()["x-trailer"], "late");

  let error = fast_path_request_body(
    PendingThenErrorBody { pending: true },
    1024,
    Duration::from_millis(100),
    false,
    true,
  )
  .await;
  assert!(!error.proven_empty());
  let error = error
    .collect()
    .await
    .expect_err("late body error should be preserved");
  assert!(error.to_string().contains("late body error"));
}
