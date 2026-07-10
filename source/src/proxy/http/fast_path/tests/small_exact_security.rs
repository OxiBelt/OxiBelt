use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};

use crate::proxy::http::body;

use super::super::{fast_path_small_exact_request_body, fast_path_small_request_body_options};

struct OverlongThenPanicBody {
  yielded: bool,
}

struct FramesBody {
  frames: VecDeque<Frame<Bytes>>,
}

struct DropTrackedBytes {
  bytes: Vec<u8>,
  drops: Arc<AtomicUsize>,
}

impl DropTrackedBytes {
  fn new(bytes: Vec<u8>, drops: Arc<AtomicUsize>) -> Self {
    Self { bytes, drops }
  }
}

impl AsRef<[u8]> for DropTrackedBytes {
  fn as_ref(&self) -> &[u8] {
    &self.bytes
  }
}

impl Drop for DropTrackedBytes {
  fn drop(&mut self) {
    self.drops.fetch_add(1, Ordering::SeqCst);
  }
}

impl FramesBody {
  fn new(frames: impl IntoIterator<Item = Frame<Bytes>>) -> Self {
    Self {
      frames: frames.into_iter().collect(),
    }
  }
}

impl Body for FramesBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    Poll::Ready(self.frames.pop_front().map(Ok))
  }

  fn is_end_stream(&self) -> bool {
    self.frames.is_empty()
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

fn small_post_body_options(
  content_length: usize,
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
    16 * 1024,
    16 * 1024,
  )
  .expect("small POST body options should be selected")
}

impl Body for OverlongThenPanicBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    if self.yielded {
      panic!("overlong small request body should fail before polling again");
    }
    self.yielded = true;
    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"too long")))))
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

#[tokio::test]
async fn small_post_request_body_rejects_overlong_body_without_buffering_to_route_limit() {
  let mut headers = http::HeaderMap::new();
  headers.insert(http::header::CONTENT_LENGTH, "1".parse().unwrap());
  let options = fast_path_small_request_body_options(
    &http::Method::POST,
    true,
    false,
    &headers,
    16 * 1024,
    16 * 1024,
  )
  .expect("small POST body options should be selected");

  let result = fast_path_small_exact_request_body(
    OverlongThenPanicBody { yielded: false },
    16 * 1024,
    Duration::from_millis(100),
    options,
    None,
  )
  .await;
  let error = match result {
    Ok(_) => panic!("overlong small POST body should fail"),
    Err(error) => error,
  };

  assert!(
    error.to_string().contains("request body length mismatch"),
    "unexpected error: {error}"
  );
}

#[tokio::test]
async fn single_exact_request_body_frame_does_not_retain_frame_owner() {
  let drops = Arc::new(AtomicUsize::new(0));
  let owner = DropTrackedBytes::new(vec![b'x'; 1024 * 1024], Arc::clone(&drops));
  let source = Bytes::from_owner(owner).slice(..1024);
  let mut body = fast_path_small_exact_request_body(
    Full::new(source).map_err(|never| -> body::BoxError { match never {} }),
    16 * 1024,
    Duration::from_millis(100),
    small_post_body_options(1024),
    None,
  )
  .await
  .expect("single-frame small POST body should collect");

  assert_eq!(
    drops.load(Ordering::SeqCst),
    1,
    "the bounded fast-path body must not retain the oversized frame owner"
  );

  let frame = body
    .frame()
    .await
    .expect("small exact body should yield one frame")
    .expect("small exact body frame should be valid");
  let data = frame
    .into_data()
    .expect("small exact body frame should contain data");
  assert_eq!(data.as_ref(), &[b'x'; 1024]);
  assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn multiple_exact_request_body_frames_coalesce_within_expected_length() {
  let frames = FramesBody::new([
    Frame::data(Bytes::from_static(b"abc")),
    Frame::data(Bytes::from_static(b"def")),
  ]);
  let body = fast_path_small_exact_request_body(
    frames,
    16 * 1024,
    Duration::from_millis(100),
    small_post_body_options(6),
    None,
  )
  .await
  .expect("multi-frame small POST body should collect");

  assert!(body.is_small_exact());
  assert_eq!(body.size_hint().exact(), Some(6));
  let collected = body
    .collect()
    .await
    .expect("coalesced small exact body should collect");
  assert_eq!(collected.to_bytes(), Bytes::from_static(b"abcdef"));
}
