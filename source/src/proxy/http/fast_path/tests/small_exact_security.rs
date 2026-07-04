use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};

use crate::proxy::http::body;

use super::super::{fast_path_small_exact_request_body, fast_path_small_request_body_options};

struct OverlongThenPanicBody {
  yielded: bool,
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
