use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};

use crate::proxy::http::body;

use super::super::{fast_path_request_body, fast_path_request_body_is_definitely_empty};

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

#[tokio::test]
async fn actual_end_stream_request_body_shortcut_does_not_poll_body() {
  let body = fast_path_request_body(EndStreamPanicBody, 1024, Duration::from_millis(100), false)
    .collect()
    .await
    .expect("end-stream fast-path body should collect");
  assert!(body.to_bytes().is_empty());
}

#[tokio::test]
async fn h2_h3_actual_end_stream_request_body_shortcut_does_not_poll_body() {
  for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
    let request = http::Request::builder()
      .version(version)
      .body(EndStreamPanicBody)
      .expect("request should build");
    let body = fast_path_request_body(request.into_body(), 1024, Duration::from_millis(100), false)
      .collect()
      .await
      .expect("end-stream h2/h3 fast-path body should collect");

    assert!(body.to_bytes().is_empty());
  }
}

#[tokio::test]
async fn h2_zero_size_hint_is_not_treated_as_empty_body() {
  let h2_content_length_zero = http::Request::builder()
    .version(http::Version::HTTP_2)
    .header(http::header::CONTENT_LENGTH, "0")
    .body(())
    .expect("request should build");
  assert!(!fast_path_request_body_is_definitely_empty(
    h2_content_length_zero.version(),
    h2_content_length_zero.headers()
  ));

  let data = fast_path_request_body(
    ZeroSizeHintDataBody { yielded: false },
    1024,
    Duration::from_millis(100),
    false,
  )
  .collect()
  .await
  .expect("zero-size-hint data body should collect");
  assert_eq!(data.to_bytes(), Bytes::from_static(b"data"));

  let trailers = fast_path_request_body(
    TrailerOnlyBody { yielded: false },
    1024,
    Duration::from_millis(100),
    false,
  )
  .collect()
  .await
  .expect("zero-size-hint trailer-only body should collect");
  assert_eq!(trailers.trailers().unwrap()["x-trailer"], "kept");
}
