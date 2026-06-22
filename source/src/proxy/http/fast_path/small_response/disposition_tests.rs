use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::{HeaderMap, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};

use crate::config::TrailerMode;
use crate::proxy::http::body::{self, ProxyBody};

use super::*;

struct PanicBody {
  upper: Option<u64>,
}

struct PendingBody {
  length: u64,
}

struct FramesBody {
  frames: VecDeque<Frame<Bytes>>,
  length: u64,
  exact_size_hint: bool,
}

impl Body for PanicBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    panic!("body should not be polled");
  }

  fn size_hint(&self) -> SizeHint {
    let mut hint = SizeHint::new();
    if let Some(upper) = self.upper {
      hint.set_upper(upper);
    }
    hint
  }
}

impl Body for PendingBody {
  type Data = Bytes;
  type Error = body::BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    _cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    Poll::Pending
  }

  fn size_hint(&self) -> SizeHint {
    let mut hint = SizeHint::new();
    hint.set_exact(self.length);
    hint
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

  fn size_hint(&self) -> SizeHint {
    let mut hint = SizeHint::new();
    if self.exact_size_hint {
      hint.set_exact(self.length);
    }
    hint
  }
}

fn headers(values: &[&str]) -> HeaderMap {
  let mut headers = HeaderMap::new();
  for value in values {
    headers.append(
      CONTENT_LENGTH,
      http::HeaderValue::from_str(value).expect("valid header value"),
    );
  }
  headers
}

fn panic_body_with_upper(upper: Option<u64>) -> ProxyBody {
  PanicBody { upper }.boxed()
}

fn frames_body(frames: Vec<Frame<Bytes>>, length: u64) -> ProxyBody {
  FramesBody {
    frames: frames.into(),
    length,
    exact_size_hint: true,
  }
  .boxed()
}

fn frames_body_without_size_hint(frames: Vec<Frame<Bytes>>, length: u64) -> ProxyBody {
  FramesBody {
    frames: frames.into(),
    length,
    exact_size_hint: false,
  }
  .boxed()
}

#[tokio::test]
async fn exact_small_content_length_rejects_short_body() {
  let body = frames_body(vec![Frame::data(Bytes::from_static(b"o"))], 2);

  let disposition = try_inline_response_body(
    &headers(&["2"]),
    body,
    Duration::from_secs(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  let SmallResponseDisposition::Error { response, reason } = disposition else {
    panic!("expected length mismatch response");
  };
  assert_eq!(reason, SmallResponseReason::LengthMismatch);
  assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn exact_small_content_length_rejects_long_body() {
  let body = frames_body(vec![Frame::data(Bytes::from_static(b"wat"))], 2);

  let disposition = try_inline_response_body(
    &headers(&["2"]),
    body,
    Duration::from_secs(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  let SmallResponseDisposition::Error { response, reason } = disposition else {
    panic!("expected length mismatch response");
  };
  assert_eq!(reason, SmallResponseReason::LengthMismatch);
  assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn duplicate_content_length_keeps_streaming_without_polling() {
  let disposition = try_inline_response_body(
    &headers(&["2", "2"]),
    panic_body_with_upper(Some(2)),
    Duration::from_secs(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  assert!(matches!(
    disposition,
    SmallResponseDisposition::Streaming {
      reason: SmallResponseReason::UnknownLength,
      ..
    }
  ));
}

#[tokio::test]
async fn invalid_content_length_keeps_streaming_without_polling() {
  let disposition = try_inline_response_body(
    &headers(&["wat"]),
    panic_body_with_upper(Some(2)),
    Duration::from_secs(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  assert!(matches!(
    disposition,
    SmallResponseDisposition::Streaming {
      reason: SmallResponseReason::UnknownLength,
      ..
    }
  ));
}

#[tokio::test]
async fn unknown_size_hint_still_collects_bounded_small_body() {
  let disposition = try_inline_response_body(
    &headers(&["2"]),
    frames_body_without_size_hint(vec![Frame::data(Bytes::from_static(b"ok"))], 2),
    Duration::from_secs(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  let SmallResponseDisposition::Inlined { body, inlined, .. } = disposition else {
    panic!("expected inline body");
  };
  assert!(inlined.is_none());
  let bytes = body
    .collect()
    .await
    .expect("inline body should collect")
    .to_bytes();
  assert_eq!(bytes.as_ref(), b"ok");
}

#[tokio::test]
async fn conflicting_size_hint_keeps_streaming_without_polling() {
  let disposition = try_inline_response_body(
    &headers(&["2"]),
    panic_body_with_upper(Some(3)),
    Duration::from_secs(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  assert!(matches!(
    disposition,
    SmallResponseDisposition::Streaming {
      reason: SmallResponseReason::UnknownLength,
      ..
    }
  ));
}

#[tokio::test]
async fn ineligible_unboxed_body_is_boxed_without_polling() {
  let disposition = try_inline_response_body(
    &headers(&["2"]),
    PanicBody { upper: Some(3) },
    Duration::from_secs(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  let SmallResponseDisposition::Streaming { body, reason } = disposition else {
    panic!("expected streaming body");
  };
  assert_eq!(reason, SmallResponseReason::UnknownLength);
  assert_eq!(body.size_hint().upper(), Some(3));
}

#[tokio::test]
async fn large_content_length_keeps_streaming_without_polling() {
  let length = body::KNOWN_SMALL_BODY_MAX_BYTES + 1;
  let content_length = length.to_string();
  let disposition = try_inline_response_body(
    &headers(&[content_length.as_str()]),
    panic_body_with_upper(Some(length as u64)),
    Duration::from_secs(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  assert!(matches!(
    disposition,
    SmallResponseDisposition::Streaming {
      reason: SmallResponseReason::UnknownLength,
      ..
    }
  ));
}

#[tokio::test]
async fn upstream_read_timeout_still_applies_to_inline_collect() {
  let body = PendingBody { length: 2 }.boxed();

  let disposition = try_inline_response_body(
    &headers(&["2"]),
    body,
    Duration::from_millis(1),
    TrailerMode::Drop,
    true,
  )
  .await;

  let SmallResponseDisposition::Error { response, reason } = disposition else {
    panic!("expected timeout response");
  };
  assert_eq!(reason, SmallResponseReason::ReadTimeout);
  assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
}
