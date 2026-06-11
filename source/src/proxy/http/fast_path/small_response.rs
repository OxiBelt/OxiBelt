use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::header::CONTENT_LENGTH;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Body;

use crate::config::TrailerMode;
use crate::proxy::http::body::{self, ProxyBody};
use crate::proxy::http::response::text_response;

pub(super) enum SmallResponseDisposition {
  Inlined {
    body: ProxyBody,
    inlined: Option<body::InlinedKnownSmallResponseBody>,
  },
  Streaming(ProxyBody),
  Error(Response<ProxyBody>),
}

pub(super) async fn try_inline_response_body<B>(
  headers: &HeaderMap,
  body: B,
  timeout: Duration,
  trailer_mode: TrailerMode,
  materialize_body: bool,
) -> SmallResponseDisposition
where
  B: Body<Data = Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  let Some(length) = exact_known_small_content_length(headers, &body) else {
    return SmallResponseDisposition::Streaming(box_body(body));
  };

  let collected = match collect_exact_small_response_body(body, length, timeout).await {
    Ok(collected) => collected,
    Err(SmallResponseReadError::Timeout) => {
      return SmallResponseDisposition::Error(text_response(
        StatusCode::GATEWAY_TIMEOUT,
        "upstream response body timed out",
      ));
    }
    Err(SmallResponseReadError::LengthMismatch) => {
      return SmallResponseDisposition::Error(text_response(
        StatusCode::BAD_GATEWAY,
        "upstream response body length mismatch",
      ));
    }
    Err(SmallResponseReadError::Body(error)) => {
      return SmallResponseDisposition::Error(text_response(
        StatusCode::BAD_GATEWAY,
        &format!("failed to read upstream response body: {error}"),
      ));
    }
  };

  let trailers = if trailer_mode == TrailerMode::Pass {
    collected.trailers
  } else {
    None
  };
  if materialize_body {
    let body = inline_body(collected.bytes, trailers);
    return SmallResponseDisposition::Inlined {
      body,
      inlined: None,
    };
  }

  let inlined = body::InlinedKnownSmallResponseBody::new(collected.bytes, trailers);
  SmallResponseDisposition::Inlined {
    body: empty_body(),
    inlined: Some(inlined),
  }
}

struct CollectedSmallResponse {
  bytes: Bytes,
  trailers: Option<HeaderMap>,
}

enum SmallResponseReadError {
  Timeout,
  LengthMismatch,
  Body(body::BoxError),
}

async fn collect_exact_small_response_body<B>(
  mut body: B,
  length: usize,
  timeout: Duration,
) -> Result<CollectedSmallResponse, SmallResponseReadError>
where
  B: Body<Data = Bytes> + Unpin,
  B::Error: Into<body::BoxError>,
{
  let mut first_chunk = None;
  let mut buffered = BytesMut::new();
  let mut total = 0usize;
  let mut trailers = None;

  loop {
    if total == length && body.is_end_stream() {
      break;
    }

    let frame = match poll_response_body_once(&mut body) {
      Poll::Ready(frame) => frame,
      Poll::Pending => tokio::time::timeout(timeout, body.frame())
        .await
        .map_err(|_| SmallResponseReadError::Timeout)?
        .map(|frame| frame.map_err(Into::into)),
    };
    let Some(frame) = frame else {
      break;
    };
    let frame = frame.map_err(SmallResponseReadError::Body)?;
    match frame.into_data() {
      Ok(data) => {
        if data.is_empty() {
          continue;
        }
        total = total
          .checked_add(data.len())
          .ok_or(SmallResponseReadError::LengthMismatch)?;
        if total > length {
          return Err(SmallResponseReadError::LengthMismatch);
        }
        if first_chunk.is_none() && buffered.is_empty() {
          first_chunk = Some(data);
        } else {
          if let Some(first) = first_chunk.take() {
            buffered.reserve(length);
            buffered.extend_from_slice(&first);
          }
          buffered.extend_from_slice(&data);
        }
      }
      Err(frame) => {
        if let Ok(frame_trailers) = frame.into_trailers() {
          trailers = Some(frame_trailers);
          break;
        }
      }
    }
  }

  if total != length {
    return Err(SmallResponseReadError::LengthMismatch);
  }

  let bytes = if let Some(chunk) = first_chunk {
    chunk
  } else if buffered.is_empty() {
    Bytes::new()
  } else {
    buffered.freeze()
  };
  Ok(CollectedSmallResponse { bytes, trailers })
}

fn poll_response_body_once<B>(
  body: &mut B,
) -> Poll<Option<Result<hyper::body::Frame<Bytes>, body::BoxError>>>
where
  B: Body<Data = Bytes> + Unpin,
  B::Error: Into<body::BoxError>,
{
  let mut context = Context::from_waker(futures_util::task::noop_waker_ref());
  match Pin::new(body).poll_frame(&mut context) {
    Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
    Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error.into()))),
    Poll::Ready(None) => Poll::Ready(None),
    Poll::Pending => Poll::Pending,
  }
}

fn exact_known_small_content_length<B>(headers: &HeaderMap, body: &B) -> Option<usize>
where
  B: Body,
{
  let mut values = headers.get_all(CONTENT_LENGTH).iter();
  let value = values.next()?;
  if values.next().is_some() {
    return None;
  }
  let length = parse_small_content_length(value)?;
  if !body::is_known_small_response_body_len(length) {
    return None;
  }
  match body.size_hint().upper() {
    Some(upper) if upper != length as u64 => None,
    _ => Some(length),
  }
}

fn parse_small_content_length(value: &http::HeaderValue) -> Option<usize> {
  parse_ascii_content_length(value.as_bytes())
    .or_else(|| value.to_str().ok()?.trim().parse::<usize>().ok())
}

fn parse_ascii_content_length(bytes: &[u8]) -> Option<usize> {
  let mut length = 0usize;
  let mut digits = 0usize;
  for &byte in bytes {
    if !byte.is_ascii_digit() {
      return None;
    }
    digits += 1;
    length = length
      .checked_mul(10)?
      .checked_add(usize::from(byte - b'0'))?;
    if !body::is_known_small_response_body_len(length) {
      return None;
    }
  }
  (digits != 0).then_some(length)
}

fn inline_body(data: Bytes, trailers: Option<HeaderMap>) -> ProxyBody {
  if let Some(trailers) = trailers {
    return Full::new(data)
      .with_trailers(std::future::ready(Some(Ok::<_, Infallible>(trailers))))
      .map_err(|never| -> body::BoxError { match never {} })
      .boxed();
  }

  full_body(data)
}

fn box_body<B>(body: B) -> ProxyBody
where
  B: Body<Data = Bytes> + Send + Sync + 'static,
  B::Error: Into<body::BoxError> + 'static,
{
  body
    .map_err(|error| -> body::BoxError { error.into() })
    .boxed()
}

fn full_body(bytes: Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}

fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;
  use std::pin::Pin;
  use std::task::{Context, Poll};

  use http_body_util::BodyExt;
  use hyper::body::{Frame, SizeHint};
  use pretty_assertions::assert_eq;

  use super::*;

  struct PanicBody {
    upper: Option<u64>,
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

  struct PendingBody {
    length: u64,
  }

  struct FramesBody {
    frames: VecDeque<Frame<Bytes>>,
    length: u64,
    exact_size_hint: bool,
  }

  struct EndAfterDataBody {
    yielded: bool,
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

  impl Body for EndAfterDataBody {
    type Data = Bytes;
    type Error = body::BoxError;

    fn poll_frame(
      mut self: Pin<&mut Self>,
      _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
      if self.yielded {
        panic!("end-stream body should not be polled after final data");
      }
      self.yielded = true;
      Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"ok")))))
    }

    fn is_end_stream(&self) -> bool {
      self.yielded
    }

    fn size_hint(&self) -> SizeHint {
      SizeHint::with_exact(2)
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
  async fn exact_small_content_length_collects_inline_body() {
    let body = full_body(Bytes::from_static(b"ok"));

    let disposition = try_inline_response_body(
      &headers(&["2"]),
      body,
      Duration::from_secs(1),
      TrailerMode::Drop,
      true,
    )
    .await;

    let SmallResponseDisposition::Inlined { body, inlined } = disposition else {
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
  async fn exact_small_content_length_can_skip_materialized_body() {
    let body = full_body(Bytes::from_static(b"ok"));

    let disposition = try_inline_response_body(
      &headers(&["2"]),
      body,
      Duration::from_secs(1),
      TrailerMode::Drop,
      false,
    )
    .await;

    let SmallResponseDisposition::Inlined { body, inlined } = disposition else {
      panic!("expected inline body");
    };
    let inlined = inlined.expect("skipped materialized body should preserve metadata");
    assert_eq!(inlined.data.as_ref(), b"ok");
    let bytes = body
      .collect()
      .await
      .expect("placeholder body should collect")
      .to_bytes();
    assert!(bytes.is_empty());
  }

  #[tokio::test]
  async fn exact_small_content_length_collects_unboxed_body_before_boxing() {
    let body = FramesBody {
      frames: vec![Frame::data(Bytes::from_static(b"ok"))].into(),
      length: 2,
      exact_size_hint: true,
    };

    let disposition = try_inline_response_body(
      &headers(&["2"]),
      body,
      Duration::from_secs(1),
      TrailerMode::Drop,
      false,
    )
    .await;

    let SmallResponseDisposition::Inlined { body, inlined } = disposition else {
      panic!("expected inline body");
    };
    let inlined = inlined.expect("skipped materialized body should preserve metadata");
    assert_eq!(inlined.data.as_ref(), b"ok");
    let bytes = body
      .collect()
      .await
      .expect("placeholder body should collect")
      .to_bytes();
    assert!(bytes.is_empty());
  }

  #[tokio::test]
  async fn exact_small_content_length_uses_end_stream_shortcut() {
    let body = EndAfterDataBody { yielded: false }.boxed();

    let disposition = try_inline_response_body(
      &headers(&["2"]),
      body,
      Duration::from_secs(1),
      TrailerMode::Drop,
      true,
    )
    .await;

    let SmallResponseDisposition::Inlined { body, inlined } = disposition else {
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
  async fn trimmed_content_length_fallback_still_collects_inline_body() {
    let body = full_body(Bytes::from_static(b"ok"));

    let disposition = try_inline_response_body(
      &headers(&[" 2 "]),
      body,
      Duration::from_secs(1),
      TrailerMode::Drop,
      true,
    )
    .await;

    let SmallResponseDisposition::Inlined { body, inlined } = disposition else {
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
  async fn exact_small_content_length_preserves_trailers_when_enabled() {
    let mut trailers = HeaderMap::new();
    trailers.insert("x-trailer", "kept".parse().unwrap());
    let body = frames_body(
      vec![
        Frame::data(Bytes::from_static(b"ok")),
        Frame::trailers(trailers),
      ],
      2,
    );

    let disposition = try_inline_response_body(
      &headers(&["2"]),
      body,
      Duration::from_secs(1),
      TrailerMode::Pass,
      true,
    )
    .await;

    let SmallResponseDisposition::Inlined { body, inlined } = disposition else {
      panic!("expected inline body");
    };
    assert!(inlined.is_none());
    let collected = body.collect().await.expect("inline body should collect");
    assert_eq!(
      collected.trailers().expect("trailers should be preserved")["x-trailer"],
      "kept"
    );
    assert_eq!(collected.to_bytes().as_ref(), b"ok");
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

    let SmallResponseDisposition::Error(response) = disposition else {
      panic!("expected length mismatch response");
    };
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

    let SmallResponseDisposition::Error(response) = disposition else {
      panic!("expected length mismatch response");
    };
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
      SmallResponseDisposition::Streaming(_)
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
      SmallResponseDisposition::Streaming(_)
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

    let SmallResponseDisposition::Inlined { body, inlined } = disposition else {
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
      SmallResponseDisposition::Streaming(_)
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

    let SmallResponseDisposition::Streaming(body) = disposition else {
      panic!("expected streaming body");
    };
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
      SmallResponseDisposition::Streaming(_)
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

    let SmallResponseDisposition::Error(response) = disposition else {
      panic!("expected timeout response");
    };
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
  }
}
