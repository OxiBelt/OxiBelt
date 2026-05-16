use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use http::{HeaderMap, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Body;

use crate::config::TrailerMode;
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};
use crate::proxy::http::response::text_response;

pub(super) enum SmallResponseDisposition {
  Inlined(ProxyBody),
  Streaming(ProxyBody),
  Error(Response<ProxyBody>),
}

pub(super) async fn try_inline_response_body(
  headers: &HeaderMap,
  body: ProxyBody,
  timeout: Duration,
  trailer_mode: TrailerMode,
) -> SmallResponseDisposition {
  let Some(length) = exact_known_small_content_length(headers, &body) else {
    return SmallResponseDisposition::Streaming(body);
  };

  let body = body::with_read_timeout(
    Limited::new(body, length),
    timeout,
    BodyTimeoutKind::UpstreamResponseRead,
  );
  let collected = match body.collect().await {
    Ok(collected) => collected,
    Err(error) if body::error_is_timeout(&error, BodyTimeoutKind::UpstreamResponseRead) => {
      return SmallResponseDisposition::Error(text_response(
        StatusCode::GATEWAY_TIMEOUT,
        "upstream response body timed out",
      ));
    }
    Err(error) => {
      return SmallResponseDisposition::Error(text_response(
        StatusCode::BAD_GATEWAY,
        &format!("failed to read upstream response body: {error}"),
      ));
    }
  };

  let trailers = collected.trailers().cloned();
  let bytes = collected.to_bytes();
  if bytes.len() != length {
    return SmallResponseDisposition::Error(text_response(
      StatusCode::BAD_GATEWAY,
      "upstream response body length mismatch",
    ));
  }

  SmallResponseDisposition::Inlined(inline_body(bytes, trailers, trailer_mode))
}

fn exact_known_small_content_length(headers: &HeaderMap, body: &ProxyBody) -> Option<usize> {
  let mut values = headers.get_all(CONTENT_LENGTH).iter();
  let value = values.next()?;
  if values.next().is_some() {
    return None;
  }
  let value = value.to_str().ok()?;
  let length = value.trim().parse::<usize>().ok()?;
  if !body::is_known_small_response_body_len(length) {
    return None;
  }
  body
    .size_hint()
    .upper()
    .is_some_and(|upper| upper == length as u64)
    .then_some(length)
}

fn inline_body(bytes: Bytes, trailers: Option<HeaderMap>, trailer_mode: TrailerMode) -> ProxyBody {
  if trailer_mode == TrailerMode::Pass
    && let Some(trailers) = trailers
  {
    return Full::new(bytes)
      .with_trailers(std::future::ready(Some(Ok::<_, Infallible>(trailers))))
      .map_err(|never| -> body::BoxError { match never {} })
      .boxed();
  }

  full_body(bytes)
}

fn full_body(bytes: Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> body::BoxError { match never {} })
    .boxed()
}

#[cfg(test)]
mod tests {
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

  #[tokio::test]
  async fn exact_small_content_length_collects_inline_body() {
    let body = full_body(Bytes::from_static(b"ok"));

    let disposition = try_inline_response_body(
      &headers(&["2"]),
      body,
      Duration::from_secs(1),
      TrailerMode::Drop,
    )
    .await;

    let SmallResponseDisposition::Inlined(body) = disposition else {
      panic!("expected inline body");
    };
    let bytes = body
      .collect()
      .await
      .expect("inline body should collect")
      .to_bytes();
    assert_eq!(bytes.as_ref(), b"ok");
  }

  #[tokio::test]
  async fn duplicate_content_length_keeps_streaming_without_polling() {
    let disposition = try_inline_response_body(
      &headers(&["2", "2"]),
      panic_body_with_upper(Some(2)),
      Duration::from_secs(1),
      TrailerMode::Drop,
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
    )
    .await;

    assert!(matches!(
      disposition,
      SmallResponseDisposition::Streaming(_)
    ));
  }

  #[tokio::test]
  async fn unknown_size_hint_keeps_streaming_without_polling() {
    let disposition = try_inline_response_body(
      &headers(&["2"]),
      panic_body_with_upper(None),
      Duration::from_secs(1),
      TrailerMode::Drop,
    )
    .await;

    assert!(matches!(
      disposition,
      SmallResponseDisposition::Streaming(_)
    ));
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
    )
    .await;

    let SmallResponseDisposition::Error(response) = disposition else {
      panic!("expected timeout response");
    };
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
  }
}
