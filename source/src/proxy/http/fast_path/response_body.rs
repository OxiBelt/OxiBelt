use http::{HeaderMap, Response};
use hyper::body::Body;

use crate::config::TrailerMode;
use crate::proxy::http::body::{self, BodyTimeoutKind, ProxyBody};
use crate::proxy::http::semantics::filter_trailers;

use super::small_response::{SmallResponseDisposition, try_inline_response_body};

pub(super) struct FastPathResponseBody {
  pub(super) body: ProxyBody,
  pub(super) known_small_response_body: bool,
  pub(super) inlined_known_small_body: Option<body::InlinedKnownSmallResponseBody>,
  pub(super) trailers_handled: bool,
  pub(super) disposition: &'static str,
  pub(super) reason: &'static str,
}

pub(super) struct FastPathResponseBodyError {
  pub(super) response: Response<ProxyBody>,
  pub(super) reason: &'static str,
}

pub(super) async fn fast_path_response_body<B>(
  headers: &HeaderMap,
  response_body: B,
  upstream_read_timeout: std::time::Duration,
  trailer_mode: TrailerMode,
  request_version: http::Version,
) -> Result<FastPathResponseBody, FastPathResponseBodyError>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  match try_inline_response_body(
    headers,
    response_body,
    upstream_read_timeout,
    trailer_mode,
    request_version != http::Version::HTTP_3,
  )
  .await
  {
    SmallResponseDisposition::Inlined { body, inlined } => Ok(FastPathResponseBody {
      body,
      known_small_response_body: true,
      inlined_known_small_body: inlined,
      trailers_handled: true,
      disposition: "inlined",
      reason: "known_small",
    }),
    SmallResponseDisposition::Streaming { body, .. } if body.is_end_stream() => {
      Ok(FastPathResponseBody {
        body,
        known_small_response_body: true,
        inlined_known_small_body: None,
        trailers_handled: true,
        disposition: "inlined",
        reason: "empty",
      })
    }
    SmallResponseDisposition::Streaming { body, reason } => Ok(FastPathResponseBody {
      body: body::with_read_timeout(
        body,
        upstream_read_timeout,
        BodyTimeoutKind::UpstreamResponseRead,
      ),
      known_small_response_body: false,
      inlined_known_small_body: None,
      trailers_handled: false,
      disposition: "streamed",
      reason: reason.as_str(),
    }),
    SmallResponseDisposition::Error { response, reason } => Err(FastPathResponseBodyError {
      response,
      reason: reason.as_str(),
    }),
  }
}

pub(super) fn fast_path_filter_trailers(body: ProxyBody, mode: TrailerMode) -> ProxyBody {
  if body.is_end_stream() {
    return body;
  }
  if mode == TrailerMode::Pass {
    return body;
  }
  filter_trailers(body, mode, false)
}
