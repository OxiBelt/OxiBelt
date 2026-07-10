use std::fmt;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use ::http::Request;
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Frame, SizeHint};

use crate::proxy::http::body::{BoxError, ProxyBody, boxed_error};
use crate::proxy::http::headers::sanitize_request_trailers_for_upstream;
use crate::proxy::http::request_framing::{
  VerifiedEmptyRequestBody, h2_or_h3_safe_method_empty_probe_allowed,
};

use super::H3RequestRecvStream;

pub(super) struct PreparedH3RequestBody {
  pub(super) request: Request<ProxyBody>,
  pub(super) verified_empty: bool,
  pub(super) inline_readiness: PreparedH3RequestBodyReadiness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PreparedH3RequestBodyReadiness {
  InlineReady,
  Spawn,
}

pub(super) async fn prepare_h3_request_body(
  request: Request<()>,
  stream: H3RequestRecvStream,
) -> Request<ProxyBody> {
  prepare_h3_request_body_inner(request, stream).await.request
}

pub(super) async fn prepare_h3_request_body_with_verification(
  request: Request<()>,
  stream: H3RequestRecvStream,
) -> PreparedH3RequestBody {
  prepare_h3_request_body_inner(request, stream).await
}

trait H3RequestBodyStream: Send + Unpin + 'static {
  type Error: fmt::Display + Send + Sync + 'static;

  fn poll_recv_data_bytes(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>, Self::Error>>;

  fn poll_recv_trailers(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>>;
}

impl H3RequestBodyStream for H3RequestRecvStream {
  type Error = h3::error::StreamError;

  fn poll_recv_data_bytes(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<Bytes>, Self::Error>> {
    self.poll_recv_data(cx).map(|result| {
      result.map(|chunk| {
        chunk.map(|mut chunk| {
          let len = chunk.remaining();
          chunk.copy_to_bytes(len)
        })
      })
    })
  }

  fn poll_recv_trailers(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<Result<Option<http::HeaderMap>, Self::Error>> {
    self.poll_recv_trailers(cx)
  }
}

async fn prepare_h3_request_body_inner<S>(
  request: Request<()>,
  mut stream: S,
) -> PreparedH3RequestBody
where
  S: H3RequestBodyStream,
{
  let empty_probe_allowed = h2_or_h3_safe_method_empty_probe_allowed(
    request.method(),
    http::Version::HTTP_3,
    request.headers(),
  );

  let first = poll_h3_request_body_once(&mut stream).await;

  match first {
    Some(Ok(None)) => {
      if empty_probe_allowed {
        match poll_h3_request_trailers_once(&mut stream).await {
          Some(Ok(None)) => {
            let (parts, _) = request.into_parts();
            drop(stream);
            verified_empty_request(parts)
          }
          Some(Ok(Some(trailers))) => direct_h3_request_body_with_initial(
            request,
            stream,
            Some(Ok(sanitized_h3_request_trailers_frame(trailers))),
            H3DirectRequestBodyState::End,
            PreparedH3RequestBodyReadiness::Spawn,
          ),
          Some(Err(error)) => direct_h3_request_body_with_initial(
            request,
            stream,
            Some(Err(downstream_h3_request_trailers_error(error))),
            H3DirectRequestBodyState::End,
            PreparedH3RequestBodyReadiness::Spawn,
          ),
          None => direct_h3_request_body_after_data_eof(request, stream),
        }
      } else {
        direct_h3_request_body_after_data_eof(request, stream)
      }
    }
    Some(Ok(Some(chunk))) => direct_h3_request_body_with_initial(
      request,
      stream,
      Some(Ok(Frame::data(chunk))),
      H3DirectRequestBodyState::Data,
      PreparedH3RequestBodyReadiness::Spawn,
    ),
    Some(Err(error)) => direct_h3_request_body_with_initial(
      request,
      stream,
      Some(Err(downstream_h3_request_body_error(error))),
      H3DirectRequestBodyState::End,
      PreparedH3RequestBodyReadiness::Spawn,
    ),
    None => direct_h3_request_body(request, stream),
  }
}

async fn poll_h3_request_body_once<S>(stream: &mut S) -> Option<Result<Option<Bytes>, S::Error>>
where
  S: H3RequestBodyStream,
{
  poll_fn(|cx| match stream.poll_recv_data_bytes(cx) {
    Poll::Ready(result) => Poll::Ready(Some(result)),
    Poll::Pending => Poll::Ready(None),
  })
  .await
}

async fn poll_h3_request_trailers_once<S>(
  stream: &mut S,
) -> Option<Result<Option<http::HeaderMap>, S::Error>>
where
  S: H3RequestBodyStream,
{
  poll_fn(|cx| match stream.poll_recv_trailers(cx) {
    Poll::Ready(result) => Poll::Ready(Some(result)),
    Poll::Pending => Poll::Ready(None),
  })
  .await
}

fn direct_h3_request_body<S>(request: Request<()>, stream: S) -> PreparedH3RequestBody
where
  S: H3RequestBodyStream,
{
  direct_h3_request_body_with_initial(
    request,
    stream,
    None,
    H3DirectRequestBodyState::Data,
    PreparedH3RequestBodyReadiness::Spawn,
  )
}

fn direct_h3_request_body_after_data_eof<S>(
  request: Request<()>,
  stream: S,
) -> PreparedH3RequestBody
where
  S: H3RequestBodyStream,
{
  direct_h3_request_body_with_initial(
    request,
    stream,
    None,
    H3DirectRequestBodyState::Trailers,
    PreparedH3RequestBodyReadiness::Spawn,
  )
}

fn direct_h3_request_body_with_initial<S>(
  request: Request<()>,
  stream: S,
  initial_frame: Option<Result<Frame<Bytes>, BoxError>>,
  state: H3DirectRequestBodyState,
  inline_readiness: PreparedH3RequestBodyReadiness,
) -> PreparedH3RequestBody
where
  S: H3RequestBodyStream,
{
  let (parts, _) = request.into_parts();
  let body = H3DirectRequestBody {
    initial_frame,
    stream: Mutex::new(stream),
    state,
  }
  .boxed();
  PreparedH3RequestBody {
    request: Request::from_parts(parts, body),
    verified_empty: false,
    inline_readiness,
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3DirectRequestBodyState {
  Data,
  Trailers,
  End,
}

struct H3DirectRequestBody<S> {
  initial_frame: Option<Result<Frame<Bytes>, BoxError>>,
  stream: Mutex<S>,
  state: H3DirectRequestBodyState,
}

impl<S> Body for H3DirectRequestBody<S>
where
  S: H3RequestBodyStream,
{
  type Data = Bytes;
  type Error = BoxError;

  fn poll_frame(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
    let this = self.get_mut();
    if let Some(frame) = this.initial_frame.take() {
      return Poll::Ready(Some(frame));
    }

    let stream = match this.stream.get_mut() {
      Ok(stream) => stream,
      Err(poisoned) => poisoned.into_inner(),
    };
    loop {
      match this.state {
        H3DirectRequestBodyState::Data => match stream.poll_recv_data_bytes(cx) {
          Poll::Ready(Ok(Some(chunk))) => return Poll::Ready(Some(Ok(Frame::data(chunk)))),
          Poll::Ready(Ok(None)) => this.state = H3DirectRequestBodyState::Trailers,
          Poll::Ready(Err(error)) => {
            this.state = H3DirectRequestBodyState::End;
            return Poll::Ready(Some(Err(downstream_h3_request_body_error(error))));
          }
          Poll::Pending => return Poll::Pending,
        },
        H3DirectRequestBodyState::Trailers => match stream.poll_recv_trailers(cx) {
          Poll::Ready(Ok(Some(trailers))) => {
            this.state = H3DirectRequestBodyState::End;
            return Poll::Ready(Some(Ok(sanitized_h3_request_trailers_frame(trailers))));
          }
          Poll::Ready(Ok(None)) => {
            this.state = H3DirectRequestBodyState::End;
            return Poll::Ready(None);
          }
          Poll::Ready(Err(error)) => {
            this.state = H3DirectRequestBodyState::End;
            return Poll::Ready(Some(Err(downstream_h3_request_trailers_error(error))));
          }
          Poll::Pending => return Poll::Pending,
        },
        H3DirectRequestBodyState::End => return Poll::Ready(None),
      }
    }
  }

  fn is_end_stream(&self) -> bool {
    self.initial_frame.is_none() && self.state == H3DirectRequestBodyState::End
  }

  fn size_hint(&self) -> SizeHint {
    SizeHint::new()
  }
}

fn sanitized_h3_request_trailers_frame(mut trailers: http::HeaderMap) -> Frame<Bytes> {
  sanitize_request_trailers_for_upstream(&mut trailers);
  Frame::trailers(trailers)
}

fn downstream_h3_request_body_error(error: impl fmt::Display) -> BoxError {
  boxed_error(std::io::Error::other(format!(
    "failed to receive downstream HTTP/3 request data: {error}"
  )))
}

fn downstream_h3_request_trailers_error(error: impl fmt::Display) -> BoxError {
  boxed_error(std::io::Error::other(format!(
    "failed to receive downstream HTTP/3 request trailers: {error}"
  )))
}

fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}

fn verified_empty_request(parts: http::request::Parts) -> PreparedH3RequestBody {
  let mut request = Request::from_parts(parts, empty_body());
  request.extensions_mut().insert(VerifiedEmptyRequestBody);
  PreparedH3RequestBody {
    request,
    verified_empty: true,
    inline_readiness: PreparedH3RequestBodyReadiness::InlineReady,
  }
}

#[cfg(test)]
#[path = "request_body_tests.rs"]
mod tests;
