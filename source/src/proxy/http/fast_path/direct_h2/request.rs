use bytes::Bytes;
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Empty};

use crate::proxy::http::body::{BoxError, ProxyBody};

pub(super) struct PreparedDirectH2Request {
  pub(super) request: Request<ProxyBody>,
  fallback_version: http::Version,
}

pub(super) struct RetryDirectH2Request {
  method: Method,
  uri: Uri,
  headers: http::HeaderMap,
  fallback_version: http::Version,
}

impl PreparedDirectH2Request {
  pub(super) fn from_request(mut request: Request<ProxyBody>) -> anyhow::Result<Self> {
    if request.uri().scheme().is_none() || request.uri().authority().is_none() {
      anyhow::bail!("direct H2 request URI must be absolute-form");
    }
    let fallback_version = request.version();
    *request.version_mut() = http::Version::HTTP_2;
    Ok(Self {
      request,
      fallback_version,
    })
  }

  pub(super) fn retry_request(&self) -> RetryDirectH2Request {
    RetryDirectH2Request {
      method: self.request.method().clone(),
      uri: self.request.uri().clone(),
      headers: self.request.headers().clone(),
      fallback_version: self.fallback_version,
    }
  }

  pub(super) fn into_request(self) -> Request<ProxyBody> {
    self.request
  }

  pub(super) fn into_fallback_request(mut self) -> Request<ProxyBody> {
    *self.request.version_mut() = self.fallback_version;
    self.request
  }
}

impl RetryDirectH2Request {
  #[allow(
    clippy::expect_used,
    reason = "retry method, URI, version, and headers were captured from a valid request"
  )]
  pub(super) fn into_request(self) -> Request<ProxyBody> {
    let mut request = Request::builder()
      .method(self.method)
      .version(http::Version::HTTP_2)
      .uri(self.uri)
      .body(empty_body())
      .expect("direct H2 retry request parts should be valid");
    *request.headers_mut() = self.headers;
    request
  }

  #[allow(
    clippy::expect_used,
    reason = "fallback method, URI, version, and headers were captured from a valid request"
  )]
  pub(super) fn into_fallback_request(self) -> Request<ProxyBody> {
    let mut request = Request::builder()
      .method(self.method)
      .version(self.fallback_version)
      .uri(self.uri)
      .body(empty_body())
      .expect("direct H2 fallback request parts should be valid");
    *request.headers_mut() = self.headers;
    request
  }
}

pub(super) fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}
