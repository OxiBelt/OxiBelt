use anyhow::Context;
use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{HeaderMap, HeaderValue, Method, Request, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Body;

use crate::proxy::http::body::{BoxError, ProxyBody};

use super::origin::DirectH1Origin;

pub(super) struct PreparedDirectH1Request {
  request: Request<ProxyBody>,
}

#[derive(Clone)]
pub(super) struct PrevalidatedDirectH1Request;

#[derive(Clone)]
pub(super) struct RetryDirectH1Request {
  method: Method,
  uri: Uri,
  headers: HeaderMap,
}

pub(in crate::proxy::http::fast_path) fn mark_prevalidated_direct_h1_request(
  request: &mut Request<ProxyBody>,
) {
  request.extensions_mut().insert(PrevalidatedDirectH1Request);
}

impl PreparedDirectH1Request {
  pub(super) fn from_request(
    request: Request<ProxyBody>,
    origin: &DirectH1Origin,
  ) -> anyhow::Result<Self> {
    let (mut parts, body) = request.into_parts();
    let prevalidated = parts
      .extensions
      .remove::<PrevalidatedDirectH1Request>()
      .is_some();
    let upstream_authority = if prevalidated {
      None
    } else {
      parts.uri.authority().map(|authority| authority.as_str())
    };
    ensure_host_header(&mut parts.headers, upstream_authority, origin)?;
    if !prevalidated {
      let path_and_query = parts
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
      let mut uri_parts = http::uri::Parts::default();
      uri_parts.path_and_query = Some(path_and_query);
      parts.uri =
        Uri::from_parts(uri_parts).context("failed to build direct H1 origin-form URI")?;
    }
    parts.version = http::Version::HTTP_11;
    Ok(Self {
      request: Request::from_parts(parts, body),
    })
  }

  pub(super) fn retry_request(&self) -> Option<RetryDirectH1Request> {
    self
      .request
      .body()
      .is_end_stream()
      .then(|| RetryDirectH1Request {
        method: self.request.method().clone(),
        uri: self.request.uri().clone(),
        headers: self.request.headers().clone(),
      })
  }

  pub(super) fn compio_empty_body_wire_eligible(&self) -> bool {
    self.request.body().is_end_stream()
      && !self.request.headers().contains_key(TRANSFER_ENCODING)
      && self
        .request
        .headers()
        .get_all(CONTENT_LENGTH)
        .iter()
        .all(|value| value.as_bytes().trim_ascii() == b"0")
  }

  pub(super) fn request(&self) -> &Request<ProxyBody> {
    &self.request
  }

  /// Serialize the already-normalized, bodyless request into an owned worker
  /// buffer. Callers retain `self` until the first socket write is submitted,
  /// which keeps pre-dispatch fallback ownership explicit.
  pub(super) fn serialize_compio_wire(&self, bytes: &mut Vec<u8>) -> anyhow::Result<()> {
    if !self.compio_empty_body_wire_eligible() {
      anyhow::bail!("Compio direct-H1 only serializes prevalidated empty request bodies");
    }
    bytes.clear();
    bytes.reserve(512usize.saturating_add(self.request.headers().len().saturating_mul(48)));
    bytes.extend_from_slice(self.request.method().as_str().as_bytes());
    bytes.push(b' ');
    let target = self
      .request
      .uri()
      .path_and_query()
      .map(|target| target.as_str())
      .unwrap_or("/");
    bytes.extend_from_slice(target.as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in self.request.headers() {
      bytes.extend_from_slice(name.as_str().as_bytes());
      bytes.extend_from_slice(b": ");
      bytes.extend_from_slice(value.as_bytes());
      bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    Ok(())
  }

  pub(super) fn into_request(self) -> Request<ProxyBody> {
    self.request
  }
}

impl RetryDirectH1Request {
  #[allow(
    clippy::expect_used,
    reason = "retry method, URI, and headers were captured from a valid request"
  )]
  pub(super) fn into_request(self) -> Request<ProxyBody> {
    let mut request = Request::builder()
      .method(self.method)
      .version(http::Version::HTTP_11)
      .uri(self.uri)
      .body(empty_body())
      .expect("direct H1 retry request parts should be valid");
    *request.headers_mut() = self.headers;
    request
  }
}

fn ensure_host_header(
  headers: &mut HeaderMap,
  upstream_authority: Option<&str>,
  origin: &DirectH1Origin,
) -> anyhow::Result<()> {
  if headers.contains_key(HOST) {
    return Ok(());
  }
  let value = match upstream_authority {
    Some(authority) => {
      HeaderValue::from_str(authority).context("upstream authority is not a header value")?
    }
    None => origin.authority_header.clone(),
  };
  headers.insert(HOST, value);
  Ok(())
}

pub(super) fn empty_body() -> ProxyBody {
  Empty::<Bytes>::new()
    .map_err(|never| -> BoxError { match never {} })
    .boxed()
}
