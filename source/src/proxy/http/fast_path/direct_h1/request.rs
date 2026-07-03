use anyhow::Context;
use bytes::Bytes;
use http::header::HOST;
use http::{HeaderMap, HeaderValue, Method, Request, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Body;

use crate::proxy::http::body::{BoxError, ProxyBody};

use super::origin::DirectH1Origin;

pub(super) struct PreparedDirectH1Request {
  request: Request<ProxyBody>,
  retry_request: Option<RetryDirectH1Request>,
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
    let retry_body_empty = body.is_end_stream();
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
    let retry_request = retry_body_empty.then(|| RetryDirectH1Request {
      method: parts.method.clone(),
      uri: parts.uri.clone(),
      headers: parts.headers.clone(),
    });
    Ok(Self {
      request: Request::from_parts(parts, body),
      retry_request,
    })
  }

  pub(super) fn retry_request(&self) -> Option<RetryDirectH1Request> {
    self.retry_request.clone()
  }

  pub(super) fn into_request(self) -> Request<ProxyBody> {
    self.request
  }
}

impl RetryDirectH1Request {
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
