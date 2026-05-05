use http::header::{ACCEPT_ENCODING, HOST, HeaderValue};
use http::{Request, Uri};
use http_body_util::BodyExt;
use hyper::body::Incoming;

use crate::config::{CompressionConfig, HttpVersion};
use crate::waf::{HeaderMutation, apply_header_mutations};

use super::body::{ProxyBody, boxed_error};
use super::headers::{add_forwarded_headers, strip_hop_by_hop_headers};
use super::version::upstream_request_version;

pub(super) struct RebuildRequestOptions<'a> {
  pub(super) target_uri: Uri,
  pub(super) compression: &'a CompressionConfig,
  pub(super) peer_addr: std::net::SocketAddr,
  pub(super) downstream_host: &'a str,
  pub(super) preserve_host: bool,
  pub(super) upstream_version: HttpVersion,
  pub(super) waf_mutations: &'a [HeaderMutation],
}

pub(super) fn rebuild_request(
  request: Request<Incoming>,
  options: RebuildRequestOptions<'_>,
) -> Request<ProxyBody> {
  let (mut parts, body) = request.into_parts();
  parts.uri = options.target_uri;
  parts.version = upstream_request_version(options.upstream_version);
  strip_hop_by_hop_headers(&mut parts.headers);

  if !options.preserve_host {
    parts.headers.remove(HOST);
  }

  add_forwarded_headers(
    &mut parts.headers,
    options.peer_addr,
    options.downstream_host,
  );

  if !parts.headers.contains_key(ACCEPT_ENCODING)
    && let Some(accept_encoding) = options.compression.accept_encoding_value()
    && let Ok(value) = HeaderValue::from_str(&accept_encoding)
  {
    parts.headers.insert(ACCEPT_ENCODING, value);
  }

  apply_header_mutations(&mut parts.headers, options.waf_mutations);

  Request::from_parts(parts, body.map_err(boxed_error).boxed())
}
