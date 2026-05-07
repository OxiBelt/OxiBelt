use http::header::{ACCEPT_ENCODING, HOST};
use http::{Request, Uri};
use http_body_util::BodyExt;
use hyper::body::Body;

use crate::config::{CompressionConfig, ForwardedHeaderMode, HttpVersion};
use crate::waf::{HeaderMutation, apply_header_mutations};

use super::body::{BoxError, ProxyBody};
use super::headers::{add_forwarded_headers, strip_hop_by_hop_headers};
use super::version::upstream_request_version;

pub(crate) struct RebuildRequestOptions<'a> {
  pub(crate) target_uri: Uri,
  pub(crate) compression: &'a CompressionConfig,
  pub(crate) peer_addr: std::net::SocketAddr,
  pub(crate) downstream_host: &'a str,
  pub(crate) downstream_scheme: &'a str,
  pub(crate) forwarded_header_mode: ForwardedHeaderMode,
  pub(crate) preserve_host: bool,
  pub(crate) upstream_version: HttpVersion,
  pub(crate) waf_mutations: &'a [HeaderMutation],
}

pub(crate) fn rebuild_request<B>(
  request: Request<B>,
  options: RebuildRequestOptions<'_>,
) -> Request<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<BoxError> + Send + Sync + 'static,
{
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
    options.downstream_scheme,
    options.forwarded_header_mode,
  );

  if options.compression.enabled {
    parts.headers.remove(ACCEPT_ENCODING);
  }

  apply_header_mutations(&mut parts.headers, options.waf_mutations);

  Request::from_parts(parts, body.map_err(Into::into).boxed())
}
