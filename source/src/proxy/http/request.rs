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

#[cfg(test)]
mod tests {
  use bytes::Bytes;
  use http_body_util::Full;
  use pretty_assertions::assert_eq;

  use super::*;

  fn empty_proxy_body() -> ProxyBody {
    Full::new(Bytes::new())
      .map_err(|never| -> BoxError { match never {} })
      .boxed()
  }

  fn rebuild_options<'a>(
    target_uri: Uri,
    compression: &'a CompressionConfig,
    downstream_host: &'a str,
    preserve_host: bool,
  ) -> RebuildRequestOptions<'a> {
    RebuildRequestOptions {
      target_uri,
      compression,
      peer_addr: "203.0.113.10:5443".parse().unwrap(),
      downstream_host,
      downstream_scheme: "https",
      forwarded_header_mode: ForwardedHeaderMode::Overwrite,
      preserve_host,
      upstream_version: HttpVersion::H1,
      waf_mutations: &[],
    }
  }

  #[test]
  fn rebuild_request_does_not_forward_absolute_form_authority_as_host_by_default() {
    let request = Request::builder()
      .uri("http://absolute.example/app?q=1")
      .header(HOST, "header.example")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig::default();

    let rebuilt = rebuild_request(
      request,
      rebuild_options(
        "http://upstream.internal/base/app?q=1".parse().unwrap(),
        &compression,
        "absolute.example",
        false,
      ),
    );

    assert_eq!(
      rebuilt.uri().to_string(),
      "http://upstream.internal/base/app?q=1"
    );
    assert!(!rebuilt.headers().contains_key(HOST));
    assert_eq!(rebuilt.headers()["x-forwarded-host"], "absolute.example");
  }

  #[test]
  fn rebuild_request_preserves_host_only_when_configured() {
    let request = Request::builder()
      .uri("http://absolute.example/app?q=1")
      .header(HOST, "header.example")
      .body(empty_proxy_body())
      .expect("request should build");
    let compression = CompressionConfig::default();

    let rebuilt = rebuild_request(
      request,
      rebuild_options(
        "http://upstream.internal/base/app?q=1".parse().unwrap(),
        &compression,
        "absolute.example",
        true,
      ),
    );

    assert_eq!(rebuilt.headers()[HOST], "header.example");
    assert_eq!(rebuilt.headers()["x-forwarded-host"], "absolute.example");
  }
}
