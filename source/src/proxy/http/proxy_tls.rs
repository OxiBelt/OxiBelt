//! Request-bound PROXY TLS emission and response privacy policy.

use http::header::{ACCEPT_ENCODING, CACHE_CONTROL};
use http::{Request, Response, StatusCode};

use crate::config::UpstreamConfig;
use crate::proxy_protocol_egress::tls::{ConnectionTlsEvidence, PreparedTlsHeader};

#[derive(Clone)]
pub(super) struct SelectedEgress;

pub(super) fn prepare<B>(
  request: &mut Request<B>,
  upstream: &UpstreamConfig,
  client_addr: std::net::SocketAddr,
) -> Result<(), StatusCode> {
  let Some(config) = upstream.proxy_protocol_tls.as_ref() else {
    return Ok(());
  };
  let evidence = request
    .extensions()
    .get::<ConnectionTlsEvidence>()
    .cloned()
    .unwrap_or_default();
  let prepared = PreparedTlsHeader::prepare(config, &evidence, client_addr)
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
  request.extensions_mut().insert(prepared);
  Ok(())
}

pub(super) fn cache_identity<B>(
  request: &Request<B>,
) -> Option<&crate::cache::CacheProxyProtocolIdentity> {
  request
    .extensions()
    .get::<PreparedTlsHeader>()
    .map(|prepared| &prepared.cache_identity)
}

pub(super) fn has_certificate_identity<B>(request: &Request<B>) -> bool {
  request
    .extensions()
    .get::<PreparedTlsHeader>()
    .is_some_and(|prepared| prepared.certificate_identity)
}

pub(super) fn apply_upstream<B>(request: &mut Request<B>) {
  if has_certificate_identity(request) {
    request.headers_mut().remove(ACCEPT_ENCODING);
  }
}

pub(super) fn finalize_response<B>(response: &mut Response<B>, enabled: bool) {
  if enabled {
    response.extensions_mut().insert(SelectedEgress);
    response
      .headers_mut()
      .insert(CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
  }
}
