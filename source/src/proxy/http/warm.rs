//! Cache-warm request execution.
//! Warmups reuse proxy planning while staying outside client-facing response paths.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use http::{HeaderMap, HeaderValue, Method, Request};
use http_body_util::BodyExt;
use tokio::sync::watch;

use crate::lifecycle::ConnectionDrain;
use crate::routes::{RouteMatchContext, RouteRequestProtocol};
use crate::state::AppSnapshot;
use crate::waf::{WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork};

use super::handle_inner;

pub(crate) struct WarmRequest {
  pub(crate) scheme: String,
  pub(crate) host: String,
  pub(crate) uri: String,
  pub(crate) method: Method,
  pub(crate) headers: HeaderMap,
  pub(crate) body: bytes::Bytes,
  pub(crate) trailers: Option<HeaderMap>,
}

#[derive(Debug, Clone)]
pub(crate) struct CacheWarmResult {
  pub(crate) status: u16,
  pub(crate) result: &'static str,
}

pub(crate) fn cache_warm_tls_metadata(scheme: &str, host: &str) -> WafTlsMetadata {
  WafTlsMetadata {
    enabled: scheme == "https",
    // HTTPS target ports belong to HTTP authority, never to TLS SNI. Preserve
    // descriptive plaintext metadata; identity selection checks `enabled`.
    sni: Some(if scheme == "https" {
      crate::routes::normalize_host(host)
    } else {
      host.to_string()
    }),
    ..WafTlsMetadata::default()
  }
}

pub(crate) async fn warm_cache_request(
  snapshot: Arc<AppSnapshot>,
  peer_addr: std::net::SocketAddr,
  input: WarmRequest,
) -> anyhow::Result<CacheWarmResult> {
  let WarmRequest {
    scheme,
    host,
    uri,
    method,
    mut headers,
    body,
    trailers,
  } = input;
  let (scheme, host, uri) = (scheme.as_str(), host.as_str(), uri.as_str());
  if scheme != "http" && scheme != "https" {
    anyhow::bail!("scheme must be http or https");
  }
  if method != Method::GET && method != Method::HEAD && !super::query::is_query(&method) {
    anyhow::bail!("method must be GET, HEAD or QUERY");
  }
  super::query::validate_content_type(&method, &headers).map_err(anyhow::Error::msg)?;
  if !super::query::is_query(&method) && (!body.is_empty() || trailers.is_some()) {
    anyhow::bail!("GET and HEAD cache warming must not carry content");
  }
  if super::query::is_query(&method) {
    headers.remove(http::header::TRANSFER_ENCODING);
    headers.insert(
      http::header::CONTENT_LENGTH,
      HeaderValue::from_str(&body.len().to_string())?,
    );
  }
  let uri = uri.parse::<http::Uri>().context("invalid warm uri")?;
  if uri.path().is_empty() || !uri.path().starts_with('/') {
    anyhow::bail!("warm uri must be an origin-form path");
  }
  headers.insert(
    http::header::HOST,
    HeaderValue::from_str(host).context("invalid warm host")?,
  );
  super::client_certificate::strip_reserved(&mut headers, &snapshot);
  let mut request = Request::builder()
    .method(method.clone())
    .uri(uri.clone())
    .body(super::body::materialized_known_small_body(body, trailers))
    .context("failed to build warm request")?;
  *request.headers_mut() = headers.clone();
  if snapshot.cache.enabled()
    && let Ok(origin) = crate::cache::CacheGroupOrigin::new(scheme, host)
  {
    // Cache warm bypasses the normal ingress request constructor, so retain
    // the submitted authority when creating the cache-group request scope.
    request
      .extensions_mut()
      .insert(crate::cache::CacheGroupRequest::new(origin));
  }
  let (listener_tx, listener_rx) = watch::channel(false);
  let (lifecycle_tx, lifecycle_rx) = watch::channel(false);
  let _ = listener_tx.send(false);
  let _ = lifecycle_tx.send(false);
  let drain = ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO);
  let tls = Arc::new(cache_warm_tls_metadata(scheme, host));
  super::headers::validate_authority_host_consistency(&request)
    .map_err(|_| anyhow::anyhow!("ambiguous warm host metadata"))?;
  let client_addr = snapshot.resolve_client_addr(
    request.headers(),
    peer_addr,
    &crate::routes::normalize_host(host),
    tls.sni.as_deref().filter(|_| tls.enabled),
  )?;
  let response = handle_inner(
    request,
    peer_addr,
    None,
    WafTransportMetadataInput::default(),
    tls.clone(),
    None,
    None,
    snapshot.clone(),
    WafProtocol::Http,
    WafTransportNetwork::Tcp,
    false,
    if scheme == "https" { "https" } else { "http" },
    drain,
  )
  .await;
  let status = response.status();
  let query_identity = response
    .extensions()
    .get::<crate::cache::CacheQueryIdentity>()
    .cloned();
  let query_hit = super::query::is_query(&method)
    && response
      .extensions()
      .get::<super::cache_status::StandardCacheStatus>()
      .is_some_and(|status| status.hit);
  let selected_tls_egress = response
    .extensions()
    .get::<super::proxy_tls::SelectedEgress>()
    .is_some();
  let completed = response.into_body().collect().await.is_ok();
  if !completed && super::query::is_query(&method) {
    return Ok(CacheWarmResult {
      status: status.as_u16(),
      result: "upstream_error",
    });
  }
  if selected_tls_egress {
    return Ok(CacheWarmResult {
      status: status.as_u16(),
      result: "upstream_error",
    });
  }
  let resolved = snapshot.route_table.resolve_normalized_host_with_context(
    &crate::routes::normalize_host(host),
    RouteMatchContext {
      path: uri.path(),
      method: Some(&method),
      headers: Some(&headers),
      query: uri.query(),
      source_ip: Some(client_addr.ip()),
      protocol: Some(RouteRequestProtocol::Http1),
      tls: Some(tls.as_ref()),
    },
    &snapshot.upstreams,
  );
  let stored = if query_hit {
    true
  } else if let Some(resolved) = resolved {
    // Synthetic warm requests have no connection evidence. Never probe an
    // unpartitioned cache after the request path rejected a TLS-TLV upstream.
    if resolved
      .upstream
      .is_some_and(|upstream| upstream.proxy_protocol_tls.is_some())
    {
      return Ok(CacheWarmResult {
        status: status.as_u16(),
        result: "upstream_error",
      });
    }
    let prepared = super::client_certificate::PreparedCertificateForwarding::prepare(
      &Request::new(()),
      resolved.route,
    )
    .map_err(|_| anyhow::anyhow!("invalid certificate forwarding configuration"))?;
    snapshot
      .cache
      .lookup_async(crate::cache::CacheLookupContext {
        group_request: None,
        no_vary_search: None,
        query_identity: query_identity.as_ref(),
        proxy_protocol_identity: None,
        certificate_identity: prepared.as_ref().map(|value| &value.cache_identity),
        policy_name: resolved.route.cache.as_deref(),
        scheme,
        host,
        method: &method,
        uri: &uri,
        request_headers: &headers,
      })
      .await
      .is_some()
  } else {
    false
  };
  let result = if stored {
    "stored"
  } else if status.is_server_error() || status.is_client_error() {
    "upstream_error"
  } else {
    "not_cacheable"
  };
  Ok(CacheWarmResult {
    status: status.as_u16(),
    result,
  })
}
