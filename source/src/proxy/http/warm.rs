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
use crate::state::AppHandle;
use crate::waf::{WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork};

use super::{full_body, handle_inner};

#[derive(Debug, Clone)]
pub(crate) struct CacheWarmResult {
  pub(crate) status: u16,
  pub(crate) result: &'static str,
}

pub(crate) async fn warm_cache_request(
  state: AppHandle,
  peer_addr: std::net::SocketAddr,
  scheme: &str,
  host: &str,
  uri: &str,
  method: Method,
  mut headers: HeaderMap,
) -> anyhow::Result<CacheWarmResult> {
  if scheme != "http" && scheme != "https" {
    anyhow::bail!("scheme must be http or https");
  }
  if method != Method::GET && method != Method::HEAD {
    anyhow::bail!("method must be GET or HEAD");
  }
  let uri = uri.parse::<http::Uri>().context("invalid warm uri")?;
  if uri.path().is_empty() || !uri.path().starts_with('/') {
    anyhow::bail!("warm uri must be an origin-form path");
  }
  headers.insert(
    http::header::HOST,
    HeaderValue::from_str(host).context("invalid warm host")?,
  );
  let mut request = Request::builder()
    .method(method.clone())
    .uri(uri.clone())
    .body(full_body(bytes::Bytes::new()))
    .context("failed to build warm request")?;
  *request.headers_mut() = headers.clone();
  let (listener_tx, listener_rx) = watch::channel(false);
  let (lifecycle_tx, lifecycle_rx) = watch::channel(false);
  let _ = listener_tx.send(false);
  let _ = lifecycle_tx.send(false);
  let drain = ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO);
  let tls = Arc::new(WafTlsMetadata {
    enabled: scheme == "https",
    sni: Some(host.to_string()),
    ..WafTlsMetadata::default()
  });
  let snapshot = state.snapshot();
  let response = handle_inner(
    request,
    peer_addr,
    None,
    WafTransportMetadataInput::default(),
    tls.clone(),
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
  let _ = response.into_body().collect().await;
  let result = snapshot
    .route_table
    .resolve_normalized_host_with_context(
      &crate::routes::normalize_host(host),
      RouteMatchContext {
        path: uri.path(),
        method: Some(&method),
        headers: Some(&headers),
        query: uri.query(),
        source_ip: Some(peer_addr.ip()),
        protocol: Some(RouteRequestProtocol::Http1),
        tls: Some(tls.as_ref()),
      },
      &snapshot.upstreams,
    )
    .and_then(|resolved| {
      snapshot.cache.lookup(crate::cache::CacheLookupContext {
        policy_name: resolved.route.cache.as_deref(),
        scheme,
        host,
        method: &method,
        uri: &uri,
        request_headers: &headers,
      })
    })
    .map(|_| "stored")
    .unwrap_or_else(|| {
      if status.is_server_error() || status.is_client_error() {
        "upstream_error"
      } else {
        "not_cacheable"
      }
    });
  Ok(CacheWarmResult {
    status: status.as_u16(),
    result,
  })
}
