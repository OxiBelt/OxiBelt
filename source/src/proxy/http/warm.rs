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
  let group_request = if snapshot.cache.enabled() {
    // Cache warm bypasses the normal ingress request constructor, so retain
    // the submitted authority when creating the cache-group request scope.
    crate::cache::CacheGroupOrigin::new(scheme, host)
      .ok()
      .map(crate::cache::CacheGroupRequest::new)
  } else {
    None
  };
  let mut request = Request::builder()
    .method(method.clone())
    .uri(uri.clone())
    .body(super::body::materialized_known_small_body(body, trailers))
    .context("failed to build warm request")?;
  *request.headers_mut() = headers.clone();
  if let Some(group_request) = group_request.as_ref() {
    request.extensions_mut().insert(group_request.clone());
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
        group_request: group_request.as_ref(),
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

#[cfg(test)]
mod tests {
  use std::convert::Infallible;
  use std::sync::Mutex;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::time::Duration;

  use bytes::Bytes;
  use http::{Response, StatusCode};
  use http_body_util::Full;
  use hyper::service::service_fn;
  use hyper_util::rt::TokioIo;
  use tokio::net::TcpListener;
  use tokio::sync::{Notify, oneshot};

  use super::*;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[tokio::test]
  async fn grouped_cache_warm_reports_stored_only_for_reusable_entries() {
    let listener = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("warm upstream should bind");
    let address = listener
      .local_addr()
      .expect("warm upstream should expose its address");
    let requests = Arc::new(AtomicUsize::new(0));
    let requests_for_server = requests.clone();
    let (invalidated_started_sender, invalidated_started) = oneshot::channel();
    let invalidated_started_sender = Arc::new(Mutex::new(Some(invalidated_started_sender)));
    let release_invalidated = Arc::new(Notify::new());
    let release_invalidated_for_server = release_invalidated.clone();
    let server = tokio::spawn(async move {
      loop {
        let (stream, _) = listener
          .accept()
          .await
          .expect("warm upstream should accept");
        let requests = requests_for_server.clone();
        let invalidated_started_sender = invalidated_started_sender.clone();
        let release_invalidated = release_invalidated_for_server.clone();
        tokio::spawn(async move {
          let service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
            let requests = requests.clone();
            let invalidated_started_sender = invalidated_started_sender.clone();
            let release_invalidated = release_invalidated.clone();
            async move {
              requests.fetch_add(1, Ordering::SeqCst);
              let response = match request.uri().path() {
                "/cached" => Response::builder()
                  .header("cache-control", "public, max-age=60")
                  .header("cache-groups", "\"warm\"")
                  .body(Full::new(Bytes::from_static(b"cached")))
                  .expect("cacheable upstream response should build"),
                "/uncacheable" => Response::builder()
                  .header("cache-control", "no-store")
                  .body(Full::new(Bytes::from_static(b"uncacheable")))
                  .expect("uncacheable upstream response should build"),
                "/invalidated" => {
                  if let Some(sender) = invalidated_started_sender
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                  {
                    let _ = sender.send(());
                  }
                  release_invalidated.notified().await;
                  Response::builder()
                    .header("cache-control", "public, max-age=60")
                    .header("cache-groups", "\"inflight\"")
                    .body(Full::new(Bytes::from_static(b"invalidated")))
                    .expect("invalidated upstream response should build")
                }
                _ => Response::builder()
                  .status(StatusCode::NOT_FOUND)
                  .body(Full::new(Bytes::new()))
                  .expect("not-found upstream response should build"),
              };
              Ok::<_, Infallible>(response)
            }
          });
          let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
        });
      }
    });

    let temporary = common::TempDir::new("grouped-cache-warm");
    let (certificate, key) =
      common::create_self_signed_cert(temporary.path(), "grouped-cache-warm");
    let raw = format!(
      r#"{}

[cache]
enabled = true
store = "memory"
default_ttl_seconds = 60
cache_methods = ["GET"]

[cache.groups]
enabled = true
"#,
      common::minimal_config_toml(&certificate, &key)
        .replace("https://app.internal.example", &format!("http://{address}"))
        .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"")
    );
    let mut config: crate::config::Config = toml::from_str(&raw).expect("warm config should parse");
    config.routes[0].cache = Some("default".to_string());
    config.validate().expect("warm config should validate");
    let snapshot = Arc::new(
      AppSnapshot::new(config)
        .await
        .expect("warm snapshot should initialize"),
    );
    let peer_addr = "127.0.0.1:12345".parse().expect("peer address");
    let warm = |uri: &str| WarmRequest {
      scheme: "http".to_string(),
      host: "example.com".to_string(),
      uri: uri.to_string(),
      method: Method::GET,
      headers: HeaderMap::new(),
      body: Bytes::new(),
      trailers: None,
    };

    let first = warm_cache_request(snapshot.clone(), peer_addr, warm("/cached"))
      .await
      .expect("cacheable warm should complete");
    assert_eq!(first.status, StatusCode::OK.as_u16());
    assert_eq!(first.result, "stored");
    let second = warm_cache_request(snapshot.clone(), peer_addr, warm("/cached"))
      .await
      .expect("reusable warm should complete");
    assert_eq!(second.result, "stored");
    assert_eq!(
      requests.load(Ordering::SeqCst),
      1,
      "a groups-enabled warm entry should be reused before probing upstream"
    );

    let uncacheable = warm_cache_request(snapshot.clone(), peer_addr, warm("/uncacheable"))
      .await
      .expect("uncacheable warm should complete");
    assert_eq!(uncacheable.result, "not_cacheable");

    let invalidated_warm = tokio::spawn(warm_cache_request(
      snapshot.clone(),
      peer_addr,
      warm("/invalidated"),
    ));
    tokio::time::timeout(Duration::from_secs(1), invalidated_started)
      .await
      .expect("in-flight warm should reach the upstream")
      .expect("in-flight warm start signal should arrive");
    snapshot
      .cache
      .purge_exact_partition_async("default", "http", "example.com", "/invalidated", None)
      .await
      .expect("exact invalidation should fence the in-flight warm");
    release_invalidated.notify_one();
    let invalidated = invalidated_warm
      .await
      .expect("in-flight warm task should not panic")
      .expect("in-flight warm should complete");
    assert_eq!(
      invalidated.result, "not_cacheable",
      "a cache-group invalidated during an upstream warm must not be reported as stored"
    );

    let origin = crate::cache::CacheGroupOrigin::new("http", "example.com")
      .expect("warm cache-group origin should parse");
    snapshot
      .cache
      .purge_group_async("default", &origin, "warm", None)
      .await
      .expect("group purge should succeed");
    let uri = "/cached".parse().expect("cached URI should parse");
    let group_request = crate::cache::CacheGroupRequest::new(origin);
    assert!(
      snapshot
        .cache
        .lookup_async(crate::cache::CacheLookupContext {
          group_request: Some(&group_request),
          no_vary_search: None,
          query_identity: None,
          proxy_protocol_identity: None,
          certificate_identity: None,
          policy_name: Some("default"),
          scheme: "http",
          host: "example.com",
          method: &Method::GET,
          uri: &uri,
          request_headers: &HeaderMap::new(),
        })
        .await
        .is_none(),
      "an invalidated groups-enabled entry must not satisfy the warm cache probe"
    );
    server.abort();
  }
}
