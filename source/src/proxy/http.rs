use std::sync::Arc;
use std::time::Duration;

use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper_util::rt::TokioIo;
use tracing::{debug, warn};

use crate::config::{HttpVersion, UpstreamConfig};
use crate::pools::PoolSelection;
use crate::state::{AppHandle, AppSnapshot, UpstreamClientRef};
use crate::waf::{
  WafBodyInput, WafProtocol, WafRequestInput, WafResponseInput, WafTlsMetadata,
  WafTransportNetwork, apply_header_mutations, request_protocol,
};

pub(crate) mod body;
pub(crate) mod compression;
pub(crate) mod headers;
pub(crate) mod request;
pub(crate) mod response;
pub(crate) mod uri;
pub(crate) mod version;

use self::body::{CapturedBody, ProxyBody, boxed_error, capture_prefix};
use self::headers::{
  add_forwarded_headers, extract_host, is_upgrade_request, strip_hop_by_hop_headers,
};
use self::request::{RebuildRequestOptions, rebuild_request};
use self::response::{text_response, upstream_error_response, waf_terminal_response};
use self::uri::{rewrite_uri, validate_downstream_path};
use self::version::select_upstream_http_version;

pub async fn handle(
  request: Request<Incoming>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  state: AppHandle,
  downstream_scheme: &'static str,
) -> Response<ProxyBody> {
  let protocol = request_protocol(request.headers());
  handle_inner(
    request,
    peer_addr,
    tcp_max_hop,
    tls,
    state,
    protocol,
    WafTransportNetwork::Tcp,
    true,
    downstream_scheme,
  )
  .await
}

pub(crate) async fn handle_http3(
  request: Request<ProxyBody>,
  peer_addr: std::net::SocketAddr,
  tls: Arc<WafTlsMetadata>,
  state: AppHandle,
) -> Response<ProxyBody> {
  handle_inner(
    request,
    peer_addr,
    None,
    tls,
    state,
    WafProtocol::Http,
    WafTransportNetwork::Udp,
    false,
    "https",
  )
  .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_inner<B>(
  request: Request<B>,
  peer_addr: std::net::SocketAddr,
  tcp_max_hop: Option<u8>,
  tls: Arc<WafTlsMetadata>,
  state: AppHandle,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  reject_connect: bool,
  downstream_scheme: &'static str,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<self::body::BoxError> + Send + Sync + 'static,
{
  let state = state.snapshot();
  state.metrics.record_request();

  if request.method() == Method::CONNECT {
    if !reject_connect {
      return text_response(
        StatusCode::BAD_REQUEST,
        "unexpected HTTP/3 CONNECT request outside WebTransport handling",
      );
    }
    return text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "CONNECT tunneling is not implemented in this build",
    );
  }

  let host = extract_host(&request).unwrap_or_default();
  let path = request.uri().path().to_string();
  if let Err((status, message)) = validate_request_limits(&request, &state.config.limits) {
    return text_response(status, message);
  }
  if let Err(error) = validate_downstream_path(&path) {
    warn!(error = %error, path = %path, "rejected unsafe downstream request path");
    return text_response(StatusCode::BAD_REQUEST, "invalid request path");
  }
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let request_version = request.version();
  let request_headers = request.headers().clone();
  let mut tags = std::collections::HashMap::new();
  let client_addr = match crate::identity::resolve_client_addr(
    &request_headers,
    peer_addr,
    &state.config.proxy.real_ip,
  ) {
    Ok(addr) => addr,
    Err(error) => {
      warn!(error = %error, peer = %peer_addr, "rejected untrusted real IP metadata");
      return text_response(
        StatusCode::BAD_REQUEST,
        "untrusted forwarded client IP metadata",
      );
    }
  };

  if let Some(status) = state
    .limits
    .check_rate_limits(client_addr.ip(), &state.config.rate_limits)
  {
    return text_response(status, "rate limit exceeded");
  }

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return text_response(StatusCode::NOT_FOUND, "no matching route");
  };

  let request = request
    .map(|body| Limited::new(body, state.config.limits.max_request_body_bytes as usize).boxed());

  let (request, captured_body) = if state
    .waf
    .requires_request_body_inspection(&resolved.route.name)
  {
    match capture_prefix(request, state.config.waf.limits.max_body_inspection_bytes).await {
      Ok(result) => {
        let (request, body) = result;
        (request, Some(body))
      }
      Err(error) => {
        warn!(error = %error, "failed to read request body for WAF inspection");
        return text_response(StatusCode::BAD_REQUEST, "failed to read request body");
      }
    }
  } else {
    (request, None)
  };
  let request_body = captured_body.as_ref().map(waf_body_input);

  let request_waf = state.waf.evaluate_request(WafRequestInput {
    method: &request_method,
    uri: &request_uri,
    version: request_version,
    headers: &request_headers,
    body: request_body,
    peer_addr: client_addr,
    downstream_host: &host,
    route_name: &resolved.route.name,
    tcp_max_hop,
    tls: tls.as_ref(),
    protocol,
    transport_network,
    tags: &tags,
  });

  for (key, value) in &request_waf.tags {
    tags.insert(key.clone(), value.clone());
  }

  if let Some(terminal) = request_waf.terminal {
    return waf_terminal_response(terminal, &request_waf.response_header_mutations);
  }

  if is_upgrade_request(&request) {
    if let Some(response) = handle_upgrade_request(
      request,
      &state,
      &resolved,
      client_addr,
      &host,
      downstream_scheme,
      &request_waf,
    )
    .await
    {
      return response;
    }
    return text_response(
      StatusCode::NOT_IMPLEMENTED,
      "unsupported HTTP upgrade request",
    );
  }

  let mut pool_selection = None;
  let upstream = if let Some(upstream_name) = request_waf.upstream_override.as_deref() {
    match state
      .upstreams
      .iter()
      .find(|upstream| upstream.name == upstream_name)
    {
      Some(upstream) => upstream,
      None => {
        warn!(upstream = upstream_name, "WAF selected an unknown upstream");
        return text_response(StatusCode::BAD_GATEWAY, "WAF selected an unknown upstream");
      }
    }
  } else if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    match state.pools.select(
      pool_name,
      client_addr.ip(),
      &format!("{host}{}", request.uri()),
      request_waf.load_balancing_policy.as_deref(),
    ) {
      Ok(selection) => {
        let name = selection.upstream_name.clone();
        pool_selection = Some(selection);
        state
          .upstreams
          .iter()
          .find(|upstream| upstream.name == name)
          .expect("pool selected synthetic upstream")
      }
      Err(error) => {
        warn!(error = %error, pool = %pool_name, "failed to select upstream pool server");
        return text_response(StatusCode::BAD_GATEWAY, "no available upstream pool server");
      }
    }
  } else {
    resolved.upstream.expect("validated route upstream")
  };

  let upstream_version = select_upstream_http_version(
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );

  if upstream_version == HttpVersion::H3 && upstream.origin.scheme() != "https" {
    return text_response(
      StatusCode::BAD_GATEWAY,
      "upstream HTTP/3 requires https origin",
    );
  }

  let target_uri = match rewrite_uri(
    &upstream.origin,
    resolved.route.path_prefix.as_str(),
    resolved.route.replace_prefix_with.as_deref(),
    request.uri(),
  ) {
    Ok(uri) => uri,
    Err(error) => {
      warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream URI");
      return text_response(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite");
    }
  };

  let rebuild = RebuildRequestOptions {
    target_uri,
    compression: &state.config.compression,
    peer_addr,
    downstream_scheme,
    downstream_host: &host,
    forwarded_header_mode: state.config.proxy.forwarded_headers.mode,
    preserve_host: upstream.preserve_host,
    upstream_version,
    waf_mutations: &request_waf.request_header_mutations,
  };
  let outbound = rebuild_request(request, rebuild);

  let cache_enabled_for_route = resolved.route.cache.as_deref() == Some("default")
    && state.cache.enabled()
    && state.cache.is_cacheable_method(&request_method);
  if let Some(response) = cached_response(
    &state,
    resolved.route.cache.as_deref(),
    downstream_scheme,
    &host,
    &request_method,
    &request_uri,
  ) {
    state.metrics.record_cache_hit();
    return compression::maybe_compress_response(
      response,
      &request_method,
      &request_headers,
      resolved.route.compression.as_deref(),
      &state.config.compression,
      &state.compression,
    );
  }
  if cache_enabled_for_route {
    state.metrics.record_cache_miss();
  }

  debug!(
      route = %resolved.route.name,
      upstream = %upstream.name,
      method = %outbound.method(),
      uri = %outbound.uri(),
      "proxying downstream request"
  );

  let upstream_response = if upstream_version == HttpVersion::H3 {
    match tokio::time::timeout(
      Duration::from_millis(upstream.request_timeout_ms),
      crate::proxy::http3::forward_request(outbound, upstream, state.as_ref()),
    )
    .await
    {
      Err(_) => {
        state.pools.report_failure(&upstream.name);
        warn!(upstream = %upstream.name, "upstream HTTP/3 request timed out");
        return upstream_error_response(
          &state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          &host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          request_body,
          &tags,
          &upstream.name,
          "upstream request timed out",
          &request_waf.response_header_mutations,
        );
      }
      Ok(Ok(response)) => response,
      Ok(Err(error)) => {
        state.pools.report_failure(&upstream.name);
        warn!(
            error = %error,
            upstream = %upstream.name,
            "upstream HTTP/3 request failed"
        );
        return upstream_error_response(
          &state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          &host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          request_body,
          &tags,
          &upstream.name,
          &error.to_string(),
          &request_waf.response_header_mutations,
        );
      }
    }
  } else {
    let Some(client) = state.clients.for_upstream_version(
      &upstream.name,
      upstream.origin.scheme(),
      upstream_version,
    ) else {
      warn!(
          upstream = %upstream.name,
          "missing upstream client pool"
      );
      return text_response(StatusCode::BAD_GATEWAY, "upstream client is not configured");
    };
    match send_with_retry(
      client,
      outbound,
      upstream,
      &state,
      state.config.proxy.retry.enabled && is_idempotent(&request_method),
    )
    .await
    {
      Ok(response) => response.map(|body| body.map_err(boxed_error).boxed()),
      Err(error) => {
        state.pools.report_failure(&upstream.name);
        warn!(
            error = %error,
            error_debug = ?error,
            upstream = %upstream.name,
            "upstream request failed"
        );
        return upstream_error_response(
          &state,
          &resolved.route.name,
          &request_method,
          &request_uri,
          request_version,
          &request_headers,
          client_addr,
          &host,
          tcp_max_hop,
          tls.as_ref(),
          protocol,
          transport_network,
          request_body,
          &tags,
          &upstream.name,
          &error.to_string(),
          &request_waf.response_header_mutations,
        );
      }
    }
  };
  state.pools.report_success(&upstream.name);
  drop(pool_selection);

  let (mut parts, body) = upstream_response.into_parts();
  strip_hop_by_hop_headers(&mut parts.headers);
  if state.config.proxy.http.trailers == crate::config::TrailerMode::Drop {
    parts.headers.remove(http::header::TRAILER);
  }
  apply_security_headers(&mut parts.headers, &state.config.security.headers);
  apply_header_mutations(&mut parts.headers, &request_waf.response_header_mutations);

  if state.waf.has_response_rules(&resolved.route.name) {
    let request_input = WafRequestInput {
      method: &request_method,
      uri: &request_uri,
      version: request_version,
      headers: &request_headers,
      body: request_body,
      peer_addr: client_addr,
      downstream_host: &host,
      route_name: &resolved.route.name,
      tcp_max_hop,
      tls: tls.as_ref(),
      protocol,
      transport_network,
      tags: &tags,
    };
    let response_waf = state.waf.evaluate_response(WafResponseInput {
      request: request_input,
      status: parts.status,
      headers: &parts.headers,
      upstream_name: &upstream.name,
      upstream_error: None,
    });
    for access_log in &response_waf.access_logs {
      state.access_logs.emit(access_log);
    }
    if let Some(terminal) = response_waf.terminal {
      let mut mutations = request_waf.response_header_mutations.clone();
      mutations.extend(response_waf.response_header_mutations);
      return waf_terminal_response(terminal, &mutations);
    }
    apply_header_mutations(&mut parts.headers, &response_waf.response_header_mutations);
  }

  let response = maybe_cache_response(
    Response::from_parts(parts, body),
    &state,
    resolved.route.cache.as_deref(),
    downstream_scheme,
    &host,
    &request_method,
    &request_uri,
  )
  .await;
  let response = compression::maybe_compress_response(
    response,
    &request_method,
    &request_headers,
    resolved.route.compression.as_deref(),
    &state.config.compression,
    &state.compression,
  );
  state.metrics.record_response(response.status());
  response
}

#[allow(clippy::too_many_arguments)]
async fn handle_upgrade_request(
  mut request: Request<ProxyBody>,
  state: &Arc<AppSnapshot>,
  resolved: &crate::routes::ResolvedRoute<'_>,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  downstream_scheme: &str,
  request_waf: &crate::waf::RequestWafDecision,
) -> Option<Response<ProxyBody>> {
  if !state.config.proxy.upgrades.websocket || !is_websocket_upgrade(&request) {
    return None;
  }

  let mut pool_selection = None;
  let upstream = if let Some(upstream_name) = request_waf.upstream_override.as_deref() {
    match state
      .upstreams
      .iter()
      .find(|upstream| upstream.name == upstream_name)
    {
      Some(upstream) => upstream,
      None => {
        return Some(text_response(
          StatusCode::BAD_GATEWAY,
          "WAF selected an unknown upstream",
        ));
      }
    }
  } else if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    match state.pools.select(
      pool_name,
      client_addr.ip(),
      &format!("{downstream_host}{}", request.uri()),
      request_waf.load_balancing_policy.as_deref(),
    ) {
      Ok(selection) => {
        let name = selection.upstream_name.clone();
        pool_selection = Some(selection);
        state
          .upstreams
          .iter()
          .find(|upstream| upstream.name == name)
          .expect("pool selected synthetic upstream")
      }
      Err(_) => {
        return Some(text_response(
          StatusCode::BAD_GATEWAY,
          "no available upstream pool server",
        ));
      }
    }
  } else {
    resolved.upstream.expect("validated route upstream")
  };

  if !upstream.websocket {
    return Some(text_response(
      StatusCode::BAD_GATEWAY,
      "selected upstream does not allow WebSocket",
    ));
  }
  let target_uri = match rewrite_uri(
    &upstream.origin,
    resolved.route.path_prefix.as_str(),
    resolved.route.replace_prefix_with.as_deref(),
    request.uri(),
  ) {
    Ok(uri) => uri,
    Err(_) => {
      return Some(text_response(
        StatusCode::BAD_REQUEST,
        "invalid upstream URI rewrite",
      ));
    }
  };
  let downstream_upgrade = hyper::upgrade::on(&mut request);
  let (mut parts, body) = request.into_parts();
  parts.uri = target_uri;
  parts.version = http::Version::HTTP_11;
  if !upstream.preserve_host {
    parts.headers.remove(http::header::HOST);
  }
  add_forwarded_headers(
    &mut parts.headers,
    client_addr,
    downstream_host,
    downstream_scheme,
    state.config.proxy.forwarded_headers.mode,
  );
  apply_header_mutations(&mut parts.headers, &request_waf.request_header_mutations);
  let outbound = Request::from_parts(parts, body);
  let Some(client) =
    state
      .clients
      .for_upstream_version(&upstream.name, upstream.origin.scheme(), HttpVersion::H1)
  else {
    return Some(text_response(
      StatusCode::BAD_GATEWAY,
      "upstream client is not configured",
    ));
  };
  let mut upstream_response = match tokio::time::timeout(
    Duration::from_millis(upstream.request_timeout_ms),
    client.request(outbound),
  )
  .await
  {
    Ok(Ok(response)) => response,
    Ok(Err(error)) => {
      state.pools.report_failure(&upstream.name);
      return Some(text_response(
        StatusCode::BAD_GATEWAY,
        &format!("upstream WebSocket request failed: {error}"),
      ));
    }
    Err(_) => {
      state.pools.report_failure(&upstream.name);
      return Some(text_response(
        StatusCode::BAD_GATEWAY,
        "upstream WebSocket request timed out",
      ));
    }
  };

  if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
    let response = upstream_response.map(|body| body.map_err(boxed_error).boxed());
    return Some(response);
  }
  let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
  let pool_report = state.pools.clone();
  let upstream_name = upstream.name.clone();
  tokio::spawn(async move {
    let result = async {
      let downstream = downstream_upgrade.await?;
      let upstream = upstream_upgrade.await?;
      let mut downstream = TokioIo::new(downstream);
      let mut upstream = TokioIo::new(upstream);
      tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;
      Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    if result.is_ok() {
      pool_report.report_success(&upstream_name);
    } else {
      pool_report.report_failure(&upstream_name);
    }
  });
  drop(pool_selection);
  Some(upstream_response.map(|body| body.map_err(boxed_error).boxed()))
}

fn is_websocket_upgrade<B>(request: &Request<B>) -> bool {
  request
    .headers()
    .get(http::header::UPGRADE)
    .and_then(|value| value.to_str().ok())
    .map(|value| value.eq_ignore_ascii_case("websocket"))
    .unwrap_or(false)
}

async fn send_with_retry(
  client: UpstreamClientRef<'_>,
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  retry_enabled: bool,
) -> anyhow::Result<Response<Incoming>> {
  if retry_enabled
    && request
      .body()
      .size_hint()
      .upper()
      .is_some_and(|upper| upper <= state.config.proxy.buffering.max_memory_body_bytes as u64)
  {
    let (parts, body) = request.into_parts();
    let body = body
      .collect()
      .await
      .map_err(|error| anyhow::anyhow!("failed to buffer retryable request body: {error}"))?
      .to_bytes();
    let tries = state.config.proxy.retry.tries.max(1);
    let mut last_error = None;
    for _ in 0..tries {
      let outbound = Request::from_parts(parts_clone(&parts), full_body(body.clone()));
      match tokio::time::timeout(
        Duration::from_millis(upstream.request_timeout_ms),
        client.request(outbound),
      )
      .await
      {
        Ok(Ok(response)) if retryable_status(response.status(), state) => {
          last_error = Some(anyhow::anyhow!(
            "upstream returned retryable status {}",
            response.status()
          ));
        }
        Ok(Ok(response)) => return Ok(response),
        Ok(Err(error)) => last_error = Some(error.into()),
        Err(_) => {
          last_error = Some(anyhow::anyhow!(
            "upstream request timed out after {}ms",
            upstream.request_timeout_ms
          ));
        }
      }
    }
    return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream retry failed")));
  }
  match tokio::time::timeout(
    Duration::from_millis(upstream.request_timeout_ms),
    client.request(request),
  )
  .await
  {
    Ok(result) => Ok(result?),
    Err(_) => anyhow::bail!(
      "upstream request timed out after {}ms",
      upstream.request_timeout_ms
    ),
  }
}

fn parts_clone(parts: &http::request::Parts) -> http::request::Parts {
  let mut builder = Request::builder()
    .method(parts.method.clone())
    .uri(parts.uri.clone())
    .version(parts.version);
  *builder.headers_mut().expect("request builder headers") = parts.headers.clone();
  builder
    .body(())
    .expect("request parts clone builds")
    .into_parts()
    .0
}

fn retryable_status(status: StatusCode, state: &AppSnapshot) -> bool {
  state.config.proxy.retry.on.iter().any(|condition| {
    matches!(
      (condition, status.as_u16()),
      (crate::config::RetryCondition::Status502, 502)
        | (crate::config::RetryCondition::Status503, 503)
        | (crate::config::RetryCondition::Status504, 504)
    )
  })
}

fn is_idempotent(method: &Method) -> bool {
  matches!(
    *method,
    Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
  )
}

fn validate_request_limits<B>(
  request: &Request<B>,
  limits: &crate::config::LimitsConfig,
) -> Result<(), (StatusCode, &'static str)> {
  if request.uri().to_string().len() > limits.max_uri_bytes {
    return Err((StatusCode::URI_TOO_LONG, "request URI is too large"));
  }
  if request.headers().len() > limits.max_headers {
    return Err((
      StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
      "too many headers",
    ));
  }
  let mut total = 0usize;
  for (name, value) in request.headers() {
    if name.as_str().len() > limits.max_header_name_bytes {
      return Err((
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "header name is too large",
      ));
    }
    if value.as_bytes().len() > limits.max_header_value_bytes {
      return Err((
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "header value is too large",
      ));
    }
    total += name.as_str().len() + value.as_bytes().len();
  }
  if total > limits.max_total_header_bytes {
    return Err((
      StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
      "headers are too large",
    ));
  }
  if let Some(length) = request
    .headers()
    .get(http::header::CONTENT_LENGTH)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.parse::<u64>().ok())
    && length > limits.max_request_body_bytes
  {
    return Err((StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"));
  }
  Ok(())
}

fn apply_security_headers(
  headers: &mut http::HeaderMap,
  config: &crate::config::SecurityHeadersConfig,
) {
  if config.hsts {
    let mut value = format!("max-age={}", config.hsts_max_age_seconds);
    if config.hsts_include_subdomains {
      value.push_str("; includeSubDomains");
    }
    if config.hsts_preload {
      value.push_str("; preload");
    }
    insert_header(headers, "strict-transport-security", &value);
  }
  if let Some(value) = &config.x_content_type_options {
    insert_header(headers, "x-content-type-options", value);
  }
  if let Some(value) = &config.referrer_policy {
    insert_header(headers, "referrer-policy", value);
  }
  if let Some(value) = &config.permissions_policy {
    insert_header(headers, "permissions-policy", value);
  }
}

fn insert_header(headers: &mut http::HeaderMap, name: &'static str, value: &str) {
  if let Ok(value) = http::HeaderValue::from_str(value) {
    headers.insert(http::HeaderName::from_static(name), value);
  }
}

fn cached_response(
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
) -> Option<Response<ProxyBody>> {
  if route_cache != Some("default")
    || !state.cache.enabled()
    || !state.cache.is_cacheable_method(method)
  {
    return None;
  }
  let key = state.cache.key(scheme, host, uri);
  state.cache.get(&key).map(|entry| {
    let mut response = Response::new(full_body(entry.body));
    *response.status_mut() = entry.status;
    *response.headers_mut() = entry.headers;
    response
  })
}

async fn maybe_cache_response(
  response: Response<ProxyBody>,
  state: &AppSnapshot,
  route_cache: Option<&str>,
  scheme: &str,
  host: &str,
  method: &Method,
  uri: &http::Uri,
) -> Response<ProxyBody> {
  if route_cache != Some("default")
    || !state.cache.enabled()
    || !state.cache.is_cacheable_method(method)
  {
    return response;
  }
  let (parts, body) = response.into_parts();
  if body
    .size_hint()
    .upper()
    .is_none_or(|upper| upper as usize > state.config.proxy.buffering.max_memory_body_bytes)
  {
    return Response::from_parts(parts, body);
  }
  match body.collect().await {
    Ok(collected) => {
      let bytes = collected.to_bytes();
      let key = state.cache.key(scheme, host, uri);
      state.cache.insert(
        key,
        crate::cache::CacheEntry {
          status: parts.status,
          headers: parts.headers.clone(),
          body: bytes.clone(),
        },
      );
      Response::from_parts(parts, full_body(bytes))
    }
    Err(error) => text_response(
      StatusCode::BAD_GATEWAY,
      &format!("failed to read upstream response body: {error}"),
    ),
  }
}

fn full_body(bytes: bytes::Bytes) -> ProxyBody {
  Full::new(bytes)
    .map_err(|never| -> self::body::BoxError { match never {} })
    .boxed()
}

pub(crate) struct PreparedWebTransport {
  pub(crate) target_url: url::Url,
  pub(crate) headers: http::HeaderMap,
  pub(crate) protocols: Vec<String>,
  pub(crate) upstream: UpstreamConfig,
  _pool_selection: Option<PoolSelection>,
}

pub(crate) fn prepare_webtransport(
  request: &Request<()>,
  peer_addr: std::net::SocketAddr,
  tls: &WafTlsMetadata,
  state: &AppSnapshot,
) -> Result<PreparedWebTransport, Box<Response<ProxyBody>>> {
  let host = extract_host(request).unwrap_or_default();
  let path = request.uri().path().to_string();
  if let Err(error) = validate_downstream_path(&path) {
    warn!(error = %error, path = %path, "rejected unsafe downstream WebTransport path");
    return Err(Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "invalid request path",
    )));
  }
  let request_method = request.method().clone();
  let request_uri = request.uri().clone();
  let request_headers = request.headers().clone();
  let mut tags = std::collections::HashMap::new();

  let Some(resolved) = state.route_table.resolve(&host, &path, &state.upstreams) else {
    return Err(Box::new(text_response(
      StatusCode::NOT_FOUND,
      "no matching route",
    )));
  };

  let request_waf = state.waf.evaluate_request(WafRequestInput {
    method: &request_method,
    uri: &request_uri,
    version: http::Version::HTTP_3,
    headers: &request_headers,
    body: None,
    peer_addr,
    downstream_host: &host,
    route_name: &resolved.route.name,
    tcp_max_hop: None,
    tls,
    protocol: WafProtocol::Webtransport,
    transport_network: WafTransportNetwork::Udp,
    tags: &tags,
  });

  for (key, value) in request_waf.tags {
    tags.insert(key, value);
  }

  if let Some(terminal) = request_waf.terminal {
    return Err(Box::new(waf_terminal_response(
      terminal,
      &request_waf.response_header_mutations,
    )));
  }

  let mut pool_selection = None;
  let upstream = if let Some(upstream_name) = request_waf.upstream_override.as_deref() {
    match state
      .upstreams
      .iter()
      .find(|upstream| upstream.name == upstream_name)
    {
      Some(upstream) => upstream,
      None => {
        warn!(upstream = upstream_name, "WAF selected an unknown upstream");
        return Err(Box::new(text_response(
          StatusCode::BAD_GATEWAY,
          "WAF selected an unknown upstream",
        )));
      }
    }
  } else if let Some(pool_name) = request_waf
    .upstream_pool_override
    .as_deref()
    .or(resolved.route.upstream_pool.as_deref())
  {
    match state.pools.select(
      pool_name,
      peer_addr.ip(),
      &format!("{host}{}", request.uri()),
      request_waf.load_balancing_policy.as_deref(),
    ) {
      Ok(selection) => {
        let name = selection.upstream_name.clone();
        pool_selection = Some(selection);
        state
          .upstreams
          .iter()
          .find(|upstream| upstream.name == name)
          .expect("pool selected synthetic upstream")
      }
      Err(error) => {
        warn!(error = %error, pool = %pool_name, "failed to select upstream pool server");
        return Err(Box::new(text_response(
          StatusCode::BAD_GATEWAY,
          "no available upstream pool server",
        )));
      }
    }
  } else {
    resolved.upstream.expect("validated route upstream")
  };

  if !upstream.webtransport {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "selected upstream does not allow WebTransport",
    )));
  }

  let upstream_version = select_upstream_http_version(
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );
  if upstream_version != HttpVersion::H3 {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "WebTransport forwarding requires HTTP/3 upstream",
    )));
  }
  if upstream.origin.scheme() != "https" {
    return Err(Box::new(text_response(
      StatusCode::BAD_GATEWAY,
      "WebTransport forwarding requires https upstream origin",
    )));
  }

  let target_uri = rewrite_uri(
    &upstream.origin,
    resolved.route.path_prefix.as_str(),
    resolved.route.replace_prefix_with.as_deref(),
    request.uri(),
  )
  .map_err(|error| {
    warn!(error = %error, route = %resolved.route.name, "failed to rewrite upstream WebTransport URI");
    Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "invalid upstream URI rewrite",
    ))
  })?;
  let target_url = url::Url::parse(&target_uri.to_string()).map_err(|error| {
    warn!(error = %error, uri = %target_uri, "failed to convert WebTransport target URI");
    Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "invalid WebTransport target URI",
    ))
  })?;

  let mut headers = request.headers().clone();
  strip_hop_by_hop_headers(&mut headers);
  if !upstream.preserve_host {
    headers.remove(http::header::HOST);
  }
  add_forwarded_headers(
    &mut headers,
    peer_addr,
    &host,
    "https",
    state.config.proxy.forwarded_headers.mode,
  );
  apply_header_mutations(&mut headers, &request_waf.request_header_mutations);

  let protocols = parse_webtransport_protocols(&headers);
  Ok(PreparedWebTransport {
    target_url,
    headers,
    protocols,
    upstream: upstream.clone(),
    _pool_selection: pool_selection,
  })
}

fn parse_webtransport_protocols(headers: &http::HeaderMap) -> Vec<String> {
  headers
    .get("wt-available-protocols")
    .and_then(|value| value.to_str().ok())
    .map(|value| {
      value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_matches('"').to_string())
        .collect()
    })
    .unwrap_or_default()
}

fn waf_body_input(body: &CapturedBody) -> WafBodyInput<'_> {
  WafBodyInput {
    bytes: body.bytes.as_ref(),
    is_truncated: body.is_truncated,
  }
}

#[cfg(test)]
mod tests {
  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  use http::header::HOST;
  use pretty_assertions::assert_eq;

  use super::*;
  use crate::config::Config;

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  fn webtransport_request() -> Request<()> {
    Request::builder()
      .method(Method::CONNECT)
      .version(http::Version::HTTP_3)
      .uri("https://example.com/session?token=1")
      .header(HOST, "example.com")
      .header("wt-available-protocols", "\"chat\", data")
      .body(())
      .expect("request should build")
  }

  #[tokio::test]
  async fn prepare_webtransport_selects_direct_upstream() {
    let temp_dir = common::TempDir::new("direct-webtransport");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "direct-webtransport");
    let raw = format!(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = true

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[proxy.auto_upgrade]
enabled = true
max_http_version = "h3"

[[upstreams]]
name = "app"
origin = "https://app.example/origin"
max_http_version = "h3"
webtransport = true

[[routes]]
name = "direct-route"
hosts = ["example.com"]
path_prefix = "/"
upstream = "app"
"#,
      cert = cert_path.display(),
      key = key_path.display(),
    );
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");

    let prepared = prepare_webtransport(
      &webtransport_request(),
      "203.0.113.10:45678".parse().unwrap(),
      &WafTlsMetadata::default(),
      &state,
    )
    .expect("direct WebTransport route should prepare");

    assert_eq!(prepared.upstream.name, "app");
    assert_eq!(
      prepared.target_url.as_str(),
      "https://app.example/origin/session?token=1"
    );
    assert_eq!(prepared.protocols, vec!["chat", "data"]);
  }

  #[tokio::test]
  async fn prepare_webtransport_pool_route_returns_bad_gateway_without_panicking() {
    let temp_dir = common::TempDir::new("pool-webtransport");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "pool-webtransport");
    let raw = format!(
      r#"
[listeners]
https_bind = "127.0.0.1:8443"
http1 = true
http2 = true
http3 = true

[tls]
cert_chain = "{cert}"
private_key = "{key}"

[tls.ocsp]
mode = "disabled"

[[upstream_pools]]
name = "app-pool"
algorithm = "round_robin"

[[upstream_pools.servers]]
origin = "https://app-a.example/origin"

[[routes]]
name = "pool-route"
hosts = ["example.com"]
path_prefix = "/"
upstream_pool = "app-pool"
"#,
      cert = cert_path.display(),
      key = key_path.display(),
    );
    let state = AppSnapshot::new(parse_config(&raw))
      .await
      .expect("snapshot should initialize");

    let response = match prepare_webtransport(
      &webtransport_request(),
      "203.0.113.10:45678".parse().unwrap(),
      &WafTlsMetadata::default(),
      &state,
    ) {
      Ok(_) => panic!("pool route should be rejected with a response, not panic"),
      Err(response) => response,
    };

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
  }
}
