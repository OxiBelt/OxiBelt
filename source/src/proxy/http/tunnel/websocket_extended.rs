//! RFC 8441/RFC 9220 WebSocket handshakes and cross-version stream bridging.

use super::*;
use base64::Engine as _;
use bytes::Bytes;
use http::HeaderValue;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::task::JoinHandle;

#[path = "websocket_extended/extensions.rs"]
mod extensions;
#[cfg(test)]
#[path = "websocket_extended/tests.rs"]
mod tests;
use extensions::extension_matches_offer;

const WEBSOCKET_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const BRIDGE_CAPACITY: usize = 64 * 1024;

trait WebSocketIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> WebSocketIo for T {}

enum UpstreamSession {
  H1(hyper::upgrade::OnUpgrade),
  H2(
    TokioIo<hyper::upgrade::Upgraded>,
    crate::proxy::http::websocket_h2::H2WebSocketConnectionGuard,
  ),
  H3(
    DuplexStream,
    crate::proxy::http3::UpstreamH3WebSocketConnectionGuard,
  ),
}

struct UpstreamGuard {
  _h2: Option<crate::proxy::http::websocket_h2::H2WebSocketConnectionGuard>,
  _h3: Option<crate::proxy::http3::UpstreamH3WebSocketConnectionGuard>,
}

impl UpstreamGuard {
  fn failed(&self) -> bool {
    self._h3.as_ref().is_some_and(|guard| guard.failed())
  }
}

impl UpstreamSession {
  async fn into_stream(self) -> anyhow::Result<(Box<dyn WebSocketIo>, UpstreamGuard)> {
    match self {
      Self::H1(upgrade) => Ok((
        Box::new(TokioIo::new(upgrade.await?)),
        UpstreamGuard {
          _h2: None,
          _h3: None,
        },
      )),
      Self::H2(stream, guard) => Ok((
        Box::new(stream),
        UpstreamGuard {
          _h2: Some(guard),
          _h3: None,
        },
      )),
      Self::H3(stream, guard) => Ok((
        Box::new(stream),
        UpstreamGuard {
          _h2: None,
          _h3: Some(guard),
        },
      )),
    }
  }
}

struct H3IngressPumps {
  upload: JoinHandle<()>,
  download: JoinHandle<()>,
  failed: Arc<AtomicBool>,
}

impl H3IngressPumps {
  fn failed(&self) -> bool {
    self.failed.load(Ordering::Acquire)
  }
}

impl Drop for H3IngressPumps {
  fn drop(&mut self) {
    self.upload.abort();
    self.download.abort();
  }
}

pub(in crate::proxy::http) fn should_handle<B>(
  request: &Request<B>,
  state: &Arc<AppSnapshot>,
  route: &RouteConfig,
) -> bool {
  is_extended_websocket_request(request)
    || (request.version() == http::Version::HTTP_11
      && route
        .upstream_http_version
        .is_some_and(|version| version != HttpVersion::H1)
      && upgrade_protocol::authorize(
        request.headers(),
        state.config.proxy.upgrades.websocket,
        state.config.proxy.upgrades.generic_http_upgrade,
        route.generic_http_upgrade,
      ) == Some(UpgradeMode::WebSocket))
}

#[allow(clippy::too_many_arguments)]
pub(in crate::proxy::http) async fn handle(
  mut request: Request<ProxyBody>,
  state: &Arc<AppSnapshot>,
  resolved: &crate::routes::ResolvedRoute<'_>,
  forwarded_client_addr: SocketAddr,
  client_addr: SocketAddr,
  downstream_host: &str,
  downstream_scheme: &str,
  downstream_port: u16,
  request_waf: &crate::waf::RequestWafDecision,
  stream_waf: Option<StreamWafRequestContext>,
  connection_limit_context: Option<&ConnectionLimitContext>,
  request_connection_permit: &mut Option<ConnectionPermit>,
  drain: ConnectionDrain,
  access_log: &mut SystemAccessLogContext<'_>,
  trace_context: Option<TraceContext>,
) -> Response<ProxyBody> {
  let route_security = RouteSecurityHeaders::new(&state.config.security, resolved.route);
  if !state.config.proxy.upgrades.websocket {
    return route_security.text(StatusCode::METHOD_NOT_ALLOWED, "WebSocket is disabled");
  }
  let downstream_version = request.version();
  let extended = is_extended_websocket_request(&request);
  let downstream_accept = match validate_downstream(&request, extended) {
    Ok(accept) => accept,
    Err(message) => return route_security.text(StatusCode::BAD_REQUEST, message),
  };
  let offered_protocol = request.headers().get("sec-websocket-protocol").cloned();
  let offered_extensions = request.headers().get("sec-websocket-extensions").cloned();
  let selected = match select_request_upstream(
    state.as_ref(),
    resolved,
    client_addr,
    downstream_host,
    request.uri(),
    request.headers().get(http::header::COOKIE),
    request_waf,
  )
  .await
  {
    Ok(selected) => selected,
    Err(error) => return route_security.apply(upstream_selection_error_response(error)),
  };
  let upstream = selected.upstream;
  if !upstream.websocket {
    return route_security.text(
      StatusCode::BAD_GATEWAY,
      "selected upstream does not allow WebSocket",
    );
  }
  let selected_pool_name = selected.pool_name().map(str::to_owned);
  if let Some(pool_name) = selected_pool_name.as_deref() {
    access_log.set_upstream_pool(pool_name);
  }
  let sticky_cookie = selected.sticky_cookie();
  let pool_selection = selected.into_pool_selection();
  access_log.set_upstream(&upstream.name, upstream.origin.scheme());
  access_log.proxy_tls_enabled = upstream.proxy_protocol_tls.is_some();
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);
  let upstream_version = version::select_websocket_upstream_http_version(
    resolved.route,
    state.config.proxy.auto_upgrade.enabled,
    state.config.proxy.auto_upgrade.max_http_version,
    upstream.max_http_version,
  );
  if upstream_version > upstream.max_http_version {
    return route_security.text(
      StatusCode::BAD_GATEWAY,
      "selected upstream cannot use route HTTP version",
    );
  }
  let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
    return route_security.text(StatusCode::BAD_GATEWAY, "upstream URI is not configured");
  };
  let target_uri = match route_actions::build_resolved_upstream_uri(
    upstream_uri,
    resolved,
    downstream_scheme,
    downstream_host,
    request.uri(),
  ) {
    Ok(uri) => uri,
    Err(_) => return route_security.text(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite"),
  };
  if let Err(status) = proxy_tls::prepare(&mut request, upstream, client_addr) {
    return route_security.text(status, "PROXY TLS metadata is unavailable or inconsistent");
  }
  let prepared_tls = request
    .extensions()
    .get::<crate::proxy_protocol_egress::tls::PreparedTlsHeader>()
    .cloned();
  let verified_early_data = early_data::is_verified(&request);
  let mut outbound = Request::builder()
    .method(if upstream_version == HttpVersion::H1 {
      Method::GET
    } else {
      Method::CONNECT
    })
    .uri(target_uri.clone())
    .version(version::upstream_request_version(upstream_version))
    .body(body::materialized_known_small_body(Bytes::new(), None))
    .expect("validated WebSocket upstream request");
  *outbound.headers_mut() = request.headers().clone();
  if upstream.preserve_host {
    set_effective_host_header(outbound.headers_mut(), downstream_host);
  } else {
    outbound.headers_mut().remove(http::header::HOST);
  }
  add_forwarded_headers(
    outbound.headers_mut(),
    forwarded_client_addr,
    downstream_host,
    downstream_scheme,
    downstream_port,
    state.config.proxy.forwarded_headers.mode,
    None,
  );
  apply_header_mutations(
    outbound.headers_mut(),
    &request_waf.request_header_mutations,
  );
  if stream_waf.is_some() {
    remove_websocket_extensions(outbound.headers_mut());
  }
  if let Some(authority) = resolved
    .route
    .actions
    .rewrite
    .as_ref()
    .and_then(|rewrite| rewrite.authority.as_deref())
  {
    set_effective_host_header(outbound.headers_mut(), authority);
  }
  early_data::apply_verified_upstream_header(outbound.headers_mut(), verified_early_data);
  state
    .telemetry
    .inject_trace_context(outbound.headers_mut(), trace_context);
  if let Some(prepared) = prepared_tls.clone() {
    outbound.extensions_mut().insert(prepared);
  }
  if let Some(prepared) = request
    .extensions()
    .get::<client_certificate::PreparedCertificateForwarding>()
    .cloned()
  {
    outbound.extensions_mut().insert(prepared);
  }
  if let Err(status) = client_certificate::apply_upstream(&mut outbound, state) {
    return route_security.text(status, "client certificate forwarding failed");
  }
  proxy_tls::apply_upstream(&mut outbound);
  let mut headers = outbound.headers().clone();
  let (response_headers, upstream_session, upstream_certificate) = match upstream_version {
    HttpVersion::H1 => {
      let key = match new_key() {
        Ok(key) => key,
        Err(_) => {
          return route_security.text(
            StatusCode::SERVICE_UNAVAILABLE,
            "WebSocket key generation failed",
          );
        }
      };
      prepare_h1_headers(&mut headers, target_uri.authority(), &key);
      *outbound.headers_mut() = headers;
      let upstream_request = async {
        if upstream.proxy_protocol_tls.is_some() {
          tcp_exchange::send_one_shot_with_proxy_protocol(
            outbound,
            upstream,
            state,
            selected_pool_name.as_deref(),
            HttpVersion::H1,
            client_addr,
            timeouts,
          )
          .await
        } else {
          let client = state
            .clients
            .for_upstream_version(&upstream.name, upstream.origin.scheme(), HttpVersion::H1)
            .context("upstream WebSocket HTTP/1 client is not configured")?;
          client.request(outbound).await.map_err(anyhow::Error::from)
        }
      };
      let mut response =
        match tokio::time::timeout(timeouts.upstream_first_byte, upstream_request).await {
          Ok(Ok(response)) => response,
          Ok(Err(error)) => {
            return upstream_error(&route_security, state, upstream, access_log, error);
          }
          Err(_) => {
            return route_security.text(
              StatusCode::BAD_GATEWAY,
              "upstream WebSocket handshake timed out",
            );
          }
        };
      if response.status() != StatusCode::SWITCHING_PROTOCOLS
        || !upgrade_protocol::is_websocket_selection(response.headers())
        || !header_has_token(response.headers(), http::header::CONNECTION, "upgrade")
        || response.headers().get("sec-websocket-accept") != Some(&accept_key(&key))
      {
        return route_security.text(
          StatusCode::BAD_GATEWAY,
          "invalid upstream WebSocket HTTP/1 handshake",
        );
      }
      let certificate = take_upstream_certificate(&mut response);
      let headers = response.headers().clone();
      (
        headers,
        UpstreamSession::H1(hyper::upgrade::on(&mut response)),
        certificate,
      )
    }
    HttpVersion::H2 => {
      let result = crate::proxy::http::websocket_h2::connect_upstream_websocket_h2(
        upstream,
        target_uri,
        headers,
        state,
        client_addr,
        selected_pool_name.as_deref(),
        timeouts,
        prepared_tls,
      )
      .await;
      let connected = match result {
        Ok(connected) => connected,
        Err(error) => return upstream_error(&route_security, state, upstream, access_log, error),
      };
      (
        connected.response_headers,
        UpstreamSession::H2(connected.stream, connected.guard),
        connected.upstream_certificate,
      )
    }
    HttpVersion::H3 => {
      let result = crate::proxy::http3::connect_upstream_websocket(
        upstream, target_uri, headers, state, timeouts,
      )
      .await;
      let (headers, stream, guard, certificate) = match result {
        Ok(connected) => connected,
        Err(error) => return upstream_error(&route_security, state, upstream, access_log, error),
      };
      (headers, UpstreamSession::H3(stream, guard), certificate)
    }
  };
  if !valid_upstream_negotiation(
    &response_headers,
    offered_protocol.as_ref(),
    offered_extensions.as_ref(),
    upstream_version,
    stream_waf.is_some(),
  ) {
    state.pools.report_failure_async(&upstream.name).await;
    return route_security.text(
      StatusCode::BAD_GATEWAY,
      "invalid upstream WebSocket negotiation",
    );
  }
  let on_upgrade =
    (downstream_version != http::Version::HTTP_3).then(|| hyper::upgrade::on(&mut request));
  let (h3_stream, response_body, h3_pumps) = if downstream_version == http::Version::HTTP_3 {
    let (stream, body, pumps) = h3_downstream_bridge(request.into_body());
    (Some(stream), body, Some(pumps))
  } else {
    (
      None,
      body::materialized_known_small_body(Bytes::new(), None),
      None,
    )
  };
  let mut downstream_response = Response::new(response_body);
  *downstream_response.status_mut() = if extended {
    StatusCode::OK
  } else {
    StatusCode::SWITCHING_PROTOCOLS
  };
  *downstream_response.headers_mut() = translated_response_headers(response_headers);
  if let Some(accept) = downstream_accept {
    downstream_response
      .headers_mut()
      .insert("sec-websocket-accept", accept);
    downstream_response.headers_mut().insert(
      http::header::CONNECTION,
      HeaderValue::from_static("Upgrade"),
    );
    downstream_response
      .headers_mut()
      .insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
  }
  apply_sticky_cookie(&mut downstream_response, sticky_cookie.as_ref());
  let connection_limit_hold =
    TunnelConnectionLimitHold::capture(request_connection_permit, connection_limit_context);
  let websocket_guard = state
    .runtime_introspection
    .guard(RuntimeCounter::WebSocketTunnel);
  let state = state.clone();
  let route_name = resolved.route.name.clone();
  let upstream_name = upstream.name.clone();
  let bandwidth = resolved.bandwidth.clone();
  let started = TelemetryRuntime::start();
  let framed_bridge = stream_waf.is_some();
  let stream_waf =
    stream_waf.map(|context| context.with_upstream_certificate(upstream_certificate));
  state
    .metrics
    .record_websocket_session_start(&state.config.metrics, &route_name, &upstream_name);
  tokio::spawn(async move {
    let _connection_limit_hold = connection_limit_hold;
    let _websocket_guard = websocket_guard;
    let h3_pumps = h3_pumps;
    let _pool_selection = pool_selection;
    let result = async {
      let downstream: Box<dyn WebSocketIo> = match on_upgrade {
        Some(upgrade) => Box::new(TokioIo::new(upgrade.await?)),
        None => Box::new(h3_stream.context("missing HTTP/3 WebSocket stream")?),
      };
      let (upstream, guard) = upstream_session.into_stream().await?;
      let bridge_result = if framed_bridge {
        crate::proxy::stream_waf::bridge_websocket(
          downstream,
          upstream,
          state.clone(),
          stream_waf,
          Some(bandwidth),
          timeouts.websocket_idle,
          drain,
        )
        .await
      } else {
        copy_bidirectional_with_idle_and_bandwidth(
          downstream,
          upstream,
          timeouts.websocket_idle,
          drain,
          Some(bandwidth),
          Some(state.metrics.clone()),
          crate::metrics::BandwidthTrafficClass::WebSocket,
          TunnelProtocol::WebSocket,
        )
        .await
      };
      if guard.failed() {
        anyhow::bail!("upstream HTTP/3 WebSocket stream failed");
      }
      bridge_result?;
      Ok::<(), anyhow::Error>(())
    }
    .await;
    let result = if h3_pumps.as_ref().is_some_and(H3IngressPumps::failed) {
      Err(anyhow::anyhow!("downstream HTTP/3 WebSocket stream failed"))
    } else {
      result
    };
    if result.is_ok() {
      state.pools.report_success_async(&upstream_name).await;
    } else {
      state.pools.report_failure_async(&upstream_name).await;
    }
    record_websocket_session_end(
      &state,
      &route_name,
      &upstream_name,
      trace_context,
      started,
      if result.is_ok() { "closed" } else { "error" },
    );
  });
  downstream_response
}

fn translated_response_headers(mut headers: HeaderMap) -> HeaderMap {
  strip_hop_by_hop_headers(&mut headers);
  for name in [
    http::header::HOST,
    http::header::CONTENT_LENGTH,
    http::header::TRANSFER_ENCODING,
    http::header::SEC_WEBSOCKET_KEY,
    http::header::SEC_WEBSOCKET_ACCEPT,
    http::header::SEC_WEBSOCKET_VERSION,
  ] {
    headers.remove(name);
  }
  headers
}

fn validate_downstream<B>(
  request: &Request<B>,
  extended: bool,
) -> Result<Option<HeaderValue>, &'static str> {
  let versions = request.headers().get_all("sec-websocket-version");
  if versions.iter().count() != 1 || versions.iter().next() != Some(&HeaderValue::from_static("13"))
  {
    return Err("WebSocket version 13 is required");
  }
  if extended {
    if request.headers().contains_key("sec-websocket-key")
      || request.headers().contains_key("sec-websocket-accept")
      || request.headers().contains_key(http::header::UPGRADE)
      || request.headers().contains_key(http::header::CONNECTION)
      || request.headers().contains_key(http::header::CONTENT_LENGTH)
      || request
        .headers()
        .contains_key(http::header::TRANSFER_ENCODING)
    {
      return Err("invalid extended WebSocket CONNECT headers");
    }
    Ok(None)
  } else {
    if request.method() != Method::GET
      || !header_has_token(request.headers(), http::header::CONNECTION, "upgrade")
      || !upgrade_protocol::is_websocket_selection(request.headers())
    {
      return Err("invalid WebSocket HTTP/1 upgrade");
    }
    let keys = request.headers().get_all("sec-websocket-key");
    if keys.iter().count() != 1 {
      return Err("WebSocket key is missing or ambiguous");
    }
    let key = keys.iter().next().ok_or("WebSocket key is missing")?;
    let key = key.to_str().map_err(|_| "invalid WebSocket key")?.trim();
    let decoded = base64::engine::general_purpose::STANDARD
      .decode(key)
      .map_err(|_| "invalid WebSocket key")?;
    if decoded.len() != 16 {
      return Err("invalid WebSocket key");
    }
    Ok(Some(accept_key(key)))
  }
}

fn accept_key(key: &str) -> HeaderValue {
  let mut input = Vec::with_capacity(key.len() + WEBSOCKET_GUID.len());
  input.extend_from_slice(key.as_bytes());
  input.extend_from_slice(WEBSOCKET_GUID);
  let digest = crate::crypto::sha1(&input);
  HeaderValue::from_str(&base64::engine::general_purpose::STANDARD.encode(digest))
    .expect("base64 accept value")
}

fn new_key() -> Result<String, getrandom::Error> {
  let mut bytes = [0_u8; 16];
  getrandom::fill(&mut bytes)?;
  Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

fn prepare_h1_headers(
  headers: &mut HeaderMap,
  authority: Option<&http::uri::Authority>,
  key: &str,
) {
  strip_hop_by_hop_headers(headers);
  headers.remove("sec-websocket-accept");
  headers.insert(
    http::header::CONNECTION,
    HeaderValue::from_static("Upgrade"),
  );
  headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
  headers.insert(
    "sec-websocket-key",
    HeaderValue::from_str(key).expect("base64 key"),
  );
  headers.insert("sec-websocket-version", HeaderValue::from_static("13"));
  if let Some(authority) = authority {
    headers.insert(
      http::header::HOST,
      HeaderValue::from_str(authority.as_str()).expect("URI authority"),
    );
  }
}

fn header_has_token(headers: &HeaderMap, name: http::HeaderName, token: &str) -> bool {
  headers.get_all(name).iter().any(|value| {
    value.to_str().ok().is_some_and(|value| {
      value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
  })
}

fn valid_upstream_negotiation(
  headers: &HeaderMap,
  offered_protocol: Option<&HeaderValue>,
  offered_extensions: Option<&HeaderValue>,
  version: HttpVersion,
  framed_bridge: bool,
) -> bool {
  if headers
    .get_all("sec-websocket-protocol")
    .iter()
    .nth(1)
    .is_some()
    || headers
      .get_all("sec-websocket-extensions")
      .iter()
      .nth(1)
      .is_some()
  {
    return false;
  }
  if version != HttpVersion::H1
    && (headers.contains_key("sec-websocket-accept")
      || headers.contains_key("sec-websocket-key")
      || headers.contains_key(http::header::UPGRADE)
      || headers.contains_key(http::header::CONNECTION)
      || headers.contains_key(http::header::CONTENT_LENGTH)
      || headers.contains_key(http::header::TRANSFER_ENCODING))
  {
    return false;
  }
  if let Some(selected) = headers.get("sec-websocket-protocol") {
    let Ok(selected) = selected.to_str() else {
      return false;
    };
    if selected.is_empty()
      || selected.contains(',')
      || !offered_protocol
        .and_then(|value| value.to_str().ok())
        .is_some_and(|offer| offer.split(',').any(|token| token.trim() == selected))
    {
      return false;
    }
  }
  if let Some(selected) = headers.get("sec-websocket-extensions") {
    if framed_bridge {
      return false;
    }
    let Some(offer) = offered_extensions.and_then(|value| value.to_str().ok()) else {
      return false;
    };
    let Ok(selected) = selected.to_str() else {
      return false;
    };
    let mut selected_names = std::collections::HashSet::new();
    for selected in selected.split(',') {
      let selected = selected.trim();
      let name = selected.split(';').next().unwrap_or("").trim();
      if name.is_empty()
        || !selected_names.insert(name.to_ascii_lowercase())
        || !offer
          .split(',')
          .any(|candidate| extension_matches_offer(selected, candidate.trim()))
      {
        return false;
      }
    }
  }
  true
}

fn upstream_error(
  route_security: &RouteSecurityHeaders,
  _state: &Arc<AppSnapshot>,
  upstream: &UpstreamConfig,
  access_log: &mut SystemAccessLogContext<'_>,
  error: anyhow::Error,
) -> Response<ProxyBody> {
  access_log.record_upstream_error("connect_error", &error.to_string());
  warn!(upstream = %upstream.name, error = %error, "WebSocket upstream connection failed");
  route_security.text(
    StatusCode::BAD_GATEWAY,
    "WebSocket upstream connection failed",
  )
}

fn h3_downstream_bridge(mut request_body: ProxyBody) -> (DuplexStream, ProxyBody, H3IngressPumps) {
  let (session, pump) = tokio::io::duplex(BRIDGE_CAPACITY);
  let (mut pump_reader, mut pump_writer) = tokio::io::split(pump);
  let (sender, response_body) = body::channel_body(1);
  let failed = Arc::new(AtomicBool::new(false));
  let upload_failed = failed.clone();
  let upload = tokio::spawn(async move {
    while let Some(frame) = request_body.frame().await {
      let Ok(frame) = frame else {
        upload_failed.store(true, Ordering::Release);
        break;
      };
      if let Ok(data) = frame.into_data() {
        if pump_writer.write_all(&data).await.is_err() {
          upload_failed.store(true, Ordering::Release);
          break;
        }
      }
    }
    let _ = pump_writer.shutdown().await;
  });
  let download_failed = failed.clone();
  let download = tokio::spawn(async move {
    let mut bytes = [0_u8; 16 * 1024];
    loop {
      match pump_reader.read(&mut bytes).await {
        Ok(0) => break,
        Err(_) => {
          download_failed.store(true, Ordering::Release);
          break;
        }
        Ok(size) => {
          if sender
            .send(Ok(hyper::body::Frame::data(Bytes::copy_from_slice(
              &bytes[..size],
            ))))
            .await
            .is_err()
          {
            download_failed.store(true, Ordering::Release);
            break;
          }
        }
      }
    }
  });
  (
    session,
    response_body,
    H3IngressPumps {
      upload,
      download,
      failed,
    },
  )
}
