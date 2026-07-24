//! Public TLS, ALPN, HTTP request dispatch, redirect, and connection permits.

use super::*;

pub(super) async fn handle_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  listener_bind: SocketAddr,
  handshake_state: Arc<AppSnapshot>,
  mut shutdown: watch::Receiver<bool>,
  mut data_plane_drain: watch::Receiver<bool>,
  drain: ConnectionDrain,
) -> anyhow::Result<()> {
  let _global_permit = acquire_global_connection_permit(&handshake_state).await?;
  let _https_connection_guard =
    handshake_state.runtime_introspection_guard(RuntimeCounter::DownstreamHttpsTcpConnection);
  let (stream, peer_addr) = proxy_protocol::accept_proxy_header(
    stream,
    peer_addr,
    &handshake_state.config.listeners.proxy_protocol,
  )
  .await?;
  let connection_limit_identity = handshake_state.config.limits.connection_limit_identity;
  let _ip_permit = if connection_limit_identity == ConnectionLimitIdentityMode::ProxyProtocol {
    Some(acquire_ip_connection_permit(&handshake_state, peer_addr).await?)
  } else {
    None
  };
  let connection_limit_context = (connection_limit_identity
    == ConnectionLimitIdentityMode::FirstRequestRealIp)
    .then(ConnectionLimitContext::default);
  let tcp_max_hop = handshake_state.waf.person_proof_tcp_max_hop();
  if let Some(max_hop) = tcp_max_hop {
    tcp_hop::apply_tcp_max_hop(&stream, peer_addr.ip(), max_hop)
      .with_context(|| format!("failed to apply TCP max hop {max_hop} for {peer_addr}"))?;
  }

  let Some(stream) = crate::sni_forward::tcp::local_stream_or_forwarded(
    stream,
    peer_addr,
    handshake_state.clone(),
    drain.clone(),
  )
  .await?
  else {
    return Ok(());
  };

  let handshake_started_at = TelemetryRuntime::start();
  let start = tokio::time::timeout(
    Duration::from_millis(handshake_state.config.limits.tls_handshake_timeout_ms),
    LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream),
  )
  .await
  .context("TLS ClientHello timed out")?
  .context("TLS ClientHello failed")?;
  let client_hello_metadata = client_hello_fingerprint_metadata(start.client_hello());
  let tls_server_config = handshake_state
    .tls_server_config
    .select(&start.client_hello());
  let mut tls_stream = tokio::time::timeout(
    Duration::from_millis(handshake_state.config.limits.tls_handshake_timeout_ms),
    start.into_stream(tls_server_config),
  )
  .await
  .context("TLS handshake timed out")?
  .context("TLS handshake failed")?;
  let mut early_data_prefix = Vec::new();
  if let Some(mut early_data) = tls_stream.get_mut().1.early_data() {
    early_data
      .read_to_end(&mut early_data_prefix)
      .context("failed to read accepted TLS early data")?;
  }
  let tcp_early_data = !early_data_prefix.is_empty();

  let negotiated = tls_stream
    .get_ref()
    .1
    .alpn_protocol()
    .map(|proto| proto.to_vec())
    .unwrap_or_else(|| b"http/1.1".to_vec());
  let alpn = String::from_utf8_lossy(&negotiated).to_string();
  handshake_state.metrics.record_tls_handshake(
    &handshake_state.config.metrics,
    "tcp",
    &alpn,
    "success",
    handshake_started_at.elapsed_ms(),
  );
  let tls_metadata = Arc::new(downstream_tls_metadata(
    tls_stream.get_ref().1,
    &client_hello_metadata,
  ));
  let tcp_metadata = tcp_hop::transport_metadata(tls_stream.get_ref().0);
  let transport_metadata = WafTransportMetadataInput {
    tcp_mss: tcp_metadata.mss,
    tcp_rtt_ms: tcp_metadata.rtt_ms,
    ..WafTransportMetadataInput::default()
  };

  let request_count = Arc::new(AtomicUsize::new(0));
  let request_counter = if negotiated == b"h2" {
    RuntimeCounter::Http2Stream
  } else {
    RuntimeCounter::Http1Request
  };
  let forwarded_header_cache = http::headers::build_forwarded_header_cache(
    peer_addr,
    "https",
    &handshake_state.config.proxy.forwarded_headers,
    &handshake_state.config.proxy.real_ip,
  );
  let h1_forwarded_header_cache = forwarded_header_cache.clone();
  let h1_tls_metadata = tls_metadata.clone();
  let h1_request_count = request_count.clone();
  let request_state = handshake_state.clone();
  let request_drain = drain.clone();
  let service = service_fn(move |mut request: hyper::Request<Incoming>| {
    let state = request_state.clone();
    let tls_metadata = tls_metadata.clone();
    let forwarded_header_cache = forwarded_header_cache.clone();
    let request_index = request_count.fetch_add(1, Ordering::Relaxed);
    let connection_limit_context = connection_limit_context.clone();
    let drain = request_drain.clone();
    async move {
      request
        .extensions_mut()
        .insert(http::DownstreamListenerBind(listener_bind));
      if tcp_early_data {
        http::early_data::mark_verified(&mut request);
      }
      let _request_guard = state.runtime_introspection_guard(request_counter);
      if request_index >= state.config.limits.max_requests_per_connection {
        return Ok(text_response(
          StatusCode::TOO_MANY_REQUESTS,
          "too many requests on this connection",
        ));
      }
      let response = http::handle_with_forwarded_header_cache(
        request,
        peer_addr,
        tcp_max_hop,
        transport_metadata,
        tls_metadata,
        connection_limit_context.clone(),
        forwarded_header_cache,
        state,
        "https",
        drain,
      )
      .await;
      if is_silent_close_response(&response) {
        Err(SilentClose)
      } else {
        Ok(response)
      }
    }
  });

  if negotiated == b"h2" {
    let _http2_connection_guard =
      handshake_state.runtime_introspection_guard(RuntimeCounter::Http2Connection);
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    crate::h2_tuning::apply_server_defaults(&mut builder, &handshake_state.config.proxy.http2);
    builder.max_header_list_size(handshake_state.config.limits.max_total_header_bytes as u32);
    let io = prefixed_io::PrefixedIo::new(tls_stream, early_data_prefix);
    let connection = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(connection);
    let mut graceful_drain = drain;
    if graceful_drain.is_graceful_connection_draining() {
      connection.as_mut().graceful_shutdown();
    }
    let result = tokio::select! {
      result = &mut connection => result,
      _ = graceful_drain.wait_for_graceful_connection_drain() => {
        connection.as_mut().graceful_shutdown();
        (&mut connection).await
      }
    };
    result.map_err(|error| anyhow::anyhow!(error))?;
  } else {
    let _http1_connection_guard =
      handshake_state.runtime_introspection_guard(RuntimeCounter::Http1Connection);
    let (io, served_requests) = if tcp_early_data {
      (
        prefixed_io::PrefixedIo::new(tls_stream, early_data_prefix),
        0,
      )
    } else {
      let Some((io, served_requests)) = h1_fast_proxy::try_handle_connection(
        tls_stream,
        peer_addr,
        listener_bind,
        &handshake_state,
        tcp_max_hop,
        h1_tls_metadata,
        transport_metadata,
        h1_forwarded_header_cache.as_ref(),
        &mut shutdown,
        &mut data_plane_drain,
      )
      .await?
      .into_continue() else {
        return Ok(());
      };
      (io, served_requests)
    };
    h1_request_count.store(served_requests, Ordering::Relaxed);
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
      .timer(TokioTimer::new())
      .header_read_timeout(Duration::from_millis(
        handshake_state.config.limits.client_header_timeout_ms,
      ))
      .max_headers(handshake_state.config.limits.max_headers)
      .max_buf_size(
        handshake_state
          .config
          .limits
          .max_total_header_bytes
          .max(8192),
      )
      .keep_alive(true);
    let io =
      http_io::InstrumentedDownstreamIo::new(io, handshake_state.metrics.clone(), "h1", "tls");
    let connection = builder.serve_connection(TokioIo::new(io), service);
    let mut graceful_drain = drain;
    let result = if handshake_state.http1_upgrades_possible {
      let connection = connection.with_upgrades();
      tokio::pin!(connection);
      if graceful_drain.is_graceful_connection_draining() {
        connection.as_mut().graceful_shutdown();
      }
      tokio::select! {
        result = &mut connection => result,
        _ = graceful_drain.wait_for_graceful_connection_drain() => {
          connection.as_mut().graceful_shutdown();
          (&mut connection).await
        }
      }
    } else {
      tokio::pin!(connection);
      if graceful_drain.is_graceful_connection_draining() {
        connection.as_mut().graceful_shutdown();
      }
      tokio::select! {
        result = &mut connection => result,
        _ = graceful_drain.wait_for_graceful_connection_drain() => {
          connection.as_mut().graceful_shutdown();
          (&mut connection).await
        }
      }
    };
    result.map_err(|error| anyhow::anyhow!(error))?;
  }

  Ok(())
}

pub(super) fn redirect_to_https(request: &hyper::Request<Incoming>) -> Response<ProxyBody> {
  let host = request
    .headers()
    .get(::http::header::HOST)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  let path = request
    .uri()
    .path_and_query()
    .map(|value| value.as_str())
    .unwrap_or("/");
  let location = format!("https://{host}{path}");
  let mut response = text_response(StatusCode::PERMANENT_REDIRECT, "");
  if let Ok(value) = ::http::HeaderValue::from_str(&location) {
    response
      .headers_mut()
      .insert(::http::header::LOCATION, value);
  }
  response
}

pub(super) async fn acquire_global_connection_permit(
  snapshot: &AppSnapshot,
) -> anyhow::Result<ConnectionPermit> {
  snapshot
    .limits
    .acquire_global_connection_async(&snapshot.config.limits)
    .await
    .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))
}

pub(super) async fn acquire_ip_connection_permit(
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
) -> anyhow::Result<ConnectionPermit> {
  snapshot
    .limits
    .acquire_ip_connection_async(
      peer_addr.ip(),
      &snapshot.config.limits,
      &snapshot.config.connection_limits,
    )
    .await
    .map_err(|status| anyhow::anyhow!("connection rejected with status {status}"))
}
