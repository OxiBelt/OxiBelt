//! Upstream HTTP/3 connection establishment and request exchange.

use super::*;

pub(in crate::proxy::http3) struct ConnectedH3Upstream {
  pub(in crate::proxy::http3) endpoint: h3_quinn::quinn::Endpoint,
  pub(in crate::proxy::http3) connection: h3_quinn::quinn::Connection,
  pub(in crate::proxy::http3) send_request: H3SendRequest,
  pub(in crate::proxy::http3) driver_task: JoinHandle<()>,
}

pub(super) async fn connect_h3_upstream(
  server_name: String,
  remote_addr: SocketAddr,
  quic_config: h3_quinn::quinn::ClientConfig,
  oxibelt_quic_config: &crate::config::QuicConfig,
  quic_host_key_base_dir: Option<&Path>,
  connect_timeout: Duration,
) -> anyhow::Result<ConnectedH3Upstream> {
  let endpoint =
    crate::quic::bind_client_endpoint(remote_addr, oxibelt_quic_config, quic_host_key_base_dir)?;
  let quinn_connection = tokio::time::timeout(
    connect_timeout,
    endpoint
      .connect_with(quic_config, remote_addr, &server_name)
      .with_context(|| format!("failed to start upstream HTTP/3 connection to {server_name}"))?,
  )
  .await
  .context("upstream HTTP/3 connect timed out")?
  .with_context(|| format!("failed to connect upstream HTTP/3 to {server_name}"))?;
  let connection = quinn_connection.clone();
  let h3_connection = h3_quinn::Connection::new(quinn_connection);
  let (mut driver, send_request) = h3::client::builder()
    .enable_datagram(true)
    .enable_extended_connect(true)
    .build(h3_connection)
    .await
    .context("failed to establish upstream HTTP/3 connection")?;
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });
  Ok(ConnectedH3Upstream {
    endpoint,
    connection,
    send_request,
    driver_task,
  })
}

pub(crate) async fn forward_request(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<ProxyBody>> {
  if let Some(pool) = state.h3_clients.for_upstream(&upstream.name) {
    return pool
      .forward_request(request, upstream, timeouts, &state.metrics, &state.overload)
      .await;
  }

  forward_one_shot_request(request, upstream, state, timeouts).await
}

pub(crate) async fn forward_one_shot_request(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<ProxyBody>> {
  let _pending = state
    .overload
    .lease(crate::overload::WorkKind::PendingUpstreamRequests, 1);
  let uri = request.uri().clone();
  state
    .metrics
    .record_http_upstream_client_request("h3", "https", "primary");
  state
    .metrics
    .record_http_upstream_client_pool_miss("h3", "https", "primary");
  let inherited_roots = state
    .config
    .proxy
    .trusted_ca_certs
    .iter()
    .chain(&upstream.extra_trusted_ca_certs)
    .cloned()
    .collect::<Vec<_>>();
  let quic_config = tls::build_upstream_quic_client_config_with_policy(
    &state.config.crypto,
    &inherited_roots,
    &upstream.tls,
    &state.config.quic,
    Some(&state.tls_resumption),
    &upstream.name,
    Some((
      &state.outbound_revocation,
      state.outbound_revocation.policy_for_upstream(upstream),
    )),
  )
  .with_context(|| format!("failed to build upstream QUIC client for {}", upstream.name))?;
  let (origin_server_name, remote_addr) = resolve_upstream_addr(&upstream.origin).await?;
  let server_name = upstream
    .tls
    .server_name
    .clone()
    .unwrap_or(origin_server_name);
  let connection_admission = state
    .circuit_breakers
    .admit_upstream_connection(None, Instant::now().checked_add(timeouts.upstream_connect))
    .await
    .map_err(anyhow::Error::new)?;
  let connected = connect_h3_upstream(
    server_name,
    remote_addr,
    quic_config,
    &state.config.quic,
    state.config.source_paths.cert_dir.as_deref(),
    timeouts.upstream_connect,
  )
  .await?;
  state
    .metrics
    .record_http_upstream_client_connection_created("h3", "https", "primary");
  let guard = OneShotH3Connection {
    _endpoint: connected.endpoint,
    _connection_admission: connection_admission,
    connection: connected.connection,
    driver_task: connected.driver_task,
  };

  let response = send_h3_request(connected.send_request, request, &uri, timeouts).await?;
  let (parts, body) = response.into_parts();
  let close_body =
    crate::proxy::http::body::with_drop_guard(body, Arc::new(std::sync::Mutex::new(Some(guard))));
  Ok(Response::from_parts(parts, close_body))
}

struct OneShotH3Connection {
  _endpoint: h3_quinn::quinn::Endpoint,
  _connection_admission: crate::circuit_breakers::AdmissionLease,
  connection: h3_quinn::quinn::Connection,
  driver_task: JoinHandle<()>,
}

impl Drop for OneShotH3Connection {
  fn drop(&mut self) {
    self
      .connection
      .close(0u32.into(), b"one-shot request complete");
    self.driver_task.abort();
  }
}

pub(super) async fn send_h3_request(
  mut send_request: H3SendRequest,
  request: Request<ProxyBody>,
  uri: &http::Uri,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<ProxyBody>> {
  let (parts, mut body) = request.into_parts();
  let h3_request = Request::from_parts(parts, ());
  let mut stream = send_request
    .send_request(h3_request)
    .await
    .with_context(|| format!("failed to send upstream HTTP/3 request {uri}"))?;

  while let Some(frame) = body.frame().await {
    let frame = frame.map_err(|error| {
      anyhow::anyhow!("failed to read request body for upstream HTTP/3: {error}")
    })?;
    match frame.into_data() {
      Ok(data) => {
        tokio::time::timeout(timeouts.upstream_send, stream.send_data(data))
          .await
          .context("upstream HTTP/3 request data send timed out")?
          .context("failed to send upstream HTTP/3 request data")?;
      }
      Err(frame) => {
        if let Ok(trailers) = frame.into_trailers() {
          tokio::time::timeout(timeouts.upstream_send, stream.send_trailers(trailers))
            .await
            .context("upstream HTTP/3 request trailers send timed out")?
            .context("failed to send upstream HTTP/3 request trailers")?;
        }
      }
    }
  }
  tokio::time::timeout(timeouts.upstream_send, stream.finish())
    .await
    .context("upstream HTTP/3 request finish timed out")?
    .context("failed to finish upstream HTTP/3 request")?;

  let mut interim = crate::proxy::http::semantics::InterimResponses::default();
  let parts = loop {
    let response = tokio::time::timeout(timeouts.upstream_first_byte, stream.recv_response())
      .await
      .context("upstream HTTP/3 first byte timed out")?
      .context("failed to receive upstream HTTP/3 response")?;
    if let Some(response) = crate::proxy::http::semantics::sanitize_interim_response(
      response.status(),
      response.headers(),
    ) {
      interim.responses.push(response);
      continue;
    }
    let (mut parts, _) = response.into_parts();
    if !interim.responses.is_empty() {
      parts.extensions.insert(interim);
    }
    break parts;
  };
  let body = response_body::upstream_h3_response_body(stream, timeouts.upstream_read);
  Ok(Response::from_parts(parts, body))
}

pub(in crate::proxy::http3) async fn connect_upstream_webtransport(
  prepared: &http_proxy::PreparedWebTransport,
  state: &AppSnapshot,
) -> anyhow::Result<web_transport_quinn::Session> {
  let inherited_roots = state
    .config
    .proxy
    .trusted_ca_certs
    .iter()
    .chain(&prepared.upstream.extra_trusted_ca_certs)
    .cloned()
    .collect::<Vec<_>>();
  let quic_config = tls::build_upstream_quic_client_config_with_policy(
    &state.config.crypto,
    &inherited_roots,
    &prepared.upstream.tls,
    &state.config.quic,
    Some(&state.tls_resumption),
    &prepared.upstream.name,
    Some((
      &state.outbound_revocation,
      state
        .outbound_revocation
        .policy_for_upstream(&prepared.upstream),
    )),
  )
  .with_context(|| {
    format!(
      "failed to build upstream WebTransport QUIC client for {}",
      prepared.upstream.name
    )
  })?;
  let mut request = web_transport_quinn::proto::ConnectRequest::new(prepared.target_url.clone())
    .with_headers(prepared.headers.clone());
  if !prepared.protocols.is_empty() {
    request = request.with_protocols(prepared.protocols.clone());
  }
  let (origin_server_name, remote_addr) = resolve_upstream_addr(&prepared.target_url).await?;
  let server_name = prepared
    .upstream
    .tls
    .server_name
    .clone()
    .unwrap_or(origin_server_name);
  let endpoint = crate::quic::bind_client_endpoint(
    remote_addr,
    &state.config.quic,
    state.config.source_paths.cert_dir.as_deref(),
  )
  .context("failed to create upstream WebTransport endpoint")?;
  let connection = tokio::time::timeout(
    prepared.timeouts.upstream_connect,
    endpoint
      .connect_with(quic_config, remote_addr, &server_name)
      .with_context(|| {
        format!("failed to start upstream WebTransport connection to {server_name}")
      })?,
  )
  .await
  .context("upstream WebTransport connect timed out")?
  .with_context(|| format!("failed to connect upstream WebTransport to {server_name}"))?;
  tokio::time::timeout(
    prepared.timeouts.upstream_first_byte,
    web_transport_quinn::Session::connect(connection, request),
  )
  .await
  .context("upstream WebTransport CONNECT timed out")?
  .context("upstream WebTransport CONNECT failed")
}

pub(super) async fn resolve_upstream_addr(
  origin: &url::Url,
) -> anyhow::Result<(String, SocketAddr)> {
  let port = origin
    .port_or_known_default()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no port: {origin}"))?;
  let host = origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no host: {origin}"))?
    .to_string();
  let remote = tokio::net::lookup_host((host.as_str(), port))
    .await
    .with_context(|| format!("failed to resolve upstream HTTP/3 host {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow::anyhow!("upstream HTTP/3 host resolved no addresses: {host}:{port}"))?;
  Ok((host, remote))
}
