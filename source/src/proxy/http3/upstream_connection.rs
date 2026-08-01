//! Upstream HTTP/3 connection establishment and request exchange.

use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) struct H3RequestDeadlines {
  pub(super) request: tokio::time::Instant,
  pub(super) connect: tokio::time::Instant,
}

impl H3RequestDeadlines {
  pub(super) fn from_timeouts(timeouts: EffectiveTimeouts) -> anyhow::Result<Self> {
    let now = tokio::time::Instant::now();
    let request = now
      .checked_add(timeouts.upstream_first_byte)
      .context("upstream HTTP/3 request deadline overflow")?;
    let connect = now
      .checked_add(timeouts.upstream_connect)
      .context("upstream HTTP/3 connect deadline overflow")?
      .min(request);
    Ok(Self { request, connect })
  }
}

pub(in crate::proxy::http3) struct ConnectedQuinnUpstream {
  endpoint: Option<h3_quinn::quinn::Endpoint>,
  connection: Option<h3_quinn::quinn::Connection>,
}

impl ConnectedQuinnUpstream {
  pub(in crate::proxy::http3) fn into_parts(
    mut self,
  ) -> anyhow::Result<(h3_quinn::quinn::Endpoint, h3_quinn::quinn::Connection)> {
    let endpoint = self
      .endpoint
      .take()
      .context("connected QUIC upstream lost its endpoint")?;
    let connection = self
      .connection
      .take()
      .context("connected QUIC upstream lost its connection")?;
    Ok((endpoint, connection))
  }
}

impl Drop for ConnectedQuinnUpstream {
  fn drop(&mut self) {
    if let Some(connection) = self.connection.take() {
      connection.close(0u32.into(), b"discarded upstream QUIC candidate");
    }
  }
}

pub(in crate::proxy::http3) struct ConnectedH3Upstream {
  _endpoint: h3_quinn::quinn::Endpoint,
  pub(in crate::proxy::http3) connection: h3_quinn::quinn::Connection,
  pub(in crate::proxy::http3) send_request: H3SendRequest,
  driver_task: JoinHandle<()>,
}

impl Drop for ConnectedH3Upstream {
  fn drop(&mut self) {
    self
      .connection
      .close(0u32.into(), b"upstream HTTP/3 connection released");
    self.driver_task.abort();
  }
}

pub(in crate::proxy::http3) struct WebTransportConnectionGuard {
  _endpoint: h3_quinn::quinn::Endpoint,
  _connection_admission: crate::circuit_breakers::AdmissionLease,
}

impl WebTransportConnectionGuard {
  pub(in crate::proxy::http3) fn new(
    endpoint: h3_quinn::quinn::Endpoint,
    connection_admission: crate::circuit_breakers::AdmissionLease,
  ) -> Self {
    Self {
      _endpoint: endpoint,
      _connection_admission: connection_admission,
    }
  }
}

pub(super) async fn connect_quinn_upstream(
  server_name: &str,
  remote_addr: SocketAddr,
  quic_config: h3_quinn::quinn::ClientConfig,
  oxibelt_quic_config: &crate::config::QuicConfig,
  quic_host_key_base_dir: Option<&Path>,
  deadline: tokio::time::Instant,
) -> anyhow::Result<ConnectedQuinnUpstream> {
  let endpoint =
    crate::quic::bind_client_endpoint(remote_addr, oxibelt_quic_config, quic_host_key_base_dir)?;
  let connection = tokio::time::timeout_at(
    deadline,
    endpoint
      .connect_with(quic_config, remote_addr, server_name)
      .with_context(|| format!("failed to start upstream QUIC connection to {server_name}"))?,
  )
  .await
  .context("upstream QUIC connect timed out")?
  .with_context(|| format!("failed to connect upstream QUIC to {server_name}"))?;
  Ok(ConnectedQuinnUpstream {
    endpoint: Some(endpoint),
    connection: Some(connection),
  })
}

pub(super) async fn connect_h3_upstream(
  server_name: &str,
  remote_addr: SocketAddr,
  quic_config: h3_quinn::quinn::ClientConfig,
  oxibelt_quic_config: &crate::config::QuicConfig,
  quic_host_key_base_dir: Option<&Path>,
  deadline: tokio::time::Instant,
) -> anyhow::Result<ConnectedH3Upstream> {
  let connected = connect_quinn_upstream(
    server_name,
    remote_addr,
    quic_config,
    oxibelt_quic_config,
    quic_host_key_base_dir,
    deadline,
  )
  .await?;
  let (endpoint, quinn_connection) = connected.into_parts()?;
  let connection = quinn_connection.clone();
  let h3_connection = h3_quinn::Connection::new(quinn_connection);
  let established = match tokio::time::timeout_at(
    deadline,
    h3::client::builder()
      .enable_datagram(true)
      .enable_extended_connect(true)
      .build(h3_connection),
  )
  .await
  {
    Ok(established) => established,
    Err(_) => {
      connection.close(0u32.into(), b"upstream HTTP/3 handshake timed out");
      anyhow::bail!("upstream HTTP/3 handshake timed out");
    }
  };
  let (mut driver, send_request) = match established {
    Ok(established) => established,
    Err(error) => {
      connection.close(0u32.into(), b"upstream HTTP/3 handshake failed");
      return Err(error).context("failed to establish upstream HTTP/3 connection");
    }
  };
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });
  Ok(ConnectedH3Upstream {
    _endpoint: endpoint,
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
  let client = state
    .h3_clients
    .for_upstream(&upstream.name)
    .with_context(|| format!("missing upstream HTTP/3 client for {}", upstream.name))?;
  client
    .forward_request(
      request,
      upstream,
      timeouts,
      &state.config.proxy.trusted_ca_certs,
      &state.metrics,
      &state.overload,
    )
    .await
}

pub(super) async fn send_h3_request(
  mut send_request: H3SendRequest,
  request: Request<ProxyBody>,
  uri: &http::Uri,
  timeouts: EffectiveTimeouts,
  request_deadline: tokio::time::Instant,
) -> anyhow::Result<Response<ProxyBody>> {
  let (parts, mut body) = request.into_parts();
  let h3_request = Request::from_parts(parts, ());
  // This is the replay boundary. Address failover is complete before this
  // future is polled; failures from here onward are returned to the caller.
  let mut stream = tokio::time::timeout_at(request_deadline, send_request.send_request(h3_request))
    .await
    .context("upstream HTTP/3 request stream wait timed out")?
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
    let response = tokio::time::timeout_at(request_deadline, stream.recv_response())
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
) -> anyhow::Result<(web_transport_quinn::Session, WebTransportConnectionGuard)> {
  let client = state
    .h3_clients
    .for_upstream(&prepared.upstream.name)
    .with_context(|| {
      format!(
        "missing upstream WebTransport client for {}",
        prepared.upstream.name
      )
    })?;
  client
    .connect_webtransport(
      prepared,
      &state.config.proxy.trusted_ca_certs,
      &state.metrics,
    )
    .await
}
