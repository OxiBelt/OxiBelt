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
  upstream_certificate: Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
}

impl ConnectedQuinnUpstream {
  pub(in crate::proxy::http3) fn into_parts(
    mut self,
  ) -> anyhow::Result<(
    h3_quinn::quinn::Endpoint,
    h3_quinn::quinn::Connection,
    Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
  )> {
    let endpoint = self
      .endpoint
      .take()
      .context("connected QUIC upstream lost its endpoint")?;
    let connection = self
      .connection
      .take()
      .context("connected QUIC upstream lost its connection")?;
    Ok((endpoint, connection, self.upstream_certificate.take()))
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
  pub(in crate::proxy::http3) upstream_certificate:
    Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
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
  .map_err(|_| {
    crate::upstream_failure::annotate(
      anyhow::anyhow!("upstream QUIC connect timed out"),
      crate::upstream_failure::UpstreamFailure::ConnectionTimeout,
    )
  })?
  .with_context(|| format!("failed to connect upstream QUIC to {server_name}"))?;
  Ok(ConnectedQuinnUpstream {
    endpoint: Some(endpoint),
    upstream_certificate: upstream_quic_peer_certificate_metadata(&connection),
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
  let (endpoint, quinn_connection, upstream_certificate) = connected.into_parts()?;
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
      return Err(crate::upstream_failure::annotate(
        anyhow::anyhow!("upstream HTTP/3 handshake timed out"),
        crate::upstream_failure::UpstreamFailure::ConnectionTimeout,
      ));
    }
  };
  let (mut driver, send_request) = match established {
    Ok(established) => established,
    Err(error) => {
      connection.close(0u32.into(), b"upstream HTTP/3 handshake failed");
      return Err(
        anyhow::Error::new(error).context("failed to establish upstream HTTP/3 connection"),
      );
    }
  };
  let driver_task = tokio::spawn(async move {
    let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
  });
  Ok(ConnectedH3Upstream {
    _endpoint: endpoint,
    connection,
    send_request,
    upstream_certificate,
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
  upstream_certificate: Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
) -> anyhow::Result<Response<ProxyBody>> {
  let (mut parts, body) = request.into_parts();
  let request_method = parts.method.clone();
  let incremental = parts
    .extensions
    .remove::<crate::proxy::http::incremental_exchange::IncrementalExchange>();
  let incremental_requested = incremental.is_some()
    || parts
      .extensions
      .get::<crate::proxy::http::incremental::IncrementalIntent>()
      .is_some()
    || crate::proxy::http::incremental::requested(&parts.headers);
  let h3_request = Request::from_parts(parts, ());
  // This is the replay boundary. Address failover is complete before this
  // future is polled; failures from here onward are returned to the caller.
  if incremental_requested {
    let exchange = incremental
      .unwrap_or_else(crate::proxy::http::incremental_exchange::IncrementalExchange::new);
    // The common pipeline guard covers this raw body until this point. From
    // here, the transport-local dispatch guard owns pre-spawn failures.
    exchange.claim_unstarted_upload();
    let dispatch_guard = exchange.begin_dispatch();
    let stream = tokio::time::timeout_at(request_deadline, send_request.send_request(h3_request))
      .await
      .context("upstream HTTP/3 request stream wait timed out")?
      .with_context(|| format!("failed to send upstream HTTP/3 request {uri}"))?;
    return send_incremental_h3_request(
      stream,
      body,
      timeouts,
      request_deadline,
      request_method,
      exchange,
      dispatch_guard,
      upstream_certificate,
    )
    .await;
  }

  let stream = tokio::time::timeout_at(request_deadline, send_request.send_request(h3_request))
    .await
    .context("upstream HTTP/3 request stream wait timed out")?
    .with_context(|| format!("failed to send upstream HTTP/3 request {uri}"))?;

  let mut stream = stream;
  let mut body = body;

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
  Ok(attach_upstream_certificate(
    Response::from_parts(parts, body),
    upstream_certificate,
  ))
}

#[allow(clippy::too_many_arguments)]
async fn send_incremental_h3_request(
  stream: h3::client::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
  body: ProxyBody,
  timeouts: EffectiveTimeouts,
  response_deadline: tokio::time::Instant,
  request_method: Method,
  exchange: crate::proxy::http::incremental_exchange::IncrementalExchange,
  dispatch_guard: crate::proxy::http::incremental_exchange::IncrementalDispatchGuard,
  upstream_certificate: Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
) -> anyhow::Result<Response<ProxyBody>> {
  let (send, mut recv) = stream.split();
  let upload_exchange = exchange.clone();
  let upload_deadline = exchange.set_upload_deadline(timeouts.incremental_upload_deadline());
  let upload = tokio::spawn(async move {
    let mut send = send;
    let body = crate::proxy::http::incremental_exchange::wrap_request_body_for_transport(
      body,
      upload_exchange.clone(),
    );
    match upload_incremental_h3_body(
      &mut send,
      body,
      timeouts.upstream_send,
      upload_deadline,
      upload_exchange.clone(),
    )
    .await
    {
      Ok(()) => upload_exchange.mark_upload_complete(),
      Err(error) => {
        send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        upload_exchange.fail_upload(format!(
          "failed to send incremental HTTP/3 request body: {error}"
        ));
      }
    }
  });
  // This join handle is owned by the exchange, not a response-body Drop
  // guard. It is bounded by the request deadline and cancellation state.
  exchange.retain(upload);
  let response_guard = dispatch_guard.uploader_started();

  let mut interim = crate::proxy::http::semantics::InterimResponses::default();
  let parts = loop {
    let response = tokio::select! {
      () = exchange.cancelled() => Err(anyhow::anyhow!(
        "incremental HTTP/3 upload cancelled before upstream response headers"
      )),
      response = tokio::time::timeout_at(response_deadline, recv.recv_response()) => response
        .context("upstream HTTP/3 first byte timed out")
        .and_then(|response| response.context("failed to receive upstream HTTP/3 response")),
    };
    let response = match response {
      Ok(response) => response,
      Err(error) => {
        exchange.cancel();
        exchange.mark_response_complete();
        return Err(error);
      }
    };
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
  let semantically_empty = response_body_is_semantically_empty(&request_method, parts.status);
  let body = response_body::observe_incremental_h3_response_body(
    recv,
    timeouts.upstream_read,
    exchange.clone(),
    semantically_empty,
  );
  let mut response = Response::from_parts(parts, body);
  response.extensions_mut().insert(exchange);
  response_guard.disarm();
  Ok(attach_upstream_certificate(response, upstream_certificate))
}

fn response_body_is_semantically_empty(method: &Method, status: StatusCode) -> bool {
  *method == Method::HEAD || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED
}

async fn upload_incremental_h3_body(
  send: &mut h3::client::RequestStream<
    <h3_quinn::BidiStream<bytes::Bytes> as h3::quic::BidiStream<bytes::Bytes>>::SendStream,
    bytes::Bytes,
  >,
  mut body: ProxyBody,
  send_timeout: Duration,
  deadline: tokio::time::Instant,
  exchange: crate::proxy::http::incremental_exchange::IncrementalExchange,
) -> anyhow::Result<()> {
  loop {
    let frame = tokio::select! {
      () = exchange.cancelled() => anyhow::bail!("incremental exchange cancelled"),
      () = tokio::time::sleep_until(deadline) => anyhow::bail!("incremental upload deadline elapsed"),
      frame = body.frame() => frame,
    };
    let Some(frame) = frame else {
      break;
    };
    let frame =
      frame.map_err(|error| anyhow::anyhow!("failed to read incremental request body: {error}"))?;
    match frame.into_data() {
      Ok(data) => {
        tokio::select! {
          () = exchange.cancelled() => anyhow::bail!("incremental exchange cancelled"),
          () = tokio::time::sleep_until(deadline) => anyhow::bail!("incremental upload deadline elapsed"),
          sent = tokio::time::timeout(send_timeout, send.send_data(data)) => {
            sent.context("incremental HTTP/3 request data send timed out")?
              .context("failed to send incremental HTTP/3 request data")?;
          }
        }
      }
      Err(frame) => {
        if let Ok(trailers) = frame.into_trailers() {
          tokio::select! {
            () = exchange.cancelled() => anyhow::bail!("incremental exchange cancelled"),
            () = tokio::time::sleep_until(deadline) => anyhow::bail!("incremental upload deadline elapsed"),
            sent = tokio::time::timeout(send_timeout, send.send_trailers(trailers)) => {
              sent.context("incremental HTTP/3 request trailers send timed out")?
                .context("failed to send incremental HTTP/3 request trailers")?;
            }
          }
        }
      }
    }
  }
  tokio::select! {
    () = exchange.cancelled() => anyhow::bail!("incremental exchange cancelled"),
    () = tokio::time::sleep_until(deadline) => anyhow::bail!("incremental upload deadline elapsed"),
    finished = tokio::time::timeout(send_timeout, send.finish()) => {
      finished.context("incremental HTTP/3 request finish timed out")?
        .context("failed to finish incremental HTTP/3 request")?;
    }
  }
  Ok(())
}

fn upstream_quic_peer_certificate_metadata(
  connection: &h3_quinn::quinn::Connection,
) -> Option<Arc<crate::waf::metadata::WafCertificateMetadata>> {
  connection
    .peer_identity()
    .and_then(|identity| {
      identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()
    })
    .as_deref()
    .and_then(|certificates| crate::tls::peer_certificate_metadata(certificates.as_slice()))
}

fn attach_upstream_certificate<T>(
  mut response: Response<T>,
  upstream_certificate: Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
) -> Response<T> {
  if let Some(upstream_certificate) = upstream_certificate {
    response
      .extensions_mut()
      .insert(crate::waf::metadata::UpstreamCertificateMetadata(
        upstream_certificate,
      ));
  }
  response
}

pub(in crate::proxy::http3) async fn connect_upstream_webtransport(
  prepared: &http_proxy::PreparedWebTransport,
  state: &AppSnapshot,
) -> anyhow::Result<(
  super::webtransport_bridge::UpstreamWebTransportSession,
  WebTransportConnectionGuard,
  Option<Arc<crate::waf::metadata::WafCertificateMetadata>>,
)> {
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn response_keeps_the_connection_certificate_snapshot() {
    let certificate = Arc::new(crate::waf::metadata::WafCertificateMetadata::default());
    let response = attach_upstream_certificate(Response::new(()), Some(certificate.clone()));
    let extension = response
      .extensions()
      .get::<crate::waf::metadata::UpstreamCertificateMetadata>()
      .expect("upstream certificate extension should be present");

    assert!(Arc::ptr_eq(&extension.0, &certificate));
  }

  #[test]
  fn response_omits_certificate_extension_without_peer_identity() {
    let response = attach_upstream_certificate::<()>(Response::new(()), None);

    assert!(
      response
        .extensions()
        .get::<crate::waf::metadata::UpstreamCertificateMetadata>()
        .is_none()
    );
  }

  #[test]
  fn semantic_empty_response_status_or_head_method_is_recognized() {
    assert!(response_body_is_semantically_empty(
      &Method::HEAD,
      StatusCode::OK
    ));
    assert!(response_body_is_semantically_empty(
      &Method::POST,
      StatusCode::NO_CONTENT
    ));
    assert!(response_body_is_semantically_empty(
      &Method::GET,
      StatusCode::NOT_MODIFIED
    ));
    assert!(!response_body_is_semantically_empty(
      &Method::GET,
      StatusCode::OK
    ));
  }
}
