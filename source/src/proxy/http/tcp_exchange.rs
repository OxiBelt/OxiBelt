//! One-shot TCP upstream exchange, PROXY protocol, retry cloning, and error classification.

use super::*;

trait OneShotUpstreamIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> OneShotUpstreamIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub(super) async fn send_one_shot_with_proxy_protocol(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  pool_name: Option<&str>,
  upstream_version: HttpVersion,
  client_addr: std::net::SocketAddr,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<Incoming>> {
  let upstream_version = TcpUpstreamHttpVersion::from_http_version(upstream_version)?;
  let port = upstream
    .origin
    .port_or_known_default()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no port: {}", upstream.origin))?;
  let host = upstream
    .origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no host: {}", upstream.origin))?;
  let now = std::time::Instant::now();
  let connect_deadline = now
    .checked_add(timeouts.upstream_connect)
    .context("upstream connection deadline overflowed")?;
  let connect_deadline = timeouts
    .upstream_deadline
    .map_or(connect_deadline, |configured| {
      configured.min(connect_deadline)
    });
  let connect_deadline = tokio::time::Instant::from_std(connect_deadline);
  let resolution_config = &state.config.proxy.upstream_resolution;
  let (resolution_policy, scheduler_policy) =
    crate::upstream_resolution::http_upstream_policies(resolution_config, upstream)?;
  let tls_enabled = upstream.origin.scheme() == "https";
  let tls_identity = if tls_enabled {
    let revocation_policy = state.outbound_revocation.policy_for_upstream(upstream);
    let revocation = Some((&state.outbound_revocation, revocation_policy));
    let inherited_roots = state
      .config
      .proxy
      .trusted_ca_certs
      .iter()
      .chain(&upstream.extra_trusted_ca_certs)
      .cloned()
      .collect::<Vec<_>>();
    let mut tls_config = crate::tls::build_upstream_client_config_with_policy(
      &state.config.crypto,
      &inherited_roots,
      &upstream.tls,
      Some(&state.tls_resumption),
      &upstream.name,
      revocation,
    )
    .context("failed to build one-shot upstream TLS config")?;
    tls_config.alpn_protocols = vec![upstream_version.as_alpn().to_vec()];
    let Some(origin_host) = upstream.origin.host_str() else {
      anyhow::bail!("upstream origin has no host");
    };
    let server_name = upstream.tls.server_name.as_deref().unwrap_or(origin_host);
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
      .map_err(|error| anyhow::anyhow!("invalid upstream TLS server name: {error}"))?;
    Some((Arc::new(tls_config), server_name))
  } else {
    None
  };
  let proxy_protocol = upstream.proxy_protocol_egress;
  let discovery_id = format!("http-proxy:{}:{host}:{port}", upstream.name);
  let svcb_enabled = resolution_config.happy_eyeballs.svcb
    == crate::config::UpstreamResolutionDnsMode::Auto
    && scheduler_policy.mode() == crate::upstream_resolution::CandidateSchedulerMode::Enabled;
  let admission = crate::upstream_resolution::ConnectionAdmissionContext::new(
    state.circuit_breakers.clone(),
    pool_name.map(Arc::<str>::from),
  );
  let io = crate::upstream_resolution::connect_http_ready_happy_eyeballs_admitted(
    host,
    port,
    &discovery_id,
    resolution_policy,
    scheduler_policy,
    match upstream_version {
      TcpUpstreamHttpVersion::H1 => crate::upstream_resolution::HttpTransportProtocol::H1,
      TcpUpstreamHttpVersion::H2 => crate::upstream_resolution::HttpTransportProtocol::H2,
    },
    tls_enabled,
    svcb_enabled,
    &upstream.svcb_allowed_ports,
    connect_deadline,
    admission,
    move |remote_addr, attempt_deadline| {
      let tls_identity = tls_identity.clone();
      async move {
        let mut stream = tokio::time::timeout_at(
          attempt_deadline,
          tokio::net::TcpStream::connect(remote_addr),
        )
        .await
        .context("upstream TCP connection timed out")?
        .with_context(|| format!("failed to connect upstream TCP candidate {remote_addr}"))?;
        crate::tcp_socket::enable_tcp_nodelay(&stream, remote_addr, "one-shot upstream");
        tokio::time::timeout_at(
          attempt_deadline,
          crate::proxy_protocol_egress::write_header(
            &mut stream,
            proxy_protocol,
            client_addr,
            remote_addr,
          ),
        )
        .await
        .context("upstream PROXY protocol egress header timed out")?
        .context("failed to write upstream PROXY protocol egress header")?;
        let io: Box<dyn OneShotUpstreamIo> = if let Some((tls_config, server_name)) = tls_identity {
          let tls = tokio::time::timeout_at(
            attempt_deadline,
            tokio_rustls::TlsConnector::from(tls_config).connect(server_name, stream),
          )
          .await
          .context("upstream TLS handshake timed out")?
          .context("upstream TLS handshake failed")?;
          if !upstream_version.accepts_negotiated_alpn(tls.get_ref().1.alpn_protocol()) {
            anyhow::bail!("upstream negotiated an incompatible ALPN protocol");
          }
          Box::new(tls)
        } else {
          Box::new(stream)
        };
        Ok(io)
      }
    },
  )
  .await?;
  tokio::time::timeout(
    timeouts.upstream_first_byte,
    send_one_shot_over_tcp_io(io, request, upstream_version, &state.config.proxy.http2),
  )
  .await
  .map_err(|_| UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte))?
}
#[derive(Clone, Copy)]
pub(super) enum TcpUpstreamHttpVersion {
  H1,
  H2,
}

impl TcpUpstreamHttpVersion {
  pub(super) fn from_http_version(version: HttpVersion) -> anyhow::Result<Self> {
    match version {
      HttpVersion::H1 => Ok(Self::H1),
      HttpVersion::H2 => Ok(Self::H2),
      HttpVersion::H3 => {
        anyhow::bail!("PROXY protocol egress is not supported for HTTP/3 upstream")
      }
    }
  }

  pub(super) fn as_alpn(self) -> &'static [u8] {
    match self {
      Self::H1 => b"http/1.1",
      Self::H2 => b"h2",
    }
  }

  fn accepts_negotiated_alpn(self, negotiated: Option<&[u8]>) -> bool {
    match self {
      Self::H1 => negotiated.is_none_or(|alpn| alpn == b"http/1.1"),
      Self::H2 => negotiated == Some(b"h2"),
    }
  }
}

#[cfg(test)]
mod alpn_tests {
  use super::TcpUpstreamHttpVersion;

  #[test]
  fn proxy_ready_transport_accepts_only_protocol_compatible_alpn() {
    assert!(TcpUpstreamHttpVersion::H1.accepts_negotiated_alpn(None));
    assert!(TcpUpstreamHttpVersion::H1.accepts_negotiated_alpn(Some(b"http/1.1")));
    assert!(!TcpUpstreamHttpVersion::H1.accepts_negotiated_alpn(Some(b"h2")));
    assert!(!TcpUpstreamHttpVersion::H1.accepts_negotiated_alpn(Some(b"unknown")));
    assert!(!TcpUpstreamHttpVersion::H2.accepts_negotiated_alpn(None));
    assert!(TcpUpstreamHttpVersion::H2.accepts_negotiated_alpn(Some(b"h2")));
    assert!(!TcpUpstreamHttpVersion::H2.accepts_negotiated_alpn(Some(b"http/1.1")));
  }
}

#[derive(Debug)]
pub(super) struct UpstreamFirstByteTimeout {
  timeout: Duration,
}

impl UpstreamFirstByteTimeout {
  pub(super) fn new(timeout: Duration) -> Self {
    Self { timeout }
  }
}

impl std::fmt::Display for UpstreamFirstByteTimeout {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "upstream request timed out after {}ms",
      self.timeout.as_millis()
    )
  }
}

impl std::error::Error for UpstreamFirstByteTimeout {}

pub(super) fn error_is_upstream_first_byte_timeout(error: &anyhow::Error) -> bool {
  error.downcast_ref::<UpstreamFirstByteTimeout>().is_some()
}

pub(super) fn should_report_upstream_request_failure(
  upstream_first_byte_timeout: bool,
  grpc_timeout_caps: semantics::GrpcTimeoutCaps,
) -> bool {
  !(upstream_first_byte_timeout && grpc_timeout_caps.upstream_first_byte)
}

pub(super) async fn send_one_shot_over_tcp_io<I>(
  io: I,
  request: Request<ProxyBody>,
  upstream_version: TcpUpstreamHttpVersion,
  http2_config: &ProxyHttp2Config,
) -> anyhow::Result<Response<Incoming>>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  match upstream_version {
    TcpUpstreamHttpVersion::H1 => {
      let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .context("failed to establish one-shot HTTP/1.1 upstream connection")?;
      tokio::spawn(async move {
        if let Err(error) = connection.await {
          warn!(error = %error, "one-shot HTTP/1.1 upstream connection failed");
        }
      });
      sender
        .send_request(request)
        .await
        .context("one-shot HTTP/1.1 upstream request failed")
    }
    TcpUpstreamHttpVersion::H2 => {
      let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
      crate::h2_tuning::apply_client_conn_defaults(&mut builder, http2_config);
      let (mut sender, connection) = builder
        .handshake(TokioIo::new(io))
        .await
        .context("failed to establish one-shot HTTP/2 upstream connection")?;
      tokio::spawn(async move {
        if let Err(error) = connection.await {
          warn!(error = %error, "one-shot HTTP/2 upstream connection failed");
        }
      });
      sender
        .send_request(request)
        .await
        .context("one-shot HTTP/2 upstream request failed")
    }
  }
}

pub(super) async fn connect_upstream_tcp(
  upstream: &UpstreamConfig,
  resolution_config: &crate::config::UpstreamResolutionConfig,
  timeouts: EffectiveTimeouts,
  admission: crate::upstream_resolution::ConnectionAdmissionContext,
) -> anyhow::Result<(
  crate::upstream_resolution::ConnectionAdmitted<TcpStream>,
  std::net::SocketAddr,
  tokio::time::Instant,
)> {
  let port = upstream
    .origin
    .port_or_known_default()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no port: {}", upstream.origin))?;
  let host = upstream
    .origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no host: {}", upstream.origin))?;
  let now = std::time::Instant::now();
  let deadline = now
    .checked_add(timeouts.upstream_connect)
    .context("upstream connection deadline overflowed")?;
  let deadline = timeouts
    .upstream_deadline
    .map_or(deadline, |configured| configured.min(deadline));
  let (resolution_policy, scheduler_policy) =
    crate::upstream_resolution::http_upstream_policies(resolution_config, upstream)?;
  let discovery_id = format!("http:{}:{host}:{port}", upstream.name);
  let deadline = tokio::time::Instant::from_std(deadline);
  let connection = crate::upstream_resolution::connect_tcp_happy_eyeballs_admitted(
    host,
    port,
    &discovery_id,
    resolution_policy,
    scheduler_policy,
    deadline,
    Some(admission),
  )
  .await;
  let (stream, address) =
    connection.with_context(|| format!("failed to connect upstream host {host}:{port}"))?;
  Ok((stream, address, deadline))
}

#[allow(
  clippy::expect_used,
  reason = "method, URI, version, and headers come from an existing valid request"
)]
pub(super) fn parts_clone(parts: &http::request::Parts) -> http::request::Parts {
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

pub(crate) fn is_idempotent(method: &Method) -> bool {
  matches!(
    *method,
    Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
  )
}
