//! One-shot TCP upstream exchange, PROXY protocol, retry cloning, and error classification.

use super::*;

pub(super) async fn send_one_shot_with_proxy_protocol(
  request: Request<ProxyBody>,
  upstream: &UpstreamConfig,
  state: &AppSnapshot,
  upstream_version: HttpVersion,
  client_addr: std::net::SocketAddr,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<Response<Incoming>> {
  let upstream_version = TcpUpstreamHttpVersion::from_http_version(upstream_version)?;
  let remote_addr = resolve_upstream_tcp_addr(&upstream.origin).await?;
  let mut stream = tokio::time::timeout(timeouts.upstream_connect, TcpStream::connect(remote_addr))
    .await
    .context("upstream connect timed out")??;
  crate::tcp_socket::enable_tcp_nodelay(&stream, remote_addr, "one-shot upstream");
  crate::proxy_protocol_egress::write_header(
    &mut stream,
    upstream.proxy_protocol_egress,
    client_addr,
    remote_addr,
  )
  .await
  .context("failed to write upstream PROXY protocol egress header")?;
  if upstream.origin.scheme() == "https" {
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
    let tls = tokio::time::timeout(
      timeouts.upstream_connect,
      tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(server_name, stream),
    )
    .await
    .context("upstream TLS handshake timed out")?
    .context("upstream TLS handshake failed")?;
    tokio::time::timeout(
      timeouts.upstream_first_byte,
      send_one_shot_over_tcp_io(tls, request, upstream_version, &state.config.proxy.http2),
    )
    .await
    .map_err(|_| UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte))?
  } else {
    tokio::time::timeout(
      timeouts.upstream_first_byte,
      send_one_shot_over_tcp_io(stream, request, upstream_version, &state.config.proxy.http2),
    )
    .await
    .map_err(|_| UpstreamFirstByteTimeout::new(timeouts.upstream_first_byte))?
  }
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

pub(super) async fn resolve_upstream_tcp_addr(
  origin: &url::Url,
) -> anyhow::Result<std::net::SocketAddr> {
  let port = origin
    .port_or_known_default()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no port: {origin}"))?;
  let host = origin
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("upstream origin has no host: {origin}"))?;
  tokio::net::lookup_host((host, port))
    .await
    .with_context(|| format!("failed to resolve upstream host {host}:{port}"))?
    .next()
    .ok_or_else(|| anyhow::anyhow!("upstream host resolved no addresses: {host}:{port}"))
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
