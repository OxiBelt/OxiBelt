use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tracing::warn;
use url::Url;

use crate::config::{CryptoConfig, ProxyHttp2Config, UpstreamConfig};
use crate::proxy::http::body::ProxyBody;
use crate::tls::{OutboundRevocationRuntime, TlsResumptionState};

pub(super) struct DirectH2Origin {
  pub(super) scheme: &'static str,
  pub(super) host: String,
  pub(super) port: u16,
}

impl DirectH2Origin {
  pub(super) fn from_url(origin: &Url) -> Option<Self> {
    let scheme = match origin.scheme() {
      "http" => "http",
      "https" => "https",
      _ => return None,
    };
    Some(Self {
      scheme,
      host: origin.host_str()?.to_owned(),
      port: origin.port_or_known_default()?,
    })
  }
}

pub(super) async fn h2_handshake_with_timeout<I>(
  io: I,
  http2_config: &ProxyHttp2Config,
  timeout: Duration,
) -> anyhow::Result<SendRequest<ProxyBody>>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  tokio::time::timeout(timeout, h2_handshake(io, http2_config))
    .await
    .context("direct H2 upstream HTTP/2 handshake timed out")?
}

pub(super) async fn h2_handshake<I>(
  io: I,
  http2_config: &ProxyHttp2Config,
) -> anyhow::Result<SendRequest<ProxyBody>>
where
  I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
  crate::h2_tuning::apply_client_conn_defaults(&mut builder, http2_config);
  let (sender, connection) = builder
    .handshake(TokioIo::new(io))
    .await
    .context("failed to establish direct HTTP/2 upstream connection")?;
  tokio::spawn(async move {
    if let Err(error) = connection.await {
      warn!(error = %error, "direct HTTP/2 upstream connection closed with error");
    }
  });
  Ok(sender)
}

pub(super) fn build_h2_tls_config(
  upstream: &UpstreamConfig,
  extra_root_certs: &[PathBuf],
  crypto: &CryptoConfig,
  tls_resumption: &TlsResumptionState,
  outbound_revocation: &OutboundRevocationRuntime,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
  let root_certs;
  let extra_root_certs = if upstream.extra_trusted_ca_certs.is_empty() {
    extra_root_certs
  } else {
    root_certs = extra_root_certs
      .iter()
      .chain(upstream.extra_trusted_ca_certs.iter())
      .cloned()
      .collect::<Vec<PathBuf>>();
    &root_certs
  };
  let revocation_policy = outbound_revocation.policy_for_upstream(upstream);
  let mut tls_config =
    crate::tls::build_upstream_client_config_with_crypto_resumption_and_revocation(
      crypto,
      extra_root_certs,
      &upstream.tls.ech,
      &upstream.tls.resumption,
      Some(tls_resumption),
      &upstream.name,
      Some((outbound_revocation, revocation_policy)),
    )?;
  tls_config.alpn_protocols = vec![b"h2".to_vec()];
  Ok(Arc::new(tls_config))
}

pub(super) async fn connect_tls_h2(
  tls_config: Arc<rustls::ClientConfig>,
  host: String,
  stream: tokio::net::TcpStream,
  http2_config: &ProxyHttp2Config,
  timeout: Duration,
) -> anyhow::Result<SendRequest<ProxyBody>> {
  let server_name = rustls::pki_types::ServerName::try_from(host)
    .map_err(|error| anyhow::anyhow!("invalid upstream TLS server name: {error}"))?;
  let tls = tokio::time::timeout(
    timeout,
    TlsConnector::from(tls_config).connect(server_name, stream),
  )
  .await
  .context("direct H2 upstream TLS handshake timed out")?
  .context("direct H2 upstream TLS handshake failed")?;
  h2_handshake_with_timeout(tls, http2_config, timeout).await
}
