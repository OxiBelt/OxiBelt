//! Internal HTTP client used for control-plane probes and administrative calls.
//! The client is separate from proxy clients to avoid mixing trust boundaries.

use std::convert::Infallible;
use std::time::Duration;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Incoming;
use hyper_rustls::{FixedServerNameResolver, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};

use crate::config::{
  CryptoConfig, OutboundTlsRevocationConfig, UpstreamEchConfig, UpstreamTlsConfig,
};
use crate::tls;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ControlBody = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct ControlHttpClient {
  client: Client<hyper_rustls::HttpsConnector<HttpConnector>, ControlBody>,
}

pub struct ControlHttpResponse {
  pub status: http::StatusCode,
  pub headers: http::HeaderMap,
  pub body: Bytes,
}

pub struct ControlHttpStreamResponse {
  pub status: http::StatusCode,
  pub headers: http::HeaderMap,
  pub body: Incoming,
}

impl ControlHttpClient {
  pub fn new(extra_root_certs: &[std::path::PathBuf]) -> anyhow::Result<Self> {
    let crypto = CryptoConfig::default();
    Self::new_with_crypto(extra_root_certs, &crypto)
  }

  /// Builds a generic control-plane client with the auxiliary TLS key-exchange policy.
  ///
  /// The derived configuration deliberately retains the historical AWS-LC/default
  /// provider and trust behavior; this switch controls only the auxiliary group.
  pub fn new_with_secp256r1mlkem768(
    extra_root_certs: &[std::path::PathBuf],
    enabled: bool,
  ) -> anyhow::Result<Self> {
    let crypto = auxiliary_crypto_config(enabled);
    Self::new_with_crypto(extra_root_certs, &crypto)
  }

  pub(crate) fn new_with_crypto(
    extra_root_certs: &[std::path::PathBuf],
    crypto: &CryptoConfig,
  ) -> anyhow::Result<Self> {
    let tls_config = tls::build_upstream_client_config_with_crypto_resumption_and_revocation(
      crypto,
      extra_root_certs,
      &UpstreamEchConfig::default(),
      &crate::config::UpstreamTlsResumptionConfig::default(),
      None,
      "control-plane",
      None,
    )
    .context("failed to build control-plane TLS client config")?;
    Ok(Self::from_tls_config(tls_config))
  }

  pub(crate) fn new_with_crypto_and_revocation(
    extra_root_certs: &[std::path::PathBuf],
    crypto: &CryptoConfig,
    revocation: &tls::OutboundRevocationRuntime,
    policy: std::sync::Arc<OutboundTlsRevocationConfig>,
  ) -> anyhow::Result<Self> {
    let tls_config = tls::build_upstream_client_config_with_crypto_resumption_and_revocation(
      crypto,
      extra_root_certs,
      &UpstreamEchConfig::default(),
      &crate::config::UpstreamTlsResumptionConfig::default(),
      None,
      "control-plane",
      Some((revocation, policy)),
    )
    .context("failed to build revocation-aware control-plane TLS client config")?;
    Ok(Self::from_tls_config(tls_config))
  }

  pub(crate) fn new_with_upstream_policy(
    inherited_root_certs: &[std::path::PathBuf],
    crypto: &CryptoConfig,
    tls_policy: &UpstreamTlsConfig,
    revocation: &tls::OutboundRevocationRuntime,
    policy: std::sync::Arc<OutboundTlsRevocationConfig>,
  ) -> anyhow::Result<Self> {
    let tls_config = tls::build_upstream_client_config_with_policy(
      crypto,
      inherited_root_certs,
      tls_policy,
      None,
      "upstream-diagnostic",
      Some((revocation, policy)),
    )
    .context("failed to build policy-aware upstream diagnostic TLS client config")?;
    let server_name = tls_policy
      .server_name
      .as_deref()
      .map(|server_name| {
        rustls::pki_types::ServerName::try_from(server_name.to_string())
          .context("invalid fixed upstream diagnostic TLS server name")
      })
      .transpose()?;
    Ok(Self::from_tls_config_with_server_name(
      tls_config,
      server_name,
    ))
  }

  #[cfg(test)]
  pub(crate) fn new_webpki_only() -> anyhow::Result<Self> {
    let crypto = CryptoConfig::default();
    Self::new_webpki_only_with_crypto(&crypto)
  }

  pub(crate) fn new_webpki_only_with_auxiliary_tls(enabled: bool) -> anyhow::Result<Self> {
    let crypto = auxiliary_crypto_config(enabled);
    Self::new_webpki_only_with_crypto(&crypto)
  }

  pub(crate) fn new_webpki_only_with_crypto(crypto: &CryptoConfig) -> anyhow::Result<Self> {
    let tls_config = tls::build_webpki_client_config_with_crypto(crypto)
      .context("failed to build WebPKI-only control-plane TLS client config")?;
    Ok(Self::from_tls_config(tls_config))
  }

  fn from_tls_config(tls_config: rustls::ClientConfig) -> Self {
    Self::from_tls_config_with_server_name(tls_config, None)
  }

  fn from_tls_config_with_server_name(
    tls_config: rustls::ClientConfig,
    server_name: Option<rustls::pki_types::ServerName<'static>>,
  ) -> Self {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    http.set_nodelay(true);
    let connector = HttpsConnectorBuilder::new()
      .with_tls_config(tls_config)
      .https_or_http();
    let connector = if let Some(server_name) = server_name {
      connector.with_server_name_resolver(FixedServerNameResolver::new(server_name))
    } else {
      connector
    };
    let connector = connector.enable_http1().enable_http2().wrap_connector(http);
    let mut builder = Client::builder(TokioExecutor::new());
    builder.pool_timer(TokioTimer::new());
    builder.pool_idle_timeout(Duration::from_secs(30));
    builder.pool_max_idle_per_host(16);
    Self {
      client: builder.build(connector),
    }
  }

  pub async fn request(
    &self,
    request: Request<ControlBody>,
    timeout: Duration,
    max_body_bytes: usize,
  ) -> anyhow::Result<ControlHttpResponse> {
    tokio::time::timeout(timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("control-plane HTTP request failed")?;
      collect_response(response, max_body_bytes).await
    })
    .await
    .context("control-plane HTTP request timed out")?
  }

  pub async fn request_stream(
    &self,
    request: Request<ControlBody>,
    timeout: Duration,
  ) -> anyhow::Result<ControlHttpStreamResponse> {
    tokio::time::timeout(timeout, async {
      let response = self
        .client
        .request(request)
        .await
        .context("control-plane HTTP request failed")?;
      let (parts, body) = response.into_parts();
      Ok(ControlHttpStreamResponse {
        status: parts.status,
        headers: parts.headers,
        body,
      })
    })
    .await
    .context("control-plane HTTP request timed out")?
  }
}

fn auxiliary_crypto_config(enabled: bool) -> CryptoConfig {
  let mut crypto = CryptoConfig::default();
  crypto.auxiliary_tls.enable_secp256r1mlkem768 = enabled;
  crypto
}

async fn collect_response(
  response: Response<Incoming>,
  max_body_bytes: usize,
) -> anyhow::Result<ControlHttpResponse> {
  let (parts, body) = response.into_parts();
  let collected = Limited::new(body, max_body_bytes)
    .collect()
    .await
    .map_err(|error| anyhow!("control-plane HTTP response body failed: {error}"))?;
  Ok(ControlHttpResponse {
    status: parts.status,
    headers: parts.headers,
    body: collected.to_bytes(),
  })
}

pub fn empty_body() -> ControlBody {
  Empty::<Bytes>::new()
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

pub fn full_body(bytes: Bytes) -> ControlBody {
  Full::new(bytes)
    .map_err(|never: Infallible| -> BoxError { match never {} })
    .boxed()
}

pub fn uri_from_url(url: &url::Url) -> anyhow::Result<Uri> {
  url
    .as_str()
    .parse::<Uri>()
    .with_context(|| format!("invalid control-plane URL {url}"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::StatusCode;
  use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
  use std::fs;
  use std::sync::Arc;
  use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpListener;
  use tokio_rustls::TlsAcceptor;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[test]
  fn webpki_only_client_builds_without_operator_roots() {
    ControlHttpClient::new_webpki_only().expect("WebPKI-only control HTTP client should build");
  }

  #[test]
  fn auxiliary_client_builds_with_secp256r1mlkem768_enabled() {
    ControlHttpClient::new_with_secp256r1mlkem768(&[], true)
      .expect("auxiliary control HTTP client should build");
    ControlHttpClient::new_webpki_only_with_auxiliary_tls(true)
      .expect("auxiliary WebPKI-only control HTTP client should build");
  }

  #[tokio::test]
  async fn auxiliary_control_client_negotiates_secp256r1mlkem768_with_configured_ca() {
    let temp_dir = common::TempDir::new("control-http-pq-interop");
    let (ca, ca_key) = common::create_self_signed_cert(temp_dir.path(), "control-http-pq-ca");
    let (cert, key) =
      common::create_ca_signed_server_cert(temp_dir.path(), "localhost", &ca, &ca_key);
    let (uri, server) = spawn_secp256r1mlkem768_server(&cert, &key).await;

    let default = ControlHttpClient::new(std::slice::from_ref(&ca))
      .expect("default control client should build");
    let default_request = Request::builder()
      .uri(uri.clone())
      .body(empty_body())
      .expect("default control request should build");
    assert!(
      default
        .request(default_request, Duration::from_secs(3), 1024)
        .await
        .is_err(),
      "default-off control client must not negotiate the P-256 hybrid group"
    );

    let enabled = ControlHttpClient::new_with_secp256r1mlkem768(std::slice::from_ref(&ca), true)
      .expect("auxiliary control client should build");
    let request = Request::builder()
      .uri(uri)
      .body(empty_body())
      .expect("auxiliary control request should build");
    let response = enabled
      .request(request, Duration::from_secs(3), 1024)
      .await
      .expect("auxiliary control client should negotiate the P-256 hybrid group");
    assert_eq!(response.status, StatusCode::OK);
    assert!(server.await.expect("PQ TLS server task should complete"));
  }

  #[tokio::test]
  async fn request_timeout_covers_response_body_collection() {
    let uri = spawn_delayed_body_server(Duration::from_millis(600), b"ok").await;
    let client = ControlHttpClient::new(&[]).expect("control HTTP client should build");
    let request = Request::builder()
      .uri(uri)
      .body(empty_body())
      .expect("request should build");

    let error = match client
      .request(request, Duration::from_millis(100), 1024)
      .await
    {
      Ok(_) => panic!("delayed response body should hit the control HTTP timeout"),
      Err(error) => error,
    };

    assert!(
      format!("{error:#}").contains("control-plane HTTP request timed out"),
      "unexpected error: {error:#}"
    );
  }

  #[tokio::test]
  async fn request_collects_response_body_before_timeout() {
    let uri = spawn_delayed_body_server(Duration::ZERO, b"ok").await;
    let client = ControlHttpClient::new(&[]).expect("control HTTP client should build");
    let request = Request::builder()
      .uri(uri)
      .body(empty_body())
      .expect("request should build");

    let response = client
      .request(request, Duration::from_secs(1), 1024)
      .await
      .expect("response should complete before the control HTTP timeout");

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, Bytes::from_static(b"ok"));
  }

  async fn spawn_delayed_body_server(body_delay: Duration, body: &'static [u8]) -> Uri {
    let listener = TcpListener::bind(("127.0.0.1", 0))
      .await
      .expect("test server should bind");
    let address = listener.local_addr().expect("test server address");
    tokio::spawn(async move {
      let (mut stream, _) = listener.accept().await.expect("test server should accept");
      read_request_headers(&mut stream).await;
      let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
      );
      stream
        .write_all(response.as_bytes())
        .await
        .expect("test server should write response headers");
      stream
        .flush()
        .await
        .expect("test server should flush headers");
      if !body_delay.is_zero() {
        tokio::time::sleep(body_delay).await;
      }
      let _ = stream.write_all(body).await;
    });
    format!("http://{address}/")
      .parse()
      .expect("test server URI should parse")
  }

  async fn read_request_headers(stream: &mut (impl AsyncRead + Unpin)) {
    let mut buffer = [0_u8; 1024];
    let mut received = Vec::new();
    loop {
      let read = stream
        .read(&mut buffer)
        .await
        .expect("test server should read request");
      if read == 0 {
        break;
      }
      received.extend_from_slice(&buffer[..read]);
      if received.windows(4).any(|window| window == b"\r\n\r\n") {
        break;
      }
    }
  }

  async fn spawn_secp256r1mlkem768_server(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
  ) -> (Uri, tokio::task::JoinHandle<bool>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
      .await
      .expect("PQ TLS server should bind");
    let port = listener
      .local_addr()
      .expect("PQ TLS listener should expose its address")
      .port();
    let cert_bytes = fs::read(cert_path).expect("PQ TLS certificate should be readable");
    let certificates = CertificateDer::pem_slice_iter(&cert_bytes)
      .collect::<Result<Vec<_>, _>>()
      .expect("PQ TLS certificate should parse");
    let key_bytes = fs::read(key_path).expect("PQ TLS key should be readable");
    let private_key =
      PrivateKeyDer::from_pem_slice(&key_bytes).expect("PQ TLS private key should parse");
    let mut provider = crate::tls::aws_lc_provider_with_secp256r1mlkem768(true);
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768];
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
      .with_safe_default_protocol_versions()
      .expect("PQ TLS versions should configure")
      .with_no_client_auth()
      .with_single_cert(certificates, private_key)
      .expect("PQ TLS server config should build");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let server = tokio::spawn(async move {
      for _ in 0..2 {
        let Ok(Ok((stream, _))) =
          tokio::time::timeout(Duration::from_secs(3), listener.accept()).await
        else {
          return false;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
          continue;
        };
        read_request_headers(&mut stream).await;
        if stream
          .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
          .await
          .is_ok()
        {
          return true;
        }
      }
      false
    });
    (
      format!("https://localhost:{port}/")
        .parse()
        .expect("PQ TLS URI should parse"),
      server,
    )
  }
}
