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
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};

use crate::config::{CryptoConfig, OutboundTlsRevocationConfig, UpstreamEchConfig};
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

  pub(crate) fn new_webpki_only() -> anyhow::Result<Self> {
    let crypto = CryptoConfig::default();
    Self::new_webpki_only_with_crypto(&crypto)
  }

  pub(crate) fn new_webpki_only_with_crypto(crypto: &CryptoConfig) -> anyhow::Result<Self> {
    let tls_config = tls::build_webpki_client_config_with_crypto(crypto)
      .context("failed to build WebPKI-only control-plane TLS client config")?;
    Ok(Self::from_tls_config(tls_config))
  }

  fn from_tls_config(tls_config: rustls::ClientConfig) -> Self {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    http.set_nodelay(true);
    let connector = HttpsConnectorBuilder::new()
      .with_tls_config(tls_config)
      .https_or_http()
      .enable_http1()
      .enable_http2()
      .wrap_connector(http);
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
  use tokio::io::{AsyncReadExt, AsyncWriteExt};
  use tokio::net::TcpListener;

  #[test]
  fn webpki_only_client_builds_without_operator_roots() {
    ControlHttpClient::new_webpki_only().expect("WebPKI-only control HTTP client should build");
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

  async fn read_request_headers(stream: &mut tokio::net::TcpStream) {
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
}
