//! Bounded HTTP transport for control-plane executables.
//!
//! This crate deliberately has no dependency on the data-plane listener runtime.

#![forbid(unsafe_code)]

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use bytes::Bytes;
use http::{Request, Response, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, pem::PemObject};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ControlBody = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct ControlHttpClient {
  client: Client<hyper_rustls::HttpsConnector<HttpConnector>, ControlBody>,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct ControlHttpResponseBodyLimitError {
  status: http::StatusCode,
  max_body_bytes: usize,
}

impl ControlHttpResponseBodyLimitError {
  pub const fn status(&self) -> http::StatusCode {
    self.status
  }

  pub const fn max_body_bytes(&self) -> usize {
    self.max_body_bytes
  }
}

impl std::fmt::Display for ControlHttpResponseBodyLimitError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "control-plane HTTP response body exceeded the {} byte limit (status {})",
      self.max_body_bytes, self.status
    )
  }
}

impl std::error::Error for ControlHttpResponseBodyLimitError {}

impl ControlHttpClient {
  /// Build a client with WebPKI roots plus explicitly supplied PEM roots.
  pub fn new(extra_root_certs: &[std::path::PathBuf]) -> anyhow::Result<Self> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for path in extra_root_certs {
      let certs = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("failed to open root certificate {}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse root certificate {}", path.display()))?;
      let (added, _ignored) = roots.add_parsable_certificates(certs);
      if added == 0 {
        bail!(
          "no parsable control-plane root certificates found in {}",
          path.display()
        );
      }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls_config = rustls::ClientConfig::builder_with_provider(provider)
      .with_safe_default_protocol_versions()
      .context("failed to configure control-plane TLS versions")?
      .with_root_certificates(roots)
      .with_no_client_auth();
    Ok(Self::from_tls_config(tls_config))
  }

  /// Build a client from a caller-owned TLS policy.
  pub fn from_tls_config(tls_config: rustls::ClientConfig) -> Self {
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
  let status = parts.status;
  let collected = Limited::new(body, max_body_bytes)
    .collect()
    .await
    .map_err(|error| {
      if error.downcast_ref::<LengthLimitError>().is_some() {
        anyhow::Error::new(ControlHttpResponseBodyLimitError {
          status,
          max_body_bytes,
        })
      } else {
        anyhow!("control-plane HTTP response body failed: {error}")
      }
    })?;
  Ok(ControlHttpResponse {
    status,
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

  #[tokio::test]
  async fn request_timeout_covers_response_body_collection() {
    let uri = spawn_delayed_body_server(Duration::from_millis(600), b"ok").await;
    let client = ControlHttpClient::new(&[]).expect("control HTTP client should build");
    let request = Request::builder()
      .uri(uri)
      .body(empty_body())
      .expect("request should build");
    let error = client
      .request(request, Duration::from_millis(100), 1024)
      .await
      .expect_err("delayed response body should time out");
    assert!(format!("{error:#}").contains("control-plane HTTP request timed out"));
  }

  #[tokio::test]
  async fn request_collects_bounded_response_body() {
    let uri = spawn_delayed_body_server(Duration::ZERO, b"ok").await;
    let client = ControlHttpClient::new(&[]).expect("control HTTP client should build");
    let request = Request::builder()
      .uri(uri)
      .body(empty_body())
      .expect("request should build");
    let response = client
      .request(request, Duration::from_secs(1), 1024)
      .await
      .expect("response should complete");
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, Bytes::from_static(b"ok"));
  }

  #[tokio::test]
  async fn response_body_limit_error_preserves_status_and_limit() {
    let uri = spawn_delayed_body_server(Duration::ZERO, b"oversized").await;
    let client = ControlHttpClient::new(&[]).expect("control HTTP client should build");
    let request = Request::builder()
      .uri(uri)
      .body(empty_body())
      .expect("request should build");
    let error = client
      .request(request, Duration::from_secs(1), 4)
      .await
      .expect_err("oversized response body should fail");
    let limit_error = error
      .downcast_ref::<ControlHttpResponseBodyLimitError>()
      .expect("body limit error should retain its concrete type");
    assert_eq!(limit_error.status(), StatusCode::OK);
    assert_eq!(limit_error.max_body_bytes(), 4);
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
      stream.flush().await.expect("test server should flush");
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
