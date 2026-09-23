//! Wire-level regression for an HTTP/3 server that rejects request headers
//! before accepting the empty request body's FIN.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use bytes::Bytes;
use h3_quinn::quinn::crypto::rustls::QuicServerConfig;
use h3_quinn::quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use tokio::sync::oneshot;

use super::{
  h3_downstream_request, upstream_tls_server_config, DownstreamArgs, DownstreamProtocol,
};

const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum ResponseMode {
  EarlyRejection,
  Complete,
  MissingResponse,
}

struct TestCertificate {
  directory: PathBuf,
  ca: PathBuf,
  cert: PathBuf,
  key: PathBuf,
}

fn run_openssl(command: &mut Command) -> anyhow::Result<()> {
  let output = command
    .output()
    .context("generate ephemeral H3 test certificate with openssl")?;
  if !output.status.success() {
    return Err(anyhow!(
      "openssl certificate generation failed: {}",
      String::from_utf8_lossy(&output.stderr)
    ));
  }
  Ok(())
}

impl TestCertificate {
  fn generate() -> anyhow::Result<Self> {
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .context("clock predates UNIX epoch")?
      .as_nanos();
    let directory = std::env::temp_dir().join(format!(
      "oxibelt-h3-early-response-{}-{now}",
      std::process::id()
    ));
    fs::create_dir(&directory).context("create isolated H3 test certificate directory")?;
    let ca = directory.join("ca.pem");
    let ca_key = directory.join("ca.key");
    let cert = directory.join("server.pem");
    let key = directory.join("server.key");
    let request = directory.join("server.csr");
    let fixture = Self {
      directory,
      ca,
      cert,
      key,
    };
    run_openssl(
      Command::new("openssl")
        .args([
          "req",
          "-x509",
          "-newkey",
          "ec",
          "-pkeyopt",
          "ec_paramgen_curve:P-256",
          "-nodes",
          "-days",
          "1",
          "-subj",
          "/CN=OxiBelt H3 test CA",
          "-addext",
          "basicConstraints=critical,CA:TRUE",
          "-addext",
          "keyUsage=critical,keyCertSign,cRLSign",
          "-keyout",
        ])
        .arg(&ca_key)
        .arg("-out")
        .arg(&fixture.ca),
    )?;
    run_openssl(
      Command::new("openssl")
        .args([
          "req",
          "-new",
          "-newkey",
          "ec",
          "-pkeyopt",
          "ec_paramgen_curve:P-256",
          "-nodes",
          "-subj",
          "/CN=localhost",
          "-addext",
          "subjectAltName=DNS:localhost,IP:127.0.0.1",
          "-keyout",
        ])
        .arg(&fixture.key)
        .arg("-out")
        .arg(&request),
    )?;
    run_openssl(
      Command::new("openssl")
        .args(["x509", "-req", "-in"])
        .arg(&request)
        .arg("-CA")
        .arg(&fixture.ca)
        .arg("-CAkey")
        .arg(&ca_key)
        .args([
          "-CAcreateserial",
          "-copy_extensions",
          "copy",
          "-days",
          "1",
          "-out",
        ])
        .arg(&fixture.cert),
    )?;
    Ok(fixture)
  }
}

impl Drop for TestCertificate {
  fn drop(&mut self) {
    let _ = fs::remove_dir_all(&self.directory);
  }
}

fn downstream_args(cert: &Path, port: u16) -> DownstreamArgs {
  DownstreamArgs {
    protocol: DownstreamProtocol::H3,
    host: "127.0.0.1".to_owned(),
    port,
    server_name: "localhost".to_owned(),
    authority: "localhost".to_owned(),
    path: "/early-rejection".to_owned(),
    method: Method::POST,
    body: Vec::new(),
    body_bytes: None,
    body_chunk_size: 16 * 1024,
    zero_length_body_end_delay_ms: None,
    omit_content_length: false,
    h2_eager_body: false,
    h3_reset_after_body_prefix: false,
    headers: HeaderMap::new(),
    ca_cert: cert.to_string_lossy().into_owned(),
    client_identity: None,
    tls_version: None,
    quic_initial_alpn_padding_bytes: 0,
    expect_status: None,
  }
}

async fn request_against_server(
  mode: ResponseMode,
) -> anyhow::Result<anyhow::Result<serde_json::Value>> {
  let fixture = TestCertificate::generate()?;
  let mut tls = upstream_tls_server_config(
    fixture
      .cert
      .to_str()
      .context("certificate path is not UTF-8")?,
    fixture.key.to_str().context("key path is not UTF-8")?,
    None,
    true,
  )?;
  tls.alpn_protocols = vec![b"h3".to_vec()];
  let crypto = QuicServerConfig::try_from(tls).context("build H3 test server TLS")?;
  let endpoint = Endpoint::server(
    QuinnServerConfig::with_crypto(Arc::new(crypto)),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
  )
  .context("bind H3 test server")?;
  let port = endpoint.local_addr()?.port();
  let (done_tx, done_rx) = oneshot::channel();
  let server = tokio::spawn(async move {
    let incoming = endpoint.accept().await.context("accept H3 connection")?;
    let quic = incoming.await.context("complete H3 connection")?;
    let mut connection = h3::server::builder()
      .build(h3_quinn::Connection::new(quic))
      .await
      .context("build H3 test connection")?;
    let resolver = connection
      .accept()
      .await
      .context("accept H3 request")?
      .context("client closed without a request")?;
    let (request, mut stream) = resolver
      .resolve_request()
      .await
      .context("read H3 headers")?;
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri().path(), "/early-rejection");
    match mode {
      ResponseMode::EarlyRejection => {
        // This mirrors a header-only security rejection: the server abandons
        // its receive half but still sends a complete response on its send half.
        stream.stop_sending(h3::error::Code::from(0u64));
        stream
          .send_response(
            Response::builder()
              .status(StatusCode::BAD_REQUEST)
              .header("x-rejection", "headers")
              .body(())?,
          )
          .await?;
        stream.send_data(Bytes::from_static(b"rejected")).await?;
        let mut trailers = HeaderMap::new();
        trailers.insert("x-complete", HeaderValue::from_static("yes"));
        stream.send_trailers(trailers).await?;
        stream.finish().await?;
      }
      ResponseMode::Complete => {
        while stream.recv_data().await?.is_some() {}
        stream
          .send_response(Response::builder().status(StatusCode::OK).body(())?)
          .await?;
        stream.send_data(Bytes::from_static(b"accepted")).await?;
        stream.finish().await?;
      }
      ResponseMode::MissingResponse => {
        stream.stop_sending(h3::error::Code::H3_NO_ERROR);
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
      }
    }
    // Keep the response stream alive until the probe either reads it or
    // returns an error. An error path need not explicitly close the connection.
    let _ = done_rx.await;
    Ok::<_, anyhow::Error>(())
  });
  let args = downstream_args(&fixture.ca, port);
  let result = tokio::time::timeout(DEADLINE, h3_downstream_request(&args)).await;
  let _ = done_tx.send(());
  tokio::time::timeout(DEADLINE, server)
    .await
    .context("H3 test server timed out")?
    .context("H3 test server panicked")??;
  result.context("H3 probe timed out")
}

#[tokio::test]
async fn header_only_rejection_preserves_the_complete_h3_response() -> anyhow::Result<()> {
  let response = request_against_server(ResponseMode::EarlyRejection).await??;
  assert_eq!(response["status"], 400);
  assert_eq!(response["headers"]["x-rejection"], "headers");
  assert_eq!(response["body"], "rejected");
  assert_eq!(response["trailers"]["x-complete"], "yes");
  Ok(())
}

#[tokio::test]
async fn normal_h3_response_remains_complete() -> anyhow::Result<()> {
  let response = request_against_server(ResponseMode::Complete).await??;
  assert_eq!(response["status"], 200);
  assert_eq!(response["body"], "accepted");
  Ok(())
}

#[tokio::test]
async fn cancelled_h3_response_still_fails() -> anyhow::Result<()> {
  let result = request_against_server(ResponseMode::MissingResponse).await?;
  assert!(result.is_err(), "a missing response must not be accepted");
  Ok(())
}
