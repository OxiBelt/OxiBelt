#[path = "common/mod.rs"]
mod common;

use std::future::poll_fn;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h3_quinn::quinn::Endpoint;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxibelt::config::{Config, RuntimeOverrides, UpstreamEchConfig};
use oxibelt::server;
use oxibelt::state::{AppHandle, AppSnapshot};
use oxibelt::tls;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const WEBSOCKET_MASKED_PING_FRAME: [u8; 10] = [0x89, 0x84, 1, 2, 3, 4, b'q', b'k', b'm', b'c'];
const WEBSOCKET_PONG_FRAME: [u8; 6] = [0x8a, 0x04, b'p', b'i', b'n', b'g'];

struct ObservedBackendRequest {
  proxy_header: Vec<u8>,
  request: Vec<u8>,
}

#[tokio::test]
async fn trusted_plaintext_tls_tlvs_reach_waf_and_are_relayed_without_cache_reuse() {
  let temporary = common::TempDir::new("proxy-protocol-tls-plaintext");
  let (certificate, key) = common::create_self_signed_cert(temporary.path(), "proxy-tls");
  let (backend_addr, mut observed, backend_task) = observing_backend().await;
  let http_addr = unused_loopback_addr().await;
  let https_addr = unused_loopback_addr().await;
  let raw = plaintext_proxy_config(
    &certificate,
    &key,
    http_addr,
    https_addr,
    backend_addr,
    "received_proxy",
  );
  let server_task = start_server(&raw).await;

  let source: SocketAddr = "198.51.100.40:51000".parse().unwrap();
  let destination: SocketAddr = "192.0.2.44:443".parse().unwrap();
  let rejected = send_prefaced_http(
    http_addr,
    &proxy_v2_ssl_header(source, destination, "rejected.pp.example"),
    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    &server_task,
  )
  .await;
  assert_eq!(
    response_status(&rejected),
    451,
    "WAF must see trusted PROXY TLS metadata"
  );
  assert!(
    tokio::time::timeout(Duration::from_millis(200), observed.recv())
      .await
      .is_err(),
    "a WAF-rejected request must not reach the backend"
  );

  for (source, common_name) in [
    ("198.51.100.40:51000", "first.pp.example"),
    ("198.51.100.41:51001", "second.pp.example"),
  ] {
    let response = send_prefaced_http(
      http_addr,
      &proxy_v2_ssl_header(source.parse().unwrap(), destination, common_name),
      b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
      &server_task,
    )
    .await;
    assert_eq!(response_status(&response), 200);
    assert!(
      response
        .windows(b"cache-control: no-store".len())
        .any(|window| window.eq_ignore_ascii_case(b"cache-control: no-store")),
      "TLS-metadata-selected egress responses must disable downstream caching"
    );
    let request = tokio::time::timeout(Duration::from_secs(2), observed.recv())
      .await
      .expect("backend observation should not time out")
      .expect("backend observer should remain available");
    assert_ssl_header(&request.proxy_header, common_name, true);
    assert_http1_request_path(&request.request, "/");
  }

  let cached = send_prefaced_http(
    http_addr,
    &proxy_v2_ssl_header(
      "198.51.100.41:51001".parse().unwrap(),
      destination,
      "second.pp.example",
    ),
    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    &server_task,
  )
  .await;
  assert_eq!(response_status(&cached), 200);
  assert!(
    tokio::time::timeout(Duration::from_millis(200), observed.recv())
      .await
      .is_err(),
    "identical selected evidence must reuse its internal cache partition"
  );
  server_task.abort();
  backend_task.abort();
}

#[tokio::test]
async fn local_tls_metadata_is_emitted_before_the_http_request() {
  let temporary = common::TempDir::new("proxy-protocol-local-tls");
  let (ca_certificate, ca_key) = common::create_self_signed_cert(temporary.path(), "local-tls-ca");
  let (certificate, key) = common::create_ca_signed_server_cert(
    temporary.path(),
    "local-tls.example",
    &ca_certificate,
    &ca_key,
  );
  let (backend_addr, mut observed, backend_task) = observing_backend().await;
  let https_addr = unused_loopback_addr().await;
  let raw = local_tls_proxy_config(&certificate, &key, https_addr, backend_addr);
  let server_task = start_server(&raw).await;

  let client_config =
    tls::build_upstream_client_config(&[ca_certificate], &UpstreamEchConfig::default())
      .expect("test client trust store should accept the generated certificate");
  let stream = connect_with_retry(https_addr, &server_task).await;
  let mut stream = TlsConnector::from(Arc::new(client_config))
    .connect("local-tls.example".try_into().unwrap(), stream)
    .await
    .expect("local TLS handshake should complete");
  stream
    .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    .await
    .expect("TLS request should write");
  let response = read_to_end(&mut stream).await;
  assert_eq!(response_status(&response), 200);
  assert!(
    response
      .windows(b"cache-control: no-store".len())
      .any(|window| window.eq_ignore_ascii_case(b"cache-control: no-store")),
    "local TLS metadata egress must disable shared response storage"
  );

  let request = tokio::time::timeout(Duration::from_secs(2), observed.recv())
    .await
    .expect("backend observation should not time out")
    .expect("backend observer should remain available");
  assert_ssl_header(&request.proxy_header, "", false);
  assert_eq!(
    request.proxy_header[31] & 0x01,
    0x01,
    "local TLS must set PP2_CLIENT_SSL"
  );
  assert_http1_request_path(&request.request, "/");

  server_task.abort();
  backend_task.abort();
}

#[tokio::test]
async fn http2_downstream_uses_tls_tlvs_for_a_tcp_http1_backend() {
  let temporary = common::TempDir::new("proxy-protocol-local-tls-h2");
  let (ca_certificate, ca_key) = common::create_self_signed_cert(temporary.path(), "local-h2-ca");
  let (certificate, key) = common::create_ca_signed_server_cert(
    temporary.path(),
    "local-h2.example",
    &ca_certificate,
    &ca_key,
  );
  let (backend_addr, mut observed, backend_task) = observing_backend().await;
  let https_addr = unused_loopback_addr().await;
  let raw = local_tls_proxy_config(&certificate, &key, https_addr, backend_addr);
  let server_task = start_server(&raw).await;

  let mut client_config =
    tls::build_upstream_client_config(&[ca_certificate], &UpstreamEchConfig::default())
      .expect("test client trust store should accept the generated certificate");
  client_config.alpn_protocols = vec![b"h2".to_vec()];
  let stream = connect_with_retry(https_addr, &server_task).await;
  let stream = TlsConnector::from(Arc::new(client_config))
    .connect("local-h2.example".try_into().unwrap(), stream)
    .await
    .expect("HTTP/2 TLS handshake should complete");
  let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
    .handshake(TokioIo::new(stream))
    .await
    .expect("HTTP/2 client connection should establish");
  let connection_task = tokio::spawn(async move {
    let _ = connection.await;
  });
  let response = sender
    .send_request(
      http::Request::builder()
        .method("GET")
        .uri("https://example.com/h2")
        .body(Empty::<Bytes>::new())
        .unwrap(),
    )
    .await
    .expect("HTTP/2 request should complete");
  assert_eq!(response.status(), http::StatusCode::OK);
  let _ = response
    .into_body()
    .collect()
    .await
    .expect("HTTP/2 response body should complete");
  connection_task.abort();

  let request = tokio::time::timeout(Duration::from_secs(2), observed.recv())
    .await
    .expect("backend observation should not time out")
    .expect("backend observer should remain available");
  assert_ssl_header(&request.proxy_header, "", false);
  assert_http1_request_path(&request.request, "/h2");

  server_task.abort();
  backend_task.abort();
}

#[tokio::test]
async fn http3_downstream_uses_tls_tlvs_for_a_tcp_http1_backend() {
  let temporary = common::TempDir::new("proxy-protocol-local-tls-h3");
  let (ca_certificate, ca_key) = common::create_self_signed_cert(temporary.path(), "local-h3-ca");
  let (certificate, key) = common::create_ca_signed_server_cert(
    temporary.path(),
    "local-h3.example",
    &ca_certificate,
    &ca_key,
  );
  let (client_certificate, client_key) = common::create_ca_signed_client_cert(
    temporary.path(),
    "local-h3-client.example",
    &ca_certificate,
    &ca_key,
  );
  let (backend_addr, mut observed, backend_task) = observing_backend().await;
  let https_addr = unused_loopback_addr().await;
  let raw = local_mtls_proxy_config(
    &certificate,
    &key,
    &ca_certificate,
    https_addr,
    backend_addr,
  )
  .replace("http3 = false", "http3 = true");
  let server_task = start_server(&raw).await;

  let mut client_tls = mtls_client_config(&ca_certificate, &client_certificate, &client_key);
  client_tls.alpn_protocols = vec![b"h3".to_vec()];
  let client_config = h3_quinn::quinn::ClientConfig::new(Arc::new(
    h3_quinn::quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
  ));
  let mut endpoint =
    Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("HTTP/3 client endpoint should bind");
  endpoint.set_default_client_config(client_config);
  let connection =
    connect_h3_with_retry(&endpoint, https_addr, "local-h3.example", &server_task).await;
  let h3_connection = h3_quinn::Connection::new(connection);
  let (mut driver, mut sender): (_, h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>) =
    h3::client::builder()
      .build(h3_connection)
      .await
      .expect("HTTP/3 client connection should establish");
  let driver_task = tokio::spawn(async move {
    let _ = poll_fn(|context| driver.poll_close(context)).await;
  });
  let request = http::Request::builder()
    .method("GET")
    .uri("https://example.com/h3")
    .body(())
    .unwrap();
  let mut stream = sender
    .send_request(request)
    .await
    .expect("HTTP/3 request should open a stream");
  stream.finish().await.expect("HTTP/3 request should finish");
  let response = tokio::time::timeout(Duration::from_secs(2), stream.recv_response())
    .await
    .expect("HTTP/3 response should not time out")
    .expect("HTTP/3 response should arrive");
  assert_eq!(response.status(), http::StatusCode::OK);
  assert_eq!(response.headers()[http::header::CACHE_CONTROL], "no-store");
  driver_task.abort();
  endpoint.close(0u32.into(), b"test complete");

  let request = tokio::time::timeout(Duration::from_secs(2), observed.recv())
    .await
    .expect("backend observation should not time out")
    .expect("backend observer should remain available");
  assert_ssl_header(&request.proxy_header, "", false);
  assert_eq!(
    request.proxy_header[31] & 0x07,
    0x05,
    "H3 proves session certificate, not current-handshake transmission"
  );
  assert_eq!(
    ssl_nested_tlv(&request.proxy_header, 0x28),
    Some(first_certificate_der(&client_certificate).as_slice())
  );
  assert_http1_request_path(&request.request, "/h3");

  server_task.abort();
  backend_task.abort();
}

#[tokio::test]
async fn connect_tunnel_writes_local_tls_tlv_before_opaque_payload() {
  let temporary = common::TempDir::new("proxy-protocol-local-tls-connect");
  let (ca_certificate, ca_key) =
    common::create_self_signed_cert(temporary.path(), "local-connect-ca");
  let (certificate, key) = common::create_ca_signed_server_cert(
    temporary.path(),
    "local-connect.example",
    &ca_certificate,
    &ca_key,
  );
  let (backend_addr, mut observed, backend_task) = opaque_observing_backend().await;
  let https_addr = unused_loopback_addr().await;
  let raw = connect_tls_proxy_config(&certificate, &key, https_addr, backend_addr);
  let server_task = start_server(&raw).await;

  let client_config =
    tls::build_upstream_client_config(&[ca_certificate], &UpstreamEchConfig::default())
      .expect("test client trust store should accept the generated certificate");
  let stream = connect_with_retry(https_addr, &server_task).await;
  let mut stream = TlsConnector::from(Arc::new(client_config))
    .connect("local-connect.example".try_into().unwrap(), stream)
    .await
    .expect("CONNECT TLS handshake should complete");
  stream
    .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    .await
    .expect("CONNECT request should write");
  let response = read_http_header_block(&mut stream).await;
  assert_eq!(response_status(&response), 200);
  stream
    .write_all(b"ping")
    .await
    .expect("CONNECT tunnel payload should write");
  let mut echo = [0u8; 4];
  tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echo))
    .await
    .expect("CONNECT tunnel echo should arrive before the test deadline")
    .expect("CONNECT tunnel should echo payload");
  assert_eq!(&echo, b"pong");

  let request = tokio::time::timeout(Duration::from_secs(2), observed.recv())
    .await
    .expect("backend observation should not time out")
    .expect("backend observer should remain available");
  assert_ssl_header(&request.proxy_header, "", false);
  assert_eq!(request.request, b"ping");

  server_task.abort();
  backend_task.abort();
}

#[tokio::test]
async fn websocket_upgrade_writes_local_tls_tlv_before_opaque_payload() {
  let temporary = common::TempDir::new("proxy-protocol-local-tls-websocket");
  let (ca_certificate, ca_key) =
    common::create_self_signed_cert(temporary.path(), "local-websocket-ca");
  let (certificate, key) = common::create_ca_signed_server_cert(
    temporary.path(),
    "local-websocket.example",
    &ca_certificate,
    &ca_key,
  );
  let (backend_addr, mut observed, backend_task) = websocket_observing_backend().await;
  let https_addr = unused_loopback_addr().await;
  let raw = local_tls_proxy_config(&certificate, &key, https_addr, backend_addr);
  let server_task = start_server(&raw).await;

  let client_config =
    tls::build_upstream_client_config(&[ca_certificate], &UpstreamEchConfig::default())
      .expect("test client trust store should accept the generated certificate");
  let stream = connect_with_retry(https_addr, &server_task).await;
  let mut stream = TlsConnector::from(Arc::new(client_config))
    .connect("local-websocket.example".try_into().unwrap(), stream)
    .await
    .expect("WebSocket TLS handshake should complete");
  stream
    .write_all(
      b"GET /socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    )
    .await
    .expect("WebSocket upgrade request should write");
  let response = read_http_header_block(&mut stream).await;
  assert_eq!(response_status(&response), 101);
  assert!(
    response
      .windows(b"Upgrade: websocket".len())
      .any(|window| window.eq_ignore_ascii_case(b"Upgrade: websocket")),
    "proxy must relay the upstream WebSocket protocol selection"
  );
  stream
    .write_all(&WEBSOCKET_MASKED_PING_FRAME)
    .await
    .expect("WebSocket ping frame should write");
  let mut echo = [0u8; WEBSOCKET_PONG_FRAME.len()];
  tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echo))
    .await
    .expect("WebSocket pong frame should arrive before the test deadline")
    .expect("WebSocket tunnel should relay the pong frame");
  assert_eq!(echo, WEBSOCKET_PONG_FRAME);

  let request = tokio::time::timeout(Duration::from_secs(2), observed.recv())
    .await
    .expect("backend observation should not time out")
    .expect("backend observer should remain available");
  assert_ssl_header(&request.proxy_header, "", false);
  assert_http1_request_path(&request.request, "/socket");
  assert!(
    request
      .request
      .windows(b"Upgrade: websocket".len())
      .any(|window| window.eq_ignore_ascii_case(b"Upgrade: websocket")),
    "the upstream request must preserve the WebSocket upgrade offer"
  );

  server_task.abort();
  backend_task.abort();
}

#[tokio::test]
async fn local_mtls_egress_emits_leaf_der_without_relaying_received_assertions() {
  let temporary = common::TempDir::new("proxy-protocol-local-mtls");
  let (ca_certificate, ca_key) = common::create_self_signed_cert(temporary.path(), "proxy-tls-ca");
  let (server_certificate, server_key) = common::create_ca_signed_server_cert(
    temporary.path(),
    "local-mtls.example",
    &ca_certificate,
    &ca_key,
  );
  let (client_certificate, client_key) = common::create_ca_signed_client_cert(
    temporary.path(),
    "local-client.example",
    &ca_certificate,
    &ca_key,
  );
  let expected_client_der = first_certificate_der(&client_certificate);
  let (backend_addr, mut observed, backend_task) = observing_backend().await;
  let https_addr = unused_loopback_addr().await;
  let raw = local_mtls_proxy_config(
    &server_certificate,
    &server_key,
    &ca_certificate,
    https_addr,
    backend_addr,
  );
  let server_task = start_server(&raw).await;

  let client_config = mtls_client_config(&ca_certificate, &client_certificate, &client_key);
  let mut raw_stream = connect_with_retry(https_addr, &server_task).await;
  raw_stream
    .write_all(&proxy_v2_ssl_header(
      "127.0.0.1:51000".parse().unwrap(),
      https_addr,
      "received-assertion.example",
    ))
    .await
    .expect("trusted test PROXY preface should write");
  let mut stream = TlsConnector::from(Arc::new(client_config))
    .connect("local-mtls.example".try_into().unwrap(), raw_stream)
    .await
    .expect("mTLS handshake should complete");
  stream
    .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    .await
    .expect("mTLS request should write");
  let response = read_to_end(&mut stream).await;
  assert_eq!(response_status(&response), 200);

  let request = tokio::time::timeout(Duration::from_secs(2), observed.recv())
    .await
    .expect("backend observation should not time out")
    .expect("backend observer should remain available");
  assert_ssl_header(&request.proxy_header, "", false);
  let ssl_flags = request.proxy_header[31];
  assert_eq!(
    ssl_flags & 0x07,
    0x07,
    "a full locally verified client certificate must set SSL, CERT_CONN, and CERT_SESS"
  );
  assert_eq!(
    &request.proxy_header[32..36],
    &0u32.to_be_bytes(),
    "a locally verified client certificate must report successful verification"
  );
  assert_eq!(
    ssl_nested_tlv(&request.proxy_header, 0x28),
    Some(expected_client_der.as_slice()),
    "explicit DER forwarding must emit exactly the locally verified leaf"
  );
  assert!(
    !request
      .proxy_header
      .windows(b"received-assertion.example".len())
      .any(|window| window == b"received-assertion.example"),
    "local_tls selection must not relay a received PROXY TLS assertion"
  );

  server_task.abort();
  backend_task.abort();
}

#[tokio::test]
async fn untrusted_or_real_ip_mismatched_tls_prefaces_do_not_reach_the_backend() {
  let temporary = common::TempDir::new("proxy-protocol-tls-negative");
  let (certificate, key) = common::create_self_signed_cert(temporary.path(), "proxy-tls-negative");
  let (backend_addr, mut observed, backend_task) = observing_backend().await;

  let untrusted_http = unused_loopback_addr().await;
  let untrusted_https = unused_loopback_addr().await;
  let mut untrusted = plaintext_proxy_config(
    &certificate,
    &key,
    untrusted_http,
    untrusted_https,
    backend_addr,
    "received_proxy",
  );
  untrusted = untrusted.replace(
    "trusted_sources = [\"127.0.0.1/32\"]",
    "trusted_sources = [\"192.0.2.0/24\"]",
  );
  let untrusted_task = start_server(&untrusted).await;
  let source: SocketAddr = "198.51.100.50:51000".parse().unwrap();
  let destination: SocketAddr = "192.0.2.50:443".parse().unwrap();
  let mut stream = connect_with_retry(untrusted_http, &untrusted_task).await;
  stream
    .write_all(&proxy_v2_ssl_header(
      source,
      destination,
      "untrusted.pp.example",
    ))
    .await
    .expect("untrusted client can write its attempted preface");
  stream
    .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    .await
    .expect("untrusted client can write its attempted request");
  let mut byte = [0u8; 1];
  match tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte)).await {
    Ok(Ok(0)) | Ok(Err(_)) => {}
    Ok(Ok(read)) => panic!("untrusted PROXY peer unexpectedly received {read} response bytes"),
    Err(_) => panic!("untrusted PROXY peer was not closed"),
  }
  assert!(
    tokio::time::timeout(Duration::from_millis(200), observed.recv())
      .await
      .is_err(),
    "an untrusted direct peer must not produce backend traffic"
  );
  untrusted_task.abort();

  let mismatch_http = unused_loopback_addr().await;
  let mismatch_https = unused_loopback_addr().await;
  let mut mismatched = plaintext_proxy_config(
    &certificate,
    &key,
    mismatch_http,
    mismatch_https,
    backend_addr,
    "received_proxy",
  );
  mismatched.push_str(
    r#"

[proxy.real_ip]
enabled = true
trusted_proxies = ["198.51.100.0/24"]
header = "x-forwarded-for"
recursive = true
fail_on_untrusted_forwarded_headers = true
"#,
  );
  let mismatch_task = start_server(&mismatched).await;
  let response = send_prefaced_http(
    mismatch_http,
    &proxy_v2_ssl_header(source, destination, "mismatch.pp.example"),
    b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 198.51.100.51\r\nConnection: close\r\n\r\n",
    &mismatch_task,
  )
  .await;
  assert_eq!(
    response_status(&response),
    502,
    "mismatched Real-IP and PROXY TLS source must fail closed"
  );
  assert!(
    tokio::time::timeout(Duration::from_millis(200), observed.recv())
      .await
      .is_err(),
    "mismatched metadata must fail before the backend dial"
  );

  mismatch_task.abort();
  backend_task.abort();
}

#[tokio::test]
async fn missing_received_proxy_tls_evidence_returns_502_before_backend_dial() {
  let temporary = common::TempDir::new("proxy-protocol-tls-missing-evidence");
  let (certificate, key) = common::create_self_signed_cert(temporary.path(), "missing-evidence");
  let (backend_addr, mut observed, backend_task) = observing_backend().await;
  let http_addr = unused_loopback_addr().await;
  let https_addr = unused_loopback_addr().await;
  let raw = missing_received_proxy_config(&certificate, &key, http_addr, https_addr, backend_addr);
  let server_task = start_server(&raw).await;

  let response = send_prefaced_http(
    http_addr,
    b"",
    b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    &server_task,
  )
  .await;
  assert_eq!(
    response_status(&response),
    502,
    "received_proxy egress without accepted PROXY TLS evidence must fail closed"
  );
  assert!(
    tokio::time::timeout(Duration::from_millis(200), observed.recv())
      .await
      .is_err(),
    "missing received TLS evidence must fail before the backend dial"
  );

  server_task.abort();
  backend_task.abort();
}

async fn observing_backend() -> (
  SocketAddr,
  mpsc::UnboundedReceiver<ObservedBackendRequest>,
  JoinHandle<()>,
) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("backend should bind");
  let address = listener
    .local_addr()
    .expect("backend address should be available");
  let (sender, receiver) = mpsc::unbounded_channel();
  let task = tokio::spawn(async move {
    while let Ok((stream, _)) = listener.accept().await {
      let sender = sender.clone();
      tokio::spawn(async move {
        let mut stream = stream;
        let proxy_header = read_proxy_v2_header(&mut stream).await;
        let request = read_http_headers(&mut stream).await;
        let _ = sender.send(ObservedBackendRequest {
          proxy_header,
          request,
        });
        stream
          .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nCache-Control: public, max-age=60\r\nConnection: close\r\n\r\nok",
          )
          .await
          .expect("backend response should write");
      });
    }
  });
  (address, receiver, task)
}

async fn opaque_observing_backend() -> (
  SocketAddr,
  mpsc::UnboundedReceiver<ObservedBackendRequest>,
  JoinHandle<()>,
) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("opaque backend should bind");
  let address = listener
    .local_addr()
    .expect("opaque backend address should be available");
  let (sender, receiver) = mpsc::unbounded_channel();
  let task = tokio::spawn(async move {
    while let Ok((stream, _)) = listener.accept().await {
      let sender = sender.clone();
      tokio::spawn(async move {
        let mut stream = stream;
        let proxy_header = read_proxy_v2_header(&mut stream).await;
        let mut payload = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut payload))
          .await
          .expect("opaque tunnel payload should arrive before the test deadline")
          .expect("opaque backend should receive tunnel payload");
        let _ = sender.send(ObservedBackendRequest {
          proxy_header,
          request: payload.to_vec(),
        });
        stream
          .write_all(b"pong")
          .await
          .expect("opaque backend echo should write");
      });
    }
  });
  (address, receiver, task)
}

async fn websocket_observing_backend() -> (
  SocketAddr,
  mpsc::UnboundedReceiver<ObservedBackendRequest>,
  JoinHandle<()>,
) {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("WebSocket backend should bind");
  let address = listener
    .local_addr()
    .expect("WebSocket backend address should be available");
  let (sender, receiver) = mpsc::unbounded_channel();
  let task = tokio::spawn(async move {
    while let Ok((stream, _)) = listener.accept().await {
      let sender = sender.clone();
      tokio::spawn(async move {
        let mut stream = stream;
        let proxy_header = read_proxy_v2_header(&mut stream).await;
        let request = read_http_headers(&mut stream).await;
        stream
          .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
          )
          .await
          .expect("WebSocket backend upgrade response should write");
        let mut payload = [0u8; WEBSOCKET_MASKED_PING_FRAME.len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut payload))
          .await
          .expect("WebSocket ping frame should arrive before the test deadline")
          .expect("WebSocket backend should receive the ping frame");
        assert_eq!(payload, WEBSOCKET_MASKED_PING_FRAME);
        let _ = sender.send(ObservedBackendRequest {
          proxy_header,
          request,
        });
        stream
          .write_all(&WEBSOCKET_PONG_FRAME)
          .await
          .expect("WebSocket backend pong frame should write");
      });
    }
  });
  (address, receiver, task)
}

async fn start_server(raw: &str) -> JoinHandle<anyhow::Result<()>> {
  let mut config: Config = toml::from_str(raw).expect("integration configuration should parse");
  config.quic.socket.workers = 1;
  if config.cache.enabled {
    config.routes[0].cache = Some("default".into());
  }
  config
    .validate()
    .expect("integration configuration should validate");
  let snapshot = AppSnapshot::new(config)
    .await
    .expect("application snapshot should initialize");
  tokio::spawn(server::serve(
    AppHandle::new(snapshot),
    None,
    RuntimeOverrides::default(),
  ))
}

fn plaintext_proxy_config(
  certificate: &std::path::Path,
  key: &std::path::Path,
  http_addr: SocketAddr,
  https_addr: SocketAddr,
  backend_addr: SocketAddr,
  source: &str,
) -> String {
  let base = common::minimal_config_toml(certificate, key)
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      &format!("https_bind = \"{https_addr}\""),
    )
    .replace(
      "http3 = false",
      &format!("http_bind = \"{http_addr}\"\nhttp_mode = \"proxy\"\nhttp3 = false"),
    )
    .replace(
      "origin = \"https://app.internal.example\"",
      &format!("origin = \"http://{backend_addr}\""),
    )
    .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"")
    .replace(
      "webtransport = true",
      "webtransport = true\nproxy_protocol_egress = \"v2\"",
    );
  format!(
    r#"{base}

[listeners.http_proxy_protocol]
enabled = true
version = "v2"
trusted_sources = ["127.0.0.1/32"]
tls_tlvs = true

[cache]
enabled = true
store = "memory"
max_size_bytes = 1048576
default_ttl_seconds = 60

[waf]
enabled = true

[[waf.rules]]
name = "reject-trusted-proxy-tls-metadata"
phase = "request"
priority = 1
when = "Request.ProxyProtocol != null && Request.ProxyProtocol.Ssl != null && Request.ProxyProtocol.Ssl.CommonName == 'rejected.pp.example'"

[[waf.rules.actions]]
type = "reject"
status = 451

[upstreams.proxy_protocol_tls]
source = "{source}"
"#
  )
}

fn local_tls_proxy_config(
  certificate: &std::path::Path,
  key: &std::path::Path,
  https_addr: SocketAddr,
  backend_addr: SocketAddr,
) -> String {
  let base = common::minimal_config_toml(certificate, key)
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      &format!("https_bind = \"{https_addr}\""),
    )
    .replace(
      "origin = \"https://app.internal.example\"",
      &format!("origin = \"http://{backend_addr}\""),
    )
    .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"")
    .replace(
      "webtransport = true",
      "webtransport = true\nproxy_protocol_egress = \"v2\"",
    );
  format!(
    r#"{base}

[upstreams.proxy_protocol_tls]
source = "local_tls"
"#
  )
}

fn missing_received_proxy_config(
  certificate: &Path,
  key: &Path,
  http_addr: SocketAddr,
  https_addr: SocketAddr,
  backend_addr: SocketAddr,
) -> String {
  let base = common::minimal_config_toml(certificate, key)
    .replace(
      "https_bind = \"127.0.0.1:8443\"",
      &format!("https_bind = \"{https_addr}\""),
    )
    .replace(
      "http3 = false",
      &format!("http_bind = \"{http_addr}\"\nhttp_mode = \"proxy\"\nhttp3 = false"),
    )
    .replace(
      "origin = \"https://app.internal.example\"",
      &format!("origin = \"http://{backend_addr}\""),
    )
    .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"")
    .replace(
      "webtransport = true",
      "webtransport = true\nproxy_protocol_egress = \"v2\"",
    );
  format!(
    r#"{base}

[upstreams.proxy_protocol_tls]
source = "received_proxy"
"#
  )
}

fn local_mtls_proxy_config(
  certificate: &Path,
  key: &Path,
  client_ca: &Path,
  https_addr: SocketAddr,
  backend_addr: SocketAddr,
) -> String {
  let base = local_tls_proxy_config(certificate, key, https_addr, backend_addr).replace(
    "[upstreams.proxy_protocol_tls]\nsource = \"local_tls\"",
    "[upstreams.proxy_protocol_tls]\nsource = \"local_tls\"\nclient_certificate = true",
  );
  format!(
    r#"{base}

[tls.client_auth]
mode = "require"
ca_certs = ["{}"]

[listeners.proxy_protocol]
enabled = true
version = "v2"
trusted_sources = ["127.0.0.1/32"]
tls_tlvs = true

"#,
    client_ca.display(),
  )
}

fn connect_tls_proxy_config(
  certificate: &Path,
  key: &Path,
  https_addr: SocketAddr,
  backend_addr: SocketAddr,
) -> String {
  local_tls_proxy_config(certificate, key, https_addr, backend_addr).replace(
    "path_prefix = \"/\"\nupstream = \"app\"",
    "path_prefix = \"/\"\nupstream = \"app\"\nconnect_tunneling = true",
  ) + r#"

[proxy.upgrades]
connect_tunneling = true
"#
}

fn proxy_v2_ssl_header(source: SocketAddr, destination: SocketAddr, common_name: &str) -> Vec<u8> {
  let mut ssl = vec![0x01, 0, 0, 0, 0];
  append_tlv(&mut ssl, 0x21, b"TLSv1.3");
  append_tlv(&mut ssl, 0x22, common_name.as_bytes());
  let mut payload = Vec::new();
  match (source, destination) {
    (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
      payload.extend_from_slice(&source.ip().octets());
      payload.extend_from_slice(&destination.ip().octets());
      payload.extend_from_slice(&source.port().to_be_bytes());
      payload.extend_from_slice(&destination.port().to_be_bytes());
    }
    _ => panic!("test only constructs IPv4 PROXY v2 headers"),
  }
  append_tlv(&mut payload, 0x20, &ssl);
  let mut header = Vec::with_capacity(16 + payload.len());
  header.extend_from_slice(V2_SIGNATURE);
  header.extend_from_slice(&[0x21, 0x11]);
  header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
  header.extend_from_slice(&payload);
  header
}

fn append_tlv(output: &mut Vec<u8>, kind: u8, value: &[u8]) {
  output.push(kind);
  output.extend_from_slice(&(value.len() as u16).to_be_bytes());
  output.extend_from_slice(value);
}

async fn read_proxy_v2_header(stream: &mut TcpStream) -> Vec<u8> {
  let mut fixed = [0u8; 16];
  tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut fixed))
    .await
    .expect("PROXY v2 header should arrive before the test deadline")
    .expect("backend should receive a complete PROXY v2 fixed header");
  assert_eq!(
    &fixed[..12],
    V2_SIGNATURE,
    "backend must receive a v2 header first"
  );
  let payload_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
  let mut header = fixed.to_vec();
  header.resize(16 + payload_len, 0);
  tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut header[16..]))
    .await
    .expect("PROXY v2 payload should arrive before the test deadline")
    .expect("backend should receive the complete PROXY v2 payload");
  header
}

async fn read_http_headers(stream: &mut TcpStream) -> Vec<u8> {
  let mut request = Vec::new();
  let mut buffer = [0u8; 1024];
  loop {
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
      .await
      .expect("backend request headers should arrive before the test deadline")
      .expect("backend request read should succeed");
    assert!(read > 0, "backend connection closed before HTTP headers");
    request.extend_from_slice(&buffer[..read]);
    if request.windows(4).any(|window| window == b"\r\n\r\n") {
      return request;
    }
  }
}

async fn send_prefaced_http(
  address: SocketAddr,
  preface: &[u8],
  request: &[u8],
  server_task: &JoinHandle<anyhow::Result<()>>,
) -> Vec<u8> {
  let mut stream = connect_with_retry(address, server_task).await;
  stream
    .write_all(preface)
    .await
    .expect("PROXY preface should write");
  stream
    .write_all(request)
    .await
    .expect("HTTP request should write");
  read_to_end(&mut stream).await
}

async fn read_to_end<S>(stream: &mut S) -> Vec<u8>
where
  S: tokio::io::AsyncRead + Unpin,
{
  let mut response = Vec::new();
  tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
    .await
    .expect("response should finish before the test deadline")
    .expect("response should read");
  response
}

async fn read_http_header_block<S>(stream: &mut S) -> Vec<u8>
where
  S: tokio::io::AsyncRead + Unpin,
{
  let mut response = Vec::new();
  let mut buffer = [0u8; 1024];
  loop {
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
      .await
      .expect("HTTP response headers should arrive before the test deadline")
      .expect("HTTP response headers should read");
    assert!(
      read > 0,
      "connection closed before CONNECT response headers"
    );
    response.extend_from_slice(&buffer[..read]);
    if response.windows(4).any(|window| window == b"\r\n\r\n") {
      return response;
    }
  }
}

async fn connect_with_retry(
  address: SocketAddr,
  server_task: &JoinHandle<anyhow::Result<()>>,
) -> TcpStream {
  let deadline = Instant::now() + Duration::from_secs(2);
  loop {
    assert!(
      !server_task.is_finished(),
      "proxy exited before accepting connections"
    );
    match TcpStream::connect(address).await {
      Ok(stream) => return stream,
      Err(_) if Instant::now() < deadline => tokio::time::sleep(Duration::from_millis(25)).await,
      Err(error) => panic!("proxy listener did not become ready: {error}"),
    }
  }
}

async fn connect_h3_with_retry(
  endpoint: &Endpoint,
  address: SocketAddr,
  server_name: &str,
  server_task: &JoinHandle<anyhow::Result<()>>,
) -> h3_quinn::quinn::Connection {
  let deadline = Instant::now() + Duration::from_secs(2);
  loop {
    assert!(
      !server_task.is_finished(),
      "proxy exited before accepting HTTP/3 connections"
    );
    let connecting = endpoint
      .connect(address, server_name)
      .expect("HTTP/3 connection attempt should start");
    match tokio::time::timeout(Duration::from_millis(250), connecting).await {
      Ok(Ok(connection)) => return connection,
      Ok(Err(_)) | Err(_) if Instant::now() < deadline => {
        tokio::time::sleep(Duration::from_millis(25)).await;
      }
      Ok(Err(error)) => panic!("HTTP/3 listener did not become ready: {error}"),
      Err(_) => panic!("HTTP/3 listener did not become ready before the test deadline"),
    }
  }
}

async fn unused_loopback_addr() -> SocketAddr {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("ephemeral test listener should bind");
  listener
    .local_addr()
    .expect("ephemeral listener should report its address")
}

fn response_status(response: &[u8]) -> u16 {
  std::str::from_utf8(response)
    .expect("HTTP response should be ASCII")
    .lines()
    .next()
    .and_then(|line| line.split_whitespace().nth(1))
    .and_then(|status| status.parse().ok())
    .unwrap_or_else(|| {
      panic!(
        "invalid HTTP response: {}",
        String::from_utf8_lossy(response)
      )
    })
}

fn assert_http1_request_path(request: &[u8], expected_path: &str) {
  let request_line = std::str::from_utf8(request)
    .expect("backend request should be ASCII")
    .split_once("\r\n")
    .map(|(line, _)| line)
    .expect("backend request must include an HTTP request line");
  let mut parts = request_line.split_whitespace();
  assert_eq!(parts.next(), Some("GET"));
  let target = parts
    .next()
    .expect("HTTP request line must include a target");
  assert_eq!(parts.next(), Some("HTTP/1.1"));
  assert!(
    parts.next().is_none(),
    "HTTP request line must have three fields"
  );
  let uri: http::Uri = target.parse().expect("HTTP request target should parse");
  assert_eq!(uri.path(), expected_path);
}

fn assert_ssl_header(header: &[u8], common_name: &str, expected_common_name: bool) {
  assert_eq!(header[12], 0x21, "PROXY v2 command must be PROXY");
  assert_eq!(header[13], 0x11, "test expects an IPv4 TCP header");
  assert!(header.len() > 31, "header must include the SSL TLV");
  assert_eq!(header[28], 0x20, "first v2 extension must be PP2_TYPE_SSL");
  let ssl_len = u16::from_be_bytes([header[29], header[30]]) as usize;
  assert_eq!(
    31 + ssl_len,
    header.len(),
    "SSL TLV must occupy the full v2 extension payload"
  );
  assert_ne!(
    header[31] & 0x01,
    0,
    "SSL assertion must set PP2_CLIENT_SSL"
  );
  if expected_common_name {
    let expected = common_name.as_bytes();
    assert!(
      header
        .windows(expected.len() + 3)
        .any(|window| window[0] == 0x22
          && window[1..3] == (expected.len() as u16).to_be_bytes()
          && &window[3..] == expected),
      "relayed SSL TLV must retain its selected common name"
    );
  } else {
    assert!(
      ssl_len > 5,
      "local TLS egress must include negotiated TLS detail TLVs"
    );
  }
}

fn ssl_nested_tlv(header: &[u8], kind: u8) -> Option<&[u8]> {
  let ssl_length = u16::from_be_bytes([header[29], header[30]]) as usize;
  let ssl = header.get(31..31 + ssl_length)?;
  let mut offset = 5;
  while offset < ssl.len() {
    let tlv_kind = *ssl.get(offset)?;
    let length = u16::from_be_bytes([*ssl.get(offset + 1)?, *ssl.get(offset + 2)?]) as usize;
    offset = offset.checked_add(3)?;
    let end = offset.checked_add(length)?;
    let value = ssl.get(offset..end)?;
    if tlv_kind == kind {
      return Some(value);
    }
    offset = end;
  }
  None
}

fn first_certificate_der(path: &Path) -> Vec<u8> {
  CertificateDer::pem_slice_iter(&std::fs::read(path).expect("certificate should read"))
    .next()
    .expect("certificate PEM should contain a certificate")
    .expect("certificate PEM should parse")
    .as_ref()
    .to_vec()
}

fn mtls_client_config(
  server_ca: &Path,
  client_certificate: &Path,
  client_key: &Path,
) -> rustls::ClientConfig {
  let mut roots = rustls::RootCertStore::empty();
  let ca_certificates =
    CertificateDer::pem_slice_iter(&std::fs::read(server_ca).expect("CA certificate should read"))
      .collect::<Result<Vec<_>, _>>()
      .expect("CA certificate should parse");
  assert!(
    roots.add_parsable_certificates(ca_certificates).0 > 0,
    "test CA should be accepted"
  );
  let certificates = CertificateDer::pem_slice_iter(
    &std::fs::read(client_certificate).expect("client certificate should read"),
  )
  .collect::<Result<Vec<_>, _>>()
  .expect("client certificate should parse");
  let key = PrivateKeyDer::from_pem_slice(
    &std::fs::read(client_key).expect("client private key should read"),
  )
  .expect("client private key should parse");
  rustls::ClientConfig::builder_with_provider(Arc::new(
    rustls::crypto::aws_lc_rs::default_provider(),
  ))
  .with_safe_default_protocol_versions()
  .expect("mTLS client protocol configuration should build")
  .with_root_certificates(roots)
  .with_client_auth_cert(certificates, key)
  .expect("mTLS client configuration should build")
}
