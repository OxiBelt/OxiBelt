use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio::net::TcpListener;

use super::*;
use crate::config::Config;
use crate::lifecycle::ConnectionDrain;
use crate::waf::{WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn certificate(path: &std::path::Path) -> ForwardedClientCertificate {
  let contents = std::fs::read(path).unwrap();
  let chain = CertificateDer::pem_slice_iter(&contents)
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  crate::tls::capture_forwarded_client_certificate(&chain).unwrap()
}

async fn send(
  state: Arc<AppSnapshot>,
  certificate: Option<ForwardedClientCertificate>,
  path: &str,
) -> (http::HeaderMap, serde_json::Value) {
  let mut request = Request::builder()
    .uri(format!("https://example.com{path}"))
    .header("host", "example.com")
    .header("accept-encoding", "gzip")
    .header("x-client-cert", "spoof-one")
    .header("X-Client-Cert", "spoof-two")
    .header("client-cert", "spoof-standard")
    .header("client-cert-chain", "spoof-chain")
    .body(
      Full::new(Bytes::new()).map_err(|never| -> super::super::body::BoxError { match never {} }),
    )
    .unwrap();
  if let Some(certificate) = certificate {
    request.extensions_mut().insert(certificate);
  }
  let (_shutdown, rx) = tokio::sync::watch::channel(false);
  let drain = ConnectionDrain::new(rx.clone(), rx, Duration::ZERO);
  let response = super::super::entry::handle_inner(
    request,
    "127.0.0.1:12345".parse().unwrap(),
    None,
    WafTransportMetadataInput::default(),
    Arc::new(WafTlsMetadata {
      enabled: true,
      sni: Some("example.com".into()),
      ..Default::default()
    }),
    None,
    None,
    state,
    WafProtocol::Http,
    WafTransportNetwork::Tcp,
    false,
    "https",
    drain,
  )
  .await;
  assert_eq!(response.status(), StatusCode::OK);
  let (parts, body) = response.into_parts();
  let bytes = body.collect().await.unwrap().to_bytes();
  (parts.headers, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn client_certificate_cache_separates_verified_absent_and_disabled_routes() {
  let temporary = common::TempDir::new("certificate-forwarding-proxy");
  let (cert_a, key_a) = common::create_self_signed_cert(temporary.path(), "client-a");
  let (cert_b, _) = common::create_self_signed_cert(temporary.path(), "client-b");
  let client_a = certificate(&cert_a);
  let client_b = certificate(&cert_b);
  let mirror_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let mirror_address = mirror_listener.local_addr().unwrap();
  let (mirror_sender, mut mirrored) = tokio::sync::mpsc::unbounded_channel();
  let mirror_server = tokio::spawn(async move {
    loop {
      let (stream, _) = mirror_listener.accept().await.unwrap();
      let sender = mirror_sender.clone();
      tokio::spawn(async move {
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
          let sender = sender.clone();
          async move {
            let protected = ["x-client-cert", "client-cert", "client-cert-chain"]
              .iter()
              .any(|name| request.headers().contains_key(*name));
            sender.send(protected).unwrap();
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
          }
        });
        let _ = hyper::server::conn::http1::Builder::new()
          .serve_connection(TokioIo::new(stream), service)
          .await;
      });
    }
  });
  let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let calls = Arc::new(AtomicUsize::new(0));
  let calls_for_server = calls.clone();
  let server = tokio::spawn(async move {
    loop {
      let (stream, _) = listener.accept().await.unwrap();
      let calls = calls_for_server.clone();
      tokio::spawn(async move {
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
          let calls = calls.clone();
          async move {
            if request.uri().path() == "/authorize" {
              for name in ["x-client-cert", "client-cert", "client-cert-chain"] {
                assert!(
                  !request.headers().contains_key(name),
                  "certificate leaked to external authorization"
                );
              }
              return Ok::<_, Infallible>(
                Response::builder()
                  .status(StatusCode::NO_CONTENT)
                  .body(Full::new(Bytes::new()))
                  .unwrap(),
              );
            }
            calls.fetch_add(1, Ordering::SeqCst);
            let certificate = request
              .headers()
              .get("x-client-cert")
              .map(|value| value.to_str().unwrap());
            let payload = serde_json::json!({
              "certificate": certificate,
              "certificate_count": request.headers().get_all("x-client-cert").iter().count(),
              "standard": request.headers().contains_key("client-cert"),
              "chain": request.headers().contains_key("client-cert-chain"),
              "accept_encoding": request.headers().get("accept-encoding").map(|value| value.to_str().unwrap()),
            });
            Ok::<_, Infallible>(
              Response::builder()
                .header("content-type", "application/json")
                .header("cache-control", "public, max-age=60")
                .header("vary", "x-client-cert")
                .body(Full::new(Bytes::from(payload.to_string())))
                .unwrap(),
            )
          }
        });
        let _ = hyper::server::conn::http1::Builder::new()
          .serve_connection(TokioIo::new(stream), service)
          .await;
      });
    }
  });
  let raw = format!(
    "{}\n[routes.client_certificate_forwarding]\nheader = \"x-client-cert\"\nformat = \"rfc9440\"\n\n[cache]\nenabled = true\nstore = \"memory\"\nmax_size_bytes = 1048576\ndefault_ttl_seconds = 60\n",
    common::minimal_config_toml(&cert_a, &key_a)
      .replace("https://app.internal.example", &format!("http://{address}"))
      .replace("max_http_version = \"h2\"", "max_http_version = \"h1\"")
  );
  let mut config: Config = toml::from_str(&raw).unwrap();
  config.routes[0].cache = Some("default".into());
  config.routes[0].external_auth = Some("auth".into());
  config.upstream_pools.push(
    toml::from_str(&format!(
      "name = 'mirror'\n[[servers]]\nid = 'mirror-server'\norigin = 'http://{mirror_address}'\n"
    ))
    .unwrap(),
  );
  config.routes[0]
    .actions
    .request_mirrors
    .push(toml::from_str("upstream_pool = 'mirror'").unwrap());
  config.external_auth.push(
    toml::from_str(&format!(
      "name = 'auth'\nendpoint = 'http://{address}/authorize'\n"
    ))
    .unwrap(),
  );
  let mut disabled = config.routes[0].clone();
  disabled.name = "unselected".into();
  disabled.path_prefix = "/disabled".into();
  disabled.client_certificate_forwarding = None;
  config.routes.insert(0, disabled);
  config.validate().unwrap();
  let state = Arc::new(AppSnapshot::new(config).await.unwrap());

  for client in [Some(client_a.clone()), Some(client_b), None] {
    let expected = client.as_ref().map(|cert| {
      cert
        .encode(ClientCertificateForwardingFormat::Rfc9440)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
    });
    for _ in 0..2 {
      let (headers, payload) = send(state.clone(), client.clone(), "/cached").await;
      assert_eq!(headers[CACHE_CONTROL], "no-store");
      assert_eq!(headers[VARY], "*");
      assert_eq!(
        payload["certificate"],
        serde_json::to_value(&expected).unwrap()
      );
      assert_eq!(payload["standard"], false);
      assert_eq!(payload["chain"], false);
      assert_eq!(payload["certificate_count"], usize::from(client.is_some()));
      if client.is_some() {
        assert!(!headers.contains_key("content-encoding"));
        assert_eq!(payload["accept_encoding"], serde_json::Value::Null);
      }
    }
  }
  assert_eq!(
    calls.load(Ordering::SeqCst),
    3,
    "each verified/absent identity should fill once"
  );
  let (_, payload) = send(state, Some(client_a), "/disabled").await;
  assert_eq!(payload["certificate"], serde_json::Value::Null);
  assert_eq!(payload["standard"], false);
  assert_eq!(payload["chain"], false);
  for _ in 0..7 {
    assert!(
      !tokio::time::timeout(Duration::from_secs(5), mirrored.recv())
        .await
        .unwrap()
        .unwrap(),
      "certificate header leaked to request mirror"
    );
  }
  server.abort();
  mirror_server.abort();
}

#[test]
fn client_certificate_failure_does_not_become_anonymous() {
  assert_eq!(
    capture_error_status(ForwardedClientCertificateCaptureError::Encoding),
    StatusCode::INTERNAL_SERVER_ERROR
  );
  let mut request = Request::new(());
  request.extensions_mut().insert(
    crate::tls::capture_forwarded_client_certificate(&[CertificateDer::from(vec![0u8; 65537])])
      .unwrap(),
  );
  let route: RouteConfig = toml::from_str("name = 'forward'\nupstream = 'app'\n[client_certificate_forwarding]\nheader = 'x-client-cert'\n").unwrap();
  assert!(matches!(
    PreparedCertificateForwarding::prepare(&request, &route),
    Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
  ));
}

#[test]
fn client_certificate_encoded_and_aggregate_limits_fail_closed() {
  let mut request = Request::new(());
  request.extensions_mut().insert(
    crate::tls::capture_forwarded_client_certificate(&[CertificateDer::from(vec![1u8; 64])])
      .unwrap(),
  );
  let route: RouteConfig = toml::from_str("name = 'forward'\nupstream = 'app'\n[client_certificate_forwarding]\nheader = 'x-client-cert'\n").unwrap();
  let prepared = PreparedCertificateForwarding::prepare(&request, &route)
    .unwrap()
    .unwrap();
  let mut limits = LimitsConfig {
    max_header_value_bytes: 10,
    ..LimitsConfig::default()
  };
  assert_eq!(
    prepared.apply(&mut HeaderMap::new(), &limits),
    Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
  );
  limits.max_header_value_bytes = 8192;
  limits.max_total_header_bytes = 10;
  assert_eq!(
    prepared.apply(&mut HeaderMap::new(), &limits),
    Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
  );
  limits.max_total_header_bytes = 32768;
  limits.max_headers = 1;
  let mut headers = HeaderMap::new();
  headers.insert("x-benign", HeaderValue::from_static("kept"));
  assert_eq!(
    prepared.apply(&mut headers, &limits),
    Err(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
  );
}

#[tokio::test]
async fn client_certificate_reserved_headers_mutations_trailers_and_delivery() {
  let temporary = common::TempDir::new("certificate-forwarding-boundaries");
  let (cert, key) = common::create_self_signed_cert(temporary.path(), "client");
  let mut config: Config = toml::from_str(&common::minimal_config_toml(&cert, &key)).unwrap();
  config.routes[0].client_certificate_forwarding =
    Some(crate::config::ClientCertificateForwardingConfig {
      header: "x-client-cert".into(),
      format: ClientCertificateForwardingFormat::Rfc9440,
    });
  let state = AppSnapshot::new(config).await.unwrap();
  let mut request = Request::new(());
  request.extensions_mut().insert(certificate(&cert));
  let prepared = PreparedCertificateForwarding::prepare(&request, &state.config.routes[0])
    .unwrap()
    .unwrap();
  let expected = prepared.value.clone().unwrap();
  request.extensions_mut().insert(prepared);
  // Simulate mutations after ingress sanitization. Only the verified projection wins.
  for name in ["x-client-cert", "client-cert", "client-cert-chain"] {
    request
      .headers_mut()
      .append(name, HeaderValue::from_static("forged"));
  }
  apply_upstream(&mut request, &state).unwrap();
  assert_eq!(request.headers()["x-client-cert"], expected);
  assert!(request.headers()["x-client-cert"].is_sensitive());
  assert!(!request.headers().contains_key("client-cert"));
  assert!(!request.headers().contains_key("client-cert-chain"));

  let (sender, body) = super::super::body::channel_body(2);
  let mut trailers = HeaderMap::new();
  for name in [
    "x-client-cert",
    "client-cert",
    "client-cert-chain",
    "x-checksum",
  ] {
    trailers.insert(name, HeaderValue::from_static("trailer-value"));
  }
  sender
    .send(Ok(hyper::body::Frame::trailers(trailers)))
    .await
    .unwrap();
  drop(sender);
  let body = super::super::semantics::sanitize_upstream_request_trailers(
    body,
    state.client_certificate_forwarding_headers.to_vec(),
  );
  let collected = body.collect().await.unwrap();
  let trailers = collected.trailers().unwrap();
  assert_eq!(trailers.len(), 1);
  assert_eq!(trailers["x-checksum"], "trailer-value");

  for status in [
    StatusCode::OK,
    StatusCode::NOT_MODIFIED,
    StatusCode::FORBIDDEN,
    StatusCode::BAD_GATEWAY,
    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
  ] {
    let mut response = Response::builder()
      .status(status)
      .header(CACHE_CONTROL, "public, max-age=60")
      .header(VARY, "Accept-Language, X-Client-Cert")
      .body(())
      .unwrap();
    finalize_response(&mut response, true, &state);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[VARY], "*");
  }
  let mut response = Response::builder()
    .header(CACHE_CONTROL, "public")
    .body(())
    .unwrap();
  finalize_response(&mut response, false, &state);
  assert_eq!(response.headers()[CACHE_CONTROL], "public");
}
