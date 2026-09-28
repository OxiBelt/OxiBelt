mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

use super::*;

async fn test_state(websocket_enabled: bool) -> (Arc<AppSnapshot>, common::TempDir) {
  let temp_dir = common::TempDir::new("extended-websocket-framing");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "extended-websocket-framing");
  let raw = format!(
    "{}\n[proxy.upgrades]\nwebsocket = {websocket_enabled}\n\n[quic.socket]\nreuse_port = true\n",
    common::minimal_config_toml(&cert_path, &key_path).replace("http3 = false", "http3 = true")
  );
  let config: crate::config::Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("config should validate");
  let state = AppSnapshot::new(config)
    .await
    .expect("snapshot should initialize");
  (Arc::new(state), temp_dir)
}

async fn pending_extended_connect_status(
  state: Arc<AppSnapshot>,
  version: http::Version,
  framing: Option<(http::header::HeaderName, &'static str)>,
) -> StatusCode {
  let (sender, pending_body) = body::channel_body(1);
  let mut builder = Request::builder()
    .method(Method::CONNECT)
    .version(version)
    .uri("https://example.com/ws")
    .header(http::header::HOST, "example.com")
    .header("sec-websocket-version", "13");
  if let Some((name, value)) = framing {
    builder = builder.header(name, value);
  }
  let mut request = builder.body(pending_body).expect("request should build");
  match version {
    http::Version::HTTP_2 => {
      request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    }
    http::Version::HTTP_3 => {
      request
        .extensions_mut()
        .insert(h3::ext::Protocol::WEBSOCKET);
    }
    _ => panic!("test requires HTTP/2 or HTTP/3"),
  }
  let tls = Arc::new(WafTlsMetadata {
    enabled: true,
    version: Some("TLSv1_3".to_owned()),
    sni: Some("example.com".to_owned()),
    ..WafTlsMetadata::default()
  });
  let response = tokio::time::timeout(
    Duration::from_secs(1),
    entry::handle_inner(
      request,
      "203.0.113.10:49152".parse().unwrap(),
      None,
      WafTransportMetadataInput::default(),
      tls,
      None,
      None,
      state,
      WafProtocol::Websocket,
      if version == http::Version::HTTP_3 {
        WafTransportNetwork::Udp
      } else {
        WafTransportNetwork::Tcp
      },
      version != http::Version::HTTP_3,
      "https",
      test_drain(),
    ),
  )
  .await
  .expect("framing decision should not wait for body completion");
  drop(sender);
  response.status()
}

fn test_drain() -> ConnectionDrain {
  let (_listener_tx, listener_rx) = tokio::sync::watch::channel(false);
  let (_lifecycle_tx, lifecycle_rx) = tokio::sync::watch::channel(false);
  ConnectionDrain::new(listener_rx, lifecycle_rx, Duration::ZERO)
}

#[tokio::test]
async fn framed_extended_connect_is_rejected_without_reading_pending_body() {
  for websocket_enabled in [true, false] {
    let (state, _temp_dir) = test_state(websocket_enabled).await;
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
      for (framing, expected_status) in [
        ((http::header::CONTENT_LENGTH, "0"), StatusCode::BAD_REQUEST),
        ((http::header::CONTENT_LENGTH, "1"), StatusCode::BAD_REQUEST),
        (
          (http::header::CONTENT_LENGTH, "18446744073709551615"),
          StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
          (http::header::TRANSFER_ENCODING, "chunked"),
          StatusCode::BAD_REQUEST,
        ),
      ] {
        assert_eq!(
          pending_extended_connect_status(state.clone(), version, Some(framing.clone())).await,
          expected_status,
          "{version:?} framing={framing:?} websocket_enabled={websocket_enabled}"
        );
      }
    }
  }
}

#[tokio::test]
async fn unframed_extended_connect_reaches_disabled_websocket_gate() {
  let (state, _temp_dir) = test_state(false).await;
  for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
    assert_eq!(
      pending_extended_connect_status(state.clone(), version, None).await,
      StatusCode::METHOD_NOT_ALLOWED,
      "{version:?}"
    );
  }
}
