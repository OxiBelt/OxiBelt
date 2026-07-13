use std::time::{Duration, Instant};

use super::*;
use crate::config::{Config, UpstreamEchConfig};
use crate::tls;
use tokio::sync::watch;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn parse_test_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

#[tokio::test]
async fn quiesced_http3_listener_discards_new_handshakes_until_shutdown() {
  let temp_dir = common::TempDir::new("quiesced-http3-listener");
  let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), "quic-predrain");
  let config = parse_test_config(&common::minimal_config_toml(&cert_path, &key_path));
  let tls_config = config.tls.clone();
  let quic_config = config.quic.clone();
  let state = AppHandle::new(
    AppSnapshot::new(config)
      .await
      .expect("snapshot should initialize"),
  );
  let server_config = tls::build_quic_server_config(&tls_config, &quic_config, None)
    .expect("QUIC server config should initialize");
  let endpoint = crate::quic::bind_server_endpoint(
    "127.0.0.1:0".parse().unwrap(),
    server_config,
    &quic_config,
    None,
  )
  .expect("QUIC endpoint should bind");
  let endpoint_stats = endpoint.clone();
  let server_addr = endpoint
    .local_addr()
    .expect("QUIC endpoint should expose its listener address");
  let (_quiesce_tx, quiesce_rx) = watch::channel(true);
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let listener_task = tokio::spawn(serve_http3(
    endpoint,
    state,
    quiesce_rx,
    shutdown_rx,
    0,
    TaskRegistry::default(),
    Duration::from_secs(1),
  ));

  let client_config = tls::build_upstream_quic_client_config(
    std::slice::from_ref(&cert_path),
    &UpstreamEchConfig::default(),
    &quic_config,
  )
  .expect("QUIC client config should initialize");
  let mut client_endpoint = h3_quinn::quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
    .expect("QUIC client endpoint should bind");
  client_endpoint.set_default_client_config(client_config);
  let connecting = client_endpoint
    .connect(server_addr, "quic-predrain")
    .expect("QUIC client should start its handshake");
  let client_task = tokio::spawn(async move {
    let _ = connecting.await;
  });

  let deadline = Instant::now() + Duration::from_secs(2);
  while endpoint_stats.stats().ignored_handshakes == 0 {
    assert!(
      Instant::now() < deadline,
      "quiesced HTTP/3 listener should consume and ignore the new handshake"
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert!(
    !listener_task.is_finished(),
    "pre-drain must keep consuming handshakes until final shutdown"
  );

  shutdown_tx.send(true).unwrap();
  tokio::time::timeout(Duration::from_secs(2), listener_task)
    .await
    .expect("quiesced HTTP/3 listener should stop after final shutdown")
    .expect("quiesced HTTP/3 listener task should not panic")
    .expect("quiesced HTTP/3 listener should exit cleanly");
  client_endpoint.close(0u32.into(), b"test complete");
  client_task.abort();
}
