use super::*;
use std::task::Poll;
use std::time::Duration;

use crate::config::{Config, UpstreamEchConfig};
use crate::tls;
use h3::quic::RecvStream as _;
use h3_quinn::quinn::{Connection as QuinnConnection, Endpoint, VarInt};

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

struct LoopbackQuinn {
  _server_endpoint: Endpoint,
  _client_endpoint: Endpoint,
  server: QuinnConnection,
  client: QuinnConnection,
}

async fn loopback_quinn() -> LoopbackQuinn {
  let temp_dir = common::TempDir::new("quic-h3-recv-stream");
  let (ca_certificate, ca_key) = common::create_self_signed_cert(temp_dir.path(), "h3-loopback-ca");
  let (certificate, private_key) =
    common::create_ca_signed_server_cert(temp_dir.path(), "h3-loopback", &ca_certificate, &ca_key);
  let config: Config = toml::from_str(&common::minimal_config_toml(&certificate, &private_key))
    .expect("QUIC loopback configuration should parse");
  let server_config = tls::build_quic_server_config(&config.tls, &config.quic, None)
    .expect("QUIC loopback server configuration should build");
  let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
    .expect("QUIC loopback server endpoint should bind");
  let server_address = server_endpoint
    .local_addr()
    .expect("QUIC loopback server address should resolve");
  let client_config = tls::build_upstream_quic_client_config(
    std::slice::from_ref(&ca_certificate),
    &UpstreamEchConfig::default(),
    &config.quic,
  )
  .expect("QUIC loopback client configuration should build");
  let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap())
    .expect("QUIC loopback client endpoint should bind");
  client_endpoint.set_default_client_config(client_config);

  let (client, server) = tokio::time::timeout(Duration::from_secs(5), async {
    tokio::join!(
      async {
        client_endpoint
          .connect(server_address, "h3-loopback")
          .expect("QUIC loopback client should start its handshake")
          .await
      },
      async {
        server_endpoint
          .accept()
          .await
          .expect("QUIC loopback server should accept a connection")
          .await
      }
    )
  })
  .await
  .expect("QUIC loopback handshake should complete");

  LoopbackQuinn {
    _server_endpoint: server_endpoint,
    _client_endpoint: client_endpoint,
    server: server.expect("QUIC loopback server handshake should succeed"),
    client: client.expect("QUIC loopback client handshake should succeed"),
  }
}

async fn next_data(stream: &mut RecvStream) -> Result<Option<Bytes>, StreamErrorIncoming> {
  tokio::time::timeout(
    Duration::from_secs(5),
    std::future::poll_fn(|cx| stream.poll_data(cx)),
  )
  .await
  .expect("HTTP/3 receive stream should become readable")
}

async fn assert_pending(stream: &mut RecvStream) {
  let poll = std::future::poll_fn(|cx| Poll::Ready(stream.poll_data(cx))).await;
  assert!(poll.is_pending(), "HTTP/3 receive stream should be pending");
}

async fn pending_read_stop_preserves_code_after_drop_and_sibling_is_usable_inner() {
  const STOP_CODE: u64 = 0x4a;
  let pair = loopback_quinn().await;

  let (mut client_send, _) = pair
    .client
    .open_bi()
    .await
    .expect("client should open the stopped stream");
  client_send
    .write_all(b"trigger")
    .await
    .expect("client should make the stopped stream visible");
  let (_, server_recv) = pair
    .server
    .accept_bi()
    .await
    .expect("server should accept the stopped stream");
  let mut server_recv = RecvStream::new(server_recv);
  assert_eq!(
    next_data(&mut server_recv)
      .await
      .expect("trigger should arrive"),
    Some(Bytes::from_static(b"trigger"))
  );
  assert_pending(&mut server_recv).await;

  server_recv.stop_sending(STOP_CODE);
  let stopped = tokio::time::timeout(Duration::from_secs(5), client_send.stopped())
    .await
    .expect("client should observe STOP_SENDING")
    .expect("client connection should remain open");
  assert_eq!(stopped, Some(VarInt::from_u64(STOP_CODE).unwrap()));
  drop(server_recv);

  let (mut sibling_send, _) = pair
    .client
    .open_bi()
    .await
    .expect("client should open a sibling stream");
  sibling_send
    .write_all(b"sibling")
    .await
    .expect("client should write the sibling stream");
  sibling_send
    .finish()
    .expect("client should finish the sibling stream");
  let (_, sibling_recv) = pair
    .server
    .accept_bi()
    .await
    .expect("server should accept the sibling stream");
  let mut sibling_recv = RecvStream::new(sibling_recv);
  assert_eq!(
    next_data(&mut sibling_recv)
      .await
      .expect("sibling bytes should arrive"),
    Some(Bytes::from_static(b"sibling"))
  );
  assert_eq!(
    next_data(&mut sibling_recv)
      .await
      .expect("sibling FIN should arrive"),
    None
  );
}

#[tokio::test]
async fn pending_read_stop_preserves_code_after_drop_and_sibling_is_usable() {
  tokio::time::timeout(
    Duration::from_secs(15),
    pending_read_stop_preserves_code_after_drop_and_sibling_is_usable_inner(),
  )
  .await
  .expect("pending STOP_SENDING regression test should complete");
}

async fn pending_read_resumes_ordered_bytes_fin_and_peer_reset_inner() {
  const RESET_CODE: u64 = 0x57;
  let pair = loopback_quinn().await;

  let (mut client_send, _) = pair
    .client
    .open_bi()
    .await
    .expect("client should open the ordered stream");
  client_send
    .write_all(b"ordered ")
    .await
    .expect("client should make the ordered stream visible");
  let (_, server_recv) = pair
    .server
    .accept_bi()
    .await
    .expect("server should accept the ordered stream");
  let mut server_recv = RecvStream::new(server_recv);
  assert_eq!(
    next_data(&mut server_recv)
      .await
      .expect("ordered prefix should arrive"),
    Some(Bytes::from_static(b"ordered "))
  );
  assert_pending(&mut server_recv).await;
  let mut resumed_read = Box::pin(std::future::poll_fn(|cx| server_recv.poll_data(cx)));
  assert!(
    futures_util::poll!(resumed_read.as_mut()).is_pending(),
    "resumed read should wait for the suffix"
  );
  client_send
    .write_all(b"bytes")
    .await
    .expect("client should resume the ordered stream");
  client_send
    .finish()
    .expect("client should finish the ordered stream");
  assert_eq!(
    tokio::time::timeout(Duration::from_secs(5), resumed_read)
      .await
      .expect("ordered suffix should wake the pending read")
      .expect("ordered suffix should arrive"),
    Some(Bytes::from_static(b"bytes"))
  );
  assert_eq!(
    next_data(&mut server_recv)
      .await
      .expect("ordered FIN should arrive"),
    None
  );

  let (mut reset_send, _) = pair
    .client
    .open_bi()
    .await
    .expect("client should open the reset stream");
  reset_send
    .write_all(b"trigger")
    .await
    .expect("client should make the reset stream visible");
  let (_, reset_recv) = pair
    .server
    .accept_bi()
    .await
    .expect("server should accept the reset stream");
  let mut reset_recv = RecvStream::new(reset_recv);
  assert_eq!(
    next_data(&mut reset_recv)
      .await
      .expect("reset trigger should arrive"),
    Some(Bytes::from_static(b"trigger"))
  );
  assert_pending(&mut reset_recv).await;
  let mut reset_read = Box::pin(std::future::poll_fn(|cx| reset_recv.poll_data(cx)));
  assert!(
    futures_util::poll!(reset_read.as_mut()).is_pending(),
    "reset read should wait for the peer reset"
  );
  reset_send
    .reset(VarInt::from_u64(RESET_CODE).unwrap())
    .expect("client should reset the stream");
  assert!(matches!(
    tokio::time::timeout(Duration::from_secs(5), reset_read)
      .await
      .expect("peer reset should wake the pending read"),
    Err(StreamErrorIncoming::StreamTerminated { error_code }) if error_code == RESET_CODE
  ));
}

#[tokio::test]
async fn pending_read_resumes_ordered_bytes_fin_and_peer_reset() {
  tokio::time::timeout(
    Duration::from_secs(15),
    pending_read_resumes_ordered_bytes_fin_and_peer_reset_inner(),
  )
  .await
  .expect("pending read resume and reset regression test should complete");
}

#[test]
fn early_data_tracker_only_records_early_streams_once() {
  let tracker = EarlyDataTracker::default();
  let stream_id = StreamId::try_from(0).unwrap();

  tracker.note(stream_id, false);
  assert!(!tracker.has_early_streams());
  assert!(!tracker.take(stream_id));

  tracker.note(stream_id, true);
  assert!(tracker.has_early_streams());
  assert!(tracker.take(stream_id));
  assert!(!tracker.has_early_streams());
  assert!(!tracker.take(stream_id));
}
