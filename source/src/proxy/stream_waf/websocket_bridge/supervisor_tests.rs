use std::sync::Arc;

use fastwebsockets::{Role, after_handshake_split};
use tokio::io::{AsyncWriteExt, duplex};
use tokio::sync::{Mutex, Notify};

use super::*;

#[tokio::test]
async fn rejects_oversized_pong_instead_of_forwarding_it_unlimited() {
  let (mut peer, bridge) = duplex(512);
  let (bridge_read, bridge_write) = tokio::io::split(bridge);
  let (reader, _writer) = after_handshake_split(bridge_read, bridge_write, Role::Server);
  let mut reader = WebSocketFrameReader::spawn(reader);
  let mask = [1, 2, 3, 4];
  let mut encoded = vec![0x8a, 0xfe, 0, 126];
  encoded.extend_from_slice(&mask);
  encoded.extend((0..126).map(|index| mask[index % mask.len()]));
  peer.write_all(&encoded).await.unwrap();

  let error = match reader.next(MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES).await {
    Ok(_) => panic!("oversized Pong bypassed bandwidth shaping"),
    Err(error) => error,
  };
  assert!(error.to_string().contains("Frame too large"));
}

#[tokio::test]
async fn reciprocal_close_leaves_the_other_pump_running_until_it_finishes() {
  let downstream = test_writer(Role::Server);
  let upstream = test_writer(Role::Client);
  let release = Arc::new(Notify::new());
  let task_release = release.clone();
  let mut other = tokio::spawn(async move {
    task_release.notified().await;
    Err(PumpError::PeerClosed)
  });

  let finishing = finish_pump(
    Ok(Err(PumpError::PeerClosed)),
    &mut other,
    &downstream,
    &upstream,
  );
  tokio::pin!(finishing);
  assert!(futures_util::poll!(finishing.as_mut()).is_pending());
  release.notify_one();
  assert!(finishing.await.is_ok());
}

fn test_writer(role: Role) -> SharedWebSocketWriter<tokio::io::WriteHalf<tokio::io::DuplexStream>> {
  let (bridge, _peer) = duplex(64);
  let (read, write) = tokio::io::split(bridge);
  let (_reader, writer) = after_handshake_split(read, write, role);
  Arc::new(Mutex::new(writer))
}
