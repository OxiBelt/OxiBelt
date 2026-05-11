use fastwebsockets::{Frame, Payload, Role, WebSocketError, after_handshake_split};
use tokio::io::duplex;

use super::*;

#[test]
fn websocket_frame_limit_tracks_waf_prefix_without_large_floor() {
  assert_eq!(websocket_max_frame_size(1024), 1025);
  assert!(websocket_max_frame_size(1024) < 16 * 1024 * 1024);
}

#[tokio::test]
async fn websocket_reader_accepts_payload_at_waf_prefix() {
  let payload = vec![b'a'; 1024];
  let frame = read_client_payload_with_limit(1024, &payload)
    .await
    .expect("payload at the WAF prefix limit should be accepted");

  assert_eq!(frame.opcode, fastwebsockets::OpCode::Binary);
  assert_eq!(frame.payload, payload);
}

#[tokio::test]
async fn websocket_reader_rejects_payload_above_waf_prefix() {
  let payload = vec![b'a'; 1025];
  let error = match read_client_payload_with_limit(1024, &payload).await {
    Ok(_) => panic!("payload above the WAF prefix limit should be rejected"),
    Err(error) => error,
  };

  assert!(
    matches!(error, WebSocketError::FrameTooLarge),
    "expected frame-size rejection, got {error:?}"
  );
}

async fn read_client_payload_with_limit(
  limit: usize,
  payload: &[u8],
) -> Result<OwnedWebSocketFrame, WebSocketError> {
  let (client, server) = duplex(limit + payload.len() + 128);
  let (client_read, client_write) = tokio::io::split(client);
  let (_client_reader, mut client_writer) =
    after_handshake_split(client_read, client_write, Role::Client);
  let (server_read, server_write) = tokio::io::split(server);
  let (mut server_reader, _server_writer) =
    after_handshake_split(server_read, server_write, Role::Server);
  configure_reader(&mut server_reader, limit);

  client_writer
    .write_frame(Frame::binary(Payload::Borrowed(payload)))
    .await?;
  client_writer.flush().await?;

  read_owned_frame(&mut server_reader).await
}
