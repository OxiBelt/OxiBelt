use std::num::NonZeroU64;

use fastwebsockets::{Frame, OpCode, Payload, Role, after_handshake_split};
use tokio::io::{AsyncWriteExt, duplex};

use super::*;
use crate::bandwidth::{BandwidthPolicy, BandwidthRate};
use crate::proxy::stream_waf::read_owned_frame;

type TestPump = WebSocketDirectionPump<tokio::io::WriteHalf<tokio::io::DuplexStream>>;

#[tokio::test(start_paused = true)]
async fn shaped_data_is_progressive_and_control_frames_overtake_a_wait() {
  let (source_peer, source_bridge) = duplex(4096);
  let (source_peer_read, source_peer_write) = tokio::io::split(source_peer);
  let (_source_peer_reader, mut source_peer_writer) =
    after_handshake_split(source_peer_read, source_peer_write, Role::Client);
  let (source_bridge_read, source_bridge_write) = tokio::io::split(source_bridge);
  let (mut source_bridge_reader, _source_bridge_writer) =
    after_handshake_split(source_bridge_read, source_bridge_write, Role::Server);
  configure_reader_controls(&mut source_bridge_reader);

  let (destination_bridge, destination_peer) = duplex(4096);
  let (destination_bridge_read, destination_bridge_write) = tokio::io::split(destination_bridge);
  let (_destination_bridge_reader, destination_bridge_writer) = after_handshake_split(
    destination_bridge_read,
    destination_bridge_write,
    Role::Client,
  );
  let (destination_peer_read, destination_peer_write) = tokio::io::split(destination_peer);
  let (mut destination_peer_reader, _destination_peer_writer) =
    after_handshake_split(destination_peer_read, destination_peer_write, Role::Server);
  configure_reader_controls(&mut destination_peer_reader);

  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(1).unwrap());
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(rate, BandwidthRate::Unlimited));
  let (activity_tx, mut activity_rx) = mpsc::channel(16);
  let pump = tokio::spawn(
    WebSocketDirectionPump {
      reader: WebSocketFrameReader::spawn(source_bridge_reader),
      writer: Arc::new(Mutex::new(destination_bridge_writer)),
      state: None,
      context: None,
      messages: WebSocketMessageState::new(0),
      direction: WafStreamDirection::DownstreamToUpstream,
      flow: Some(limiter.flow(BandwidthDirection::Upload)),
      metrics: Metrics::new(),
      activity: activity_tx,
      deferred_data: None,
      priority_data: None,
      pending_waf_upload: None,
      read_error_context: "test source read failed",
      write_error_context: "test destination write failed",
    }
    .run(),
  );

  source_peer_writer
    .write_frame(Frame::binary(Payload::Borrowed(b"ab")))
    .await
    .unwrap();
  source_peer_writer
    .write_frame(Frame::new(
      true,
      OpCode::Ping,
      None,
      Payload::Borrowed(b"control-payload"),
    ))
    .await
    .unwrap();
  source_peer_writer.flush().await.unwrap();

  wait_for_network(&mut activity_rx).await;
  let first = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(first.opcode, OpCode::Binary);
  assert!(!first.fin);
  assert_eq!(first.payload, b"a");

  wait_for_network(&mut activity_rx).await;
  let control = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(control.opcode, OpCode::Ping);
  assert_eq!(control.payload, b"control-payload");

  let final_fragment = read_owned_frame(&mut destination_peer_reader);
  tokio::pin!(final_fragment);
  assert!(futures_util::poll!(final_fragment.as_mut()).is_pending());
  tokio::time::advance(Duration::from_secs(1)).await;
  let final_fragment = final_fragment.await.unwrap();
  assert_eq!(final_fragment.opcode, OpCode::Continuation);
  assert!(final_fragment.fin);
  assert_eq!(final_fragment.payload, b"b");

  pump.abort();
}

#[tokio::test(start_paused = true)]
async fn controls_behind_deferred_data_overtake_the_current_frame_wait() {
  let (source_peer, source_bridge) = duplex(4096);
  let (source_peer_read, source_peer_write) = tokio::io::split(source_peer);
  let (_source_peer_reader, mut source_peer_writer) =
    after_handshake_split(source_peer_read, source_peer_write, Role::Client);
  let (source_bridge_read, source_bridge_write) = tokio::io::split(source_bridge);
  let (mut source_bridge_reader, _source_bridge_writer) =
    after_handshake_split(source_bridge_read, source_bridge_write, Role::Server);
  configure_reader_controls(&mut source_bridge_reader);

  let (destination_bridge, destination_peer) = duplex(4096);
  let (destination_bridge_read, destination_bridge_write) = tokio::io::split(destination_bridge);
  let (_destination_bridge_reader, destination_bridge_writer) = after_handshake_split(
    destination_bridge_read,
    destination_bridge_write,
    Role::Client,
  );
  let (destination_peer_read, destination_peer_write) = tokio::io::split(destination_peer);
  let (mut destination_peer_reader, _destination_peer_writer) =
    after_handshake_split(destination_peer_read, destination_peer_write, Role::Server);
  configure_reader_controls(&mut destination_peer_reader);

  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(1).unwrap());
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(rate, BandwidthRate::Unlimited));
  let (activity, mut activity_rx) = mpsc::channel(16);
  let pump = tokio::spawn(
    WebSocketDirectionPump {
      reader: WebSocketFrameReader::spawn(source_bridge_reader),
      writer: Arc::new(Mutex::new(destination_bridge_writer)),
      state: None,
      context: None,
      messages: WebSocketMessageState::new(0),
      direction: WafStreamDirection::DownstreamToUpstream,
      flow: Some(limiter.flow(BandwidthDirection::Upload)),
      metrics: Metrics::new(),
      activity,
      deferred_data: None,
      priority_data: None,
      pending_waf_upload: None,
      read_error_context: "test source read failed",
      write_error_context: "test destination write failed",
    }
    .run(),
  );

  source_peer_writer
    .write_frame(Frame::binary(Payload::Borrowed(b"ab")))
    .await
    .unwrap();
  source_peer_writer.flush().await.unwrap();
  wait_for_network(&mut activity_rx).await;
  let first = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(first.opcode, OpCode::Binary);
  assert!(!first.fin);
  assert_eq!(first.payload, b"a");

  source_peer_writer
    .write_frame(Frame::binary(Payload::Borrowed(b"deferred")))
    .await
    .unwrap();
  source_peer_writer
    .write_frame(Frame::new(
      true,
      OpCode::Ping,
      None,
      Payload::Borrowed(b"ping"),
    ))
    .await
    .unwrap();
  source_peer_writer
    .write_frame(Frame::new(
      true,
      OpCode::Pong,
      None,
      Payload::Borrowed(b"pong"),
    ))
    .await
    .unwrap();
  source_peer_writer
    .write_frame(Frame::close(1000, b"done"))
    .await
    .unwrap();
  source_peer_writer.flush().await.unwrap();

  for (opcode, payload) in [
    (OpCode::Ping, b"ping".as_slice()),
    (OpCode::Pong, b"pong".as_slice()),
    (
      OpCode::Close,
      [3_u8, 232, b'd', b'o', b'n', b'e'].as_slice(),
    ),
  ] {
    wait_for_network(&mut activity_rx).await;
    let control = read_owned_frame(&mut destination_peer_reader)
      .await
      .unwrap();
    assert_eq!(control.opcode, opcode);
    assert_eq!(control.payload, payload);
  }
  assert!(matches!(pump.await.unwrap(), Err(PumpError::PeerClosed)));
}

#[tokio::test(start_paused = true)]
async fn an_already_ready_control_beats_an_immediate_grant() {
  let (source_peer, source_bridge) = duplex(4096);
  let (source_peer_read, source_peer_write) = tokio::io::split(source_peer);
  let (_source_peer_reader, mut source_peer_writer) =
    after_handshake_split(source_peer_read, source_peer_write, Role::Client);
  let (source_bridge_read, source_bridge_write) = tokio::io::split(source_bridge);
  let (mut source_bridge_reader, _source_bridge_writer) =
    after_handshake_split(source_bridge_read, source_bridge_write, Role::Server);
  configure_reader_controls(&mut source_bridge_reader);

  let (destination_bridge, destination_peer) = duplex(4096);
  let (destination_bridge_read, destination_bridge_write) = tokio::io::split(destination_bridge);
  let (_destination_bridge_reader, destination_bridge_writer) = after_handshake_split(
    destination_bridge_read,
    destination_bridge_write,
    Role::Client,
  );
  let (destination_peer_read, destination_peer_write) = tokio::io::split(destination_peer);
  let (mut destination_peer_reader, _destination_peer_writer) =
    after_handshake_split(destination_peer_read, destination_peer_write, Role::Server);
  configure_reader_controls(&mut destination_peer_reader);

  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(1).unwrap());
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(rate, BandwidthRate::Unlimited));
  let (activity, _activity_rx) = mpsc::channel(16);
  let mut pump = WebSocketDirectionPump {
    reader: WebSocketFrameReader::spawn(source_bridge_reader),
    writer: Arc::new(Mutex::new(destination_bridge_writer)),
    state: None,
    context: None,
    messages: WebSocketMessageState::new(0),
    direction: WafStreamDirection::DownstreamToUpstream,
    flow: None,
    metrics: Metrics::new(),
    activity,
    deferred_data: None,
    priority_data: None,
    pending_waf_upload: None,
    read_error_context: "test source read failed",
    write_error_context: "test destination write failed",
  };
  let mut flow = limiter.flow(BandwidthDirection::Upload);

  source_peer_writer
    .write_frame(Frame::new(
      true,
      OpCode::Ping,
      None,
      Payload::Borrowed(b"ready"),
    ))
    .await
    .unwrap();
  source_peer_writer.flush().await.unwrap();
  pump
    .reader
    .prepare(MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES)
    .await
    .unwrap();
  pump.reader.wait_until_ready().await;

  let grant = pump.acquire_with_lookahead(&mut flow, 1).await.unwrap();
  assert_eq!(grant.bytes, 1);
  let control = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(control.opcode, OpCode::Ping);
  assert_eq!(control.payload, b"ready");
}

#[tokio::test]
async fn reader_rejects_an_oversized_declared_frame_before_its_payload() {
  let (mut source_peer, source_bridge) = duplex(64);
  let (source_bridge_read, source_bridge_write) = tokio::io::split(source_bridge);
  let (source_bridge_reader, _source_bridge_writer) =
    after_handshake_split(source_bridge_read, source_bridge_write, Role::Server);
  let mut reader = WebSocketFrameReader::spawn(source_bridge_reader);
  let declared = u64::try_from(MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES + 1).unwrap();
  let mut header = vec![0x82, 0xff];
  header.extend_from_slice(&declared.to_be_bytes());
  header.extend_from_slice(&[1, 2, 3, 4]);
  source_peer.write_all(&header).await.unwrap();

  let error = match reader.next(MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES).await {
    Ok(_) => panic!("oversized WebSocket frame was accepted"),
    Err(error) => error,
  };
  assert!(error.to_string().contains("Frame too large"));
}

#[tokio::test]
async fn reader_cap_stays_bounded_across_live_policy_changes() {
  let (mut pump, _activity_rx) = refundable_upload_test_pump();
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::UNLIMITED);
  pump.flow = Some(limiter.flow(BandwidthDirection::Upload));
  assert_eq!(
    pump.reader_payload_limit(),
    MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES
  );

  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(1).unwrap());
  limiter
    .update(BandwidthPolicy::new(rate, BandwidthRate::Unlimited))
    .unwrap();
  assert_eq!(
    pump.reader_payload_limit(),
    MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES
  );

  limiter.update(BandwidthPolicy::UNLIMITED).unwrap();
  assert_eq!(
    pump.reader_payload_limit(),
    MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES
  );
}

#[tokio::test]
async fn reader_accepts_a_frame_at_the_retention_cap() {
  let capacity = MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES + 64;
  let (source_peer, source_bridge) = duplex(capacity);
  let (source_peer_read, source_peer_write) = tokio::io::split(source_peer);
  let (_source_peer_reader, mut source_peer_writer) =
    after_handshake_split(source_peer_read, source_peer_write, Role::Client);
  let (source_bridge_read, source_bridge_write) = tokio::io::split(source_bridge);
  let (source_bridge_reader, _source_bridge_writer) =
    after_handshake_split(source_bridge_read, source_bridge_write, Role::Server);
  let mut reader = WebSocketFrameReader::spawn(source_bridge_reader);
  let writer = tokio::spawn(async move {
    source_peer_writer
      .write_frame(Frame::binary(Payload::Owned(vec![
        0;
        MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES
      ])))
      .await
      .unwrap();
    source_peer_writer.flush().await.unwrap();
  });

  let frame = reader
    .next(MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES)
    .await
    .expect("frame at the retention cap should be accepted");
  assert_eq!(frame.payload.len(), MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES);
  writer.await.unwrap();
}

#[tokio::test]
async fn reader_accepts_a_fragmented_message_larger_than_the_frame_cap() {
  let fragment_bytes = MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES / 2 + 1;
  let capacity = fragment_bytes * 2 + 128;
  let (source_peer, source_bridge) = duplex(capacity);
  let (source_peer_read, source_peer_write) = tokio::io::split(source_peer);
  let (_source_peer_reader, mut source_peer_writer) =
    after_handshake_split(source_peer_read, source_peer_write, Role::Client);
  let (source_bridge_read, source_bridge_write) = tokio::io::split(source_bridge);
  let (source_bridge_reader, _source_bridge_writer) =
    after_handshake_split(source_bridge_read, source_bridge_write, Role::Server);
  let mut reader = WebSocketFrameReader::spawn(source_bridge_reader);
  let writer = tokio::spawn(async move {
    source_peer_writer
      .write_frame(Frame::new(
        false,
        OpCode::Binary,
        None,
        Payload::Owned(vec![0; fragment_bytes]),
      ))
      .await
      .unwrap();
    source_peer_writer
      .write_frame(Frame::new(
        true,
        OpCode::Continuation,
        None,
        Payload::Owned(vec![0; fragment_bytes]),
      ))
      .await
      .unwrap();
    source_peer_writer.flush().await.unwrap();
  });

  let first = reader
    .next(MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES)
    .await
    .expect("first fragment should be accepted");
  let second = reader
    .next(MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES)
    .await
    .expect("second fragment should be accepted");
  assert_eq!(first.opcode, OpCode::Binary);
  assert!(!first.fin);
  assert_eq!(second.opcode, OpCode::Continuation);
  assert!(second.fin);
  assert!(first.payload.len() + second.payload.len() > MAX_WEBSOCKET_FRAME_PAYLOAD_BYTES);
  writer.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn control_overtakes_a_pending_pre_waf_refundable_acquisition() {
  let (source_peer, source_bridge) = duplex(4096);
  let (source_peer_read, source_peer_write) = tokio::io::split(source_peer);
  let (_source_peer_reader, mut source_peer_writer) =
    after_handshake_split(source_peer_read, source_peer_write, Role::Client);
  let (source_bridge_read, source_bridge_write) = tokio::io::split(source_bridge);
  let (mut source_bridge_reader, _source_bridge_writer) =
    after_handshake_split(source_bridge_read, source_bridge_write, Role::Server);
  configure_reader_controls(&mut source_bridge_reader);

  let (destination_bridge, destination_peer) = duplex(4096);
  let (destination_bridge_read, destination_bridge_write) = tokio::io::split(destination_bridge);
  let (_destination_bridge_reader, destination_bridge_writer) = after_handshake_split(
    destination_bridge_read,
    destination_bridge_write,
    Role::Client,
  );
  let (destination_peer_read, destination_peer_write) = tokio::io::split(destination_peer);
  let (mut destination_peer_reader, _destination_peer_writer) =
    after_handshake_split(destination_peer_read, destination_peer_write, Role::Server);
  configure_reader_controls(&mut destination_peer_reader);

  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(1).unwrap());
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(rate, BandwidthRate::Unlimited));
  let mut flow = limiter.flow(BandwidthDirection::Upload);
  flow.acquire(1).await.unwrap();
  let (activity, mut activity_rx) = mpsc::channel(16);
  let mut pump = WebSocketDirectionPump {
    reader: WebSocketFrameReader::spawn(source_bridge_reader),
    writer: Arc::new(Mutex::new(destination_bridge_writer)),
    state: None,
    context: None,
    messages: WebSocketMessageState::new(0),
    direction: WafStreamDirection::DownstreamToUpstream,
    flow: None,
    metrics: Metrics::new(),
    activity,
    deferred_data: None,
    priority_data: None,
    pending_waf_upload: None,
    read_error_context: "test source read failed",
    write_error_context: "test destination write failed",
  };

  source_peer_writer
    .write_frame(Frame::new(
      true,
      OpCode::Ping,
      None,
      Payload::Borrowed(b"pre-waf-control"),
    ))
    .await
    .unwrap();
  source_peer_writer.flush().await.unwrap();
  let started = tokio::time::Instant::now();
  let reservation = tokio::spawn(async move {
    let result = pump.reserve_refundable_with_lookahead(&mut flow, 1).await;
    (result, pump, flow)
  });

  wait_for_network(&mut activity_rx).await;
  let control = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(control.opcode, OpCode::Ping);
  assert_eq!(control.payload, b"pre-waf-control");
  assert_eq!(tokio::time::Instant::now(), started);

  reservation.abort();
}

#[tokio::test(start_paused = true)]
async fn grant_does_not_cancel_a_partially_read_lookahead_frame() {
  let (mut source_peer, source_bridge) = duplex(4096);
  let (source_bridge_read, source_bridge_write) = tokio::io::split(source_bridge);
  let (mut source_bridge_reader, _source_bridge_writer) =
    after_handshake_split(source_bridge_read, source_bridge_write, Role::Server);
  configure_reader_controls(&mut source_bridge_reader);

  let (destination_bridge, destination_peer) = duplex(4096);
  let (destination_bridge_read, destination_bridge_write) = tokio::io::split(destination_bridge);
  let (_destination_bridge_reader, destination_bridge_writer) = after_handshake_split(
    destination_bridge_read,
    destination_bridge_write,
    Role::Client,
  );
  let (destination_peer_read, destination_peer_write) = tokio::io::split(destination_peer);
  let (mut destination_peer_reader, _destination_peer_writer) =
    after_handshake_split(destination_peer_read, destination_peer_write, Role::Server);
  configure_reader_controls(&mut destination_peer_reader);

  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(1).unwrap());
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(rate, BandwidthRate::Unlimited));
  let (activity, mut activity_rx) = mpsc::channel(16);
  let pump = tokio::spawn(
    WebSocketDirectionPump {
      reader: WebSocketFrameReader::spawn(source_bridge_reader),
      writer: Arc::new(Mutex::new(destination_bridge_writer)),
      state: None,
      context: None,
      messages: WebSocketMessageState::new(0),
      direction: WafStreamDirection::DownstreamToUpstream,
      flow: Some(limiter.flow(BandwidthDirection::Upload)),
      metrics: Metrics::new(),
      activity,
      deferred_data: None,
      priority_data: None,
      pending_waf_upload: None,
      read_error_context: "test source read failed",
      write_error_context: "test destination write failed",
    }
    .run(),
  );

  let current = masked_frame(0x2, b"ab", [1, 2, 3, 4]);
  let ping = masked_frame(0x9, b"p", [5, 6, 7, 8]);
  source_peer.write_all(&current).await.unwrap();
  source_peer.write_all(&ping[..6]).await.unwrap();
  source_peer.flush().await.unwrap();

  wait_for_network(&mut activity_rx).await;
  let first = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(first.opcode, OpCode::Binary);
  assert_eq!(first.payload, b"a");
  wait_for_wait_started(&mut activity_rx).await;
  tokio::task::yield_now().await;

  tokio::time::advance(Duration::from_secs(1)).await;
  wait_for_network(&mut activity_rx).await;
  let continuation = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(continuation.opcode, OpCode::Continuation);
  assert_eq!(continuation.payload, b"b");

  source_peer.write_all(&ping[6..]).await.unwrap();
  source_peer.flush().await.unwrap();
  wait_for_network(&mut activity_rx).await;
  let ping = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(ping.opcode, OpCode::Ping);
  assert_eq!(ping.payload, b"p");

  let pong = masked_frame(0xA, b"q", [9, 10, 11, 12]);
  source_peer.write_all(&pong).await.unwrap();
  source_peer.flush().await.unwrap();
  wait_for_network(&mut activity_rx).await;
  let pong = read_owned_frame(&mut destination_peer_reader)
    .await
    .unwrap();
  assert_eq!(pong.opcode, OpCode::Pong);
  assert_eq!(pong.payload, b"q");

  pump.abort();
}

#[tokio::test(start_paused = true)]
async fn approved_waf_upload_refunds_before_progressive_output_acquisition() {
  let (mut pump, _activity_rx) = refundable_upload_test_pump();
  let mut flow = pump.flow.take().unwrap();
  pump
    .reserve_refundable_with_lookahead(&mut flow, 1)
    .await
    .unwrap();
  assert_eq!(pump.pending_waf_upload.as_ref().unwrap().bytes(), 1);

  pump.refund_pending_upload();
  {
    let output_grant = flow.acquire(1);
    tokio::pin!(output_grant);
    assert!(futures_util::poll!(output_grant.as_mut()).is_ready());
  }

  let next_output = flow.acquire(1);
  tokio::pin!(next_output);
  assert!(futures_util::poll!(next_output.as_mut()).is_pending());
}

#[tokio::test(start_paused = true)]
async fn blocked_waf_upload_commits_preinspection_acquisition() {
  let (mut pump, _activity_rx) = refundable_upload_test_pump();
  let mut flow = pump.flow.take().unwrap();
  pump
    .reserve_refundable_with_lookahead(&mut flow, 1)
    .await
    .unwrap();

  pump.commit_pending_upload();
  let next_upload = flow.acquire(1);
  tokio::pin!(next_upload);
  assert!(futures_util::poll!(next_upload.as_mut()).is_pending());
}

#[tokio::test(start_paused = true)]
async fn partial_waf_upload_is_committed_when_the_pump_closes() {
  let (mut pump, _activity_rx) = refundable_upload_test_pump();
  let mut flow = pump.flow.take().unwrap();
  pump
    .reserve_refundable_with_lookahead(&mut flow, 1)
    .await
    .unwrap();
  drop(pump);

  let next_upload = flow.acquire(1);
  tokio::pin!(next_upload);
  assert!(futures_util::poll!(next_upload.as_mut()).is_pending());
}

fn refundable_upload_test_pump() -> (TestPump, mpsc::Receiver<BridgeActivity>) {
  let (_source_peer, source_bridge) = duplex(256);
  let (source_read, source_write) = tokio::io::split(source_bridge);
  let (reader, _source_writer) = after_handshake_split(source_read, source_write, Role::Server);
  let (destination_bridge, _destination_peer) = duplex(256);
  let (destination_read, destination_write) = tokio::io::split(destination_bridge);
  let (_destination_reader, writer) =
    after_handshake_split(destination_read, destination_write, Role::Client);
  let rate = BandwidthRate::BytesPerSecond(NonZeroU64::new(1).unwrap());
  let limiter = RouteBandwidthLimiter::new(BandwidthPolicy::new(rate, BandwidthRate::Unlimited));
  let (activity, activity_rx) = mpsc::channel(4);
  (
    WebSocketDirectionPump {
      reader: WebSocketFrameReader::spawn(reader),
      writer: Arc::new(Mutex::new(writer)),
      state: None,
      context: None,
      messages: WebSocketMessageState::new(0),
      direction: WafStreamDirection::DownstreamToUpstream,
      flow: Some(limiter.flow(BandwidthDirection::Upload)),
      metrics: Metrics::new(),
      activity,
      deferred_data: None,
      priority_data: None,
      pending_waf_upload: None,
      read_error_context: "test source read failed",
      write_error_context: "test destination write failed",
    },
    activity_rx,
  )
}

async fn wait_for_network(activity_rx: &mut mpsc::Receiver<BridgeActivity>) {
  loop {
    match activity_rx.recv().await {
      Some(BridgeActivity::Network) => return,
      Some(BridgeActivity::BandwidthWaitStarted | BridgeActivity::BandwidthWaitEnded) => {}
      None => panic!("WebSocket pump stopped before reporting network activity"),
    }
  }
}

async fn wait_for_wait_started(activity_rx: &mut mpsc::Receiver<BridgeActivity>) {
  loop {
    match activity_rx.recv().await {
      Some(BridgeActivity::BandwidthWaitStarted) => return,
      Some(BridgeActivity::Network | BridgeActivity::BandwidthWaitEnded) => {}
      None => panic!("WebSocket pump stopped before starting its bandwidth wait"),
    }
  }
}

fn masked_frame(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
  assert!(payload.len() < 126);
  let mut encoded = Vec::with_capacity(6 + payload.len());
  encoded.push(0x80 | opcode);
  encoded.push(0x80 | payload.len() as u8);
  encoded.extend_from_slice(&mask);
  encoded.extend(
    payload
      .iter()
      .enumerate()
      .map(|(index, byte)| byte ^ mask[index % mask.len()]),
  );
  encoded
}
