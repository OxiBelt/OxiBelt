use std::convert::TryFrom;

use h3::quic::StreamId;
use http::StatusCode;

use super::*;
use crate::config::Config;
use crate::state::AppSnapshot;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn parse_config(raw: &str) -> Config {
  let config: Config = toml::from_str(raw).expect("config should parse");
  config.validate().expect("config should validate");
  config
}

async fn state_with_webtransport_limits(
  identity: &str,
  max_connections_per_ip: usize,
  max_webtransport_sessions_per_ip: usize,
  extra_config: &str,
) -> AppSnapshot {
  let temp_dir = common::TempDir::new("webtransport-session-limits");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "webtransport-session-limits");
  let raw = format!(
    r#"
{}

[limits]
max_connections = 64
max_connections_per_ip = {max_connections_per_ip}
connection_limit_identity = "{identity}"
max_webtransport_sessions = 64
max_webtransport_sessions_per_ip = {max_webtransport_sessions_per_ip}
max_webtransport_sessions_per_connection = 2

{extra_config}
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize")
}

async fn state_with_webtransport_session_limit(identity: &str) -> AppSnapshot {
  state_with_webtransport_limits(identity, 1, 1, "").await
}

#[test]
fn session_index_inserts_and_removes_sessions() {
  let mut index = WebTransportSessionIndex::default();
  let connect_stream_id = StreamId::try_from(8).expect("valid stream id");

  let session_id = index.insert(connect_stream_id);

  assert_eq!(session_id, session_id_for_stream_id(connect_stream_id));
  assert!(index.contains(session_id));
  assert_eq!(index.connect_stream_id(session_id), Some(connect_stream_id));

  index.remove(session_id);

  assert!(!index.contains(session_id));
  assert_eq!(index.connect_stream_id(session_id), None);
}

#[test]
fn unknown_sessions_do_not_route() {
  let mut index = WebTransportSessionIndex::default();
  let known_stream_id = StreamId::try_from(0).expect("valid stream id");
  let unknown_stream_id = StreamId::try_from(4).expect("valid stream id");

  index.insert(known_stream_id);

  assert_eq!(
    index.session_for_datagram_stream_id(unknown_stream_id),
    None
  );
}

#[test]
fn datagram_lookup_uses_associated_connect_stream_id() {
  let mut index = WebTransportSessionIndex::default();
  let connect_stream_id = StreamId::try_from(12).expect("valid stream id");
  let other_connect_stream_id = StreamId::try_from(16).expect("valid stream id");

  let session_id = index.insert(connect_stream_id);

  assert_eq!(
    index.session_for_datagram_stream_id(connect_stream_id),
    Some(session_id)
  );
  assert_eq!(
    index.session_for_datagram_stream_id(other_connect_stream_id),
    None
  );
}

#[test]
fn datagram_pacer_queue_keeps_oldest_and_drops_newest() {
  let (sender, mut receiver) = datagram_pacer_channel();

  assert_eq!(
    try_queue_datagram(&sender, Bytes::from_static(b"oldest")),
    DatagramQueueOutcome::Queued
  );
  assert_eq!(
    try_queue_datagram(&sender, Bytes::from_static(b"newest")),
    DatagramQueueOutcome::DroppedNewest
  );
  let oldest = receiver.try_recv().expect("oldest datagram remains queued");
  assert_eq!(oldest.payload, Bytes::from_static(b"oldest"));
  assert_eq!(
    try_queue_datagram(&sender, Bytes::from_static(b"still-newest")),
    DatagramQueueOutcome::DroppedNewest,
    "the single slot remains occupied until pacing finishes"
  );
  drop(oldest);

  drop(receiver);
  assert_eq!(
    try_queue_datagram(&sender, Bytes::from_static(b"closed")),
    DatagramQueueOutcome::Closed
  );
}

#[test]
fn stream_directions_map_to_client_upload_and_download() {
  assert_eq!(
    bandwidth_direction(WafStreamDirection::DownstreamToUpstream),
    BandwidthDirection::Upload
  );
  assert_eq!(
    bandwidth_direction(WafStreamDirection::UpstreamToDownstream),
    BandwidthDirection::Download
  );
}

#[tokio::test]
async fn webtransport_session_permits_enforce_proxy_protocol_per_ip_limit() {
  let state = state_with_webtransport_session_limit("proxy_protocol").await;
  let ip = "203.0.113.10".parse().unwrap();

  let first = acquire_webtransport_session_permits(ip, None, &state)
    .await
    .expect("first WebTransport session should acquire a permit");

  assert_eq!(
    acquire_webtransport_session_permits(ip, None, &state)
      .await
      .err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  drop(first);
  assert!(
    acquire_webtransport_session_permits(ip, None, &state)
      .await
      .is_ok()
  );
}

#[tokio::test]
async fn webtransport_first_request_identity_uses_bound_ip_for_later_sessions() {
  let state = state_with_webtransport_session_limit("first_request_real_ip").await;
  let context = ConnectionLimitContext::default();
  let first_ip = "203.0.113.20".parse().unwrap();
  let spoofed_later_ip = "203.0.113.21".parse().unwrap();

  let first = acquire_webtransport_session_permits(first_ip, Some(&context), &state)
    .await
    .expect("first WebTransport session should bind and acquire a permit");

  assert_eq!(
    acquire_webtransport_session_permits(spoofed_later_ip, Some(&context), &state)
      .await
      .err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  drop(first);
  assert!(
    acquire_webtransport_session_permits(spoofed_later_ip, Some(&context), &state)
      .await
      .is_ok(),
    "after release, the same first-request identity should be reusable"
  );
}

#[tokio::test]
async fn webtransport_per_request_identity_rejects_when_normal_ip_limit_is_exhausted() {
  let state = state_with_webtransport_limits("per_request_real_ip", 1, 64, "").await;
  let ip = "203.0.113.30".parse().unwrap();
  let normal_connection = state
    .limits
    .acquire_ip_connection(ip, &state.config.limits, &state.config.connection_limits)
    .expect("ordinary request should acquire the only normal per-IP permit");

  assert_eq!(
    acquire_webtransport_session_permits(ip, None, &state)
      .await
      .err(),
    Some(StatusCode::TOO_MANY_REQUESTS),
    "WebTransport must honor the existing normal per-IP connection counter"
  );

  drop(normal_connection);
  assert!(
    acquire_webtransport_session_permits(ip, None, &state)
      .await
      .is_ok(),
    "WebTransport should proceed once the normal per-IP permit is released"
  );
}

#[tokio::test]
async fn webtransport_per_request_identity_holds_normal_ip_permit_for_session_lifetime() {
  let state = state_with_webtransport_limits("per_request_real_ip", 1, 64, "").await;
  let ip = "203.0.113.31".parse().unwrap();

  let webtransport = acquire_webtransport_session_permits(ip, None, &state)
    .await
    .expect("WebTransport session should acquire normal and session permits");

  assert_eq!(
    state
      .limits
      .acquire_ip_connection(ip, &state.config.limits, &state.config.connection_limits)
      .err(),
    Some(StatusCode::TOO_MANY_REQUESTS),
    "normal per-IP quota should stay occupied while the WebTransport session is active"
  );

  drop(webtransport);
  assert!(
    state
      .limits
      .acquire_ip_connection(ip, &state.config.limits, &state.config.connection_limits)
      .is_ok(),
    "normal per-IP quota should be released when the WebTransport session ends"
  );
}

#[tokio::test]
async fn webtransport_first_request_identity_binds_normal_ip_permit_to_connection_context() {
  let state = state_with_webtransport_limits("first_request_real_ip", 1, 64, "").await;
  let context = ConnectionLimitContext::default();
  let ip = "203.0.113.32".parse().unwrap();

  let webtransport = acquire_webtransport_session_permits(ip, Some(&context), &state)
    .await
    .expect("WebTransport session should bind the first request Real-IP permit");

  assert_eq!(
    state
      .limits
      .acquire_ip_connection(ip, &state.config.limits, &state.config.connection_limits)
      .err(),
    Some(StatusCode::TOO_MANY_REQUESTS),
    "first-request Real-IP quota should be held by the connection context"
  );

  drop(webtransport);
  assert_eq!(
    state
      .limits
      .acquire_ip_connection(ip, &state.config.limits, &state.config.connection_limits)
      .err(),
    Some(StatusCode::TOO_MANY_REQUESTS),
    "the first-request permit intentionally remains held until the HTTP/3 connection context drops"
  );

  drop(context);
  assert!(
    state
      .limits
      .acquire_ip_connection(ip, &state.config.limits, &state.config.connection_limits)
      .is_ok(),
    "dropping the connection context should release the normal per-IP quota"
  );
}

#[tokio::test]
async fn webtransport_real_ip_identity_rejects_when_named_connection_limit_is_exhausted() {
  let state = state_with_webtransport_limits(
    "per_request_real_ip",
    64,
    64,
    r#"
[[connection_limits]]
name = "tenant"
limit = 1
status = 425
"#,
  )
  .await;
  let ip = "203.0.113.33".parse().unwrap();
  let normal_connection = state
    .limits
    .acquire_ip_connection(ip, &state.config.limits, &state.config.connection_limits)
    .expect("ordinary request should acquire the only named connection permit");

  assert_eq!(
    acquire_webtransport_session_permits(ip, None, &state)
      .await
      .err(),
    Some(StatusCode::TOO_EARLY),
    "WebTransport must honor named normal connection counters and their configured status"
  );

  drop(normal_connection);
  assert!(
    acquire_webtransport_session_permits(ip, None, &state)
      .await
      .is_ok()
  );
}
