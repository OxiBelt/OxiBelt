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

async fn state_with_webtransport_session_limit(identity: &str) -> AppSnapshot {
  let temp_dir = common::TempDir::new("webtransport-session-limits");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "webtransport-session-limits");
  let raw = format!(
    r#"
{}

[limits]
max_connections = 64
max_connections_per_ip = 1
connection_limit_identity = "{identity}"
max_webtransport_sessions = 64
max_webtransport_sessions_per_ip = 1
max_webtransport_sessions_per_connection = 2
"#,
    common::minimal_config_toml(&cert_path, &key_path)
  );

  AppSnapshot::new(parse_config(&raw))
    .await
    .expect("snapshot should initialize")
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

#[tokio::test]
async fn webtransport_session_permits_enforce_proxy_protocol_per_ip_limit() {
  let state = state_with_webtransport_session_limit("proxy_protocol").await;
  let ip = "203.0.113.10".parse().unwrap();

  let first = acquire_webtransport_session_permit(ip, None, &state)
    .expect("first WebTransport session should acquire a permit");

  assert_eq!(
    acquire_webtransport_session_permit(ip, None, &state).err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  drop(first);
  assert!(acquire_webtransport_session_permit(ip, None, &state).is_ok());
}

#[tokio::test]
async fn webtransport_first_request_identity_uses_bound_ip_for_later_sessions() {
  let state = state_with_webtransport_session_limit("first_request_real_ip").await;
  let context = ConnectionLimitContext::default();
  let first_ip = "203.0.113.20".parse().unwrap();
  let spoofed_later_ip = "203.0.113.21".parse().unwrap();

  let first = acquire_webtransport_session_permit(first_ip, Some(&context), &state)
    .expect("first WebTransport session should bind and acquire a permit");

  assert_eq!(
    acquire_webtransport_session_permit(spoofed_later_ip, Some(&context), &state).err(),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );

  drop(first);
  assert!(
    acquire_webtransport_session_permit(spoofed_later_ip, Some(&context), &state).is_ok(),
    "after release, the same first-request identity should be reusable"
  );
}
