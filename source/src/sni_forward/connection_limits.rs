use std::net::SocketAddr;

use http::StatusCode;

use crate::config::ConnectionLimitIdentityMode;
use crate::limits::ConnectionPermit;
use crate::state::AppSnapshot;

pub(crate) fn acquire_tcp_forward_connection_permit(
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
) -> Result<Option<ConnectionPermit>, StatusCode> {
  match snapshot.config.limits.connection_limit_identity {
    ConnectionLimitIdentityMode::ProxyProtocol => Ok(None),
    ConnectionLimitIdentityMode::FirstRequestRealIp
    | ConnectionLimitIdentityMode::PerRequestRealIp => snapshot
      .limits
      .acquire_ip_connection(
        peer_addr.ip(),
        &snapshot.config.limits,
        &snapshot.config.connection_limits,
      )
      .map(Some),
  }
}

pub(crate) fn acquire_quic_forward_connection_permit(
  snapshot: &AppSnapshot,
  peer_addr: SocketAddr,
) -> Result<ConnectionPermit, StatusCode> {
  snapshot.limits.acquire_connection(
    peer_addr.ip(),
    &snapshot.config.limits,
    &snapshot.config.connection_limits,
  )
}

#[cfg(test)]
mod tests {
  use http::StatusCode;

  use super::*;
  use crate::config::{Config, ConnectionLimitIdentityMode};
  use crate::state::AppSnapshot;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[tokio::test]
  async fn tcp_forward_real_ip_modes_hold_ip_connection_permit() {
    let snapshot = limited_snapshot(
      "sni-forward-tcp-limits",
      ConnectionLimitIdentityMode::FirstRequestRealIp,
      4,
      1,
    )
    .await;
    let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let permit = acquire_tcp_forward_connection_permit(&snapshot, peer)
      .expect("first forwarded TCP lease should succeed")
      .expect("real-ip mode should acquire an IP permit");

    assert_eq!(
      tcp_forward_error_status(&snapshot, peer),
      StatusCode::TOO_MANY_REQUESTS
    );

    drop(permit);
    assert!(acquire_tcp_forward_connection_permit(&snapshot, peer).is_ok());
  }

  #[tokio::test]
  async fn tcp_forward_proxy_protocol_mode_uses_outer_connection_permits() {
    let snapshot = limited_snapshot(
      "sni-forward-tcp-proxy-protocol-limits",
      ConnectionLimitIdentityMode::ProxyProtocol,
      1,
      1,
    )
    .await;
    let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    assert!(
      acquire_tcp_forward_connection_permit(&snapshot, peer)
        .expect("proxy-protocol mode should not add an inner TCP permit")
        .is_none()
    );
  }

  #[tokio::test]
  async fn quic_forward_sessions_use_total_and_ip_connection_limits() {
    let snapshot = limited_snapshot(
      "sni-forward-quic-limits",
      ConnectionLimitIdentityMode::ProxyProtocol,
      2,
      1,
    )
    .await;
    let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    let permit = acquire_quic_forward_connection_permit(&snapshot, peer)
      .expect("first forwarded QUIC lease should succeed");

    assert_eq!(
      quic_forward_error_status(&snapshot, peer),
      StatusCode::TOO_MANY_REQUESTS
    );

    drop(permit);
    let first = acquire_quic_forward_connection_permit(&snapshot, peer)
      .expect("released QUIC lease should become available again");
    let other_peer: SocketAddr = "127.0.0.2:12345".parse().unwrap();
    let second = acquire_quic_forward_connection_permit(&snapshot, other_peer)
      .expect("second IP should fit under total limit");

    assert_eq!(
      quic_forward_error_status(&snapshot, "127.0.0.3:12345".parse().unwrap()),
      StatusCode::SERVICE_UNAVAILABLE
    );

    drop(first);
    drop(second);
  }

  async fn limited_snapshot(
    name: &str,
    identity: ConnectionLimitIdentityMode,
    max_connections: usize,
    max_connections_per_ip: usize,
  ) -> AppSnapshot {
    let temp_dir = common::TempDir::new(name);
    let (cert_path, key_path) = common::create_self_signed_cert(temp_dir.path(), name);
    let mut config = parse_config(&common::minimal_config_toml(&cert_path, &key_path));
    config.limits.connection_limit_identity = identity;
    config.limits.max_connections = max_connections;
    config.limits.max_connections_per_ip = max_connections_per_ip;
    AppSnapshot::new(config)
      .await
      .expect("application snapshot should initialize")
  }

  fn parse_config(raw: &str) -> Config {
    let config: Config = toml::from_str(raw).expect("config should parse");
    config.validate().expect("config should validate");
    config
  }

  fn tcp_forward_error_status(snapshot: &AppSnapshot, peer: SocketAddr) -> StatusCode {
    match acquire_tcp_forward_connection_permit(snapshot, peer) {
      Ok(_) => panic!("forwarded TCP connection permit should be rejected"),
      Err(status) => status,
    }
  }

  fn quic_forward_error_status(snapshot: &AppSnapshot, peer: SocketAddr) -> StatusCode {
    match acquire_quic_forward_connection_permit(snapshot, peer) {
      Ok(_) => panic!("forwarded QUIC connection permit should be rejected"),
      Err(status) => status,
    }
  }
}
