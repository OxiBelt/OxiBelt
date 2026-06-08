//! UDP stream listener runtime.
//! UDP flows are pinned by downstream socket address and expire on idle timeout or capacity pressure.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{StreamListenerConfig, StreamNetwork};
use crate::lifecycle::TaskRegistry;
use crate::limits::ConnectionPermit;
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::sni_forward::quic::extract_initial_sni;
use crate::state::AppHandle;
use crate::stream::sni::select_stream_route;
use crate::stream::target::{ResolvedStreamTarget, resolve_stream_route_target};

const MAX_UDP_DATAGRAM_BYTES: usize = 65_535;

pub(super) fn bind_udp_socket(bind: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?;
  socket.set_reuse_address(true)?;
  socket.bind(&bind.into())?;
  let socket: std::net::UdpSocket = socket.into();
  socket.set_nonblocking(true)?;
  Ok(socket)
}

pub(super) async fn serve_udp_listener(
  socket: UdpSocket,
  config: StreamListenerConfig,
  state: AppHandle,
  mut shutdown: watch::Receiver<bool>,
  _connections: TaskRegistry,
) -> anyhow::Result<()> {
  let bind = socket.local_addr()?;
  info!(name = %config.name, bind = %bind, "UDP stream listener started");
  let socket = Arc::new(socket);
  let mut flows: HashMap<SocketAddr, UdpFlowSession> = HashMap::new();
  let mut buffer = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
  let mut expire = tokio::time::interval(Duration::from_secs(5));

  loop {
    tokio::select! {
      biased;
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          info!(name = %config.name, bind = %bind, "UDP stream listener stopped");
        }
        return Ok(());
      }
      _ = expire.tick() => {
        expire_udp_flows(&mut flows, Duration::from_millis(config.idle_timeout_ms), &state, &config.name);
      }
      received = socket.recv_from(&mut buffer) => {
        let (len, peer_addr) = received.context("failed to receive UDP stream datagram")?;
        let datagram = &buffer[..len];
        if let Err(error) = proxy_udp_datagram(&socket, &mut flows, &config, &state, peer_addr, datagram).await {
          warn!(name = %config.name, peer = %peer_addr, error = %error, "UDP stream datagram failed");
        }
      }
    }
  }
}

struct UdpFlowSession {
  upstream: Arc<UdpSocket>,
  upstream_task: JoinHandle<()>,
  target_label: String,
  route_name: String,
  last_activity: Instant,
  rate: Option<UdpRateBucket>,
  _selection: Option<crate::stream::pools::StreamPoolSelection>,
  _connection_permit: ConnectionPermit,
  _introspection_guard: crate::runtime_introspection::RuntimeCounterGuard,
}

impl Drop for UdpFlowSession {
  fn drop(&mut self) {
    self.upstream_task.abort();
  }
}

struct UdpRateBucket {
  tokens: f64,
  last: Instant,
}

async fn proxy_udp_datagram(
  downstream: &Arc<UdpSocket>,
  flows: &mut HashMap<SocketAddr, UdpFlowSession>,
  config: &StreamListenerConfig,
  state: &AppHandle,
  peer_addr: SocketAddr,
  datagram: &[u8],
) -> anyhow::Result<()> {
  expire_udp_flows(
    flows,
    Duration::from_millis(config.idle_timeout_ms),
    state,
    &config.name,
  );
  if !flows.contains_key(&peer_addr) {
    let Some((route_name, resolved)) =
      classify_udp_flow(config, state, peer_addr, datagram).await?
    else {
      return Ok(());
    };
    let permit = acquire_udp_flow_permit(state, peer_addr)?;
    let upstream = Arc::new(UdpSocket::bind(client_bind_addr(resolved.addr)).await?);
    upstream.connect(resolved.addr).await?;
    let upstream_reader = upstream.clone();
    let downstream_writer = downstream.clone();
    let target_label = resolved.label;
    let listener_name = config.name.clone();
    let upstream_task = tokio::spawn(async move {
      let mut buf = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
      while let Ok(len) = upstream_reader.recv(&mut buf).await {
        if downstream_writer
          .send_to(&buf[..len], peer_addr)
          .await
          .is_err()
        {
          break;
        }
      }
    });
    let introspection_guard = state
      .snapshot()
      .runtime_introspection
      .guard(RuntimeCounter::StreamListenerUdpFlow);
    info!(
      name = %listener_name,
      peer = %peer_addr,
      route = %route_name,
      target = %target_label,
      "UDP stream flow started"
    );
    while flows.len() >= config.max_udp_flows {
      let Some(oldest) = oldest_flow(flows) else {
        break;
      };
      if let Some(session) = flows.remove(&oldest) {
        state.snapshot().metrics.record_stream_session_end(
          "udp",
          &config.name,
          &session.route_name,
          false,
        );
      }
    }
    flows.insert(
      peer_addr,
      UdpFlowSession {
        upstream,
        upstream_task,
        target_label,
        route_name,
        last_activity: Instant::now(),
        rate: config.udp_datagram_rate.as_ref().map(|_| UdpRateBucket {
          tokens: f64::from(config.udp_datagram_burst),
          last: Instant::now(),
        }),
        _selection: resolved.selection,
        _connection_permit: permit,
        _introspection_guard: introspection_guard,
      },
    );
  }

  if let Some(session) = flows.get_mut(&peer_addr) {
    if !udp_rate_allows(config, session) {
      state
        .snapshot()
        .metrics
        .record_stream_udp_rate_limited(&config.name);
      return Ok(());
    }
    session.upstream.send(datagram).await?;
    session.last_activity = Instant::now();
    state
      .snapshot()
      .metrics
      .add_stream_bytes("udp", datagram.len() as u64);
  }
  Ok(())
}

async fn classify_udp_flow(
  config: &StreamListenerConfig,
  state: &AppHandle,
  peer_addr: SocketAddr,
  datagram: &[u8],
) -> anyhow::Result<Option<(String, ResolvedStreamTarget)>> {
  let sni = if config.sni_rules.is_empty() {
    None
  } else {
    extract_initial_sni(datagram).ok().and_then(|(sni, _)| sni)
  };
  let Some(route) = select_stream_route(config, sni.as_deref()) else {
    return Ok(None);
  };
  let resolved =
    resolve_stream_route_target(state, StreamNetwork::Udp, route.target, peer_addr).await?;
  Ok(Some((route.name.to_string(), resolved)))
}

fn acquire_udp_flow_permit(
  state: &AppHandle,
  peer_addr: SocketAddr,
) -> anyhow::Result<ConnectionPermit> {
  let snapshot = state.snapshot();
  snapshot
    .limits
    .acquire_connection(
      peer_addr.ip(),
      &snapshot.config.limits,
      &snapshot.config.connection_limits,
    )
    .map_err(|status| anyhow::anyhow!("UDP stream flow rejected with status {status}"))
}

fn udp_rate_allows(config: &StreamListenerConfig, session: &mut UdpFlowSession) -> bool {
  let Some(rate) = config.udp_datagram_rate.as_deref() else {
    return true;
  };
  let Some(bucket) = session.rate.as_mut() else {
    return true;
  };
  let Ok(rate) = crate::limits::parse_rate(rate) else {
    return false;
  };
  let now = Instant::now();
  let elapsed = now.duration_since(bucket.last).as_secs_f64();
  bucket.last = now;
  bucket.tokens =
    (bucket.tokens + elapsed * rate.per_second()).min(f64::from(config.udp_datagram_burst.max(1)));
  if bucket.tokens < 1.0 {
    return false;
  }
  bucket.tokens -= 1.0;
  true
}

fn expire_udp_flows(
  flows: &mut HashMap<SocketAddr, UdpFlowSession>,
  idle_timeout: Duration,
  state: &AppHandle,
  listener_name: &str,
) {
  let now = Instant::now();
  let expired = flows
    .iter()
    .filter_map(|(peer, session)| {
      (now.duration_since(session.last_activity) >= idle_timeout).then_some(*peer)
    })
    .collect::<Vec<_>>();
  for peer in expired {
    if let Some(session) = flows.remove(&peer) {
      info!(
        name = %listener_name,
        peer = %peer,
        route = %session.route_name,
        target = %session.target_label,
        "UDP stream flow expired"
      );
      state.snapshot().metrics.record_stream_session_end(
        "udp",
        listener_name,
        &session.route_name,
        true,
      );
    }
  }
}

fn oldest_flow(flows: &HashMap<SocketAddr, UdpFlowSession>) -> Option<SocketAddr> {
  flows
    .iter()
    .min_by_key(|(_, session)| session.last_activity)
    .map(|(peer, _)| *peer)
}

fn client_bind_addr(remote: SocketAddr) -> SocketAddr {
  match remote {
    SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("static IPv4 bind"),
    SocketAddr::V6(_) => "[::]:0".parse().expect("static IPv6 bind"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::config::{Config, ProxyProtocolEgressMode, StreamSniRuleConfig};
  use crate::state::{AppHandle, AppSnapshot};

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

  async fn app_handle() -> AppHandle {
    let temp_dir = common::TempDir::new("udp-flow-eviction");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "udp-flow-eviction");
    let raw = common::minimal_config_toml(&cert_path, &key_path);
    AppHandle::new(
      AppSnapshot::new(parse_config(&raw))
        .await
        .expect("application snapshot should initialize"),
    )
  }

  fn sni_only_udp_listener(max_udp_flows: usize) -> StreamListenerConfig {
    StreamListenerConfig {
      name: "udp-sni-only".to_string(),
      network: StreamNetwork::Udp,
      bind: "127.0.0.1:0".parse().expect("listener bind should parse"),
      target: None,
      upstream_pool: None,
      connect_timeout_ms: 1000,
      idle_timeout_ms: 60_000,
      proxy_protocol_egress: ProxyProtocolEgressMode::Off,
      max_udp_flows,
      udp_datagram_rate: None,
      udp_datagram_burst: 1,
      sni_rules: vec![StreamSniRuleConfig {
        name: "tenant-a".to_string(),
        server_names: vec!["tenant-a.example.com".to_string()],
        target: Some("127.0.0.1:443".to_string()),
        upstream_pool: None,
        connect_timeout_ms: 1000,
        idle_timeout_ms: 60_000,
        proxy_protocol_egress: ProxyProtocolEgressMode::Off,
      }],
    }
  }

  async fn seeded_udp_flow(state: &AppHandle, route_name: &str) -> anyhow::Result<UdpFlowSession> {
    let upstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let upstream_task = tokio::spawn(async {
      std::future::pending::<()>().await;
    });
    Ok(UdpFlowSession {
      upstream,
      upstream_task,
      target_label: "127.0.0.1:443".to_string(),
      route_name: route_name.to_string(),
      last_activity: Instant::now(),
      rate: None,
      _selection: None,
      _connection_permit: acquire_udp_flow_permit(state, "127.0.0.1:49152".parse()?)?,
      _introspection_guard: state
        .snapshot()
        .runtime_introspection
        .guard(RuntimeCounter::StreamListenerUdpFlow),
    })
  }

  #[tokio::test]
  async fn unroutable_udp_sni_datagram_preserves_existing_flow() -> anyhow::Result<()> {
    let state = app_handle().await;
    let config = sni_only_udp_listener(1);
    let victim_peer: SocketAddr = "127.0.0.1:49152".parse()?;
    let attacker_peer: SocketAddr = "127.0.0.1:49153".parse()?;
    let downstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let mut flows = HashMap::from([(victim_peer, seeded_udp_flow(&state, "tenant-a").await?)]);

    proxy_udp_datagram(
      &downstream,
      &mut flows,
      &config,
      &state,
      attacker_peer,
      b"not a QUIC Initial",
    )
    .await?;

    assert!(
      flows.contains_key(&victim_peer),
      "unroutable new UDP peer must not evict an established flow"
    );
    assert!(
      !flows.contains_key(&attacker_peer),
      "unroutable new UDP peer must not create a replacement flow"
    );
    Ok(())
  }
}
