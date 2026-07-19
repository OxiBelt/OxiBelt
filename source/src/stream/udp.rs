//! UDP stream listener runtime.
//! UDP flows are pinned by downstream socket address and expire on idle timeout or capacity pressure.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::{StreamListenerConfig, StreamNetwork, UdpBatchMode};
use crate::lifecycle::TaskRegistry;
use crate::limits::ConnectionPermit;
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::sni_forward::quic::extract_initial_sni;
use crate::state::AppHandle;
use crate::stream::sni::select_stream_route;
use crate::stream::target::resolve_stream_route_target;

const MAX_UDP_DATAGRAM_BYTES: usize = 65_535;

pub(super) fn bind_udp_socket(bind: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
  if let Some(socket) = crate::netport_switcher::bind_udp_socket(
    bind,
    crate::netport_switcher::SwitcherUdpOptions::simple(),
    "stream UDP",
    0,
  )? {
    return Ok(socket);
  }
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
  mut quiesce: watch::Receiver<bool>,
  mut shutdown: watch::Receiver<bool>,
  connections: TaskRegistry,
) -> anyhow::Result<()> {
  let bind = socket.local_addr()?;
  info!(name = %config.name, bind = %bind, "UDP stream listener started");
  let socket = Arc::new(socket);
  let mut flows: HashMap<SocketAddr, UdpFlowSession> = HashMap::new();
  let mut buffer = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
  let expiry_interval = Duration::from_millis(config.idle_timeout_ms.div_ceil(2).clamp(10, 5_000));
  let mut expire = tokio::time::interval(expiry_interval);
  let mut udp_batch = udp_batch_enabled(config.udp_batch);
  let mut quiescing = *quiesce.borrow();
  let mut new_flow_rate = udp_rate_bucket(
    config.udp_new_flow_rate.as_deref(),
    config.udp_new_flow_burst,
  );

  loop {
    tokio::select! {
      biased;
      changed = quiesce.changed() => {
        if changed.is_err() || *quiesce.borrow() {
          quiescing = true;
          info!(name = %config.name, bind = %bind, "UDP stream listener quiesced");
          if flows.is_empty() {
            return Ok(());
          }
        }
      }
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          info!(name = %config.name, bind = %bind, "UDP stream listener stopped");
        }
        force_shutdown_udp_flows(&mut flows, &state, &config.name);
        return Ok(());
      }
      _ = expire.tick() => {
        expire_udp_flows(&mut flows, Duration::from_millis(config.idle_timeout_ms), &state, &config.name);
        if quiescing && flows.is_empty() {
          return Ok(());
        }
      }
      received = recv_udp_datagrams(&socket, &mut buffer, &config, udp_batch) => {
        let datagrams = match received {
          Ok(datagrams) => datagrams,
          Err(error) if config.udp_batch == UdpBatchMode::Auto && udp_batch => {
            warn!(name = %config.name, error = %error, "UDP batch receive failed; falling back to tokio UdpSocket");
            udp_batch = false;
            continue;
          }
          Err(error) => {
            force_shutdown_udp_flows(&mut flows, &state, &config.name);
            return Err(error).context("failed to receive UDP stream datagram");
          }
        };
        for (peer_addr, datagram) in datagrams {
          if let Err(error) = (UdpProxyContext {
            downstream: &socket,
            config: &config,
            state: &state,
            connections: &connections,
          })
          .proxy_datagram(
            &mut flows,
            &mut new_flow_rate,
            peer_addr,
            &datagram,
            !quiescing,
          ).await {
            state.snapshot().metrics.record_stream_udp_datagram_dropped(&config.name);
            warn!(name = %config.name, peer = %peer_addr, error = %error, "UDP stream datagram failed");
          }
        }
      }
    }
  }
}

async fn recv_udp_datagrams(
  socket: &UdpSocket,
  buffer: &mut [u8],
  config: &StreamListenerConfig,
  udp_batch: bool,
) -> anyhow::Result<Vec<(SocketAddr, Vec<u8>)>> {
  if udp_batch {
    let datagrams = crate::stream::udp_batch::recv_from_batch(
      socket,
      config.udp_batch_size,
      MAX_UDP_DATAGRAM_BYTES,
    )
    .await?;
    return Ok(
      datagrams
        .into_iter()
        .map(|datagram| (datagram.peer, datagram.bytes))
        .collect(),
    );
  }
  let (len, peer_addr) = socket.recv_from(buffer).await?;
  Ok(vec![(peer_addr, buffer[..len].to_vec())])
}

struct UdpFlowSession {
  upstream: Arc<UdpSocket>,
  cancel: watch::Sender<bool>,
  target_label: String,
  route_name: String,
  activity: Arc<UdpActivity>,
  rate: Option<UdpRateBucket>,
  _selection: Option<crate::stream::pools::StreamPoolSelection>,
  _connection_permit: ConnectionPermit,
  _introspection_guard: crate::runtime_introspection::RuntimeCounterGuard,
}

impl Drop for UdpFlowSession {
  fn drop(&mut self) {
    let _ = self.cancel.send(true);
  }
}

struct UdpRateBucket {
  tokens: f64,
  last: Instant,
  per_second: f64,
}

struct UdpActivity {
  started: Instant,
  last_millis: AtomicU64,
}

impl UdpActivity {
  fn new() -> Self {
    Self {
      started: Instant::now(),
      last_millis: AtomicU64::new(0),
    }
  }

  fn touch(&self) {
    let elapsed = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    self.last_millis.store(elapsed, Ordering::Relaxed);
  }

  fn idle_for(&self) -> Duration {
    let now = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    Duration::from_millis(now.saturating_sub(self.last_millis.load(Ordering::Relaxed)))
  }

  fn last_millis(&self) -> u64 {
    self.last_millis.load(Ordering::Relaxed)
  }
}

struct UdpProxyContext<'a> {
  downstream: &'a Arc<UdpSocket>,
  config: &'a StreamListenerConfig,
  state: &'a AppHandle,
  connections: &'a TaskRegistry,
}

impl UdpProxyContext<'_> {
  async fn proxy_datagram(
    &self,
    flows: &mut HashMap<SocketAddr, UdpFlowSession>,
    new_flow_rate: &mut Option<UdpRateBucket>,
    peer_addr: SocketAddr,
    datagram: &[u8],
    allow_new_flow: bool,
  ) -> anyhow::Result<()> {
    let downstream = self.downstream;
    let config = self.config;
    let state = self.state;
    let connections = self.connections;
    let known_flow = flows.contains_key(&peer_addr);
    if !udp_flow_admitted(allow_new_flow, known_flow) {
      let metrics = &state.snapshot().metrics;
      metrics.record_stream_udp_flow_admission_rejection(&config.name);
      metrics.record_stream_udp_datagram_dropped(&config.name);
      return Ok(());
    }
    if !known_flow {
      let Some(route) = classify_udp_route(config, datagram) else {
        state
          .snapshot()
          .metrics
          .record_stream_udp_datagram_dropped(&config.name);
        return Ok(());
      };
      if !udp_rate_allows(new_flow_rate.as_mut(), config.udp_new_flow_burst) {
        let metrics = &state.snapshot().metrics;
        metrics.record_stream_udp_flow_admission_rejection(&config.name);
        metrics.record_stream_udp_datagram_dropped(&config.name);
        return Ok(());
      }
      let route_name = route.name.to_string();
      let resolved =
        resolve_stream_route_target(state, StreamNetwork::Udp, route.target, peer_addr).await?;
      let permit = match acquire_udp_flow_permit(state, peer_addr).await {
        Ok(permit) => permit,
        Err(error) => {
          state
            .snapshot()
            .metrics
            .record_stream_udp_flow_admission_rejection(&config.name);
          return Err(error);
        }
      };
      let upstream = Arc::new(UdpSocket::bind(client_bind_addr(resolved.addr)).await?);
      upstream.connect(resolved.addr).await?;
      let upstream_reader = upstream.clone();
      let downstream_writer = downstream.clone();
      let target_label = resolved.label;
      let listener_name = config.name.clone();
      let upstream_listener_name = listener_name.clone();
      let metrics = state.snapshot().metrics.clone();
      let activity = Arc::new(UdpActivity::new());
      let upstream_activity = activity.clone();
      let upstream_udp_batch = udp_batch_enabled(config.udp_batch);
      let upstream_udp_batch_required = config.udp_batch == UdpBatchMode::Required;
      let udp_batch_size = config.udp_batch_size;
      let (cancel, mut cancelled) = watch::channel(false);
      connections.spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
        let mut upstream_udp_batch = upstream_udp_batch;
        loop {
          if upstream_udp_batch {
            let received = tokio::select! {
              biased;
              changed = cancelled.changed() => {
                if changed.is_err() || *cancelled.borrow() {
                  return;
                }
                continue;
              }
              received = crate::stream::udp_batch::recv_connected_batch(
                &upstream_reader,
                udp_batch_size,
                MAX_UDP_DATAGRAM_BYTES,
              ) => received,
            };
            match received {
              Ok(datagrams) if !datagrams.is_empty() => {
                let sent =
                  crate::stream::udp_batch::sendmmsg_to(&downstream_writer, peer_addr, &datagrams)
                    .await
                    .unwrap_or(0);
                let sent = sent.min(datagrams.len());
                let mut forwarded = datagrams[..sent].iter().map(Vec::len).sum::<usize>();
                for datagram in datagrams.iter().skip(sent) {
                  if downstream_writer
                    .send_to(datagram, peer_addr)
                    .await
                    .is_err()
                  {
                    metrics.record_stream_udp_datagram_dropped(&upstream_listener_name);
                    return;
                  }
                  forwarded = forwarded.saturating_add(datagram.len());
                }
                upstream_activity.touch();
                metrics.add_stream_bytes("udp", forwarded as u64);
                continue;
              }
              Ok(_) => continue,
              Err(_) if upstream_udp_batch_required => return,
              Err(_) => upstream_udp_batch = false,
            }
          }
          let received = tokio::select! {
            biased;
            changed = cancelled.changed() => {
              if changed.is_err() || *cancelled.borrow() {
                return;
              }
              continue;
            }
            received = upstream_reader.recv(&mut buf) => received,
          };
          match received {
            Ok(len) => {
              if downstream_writer
                .send_to(&buf[..len], peer_addr)
                .await
                .is_err()
              {
                metrics.record_stream_udp_datagram_dropped(&upstream_listener_name);
                break;
              }
              upstream_activity.touch();
              metrics.add_stream_bytes("udp", len as u64);
            }
            Err(_) => break,
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
          let metrics = &state.snapshot().metrics;
          metrics.record_stream_session_end("udp", &config.name, &session.route_name, false);
          metrics.record_stream_udp_flow_evicted(&config.name);
        }
      }
      flows.insert(
        peer_addr,
        UdpFlowSession {
          upstream,
          cancel,
          target_label,
          route_name,
          activity,
          rate: udp_rate_bucket(
            config.udp_datagram_rate.as_deref(),
            config.udp_datagram_burst,
          ),
          _selection: resolved.selection,
          _connection_permit: permit,
          _introspection_guard: introspection_guard,
        },
      );
      state
        .snapshot()
        .metrics
        .record_stream_udp_flow_created(&config.name);
    }

    if let Some(session) = flows.get_mut(&peer_addr) {
      if !udp_rate_allows(session.rate.as_mut(), config.udp_datagram_burst) {
        let metrics = &state.snapshot().metrics;
        metrics.record_stream_udp_rate_limited(&config.name);
        metrics.record_stream_udp_datagram_dropped(&config.name);
        return Ok(());
      }
      session.upstream.send(datagram).await?;
      session.activity.touch();
      state
        .snapshot()
        .metrics
        .add_stream_bytes("udp", datagram.len() as u64);
    }
    Ok(())
  }
}

fn udp_flow_admitted(allow_new_flow: bool, known_flow: bool) -> bool {
  allow_new_flow || known_flow
}

fn classify_udp_route<'a>(
  config: &'a StreamListenerConfig,
  datagram: &[u8],
) -> Option<crate::stream::sni::StreamRoute<'a>> {
  let sni = if config.sni_rules.is_empty() {
    None
  } else {
    extract_initial_sni(datagram).ok().and_then(|(sni, _)| sni)
  };
  select_stream_route(config, sni.as_deref())
}

async fn acquire_udp_flow_permit(
  state: &AppHandle,
  peer_addr: SocketAddr,
) -> anyhow::Result<ConnectionPermit> {
  let snapshot = state.snapshot();
  snapshot
    .limits
    .acquire_connection_async(
      peer_addr.ip(),
      &snapshot.config.limits,
      &snapshot.config.connection_limits,
    )
    .await
    .map_err(|status| anyhow::anyhow!("UDP stream flow rejected with status {status}"))
}

fn udp_rate_bucket(rate: Option<&str>, burst: u32) -> Option<UdpRateBucket> {
  let per_second = crate::limits::parse_rate(rate?).ok()?.per_second();
  Some(UdpRateBucket {
    tokens: f64::from(burst),
    last: Instant::now(),
    per_second,
  })
}

fn udp_rate_allows(bucket: Option<&mut UdpRateBucket>, burst: u32) -> bool {
  let Some(bucket) = bucket else {
    return true;
  };
  let now = Instant::now();
  let elapsed = now.duration_since(bucket.last).as_secs_f64();
  bucket.last = now;
  bucket.tokens = (bucket.tokens + elapsed * bucket.per_second).min(f64::from(burst.max(1)));
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
  let expired = flows
    .iter()
    .filter_map(|(peer, session)| (session.activity.idle_for() >= idle_timeout).then_some(*peer))
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
      let metrics = &state.snapshot().metrics;
      metrics.record_stream_session_end("udp", listener_name, &session.route_name, true);
      metrics.record_stream_udp_flow_expired(listener_name);
    }
  }
}

fn force_shutdown_udp_flows(
  flows: &mut HashMap<SocketAddr, UdpFlowSession>,
  state: &AppHandle,
  listener_name: &str,
) {
  let metrics = &state.snapshot().metrics;
  metrics.record_stream_udp_flows_forced_shutdown(listener_name, flows.len());
  for (_, session) in flows.drain() {
    metrics.record_stream_session_end("udp", listener_name, &session.route_name, false);
  }
}

fn oldest_flow(flows: &HashMap<SocketAddr, UdpFlowSession>) -> Option<SocketAddr> {
  flows
    .iter()
    .min_by_key(|(_, session)| session.activity.last_millis())
    .map(|(peer, _)| *peer)
}

fn client_bind_addr(remote: SocketAddr) -> SocketAddr {
  match remote {
    SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
    SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
  }
}

fn udp_batch_enabled(mode: UdpBatchMode) -> bool {
  match mode {
    UdpBatchMode::Off => false,
    UdpBatchMode::Auto | UdpBatchMode::Required => cfg!(target_os = "linux"),
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
      udp_datagram_burst: 0,
      udp_new_flow_rate: None,
      udp_new_flow_burst: 0,
      udp_batch: crate::config::UdpBatchMode::Auto,
      udp_batch_size: 16,
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
    let (cancel, _cancelled) = watch::channel(false);
    Ok(UdpFlowSession {
      upstream,
      cancel,
      target_label: "127.0.0.1:443".to_string(),
      route_name: route_name.to_string(),
      activity: Arc::new(UdpActivity::new()),
      rate: None,
      _selection: None,
      _connection_permit: acquire_udp_flow_permit(state, "127.0.0.1:49152".parse()?).await?,
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
    let connections = TaskRegistry::default();
    let mut new_flow_rate = None;

    UdpProxyContext {
      downstream: &downstream,
      config: &config,
      state: &state,
      connections: &connections,
    }
    .proxy_datagram(
      &mut flows,
      &mut new_flow_rate,
      attacker_peer,
      b"not a QUIC Initial",
      true,
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

  #[tokio::test]
  async fn datagram_hot_path_leaves_expiry_to_interval_sweep() -> anyhow::Result<()> {
    let state = app_handle().await;
    let config = sni_only_udp_listener(1);
    let victim_peer: SocketAddr = "127.0.0.1:49152".parse()?;
    let attacker_peer: SocketAddr = "127.0.0.1:49153".parse()?;
    let downstream = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let mut victim = seeded_udp_flow(&state, "tenant-a").await?;
    victim.activity = Arc::new(UdpActivity {
      started: Instant::now() - Duration::from_secs(2),
      last_millis: AtomicU64::new(0),
    });
    let mut flows = HashMap::from([(victim_peer, victim)]);
    let connections = TaskRegistry::default();
    let mut new_flow_rate = None;

    UdpProxyContext {
      downstream: &downstream,
      config: &config,
      state: &state,
      connections: &connections,
    }
    .proxy_datagram(
      &mut flows,
      &mut new_flow_rate,
      attacker_peer,
      b"not a QUIC Initial",
      true,
    )
    .await?;

    assert!(
      flows.contains_key(&victim_peer),
      "per-datagram processing must not scan the complete flow table"
    );
    expire_udp_flows(&mut flows, Duration::from_secs(1), &state, &config.name);
    assert!(
      flows.is_empty(),
      "the listener interval sweep must still reap idle flows"
    );
    Ok(())
  }

  #[test]
  fn quiescing_udp_listener_keeps_existing_flow_and_rejects_new_peer() {
    assert!(udp_flow_admitted(false, true));
    assert!(!udp_flow_admitted(false, false));
    assert!(udp_flow_admitted(true, false));
  }

  #[test]
  fn listener_new_flow_bucket_is_bounded_and_refills() {
    let mut bucket = UdpRateBucket {
      tokens: 1.0,
      last: Instant::now(),
      per_second: 10.0,
    };
    assert!(udp_rate_allows(Some(&mut bucket), 1));
    assert!(!udp_rate_allows(Some(&mut bucket), 1));
    bucket.last = Instant::now() - Duration::from_secs(1);
    assert!(udp_rate_allows(Some(&mut bucket), 1));
    assert!(bucket.tokens <= 1.0);
  }

  #[test]
  fn upstream_activity_prevents_downstream_only_idle_expiry() {
    let activity = UdpActivity::new();
    std::thread::sleep(Duration::from_millis(2));
    activity.touch();
    assert!(activity.idle_for() < Duration::from_millis(20));
  }
}
