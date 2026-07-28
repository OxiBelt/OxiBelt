//! UDP stream listener runtime.
//! UDP flows are pinned by downstream socket address and expire on idle timeout or capacity pressure.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::config::{
  MAX_SHARED_UDP_RATE_PER_SECOND, MIN_SHARED_UDP_RATE_PER_SECOND, SHARED_UDP_RENEW_BATCH_SIZE,
  StreamListenerConfig, StreamNetwork, UdpBatchMode, UdpFlowState, shared_udp_flow_lease_timing_ms,
  shared_udp_renew_parallelism,
};
use crate::lifecycle::TaskRegistry;
use crate::limits::ConnectionPermit;
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::shared_state::{
  UdpFlowClaimOutcome, UdpFlowClaimRequest, UdpFlowLease, UdpFlowLookupOutcome, UdpFlowOwner,
  UdpFlowRateLimit, UdpFlowReleaseOutcome, UdpFlowStore, UdpFlowTokenOutcome, UdpFlowTokenRequest,
  UdpFlowTouchOutcome, UdpFlowTouchRequest,
};
use crate::sni_forward::quic::extract_initial_sni;
use crate::state::AppHandle;
use crate::stream::SharedUdpListenerRuntime;
use crate::stream::sni::{
  select_default_stream_route, select_stream_route, select_stream_rule_by_name,
};
use crate::stream::target::{
  ResolvedStreamTarget, SelectedStreamTarget, resolve_stream_route_target,
  select_restored_stream_route_target, select_stream_route_target,
};
use crate::stream::udp_flow_state::{
  listener_scope_material, peer_material, restore_target_identity, routing_fingerprint,
  target_for_selection,
};

const MAX_UDP_DATAGRAM_BYTES: usize = 65_535;
const MAX_UDP_FLOW_MAINTENANCE_BATCH: usize = SHARED_UDP_RENEW_BATCH_SIZE as usize;
const MAX_SHARED_TOKEN_LEASE: u32 = 16;

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
  shared_udp_runtime: Option<SharedUdpListenerRuntime>,
  mut quiesce: watch::Receiver<bool>,
  mut shutdown: watch::Receiver<bool>,
  connections: TaskRegistry,
) -> anyhow::Result<()> {
  let bind = socket.local_addr()?;
  info!(name = %config.name, bind = %bind, "UDP stream listener started");
  let socket = Arc::new(socket);
  let mut flows: HashMap<SocketAddr, UdpFlowSession> = HashMap::new();
  let mut buffer = vec![0u8; MAX_UDP_DATAGRAM_BYTES];
  let mut udp_batch = udp_batch_enabled(config.udp_batch);
  let mut quiescing = *quiesce.borrow();
  let durable = durable_udp_context(shared_udp_runtime.as_ref(), &config)?;
  let expiry_interval = Duration::from_millis(config.idle_timeout_ms.div_ceil(2).clamp(10, 5_000));
  let maintenance_interval = durable
    .as_ref()
    .map(|context| {
      context
        .renew_interval
        .checked_div(2)
        .unwrap_or(Duration::from_millis(10))
        .max(Duration::from_millis(10))
        .min(expiry_interval)
    })
    .unwrap_or(expiry_interval);
  let mut expire = tokio::time::interval(maintenance_interval);
  let (renewal_tx, mut renewal_rx) = mpsc::channel(1);
  let mut renewal_inflight = false;
  let (release_tx, release_rx) = mpsc::channel(4);
  spawn_udp_flow_release_worker(
    release_rx,
    state.clone(),
    config.name.clone(),
    connections.clone(),
  );
  let mut new_flow_rate = (durable.is_none())
    .then(|| {
      udp_rate_bucket(
        config.udp_new_flow_rate.as_deref(),
        config.udp_new_flow_burst,
      )
    })
    .flatten();

  loop {
    tokio::select! {
      biased;
      changed = quiesce.changed() => {
        if changed.is_err() || *quiesce.borrow() {
          quiescing = true;
          info!(name = %config.name, bind = %bind, "UDP stream listener quiesced");
          if durable.is_some() {
            release_and_shutdown_udp_flows(&mut flows, &state, &config.name, false).await;
            return Ok(());
          }
          if flows.is_empty() {
            return Ok(());
          }
        }
      }
      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          info!(name = %config.name, bind = %bind, "UDP stream listener stopped");
        }
        release_and_shutdown_udp_flows(&mut flows, &state, &config.name, true).await;
        return Ok(());
      }
      Some(message) = renewal_rx.recv(), if renewal_inflight => {
        match message {
          UdpFlowRenewalMessage::Batch(batch) => {
            apply_udp_flow_renewals(&mut flows, vec![batch], &state, &config.name);
          }
          UdpFlowRenewalMessage::Complete => renewal_inflight = false,
        }
      }
      _ = expire.tick() => {
        let renewals = maintain_udp_flows(
          &mut flows,
          Duration::from_millis(config.idle_timeout_ms),
          durable.as_ref(),
          &state,
          &config,
          &release_tx,
        ).await;
        if !renewal_inflight
          && !renewals.is_empty()
          && let Some(context) = durable.as_ref()
        {
          spawn_udp_flow_renewals(
            context.clone(),
            renewals,
            renewal_tx.clone(),
            &connections,
          );
          renewal_inflight = true;
        }
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
            release_and_shutdown_udp_flows(&mut flows, &state, &config.name, true).await;
            return Err(error).context("failed to receive UDP stream datagram");
          }
        };
        for (peer_addr, datagram) in datagrams {
          if let Err(error) = (UdpProxyContext {
            downstream: &socket,
            config: &config,
            state: &state,
            connections: &connections,
            durable: durable.as_ref(),
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
  durable: Option<DurableUdpFlowSession>,
  _selection: Option<crate::stream::pools::StreamPoolSelection>,
  _connection_permit: ConnectionPermit,
  _introspection_guard: crate::runtime_introspection::RuntimeCounterGuard,
}

impl Drop for UdpFlowSession {
  fn drop(&mut self) {
    let _ = self.cancel.send(true);
  }
}

#[derive(Clone)]
struct DurableUdpContext {
  store: UdpFlowStore,
  owner: UdpFlowOwner,
  owner_ttl: Duration,
  idle_ttl: Duration,
  renew_interval: Duration,
  renew_parallelism: usize,
}

struct DurableUdpFlowSession {
  store: UdpFlowStore,
  lease: UdpFlowLease,
  local_tokens: u32,
  fence: Arc<UdpFlowFence>,
  renew_at: Instant,
  owner_ttl: Duration,
  renew_interval: Duration,
  checkpoint_activity_millis: u64,
}

struct PendingUdpFlowRenewal {
  peer: SocketAddr,
  checkpoint_activity_millis: u64,
  request: UdpFlowTouchRequest,
}

struct UdpFlowRenewalBatch {
  started: Instant,
  entries: Vec<(SocketAddr, u64, UdpFlowLease)>,
  outcome: anyhow::Result<Vec<UdpFlowTouchOutcome>>,
}

enum UdpFlowRenewalMessage {
  Batch(UdpFlowRenewalBatch),
  Complete,
}

struct UdpFlowFence {
  started: Instant,
  valid_until_millis: AtomicU64,
  fenced: AtomicBool,
}

impl UdpFlowFence {
  fn new(valid_until: Instant) -> Self {
    let started = Instant::now();
    Self {
      started,
      valid_until_millis: AtomicU64::new(
        valid_until
          .saturating_duration_since(started)
          .as_millis()
          .min(u128::from(u64::MAX)) as u64,
      ),
      fenced: AtomicBool::new(false),
    }
  }

  fn set_valid_until(&self, valid_until: Instant) {
    self.valid_until_millis.store(
      valid_until
        .saturating_duration_since(self.started)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64,
      Ordering::Release,
    );
  }

  fn fence(&self) {
    self.fenced.store(true, Ordering::Release);
  }

  fn is_valid(&self) -> bool {
    if self.fenced.load(Ordering::Acquire) {
      return false;
    }
    let elapsed = self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    elapsed < self.valid_until_millis.load(Ordering::Acquire)
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
  durable: Option<&'a DurableUdpContext>,
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
    let config = self.config;
    let state = self.state;
    if flows
      .get(&peer_addr)
      .and_then(|session| session.durable.as_ref())
      .is_some_and(|durable| !durable.fence.is_valid())
      && let Some(session) = flows.remove(&peer_addr)
    {
      state
        .snapshot()
        .metrics
        .record_stream_udp_flow_fence_rejection(&config.name);
      release_udp_session(session, state, &config.name, false, true).await;
    }
    let known_flow = flows.contains_key(&peer_addr);
    if !udp_flow_admitted(allow_new_flow, known_flow) {
      let metrics = &state.snapshot().metrics;
      metrics.record_stream_udp_flow_admission_rejection(&config.name);
      metrics.record_stream_udp_datagram_dropped(&config.name);
      return Ok(());
    }
    if !known_flow {
      let Some((session, restored)) = self
        .establish_udp_flow(new_flow_rate, peer_addr, datagram)
        .await?
      else {
        return Ok(());
      };
      if self.durable.is_some() && flows.len() >= config.max_udp_flows {
        release_udp_session(session, state, &config.name, false, false).await;
        record_udp_admission_rejection(state, &config.name);
        return Ok(());
      }
      while self.durable.is_none() && flows.len() >= config.max_udp_flows {
        let Some(oldest) = oldest_flow(flows) else {
          break;
        };
        if let Some(session) = flows.remove(&oldest) {
          let metrics = &state.snapshot().metrics;
          metrics.record_stream_session_end("udp", &config.name, &session.route_name, false);
          metrics.record_stream_udp_flow_evicted(&config.name);
        }
      }
      flows.insert(peer_addr, session);
      let metrics = &state.snapshot().metrics;
      if restored {
        metrics.record_stream_udp_flow_restored(&config.name);
      } else {
        metrics.record_stream_udp_flow_created(&config.name);
      }
    }

    if let Some(session) = flows.get_mut(&peer_addr) {
      let rate_decision =
        if let (Some(context), Some(durable)) = (self.durable, session.durable.as_mut()) {
          durable_udp_rate_allows(context, durable, config).await?
        } else {
          if udp_rate_allows(session.rate.as_mut(), config.udp_datagram_burst) {
            DurableRateDecision::Allowed
          } else {
            DurableRateDecision::RateLimited
          }
        };
      match rate_decision {
        DurableRateDecision::Allowed => {}
        DurableRateDecision::RateLimited => {
          let metrics = &state.snapshot().metrics;
          metrics.record_stream_udp_rate_limited(&config.name);
          metrics.record_stream_udp_datagram_dropped(&config.name);
          return Ok(());
        }
        DurableRateDecision::Fenced => {
          let metrics = &state.snapshot().metrics;
          metrics.record_stream_udp_flow_fence_rejection(&config.name);
          metrics.record_stream_udp_datagram_dropped(&config.name);
          return Ok(());
        }
      }
      if session
        .durable
        .as_ref()
        .is_some_and(|durable| !durable.fence.is_valid())
      {
        let metrics = &state.snapshot().metrics;
        metrics.record_stream_udp_flow_fence_rejection(&config.name);
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

  async fn establish_udp_flow(
    &self,
    new_flow_rate: &mut Option<UdpRateBucket>,
    peer_addr: SocketAddr,
    datagram: &[u8],
  ) -> anyhow::Result<Option<(UdpFlowSession, bool)>> {
    let prepared = if let Some(durable) = self.durable {
      match prepare_durable_udp_flow(durable, self.state, self.config, peer_addr, datagram).await {
        Ok(Some(prepared)) => prepared,
        Ok(None) => {
          record_udp_admission_rejection(self.state, &self.config.name);
          return Ok(None);
        }
        Err(error) => {
          self
            .state
            .snapshot()
            .metrics
            .record_stream_udp_flow_persistence_error(&self.config.name);
          return Err(error);
        }
      }
    } else {
      let Some(route) = classify_udp_route(self.config, datagram) else {
        self
          .state
          .snapshot()
          .metrics
          .record_stream_udp_datagram_dropped(&self.config.name);
        return Ok(None);
      };
      if !udp_rate_allows(new_flow_rate.as_mut(), self.config.udp_new_flow_burst) {
        record_udp_admission_rejection(self.state, &self.config.name);
        return Ok(None);
      }
      let route_name = route.name.to_string();
      let resolved =
        resolve_stream_route_target(self.state, StreamNetwork::Udp, route.target, peer_addr)
          .await?;
      PreparedUdpFlow {
        route_name,
        target: PreparedStreamTarget::Resolved(resolved),
        durable: None,
        restored: false,
      }
    };

    let permit =
      match acquire_udp_flow_permit(self.state, peer_addr, prepared.durable.as_ref()).await {
        Ok(permit) => permit,
        Err(error) => {
          if let Some(durable) = prepared.durable.as_ref() {
            rollback_pre_activation(durable).await;
          }
          record_udp_admission_rejection(self.state, &self.config.name);
          return Err(error);
        }
      };
    let restored = prepared.restored;
    match build_udp_flow_session(
      self,
      peer_addr,
      prepared.route_name,
      prepared.target,
      prepared.durable,
      permit,
    )
    .await
    {
      Ok(session) => Ok(Some((session, restored))),
      Err(error) => Err(error),
    }
  }
}

struct PreparedUdpFlow {
  route_name: String,
  target: PreparedStreamTarget,
  durable: Option<PreparedDurableUdpFlow>,
  restored: bool,
}

enum PreparedStreamTarget {
  Resolved(ResolvedStreamTarget),
  Selected(SelectedStreamTarget),
}

impl PreparedStreamTarget {
  async fn resolve(self) -> anyhow::Result<ResolvedStreamTarget> {
    match self {
      Self::Resolved(resolved) => Ok(resolved),
      Self::Selected(selected) => selected.resolve().await,
    }
  }
}

struct PreparedDurableUdpFlow {
  context: DurableUdpContext,
  lease: UdpFlowLease,
  owner_valid_until: Instant,
  created: bool,
}

enum DurableRateDecision {
  Allowed,
  RateLimited,
  Fenced,
}

fn durable_udp_context(
  shared_udp_runtime: Option<&SharedUdpListenerRuntime>,
  config: &StreamListenerConfig,
) -> anyhow::Result<Option<DurableUdpContext>> {
  if config.udp_flow_state == UdpFlowState::Local {
    return Ok(None);
  }
  let shared_udp_runtime = shared_udp_runtime
    .context("shared-required UDP flow state has no active shared-state runtime")?;
  let shared = shared_udp_runtime.shared_state.as_ref();
  let shared_state_config = &shared_udp_runtime.shared_state_config;
  let store = shared
    .udp_flow_store()
    .context("shared-required UDP flow state has no configured durable store")?;
  let operation_timeout_ms = shared_state_config.operation_timeout_ms;
  let idle_ttl = Duration::from_millis(config.idle_timeout_ms);
  let (renew_interval_ms, owner_ttl_ms) =
    shared_udp_flow_lease_timing_ms(operation_timeout_ms, config.idle_timeout_ms);
  let renew_interval = Duration::from_millis(renew_interval_ms);
  let owner_ttl = Duration::from_millis(owner_ttl_ms);
  let backend_name = shared_state_config
    .udp_flows_backend
    .as_deref()
    .context("shared-required UDP flow state has no configured backend name")?;
  let backend = shared_state_config
    .backends
    .iter()
    .find(|backend| backend.name == backend_name)
    .context("shared-required UDP flow state backend is absent from active config")?;
  let renew_parallelism = usize::try_from(shared_udp_renew_parallelism(backend.max_connections))
    .context("shared-required UDP renewal parallelism is too large")?;
  let mut incarnation = [0_u8; 32];
  crate::crypto::random_fill(&mut incarnation)
    .context("failed to generate durable UDP listener incarnation")?;
  let mut owner_material =
    Vec::with_capacity(shared.instance_id().len() + config.name.len() + incarnation.len() + 2);
  owner_material.extend_from_slice(shared.instance_id().as_bytes());
  owner_material.push(0);
  owner_material.extend_from_slice(config.name.as_bytes());
  owner_material.push(0);
  owner_material.extend_from_slice(&incarnation);
  let owner = store.owner_for(&owner_material)?;
  Ok(Some(DurableUdpContext {
    store,
    owner,
    owner_ttl,
    idle_ttl,
    renew_interval,
    renew_parallelism,
  }))
}

async fn prepare_durable_udp_flow(
  context: &DurableUdpContext,
  state: &AppHandle,
  listener: &StreamListenerConfig,
  peer_addr: SocketAddr,
  datagram: &[u8],
) -> anyhow::Result<Option<PreparedUdpFlow>> {
  let snapshot = state.snapshot();
  let routing_fingerprint = routing_fingerprint(&snapshot.config, listener);
  let identity = context.store.derive_identity(
    &listener_scope_material(listener),
    &peer_material(peer_addr),
  )?;
  let generation = context.store.generation_for(&routing_fingerprint)?;
  let lookup = context.store.lookup(&identity, generation).await?;
  let mut newly_selected = None;
  let proposed_target = match lookup {
    UdpFlowLookupOutcome::Missing { .. } => {
      let Some(route) = classify_udp_route(listener, datagram) else {
        snapshot
          .metrics
          .record_stream_udp_datagram_dropped(&listener.name);
        return Ok(None);
      };
      let selected =
        select_stream_route_target(&snapshot, StreamNetwork::Udp, route.target, peer_addr)?;
      let target = target_for_selection(&context.store, route, &selected.identity())?;
      newly_selected = Some((route.name.to_string(), selected));
      target
    }
    UdpFlowLookupOutcome::Found(record) => record.target().clone(),
    UdpFlowLookupOutcome::GenerationMismatch { .. } => {
      snapshot
        .metrics
        .record_stream_udp_flow_fence_rejection(&listener.name);
      return Ok(None);
    }
  };
  let claim_started = Instant::now();
  let claim = context
    .store
    .claim_or_create(UdpFlowClaimRequest {
      identity,
      generation,
      owner: context.owner.clone(),
      proposed_target,
      max_flows: listener.max_udp_flows,
      owner_ttl: context.owner_ttl,
      idle_ttl: context.idle_ttl,
      initial_tokens: if listener.udp_datagram_rate.is_some() {
        listener.udp_datagram_burst.max(1)
      } else {
        0
      },
      new_flow_rate: durable_rate_limit(
        listener.udp_new_flow_rate.as_deref(),
        listener.udp_new_flow_burst,
      )?,
    })
    .await?;
  let (lease, restored) = match claim {
    UdpFlowClaimOutcome::Created(lease) => (lease, false),
    UdpFlowClaimOutcome::Recovered(lease) | UdpFlowClaimOutcome::Owned(lease) => (lease, true),
    UdpFlowClaimOutcome::Busy { .. } => {
      state
        .snapshot()
        .metrics
        .record_stream_udp_flow_fence_rejection(&listener.name);
      return Ok(None);
    }
    UdpFlowClaimOutcome::CapacityReached { .. } | UdpFlowClaimOutcome::RateLimited { .. } => {
      return Ok(None);
    }
    UdpFlowClaimOutcome::GenerationMismatch { .. } => {
      state
        .snapshot()
        .metrics
        .record_stream_udp_flow_fence_rejection(&listener.name);
      return Ok(None);
    }
  };

  let (route_name, selected) = if !restored {
    let Some(prepared) = newly_selected else {
      let _ = context.store.abort_created(&lease).await;
      anyhow::bail!("durable UDP flow creation lost its active target");
    };
    prepared
  } else {
    match restore_durable_udp_target(context, &snapshot, listener, lease.target()) {
      Ok(restored) => restored,
      Err(error) => {
        let _ = context.store.release_if_generation(&lease).await;
        return Err(error);
      }
    }
  };
  Ok(Some(PreparedUdpFlow {
    route_name,
    target: PreparedStreamTarget::Selected(selected),
    durable: Some(PreparedDurableUdpFlow {
      context: context.clone(),
      owner_valid_until: claim_started + confirmed_owner_duration(&lease, context.owner_ttl),
      lease,
      created: !restored,
    }),
    restored,
  }))
}

fn restore_durable_udp_target(
  context: &DurableUdpContext,
  snapshot: &crate::state::AppSnapshot,
  listener: &StreamListenerConfig,
  target: &crate::shared_state::UdpFlowTarget,
) -> anyhow::Result<(String, SelectedStreamTarget)> {
  let config = &snapshot.config;
  let mut routes = Vec::with_capacity(listener.sni_rules.len() + 1);
  routes.extend(select_default_stream_route(listener));
  routes.extend(
    listener
      .sni_rules
      .iter()
      .filter_map(|rule| select_stream_rule_by_name(listener, &rule.name)),
  );
  for route in routes {
    let Ok(identity) = restore_target_identity(&context.store, config, route, target) else {
      continue;
    };
    let selected =
      select_restored_stream_route_target(snapshot, StreamNetwork::Udp, route.target, &identity)?;
    return Ok((route.name.to_string(), selected));
  }
  anyhow::bail!("durable UDP flow route or target is absent from the active configuration")
}

async fn build_udp_flow_session(
  context: &UdpProxyContext<'_>,
  peer_addr: SocketAddr,
  route_name: String,
  target: PreparedStreamTarget,
  durable: Option<PreparedDurableUdpFlow>,
  permit: ConnectionPermit,
) -> anyhow::Result<UdpFlowSession> {
  let release_on_error = durable.as_ref().map(|prepared| {
    (
      prepared.context.store.clone(),
      prepared.lease.clone(),
      prepared.created,
    )
  });
  let result = async {
    let resolved = target.resolve().await?;
    let upstream = Arc::new(UdpSocket::bind(client_bind_addr(resolved.addr)).await?);
    upstream.connect(resolved.addr).await?;
    let upstream_reader = upstream.clone();
    let downstream_writer = context.downstream.clone();
    let target_label = resolved.label;
    let listener_name = context.config.name.clone();
    let upstream_listener_name = listener_name.clone();
    let metrics = context.state.snapshot().metrics.clone();
    let activity = Arc::new(UdpActivity::new());
    let upstream_activity = activity.clone();
    let upstream_udp_batch = udp_batch_enabled(context.config.udp_batch);
    let upstream_udp_batch_required = context.config.udp_batch == UdpBatchMode::Required;
    let udp_batch_size = context.config.udp_batch_size;
    let (cancel, mut cancelled) = watch::channel(false);
    let durable = durable.map(|prepared| {
      let now = Instant::now();
      let first_renewal = prepared
        .context
        .renew_interval
        .checked_div(2)
        .unwrap_or(prepared.context.renew_interval);
      DurableUdpFlowSession {
        store: prepared.context.store,
        lease: prepared.lease,
        local_tokens: 0,
        fence: Arc::new(UdpFlowFence::new(prepared.owner_valid_until)),
        renew_at: now + first_renewal,
        owner_ttl: prepared.context.owner_ttl,
        renew_interval: prepared.context.renew_interval,
        checkpoint_activity_millis: 0,
      }
    });
    if durable
      .as_ref()
      .is_some_and(|durable| !durable.fence.is_valid())
    {
      anyhow::bail!("durable UDP owner lease expired during flow setup");
    }
    let upstream_fence = durable.as_ref().map(|durable| durable.fence.clone());
    context.connections.spawn(async move {
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
              if upstream_fence
                .as_ref()
                .is_some_and(|fence| !fence.is_valid())
              {
                return;
              }
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
            if upstream_fence
              .as_ref()
              .is_some_and(|fence| !fence.is_valid())
            {
              return;
            }
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
    let introspection_guard = context
      .state
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
    Ok(UdpFlowSession {
      upstream,
      cancel,
      target_label,
      route_name,
      activity,
      rate: context
        .durable
        .is_none()
        .then(|| {
          udp_rate_bucket(
            context.config.udp_datagram_rate.as_deref(),
            context.config.udp_datagram_burst,
          )
        })
        .flatten(),
      durable,
      _selection: resolved.selection,
      _connection_permit: permit,
      _introspection_guard: introspection_guard,
    })
  }
  .await;
  if result.is_err()
    && let Some((store, lease, created)) = release_on_error
  {
    if created {
      let _ = store.abort_created(&lease).await;
    } else {
      let _ = store.release_if_generation(&lease).await;
    }
  }
  result
}

async fn rollback_pre_activation(prepared: &PreparedDurableUdpFlow) {
  if prepared.created {
    let _ = prepared.context.store.abort_created(&prepared.lease).await;
  } else {
    let _ = prepared
      .context
      .store
      .release_if_generation(&prepared.lease)
      .await;
  }
}

async fn durable_udp_rate_allows(
  context: &DurableUdpContext,
  durable: &mut DurableUdpFlowSession,
  config: &StreamListenerConfig,
) -> anyhow::Result<DurableRateDecision> {
  let Some(rate) = durable_rate_limit(
    config.udp_datagram_rate.as_deref(),
    config.udp_datagram_burst,
  )?
  else {
    return Ok(DurableRateDecision::Allowed);
  };
  if durable.local_tokens > 0 {
    durable.local_tokens -= 1;
    return Ok(DurableRateDecision::Allowed);
  }
  let requested_tokens = rate.burst.clamp(1, MAX_SHARED_TOKEN_LEASE);
  match context
    .store
    .lease_tokens(UdpFlowTokenRequest {
      lease: durable.lease.clone(),
      requested_tokens,
      refill_micros_per_second: rate.refill_micros_per_second,
      burst: rate.burst,
    })
    .await?
  {
    UdpFlowTokenOutcome::Granted { tokens, .. } if tokens > 0 => {
      durable.local_tokens = tokens - 1;
      Ok(DurableRateDecision::Allowed)
    }
    UdpFlowTokenOutcome::Granted { .. } | UdpFlowTokenOutcome::RateLimited { .. } => {
      Ok(DurableRateDecision::RateLimited)
    }
    UdpFlowTokenOutcome::Lost { .. } | UdpFlowTokenOutcome::GenerationMismatch { .. } => {
      durable.fence.fence();
      Ok(DurableRateDecision::Fenced)
    }
  }
}

fn durable_rate_limit(rate: Option<&str>, burst: u32) -> anyhow::Result<Option<UdpFlowRateLimit>> {
  let Some(rate) = rate else {
    return Ok(None);
  };
  let per_second = crate::limits::parse_rate(rate)?.per_second();
  if !(MIN_SHARED_UDP_RATE_PER_SECOND..=MAX_SHARED_UDP_RATE_PER_SECOND as f64).contains(&per_second)
  {
    anyhow::bail!("durable UDP rate is outside the validated shared-state representation");
  }
  let refill_micros_per_second = (per_second * 1_000_000.0).floor() as u64;
  Ok(Some(UdpFlowRateLimit {
    refill_micros_per_second,
    burst: burst.max(1),
  }))
}

fn confirmed_owner_duration(lease: &UdpFlowLease, maximum: Duration) -> Duration {
  let record = lease.record();
  let remaining_ms = record
    .owner_expires_at_ms()
    .saturating_sub(record.server_now_ms())
    .max(0) as u64;
  Duration::from_millis(remaining_ms).min(maximum)
}

fn record_udp_admission_rejection(state: &AppHandle, listener_name: &str) {
  let metrics = &state.snapshot().metrics;
  metrics.record_stream_udp_flow_admission_rejection(listener_name);
  metrics.record_stream_udp_datagram_dropped(listener_name);
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
  durable: Option<&PreparedDurableUdpFlow>,
) -> anyhow::Result<ConnectionPermit> {
  let snapshot = state.snapshot();
  let acquired = if let Some(durable) = durable {
    let marker = durable
      .context
      .store
      .connection_lease_marker(&durable.lease);
    snapshot
      .limits
      .acquire_connection_with_udp_marker_async(
        peer_addr.ip(),
        &snapshot.config.limits,
        &snapshot.config.connection_limits,
        &marker,
      )
      .await
  } else {
    snapshot
      .limits
      .acquire_connection_async(
        peer_addr.ip(),
        &snapshot.config.limits,
        &snapshot.config.connection_limits,
      )
      .await
  };
  acquired.map_err(|status| anyhow::anyhow!("UDP stream flow rejected with status {status}"))
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

async fn maintain_udp_flows(
  flows: &mut HashMap<SocketAddr, UdpFlowSession>,
  idle_timeout: Duration,
  durable_context: Option<&DurableUdpContext>,
  state: &AppHandle,
  listener: &StreamListenerConfig,
  release_tx: &mpsc::Sender<Vec<(UdpFlowStore, UdpFlowLease)>>,
) -> Vec<PendingUdpFlowRenewal> {
  let listener_name = listener.name.as_str();
  let mut releases = Vec::new();
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
      if let Some(release) = deactivate_udp_session(session, state, listener_name, true, true) {
        releases.push(release);
      }
    }
  }
  queue_udp_flow_releases(releases, state, listener_name, release_tx);

  let Some(context) = durable_context else {
    return Vec::new();
  };
  let snapshot = state.snapshot();
  let generation = match context
    .store
    .generation_for(&routing_fingerprint(&snapshot.config, listener))
  {
    Ok(generation) => generation,
    Err(error) => {
      snapshot
        .metrics
        .record_stream_udp_flow_persistence_error(listener_name);
      warn!(name = %listener_name, error = %error, "failed to fingerprint durable UDP flow generation");
      return Vec::new();
    }
  };
  drop(snapshot);

  let now = Instant::now();
  let fenced = flows
    .iter()
    .filter_map(|(peer, session)| {
      let durable = session.durable.as_ref()?;
      (durable.lease.generation() != generation || !durable.fence.is_valid()).then_some(*peer)
    })
    .collect::<Vec<_>>();
  let mut releases = Vec::new();
  for peer in fenced {
    if let Some(session) = flows.remove(&peer) {
      state
        .snapshot()
        .metrics
        .record_stream_udp_flow_fence_rejection(listener_name);
      if let Some(release) = deactivate_udp_session(session, state, listener_name, false, true) {
        releases.push(release);
      }
    }
  }
  queue_udp_flow_releases(releases, state, listener_name, release_tx);

  flows
    .iter()
    .filter_map(|(peer, session)| {
      let durable = session.durable.as_ref()?;
      (now >= durable.renew_at).then(|| {
        let checkpoint_activity_millis = session.activity.last_millis();
        PendingUdpFlowRenewal {
          peer: *peer,
          checkpoint_activity_millis,
          request: UdpFlowTouchRequest {
            lease: durable.lease.clone(),
            owner_ttl: context.owner_ttl,
            idle_ttl: context.idle_ttl,
            touch_idle: checkpoint_activity_millis != durable.checkpoint_activity_millis,
          },
        }
      })
    })
    .collect()
}

fn spawn_udp_flow_renewals(
  context: DurableUdpContext,
  renewals: Vec<PendingUdpFlowRenewal>,
  result_tx: mpsc::Sender<UdpFlowRenewalMessage>,
  connections: &TaskRegistry,
) {
  connections.spawn(async move {
    use futures_util::StreamExt;
    let batches = renewals
      .chunks(MAX_UDP_FLOW_MAINTENANCE_BATCH)
      .map(|chunk| {
        let store = context.store.clone();
        let entries = chunk
          .iter()
          .map(|renewal| {
            (
              renewal.peer,
              renewal.checkpoint_activity_millis,
              renewal.request.lease.clone(),
            )
          })
          .collect::<Vec<_>>();
        let requests = chunk
          .iter()
          .map(|renewal| renewal.request.clone())
          .collect::<Vec<_>>();
        async move {
          let started = Instant::now();
          let outcome = store.renew_and_touch_batch(&requests).await;
          UdpFlowRenewalBatch {
            started,
            entries,
            outcome,
          }
        }
      })
      .collect::<Vec<_>>();
    let mut outcomes =
      futures_util::stream::iter(batches).buffer_unordered(context.renew_parallelism);
    while let Some(batch) = outcomes.next().await {
      if result_tx
        .send(UdpFlowRenewalMessage::Batch(batch))
        .await
        .is_err()
      {
        return;
      }
    }
    let _ = result_tx.send(UdpFlowRenewalMessage::Complete).await;
  });
}

fn apply_udp_flow_renewals(
  flows: &mut HashMap<SocketAddr, UdpFlowSession>,
  batches: Vec<UdpFlowRenewalBatch>,
  state: &AppHandle,
  listener_name: &str,
) {
  let mut lost = Vec::new();
  for batch in batches {
    let outcomes = match batch.outcome {
      Ok(outcomes) if outcomes.len() == batch.entries.len() => outcomes,
      Ok(_) => {
        state
          .snapshot()
          .metrics
          .record_stream_udp_flow_persistence_error(listener_name);
        warn!(name = %listener_name, "durable UDP flow renewal returned a misaligned batch");
        continue;
      }
      Err(error) => {
        state
          .snapshot()
          .metrics
          .record_stream_udp_flow_persistence_error(listener_name);
        warn!(name = %listener_name, error = %error, "durable UDP flow renewal failed");
        continue;
      }
    };
    for ((peer, checkpoint, expected_lease), outcome) in batch.entries.into_iter().zip(outcomes) {
      match outcome {
        UdpFlowTouchOutcome::Renewed(lease) => {
          if let Some(session) = flows.get_mut(&peer)
            && let Some(durable) = session.durable.as_mut()
            && durable.lease == expected_lease
          {
            let valid_until = batch.started + confirmed_owner_duration(&lease, durable.owner_ttl);
            durable.fence.set_valid_until(valid_until);
            let regular_renewal = batch.started
              + durable
                .renew_interval
                .checked_div(2)
                .unwrap_or(durable.renew_interval);
            let last_safe_renewal = valid_until
              .checked_sub(durable.renew_interval)
              .unwrap_or(batch.started);
            durable.renew_at = regular_renewal.min(last_safe_renewal);
            durable.checkpoint_activity_millis = checkpoint;
            durable.lease = lease;
          }
        }
        UdpFlowTouchOutcome::Lost { .. } | UdpFlowTouchOutcome::GenerationMismatch { .. } => {
          lost.push((peer, expected_lease))
        }
      }
    }
  }
  for (peer, expected_lease) in lost {
    let should_remove = flows
      .get(&peer)
      .and_then(|session| session.durable.as_ref())
      .is_some_and(|durable| durable.lease == expected_lease);
    if should_remove && let Some(session) = flows.remove(&peer) {
      if let Some(durable) = session.durable.as_ref() {
        durable.fence.fence();
      }
      let _ = session.cancel.send(true);
      let metrics = &state.snapshot().metrics;
      metrics.record_stream_udp_flow_fence_rejection(listener_name);
      metrics.record_stream_session_end("udp", listener_name, &session.route_name, false);
      metrics.record_stream_udp_flow_ended(listener_name);
    }
  }
}

async fn release_udp_session(
  session: UdpFlowSession,
  state: &AppHandle,
  listener_name: &str,
  expired: bool,
  counted: bool,
) {
  let release = deactivate_udp_session(session, state, listener_name, expired, counted);
  if let Some((store, lease)) = release {
    record_udp_flow_release(store, lease, state, listener_name).await;
  }
}

fn queue_udp_flow_releases(
  releases: Vec<(UdpFlowStore, UdpFlowLease)>,
  state: &AppHandle,
  listener_name: &str,
  release_tx: &mpsc::Sender<Vec<(UdpFlowStore, UdpFlowLease)>>,
) {
  if releases.is_empty() {
    return;
  }
  if let Err(error) = release_tx.try_send(releases) {
    let count = error.into_inner().len();
    state
      .snapshot()
      .metrics
      .record_stream_udp_flow_persistence_error(listener_name);
    warn!(
      name = %listener_name,
      count,
      "durable UDP flow release queue is full; owners will expire at their bounded leases"
    );
  }
}

fn spawn_udp_flow_release_worker(
  mut release_rx: mpsc::Receiver<Vec<(UdpFlowStore, UdpFlowLease)>>,
  state: AppHandle,
  listener_name: String,
  connections: TaskRegistry,
) {
  let registry = connections.clone();
  registry.spawn(async move {
    use futures_util::StreamExt;
    while let Some(releases) = release_rx.recv().await {
      futures_util::stream::iter(releases.into_iter().map(|(store, lease)| {
        let state = &state;
        let listener_name = &listener_name;
        async move {
          record_udp_flow_release(store, lease, state, listener_name).await;
        }
      }))
      .buffer_unordered(16)
      .collect::<Vec<_>>()
      .await;
    }
  });
}

fn deactivate_udp_session(
  session: UdpFlowSession,
  state: &AppHandle,
  listener_name: &str,
  expired: bool,
  counted: bool,
) -> Option<(UdpFlowStore, UdpFlowLease)> {
  if let Some(durable) = session.durable.as_ref() {
    durable.fence.fence();
  }
  let _ = session.cancel.send(true);
  let metrics = &state.snapshot().metrics;
  metrics.record_stream_session_end("udp", listener_name, &session.route_name, expired);
  if expired {
    metrics.record_stream_udp_flow_expired(listener_name);
  } else if counted {
    metrics.record_stream_udp_flow_ended(listener_name);
  }
  session
    .durable
    .as_ref()
    .map(|durable| (durable.store.clone(), durable.lease.clone()))
}

async fn record_udp_flow_release(
  store: UdpFlowStore,
  lease: UdpFlowLease,
  state: &AppHandle,
  listener_name: &str,
) {
  match store.release_if_generation(&lease).await {
    Ok(
      UdpFlowReleaseOutcome::Released { .. }
      | UdpFlowReleaseOutcome::Missing { .. }
      | UdpFlowReleaseOutcome::Lost { .. }
      | UdpFlowReleaseOutcome::GenerationMismatch { .. },
    ) => {}
    Err(error) => {
      state
        .snapshot()
        .metrics
        .record_stream_udp_flow_persistence_error(listener_name);
      warn!(name = %listener_name, error = %error, "durable UDP flow release failed");
    }
  }
}

async fn release_and_shutdown_udp_flows(
  flows: &mut HashMap<SocketAddr, UdpFlowSession>,
  state: &AppHandle,
  listener_name: &str,
  forced: bool,
) {
  let metrics = &state.snapshot().metrics;
  if forced {
    metrics.record_stream_udp_flows_forced_shutdown(listener_name, flows.len());
  } else {
    metrics.record_stream_udp_flows_ended(flows.len());
  }
  let mut releases = Vec::new();
  for (_, session) in flows.drain() {
    if let Some(durable) = session.durable.as_ref() {
      durable.fence.fence();
      releases.push((durable.store.clone(), durable.lease.clone()));
    }
    let _ = session.cancel.send(true);
    metrics.record_stream_session_end("udp", listener_name, &session.route_name, false);
  }
  use futures_util::StreamExt;
  let outcomes = futures_util::stream::iter(
    releases
      .into_iter()
      .map(|(store, lease)| async move { store.release_if_generation(&lease).await }),
  )
  .buffer_unordered(16)
  .collect::<Vec<_>>()
  .await;
  for outcome in outcomes {
    if let Err(error) = outcome {
      metrics.record_stream_udp_flow_persistence_error(listener_name);
      warn!(name = %listener_name, error = %error, "durable UDP flow shutdown release failed");
    }
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

  use crate::config::{Config, ProxyProtocolEgressMode, StreamSniRuleConfig, UdpFlowState};
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
      udp_flow_state: UdpFlowState::Local,
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
      durable: None,
      _selection: None,
      _connection_permit: acquire_udp_flow_permit(state, "127.0.0.1:49152".parse()?, None).await?,
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
      durable: None,
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
    let (release_tx, _release_rx) = mpsc::channel(1);
    let mut new_flow_rate = None;

    UdpProxyContext {
      downstream: &downstream,
      config: &config,
      state: &state,
      connections: &connections,
      durable: None,
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
    let _ = maintain_udp_flows(
      &mut flows,
      Duration::from_secs(1),
      None,
      &state,
      &config,
      &release_tx,
    )
    .await;
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
