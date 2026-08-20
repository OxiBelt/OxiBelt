//! TTL-aware HTTP/3 endpoint selection and bounded pre-dispatch racing.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant as StdInstant};

use anyhow::Context;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Mutex;

use super::upstream_connection::{
  ConnectedH3Upstream, ConnectedQuinnUpstream, connect_h3_upstream, connect_quinn_upstream,
};
use super::upstream_pool::LogicalH3Origin;
use crate::circuit_breakers::{AdmissionLease, CircuitBreakerRuntime};
use crate::config::{QuicConfig, QuicUpstreamResolutionConfig};
use crate::metrics::Metrics;
use crate::metrics::http3_upstream::{
  H3EndpointAttemptOutcome, H3EndpointFamily, H3EndpointSelectionEvent, H3PoolWaitOutcome,
  H3PoolWaitScope, H3ResolverCacheEvent, H3ResolverErrorClass, H3ResolverOutcome,
};
use crate::upstream_resolution::{
  CandidateSchedulerConfig, CandidateSchedulerMode, HappyEyeballsCandidate, HttpTransportProtocol,
  ResolutionOrigin, ResolutionPolicy, SharedEndpointResolver,
  resolve_http_candidate_updates_with_resolver,
};

const MAX_SIMULTANEOUS_FAMILY_ATTEMPTS: usize = 2;
const RECENT_SUCCESS_PREFERENCE_USES: usize = 1;

mod failure;
#[cfg(test)]
mod tests;
pub(super) use failure::SharedConnectFailure;
use failure::admission_rejection;

pub(super) struct AdmittedUpstream<T> {
  pub(super) connected: T,
  pub(super) admission: AdmissionLease,
}

pub(super) struct H3ResolvedCandidates {
  updates: tokio::sync::watch::Receiver<Arc<[HappyEyeballsCandidate<SocketAddr>]>>,
  valid_until: tokio::time::Instant,
}

pub(super) struct H3EndpointRuntime {
  resolver: SharedEndpointResolver,
  origin_host: String,
  origin_port: u16,
  server_name: String,
  client_config: h3_quinn::quinn::ClientConfig,
  quic_config: QuicConfig,
  quic_host_key_base_dir: Option<PathBuf>,
  circuit_breakers: Arc<CircuitBreakerRuntime>,
  circuit_pool: Option<Arc<str>>,
  policy: QuicUpstreamResolutionConfig,
  resolution_policy: ResolutionPolicy,
  scheduler_policy: CandidateSchedulerConfig,
  svcb_enabled: bool,
  allowed_svcb_ports: Arc<[u16]>,
  health: Mutex<EndpointSelectionState>,
  last_valid_until: StdMutex<Option<tokio::time::Instant>>,
  refreshable: AtomicBool,
  refresh_in_flight: AtomicBool,
}

impl H3EndpointRuntime {
  #[allow(
    clippy::too_many_arguments,
    reason = "constructor keeps independently validated transport and discovery policies explicit"
  )]
  pub(super) fn new(
    logical_origin: &LogicalH3Origin,
    client_config: h3_quinn::quinn::ClientConfig,
    quic_config: QuicConfig,
    policy: QuicUpstreamResolutionConfig,
    resolution_policy: ResolutionPolicy,
    scheduler_policy: CandidateSchedulerConfig,
    svcb_enabled: bool,
    allowed_svcb_ports: Arc<[u16]>,
    quic_host_key_base_dir: Option<PathBuf>,
    circuit_breakers: Arc<CircuitBreakerRuntime>,
    circuit_pool: Option<Arc<str>>,
  ) -> anyhow::Result<Self> {
    let origin = ResolutionOrigin::new(
      &logical_origin.host,
      logical_origin.port,
      logical_origin.discovery_identity.clone(),
    )?;
    Ok(Self {
      resolver: SharedEndpointResolver::system(origin, resolution_policy),
      origin_host: logical_origin.host.clone(),
      origin_port: logical_origin.port,
      server_name: logical_origin.server_name.clone(),
      client_config,
      policy,
      resolution_policy,
      scheduler_policy,
      svcb_enabled,
      allowed_svcb_ports,
      quic_config,
      quic_host_key_base_dir,
      circuit_breakers,
      circuit_pool,
      health: Mutex::new(EndpointSelectionState::default()),
      last_valid_until: StdMutex::new(None),
      refreshable: AtomicBool::new(true),
      refresh_in_flight: AtomicBool::new(false),
    })
  }

  pub(super) async fn resolve(
    &self,
    deadline: tokio::time::Instant,
    metrics: &Metrics,
  ) -> Result<H3ResolvedCandidates, SharedConnectFailure> {
    let started = StdInstant::now();
    let mut updates = resolve_http_candidate_updates_with_resolver(
      self.resolver.clone(),
      &self.origin_host,
      self.origin_port,
      self.resolution_policy,
      HttpTransportProtocol::H3,
      true,
      self.svcb_enabled,
      &self.allowed_svcb_ports,
      deadline,
    );
    loop {
      let snapshot = updates.borrow_and_update().clone();
      if !snapshot.is_empty() {
        let ipv4 = snapshot
          .iter()
          .filter(|candidate| candidate.value_ref().is_ipv4())
          .count();
        metrics.observe_h3_resolver(H3ResolverOutcome::Success, started.elapsed());
        metrics.observe_h3_pool_wait(
          H3PoolWaitScope::Resolution,
          H3PoolWaitOutcome::Ready,
          started.elapsed(),
        );
        metrics.observe_h3_resolver_candidates(H3EndpointFamily::Ipv4, ipv4);
        metrics.observe_h3_resolver_candidates(
          H3EndpointFamily::Ipv6,
          snapshot.len().saturating_sub(ipv4),
        );
        metrics.observe_h3_resolver_candidates(H3EndpointFamily::All, snapshot.len());
        *lock_unpoisoned(&self.last_valid_until) = Some(deadline);
        self.refreshable.store(true, Ordering::Release);
        return Ok(H3ResolvedCandidates {
          updates,
          valid_until: deadline,
        });
      }
      tokio::select! {
        _ = tokio::time::sleep_until(deadline) => {
          metrics.observe_h3_resolver(H3ResolverOutcome::Error, started.elapsed());
          metrics.observe_h3_pool_wait(
            H3PoolWaitScope::Resolution,
            H3PoolWaitOutcome::Error,
            started.elapsed(),
          );
          return Err(SharedConnectFailure::message(
            "upstream HTTP/3 resolution timed out",
            deadline,
          ));
        }
        changed = updates.changed() => {
          if changed.is_err() {
            metrics.record_h3_resolver_error(H3ResolverErrorClass::Other);
            metrics.observe_h3_resolver(H3ResolverOutcome::Error, started.elapsed());
            metrics.observe_h3_pool_wait(
              H3PoolWaitScope::Resolution,
              H3PoolWaitOutcome::Error,
              started.elapsed(),
            );
            return Err(SharedConnectFailure::message(
              "upstream resolver returned no HTTP/3 candidates",
              retry_deadline(&self.policy, tokio::time::Instant::now(), deadline),
            ));
          }
        }
      }
    }
  }

  pub(super) async fn resolve_and_connect_h3(
    &self,
    deadline: tokio::time::Instant,
    metrics: &Metrics,
  ) -> Result<AdmittedUpstream<ConnectedH3Upstream>, SharedConnectFailure> {
    let resolved = self.resolve(deadline, metrics).await?;
    self.connect_h3(resolved, deadline, metrics).await
  }

  pub(super) fn refresh_if_expired(
    self: &Arc<Self>,
    deadline: tokio::time::Instant,
    metrics: Arc<Metrics>,
  ) {
    let valid_until = *lock_unpoisoned(&self.last_valid_until);
    let expired = valid_until.is_some_and(|valid_until| valid_until <= tokio::time::Instant::now());
    if !expired
      || !self.refreshable.load(Ordering::Acquire)
      || deadline <= tokio::time::Instant::now()
      || self
        .refresh_in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
      return;
    }
    metrics.record_h3_resolver_cache_event(H3ResolverCacheEvent::Stale);
    let endpoints = Arc::clone(self);
    tokio::spawn(async move {
      let _ = endpoints.resolve(deadline, &metrics).await;
      endpoints.refresh_in_flight.store(false, Ordering::Release);
    });
  }

  pub(super) async fn resolve_and_connect_quinn(
    &self,
    deadline: tokio::time::Instant,
    metrics: &Metrics,
  ) -> Result<AdmittedUpstream<ConnectedQuinnUpstream>, SharedConnectFailure> {
    let resolved = self.resolve(deadline, metrics).await?;
    self
      .race_candidates(
        resolved,
        deadline,
        metrics,
        |address, candidate_deadline| self.connect_admitted_quinn(address, candidate_deadline),
      )
      .await
  }

  pub(super) async fn connect_h3(
    &self,
    resolved: H3ResolvedCandidates,
    deadline: tokio::time::Instant,
    metrics: &Metrics,
  ) -> Result<AdmittedUpstream<ConnectedH3Upstream>, SharedConnectFailure> {
    self
      .race_candidates(
        resolved,
        deadline,
        metrics,
        |address, candidate_deadline| self.connect_admitted_h3(address, candidate_deadline),
      )
      .await
  }

  async fn connect_admitted_h3(
    &self,
    address: SocketAddr,
    deadline: tokio::time::Instant,
  ) -> anyhow::Result<AdmittedUpstream<ConnectedH3Upstream>> {
    let admission = self
      .circuit_breakers
      .admit_upstream_connection(self.circuit_pool.as_deref(), Some(deadline.into_std()))
      .await
      .map_err(anyhow::Error::new)?;
    let connected = connect_h3_upstream(
      &self.server_name,
      address,
      self.client_config.clone(),
      &self.quic_config,
      self.quic_host_key_base_dir.as_deref(),
      deadline,
    )
    .await?;
    Ok(AdmittedUpstream {
      connected,
      admission,
    })
  }

  async fn connect_admitted_quinn(
    &self,
    address: SocketAddr,
    deadline: tokio::time::Instant,
  ) -> anyhow::Result<AdmittedUpstream<ConnectedQuinnUpstream>> {
    let admission = self
      .circuit_breakers
      .admit_upstream_connection(self.circuit_pool.as_deref(), Some(deadline.into_std()))
      .await
      .map_err(anyhow::Error::new)?;
    let connected = connect_quinn_upstream(
      &self.server_name,
      address,
      self.client_config.clone(),
      &self.quic_config,
      self.quic_host_key_base_dir.as_deref(),
      deadline,
    )
    .await?;
    Ok(AdmittedUpstream {
      connected,
      admission,
    })
  }

  async fn race_candidates<T, Connect, ConnectFuture>(
    &self,
    resolved: H3ResolvedCandidates,
    deadline: tokio::time::Instant,
    metrics: &Metrics,
    connect: Connect,
  ) -> Result<AdmittedUpstream<T>, SharedConnectFailure>
  where
    Connect: Fn(SocketAddr, tokio::time::Instant) -> ConnectFuture,
    ConnectFuture: Future<Output = anyhow::Result<AdmittedUpstream<T>>>,
  {
    if resolved.valid_until <= tokio::time::Instant::now() {
      return Err(SharedConnectFailure::message(
        "upstream endpoint set expired before connection selection",
        retry_deadline(&self.policy, tokio::time::Instant::now(), deadline),
      ));
    }
    let addresses = resolved
      .updates
      .borrow()
      .iter()
      .map(|candidate| *candidate.value_ref())
      .collect::<Vec<_>>();
    race_candidates(
      &self.policy,
      self.scheduler_policy,
      &self.health,
      addresses,
      Some(resolved.updates),
      deadline,
      metrics,
      connect,
    )
    .await
  }
}

#[allow(
  clippy::too_many_arguments,
  reason = "race core keeps policy, update stream, health, telemetry, and connector ownership explicit"
)]
async fn race_candidates<T, Connect, ConnectFuture>(
  policy: &QuicUpstreamResolutionConfig,
  scheduler_policy: CandidateSchedulerConfig,
  health: &Mutex<EndpointSelectionState>,
  addresses: Vec<SocketAddr>,
  mut updates: Option<tokio::sync::watch::Receiver<Arc<[HappyEyeballsCandidate<SocketAddr>]>>>,
  deadline: tokio::time::Instant,
  metrics: &Metrics,
  connect: Connect,
) -> Result<T, SharedConnectFailure>
where
  Connect: Fn(SocketAddr, tokio::time::Instant) -> ConnectFuture,
  ConnectFuture: Future<Output = anyhow::Result<T>>,
{
  if tokio::time::Instant::now() >= deadline {
    return Err(SharedConnectFailure::message(
      "upstream HTTP/3 endpoint race timed out",
      deadline,
    ));
  }
  let plan = candidate_plan(
    policy,
    scheduler_policy.first_family_count(),
    health,
    addresses,
    metrics,
  )
  .await;
  if plan.candidates.is_empty() {
    return Err(SharedConnectFailure::message(
      "all upstream HTTP/3 endpoints are cooling down",
      plan.retry_at.unwrap_or(deadline),
    ));
  }
  if tokio::time::Instant::now() >= deadline {
    return Err(SharedConnectFailure::message(
      "upstream HTTP/3 endpoint race timed out",
      deadline,
    ));
  }

  let mut candidates = VecDeque::from(plan.candidates);
  let mut started_addresses = HashSet::new();
  let mut launched_with_peer = HashSet::new();
  let mut attempts_started = 0usize;
  let mut in_flight = FuturesUnordered::new();
  let mut active_by_family = [0usize; 2];
  let first = candidates
    .pop_front()
    .context("HTTP/3 candidate plan unexpectedly empty")
    .map_err(|error| SharedConnectFailure::from_error(error, deadline))?;
  record_candidate_started(metrics, first, &mut active_by_family);
  started_addresses.insert(first);
  attempts_started = attempts_started.saturating_add(1);
  in_flight.push(tagged_connect(first, connect(first, deadline)));
  let stagger = scheduler_policy.effective_connection_attempt_delay();
  let max_concurrent_attempts = match scheduler_policy.mode() {
    CandidateSchedulerMode::Enabled => scheduler_policy
      .max_concurrent_attempts()
      .min(MAX_SIMULTANEOUS_FAMILY_ATTEMPTS),
    CandidateSchedulerMode::LegacySequential => 1,
  };
  let mut next_launch = next_candidate_launch(tokio::time::Instant::now(), stagger, deadline);
  let mut last_endpoint_error = None;
  let mut admission_error = None;
  let mut deferred_admission = false;

  loop {
    if in_flight.is_empty()
      && (admission_error.is_some()
        || attempts_started >= policy.effective_max_connect_attempts()
        || (candidates.is_empty() && updates.is_none()))
    {
      break;
    }
    let can_stagger = admission_error.is_none()
      && !deferred_admission
      && attempts_started < policy.effective_max_connect_attempts()
      && in_flight.len() < max_concurrent_attempts
      && !candidates.is_empty()
      && next_launch < deadline;
    let has_in_flight = !in_flight.is_empty();
    tokio::select! {
      _ = tokio::time::sleep_until(deadline) => {
        record_candidate_cancellations(metrics, active_by_family);
        return Err(SharedConnectFailure::message(
          "upstream HTTP/3 endpoint race timed out",
          deadline,
        ));
      }
      result = in_flight.next(), if has_in_flight => {
        let Some((address, result)) = result else {
          continue;
        };
        let may_self_contend = launched_with_peer.remove(&address);
        decrement_active(address, &mut active_by_family);
        match result {
          Ok(connected) => {
            metrics.record_h3_endpoint_attempt(
              endpoint_family(address),
              H3EndpointAttemptOutcome::Won,
            );
            record_success(health, address, metrics).await;
            record_candidate_cancellations(metrics, active_by_family);
            return Ok(connected);
          }
          Err(error) => {
            if admission_rejection(&error).is_some() {
              metrics.record_h3_endpoint_attempt(
                endpoint_family(address),
                H3EndpointAttemptOutcome::Canceled,
              );
              if may_self_contend {
                started_addresses.remove(&address);
                attempts_started = attempts_started.saturating_sub(1);
                candidates.push_front(address);
                deferred_admission = !in_flight.is_empty();
                if !deferred_admission {
                  next_launch = tokio::time::Instant::now();
                }
                continue;
              }
              admission_error.get_or_insert(error);
              continue;
            }
            metrics.record_h3_endpoint_attempt(
              endpoint_family(address),
              H3EndpointAttemptOutcome::Failed,
            );
            record_failure(policy, health, address, metrics).await;
            last_endpoint_error = Some(error);
            if deferred_admission {
              deferred_admission = false;
              admission_error = None;
              next_launch = tokio::time::Instant::now();
            }
          }
        }
      }
      changed = async {
        match &mut updates {
          Some(updates) => updates.changed().await,
          None => std::future::pending().await,
        }
      }, if updates.is_some() => {
        match changed {
          Ok(()) => {
            let Some(updates_receiver) = updates.as_mut() else {
              continue;
            };
            let snapshot = updates_receiver.borrow_and_update().clone();
            let addresses = snapshot
              .iter()
              .map(|candidate| *candidate.value_ref())
              .collect::<Vec<_>>();
            let updated = candidate_plan(
              policy,
              scheduler_policy.first_family_count(),
              health,
              addresses,
              metrics,
            )
            .await;
            candidates = updated
              .candidates
              .into_iter()
              .filter(|address| !started_addresses.contains(address))
              .collect();
          }
          Err(_) => updates = None,
        }
      }
      _ = tokio::time::sleep_until(next_launch), if can_stagger => {
        if let Some(address) = candidates.pop_front() {
          if !in_flight.is_empty() {
            launched_with_peer.insert(address);
          }
          record_candidate_started(metrics, address, &mut active_by_family);
          started_addresses.insert(address);
          attempts_started = attempts_started.saturating_add(1);
          in_flight.push(tagged_connect(address, connect(address, deadline)));
          next_launch = next_candidate_launch(tokio::time::Instant::now(), stagger, deadline);
        }
      }
    }
  }

  let error = admission_error
    .or(last_endpoint_error)
    .unwrap_or_else(|| anyhow::anyhow!("upstream HTTP/3 endpoint set was exhausted"));
  let now = tokio::time::Instant::now();
  let retry_at = if let Some(admission) = admission_rejection(&error) {
    now
      .checked_add(admission.retry_after)
      .unwrap_or(deadline)
      .min(deadline)
      .max(retry_deadline(policy, now, deadline))
  } else {
    next_retry_at(health)
      .await
      .unwrap_or_else(|| retry_deadline(policy, now, deadline))
  };
  Err(SharedConnectFailure::from_error(error, retry_at))
}

async fn candidate_plan(
  policy: &QuicUpstreamResolutionConfig,
  first_family_count: usize,
  health: &Mutex<EndpointSelectionState>,
  addresses: Vec<SocketAddr>,
  metrics: &Metrics,
) -> CandidatePlan {
  let now = tokio::time::Instant::now();
  let mut unique = Vec::new();
  let mut seen = HashSet::new();
  for address in addresses {
    if seen.insert(address) {
      unique.push(address);
    }
  }
  let mut health = health.lock().await;
  health.entries.retain(|address, _| seen.contains(address));
  let mut eligible = Vec::new();
  let mut retry_at = None;
  for address in unique {
    let entry = health.entries.entry(address).or_default();
    match entry.cooldown {
      EndpointCooldown::Ready => eligible.push(address),
      EndpointCooldown::Until(until) if until <= now => {
        entry.cooldown = EndpointCooldown::Ready;
        metrics.record_h3_endpoint_selection(H3EndpointSelectionEvent::CooldownExpired);
        eligible.push(address);
      }
      EndpointCooldown::Until(until) => {
        retry_at = Some(retry_at.map_or(until, |current: tokio::time::Instant| current.min(until)));
        metrics.record_h3_endpoint_selection(H3EndpointSelectionEvent::CooldownSkipped);
      }
      EndpointCooldown::Indefinite => {
        metrics.record_h3_endpoint_selection(H3EndpointSelectionEvent::CooldownSkipped);
      }
    }
  }
  if eligible.is_empty() {
    return CandidatePlan {
      candidates: Vec::new(),
      retry_at,
    };
  }

  let (eligible, preferred_used) = rotate_with_preference(eligible, &mut health);
  if preferred_used {
    metrics.record_h3_endpoint_selection(H3EndpointSelectionEvent::SuccessPreferred);
  } else {
    metrics.record_h3_endpoint_selection(H3EndpointSelectionEvent::Rotated);
  }
  let candidates = interleave_families(eligible, first_family_count)
    .into_iter()
    .take(policy.effective_max_connect_attempts())
    .collect();
  CandidatePlan {
    candidates,
    retry_at,
  }
}

async fn record_success(
  health: &Mutex<EndpointSelectionState>,
  address: SocketAddr,
  metrics: &Metrics,
) {
  let mut health = health.lock().await;
  let entry = health.entries.entry(address).or_default();
  entry.failures = 0;
  entry.cooldown = EndpointCooldown::Ready;
  health.preferred = Some(PreferredEndpoint {
    address,
    remaining: RECENT_SUCCESS_PREFERENCE_USES,
  });
  metrics.record_h3_endpoint_selection(H3EndpointSelectionEvent::SuccessPreferred);
}

async fn record_failure(
  policy: &QuicUpstreamResolutionConfig,
  health: &Mutex<EndpointSelectionState>,
  address: SocketAddr,
  metrics: &Metrics,
) {
  let mut health = health.lock().await;
  let entry = health.entries.entry(address).or_default();
  entry.failures = entry.failures.saturating_add(1);
  let shift = entry.failures.saturating_sub(1).min(63);
  let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
  let delay_ms = policy
    .cooldown_base_ms
    .saturating_mul(multiplier)
    .min(policy.cooldown_max_ms);
  entry.cooldown = tokio::time::Instant::now()
    .checked_add(Duration::from_millis(delay_ms))
    .map_or(EndpointCooldown::Indefinite, EndpointCooldown::Until);
  if health
    .preferred
    .as_ref()
    .is_some_and(|preferred| preferred.address == address)
  {
    health.preferred = None;
  }
  metrics.record_h3_endpoint_selection(H3EndpointSelectionEvent::CooldownEntered);
}

async fn next_retry_at(health: &Mutex<EndpointSelectionState>) -> Option<tokio::time::Instant> {
  health
    .lock()
    .await
    .entries
    .values()
    .filter_map(|entry| match entry.cooldown {
      EndpointCooldown::Until(until) => Some(until),
      EndpointCooldown::Ready | EndpointCooldown::Indefinite => None,
    })
    .min()
}

fn retry_deadline(
  policy: &QuicUpstreamResolutionConfig,
  now: tokio::time::Instant,
  request_deadline: tokio::time::Instant,
) -> tokio::time::Instant {
  now
    .checked_add(Duration::from_millis(policy.cooldown_base_ms))
    .unwrap_or(request_deadline)
    .min(request_deadline)
}

fn next_candidate_launch(
  last_launch: tokio::time::Instant,
  stagger: Duration,
  deadline: tokio::time::Instant,
) -> tokio::time::Instant {
  last_launch
    .checked_add(stagger)
    .unwrap_or(deadline)
    .min(deadline)
}

#[derive(Default)]
struct EndpointSelectionState {
  entries: HashMap<SocketAddr, EndpointHealth>,
  rotation_cursor: usize,
  preferred: Option<PreferredEndpoint>,
}

#[derive(Default)]
struct EndpointHealth {
  failures: u32,
  cooldown: EndpointCooldown,
}

#[derive(Clone, Copy, Default)]
enum EndpointCooldown {
  #[default]
  Ready,
  Until(tokio::time::Instant),
  Indefinite,
}

struct PreferredEndpoint {
  address: SocketAddr,
  remaining: usize,
}

struct CandidatePlan {
  candidates: Vec<SocketAddr>,
  retry_at: Option<tokio::time::Instant>,
}

async fn tagged_connect<T, ConnectFuture>(
  address: SocketAddr,
  future: ConnectFuture,
) -> (SocketAddr, anyhow::Result<T>)
where
  ConnectFuture: Future<Output = anyhow::Result<T>>,
{
  (address, future.await)
}

fn interleave_families(addresses: Vec<SocketAddr>, first_family_count: usize) -> Vec<SocketAddr> {
  let start_with_ipv6 = addresses.first().is_some_and(SocketAddr::is_ipv6);
  let mut ipv4 = addresses
    .iter()
    .copied()
    .filter(SocketAddr::is_ipv4)
    .collect::<VecDeque<_>>();
  let mut ipv6 = addresses
    .into_iter()
    .filter(SocketAddr::is_ipv6)
    .collect::<VecDeque<_>>();
  let mut interleaved = Vec::with_capacity(ipv4.len().saturating_add(ipv6.len()));
  for _ in 0..first_family_count {
    let candidate = if start_with_ipv6 {
      ipv6.pop_front().or_else(|| ipv4.pop_front())
    } else {
      ipv4.pop_front().or_else(|| ipv6.pop_front())
    };
    if let Some(candidate) = candidate {
      interleaved.push(candidate);
    }
  }
  let mut ipv6_turn = !start_with_ipv6;
  while !ipv4.is_empty() || !ipv6.is_empty() {
    let candidate = if ipv6_turn {
      ipv6.pop_front().or_else(|| ipv4.pop_front())
    } else {
      ipv4.pop_front().or_else(|| ipv6.pop_front())
    };
    if let Some(candidate) = candidate {
      interleaved.push(candidate);
    }
    ipv6_turn = !ipv6_turn;
  }
  interleaved
}

fn rotate_with_preference(
  mut eligible: Vec<SocketAddr>,
  health: &mut EndpointSelectionState,
) -> (Vec<SocketAddr>, bool) {
  let rotation = health.rotation_cursor % eligible.len();
  eligible.rotate_left(rotation);
  if let Some(preferred) = &mut health.preferred
    && preferred.remaining > 0
    && let Some(index) = eligible
      .iter()
      .position(|address| *address == preferred.address)
  {
    eligible.swap(0, index);
    preferred.remaining = preferred.remaining.saturating_sub(1);
    return (eligible, true);
  }
  health.rotation_cursor = health.rotation_cursor.wrapping_add(1);
  (eligible, false)
}

fn endpoint_family(address: SocketAddr) -> H3EndpointFamily {
  if address.is_ipv4() {
    H3EndpointFamily::Ipv4
  } else {
    H3EndpointFamily::Ipv6
  }
}

fn family_index(address: SocketAddr) -> usize {
  usize::from(address.is_ipv6())
}

fn record_candidate_started(
  metrics: &Metrics,
  address: SocketAddr,
  active_by_family: &mut [usize; 2],
) {
  active_by_family[family_index(address)] =
    active_by_family[family_index(address)].saturating_add(1);
  metrics.record_h3_endpoint_attempt(endpoint_family(address), H3EndpointAttemptOutcome::Started);
}

fn decrement_active(address: SocketAddr, active_by_family: &mut [usize; 2]) {
  active_by_family[family_index(address)] =
    active_by_family[family_index(address)].saturating_sub(1);
}

fn record_candidate_cancellations(metrics: &Metrics, active_by_family: [usize; 2]) {
  for (family, count) in [H3EndpointFamily::Ipv4, H3EndpointFamily::Ipv6]
    .into_iter()
    .zip(active_by_family)
  {
    for _ in 0..count {
      metrics.record_h3_endpoint_attempt(family, H3EndpointAttemptOutcome::Canceled);
    }
  }
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
  match mutex.lock() {
    Ok(guard) => guard,
    Err(poisoned) => {
      mutex.clear_poison();
      poisoned.into_inner()
    }
  }
}
