//! Upstream-pool runtime state and selection entrypoints.
//! Selection, health, and sticky routing stay coordinated through one snapshot.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::bail;
use http::HeaderValue;
use serde::Serialize;

use crate::config::{
  HealthCheckProtocol, HttpVersion, LoadBalancingAlgorithm, ProxyProtocolEgressMode,
  UpstreamConfig, UpstreamPoolConfig, UpstreamPoolServerConfig, UpstreamTlsConfig,
  upstream_pool_server_id,
};
use crate::metrics::Metrics;
use crate::shared_state::SharedState;

mod health;
mod selection;
mod shared_runtime;
mod sticky;

const EWMA_FAILURE_PENALTY_MS: u64 = 30_000;

use health::{
  HEALTH_REASON_ACTIVE_FAILURE, HEALTH_REASON_ACTIVE_SUCCESS, HEALTH_REASON_OUTLIER_EJECTED,
  HEALTH_REASON_PASSIVE_FAILURE, HEALTH_REASON_PASSIVE_SUCCESS, HEALTH_REASON_UNKNOWN,
  effective_server_weight, effective_weight_percent_at, health_reason_label, mark_health_report,
  maybe_eject_outlier, now_millis, optional_millis, server_healthy, set_server_health,
  slow_start_remaining_ms_at, source_for_server,
};
use selection::build_sticky_fallback;
#[cfg(test)]
use selection::{normalized_active_score, weighted_available};
use selection::{parse_policy_override, select_by_algorithm};

#[derive(Debug)]
pub struct PoolState {
  pools: HashMap<String, Arc<PoolRuntime>>,
  shared_state: Option<Arc<SharedState>>,
  metrics: Option<Arc<Metrics>>,
}

#[derive(Debug)]
struct PoolRuntime {
  config: UpstreamPoolConfig,
  servers: Vec<Arc<PoolServerRuntime>>,
  chooser: AtomicUsize,
  sticky_secret: RwLock<[u8; 32]>,
}

#[derive(Debug)]
struct PoolServerRuntime {
  server_id: String,
  upstream_name: String,
  local_active: AtomicUsize,
  shared_active: AtomicUsize,
  healthy: AtomicBool,
  consecutive_successes: AtomicU32,
  consecutive_failures: AtomicU32,
  ewma_latency_ms: AtomicU64,
  ready_since_ms: AtomicU64,
  ejected_until_ms: AtomicU64,
  ejection_count: AtomicU32,
  last_health_check_ms: AtomicU64,
  health_reason: AtomicU8,
}

impl PoolServerRuntime {
  fn new(
    pool_name: &str,
    config: &UpstreamPoolServerConfig,
    server_id: &str,
    previous_pool_exists: bool,
    previous: Option<&PoolServerRuntime>,
    previous_config: Option<&UpstreamPoolServerConfig>,
    now_ms: u64,
  ) -> Self {
    let recovered_to_ready = previous_config.is_some_and(|previous| {
      !previous.state.accepts_new_requests() && config.state.accepts_new_requests()
    });
    let ready_since_ms = match previous {
      Some(_) if recovered_to_ready => now_ms,
      Some(previous) => previous.ready_since_ms.load(Ordering::Relaxed),
      None if previous_pool_exists => now_ms,
      None => 0,
    };
    Self {
      upstream_name: synthetic_upstream_name_for_id(pool_name, server_id),
      server_id: server_id.to_string(),
      local_active: AtomicUsize::new(0),
      shared_active: AtomicUsize::new(0),
      healthy: AtomicBool::new(
        previous
          .map(|previous| previous.healthy.load(Ordering::Relaxed))
          .unwrap_or(true),
      ),
      consecutive_successes: AtomicU32::new(
        previous
          .map(|previous| previous.consecutive_successes.load(Ordering::Relaxed))
          .unwrap_or(0),
      ),
      consecutive_failures: AtomicU32::new(
        previous
          .map(|previous| previous.consecutive_failures.load(Ordering::Relaxed))
          .unwrap_or(0),
      ),
      ewma_latency_ms: AtomicU64::new(
        previous
          .map(|previous| previous.ewma_latency_ms.load(Ordering::Relaxed))
          .unwrap_or(0),
      ),
      ready_since_ms: AtomicU64::new(ready_since_ms),
      ejected_until_ms: AtomicU64::new(
        previous
          .map(|previous| previous.ejected_until_ms.load(Ordering::Relaxed))
          .unwrap_or(0),
      ),
      ejection_count: AtomicU32::new(
        previous
          .map(|previous| previous.ejection_count.load(Ordering::Relaxed))
          .unwrap_or(0),
      ),
      last_health_check_ms: AtomicU64::new(
        previous
          .map(|previous| previous.last_health_check_ms.load(Ordering::Relaxed))
          .unwrap_or(0),
      ),
      health_reason: AtomicU8::new(
        previous
          .map(|previous| previous.health_reason.load(Ordering::Relaxed))
          .unwrap_or(HEALTH_REASON_UNKNOWN),
      ),
    }
  }
}

pub struct PoolSelection {
  pub pool_name: String,
  pub upstream_name: String,
  server: Arc<PoolServerRuntime>,
  shared_state: Option<Arc<SharedState>>,
  sticky_cookie: Option<HeaderValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolRuntimeSnapshot {
  pub name: String,
  pub algorithm: String,
  pub servers: Vec<PoolServerRuntimeSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolServerRuntimeSnapshot {
  pub id: String,
  pub upstream_name: String,
  pub origin: String,
  pub source: String,
  pub state: String,
  pub weight: u32,
  pub max_conns: usize,
  pub backup: bool,
  pub active: usize,
  pub healthy: bool,
  pub health_reason: String,
  pub last_health_check_ms: Option<u64>,
  pub ejected_until_ms: Option<u64>,
  pub ejection_count: u32,
  pub slow_start_remaining_ms: Option<u64>,
  pub effective_weight_percent: u32,
}

impl Drop for PoolSelection {
  fn drop(&mut self) {
    self.server.local_active.fetch_sub(1, Ordering::Relaxed);
    if let Some(shared) = &self.shared_state {
      shared.defer_pool_active_add(&self.upstream_name, -1);
    }
  }
}

impl PoolState {
  pub fn new(configs: &[UpstreamPoolConfig], shared_state: Option<Arc<SharedState>>) -> Arc<Self> {
    Self::new_with_previous_and_metrics(configs, shared_state, None, None)
  }

  pub fn new_with_previous(
    configs: &[UpstreamPoolConfig],
    shared_state: Option<Arc<SharedState>>,
    previous: Option<&PoolState>,
  ) -> Arc<Self> {
    Self::new_with_previous_and_metrics(configs, shared_state, previous, None)
  }

  pub fn new_with_previous_and_metrics(
    configs: &[UpstreamPoolConfig],
    shared_state: Option<Arc<SharedState>>,
    previous: Option<&PoolState>,
    metrics: Option<Arc<Metrics>>,
  ) -> Arc<Self> {
    let now_ms = now_millis();
    let pools = configs
      .iter()
      .map(|config| {
        let previous_pool = previous.and_then(|state| state.pools.get(&config.name));
        let servers = config
          .servers
          .iter()
          .enumerate()
          .map(|(index, server_config)| {
            let server_id = upstream_pool_server_id(index, server_config);
            let previous_runtime = previous_pool.and_then(|pool| {
              pool
                .servers
                .iter()
                .find(|server| server.server_id == server_id)
            });
            let previous_config = previous_pool.and_then(|pool| {
              pool
                .config
                .servers
                .iter()
                .enumerate()
                .find_map(|(index, server)| {
                  (upstream_pool_server_id(index, server) == server_id).then_some(server)
                })
            });
            Arc::new(PoolServerRuntime::new(
              &config.name,
              server_config,
              &server_id,
              previous_pool.is_some(),
              previous_runtime.map(Arc::as_ref),
              previous_config,
              now_ms,
            ))
          })
          .collect();
        (
          config.name.clone(),
          Arc::new(PoolRuntime {
            config: config.clone(),
            servers,
            chooser: AtomicUsize::new(0x9e37_79b9),
            sticky_secret: RwLock::new(sticky::sticky_secret_for_pool(
              config,
              shared_state.as_ref(),
            )),
          }),
        )
      })
      .collect();
    Arc::new(Self {
      pools,
      shared_state,
      metrics,
    })
  }

  pub fn synthetic_upstreams(configs: &[UpstreamPoolConfig]) -> Vec<UpstreamConfig> {
    configs
      .iter()
      .flat_map(|pool| {
        pool
          .servers
          .iter()
          .enumerate()
          .map(|(index, server)| UpstreamConfig {
            name: synthetic_upstream_name_for_id(
              &pool.name,
              &upstream_pool_server_id(index, server),
            ),
            origin: server.origin.clone(),
            max_http_version: if server.origin.scheme() == "http"
              && pool.health_check.protocol != HealthCheckProtocol::Grpc
            {
              HttpVersion::H1
            } else {
              HttpVersion::H2
            },
            connect_timeout_ms: 3_000,
            request_timeout_ms: 30_000,
            first_byte_timeout_ms: 30_000,
            read_timeout_ms: 30_000,
            send_timeout_ms: 30_000,
            idle_timeout_ms: pool.keepalive.idle_timeout_ms,
            max_lifetime_ms: pool.keepalive.max_lifetime_ms,
            pool_max_idle_per_host: pool.keepalive.max_idle,
            preserve_host: false,
            websocket: true,
            webrtc: true,
            webtransport: true,
            proxy_protocol_egress: ProxyProtocolEgressMode::Off,
            tls: UpstreamTlsConfig::default(),
            extra_trusted_ca_certs: Vec::new(),
          })
      })
      .collect()
  }

  pub fn health_check_upstreams(configs: &[UpstreamPoolConfig]) -> Vec<UpstreamConfig> {
    configs
      .iter()
      .flat_map(|pool| {
        pool
          .servers
          .iter()
          .enumerate()
          .map(|(index, server)| UpstreamConfig {
            name: synthetic_upstream_name_for_id(
              &pool.name,
              &upstream_pool_server_id(index, server),
            ),
            origin: server.origin.clone(),
            max_http_version: if server.origin.scheme() == "http"
              && pool.health_check.protocol != HealthCheckProtocol::Grpc
            {
              HttpVersion::H1
            } else {
              HttpVersion::H2
            },
            connect_timeout_ms: 3_000,
            request_timeout_ms: 30_000,
            first_byte_timeout_ms: 30_000,
            read_timeout_ms: 30_000,
            send_timeout_ms: 30_000,
            idle_timeout_ms: pool.keepalive.idle_timeout_ms,
            max_lifetime_ms: pool.keepalive.max_lifetime_ms,
            pool_max_idle_per_host: pool.keepalive.max_idle,
            preserve_host: false,
            websocket: true,
            webrtc: true,
            webtransport: true,
            proxy_protocol_egress: ProxyProtocolEgressMode::Off,
            tls: UpstreamTlsConfig {
              upstream_revocation: pool.health_check.tls.upstream_revocation.clone(),
              ..UpstreamTlsConfig::default()
            },
            extra_trusted_ca_certs: pool.health_check.tls.trusted_ca_certs.clone(),
          })
      })
      .collect()
  }

  pub fn select(
    &self,
    pool_name: &str,
    client_ip: IpAddr,
    hash_key: &str,
    policy_override: Option<&str>,
  ) -> anyhow::Result<PoolSelection> {
    self.select_with_cookie_header(pool_name, client_ip, hash_key, policy_override, None)
  }

  pub fn select_with_cookie_header(
    &self,
    pool_name: &str,
    client_ip: IpAddr,
    hash_key: &str,
    policy_override: Option<&str>,
    cookie_header: Option<&HeaderValue>,
  ) -> anyhow::Result<PoolSelection> {
    self.select_with_cookie_header_excluding(
      pool_name,
      client_ip,
      hash_key,
      policy_override,
      cookie_header,
      &[],
    )
  }

  pub fn select_with_cookie_header_excluding(
    &self,
    pool_name: &str,
    client_ip: IpAddr,
    hash_key: &str,
    policy_override: Option<&str>,
    cookie_header: Option<&HeaderValue>,
    excluded_upstreams: &[String],
  ) -> anyhow::Result<PoolSelection> {
    let Some(pool) = self.pools.get(pool_name).cloned() else {
      bail!("unknown upstream pool {pool_name}");
    };
    let algorithm = policy_override
      .and_then(parse_policy_override)
      .unwrap_or(pool.config.algorithm);
    let excluded_upstreams = excluded_upstreams
      .iter()
      .map(String::as_str)
      .collect::<HashSet<_>>();

    let (server, sticky_cookie) = if algorithm == LoadBalancingAlgorithm::StickyCookie {
      sticky::select_sticky_cookie(
        &pool,
        client_ip,
        hash_key,
        cookie_header,
        &excluded_upstreams,
      )
    } else {
      (
        select_by_algorithm(&pool, algorithm, client_ip, hash_key, &excluded_upstreams),
        None,
      )
    };
    let server = server
      .ok_or_else(|| anyhow::anyhow!("upstream pool {pool_name} has no available servers"))?;
    Ok(self.selection_from_server(pool_name, server, sticky_cookie))
  }

  pub fn snapshots(&self) -> Vec<PoolRuntimeSnapshot> {
    let mut snapshots = self.pools.values().map(pool_snapshot).collect::<Vec<_>>();
    snapshots.sort_by(|left, right| left.name.cmp(&right.name));
    snapshots
  }

  pub fn snapshot(&self, pool_name: &str) -> Option<PoolRuntimeSnapshot> {
    self.pools.get(pool_name).map(pool_snapshot)
  }

  pub fn publish_server_count_metrics(&self) {
    let Some(metrics) = &self.metrics else {
      return;
    };
    let mut counts = HashMap::new();
    for pool in self.snapshots() {
      for server in pool.servers {
        *counts
          .entry((
            pool.name.clone(),
            server.source,
            server.state,
            server.health_reason,
          ))
          .or_insert(0_u64) += 1;
      }
    }
    metrics.set_upstream_pool_server_counts(
      counts
        .into_iter()
        .map(|((pool, source, state, reason), count)| (pool, source, state, reason, count))
        .collect(),
    );
  }

  pub fn report_success(&self, upstream_name: &str) {
    self.report_success_with_reason(upstream_name, HEALTH_REASON_PASSIVE_SUCCESS);
  }

  pub async fn report_success_async(&self, upstream_name: &str) {
    self.report_success(upstream_name);
    self.report_shared_health_async(upstream_name, true).await;
  }

  pub fn report_active_success(&self, upstream_name: &str) {
    self.report_success_with_reason(upstream_name, HEALTH_REASON_ACTIVE_SUCCESS);
  }

  pub async fn report_active_success_async(&self, upstream_name: &str) {
    self.report_active_success(upstream_name);
    self.report_shared_health_async(upstream_name, true).await;
  }

  fn report_success_with_reason(&self, upstream_name: &str, reason: u8) {
    if self.pools.is_empty() {
      return;
    }
    if let Some((pool, server)) = self.find_pool_server(upstream_name) {
      let now_ms = mark_health_report(&server, reason);
      self.record_health_report(&pool, &server, true, reason);
      server.consecutive_failures.store(0, Ordering::Relaxed);
      let successes = server.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
      if !pool.config.health_check.enabled
        || successes >= pool.config.health_check.healthy_threshold
      {
        set_server_health(&server, true, now_ms);
      }
      self.publish_server_count_metrics();
    }
  }

  pub fn report_success_latency(&self, upstream_name: &str, latency_ms: u64) {
    if let Some((_, server)) = self.find_pool_server(upstream_name) {
      observe_ewma_latency(&server, latency_ms);
    }
    self.report_success_with_reason(upstream_name, HEALTH_REASON_PASSIVE_SUCCESS);
  }

  pub async fn report_success_latency_async(&self, upstream_name: &str, latency_ms: u64) {
    self.report_success_latency(upstream_name, latency_ms);
    self.report_shared_health_async(upstream_name, true).await;
  }

  pub fn report_failure(&self, upstream_name: &str) {
    self.report_failure_with_reason(upstream_name, HEALTH_REASON_PASSIVE_FAILURE);
  }

  pub async fn report_failure_async(&self, upstream_name: &str) {
    self.report_failure(upstream_name);
    self.report_shared_health_async(upstream_name, false).await;
  }

  pub fn report_active_failure(&self, upstream_name: &str) {
    self.report_failure_with_reason(upstream_name, HEALTH_REASON_ACTIVE_FAILURE);
  }

  pub async fn report_active_failure_async(&self, upstream_name: &str) {
    self.report_active_failure(upstream_name);
    self.report_shared_health_async(upstream_name, false).await;
  }

  fn report_failure_with_reason(&self, upstream_name: &str, reason: u8) {
    if self.pools.is_empty() {
      return;
    }
    if let Some((pool, server)) = self.find_pool_server(upstream_name) {
      let now_ms = mark_health_report(&server, reason);
      observe_ewma_latency(&server, EWMA_FAILURE_PENALTY_MS);
      self.record_health_report(&pool, &server, false, reason);
      let shared_health = None;
      server.consecutive_successes.store(0, Ordering::Relaxed);
      let failures = server.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
      if let Some(healthy) = shared_health {
        set_server_health(&server, healthy, now_ms);
      }
      if maybe_eject_outlier(&pool, &server, failures, now_ms) {
        self.record_outlier_ejection(&pool, &server);
      }
      if pool.config.health_check.enabled
        && failures >= pool.config.health_check.unhealthy_threshold
      {
        set_server_health(&server, false, now_ms);
      }
      self.publish_server_count_metrics();
    }
  }

  fn find_pool_server(
    &self,
    upstream_name: &str,
  ) -> Option<(Arc<PoolRuntime>, Arc<PoolServerRuntime>)> {
    for pool in self.pools.values() {
      for server in &pool.servers {
        if server.upstream_name == upstream_name {
          return Some((pool.clone(), server.clone()));
        }
      }
    }
    None
  }

  fn selection_from_server(
    &self,
    pool_name: &str,
    server: Arc<PoolServerRuntime>,
    sticky_cookie: Option<HeaderValue>,
  ) -> PoolSelection {
    server.local_active.fetch_add(1, Ordering::Relaxed);
    PoolSelection {
      pool_name: pool_name.to_string(),
      upstream_name: server.upstream_name.clone(),
      server,
      shared_state: self.shared_state.clone(),
      sticky_cookie,
    }
  }

  fn record_health_report(
    &self,
    pool: &PoolRuntime,
    server: &PoolServerRuntime,
    success: bool,
    reason: u8,
  ) {
    let Some(metrics) = &self.metrics else {
      return;
    };
    if let Some(source) = source_for_server(pool, server) {
      metrics.record_upstream_pool_health_report(
        &pool.config.name,
        source.as_str(),
        if success { "success" } else { "failure" },
        health_reason_label(reason),
      );
    }
  }

  fn record_outlier_ejection(&self, pool: &PoolRuntime, server: &PoolServerRuntime) {
    let Some(metrics) = &self.metrics else {
      return;
    };
    if let Some(source) = source_for_server(pool, server) {
      metrics.record_upstream_pool_outlier_ejection(
        &pool.config.name,
        source.as_str(),
        health_reason_label(HEALTH_REASON_OUTLIER_EJECTED),
      );
    }
  }
}

impl PoolSelection {
  pub fn sticky_cookie(&self) -> Option<HeaderValue> {
    self.sticky_cookie.clone()
  }
}

fn observe_ewma_latency(server: &PoolServerRuntime, sample_ms: u64) {
  let sample_ms = sample_ms.max(1);
  let _ = server
    .ewma_latency_ms
    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
      Some(if current == 0 {
        sample_ms
      } else {
        current
          .saturating_mul(7)
          .saturating_add(sample_ms)
          .saturating_div(8)
      })
    });
}

fn server_capacity_available(
  pool: &PoolRuntime,
  index: usize,
  server: &Arc<PoolServerRuntime>,
) -> bool {
  let max_conns = pool.config.servers[index].max_conns;
  max_conns == 0 || active_count(pool, server) < max_conns
}
fn active_count(_pool: &PoolRuntime, server: &PoolServerRuntime) -> usize {
  let local_active = server.local_active.load(Ordering::Relaxed);
  local_active.max(server.shared_active.load(Ordering::Relaxed))
}

fn server_config(pool: &PoolRuntime, index: usize) -> &UpstreamPoolServerConfig {
  &pool.config.servers[index]
}

#[allow(dead_code)]
pub(crate) fn synthetic_upstream_name(pool: &str, index: usize) -> String {
  format!("pool:{pool}:{index}")
}

pub(crate) fn synthetic_upstream_name_for_id(pool: &str, server_id: &str) -> String {
  if server_id_is_public_label_safe(server_id) {
    return format!("pool:{pool}:{server_id}");
  }
  format!(
    "pool:{pool}:server-{:016x}",
    stable_server_label_hash(pool, server_id)
  )
}

fn server_id_is_public_label_safe(server_id: &str) -> bool {
  !server_id.is_empty()
    && server_id.len() <= 64
    && server_id
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn stable_server_label_hash(pool: &str, server_id: &str) -> u64 {
  let mut hash = 0xcbf29ce484222325_u64;
  for byte in pool
    .as_bytes()
    .iter()
    .copied()
    .chain([0xff])
    .chain(server_id.as_bytes().iter().copied())
  {
    hash ^= u64::from(byte);
    hash = hash.wrapping_mul(0x100000001b3);
  }
  hash
}

fn pool_snapshot(pool: &Arc<PoolRuntime>) -> PoolRuntimeSnapshot {
  let now_ms = now_millis();
  let mut servers = pool
    .servers
    .iter()
    .enumerate()
    .map(|(index, server)| {
      let config = server_config(pool, index);
      let ejected_until_ms = server.ejected_until_ms.load(Ordering::Relaxed);
      PoolServerRuntimeSnapshot {
        id: server.server_id.clone(),
        upstream_name: server.upstream_name.clone(),
        origin: config.origin.to_string(),
        source: config.source.as_str().to_string(),
        state: config.state.as_str().to_string(),
        weight: config.weight,
        max_conns: config.max_conns,
        backup: config.backup,
        active: active_count(pool, server),
        healthy: server_healthy(pool, server),
        health_reason: health_reason_label(server.health_reason.load(Ordering::Relaxed))
          .to_string(),
        last_health_check_ms: optional_millis(server.last_health_check_ms.load(Ordering::Relaxed)),
        ejected_until_ms: optional_millis(ejected_until_ms),
        ejection_count: server.ejection_count.load(Ordering::Relaxed),
        slow_start_remaining_ms: slow_start_remaining_ms_at(pool, server, now_ms),
        effective_weight_percent: effective_weight_percent_at(pool, server, now_ms),
      }
    })
    .collect::<Vec<_>>();
  servers.sort_by(|left, right| left.id.cmp(&right.id));
  PoolRuntimeSnapshot {
    name: pool.config.name.clone(),
    algorithm: format!("{:?}", pool.config.algorithm),
    servers,
  }
}

#[cfg(test)]
mod tests;
