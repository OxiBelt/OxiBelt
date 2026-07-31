//! Best-effort process resource discovery for automatic circuit-breaker limits.
//!
//! Discovery never decides whether a configuration is valid. It only turns a
//! validated `"auto"` setting into a conservative process-local number, and
//! therefore always has a safe one-core / modest-memory fallback.

use std::fs;
use std::time::Duration;

use crate::config::{CircuitBreakerScopeConfig, Config};
use anyhow::{Context, ensure};

const MAX_COMPIO_DIRECT_H1_WORKERS: usize = 256;
const MAX_COMPIO_DIRECT_H1_QUEUE_ENTRIES: usize = 4_096;
const MAX_COMPIO_DIRECT_H1_CONNECTIONS: usize = 4_096;
const COMPIO_DIRECT_H1_WORKER_MEMORY_RESERVATION_BYTES: u64 = 8 * 1024 * 1024;
const COMPIO_DIRECT_H1_QUEUE_ENTRY_MEMORY_BYTES: u64 = 64 * 1024;
const COMPIO_DIRECT_H1_CONNECTION_MEMORY_BYTES: u64 = 32 * 1024;
/// Reload keeps the active fleet alive while one replacement fleet is staged.
const COMPIO_DIRECT_H1_MAX_OVERLAPPING_FLEETS: u64 = 2;
/// Independent resource partitions keep two overlapping fleets below the
/// discovered process memory ceiling: workers 1/2, queues 1/8, connections 1/4.
const COMPIO_DIRECT_H1_WORKER_MEMORY_PARTITION: u64 = 2;
const COMPIO_DIRECT_H1_QUEUE_MEMORY_PARTITION: u64 = 8;
const COMPIO_DIRECT_H1_CONNECTION_MEMORY_PARTITION: u64 = 4;

#[derive(Debug, Clone, Copy)]
pub(super) struct RuntimeResources {
  pub(super) cpu: f64,
  pub(super) memory_bytes: u64,
  pub(super) usable_file_descriptors: u64,
  pub(super) buffering_bytes: u64,
  pub(super) decoded_body_bytes: u64,
}

impl RuntimeResources {
  pub(super) fn discover(config: &Config) -> Self {
    let runtime_parallelism = std::thread::available_parallelism()
      .map(|value| value.get() as f64)
      .unwrap_or(1.0);
    let cgroup_cpu = cgroup_cpu_limit();
    let cpu_request = std::env::var("OXIBELT_KUBERNETES_CPU_REQUEST")
      .ok()
      .and_then(|value| parse_cpu(&value));
    // A Kubernetes request is a scheduling signal rather than a hard cap. Use
    // it only when the cgroup did not expose a quota.
    let cpu = cgroup_cpu
      .or(cpu_request)
      .unwrap_or(runtime_parallelism)
      .min(runtime_parallelism)
      .max(0.1);
    let cgroup_memory = cgroup_memory_limit();
    let memory_request = std::env::var("OXIBELT_KUBERNETES_MEMORY_REQUEST_BYTES")
      .ok()
      .and_then(|value| value.parse::<u64>().ok());
    let memory_bytes = effective_memory_bytes(cgroup_memory, memory_request);
    let buffering_bytes = config.proxy.buffering.max_memory_body_bytes.max(64 * 1024) as u64;
    let decoded_body_bytes = config
      .waf
      .http_body_compression
      .max_decoded_body_bytes
      .max(64 * 1024) as u64;
    let reserved_file_descriptors = config
      .overload
      .reserved_capacity
      .file_descriptors
      .saturating_add(config.upstream_pools.len() as u64);
    Self {
      cpu,
      memory_bytes,
      usable_file_descriptors: effective_usable_file_descriptors(
        file_descriptor_limit(),
        reserved_file_descriptors,
      ),
      buffering_bytes,
      decoded_body_bytes,
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum AutoScope {
  Global,
  Route,
  Pool,
}

impl RuntimeResources {
  pub(super) fn active_requests(self, scope: AutoScope, global: usize) -> usize {
    match scope {
      AutoScope::Global => {
        let cpu_bound = clamp_ceil(256.0 * self.cpu, 64, 8_192);
        let memory_bound = (self.memory_bytes / self.buffering_bytes.saturating_mul(8)).max(32);
        cpu_bound.min(memory_bound as usize)
      }
      AutoScope::Route => global.min(clamp_ceil(128.0 * self.cpu, 32, 4_096)),
      AutoScope::Pool => global.min(clamp_ceil(128.0 * self.cpu, 32, 4_096)),
    }
  }

  pub(super) fn pending_requests(self, scope: AutoScope, global: usize) -> usize {
    match scope {
      AutoScope::Global => {
        let cpu_bound = clamp_ceil(32.0 * self.cpu, 8, 1_024);
        let memory_bound = (self.memory_bytes / self.buffering_bytes.saturating_mul(32)).max(4);
        cpu_bound.min(memory_bound as usize)
      }
      AutoScope::Route => global.min(clamp_ceil(16.0 * self.cpu, 4, 256)),
      AutoScope::Pool => global.min(clamp_ceil(16.0 * self.cpu, 4, 256)),
    }
  }

  pub(super) fn connections(self, scope: AutoScope, global: usize) -> usize {
    match scope {
      AutoScope::Global => clamp_ceil(64.0 * self.cpu, 16, 2_048)
        .min(usize::try_from(self.usable_file_descriptors / 4).unwrap_or(usize::MAX)),
      AutoScope::Route => global.min(clamp_ceil(16.0 * self.cpu, 4, 512)),
      AutoScope::Pool => global.min(clamp_ceil(16.0 * self.cpu, 4, 512)),
    }
  }

  pub(super) fn streams(self, scope: AutoScope, global_active: usize, global: usize) -> usize {
    match scope {
      AutoScope::Global => global_active.min(clamp_ceil(256.0 * self.cpu, 64, 8_192)),
      AutoScope::Route => global.min(clamp_ceil(128.0 * self.cpu, 32, 4_096)),
      AutoScope::Pool => global.min(clamp_ceil(128.0 * self.cpu, 32, 4_096)),
    }
  }

  pub(super) fn inspection_jobs(self, scope: AutoScope, global: usize) -> usize {
    match scope {
      AutoScope::Global => clamp_ceil(2.0 * self.cpu, 1, 64)
        .min((self.memory_bytes / self.decoded_body_bytes.saturating_mul(4)).max(1) as usize),
      AutoScope::Route | AutoScope::Pool => global.min(clamp_ceil(self.cpu, 1, 32)),
    }
  }

  pub(super) fn retry_concurrency(self) -> usize {
    clamp_ceil(4.0 * self.cpu, 1, 128)
  }

  pub(super) fn retry_queue(self, retry_concurrency: usize) -> usize {
    retry_concurrency.saturating_mul(2).min(256)
  }
}

pub(super) fn configured_capacity(
  setting: crate::config::CapacitySetting,
  automatic: usize,
) -> usize {
  setting.fixed().unwrap_or(automatic).max(1)
}

pub(super) fn configured_queue_capacity(
  setting: crate::config::CapacitySetting,
  automatic: usize,
) -> usize {
  setting.fixed().unwrap_or(automatic)
}

fn configured_connection_capacity(
  setting: crate::config::CapacitySetting,
  automatic: usize,
) -> usize {
  setting.fixed().unwrap_or(automatic)
}

pub(super) fn scope_defaults(
  resources: RuntimeResources,
  scope: AutoScope,
  config: &CircuitBreakerScopeConfig,
  global: Option<&ResolvedAutoScope>,
) -> ResolvedAutoScope {
  let global_active = global.map_or_else(
    || resources.active_requests(AutoScope::Global, usize::MAX),
    |value| value.active_requests,
  );
  let global_pending = global.map_or_else(
    || resources.pending_requests(AutoScope::Global, usize::MAX),
    |value| value.pending_requests,
  );
  let global_connections = global.map_or_else(
    || resources.connections(AutoScope::Global, usize::MAX),
    |value| value.connections,
  );
  let global_streams = global.map_or_else(
    || resources.streams(AutoScope::Global, global_active, usize::MAX),
    |value| value.streams,
  );
  let global_inspection = global.map_or_else(
    || resources.inspection_jobs(AutoScope::Global, usize::MAX),
    |value| value.inspection_jobs,
  );
  let active_automatic = resources.active_requests(scope, global_active);
  let pending_automatic = resources.pending_requests(scope, global_pending);
  let connection_automatic = resources.connections(scope, global_connections);
  let stream_automatic = resources.streams(scope, global_active, global_streams);
  let inspection_automatic = resources.inspection_jobs(scope, global_inspection);
  ResolvedAutoScope {
    active_requests: configured_capacity(config.max_active_requests, active_automatic),
    pending_requests: configured_queue_capacity(config.max_pending_requests, pending_automatic),
    connections: configured_connection_capacity(config.max_connections, connection_automatic),
    streams: configured_capacity(config.max_streams, stream_automatic),
    inspection_jobs: configured_capacity(config.max_body_inspection_jobs, inspection_automatic),
    decompression_jobs: configured_capacity(config.max_decompression_jobs, inspection_automatic),
  }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ResolvedAutoScope {
  pub(super) active_requests: usize,
  pub(super) pending_requests: usize,
  pub(super) connections: usize,
  pub(super) streams: usize,
  pub(super) inspection_jobs: usize,
  pub(super) decompression_jobs: usize,
}

/// A bounded transport-service projection of the existing process-local circuit-breaker policy.
///
/// This is deliberately not a second configuration surface. The Compio direct-H1 service uses
/// the same resolved queue, timeout, and connection budgets as the established admission layer.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct CompioDirectH1Budget {
  pub(crate) worker_count: usize,
  pub(crate) queue_capacity_per_worker: usize,
  pub(crate) max_waiters: usize,
  pub(crate) queue_wait_timeout: Duration,
  pub(crate) max_connections_global: usize,
  pub(crate) max_connections_per_origin: usize,
}

pub(crate) fn compio_direct_h1_budget(config: &Config) -> anyhow::Result<CompioDirectH1Budget> {
  let worker_count = config.runtime.worker_threads;
  ensure!(
    worker_count > 0,
    "runtime.worker_threads must be greater than 0 before resolving the Compio direct-H1 budget"
  );

  let resources = RuntimeResources::discover(config);
  let safe_worker_count = compio_worker_memory_limit(resources.memory_bytes);
  ensure!(
    worker_count <= safe_worker_count,
    "resolved Compio direct-H1 worker count {worker_count} exceeds the internal resource safety limit {safe_worker_count}"
  );
  let global = scope_defaults(
    resources,
    AutoScope::Global,
    &config.circuit_breakers.global,
    None,
  );
  let per_origin = scope_defaults(
    resources,
    AutoScope::Pool,
    &config.circuit_breakers.pool_defaults,
    Some(&global),
  );
  let memory_connection_limit = compio_connection_memory_limit(resources.memory_bytes);
  let file_descriptor_connection_limit = usize::try_from(
    resources.usable_file_descriptors / 4 / COMPIO_DIRECT_H1_MAX_OVERLAPPING_FLEETS,
  )
  .unwrap_or(usize::MAX);
  let safe_connection_limit = memory_connection_limit
    .min(file_descriptor_connection_limit)
    .min(MAX_COMPIO_DIRECT_H1_CONNECTIONS);
  ensure!(
    global.connections <= safe_connection_limit,
    "resolved Compio direct-H1 global connection capacity {} exceeds the internal resource safety limit {safe_connection_limit}",
    global.connections
  );
  let max_connections_per_origin = per_origin.connections.min(global.connections);
  ensure!(
    max_connections_per_origin <= safe_connection_limit,
    "resolved Compio direct-H1 per-origin connection capacity {max_connections_per_origin} exceeds the internal resource safety limit {safe_connection_limit}"
  );
  ensure!(
    global.connections > 0 && max_connections_per_origin > 0,
    "resolved Compio direct-H1 connection capacity is zero after process resource reservations"
  );
  // Worker handoff slots cover both the configured external pending share and
  // the worker's share of the already-bounded active-operation ceiling. The
  // global operation semaphore still caps queued plus active work at
  // `global.connections`; this capacity prevents a one-slot cross-runtime
  // convoy without admitting additional operations.
  let queue_capacity_per_worker = global
    .pending_requests
    .div_ceil(worker_count)
    .max(global.connections.div_ceil(worker_count))
    .max(1);
  let physical_queue_capacity = worker_count
    .checked_mul(queue_capacity_per_worker)
    .context("resolved Compio direct-H1 submission capacity is too large")?;
  let combined_queue_capacity = physical_queue_capacity
    .checked_add(global.pending_requests)
    .context("resolved Compio direct-H1 combined queue and waiter capacity is too large")?;
  let safe_queue_capacity = compio_queue_memory_limit(resources.memory_bytes);
  ensure!(
    combined_queue_capacity <= safe_queue_capacity,
    "resolved Compio direct-H1 queue capacity {physical_queue_capacity} with {} waiters has combined capacity {combined_queue_capacity}, which exceeds the internal memory safety limit {safe_queue_capacity}",
    global.pending_requests
  );

  Ok(CompioDirectH1Budget {
    worker_count,
    queue_capacity_per_worker,
    max_waiters: global.pending_requests,
    queue_wait_timeout: Duration::from_millis(
      config.circuit_breakers.global.pending_queue_timeout_ms,
    ),
    max_connections_global: global.connections,
    max_connections_per_origin,
  })
}

fn clamp_ceil(value: f64, min: usize, max: usize) -> usize {
  value.ceil().clamp(min as f64, max as f64) as usize
}

fn effective_memory_bytes(cgroup: Option<u64>, kubernetes_request: Option<u64>) -> u64 {
  cgroup.or(kubernetes_request).unwrap_or(512 * 1024 * 1024)
}

fn effective_usable_file_descriptors(discovered: Option<u64>, reserved: u64) -> u64 {
  discovered.unwrap_or(1_024).saturating_sub(reserved)
}

fn compio_worker_memory_limit(memory_bytes: u64) -> usize {
  usize::try_from(
    memory_bytes
      / COMPIO_DIRECT_H1_WORKER_MEMORY_PARTITION
      / COMPIO_DIRECT_H1_MAX_OVERLAPPING_FLEETS
      / COMPIO_DIRECT_H1_WORKER_MEMORY_RESERVATION_BYTES,
  )
  .unwrap_or(usize::MAX)
  .min(MAX_COMPIO_DIRECT_H1_WORKERS)
}

fn compio_queue_memory_limit(memory_bytes: u64) -> usize {
  usize::try_from(
    memory_bytes
      / COMPIO_DIRECT_H1_QUEUE_MEMORY_PARTITION
      / COMPIO_DIRECT_H1_MAX_OVERLAPPING_FLEETS
      / COMPIO_DIRECT_H1_QUEUE_ENTRY_MEMORY_BYTES,
  )
  .unwrap_or(usize::MAX)
  .min(MAX_COMPIO_DIRECT_H1_QUEUE_ENTRIES)
}

fn compio_connection_memory_limit(memory_bytes: u64) -> usize {
  usize::try_from(
    memory_bytes
      / COMPIO_DIRECT_H1_CONNECTION_MEMORY_PARTITION
      / COMPIO_DIRECT_H1_MAX_OVERLAPPING_FLEETS
      / COMPIO_DIRECT_H1_CONNECTION_MEMORY_BYTES,
  )
  .unwrap_or(usize::MAX)
}

fn cgroup_cpu_limit() -> Option<f64> {
  let quota = fs::read_to_string("/sys/fs/cgroup/cpu.max")
    .ok()
    .and_then(|value| {
      let mut parts = value.split_whitespace();
      let quota = parts.next()?;
      let period = parts.next()?.parse::<f64>().ok()?;
      (quota != "max")
        .then(|| quota.parse::<f64>().ok().map(|quota| quota / period))
        .flatten()
    });
  let cpuset = fs::read_to_string("/sys/fs/cgroup/cpuset.cpus.effective")
    .ok()
    .and_then(|value| parse_cpu_set(&value))
    .map(|count| count as f64);
  match (quota, cpuset) {
    (Some(quota), Some(cpuset)) => Some(quota.min(cpuset)),
    (Some(quota), None) => Some(quota),
    (None, Some(cpuset)) => Some(cpuset),
    (None, None) => None,
  }
}

fn cgroup_memory_limit() -> Option<u64> {
  [
    "/sys/fs/cgroup/memory.max",
    "/sys/fs/cgroup/memory/memory.limit_in_bytes",
  ]
  .into_iter()
  .find_map(|path| {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim();
    if value == "max" {
      return None;
    }
    let value = value.parse::<u64>().ok()?;
    // cgroup v1 uses a very large sentinel for an unlimited controller.
    (value < (1_u64 << 60)).then_some(value)
  })
}

fn file_descriptor_limit() -> Option<u64> {
  let limits = fs::read_to_string("/proc/self/limits").ok()?;
  limits.lines().find_map(|line| {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    (fields.len() >= 4 && fields[0] == "Max" && fields[1] == "open")
      .then(|| fields[3].parse::<u64>().ok())
      .flatten()
  })
}

fn parse_cpu(value: &str) -> Option<f64> {
  let value = value.trim();
  if let Some(millicores) = value.strip_suffix('m') {
    return millicores
      .parse::<f64>()
      .ok()
      .filter(|value| *value > 0.0)
      .map(|value| value / 1_000.0);
  }
  value.parse::<f64>().ok().filter(|value| *value > 0.0)
}

fn parse_cpu_set(value: &str) -> Option<usize> {
  let mut count = 0_usize;
  for range in value.trim().split(',').filter(|value| !value.is_empty()) {
    let mut parts = range.split('-');
    let start = parts.next()?.parse::<usize>().ok()?;
    let end = match parts.next() {
      Some(value) => value.parse::<usize>().ok()?,
      None => start,
    };
    if parts.next().is_some() || end < start {
      return None;
    }
    count = count.checked_add(end.checked_sub(start)?.checked_add(1)?)?;
  }
  (count > 0).then_some(count)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cpu_set_parser_handles_ranges() {
    assert_eq!(parse_cpu_set("0-2,4,8-9"), Some(6));
    assert_eq!(parse_cpu_set("2-1"), None);
  }

  #[test]
  fn cpu_request_parser_accepts_kubernetes_forms() {
    assert_eq!(parse_cpu("250m"), Some(0.25));
    assert_eq!(parse_cpu("1.5"), Some(1.5));
    assert_eq!(parse_cpu("0m"), None);
  }

  #[test]
  fn known_memory_limits_are_not_inflated_to_the_fallback_floor() {
    assert_eq!(
      effective_memory_bytes(Some(8 * 1024 * 1024), None),
      8 * 1024 * 1024
    );
    assert_eq!(
      effective_memory_bytes(None, Some(12 * 1024 * 1024)),
      12 * 1024 * 1024
    );
    assert_eq!(effective_memory_bytes(None, None), 512 * 1024 * 1024);
  }

  #[test]
  fn known_file_descriptor_limits_are_not_inflated() {
    assert_eq!(effective_usable_file_descriptors(Some(32), 8), 24);
    assert_eq!(effective_usable_file_descriptors(Some(8), 32), 0);
    assert_eq!(effective_usable_file_descriptors(None, 24), 1_000);
  }

  #[test]
  fn overlapping_fleet_memory_partitions_remain_below_the_process_limit() {
    let memory_bytes = 512 * 1024 * 1024;
    let workers = compio_worker_memory_limit(memory_bytes) as u64
      * COMPIO_DIRECT_H1_WORKER_MEMORY_RESERVATION_BYTES
      * COMPIO_DIRECT_H1_MAX_OVERLAPPING_FLEETS;
    let queues = compio_queue_memory_limit(memory_bytes) as u64
      * COMPIO_DIRECT_H1_QUEUE_ENTRY_MEMORY_BYTES
      * COMPIO_DIRECT_H1_MAX_OVERLAPPING_FLEETS;
    let connections = compio_connection_memory_limit(memory_bytes) as u64
      * COMPIO_DIRECT_H1_CONNECTION_MEMORY_BYTES
      * COMPIO_DIRECT_H1_MAX_OVERLAPPING_FLEETS;

    assert!(workers <= memory_bytes / COMPIO_DIRECT_H1_WORKER_MEMORY_PARTITION);
    assert!(queues <= memory_bytes / COMPIO_DIRECT_H1_QUEUE_MEMORY_PARTITION);
    assert!(connections <= memory_bytes / COMPIO_DIRECT_H1_CONNECTION_MEMORY_PARTITION);
    assert!(workers + queues + connections <= memory_bytes * 7 / 8);
  }
}
