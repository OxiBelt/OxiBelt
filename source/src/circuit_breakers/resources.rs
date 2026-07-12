//! Best-effort process resource discovery for automatic circuit-breaker limits.
//!
//! Discovery never decides whether a configuration is valid. It only turns a
//! validated `"auto"` setting into a conservative process-local number, and
//! therefore always has a safe one-core / modest-memory fallback.

use std::fs;

use crate::config::{CircuitBreakerScopeConfig, Config};

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
    let memory_bytes = cgroup_memory
      .or(memory_request)
      .unwrap_or(512 * 1024 * 1024)
      .max(64 * 1024 * 1024);
    let buffering_bytes = config.proxy.buffering.max_memory_body_bytes.max(64 * 1024) as u64;
    let decoded_body_bytes = config
      .waf
      .http_body_compression
      .max_decoded_body_bytes
      .max(64 * 1024) as u64;
    let file_descriptors = file_descriptor_limit().unwrap_or(1_024).max(64);
    let reserved_file_descriptors = config
      .overload
      .reserved_capacity
      .file_descriptors
      .saturating_add(config.upstream_pools.len() as u64);
    Self {
      cpu,
      memory_bytes,
      usable_file_descriptors: file_descriptors
        .saturating_sub(reserved_file_descriptors)
        .max(1),
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
        .min((self.usable_file_descriptors / 4).max(1) as usize),
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
    connections: configured_capacity(config.max_connections, connection_automatic),
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

fn clamp_ceil(value: f64, min: usize, max: usize) -> usize {
  value.ceil().clamp(min as f64, max as f64) as usize
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
}
