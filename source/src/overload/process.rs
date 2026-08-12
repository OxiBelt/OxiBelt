//! Linux process and cgroup samples used by the overload manager.

use anyhow::{Context, Result, anyhow};

pub(super) struct ProcessSample {
  pub(super) rss_bytes: u64,
  pub(super) memory_current_bytes: u64,
  pub(super) memory_limit_bytes: Option<u64>,
  pub(super) fd_used: u64,
  pub(super) fd_limit: u64,
  pub(super) cpu_usage_usec: u64,
  pub(super) cpu_capacity: f64,
}

pub(super) fn read_process_sample() -> Result<ProcessSample> {
  let rss_bytes = read_rss_bytes()?;
  let cgroup_memory = crate::platform_resources::cgroup_memory_observation();
  let host_memory = cgroup_memory
    .is_none()
    .then(crate::platform_resources::host_memory_bytes)
    .flatten();
  let (memory_current_bytes, memory_limit_bytes) =
    select_memory_values(rss_bytes, cgroup_memory, host_memory)?;
  let fd_used = crate::platform_fs::count_directory_entries("/proc/self/fd")? as u64;
  let fd_limit = read_fd_limit()?;
  let cpu_usage_usec = read_cpu_usage_usec().unwrap_or(0);
  let cpu_capacity = read_cpu_capacity().unwrap_or_else(|| {
    std::thread::available_parallelism()
      .map(|value| value.get() as f64)
      .unwrap_or(1.0)
  });
  Ok(ProcessSample {
    rss_bytes,
    memory_current_bytes,
    memory_limit_bytes,
    fd_used,
    fd_limit,
    cpu_usage_usec,
    cpu_capacity,
  })
}

pub(super) fn select_memory_values(
  rss_bytes: u64,
  cgroup_memory: Option<crate::platform_resources::CgroupMemoryObservation>,
  host_memory_bytes: Option<u64>,
) -> Result<(u64, Option<u64>)> {
  let Some(observation) = cgroup_memory else {
    return Ok((rss_bytes, host_memory_bytes));
  };
  let current_bytes = observation
    .current_bytes
    .context("finite cgroup memory limit has no readable same-hierarchy usage value")?;
  Ok((current_bytes, Some(observation.limit_bytes)))
}

fn read_rss_bytes() -> Result<u64> {
  crate::platform_fs::read_to_string("/proc/self/status")?
    .lines()
    .find_map(|line| line.strip_prefix("VmRSS:"))
    .and_then(|value| value.split_whitespace().next())
    .and_then(|value| value.parse::<u64>().ok())
    .map(|kilobytes| kilobytes.saturating_mul(1_024))
    .ok_or_else(|| anyhow!("/proc/self/status does not contain VmRSS"))
}

fn read_fd_limit() -> Result<u64> {
  crate::platform_fs::read_to_string("/proc/self/limits")?
    .lines()
    .find(|line| line.starts_with("Max open files"))
    .and_then(|line| line.split_whitespace().nth(3))
    .and_then(|value| value.parse::<u64>().ok())
    .ok_or_else(|| anyhow!("/proc/self/limits does not contain a finite open-file limit"))
}

fn read_cpu_usage_usec() -> Option<u64> {
  crate::platform_fs::read_to_string("/sys/fs/cgroup/cpu.stat")
    .ok()?
    .lines()
    .find_map(|line| {
      let (key, value) = line.split_once(' ')?;
      (key == "usage_usec").then(|| value.parse().ok()).flatten()
    })
}

fn read_cpu_capacity() -> Option<f64> {
  let value = crate::platform_fs::read_to_string("/sys/fs/cgroup/cpu.max").ok()?;
  let mut values = value.split_whitespace();
  let quota = values.next()?;
  let period = values.next()?.parse::<f64>().ok()?;
  (quota != "max")
    .then(|| quota.parse::<f64>().ok().map(|quota| quota / period))
    .flatten()
}
