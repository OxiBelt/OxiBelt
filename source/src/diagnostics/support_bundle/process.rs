use std::collections::BTreeMap;
use std::fs;

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProcessSnapshot {
  pub open_fds: Option<usize>,
  pub rss_kib: Option<u64>,
  pub threads: Option<u64>,
  pub max_open_files: Option<LimitValue>,
}

#[derive(Debug, Serialize)]
pub struct LimitValue {
  pub soft: String,
  pub hard: String,
}

pub(super) fn process_snapshot() -> ProcessSnapshot {
  let status = proc_status_values();
  ProcessSnapshot {
    open_fds: fs::read_dir("/proc/self/fd")
      .ok()
      .map(|entries| entries.filter_map(Result::ok).count()),
    rss_kib: status.get("VmRSS").and_then(|value| parse_kib(value)),
    threads: status
      .get("Threads")
      .and_then(|value| parse_u64_prefix(value)),
    max_open_files: proc_max_open_files(),
  }
}

fn proc_status_values() -> BTreeMap<String, String> {
  let Ok(raw) = fs::read_to_string("/proc/self/status") else {
    return BTreeMap::new();
  };
  raw
    .lines()
    .filter_map(|line| {
      let (key, value) = line.split_once(':')?;
      Some((key.to_string(), value.trim().to_string()))
    })
    .collect()
}

fn proc_max_open_files() -> Option<LimitValue> {
  let raw = fs::read_to_string("/proc/self/limits").ok()?;
  raw.lines().find_map(|line| {
    let rest = line.strip_prefix("Max open files")?.trim();
    let mut parts = rest.split_whitespace();
    let soft = parts.next()?.to_string();
    let hard = parts.next()?.to_string();
    Some(LimitValue { soft, hard })
  })
}

fn parse_kib(value: &str) -> Option<u64> {
  parse_u64_prefix(value)
}

fn parse_u64_prefix(value: &str) -> Option<u64> {
  value.split_whitespace().next()?.parse().ok()
}
