use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{UpstreamPoolServerSource, upstream_pool_server_id};

use super::{PoolRuntime, PoolServerRuntime, server_config};

pub(super) const HEALTH_REASON_UNKNOWN: u8 = 0;
pub(super) const HEALTH_REASON_PASSIVE_SUCCESS: u8 = 1;
pub(super) const HEALTH_REASON_PASSIVE_FAILURE: u8 = 2;
pub(super) const HEALTH_REASON_ACTIVE_SUCCESS: u8 = 3;
pub(super) const HEALTH_REASON_ACTIVE_FAILURE: u8 = 4;
pub(super) const HEALTH_REASON_OUTLIER_EJECTED: u8 = 5;

pub(super) fn mark_health_report(server: &PoolServerRuntime, reason: u8) -> u64 {
  let now_ms = now_millis();
  server.last_health_check_ms.store(now_ms, Ordering::Relaxed);
  server.health_reason.store(reason, Ordering::Relaxed);
  now_ms
}

pub(super) fn set_server_health(server: &PoolServerRuntime, healthy: bool, now_ms: u64) {
  if healthy {
    let was_healthy = server.healthy.swap(true, Ordering::Relaxed);
    let was_ejected = server.ejected_until_ms.swap(0, Ordering::Relaxed) > now_ms;
    if !was_healthy || was_ejected {
      server.ready_since_ms.store(now_ms, Ordering::Relaxed);
    }
  } else {
    server.healthy.store(false, Ordering::Relaxed);
  }
}

pub(super) fn maybe_eject_outlier(
  pool: &PoolRuntime,
  server: &PoolServerRuntime,
  failures: u32,
  now_ms: u64,
) -> bool {
  let config = &pool.config.outlier_ejection;
  if !config.enabled || failures < config.consecutive_failures {
    return false;
  }
  let previous_ejections = server.ejection_count.fetch_add(1, Ordering::Relaxed);
  let duration = outlier_ejection_duration_ms(pool, previous_ejections);
  server
    .ejected_until_ms
    .store(now_ms.saturating_add(duration), Ordering::Relaxed);
  server
    .health_reason
    .store(HEALTH_REASON_OUTLIER_EJECTED, Ordering::Relaxed);
  true
}

fn outlier_ejection_duration_ms(pool: &PoolRuntime, previous_ejections: u32) -> u64 {
  let config = &pool.config.outlier_ejection;
  let shift = previous_ejections.min(16);
  let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
  config
    .base_ejection_ms
    .saturating_mul(multiplier)
    .min(config.max_ejection_ms)
}

pub(super) fn source_for_server(
  pool: &PoolRuntime,
  server: &PoolServerRuntime,
) -> Option<UpstreamPoolServerSource> {
  pool
    .config
    .servers
    .iter()
    .enumerate()
    .find_map(|(index, config)| {
      (upstream_pool_server_id(index, config) == server.server_id).then_some(config.source)
    })
}

pub(super) fn server_healthy(pool: &PoolRuntime, server: &PoolServerRuntime) -> bool {
  if ejection_active(server, now_millis()) {
    return false;
  }
  if let Some(shared) = &pool.shared_state
    && let Ok(Some(healthy)) = shared.pool_health(&server.upstream_name)
  {
    return healthy;
  }
  server.healthy.load(Ordering::Relaxed)
}

fn ejection_active(server: &PoolServerRuntime, now_ms: u64) -> bool {
  let ejected_until = server.ejected_until_ms.load(Ordering::Relaxed);
  if ejected_until == 0 {
    return false;
  }
  if ejected_until > now_ms {
    return true;
  }
  if server
    .ejected_until_ms
    .compare_exchange(ejected_until, 0, Ordering::Relaxed, Ordering::Relaxed)
    .is_ok()
  {
    server.ready_since_ms.store(now_ms, Ordering::Relaxed);
  }
  false
}

pub(super) fn effective_server_weight(
  pool: &PoolRuntime,
  index: usize,
  server: &PoolServerRuntime,
) -> u32 {
  let base = u64::from(server_config(pool, index).weight.max(1));
  let percent = u64::from(effective_weight_percent_at(pool, server, now_millis()));
  base
    .saturating_mul(percent)
    .saturating_add(99)
    .saturating_div(100)
    .clamp(1, u64::from(u32::MAX)) as u32
}

pub(super) fn effective_weight_percent_at(
  pool: &PoolRuntime,
  server: &PoolServerRuntime,
  now_ms: u64,
) -> u32 {
  if !pool.config.slow_start.enabled {
    return 100;
  }
  let ready_since_ms = server.ready_since_ms.load(Ordering::Relaxed);
  if ready_since_ms == 0 {
    return 100;
  }
  let elapsed = now_ms.saturating_sub(ready_since_ms);
  if elapsed >= pool.config.slow_start.duration_ms {
    return 100;
  }
  let min_percent = pool.config.slow_start.min_weight_percent.min(100);
  let span = 100u32.saturating_sub(min_percent);
  min_percent
    .saturating_add(((u64::from(span) * elapsed) / pool.config.slow_start.duration_ms) as u32)
}

pub(super) fn slow_start_remaining_ms_at(
  pool: &PoolRuntime,
  server: &PoolServerRuntime,
  now_ms: u64,
) -> Option<u64> {
  if !pool.config.slow_start.enabled {
    return None;
  }
  let ready_since_ms = server.ready_since_ms.load(Ordering::Relaxed);
  if ready_since_ms == 0 {
    return None;
  }
  pool
    .config
    .slow_start
    .duration_ms
    .checked_sub(now_ms.saturating_sub(ready_since_ms))
    .filter(|remaining| *remaining > 0)
}

pub(super) fn optional_millis(value: u64) -> Option<u64> {
  (value > 0).then_some(value)
}

pub(super) fn health_reason_label(reason: u8) -> &'static str {
  match reason {
    HEALTH_REASON_PASSIVE_SUCCESS => "passive_success",
    HEALTH_REASON_PASSIVE_FAILURE => "passive_failure",
    HEALTH_REASON_ACTIVE_SUCCESS => "active_success",
    HEALTH_REASON_ACTIVE_FAILURE => "active_failure",
    HEALTH_REASON_OUTLIER_EJECTED => "outlier_ejected",
    _ => "unknown",
  }
}

pub(super) fn now_millis() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis()
    .min(u128::from(u64::MAX)) as u64
}
