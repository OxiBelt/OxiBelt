use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use http::StatusCode;

use crate::cache::CacheStats;

#[derive(Debug, Default)]
pub struct Metrics {
  requests_total: StripedCounter,
  responses_total: StripedCounter,
  upstream_errors_total: StripedCounter,
  cache_hits_total: AtomicU64,
  cache_misses_total: AtomicU64,
  cache_revalidations_total: AtomicU64,
  cache_stale_served_total: AtomicU64,
  cache_purges_total: AtomicU64,
  cache_tag_purges_total: AtomicU64,
  cache_admission_rejections_total: AtomicU64,
  cache_fill_waiters_total: AtomicU64,
  cache_fill_lock_conflicts_total: AtomicU64,
  cache_fill_lock_timeouts_total: AtomicU64,
  cache_fill_errors_total: AtomicU64,
  cache_background_refresh_success_total: AtomicU64,
  cache_background_refresh_errors_total: AtomicU64,
  cache_background_refresh_skips_total: AtomicU64,
  dynamic_policy_matches_total: AtomicU64,
  dynamic_policy_rejects_total: AtomicU64,
  dynamic_policy_rate_limit_denied_total: AtomicU64,
  dynamic_policy_refresh_success_total: AtomicU64,
  dynamic_policy_refresh_errors_total: AtomicU64,
  dynamic_policy_active_policies: AtomicU64,
}

const COUNTER_STRIPES: usize = 64;
static NEXT_COUNTER_STRIPE: AtomicUsize = AtomicUsize::new(0);

thread_local! {
  static COUNTER_STRIPE: usize = NEXT_COUNTER_STRIPE.fetch_add(1, Ordering::Relaxed) % COUNTER_STRIPES;
}

#[derive(Debug)]
#[repr(align(64))]
struct PaddedAtomicU64 {
  value: AtomicU64,
}

impl Default for PaddedAtomicU64 {
  fn default() -> Self {
    Self {
      value: AtomicU64::new(0),
    }
  }
}

#[derive(Debug)]
struct StripedCounter {
  stripes: [PaddedAtomicU64; COUNTER_STRIPES],
}

impl Default for StripedCounter {
  fn default() -> Self {
    Self {
      stripes: std::array::from_fn(|_| PaddedAtomicU64::default()),
    }
  }
}

impl StripedCounter {
  fn increment(&self) {
    COUNTER_STRIPE.with(|stripe| {
      self.stripes[*stripe].value.fetch_add(1, Ordering::Relaxed);
    });
  }

  fn load(&self) -> u64 {
    self
      .stripes
      .iter()
      .map(|stripe| stripe.value.load(Ordering::Relaxed))
      .sum()
  }
}

impl Metrics {
  pub fn new() -> Arc<Self> {
    Arc::new(Self::default())
  }

  pub fn record_request(&self) {
    self.requests_total.increment();
  }

  pub fn record_response(&self, status: StatusCode) {
    self.responses_total.increment();
    if status.is_server_error() {
      self.upstream_errors_total.increment();
    }
  }

  pub fn record_cache_hit(&self) {
    self.cache_hits_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_miss(&self) {
    self.cache_misses_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_revalidation(&self) {
    self
      .cache_revalidations_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_stale(&self) {
    self
      .cache_stale_served_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_purge(&self) {
    self.cache_purges_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_tag_purge(&self) {
    self.cache_tag_purges_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_admission_rejection(&self) {
    self
      .cache_admission_rejections_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_fill_waiter(&self) {
    self
      .cache_fill_waiters_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_fill_lock_conflict(&self) {
    self
      .cache_fill_lock_conflicts_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_fill_lock_timeout(&self) {
    self
      .cache_fill_lock_timeouts_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_fill_error(&self) {
    self.cache_fill_errors_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_background_refresh_success(&self) {
    self
      .cache_background_refresh_success_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_background_refresh_error(&self) {
    self
      .cache_background_refresh_errors_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_cache_background_refresh_skip(&self) {
    self
      .cache_background_refresh_skips_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_dynamic_policy_match(&self) {
    self
      .dynamic_policy_matches_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_dynamic_policy_reject(&self) {
    self
      .dynamic_policy_rejects_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_dynamic_policy_rate_limit_denied(&self) {
    self
      .dynamic_policy_rate_limit_denied_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_dynamic_policy_refresh_success(&self) {
    self
      .dynamic_policy_refresh_success_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_dynamic_policy_refresh_error(&self) {
    self
      .dynamic_policy_refresh_errors_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn set_dynamic_policy_active_policies(&self, count: u64) {
    self
      .dynamic_policy_active_policies
      .store(count, Ordering::Relaxed);
  }

  pub fn prometheus(&self, cache: CacheStats) -> String {
    format!(
      "# TYPE oxibelt_requests_total counter\noxibelt_requests_total {}\n# TYPE oxibelt_responses_total counter\noxibelt_responses_total {}\n# TYPE oxibelt_upstream_errors_total counter\noxibelt_upstream_errors_total {}\n# TYPE oxibelt_cache_hits_total counter\noxibelt_cache_hits_total {}\n# TYPE oxibelt_cache_misses_total counter\noxibelt_cache_misses_total {}\n# TYPE oxibelt_cache_revalidations_total counter\noxibelt_cache_revalidations_total {}\n# TYPE oxibelt_cache_stale_served_total counter\noxibelt_cache_stale_served_total {}\n# TYPE oxibelt_cache_purges_total counter\noxibelt_cache_purges_total {}\n# TYPE oxibelt_cache_tag_purges_total counter\noxibelt_cache_tag_purges_total {}\n# TYPE oxibelt_cache_admission_rejections_total counter\noxibelt_cache_admission_rejections_total {}\n# TYPE oxibelt_cache_fill_waiters_total counter\noxibelt_cache_fill_waiters_total {}\n# TYPE oxibelt_cache_fill_lock_conflicts_total counter\noxibelt_cache_fill_lock_conflicts_total {}\n# TYPE oxibelt_cache_fill_lock_timeouts_total counter\noxibelt_cache_fill_lock_timeouts_total {}\n# TYPE oxibelt_cache_fill_errors_total counter\noxibelt_cache_fill_errors_total {}\n# TYPE oxibelt_cache_background_refresh_success_total counter\noxibelt_cache_background_refresh_success_total {}\n# TYPE oxibelt_cache_background_refresh_errors_total counter\noxibelt_cache_background_refresh_errors_total {}\n# TYPE oxibelt_cache_background_refresh_skips_total counter\noxibelt_cache_background_refresh_skips_total {}\n# TYPE oxibelt_dynamic_policy_matches_total counter\noxibelt_dynamic_policy_matches_total {}\n# TYPE oxibelt_dynamic_policy_rejects_total counter\noxibelt_dynamic_policy_rejects_total {}\n# TYPE oxibelt_dynamic_policy_rate_limit_denied_total counter\noxibelt_dynamic_policy_rate_limit_denied_total {}\n# TYPE oxibelt_dynamic_policy_refresh_success_total counter\noxibelt_dynamic_policy_refresh_success_total {}\n# TYPE oxibelt_dynamic_policy_refresh_errors_total counter\noxibelt_dynamic_policy_refresh_errors_total {}\n# TYPE oxibelt_dynamic_policy_active_policies gauge\noxibelt_dynamic_policy_active_policies {}\n# TYPE oxibelt_cache_disk_recovered_entries_total counter\noxibelt_cache_disk_recovered_entries_total {}\n# TYPE oxibelt_cache_disk_recovery_errors_total counter\noxibelt_cache_disk_recovery_errors_total {}\n# TYPE oxibelt_cache_disk_recovery_removed_files_total counter\noxibelt_cache_disk_recovery_removed_files_total {}\n# TYPE oxibelt_cache_memory_entries gauge\noxibelt_cache_memory_entries {}\n# TYPE oxibelt_cache_disk_entries gauge\noxibelt_cache_disk_entries {}\n# TYPE oxibelt_cache_tmpfs_entries gauge\noxibelt_cache_tmpfs_entries {}\n# TYPE oxibelt_cache_memory_bytes gauge\noxibelt_cache_memory_bytes {}\n# TYPE oxibelt_cache_disk_bytes gauge\noxibelt_cache_disk_bytes {}\n# TYPE oxibelt_cache_tmpfs_bytes gauge\noxibelt_cache_tmpfs_bytes {}\n",
      self.requests_total.load(),
      self.responses_total.load(),
      self.upstream_errors_total.load(),
      self.cache_hits_total.load(Ordering::Relaxed),
      self.cache_misses_total.load(Ordering::Relaxed),
      self.cache_revalidations_total.load(Ordering::Relaxed),
      self.cache_stale_served_total.load(Ordering::Relaxed),
      self.cache_purges_total.load(Ordering::Relaxed),
      self.cache_tag_purges_total.load(Ordering::Relaxed),
      self
        .cache_admission_rejections_total
        .load(Ordering::Relaxed),
      self.cache_fill_waiters_total.load(Ordering::Relaxed),
      self.cache_fill_lock_conflicts_total.load(Ordering::Relaxed),
      self.cache_fill_lock_timeouts_total.load(Ordering::Relaxed),
      self.cache_fill_errors_total.load(Ordering::Relaxed),
      self
        .cache_background_refresh_success_total
        .load(Ordering::Relaxed),
      self
        .cache_background_refresh_errors_total
        .load(Ordering::Relaxed),
      self
        .cache_background_refresh_skips_total
        .load(Ordering::Relaxed),
      self.dynamic_policy_matches_total.load(Ordering::Relaxed),
      self.dynamic_policy_rejects_total.load(Ordering::Relaxed),
      self
        .dynamic_policy_rate_limit_denied_total
        .load(Ordering::Relaxed),
      self
        .dynamic_policy_refresh_success_total
        .load(Ordering::Relaxed),
      self
        .dynamic_policy_refresh_errors_total
        .load(Ordering::Relaxed),
      self.dynamic_policy_active_policies.load(Ordering::Relaxed),
      cache.disk_recovered_entries_total,
      cache.disk_recovery_errors_total,
      cache.disk_recovery_removed_files_total,
      cache.memory_entries,
      cache.disk_entries,
      cache.tmpfs_entries,
      cache.memory_bytes,
      cache.disk_bytes,
      cache.tmpfs_bytes,
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn prometheus_output_omits_waf_rule_metadata() {
    let metrics = Metrics::new();
    let body = metrics.prometheus(CacheStats::default());

    assert!(body.contains("oxibelt_requests_total"));
    assert!(body.contains("oxibelt_cache_tag_purges_total"));
    assert!(body.contains("oxibelt_cache_background_refresh_success_total"));
    assert!(body.contains("oxibelt_cache_disk_recovered_entries_total"));
    assert!(!body.contains("oxibelt_waf_rule_hits_total"));
    assert!(!body.contains("rule_name"));
    assert!(!body.contains("rule_id"));
  }

  #[test]
  fn striped_counters_sum_all_increments() {
    let metrics = Metrics::new();
    for _ in 0..7 {
      metrics.record_request();
    }
    for status in [
      StatusCode::OK,
      StatusCode::CREATED,
      StatusCode::BAD_GATEWAY,
      StatusCode::GATEWAY_TIMEOUT,
    ] {
      metrics.record_response(status);
    }

    let body = metrics.prometheus(CacheStats::default());
    assert!(body.contains("oxibelt_requests_total 7\n"));
    assert!(body.contains("oxibelt_responses_total 4\n"));
    assert!(body.contains("oxibelt_upstream_errors_total 2\n"));
  }
}
