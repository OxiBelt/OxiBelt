use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;

use crate::cache::CacheStats;

#[derive(Debug, Default)]
pub struct Metrics {
  requests_total: AtomicU64,
  responses_total: AtomicU64,
  upstream_errors_total: AtomicU64,
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
}

impl Metrics {
  pub fn new() -> Arc<Self> {
    Arc::new(Self::default())
  }

  pub fn record_request(&self) {
    self.requests_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_response(&self, status: StatusCode) {
    self.responses_total.fetch_add(1, Ordering::Relaxed);
    if status.is_server_error() {
      self.upstream_errors_total.fetch_add(1, Ordering::Relaxed);
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

  pub fn prometheus(&self, cache: CacheStats) -> String {
    format!(
      "# TYPE oxibelt_requests_total counter\noxibelt_requests_total {}\n# TYPE oxibelt_responses_total counter\noxibelt_responses_total {}\n# TYPE oxibelt_upstream_errors_total counter\noxibelt_upstream_errors_total {}\n# TYPE oxibelt_cache_hits_total counter\noxibelt_cache_hits_total {}\n# TYPE oxibelt_cache_misses_total counter\noxibelt_cache_misses_total {}\n# TYPE oxibelt_cache_revalidations_total counter\noxibelt_cache_revalidations_total {}\n# TYPE oxibelt_cache_stale_served_total counter\noxibelt_cache_stale_served_total {}\n# TYPE oxibelt_cache_purges_total counter\noxibelt_cache_purges_total {}\n# TYPE oxibelt_cache_tag_purges_total counter\noxibelt_cache_tag_purges_total {}\n# TYPE oxibelt_cache_admission_rejections_total counter\noxibelt_cache_admission_rejections_total {}\n# TYPE oxibelt_cache_fill_waiters_total counter\noxibelt_cache_fill_waiters_total {}\n# TYPE oxibelt_cache_fill_lock_conflicts_total counter\noxibelt_cache_fill_lock_conflicts_total {}\n# TYPE oxibelt_cache_fill_lock_timeouts_total counter\noxibelt_cache_fill_lock_timeouts_total {}\n# TYPE oxibelt_cache_fill_errors_total counter\noxibelt_cache_fill_errors_total {}\n# TYPE oxibelt_cache_background_refresh_success_total counter\noxibelt_cache_background_refresh_success_total {}\n# TYPE oxibelt_cache_background_refresh_errors_total counter\noxibelt_cache_background_refresh_errors_total {}\n# TYPE oxibelt_cache_background_refresh_skips_total counter\noxibelt_cache_background_refresh_skips_total {}\n# TYPE oxibelt_cache_disk_recovered_entries_total counter\noxibelt_cache_disk_recovered_entries_total {}\n# TYPE oxibelt_cache_disk_recovery_errors_total counter\noxibelt_cache_disk_recovery_errors_total {}\n# TYPE oxibelt_cache_disk_recovery_removed_files_total counter\noxibelt_cache_disk_recovery_removed_files_total {}\n# TYPE oxibelt_cache_memory_entries gauge\noxibelt_cache_memory_entries {}\n# TYPE oxibelt_cache_disk_entries gauge\noxibelt_cache_disk_entries {}\n# TYPE oxibelt_cache_tmpfs_entries gauge\noxibelt_cache_tmpfs_entries {}\n# TYPE oxibelt_cache_memory_bytes gauge\noxibelt_cache_memory_bytes {}\n# TYPE oxibelt_cache_disk_bytes gauge\noxibelt_cache_disk_bytes {}\n# TYPE oxibelt_cache_tmpfs_bytes gauge\noxibelt_cache_tmpfs_bytes {}\n",
      self.requests_total.load(Ordering::Relaxed),
      self.responses_total.load(Ordering::Relaxed),
      self.upstream_errors_total.load(Ordering::Relaxed),
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
}
