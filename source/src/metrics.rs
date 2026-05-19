use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use http::StatusCode;

use crate::cache::CacheStats;
use crate::tls::TlsServerSessionStorageStats;

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

  pub fn prometheus(
    &self,
    cache: CacheStats,
    tls_session_storage: TlsServerSessionStorageStats,
  ) -> String {
    let mut output = String::new();
    append_metric(
      &mut output,
      "oxibelt_requests_total",
      "counter",
      self.requests_total.load(),
    );
    append_metric(
      &mut output,
      "oxibelt_responses_total",
      "counter",
      self.responses_total.load(),
    );
    append_metric(
      &mut output,
      "oxibelt_upstream_errors_total",
      "counter",
      self.upstream_errors_total.load(),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_hits_total",
      "counter",
      self.cache_hits_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_misses_total",
      "counter",
      self.cache_misses_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_revalidations_total",
      "counter",
      self.cache_revalidations_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_stale_served_total",
      "counter",
      self.cache_stale_served_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_purges_total",
      "counter",
      self.cache_purges_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_tag_purges_total",
      "counter",
      self.cache_tag_purges_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_admission_rejections_total",
      "counter",
      self
        .cache_admission_rejections_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_fill_waiters_total",
      "counter",
      self.cache_fill_waiters_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_fill_lock_conflicts_total",
      "counter",
      self.cache_fill_lock_conflicts_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_fill_lock_timeouts_total",
      "counter",
      self.cache_fill_lock_timeouts_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_fill_errors_total",
      "counter",
      self.cache_fill_errors_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_background_refresh_success_total",
      "counter",
      self
        .cache_background_refresh_success_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_background_refresh_errors_total",
      "counter",
      self
        .cache_background_refresh_errors_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_background_refresh_skips_total",
      "counter",
      self
        .cache_background_refresh_skips_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_dynamic_policy_matches_total",
      "counter",
      self.dynamic_policy_matches_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_dynamic_policy_rejects_total",
      "counter",
      self.dynamic_policy_rejects_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_dynamic_policy_rate_limit_denied_total",
      "counter",
      self
        .dynamic_policy_rate_limit_denied_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_dynamic_policy_refresh_success_total",
      "counter",
      self
        .dynamic_policy_refresh_success_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_dynamic_policy_refresh_errors_total",
      "counter",
      self
        .dynamic_policy_refresh_errors_total
        .load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_dynamic_policy_active_policies",
      "gauge",
      self.dynamic_policy_active_policies.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_cache_disk_recovered_entries_total",
      "counter",
      cache.disk_recovered_entries_total,
    );
    append_metric(
      &mut output,
      "oxibelt_cache_disk_recovery_errors_total",
      "counter",
      cache.disk_recovery_errors_total,
    );
    append_metric(
      &mut output,
      "oxibelt_cache_disk_recovery_removed_files_total",
      "counter",
      cache.disk_recovery_removed_files_total,
    );
    append_metric(
      &mut output,
      "oxibelt_cache_memory_entries",
      "gauge",
      cache.memory_entries,
    );
    append_metric(
      &mut output,
      "oxibelt_cache_disk_entries",
      "gauge",
      cache.disk_entries,
    );
    append_metric(
      &mut output,
      "oxibelt_cache_tmpfs_entries",
      "gauge",
      cache.tmpfs_entries,
    );
    append_metric(
      &mut output,
      "oxibelt_cache_memory_bytes",
      "gauge",
      cache.memory_bytes,
    );
    append_metric(
      &mut output,
      "oxibelt_cache_disk_bytes",
      "gauge",
      cache.disk_bytes,
    );
    append_metric(
      &mut output,
      "oxibelt_cache_tmpfs_bytes",
      "gauge",
      cache.tmpfs_bytes,
    );
    append_metric(
      &mut output,
      "oxibelt_tls_server_session_storage_put_total",
      "counter",
      tls_session_storage.put_count,
    );
    append_metric(
      &mut output,
      "oxibelt_tls_server_session_storage_get_total",
      "counter",
      tls_session_storage.get_count,
    );
    append_metric(
      &mut output,
      "oxibelt_tls_server_session_storage_take_total",
      "counter",
      tls_session_storage.take_count,
    );
    append_metric(
      &mut output,
      "oxibelt_tls_server_session_storage_lock_wait_ns_total",
      "counter",
      tls_session_storage.lock_wait_ns,
    );
    append_metric(
      &mut output,
      "oxibelt_tls_server_session_storage_put_duration_ns_total",
      "counter",
      tls_session_storage.put_duration_ns,
    );
    output
  }
}

fn append_metric(output: &mut String, name: &str, kind: &str, value: impl std::fmt::Display) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push(' ');
  output.push_str(kind);
  output.push('\n');
  output.push_str(name);
  output.push(' ');
  output.push_str(&value.to_string());
  output.push('\n');
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn prometheus_output_omits_waf_rule_metadata() {
    let metrics = Metrics::new();
    let body = metrics.prometheus(
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );

    assert!(body.contains("oxibelt_requests_total"));
    assert!(body.contains("oxibelt_cache_tag_purges_total"));
    assert!(body.contains("oxibelt_cache_background_refresh_success_total"));
    assert!(body.contains("oxibelt_cache_disk_recovered_entries_total"));
    assert!(body.contains("oxibelt_tls_server_session_storage_put_total"));
    assert!(!body.contains("oxibelt_waf_rule_hits_total"));
    assert!(!body.contains("rule_name"));
    assert!(!body.contains("rule_id"));
  }

  #[test]
  fn prometheus_output_includes_tls_session_storage_diagnostics() {
    let metrics = Metrics::new();
    let body = metrics.prometheus(
      CacheStats::default(),
      TlsServerSessionStorageStats {
        put_count: 11,
        get_count: 13,
        take_count: 17,
        lock_wait_ns: 19,
        put_duration_ns: 23,
      },
    );

    assert!(body.contains("oxibelt_tls_server_session_storage_put_total 11"));
    assert!(body.contains("oxibelt_tls_server_session_storage_get_total 13"));
    assert!(body.contains("oxibelt_tls_server_session_storage_take_total 17"));
    assert!(body.contains("oxibelt_tls_server_session_storage_lock_wait_ns_total 19"));
    assert!(body.contains("oxibelt_tls_server_session_storage_put_duration_ns_total 23"));
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

    let body = metrics.prometheus(
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );
    assert!(body.contains("oxibelt_requests_total 7\n"));
    assert!(body.contains("oxibelt_responses_total 4\n"));
    assert!(body.contains("oxibelt_upstream_errors_total 2\n"));
  }
}
