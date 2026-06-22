//! Prometheus metrics registration and update helpers.
//! Label values are constrained at call sites so exported series remain low-cardinality.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http::StatusCode;

use crate::cache::CacheStats;
use crate::config::{MetricsConfig, MetricsDetail};
use crate::tls::TlsServerSessionStorageStats;

mod auth;
mod crlite;
mod detail;
pub(crate) mod fast_path;
mod http_io;
mod ocsp;
mod outbound_revocation;
mod pool;
mod sni_forward;
mod stream;
mod upstream_client;

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
  external_auth_allowed_total: AtomicU64,
  external_auth_denied_total: AtomicU64,
  external_auth_errors_total: AtomicU64,
  request_mirror_success_total: AtomicU64,
  request_mirror_errors_total: AtomicU64,
  request_mirror_skips_total: AtomicU64,
  mitigation_queued_total: AtomicU64,
  mitigation_dropped_total: AtomicU64,
  mitigation_write_errors_total: AtomicU64,
  mitigation_fail_closed_total: AtomicU64,
  mitigation_queue_depth: AtomicU64,
  mitigation_writer_healthy: AtomicU64,
  crlite: crlite::CrliteMetrics,
  ocsp: ocsp::OcspMetrics,
  outbound_revocation: outbound_revocation::OutboundRevocationMetrics,
  fast_path: fast_path::FastPathMetrics,
  http_io: http_io::HttpIoMetrics,
  upstream_client: upstream_client::UpstreamClientMetrics,
  sni_forward: sni_forward::SniForwardMetrics,
  stream: stream::StreamMetrics,
  pool: pool::PoolMetrics,
  detailed: Mutex<detail::DetailedMetrics>,
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

  pub fn record_plain_proxy_fast_path_decision(&self, protocol: &str, outcome: &str, reason: &str) {
    self
      .fast_path
      .record_plain_proxy_decision(protocol, outcome, reason);
  }

  pub fn record_fast_path_response_body(&self, protocol: &str, disposition: &str, reason: &str) {
    self
      .fast_path
      .record_response_body(protocol, disposition, reason);
  }

  pub fn record_fast_path_request_body(&self, protocol: &str, outcome: &str) {
    self.fast_path.record_request_body(protocol, outcome);
  }

  pub fn record_fast_path_transport(
    &self,
    transport: &str,
    protocol: &str,
    outcome: &str,
    reason: &str,
  ) {
    self
      .fast_path
      .record_transport(transport, protocol, outcome, reason);
  }

  pub fn record_direct_h1_transport_hit(&self, protocol: &str) {
    self.fast_path.record_direct_h1_transport_hit(protocol);
  }

  pub fn record_direct_h1_transport_miss(&self, protocol: &str, reason: &str) {
    self
      .fast_path
      .record_direct_h1_transport_miss(protocol, reason);
  }

  pub fn record_direct_h2_transport_hit(&self, protocol: &str) {
    self.fast_path.record_direct_h2_transport_hit(protocol);
  }

  pub fn record_direct_h2_transport_miss(&self, protocol: &str, reason: &str) {
    self
      .fast_path
      .record_direct_h2_transport_miss(protocol, reason);
  }

  pub fn record_direct_h1_pool_event(&self, event: &str) {
    self.fast_path.record_direct_h1_pool_event(event);
  }

  pub fn record_direct_h2_pool_event(&self, event: &str) {
    self.fast_path.record_direct_h2_pool_event(event);
  }

  pub fn record_static_fast_path_response(&self, source: &str, outcome: &str) {
    self
      .fast_path
      .record_static_fast_path_response(source, outcome);
  }

  pub fn record_fast_path_stage_duration_ns(
    &self,
    path: &str,
    protocol: &str,
    stage: &str,
    outcome: &str,
    duration_ns: u64,
  ) {
    self
      .fast_path
      .record_stage_duration_ns(path, protocol, stage, outcome, duration_ns);
  }

  pub fn record_http_upstream_client_request(&self, version: &str, scheme: &str, pool: &str) {
    self.upstream_client.record_request(version, scheme, pool);
  }

  pub fn record_http_upstream_client_pool_miss(&self, version: &str, scheme: &str, pool: &str) {
    self.upstream_client.record_pool_miss(version, scheme, pool);
  }

  pub fn record_http_upstream_client_connection_created(
    &self,
    version: &str,
    scheme: &str,
    pool: &str,
  ) {
    self
      .upstream_client
      .record_connection_created(version, scheme, pool);
  }

  pub fn record_http_downstream_write_flush(&self, protocol: &str, transport: &str) {
    self
      .http_io
      .record_downstream_write_flush(protocol, transport);
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

  pub fn record_mitigation_queued(&self) {
    self.mitigation_queued_total.fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_mitigation_dropped(&self) {
    self
      .mitigation_dropped_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_mitigation_write_error(&self) {
    self
      .mitigation_write_errors_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_mitigation_fail_closed(&self) {
    self
      .mitigation_fail_closed_total
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn add_mitigation_queue_depth(&self, delta: i64) {
    if delta >= 0 {
      self
        .mitigation_queue_depth
        .fetch_add(delta as u64, Ordering::Relaxed);
    } else {
      self
        .mitigation_queue_depth
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
          Some(current.saturating_sub(delta.unsigned_abs()))
        })
        .ok();
    }
  }

  pub fn set_mitigation_writer_healthy(&self, healthy: bool) {
    self
      .mitigation_writer_healthy
      .store(u64::from(healthy), Ordering::Relaxed);
  }

  pub fn set_upstream_pool_server_counts(
    &self,
    counts: Vec<(String, String, String, String, u64)>,
  ) {
    self.pool.set_server_counts(counts);
  }

  pub fn record_upstream_pool_health_report(
    &self,
    pool_name: &str,
    source: &str,
    outcome: &str,
    reason: &str,
  ) {
    self
      .pool
      .record_health_report(pool_name, source, outcome, reason);
  }

  pub fn record_upstream_pool_outlier_ejection(&self, pool_name: &str, source: &str, reason: &str) {
    self.pool.record_outlier_ejection(pool_name, source, reason);
  }

  pub fn prometheus(
    &self,
    config: &MetricsConfig,
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
    auth::append_auth_and_mirror_metrics(&mut output, self);
    append_metric(
      &mut output,
      "oxibelt_mitigation_queued_total",
      "counter",
      self.mitigation_queued_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_mitigation_dropped_total",
      "counter",
      self.mitigation_dropped_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_mitigation_write_errors_total",
      "counter",
      self.mitigation_write_errors_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_mitigation_fail_closed_total",
      "counter",
      self.mitigation_fail_closed_total.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_mitigation_queue_depth",
      "gauge",
      self.mitigation_queue_depth.load(Ordering::Relaxed),
    );
    append_metric(
      &mut output,
      "oxibelt_mitigation_writer_healthy",
      "gauge",
      self.mitigation_writer_healthy.load(Ordering::Relaxed),
    );
    self.append_crlite_prometheus(&mut output);
    self.append_ocsp_prometheus(&mut output);
    self.append_outbound_revocation_prometheus(&mut output);
    self.append_fast_path_prometheus(&mut output);
    self.append_upstream_client_prometheus(&mut output);
    self.append_http_io_prometheus(&mut output);
    self.append_sni_forward_prometheus(&mut output);
    self.append_stream_prometheus(&mut output);
    self.append_upstream_pool_prometheus(&mut output);
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
    if config.detail == MetricsDetail::Detailed {
      self.append_detailed_prometheus(&mut output);
    }
    output
  }

  fn append_upstream_pool_prometheus(&self, output: &mut String) {
    self.pool.append_prometheus(output);
  }

  fn append_fast_path_prometheus(&self, output: &mut String) {
    self.fast_path.append_prometheus(output);
  }

  fn append_upstream_client_prometheus(&self, output: &mut String) {
    self.upstream_client.append_prometheus(output);
  }

  fn append_http_io_prometheus(&self, output: &mut String) {
    self.http_io.append_prometheus(output);
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
mod tests;
