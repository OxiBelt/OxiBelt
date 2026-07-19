//! Prometheus rendering for cache storage and TLS session-storage metrics.

use crate::cache::CacheStats;
use crate::tls::TlsServerSessionStorageStats;

use super::append_metric;

pub(super) fn append_storage_metrics(
  output: &mut String,
  cache: CacheStats,
  tls_session_storage: TlsServerSessionStorageStats,
) {
  append_metric(
    output,
    "oxibelt_cache_disk_recovered_entries_total",
    "counter",
    cache.disk_recovered_entries_total,
  );
  append_metric(
    output,
    "oxibelt_cache_disk_recovery_errors_total",
    "counter",
    cache.disk_recovery_errors_total,
  );
  append_metric(
    output,
    "oxibelt_cache_disk_recovery_removed_files_total",
    "counter",
    cache.disk_recovery_removed_files_total,
  );
  append_metric(
    output,
    "oxibelt_cache_memory_entries",
    "gauge",
    cache.memory_entries,
  );
  append_metric(
    output,
    "oxibelt_cache_disk_entries",
    "gauge",
    cache.disk_entries,
  );
  append_metric(
    output,
    "oxibelt_cache_tmpfs_entries",
    "gauge",
    cache.tmpfs_entries,
  );
  append_metric(
    output,
    "oxibelt_cache_memory_bytes",
    "gauge",
    cache.memory_bytes,
  );
  append_metric(
    output,
    "oxibelt_cache_disk_bytes",
    "gauge",
    cache.disk_bytes,
  );
  append_metric(
    output,
    "oxibelt_cache_tmpfs_bytes",
    "gauge",
    cache.tmpfs_bytes,
  );
  append_metric(
    output,
    "oxibelt_tls_server_session_storage_put_total",
    "counter",
    tls_session_storage.put_count,
  );
  append_metric(
    output,
    "oxibelt_tls_server_session_storage_get_total",
    "counter",
    tls_session_storage.get_count,
  );
  append_metric(
    output,
    "oxibelt_tls_server_session_storage_take_total",
    "counter",
    tls_session_storage.take_count,
  );
  append_metric(
    output,
    "oxibelt_tls_server_session_storage_lock_wait_ns_total",
    "counter",
    tls_session_storage.lock_wait_ns,
  );
  append_metric(
    output,
    "oxibelt_tls_server_session_storage_put_duration_ns_total",
    "counter",
    tls_session_storage.put_duration_ns,
  );
}
