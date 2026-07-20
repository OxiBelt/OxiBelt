//! Centralized configuration defaults shared by schema modules.

use super::*;

pub(super) fn default_true() -> bool {
  true
}

pub(super) fn default_hot_reload_poll_interval_ms() -> u64 {
  2_000
}

pub(super) fn default_drain_graceful_timeout_ms() -> u64 {
  30_000
}

pub(super) fn default_drain_long_connection_close_delay_ms() -> u64 {
  300_000
}

pub(super) fn default_runtime_accept_backlog() -> u32 {
  1_024
}

pub(super) fn default_accept_error_backoff_ms() -> u64 {
  50
}

pub(super) fn default_hosts() -> Vec<String> {
  vec!["*".to_string()]
}

pub(super) fn default_path_prefix() -> String {
  "/".to_string()
}

pub(super) fn default_connect_timeout_ms() -> u64 {
  3_000
}

pub(super) fn default_request_timeout_ms() -> u64 {
  30_000
}

pub(super) fn default_proxy_max_http_version() -> HttpVersion {
  HttpVersion::H2
}

pub(super) fn default_client_header_timeout_ms() -> u64 {
  10_000
}

pub(super) fn default_client_body_timeout_ms() -> u64 {
  30_000
}

pub(super) fn default_client_idle_timeout_ms() -> u64 {
  75_000
}

pub(super) fn default_tls_handshake_timeout_ms() -> u64 {
  10_000
}

pub(super) fn default_response_send_timeout_ms() -> u64 {
  60_000
}

pub(super) fn default_max_headers() -> usize {
  128
}

pub(super) fn default_max_header_name_bytes() -> usize {
  128
}

pub(super) fn default_max_header_value_bytes() -> usize {
  8_192
}

pub(super) fn default_max_total_header_bytes() -> usize {
  65_536
}

pub(super) fn default_max_uri_bytes() -> usize {
  8_192
}

pub(super) fn default_max_request_body_bytes() -> u64 {
  10_485_760
}

pub(super) fn default_buffering_max_memory_body_bytes() -> usize {
  1_048_576
}

pub(super) fn default_connection_limit_status() -> u16 {
  429
}

pub(super) fn default_cache_max_size_bytes() -> usize {
  1_073_741_824
}

pub(super) fn default_cache_memory_auto_fraction() -> f64 {
  0.5
}

pub(super) fn default_cache_default_ttl_seconds() -> u64 {
  60
}

pub(super) fn default_cache_methods() -> Vec<String> {
  vec!["GET".to_string(), "HEAD".to_string()]
}

pub(super) fn default_cache_key() -> String {
  "{scheme}:{host}:{uri}".to_string()
}

pub(super) fn default_cache_tag_headers() -> Vec<String> {
  vec!["Surrogate-Key".to_string(), "Cache-Tag".to_string()]
}

pub(super) fn default_cache_max_tags_per_entry() -> usize {
  32
}

pub(super) fn default_cache_max_tag_bytes() -> usize {
  128
}

pub(super) fn default_cache_max_vary_fields() -> usize {
  8
}

pub(super) fn default_cache_max_vary_variants_per_key() -> usize {
  64
}

pub(super) fn default_cache_bypass_request_headers() -> Vec<String> {
  vec![
    "Authorization".to_string(),
    "Cookie".to_string(),
    "Proxy-Authorization".to_string(),
  ]
}

pub(super) fn default_cache_stream_chunk_bytes() -> usize {
  1_048_576
}

pub(super) fn default_cache_background_refresh_max_concurrent() -> usize {
  16
}

pub(super) fn default_cache_lock_wait_timeout_ms() -> u64 {
  10_000
}

pub(crate) fn default_cache_tmpfs_dir() -> PathBuf {
  PathBuf::from("/dev/shm/oxibelt-cache")
}

pub(super) fn default_admin_bind() -> SocketAddr {
  SocketAddr::from(([127, 0, 0, 1], 9092))
}

pub(super) fn default_admin_bearer_token_env() -> String {
  "OXIBELT_ADMIN_TOKEN".to_string()
}

pub(super) fn default_cache_purge_signing_key_env() -> String {
  "OXIBELT_CACHE_PURGE_HMAC_KEY".to_string()
}

pub(super) fn default_cache_purge_signing_max_skew_seconds() -> u64 {
  300
}

pub(super) fn default_cache_purge_signing_nonce_ttl_seconds() -> u64 {
  600
}

pub(super) fn default_admin_plaintext_allowed_source_cidrs() -> Vec<String> {
  vec!["127.0.0.0/8".to_string(), "::1/128".to_string()]
}

pub(super) fn default_metrics_bind() -> SocketAddr {
  SocketAddr::from(([127, 0, 0, 1], 9090))
}

pub(super) fn default_metrics_histogram_buckets_ms() -> Vec<u64> {
  vec![1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
}

pub(super) fn default_health_bind() -> SocketAddr {
  SocketAddr::from(([127, 0, 0, 1], 9091))
}

pub(super) fn default_ready_path() -> String {
  "/ready".to_string()
}

pub(super) fn default_live_path() -> String {
  "/live".to_string()
}

pub(super) fn default_pool_keepalive_max_idle() -> usize {
  32
}

pub(super) fn default_upstream_pool_max_idle_per_host() -> usize {
  128
}

pub(super) fn default_pool_keepalive_max_lifetime_ms() -> u64 {
  3_600_000
}

pub(super) fn default_pool_server_weight() -> u32 {
  1
}

pub(super) fn default_discovery_refresh_interval_ms() -> u64 {
  30_000
}

pub(super) fn default_discovery_min_ttl_ms() -> u64 {
  1_000
}

pub(super) fn default_database_postgres_max_connections() -> u32 {
  4
}

pub(super) fn default_database_postgres_connect_timeout_ms() -> u64 {
  3_000
}

pub(super) fn default_admin_audit_queue_capacity() -> usize {
  1024
}
