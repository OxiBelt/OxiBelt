//! Limits and cache configuration schema.

use super::*;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LimitsConfig {
  #[serde(default = "default_max_connections")]
  pub max_connections: usize,
  #[serde(default = "default_max_connections_per_ip")]
  pub max_connections_per_ip: usize,
  #[serde(default)]
  pub max_webtransport_sessions: Option<usize>,
  #[serde(default)]
  pub max_webtransport_sessions_per_ip: Option<usize>,
  #[serde(default = "default_max_webtransport_sessions_per_connection")]
  pub max_webtransport_sessions_per_connection: usize,
  #[serde(default)]
  pub connection_limit_identity: ConnectionLimitIdentityMode,
  #[serde(default = "default_max_requests_per_connection")]
  pub max_requests_per_connection: usize,
  #[serde(default = "default_client_header_timeout_ms")]
  pub client_header_timeout_ms: u64,
  #[serde(default = "default_client_body_timeout_ms")]
  pub client_body_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub client_idle_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub websocket_idle_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub webtransport_idle_timeout_ms: u64,
  #[serde(default = "default_tls_handshake_timeout_ms")]
  pub tls_handshake_timeout_ms: u64,
  #[serde(default = "default_response_send_timeout_ms")]
  pub response_send_timeout_ms: u64,
  #[serde(default = "default_max_headers")]
  pub max_headers: usize,
  #[serde(default = "default_max_header_name_bytes")]
  pub max_header_name_bytes: usize,
  #[serde(default = "default_max_header_value_bytes")]
  pub max_header_value_bytes: usize,
  #[serde(default = "default_max_total_header_bytes")]
  pub max_total_header_bytes: usize,
  #[serde(default = "default_max_uri_bytes")]
  pub max_uri_bytes: usize,
  #[serde(default = "default_max_request_body_bytes")]
  pub max_request_body_bytes: u64,
}

impl Default for LimitsConfig {
  fn default() -> Self {
    Self {
      max_connections: default_max_connections(),
      max_connections_per_ip: default_max_connections_per_ip(),
      max_webtransport_sessions: None,
      max_webtransport_sessions_per_ip: None,
      max_webtransport_sessions_per_connection: default_max_webtransport_sessions_per_connection(),
      connection_limit_identity: ConnectionLimitIdentityMode::default(),
      max_requests_per_connection: default_max_requests_per_connection(),
      client_header_timeout_ms: default_client_header_timeout_ms(),
      client_body_timeout_ms: default_client_body_timeout_ms(),
      client_idle_timeout_ms: default_client_idle_timeout_ms(),
      websocket_idle_timeout_ms: default_client_idle_timeout_ms(),
      webtransport_idle_timeout_ms: default_client_idle_timeout_ms(),
      tls_handshake_timeout_ms: default_tls_handshake_timeout_ms(),
      response_send_timeout_ms: default_response_send_timeout_ms(),
      max_headers: default_max_headers(),
      max_header_name_bytes: default_max_header_name_bytes(),
      max_header_value_bytes: default_max_header_value_bytes(),
      max_total_header_bytes: default_max_total_header_bytes(),
      max_uri_bytes: default_max_uri_bytes(),
      max_request_body_bytes: default_max_request_body_bytes(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionLimitIdentityMode {
  #[default]
  ProxyProtocol,
  FirstRequestRealIp,
  PerRequestRealIp,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ConnectionLimitConfig {
  pub name: String,
  #[serde(default)]
  pub key: LimitKey,
  pub limit: usize,
  #[serde(default = "default_connection_limit_status")]
  pub status: u16,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LimitKey {
  #[default]
  ClientIp,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LimitMode {
  #[default]
  Enforcing,
  Monitor,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CacheConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub store: CacheStore,
  #[serde(default)]
  pub tmpfs_dir: Option<PathBuf>,
  #[serde(default)]
  pub disk_dir: Option<PathBuf>,
  #[serde(default = "default_cache_max_size_bytes")]
  pub max_size_bytes: usize,
  #[serde(default)]
  pub memory_max_size_bytes: Option<usize>,
  #[serde(default)]
  pub disk_max_size_bytes: Option<usize>,
  #[serde(default = "default_cache_memory_auto_fraction")]
  pub memory_auto_fraction: f64,
  #[serde(default = "default_cache_default_ttl_seconds")]
  pub default_ttl_seconds: u64,
  #[serde(default = "default_cache_methods")]
  pub cache_methods: Vec<String>,
  #[serde(default = "default_cache_key")]
  pub cache_key: String,
  #[serde(default)]
  pub partition_key: String,
  #[serde(default = "default_true")]
  pub respect_cache_control: bool,
  #[serde(default)]
  pub surrogate: CacheSurrogateConfig,
  #[serde(default)]
  pub stale_if_error_seconds: u64,
  #[serde(default = "default_true")]
  pub lock: bool,
  #[serde(default)]
  pub stale_while_revalidate_seconds: u64,
  #[serde(default)]
  pub negative_statuses: Vec<u16>,
  #[serde(default)]
  pub negative_ttl_seconds: u64,
  #[serde(default = "default_cache_tag_headers")]
  pub tag_headers: Vec<String>,
  #[serde(default = "default_cache_max_tags_per_entry")]
  pub max_tags_per_entry: usize,
  #[serde(default = "default_cache_max_tag_bytes")]
  pub max_tag_bytes: usize,
  #[serde(default = "default_cache_max_vary_fields")]
  pub max_vary_fields: usize,
  #[serde(default = "default_cache_max_vary_variants_per_key")]
  pub max_vary_variants_per_key: usize,
  #[serde(default = "default_cache_bypass_request_headers")]
  pub bypass_request_headers: Vec<String>,
  #[serde(default = "default_true")]
  pub stream_large_objects: bool,
  #[serde(default = "default_cache_stream_chunk_bytes")]
  pub stream_chunk_bytes: usize,
  #[serde(default = "default_true")]
  pub background_refresh: bool,
  #[serde(default = "default_cache_background_refresh_max_concurrent")]
  pub background_refresh_max_concurrent: usize,
  #[serde(default = "default_cache_lock_wait_timeout_ms")]
  pub lock_wait_timeout_ms: u64,
  #[serde(default)]
  pub copy_file_range: CacheCopyFileRangeMode,
  #[serde(default)]
  pub admission: CacheAdmissionConfig,
  #[serde(default)]
  pub stale_if_error: CacheStaleIfErrorConfig,
  #[serde(default)]
  pub policies: Vec<CachePolicyConfig>,
  #[serde(default)]
  pub external_handler: Option<String>,
  #[serde(default)]
  pub external_handlers: Vec<ExternalCacheHandlerConfig>,
}

impl Default for CacheConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      store: CacheStore::Memory,
      tmpfs_dir: None,
      disk_dir: None,
      max_size_bytes: default_cache_max_size_bytes(),
      memory_max_size_bytes: None,
      disk_max_size_bytes: None,
      memory_auto_fraction: default_cache_memory_auto_fraction(),
      default_ttl_seconds: default_cache_default_ttl_seconds(),
      cache_methods: default_cache_methods(),
      cache_key: default_cache_key(),
      partition_key: String::new(),
      respect_cache_control: true,
      surrogate: CacheSurrogateConfig::default(),
      stale_if_error_seconds: 0,
      lock: true,
      stale_while_revalidate_seconds: 0,
      negative_statuses: Vec::new(),
      negative_ttl_seconds: 0,
      tag_headers: default_cache_tag_headers(),
      max_tags_per_entry: default_cache_max_tags_per_entry(),
      max_tag_bytes: default_cache_max_tag_bytes(),
      max_vary_fields: default_cache_max_vary_fields(),
      max_vary_variants_per_key: default_cache_max_vary_variants_per_key(),
      bypass_request_headers: default_cache_bypass_request_headers(),
      stream_large_objects: true,
      stream_chunk_bytes: default_cache_stream_chunk_bytes(),
      background_refresh: true,
      background_refresh_max_concurrent: default_cache_background_refresh_max_concurrent(),
      lock_wait_timeout_ms: default_cache_lock_wait_timeout_ms(),
      copy_file_range: CacheCopyFileRangeMode::Auto,
      admission: CacheAdmissionConfig::default(),
      stale_if_error: CacheStaleIfErrorConfig::default(),
      policies: Vec::new(),
      external_handler: None,
      external_handlers: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CacheStore {
  #[default]
  Memory,
  Tmpfs,
  Disk,
  MemoryThenDisk,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CacheCopyFileRangeMode {
  #[default]
  Auto,
  Off,
  Required,
}

impl CacheStore {
  pub fn uses_disk(self) -> bool {
    matches!(self, Self::Disk | Self::MemoryThenDisk)
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CachePolicyConfig {
  pub name: String,
  #[serde(default)]
  pub store: Option<CacheStore>,
  #[serde(default)]
  pub cache_key: Option<String>,
  #[serde(default)]
  pub partition_key: Option<String>,
  #[serde(default)]
  pub default_ttl_seconds: Option<u64>,
  #[serde(default)]
  pub negative_statuses: Option<Vec<u16>>,
  #[serde(default)]
  pub negative_ttl_seconds: Option<u64>,
  #[serde(default)]
  pub memory_max_size_bytes: Option<usize>,
  #[serde(default)]
  pub disk_max_size_bytes: Option<usize>,
  #[serde(default)]
  pub tag_headers: Option<Vec<String>>,
  #[serde(default)]
  pub max_tags_per_entry: Option<usize>,
  #[serde(default)]
  pub max_tag_bytes: Option<usize>,
  #[serde(default)]
  pub max_vary_fields: Option<usize>,
  #[serde(default)]
  pub max_vary_variants_per_key: Option<usize>,
  #[serde(default)]
  pub background_refresh: Option<bool>,
  #[serde(default)]
  pub background_refresh_max_concurrent: Option<usize>,
  #[serde(default)]
  pub lock_wait_timeout_ms: Option<u64>,
  #[serde(default)]
  pub admission: Option<CacheAdmissionConfig>,
  #[serde(default)]
  pub stale_if_error: Option<CacheStaleIfErrorConfig>,
  #[serde(default)]
  pub external_handler: Option<String>,
  #[serde(default)]
  pub rules: Vec<CachePolicyRuleConfig>,
}
