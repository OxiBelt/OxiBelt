//! Admin, observability, and upstream configuration schema.

use super::*;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_admin_bind")]
  pub bind: SocketAddr,
  #[serde(default = "default_admin_bearer_token_env")]
  pub bearer_token_env: String,
  #[serde(default)]
  pub transport: AdminTransportMode,
  #[serde(default)]
  pub allow_insecure_plaintext: bool,
  #[serde(default = "default_admin_plaintext_allowed_source_cidrs")]
  pub plaintext_allowed_source_cidrs: Vec<String>,
  #[serde(default)]
  pub cache_purge_signing: AdminCachePurgeSigningConfig,
  #[serde(default)]
  pub workload_identity: AdminWorkloadIdentityConfig,
  #[serde(default)]
  pub audit: AdminAuditConfig,
  #[serde(default)]
  pub operations: AdminOperationsConfig,
  #[serde(default)]
  pub mutations: AdminMutationsConfig,
  #[serde(default)]
  pub http3: AdminHttp3Config,
  #[serde(default)]
  pub tls: AdminTlsConfig,
  #[serde(default, rename = "rbac")]
  pub(super) legacy_rbac: Option<LegacyAdminRbacConfig>,
  #[serde(default, rename = "token_store")]
  pub(super) legacy_token_store: Option<LegacyAdminTokenStoreConfig>,
}

impl Default for AdminConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      bind: default_admin_bind(),
      bearer_token_env: default_admin_bearer_token_env(),
      transport: AdminTransportMode::Auto,
      allow_insecure_plaintext: false,
      plaintext_allowed_source_cidrs: default_admin_plaintext_allowed_source_cidrs(),
      cache_purge_signing: AdminCachePurgeSigningConfig::default(),
      workload_identity: AdminWorkloadIdentityConfig::default(),
      audit: AdminAuditConfig::default(),
      operations: AdminOperationsConfig::default(),
      mutations: AdminMutationsConfig::default(),
      http3: AdminHttp3Config::default(),
      tls: AdminTlsConfig::default(),
      legacy_rbac: None,
      legacy_token_store: None,
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct AdminHttp3Config {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub bind: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminCachePurgeSigningConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_cache_purge_signing_key_env")]
  pub key_env: String,
  #[serde(default = "default_cache_purge_signing_max_skew_seconds")]
  pub max_skew_seconds: u64,
  #[serde(default = "default_cache_purge_signing_nonce_ttl_seconds")]
  pub nonce_ttl_seconds: u64,
}

impl Default for AdminCachePurgeSigningConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      key_env: default_cache_purge_signing_key_env(),
      max_skew_seconds: default_cache_purge_signing_max_skew_seconds(),
      nonce_ttl_seconds: default_cache_purge_signing_nonce_ttl_seconds(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminTransportMode {
  #[default]
  Auto,
  Tls,
  PlaintextAllowlist,
  Plaintext,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MetricsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_metrics_bind")]
  pub bind: SocketAddr,
  #[serde(default)]
  pub format: MetricsFormat,
  #[serde(default)]
  pub detail: MetricsDetail,
  #[serde(default = "default_metrics_histogram_buckets_ms")]
  pub histogram_buckets_ms: Vec<u64>,
}

impl Default for MetricsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      bind: default_metrics_bind(),
      format: MetricsFormat::Prometheus,
      detail: MetricsDetail::Detailed,
      histogram_buckets_ms: default_metrics_histogram_buckets_ms(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MetricsFormat {
  #[default]
  Prometheus,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MetricsDetail {
  Basic,
  #[default]
  Detailed,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HealthConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_health_bind")]
  pub bind: SocketAddr,
  #[serde(default = "default_ready_path")]
  pub ready_path: String,
  #[serde(default = "default_live_path")]
  pub live_path: String,
}

impl Default for HealthConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      bind: default_health_bind(),
      ready_path: default_ready_path(),
      live_path: default_live_path(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamConfig {
  pub name: String,
  pub origin: Url,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
  #[serde(default)]
  pub happy_eyeballs_mode: HappyEyeballsMode,
  #[serde(default)]
  pub svcb_allowed_ports: Vec<u16>,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub request_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub first_byte_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub read_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub send_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(skip, default = "default_pool_keepalive_max_lifetime_ms")]
  pub max_lifetime_ms: u64,
  #[serde(default = "default_upstream_pool_max_idle_per_host")]
  pub pool_max_idle_per_host: usize,
  #[serde(default)]
  pub preserve_host: bool,
  #[serde(default = "default_true")]
  pub websocket: bool,
  #[serde(default = "default_true")]
  pub webrtc: bool,
  #[serde(default = "default_true")]
  pub webtransport: bool,
  #[serde(default)]
  pub proxy_protocol_egress: ProxyProtocolEgressMode,
  #[serde(default)]
  pub tls: UpstreamTlsConfig,
  #[serde(skip)]
  pub extra_trusted_ca_certs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HappyEyeballsMode {
  #[default]
  Inherit,
  V3,
  Legacy,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolEgressMode {
  #[default]
  Off,
  V1,
  V2,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolConfig {
  pub name: String,
  #[serde(default)]
  pub algorithm: LoadBalancingAlgorithm,
  #[serde(default)]
  pub hash_key: Option<String>,
  #[serde(default)]
  pub sticky_cookie: UpstreamPoolStickyCookieConfig,
  #[serde(default)]
  pub keepalive: UpstreamPoolKeepaliveConfig,
  #[serde(default)]
  pub slow_start: UpstreamPoolSlowStartConfig,
  #[serde(default)]
  pub outlier_ejection: UpstreamPoolOutlierEjectionConfig,
  #[serde(default)]
  pub circuit_breaker: Option<CircuitBreakerScopeOverride>,
  #[serde(default)]
  pub servers: Vec<UpstreamPoolServerConfig>,
  #[serde(default)]
  pub discovery: Vec<UpstreamPoolDiscoveryConfig>,
  #[serde(default)]
  pub health_check: UpstreamPoolHealthCheckConfig,
}

impl UpstreamPoolConfig {
  pub(super) fn resolve_discovery_paths(
    &mut self,
    config_dir: &Path,
  ) -> anyhow::Result<Vec<PathBuf>> {
    let mut resolved_paths = Vec::new();
    for discovery in &mut self.discovery {
      if discovery.provider == UpstreamDiscoveryProvider::File {
        let Some(path) = discovery.file.take() else {
          continue;
        };
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "upstream_pools.discovery.file",
          config_dir,
          &path,
        )?;
        discovery.file = Some(resolved);
        resolved_paths.push(logical);
      }
    }
    Ok(resolved_paths)
  }

  pub(super) fn resolve_tls_paths(&mut self, cert_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut resolved_paths = Vec::new();
    for server in &mut self.servers {
      resolved_paths.extend(server.tls.resolve_relative_paths(cert_dir)?);
    }
    for discovery in &mut self.discovery {
      resolved_paths.extend(discovery.tls.resolve_relative_paths(cert_dir)?);
    }
    Ok(resolved_paths)
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamDiscoveryProvider {
  Dns,
  File,
  Kubernetes,
  Consul,
  Etcd,
  Nomad,
}

impl UpstreamDiscoveryProvider {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Dns => "dns",
      Self::File => "file",
      Self::Kubernetes => "kubernetes",
      Self::Consul => "consul",
      Self::Etcd => "etcd",
      Self::Nomad => "nomad",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DnsDiscoveryRecordType {
  A,
  Aaaa,
  #[default]
  #[serde(rename = "a_aaaa")]
  AAndAaaa,
  Srv,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryUpstreamScheme {
  #[default]
  Http,
  Https,
}

impl DiscoveryUpstreamScheme {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Http => "http",
      Self::Https => "https",
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
  #[default]
  PowerOfTwoChoices,
  WeightedLeastConn,
  RendezvousHash,
  RendezvousIpHash,
  Ewma,
  LeastTime,
  StickyCookie,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolKeepaliveConfig {
  #[serde(default = "default_pool_keepalive_max_idle")]
  pub max_idle: usize,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default = "default_pool_keepalive_max_lifetime_ms")]
  pub max_lifetime_ms: u64,
}

impl Default for UpstreamPoolKeepaliveConfig {
  fn default() -> Self {
    Self {
      max_idle: default_pool_keepalive_max_idle(),
      idle_timeout_ms: default_client_idle_timeout_ms(),
      max_lifetime_ms: default_pool_keepalive_max_lifetime_ms(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolServerConfig {
  #[serde(default)]
  pub id: Option<String>,
  pub origin: Url,
  #[serde(default = "default_pool_server_weight")]
  pub weight: u32,
  #[serde(default)]
  pub max_conns: usize,
  #[serde(default)]
  pub backup: bool,
  #[serde(default)]
  pub state: UpstreamPoolServerState,
  #[serde(default)]
  pub tls: UpstreamTlsConfig,
  #[serde(skip)]
  pub source: UpstreamPoolServerSource,
  #[serde(skip)]
  pub discovery_instance_id: Option<String>,
  #[serde(skip)]
  pub discovered_weight: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamPoolServerState {
  #[default]
  Ready,
  Drain,
  Down,
  Maintenance,
}

impl UpstreamPoolServerState {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Ready => "ready",
      Self::Drain => "drain",
      Self::Down => "down",
      Self::Maintenance => "maintenance",
    }
  }

  pub fn accepts_new_requests(self) -> bool {
    self == Self::Ready
  }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub enum UpstreamPoolServerSource {
  #[default]
  Static,
  Dns,
  File,
  Kubernetes,
  Consul,
  Etcd,
  Nomad,
  Admin,
}

impl UpstreamPoolServerSource {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Static => "static",
      Self::Dns => "dns",
      Self::File => "file",
      Self::Kubernetes => "kubernetes",
      Self::Consul => "consul",
      Self::Etcd => "etcd",
      Self::Nomad => "nomad",
      Self::Admin => "admin",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamEchConfig {
  #[serde(default)]
  pub mode: UpstreamEchMode,
  #[serde(default)]
  pub config_list_file: Option<PathBuf>,
}

impl Default for UpstreamEchConfig {
  fn default() -> Self {
    Self {
      mode: UpstreamEchMode::Disabled,
      config_list_file: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamEchMode {
  #[default]
  Disabled,
  Grease,
  ConfigList,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum HttpVersion {
  #[serde(rename = "h1")]
  H1,
  #[serde(rename = "h2")]
  H2,
  #[serde(rename = "h3")]
  H3,
}

impl HttpVersion {
  pub fn as_alpn(self) -> &'static [u8] {
    match self {
      Self::H1 => b"http/1.1",
      Self::H2 => b"h2",
      Self::H3 => b"h3",
    }
  }
}
