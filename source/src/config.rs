use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use serde::Deserialize;
use url::Url;

use crate::waf::{AccessLogFieldConfig, RouteWafConfig, WafConfig};

mod dynamic_policy;
mod limits;
mod stream;
mod tls;
mod turn;
mod workers;
pub use dynamic_policy::*;
use limits::{
  default_max_connections, default_max_connections_per_ip, default_max_requests_per_connection,
  default_max_webtransport_sessions_per_connection,
};
pub use stream::*;
pub use tls::*;
pub use turn::*;
pub use workers::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
  pub config: ConfigBehaviorConfig,
  pub logging: LoggingConfig,
  pub runtime: RuntimeConfig,
  pub listeners: ListenerConfig,
  pub tls: TlsConfig,
  pub quic: QuicConfig,
  pub proxy: ProxyConfig,
  pub limits: LimitsConfig,
  pub rate_limits: Vec<RateLimitConfig>,
  pub connection_limits: Vec<ConnectionLimitConfig>,
  pub compression: CompressionConfig,
  pub cache: CacheConfig,
  pub admin: AdminConfig,
  pub metrics: MetricsConfig,
  pub health: HealthConfig,
  pub security: SecurityConfig,
  pub database: DatabaseConfig,
  pub shared_state: SharedStateConfig,
  pub dynamic_policy: DynamicPolicyConfig,
  pub upstreams: Vec<UpstreamConfig>,
  pub upstream_pools: Vec<UpstreamPoolConfig>,
  pub turn_upstream_pools: Vec<TurnUpstreamPoolConfig>,
  pub stream_listeners: Vec<StreamListenerConfig>,
  pub webrtc_turn_listeners: Vec<WebRtcTurnListenerConfig>,
  pub routes: Vec<RouteConfig>,
  pub waf: WafConfig,
  pub source_paths: ConfigSourcePaths,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
  #[serde(default)]
  config: ConfigBehaviorConfig,
  #[serde(default)]
  logging: LoggingConfig,
  #[serde(default)]
  runtime: RawRuntimeConfig,
  listeners: ListenerConfig,
  tls: TlsConfig,
  #[serde(default)]
  quic: RawQuicConfig,
  #[serde(default)]
  proxy: ProxyConfig,
  #[serde(default)]
  limits: LimitsConfig,
  #[serde(default)]
  rate_limits: Vec<RateLimitConfig>,
  #[serde(default)]
  connection_limits: Vec<ConnectionLimitConfig>,
  #[serde(default)]
  compression: CompressionConfig,
  #[serde(default)]
  cache: CacheConfig,
  #[serde(default)]
  admin: AdminConfig,
  #[serde(default)]
  metrics: MetricsConfig,
  #[serde(default)]
  health: HealthConfig,
  #[serde(default)]
  security: SecurityConfig,
  #[serde(default)]
  database: DatabaseConfig,
  #[serde(default)]
  shared_state: SharedStateConfig,
  #[serde(default)]
  dynamic_policy: DynamicPolicyConfig,
  #[serde(default)]
  upstreams: Vec<UpstreamConfig>,
  #[serde(default)]
  upstream_pools: Vec<UpstreamPoolConfig>,
  #[serde(default)]
  turn_upstream_pools: Vec<TurnUpstreamPoolConfig>,
  #[serde(default)]
  stream_listeners: Vec<StreamListenerConfig>,
  #[serde(default)]
  webrtc_turn_listeners: Vec<WebRtcTurnListenerConfig>,
  #[serde(default)]
  routes: Vec<RouteConfig>,
  #[serde(default)]
  waf: WafConfig,
}

impl TryFrom<RawConfig> for Config {
  type Error = anyhow::Error;

  fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
    let parallelism = WorkerParallelism::detect();
    let runtime = RuntimeConfig::resolve(raw.runtime, parallelism)?;
    let quic = QuicConfig::resolve(raw.quic, runtime.worker_multipliers, parallelism)?;
    Ok(Self {
      config: raw.config,
      logging: raw.logging,
      runtime,
      listeners: raw.listeners,
      tls: raw.tls,
      quic,
      proxy: raw.proxy,
      limits: raw.limits,
      rate_limits: raw.rate_limits,
      connection_limits: raw.connection_limits,
      compression: raw.compression,
      cache: raw.cache,
      admin: raw.admin,
      metrics: raw.metrics,
      health: raw.health,
      security: raw.security,
      database: raw.database,
      shared_state: raw.shared_state,
      dynamic_policy: raw.dynamic_policy,
      upstreams: raw.upstreams,
      upstream_pools: raw.upstream_pools,
      turn_upstream_pools: raw.turn_upstream_pools,
      stream_listeners: raw.stream_listeners,
      webrtc_turn_listeners: raw.webrtc_turn_listeners,
      routes: raw.routes,
      waf: raw.waf,
      source_paths: ConfigSourcePaths::default(),
    })
  }
}

impl<'de> Deserialize<'de> for Config {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    RawConfig::deserialize(deserializer)?
      .try_into()
      .map_err(serde::de::Error::custom)
  }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfigSourcePaths {
  pub config_entry: Option<PathBuf>,
  pub config_dir: Option<PathBuf>,
  pub cert_dir: Option<PathBuf>,
  pub config_files: Vec<PathBuf>,
  pub runtime_files: Vec<PathBuf>,
  pub discovery_files: Vec<PathBuf>,
  pub downstream_tls_files: Vec<PathBuf>,
  pub downstream_tls_cert_chain: Option<PathBuf>,
  pub downstream_tls_private_key: Option<PathBuf>,
  pub downstream_tls_ocsp_response_file: Option<PathBuf>,
  pub quic_host_key_file: Option<PathBuf>,
  pub oxirule_files: Vec<PathBuf>,
}

impl ConfigSourcePaths {
  pub fn all_reload_files(&self) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(path) = &self.config_entry {
      files.push(path.clone());
    }
    files.extend(self.config_files.iter().cloned());
    files.extend(self.runtime_files.iter().cloned());
    files.extend(self.oxirule_files.iter().cloned());
    dedup_paths(files)
  }

  pub fn oxirule_reload_files(&self) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(path) = &self.config_entry {
      files.push(path.clone());
    }
    files.extend(self.config_files.iter().cloned());
    files.extend(self.oxirule_files.iter().cloned());
    dedup_paths(files)
  }

  pub fn downstream_tls_reload_files(&self) -> Vec<PathBuf> {
    dedup_paths(self.downstream_tls_files.clone())
  }

  fn remember_runtime_file(&mut self, path: PathBuf) {
    push_unique_path(&mut self.runtime_files, path);
  }

  fn remember_discovery_file(&mut self, path: PathBuf) {
    push_unique_path(&mut self.discovery_files, path);
  }

  fn remember_downstream_tls_file(&mut self, path: PathBuf) {
    push_unique_path(&mut self.downstream_tls_files, path);
  }

  fn remember_oxirule_file(&mut self, path: PathBuf) {
    push_unique_path(&mut self.oxirule_files, path);
  }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeOverrides {
  pub hot_reload_mode: Option<HotReloadMode>,
  pub hot_reload_poll_interval_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ConfigBehaviorConfig {
  #[serde(default = "default_true")]
  pub strict_unknown_fields: bool,
  #[serde(default = "default_true")]
  pub warn_on_deprecated_fields: bool,
}

impl Default for ConfigBehaviorConfig {
  fn default() -> Self {
    Self {
      strict_unknown_fields: true,
      warn_on_deprecated_fields: true,
    }
  }
}

impl Config {
  pub fn load(path: &Path) -> anyhow::Result<Self> {
    let path_roots = config_path_roots(path)?;
    let loaded = load_toml_with_includes(path)?;
    validate_merged_toml_shape(&loaded.value)?;
    let mut config: Self = loaded
      .value
      .try_into()
      .with_context(|| format!("failed to decode merged TOML from {}", path.display()))?;
    config.source_paths.config_entry = Some(absolute_config_path(path)?);
    config.source_paths.config_files = loaded.files;
    config.resolve_relative_paths(&path_roots)?;
    config.load_external_waf_rules()?;
    config.collect_loaded_waf_rule_paths();
    Ok(config)
  }

  pub fn load_effective_toml_redacted(path: &Path) -> anyhow::Result<toml::Value> {
    let loaded = load_toml_with_includes(path)?;
    validate_merged_toml_shape(&loaded.value)?;
    let mut value = loaded.value;
    let config = Self::load(path)?;
    config.validate()?;
    config.write_resolved_workers_to_toml(&mut value)?;
    redact_effective_toml(&mut value);
    Ok(value)
  }

  pub fn log_worker_resolution(&self) {
    let resolution = self.runtime.worker_resolution;
    if let Some(error) = resolution.fallback_error {
      tracing::warn!(
        error,
        fallback_parallelism = resolution.available_parallelism,
        "worker auto-scaling fell back to one available thread"
      );
    }
    tracing::info!(
      available_parallelism = resolution.available_parallelism,
      runtime_multiplier = resolution.runtime_multiplier,
      accept_multiplier = resolution.accept_multiplier,
      quic_socket_multiplier = resolution.quic_socket_multiplier,
      runtime_worker_threads = self.runtime.worker_threads,
      accept_workers = self.runtime.accept.workers,
      quic_socket_workers = self.quic.socket.workers,
      "resolved worker auto-scaling"
    );
  }

  pub fn apply_runtime_overrides(&mut self, overrides: &RuntimeOverrides) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(mode) = overrides.hot_reload_mode {
      if self.runtime.hot_reload.mode != mode {
        warnings.push(format!(
          "CLI --hot-reload-mode={mode} overrides runtime.hot_reload.mode={}",
          self.runtime.hot_reload.mode
        ));
      }
      self.runtime.hot_reload.mode = mode;
    }
    if let Some(poll_interval_ms) = overrides.hot_reload_poll_interval_ms {
      if self.runtime.hot_reload.poll_interval_ms != poll_interval_ms {
        warnings.push(format!(
          "CLI --hot-reload-poll-interval-ms={poll_interval_ms} overrides runtime.hot_reload.poll_interval_ms={}",
          self.runtime.hot_reload.poll_interval_ms
        ));
      }
      self.runtime.hot_reload.poll_interval_ms = poll_interval_ms;
    }
    warnings
  }

  fn write_resolved_workers_to_toml(&self, value: &mut toml::Value) -> anyhow::Result<()> {
    set_toml_integer_path(
      value,
      &["runtime", "worker_threads"],
      self.runtime.worker_threads,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "runtime"],
      self.runtime.worker_multipliers.runtime,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "accept"],
      self.runtime.worker_multipliers.accept,
    )?;
    set_toml_float_path(
      value,
      &["runtime", "worker_multipliers", "quic_socket"],
      self.runtime.worker_multipliers.quic_socket,
    )?;
    set_toml_integer_path(
      value,
      &["runtime", "accept", "workers"],
      self.runtime.accept.workers,
    )?;
    set_toml_integer_path(
      value,
      &["quic", "socket", "workers"],
      self.quic.socket.workers,
    )
  }

  pub fn non_waf_equivalent(&self, other: &Self) -> bool {
    self.logging == other.logging
      && self.config == other.config
      && self.runtime == other.runtime
      && self.listeners == other.listeners
      && self.tls == other.tls
      && self.quic == other.quic
      && self.proxy == other.proxy
      && self.limits == other.limits
      && self.rate_limits == other.rate_limits
      && self.connection_limits == other.connection_limits
      && self.compression == other.compression
      && self.cache == other.cache
      && self.admin == other.admin
      && self.metrics == other.metrics
      && self.health == other.health
      && self.security == other.security
      && self.database == other.database
      && self.shared_state == other.shared_state
      && self.dynamic_policy == other.dynamic_policy
      && self.upstreams == other.upstreams
      && self.upstream_pools == other.upstream_pools
      && self.turn_upstream_pools == other.turn_upstream_pools
      && self.stream_listeners == other.stream_listeners
      && self.webrtc_turn_listeners == other.webrtc_turn_listeners
      && routes_without_waf_are_equivalent(&self.routes, &other.routes)
  }

  pub fn waf_equivalent(&self, other: &Self) -> bool {
    self.waf == other.waf && route_waf_configs_are_equivalent(&self.routes, &other.routes)
  }

  fn resolve_relative_paths(&mut self, path_roots: &ConfigPathRoots) -> anyhow::Result<()> {
    self.source_paths.config_dir = Some(path_roots.config_dir.clone());
    self.source_paths.cert_dir = Some(path_roots.cert_dir.clone());
    let (tls_cert_chain, tls_cert_chain_logical) =
      resolve_existing_local_config_file_path_with_logical(
        "tls.cert_chain",
        &path_roots.cert_dir,
        &self.tls.cert_chain,
      )?;
    self.tls.cert_chain = tls_cert_chain;
    self
      .source_paths
      .remember_runtime_file(tls_cert_chain_logical.clone());
    self
      .source_paths
      .remember_downstream_tls_file(tls_cert_chain_logical.clone());
    self.source_paths.downstream_tls_cert_chain = Some(tls_cert_chain_logical);

    if let Some(private_key) = self.tls.private_key.take() {
      let (tls_private_key, tls_private_key_logical) =
        resolve_existing_local_config_file_path_with_logical(
          "tls.private_key",
          &path_roots.cert_dir,
          &private_key,
        )?;
      self.tls.private_key = Some(tls_private_key);
      self
        .source_paths
        .remember_runtime_file(tls_private_key_logical.clone());
      self
        .source_paths
        .remember_downstream_tls_file(tls_private_key_logical.clone());
      self.source_paths.downstream_tls_private_key = Some(tls_private_key_logical);
    }

    self.tls.ocsp.response_file = self
      .tls
      .ocsp
      .response_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "tls.ocsp.response_file",
          &path_roots.cert_dir,
          &path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self
          .source_paths
          .remember_downstream_tls_file(logical.clone());
        self.source_paths.downstream_tls_ocsp_response_file = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    self.tls.client_auth.ca_certs = self
      .tls
      .client_auth
      .ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "tls.client_auth.ca_certs",
          &path_roots.cert_dir,
          path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self.source_paths.remember_downstream_tls_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    self.proxy.trusted_ca_certs = self
      .proxy
      .trusted_ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "proxy.trusted_ca_certs",
          &path_roots.cert_dir,
          path,
        )?;
        self.source_paths.remember_runtime_file(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    self.quic.host_key_file = self
      .quic
      .host_key_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "quic.host_key_file",
          &path_roots.cert_dir,
          &path,
        )?;
        self.source_paths.remember_runtime_file(logical.clone());
        self
          .source_paths
          .remember_downstream_tls_file(logical.clone());
        self.source_paths.quic_host_key_file = Some(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    for upstream in &mut self.upstreams {
      for path in upstream.tls.resolve_relative_paths(&path_roots.cert_dir)? {
        self.source_paths.remember_runtime_file(path);
      }
    }
    for path in self
      .database
      .access_log
      .tls
      .resolve_relative_paths(&path_roots.cert_dir)?
    {
      self.source_paths.remember_runtime_file(path);
    }
    for path in self
      .logging
      .access_log
      .database
      .tls
      .resolve_relative_paths(&path_roots.cert_dir)?
    {
      self.source_paths.remember_runtime_file(path);
    }
    for backend in &mut self.shared_state.backends {
      for path in backend.tls.resolve_relative_paths(&path_roots.cert_dir)? {
        self.source_paths.remember_runtime_file(path);
      }
    }
    for pool in &mut self.upstream_pools {
      for path in pool.resolve_discovery_paths(&path_roots.config_dir)? {
        self.source_paths.remember_discovery_file(path);
      }
    }
    for listener in &mut self.webrtc_turn_listeners {
      for path in listener.tls.resolve_relative_paths(&path_roots.cert_dir)? {
        self.source_paths.remember_runtime_file(path.clone());
        self.source_paths.remember_downstream_tls_file(path);
      }
    }
    for path in self
      .admin
      .tls
      .resolve_relative_paths(&path_roots.cert_dir)?
    {
      self.source_paths.remember_runtime_file(path);
    }
    self.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    for route in &mut self.routes {
      if let Some(static_root) = route.static_root.as_ref() {
        let resolved = if static_root.is_absolute() {
          static_root.clone()
        } else {
          validate_relative_path("routes.static_root", static_root)?;
          path_roots.config_dir.join(static_root)
        };
        route.static_root = Some(crate::proxy::http::static_files::validate_static_root(
          &resolved,
        )?);
      }
      route.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    }
    Ok(())
  }

  fn load_external_waf_rules(&mut self) -> anyhow::Result<()> {
    self.waf.load_external_rules()?;
    for route in &mut self.routes {
      route.waf.load_external_rules()?;
    }
    Ok(())
  }

  fn collect_loaded_waf_rule_paths(&mut self) {
    for path in self.waf.loaded_rule_paths() {
      self.source_paths.remember_oxirule_file(path);
    }
    for route in &self.routes {
      for path in route.waf.loaded_rule_paths() {
        self.source_paths.remember_oxirule_file(path);
      }
    }
  }

  pub fn validate(&self) -> anyhow::Result<()> {
    if !self.listeners.http1 && !self.listeners.http2 && !self.listeners.http3 {
      bail!("at least one downstream HTTP version must be enabled");
    }

    if self.runtime.unprivileged_mode && self.listeners.https_bind.port() < 1024 {
      bail!(
        "https_bind {} requires a privileged port but unprivileged_mode=true",
        self.listeners.https_bind
      );
    }
    if self.runtime.unprivileged_mode
      && let Some(http_bind) = self.listeners.http_bind
      && http_bind.port() < 1024
    {
      bail!(
        "http_bind {} requires a privileged port but unprivileged_mode=true",
        http_bind
      );
    }
    if self.listeners.http_mode != HttpListenerMode::Off && self.listeners.http_bind.is_none() {
      bail!("listeners.http_bind is required when listeners.http_mode is not \"off\"");
    }
    if self.listeners.proxy_protocol.enabled {
      for cidr in &self.listeners.proxy_protocol.trusted_sources {
        crate::identity::Cidr::parse(cidr).with_context(|| {
          format!("invalid listeners.proxy_protocol.trusted_sources entry {cidr}")
        })?;
      }
    }

    self.runtime.validate()?;
    self.validate_limits()?;
    self.validate_proxy()?;
    self.validate_compression()?;
    self.validate_cache()?;
    self.validate_admin()?;
    self.validate_metrics_and_health()?;
    self.validate_security_headers()?;
    self.validate_tls()?;
    self.quic.validate(self.listeners.http3)?;
    self.logging.validate()?;

    if self.runtime.linux_only && !cfg!(target_os = "linux") {
      bail!("this build is configured for Linux only");
    }

    if self.routes.is_empty()
      && self.stream_listeners.is_empty()
      && self.webrtc_turn_listeners.is_empty()
    {
      bail!("at least one route, stream listener, or WebRTC TURN listener must be configured");
    }

    self.database.validate()?;
    self.shared_state.validate()?;

    let mut upstream_names = HashSet::new();
    for upstream in &self.upstreams {
      if upstream.name.trim().is_empty() {
        bail!("upstream name must not be empty");
      }
      if !upstream_names.insert(upstream.name.clone()) {
        bail!("duplicate upstream name: {}", upstream.name);
      }

      if upstream.origin.scheme() != "http" && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use http:// or https:// origin, got {}",
          upstream.name,
          upstream.origin
        );
      }

      if upstream.max_http_version == HttpVersion::H3 && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use https:// origin when max_http_version = \"h3\"",
          upstream.name
        );
      }
      if upstream.max_http_version == HttpVersion::H3
        && upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
      {
        bail!(
          "upstream {} cannot enable proxy_protocol_egress with max_http_version = \"h3\"",
          upstream.name
        );
      }

      upstream.tls.validate(&upstream.name)?;
      if upstream.connect_timeout_ms == 0
        || upstream.request_timeout_ms == 0
        || upstream.first_byte_timeout_ms == 0
        || upstream.read_timeout_ms == 0
        || upstream.send_timeout_ms == 0
        || upstream.idle_timeout_ms == 0
      {
        bail!(
          "upstream {} timeout values must be greater than 0",
          upstream.name
        );
      }
    }

    let mut pool_names = HashSet::new();
    for pool in &self.upstream_pools {
      if pool.name.trim().is_empty() {
        bail!("upstream pool name must not be empty");
      }
      if !pool_names.insert(pool.name.clone()) {
        bail!("duplicate upstream pool name: {}", pool.name);
      }
      if pool.algorithm == LoadBalancingAlgorithm::StickyCookie {
        bail!(
          "upstream pool {} uses sticky_cookie, but sticky sessions are reserved and not implemented yet",
          pool.name
        );
      }
      if matches!(pool.algorithm, LoadBalancingAlgorithm::Hash) && pool.hash_key.is_none() {
        bail!(
          "upstream pool {} requires hash_key when algorithm = \"hash\"",
          pool.name
        );
      }
      if pool.servers.is_empty() && pool.discovery.is_empty() {
        bail!(
          "upstream pool {} must define at least one server or discovery provider",
          pool.name
        );
      }
      let mut server_ids = HashSet::new();
      for (index, server) in pool.servers.iter().enumerate() {
        let server_id = upstream_pool_server_id(index, server);
        validate_runtime_identifier(
          &format!("upstream pool {} server id", pool.name),
          &server_id,
        )?;
        if !server_ids.insert(server_id.clone()) {
          bail!(
            "upstream pool {} has duplicate server id {server_id}",
            pool.name
          );
        }
        if server.origin.scheme() != "http" && server.origin.scheme() != "https" {
          bail!(
            "upstream pool {} server origin must use http:// or https://, got {}",
            pool.name,
            server.origin
          );
        }
        if server.weight == 0 {
          bail!(
            "upstream pool {} server weight must be greater than 0",
            pool.name
          );
        }
      }
      validate_pool_discovery(pool)?;
      if !pool.health_check.path.starts_with('/') {
        bail!(
          "upstream pool {} health_check.path must start with '/'",
          pool.name
        );
      }
      if pool.health_check.enabled {
        if pool.health_check.interval_ms == 0 {
          bail!(
            "upstream pool {} health_check.interval_ms must be greater than 0",
            pool.name
          );
        }
        if pool.health_check.timeout_ms == 0 {
          bail!(
            "upstream pool {} health_check.timeout_ms must be greater than 0",
            pool.name
          );
        }
        if pool.health_check.healthy_threshold == 0 || pool.health_check.unhealthy_threshold == 0 {
          bail!(
            "upstream pool {} health_check thresholds must be greater than 0",
            pool.name
          );
        }
      }
      for status in &pool.health_check.expected_status {
        http::StatusCode::from_u16(*status).with_context(|| {
          format!(
            "upstream pool {} has invalid expected_status {status}",
            pool.name
          )
        })?;
      }
      if pool.health_check.protocol == HealthCheckProtocol::Grpc
        && pool.health_check.grpc_expected_statuses.is_empty()
      {
        bail!(
          "upstream pool {} health_check.grpc_expected_statuses must not be empty",
          pool.name
        );
      }
    }

    let turn_pool_names = self.validate_turn_forwarding()?;

    let compression_policy_names = self
      .compression
      .policies
      .iter()
      .map(|policy| policy.name.as_str())
      .collect::<HashSet<_>>();

    let mut route_names = HashSet::new();
    for route in &self.routes {
      if route.name.trim().is_empty() {
        bail!("route name must not be empty");
      }
      if !route_names.insert(route.name.clone()) {
        bail!("duplicate route name: {}", route.name);
      }
      if route.hosts.is_empty() {
        bail!("route {} must have at least one host match", route.name);
      }
      validate_route_path_value(&route.name, "path_prefix", &route.path_prefix)?;
      if let Some(replacement) = &route.replace_prefix_with {
        validate_route_path_value(&route.name, "replace_prefix_with", replacement)?;
      }
      let target_count = usize::from(route.upstream.is_some())
        + usize::from(route.upstream_pool.is_some())
        + usize::from(route.static_root.is_some());
      if target_count != 1 {
        bail!(
          "route {} must set exactly one of upstream, upstream_pool, or static_root",
          route.name
        );
      }
      match (&route.upstream, &route.upstream_pool, &route.static_root) {
        (Some(upstream), None, None) if !upstream_names.contains(upstream) => {
          bail!(
            "route {} references unknown upstream {}",
            route.name,
            upstream
          );
        }
        (None, Some(pool), None) if !pool_names.contains(pool) => {
          bail!(
            "route {} references unknown upstream_pool {}",
            route.name,
            pool
          );
        }
        (Some(_), None, None) | (None, Some(_), None) => {}
        (None, None, Some(static_root)) => {
          crate::proxy::http::static_files::validate_static_root(static_root)
            .with_context(|| format!("route {} static_root is invalid", route.name))?;
          if route.replace_prefix_with.is_some() {
            bail!(
              "route {} cannot set replace_prefix_with when static_root is configured",
              route.name
            );
          }
          if route.cache.is_some() {
            bail!(
              "route {} cannot set cache when static_root is configured",
              route.name
            );
          }
          if route.upstream_http_version.is_some() {
            bail!(
              "route {} cannot set upstream_http_version when static_root is configured",
              route.name
            );
          }
          if route.generic_http_upgrade || route.connect_tunneling || route.grpc_web {
            bail!(
              "route {} cannot enable upstream-only route features when static_root is configured",
              route.name
            );
          }
        }
        _ => {}
      }
      if let Some(cache) = &route.cache
        && cache != "default"
        && !self
          .cache
          .policies
          .iter()
          .any(|policy| policy.name == *cache)
      {
        bail!("route {} references unknown cache {}", route.name, cache);
      }
      if let Some(compression) = &route.compression
        && compression != "default"
        && compression != "off"
        && !compression_policy_names.contains(compression.as_str())
      {
        bail!(
          "route {} references unknown compression policy {}",
          route.name,
          compression
        );
      }
      if route.grpc_web && !self.proxy.grpc_web.enabled {
        bail!(
          "route {} enables grpc_web but proxy.grpc_web.enabled is false",
          route.name
        );
      }
      if route.generic_http_upgrade && !self.proxy.upgrades.generic_http_upgrade {
        bail!(
          "route {} enables generic_http_upgrade but proxy.upgrades.generic_http_upgrade is false",
          route.name
        );
      }
      if route.connect_tunneling && !self.proxy.upgrades.connect_tunneling {
        bail!(
          "route {} enables connect_tunneling but proxy.upgrades.connect_tunneling is false",
          route.name
        );
      }
      if let Some(route_version) = route.upstream_http_version {
        match (&route.upstream, &route.upstream_pool) {
          (Some(upstream_name), None) => {
            let upstream = self
              .upstreams
              .iter()
              .find(|item| item.name == *upstream_name)
              .expect("validated route upstream");
            if route_version > upstream.max_http_version {
              bail!(
                "route {} upstream_http_version cannot exceed upstream {} max_http_version",
                route.name,
                upstream.name
              );
            }
            if route_version == HttpVersion::H3
              && upstream.proxy_protocol_egress != ProxyProtocolEgressMode::Off
            {
              bail!(
                "route {} cannot select HTTP/3 when upstream {} has proxy_protocol_egress enabled",
                route.name,
                upstream.name
              );
            }
          }
          (None, Some(_)) if route_version == HttpVersion::H3 => {
            bail!(
              "route {} cannot set upstream_http_version = \"h3\" for upstream_pool routes",
              route.name
            );
          }
          _ => {}
        }
      }
      route.timeouts.validate(&route.name)?;
    }

    self.validate_dynamic_policy(&route_names)?;
    self.validate_stream_listeners()?;
    self.validate_webrtc_turn_listeners(&turn_pool_names)?;

    match self.tls.ocsp.mode {
      OcspMode::Disabled => {}
      OcspMode::StaticFile => {
        if self.tls.ocsp.response_file.is_none() {
          bail!("tls.ocsp.response_file is required when tls.ocsp.mode = \"static_file\"");
        }
      }
      OcspMode::LiveFetch => {
        return Err(anyhow!(
          "tls.ocsp.mode = \"live_fetch\" is reserved but not implemented yet"
        ));
      }
    }

    crate::waf::validate_config(self)?;

    Ok(())
  }

  fn validate_limits(&self) -> anyhow::Result<()> {
    if self.limits.max_connections == 0
      || self.limits.max_connections_per_ip == 0
      || self.limits.max_webtransport_sessions == Some(0)
      || self.limits.max_webtransport_sessions_per_ip == Some(0)
      || self.limits.max_webtransport_sessions_per_connection == 0
      || self.limits.max_requests_per_connection == 0
      || self.limits.client_header_timeout_ms == 0
      || self.limits.client_body_timeout_ms == 0
      || self.limits.client_idle_timeout_ms == 0
      || self.limits.websocket_idle_timeout_ms == 0
      || self.limits.webtransport_idle_timeout_ms == 0
      || self.limits.tls_handshake_timeout_ms == 0
      || self.limits.response_send_timeout_ms == 0
      || self.limits.max_headers == 0
      || self.limits.max_header_name_bytes == 0
      || self.limits.max_header_value_bytes == 0
      || self.limits.max_total_header_bytes == 0
      || self.limits.max_uri_bytes == 0
      || self.limits.max_request_body_bytes == 0
    {
      bail!("limits values must be greater than 0");
    }
    let route_names = self
      .routes
      .iter()
      .map(|route| route.name.as_str())
      .collect::<HashSet<_>>();
    let mut names = HashSet::new();
    for rate_limit in &self.rate_limits {
      if rate_limit.name.trim().is_empty() {
        bail!("rate limit name must not be empty");
      }
      if !names.insert(rate_limit.name.as_str()) {
        bail!("duplicate rate limit name {}", rate_limit.name);
      }
      crate::limits::parse_rate(&rate_limit.rate)
        .with_context(|| format!("invalid rate_limits {} rate", rate_limit.name))?;
      if rate_limit.max_buckets == 0 {
        bail!(
          "rate limit {} max_buckets must be greater than 0",
          rate_limit.name
        );
      }
      http::StatusCode::from_u16(rate_limit.status)
        .with_context(|| format!("rate limit {} has invalid status", rate_limit.name))?;
      if let Some(token_header) = &rate_limit.token_header {
        if !rate_limit.key.uses_access_token() {
          bail!(
            "rate limit {} token_header requires an access_token key",
            rate_limit.name
          );
        }
        http::header::HeaderName::from_bytes(token_header.as_bytes())
          .with_context(|| format!("rate limit {} has invalid token_header", rate_limit.name))?;
      }
      let mut route_filter_names = HashSet::new();
      for route in &rate_limit.routes {
        if !route_filter_names.insert(route.as_str()) {
          bail!(
            "rate limit {} contains duplicate route {}",
            rate_limit.name,
            route
          );
        }
        if !route_names.contains(route.as_str()) {
          bail!(
            "rate limit {} references unknown route {}",
            rate_limit.name,
            route
          );
        }
      }
    }
    names.clear();
    for connection_limit in &self.connection_limits {
      if connection_limit.name.trim().is_empty() {
        bail!("connection limit name must not be empty");
      }
      if !names.insert(connection_limit.name.as_str()) {
        bail!("duplicate connection limit name {}", connection_limit.name);
      }
      if connection_limit.limit == 0 {
        bail!(
          "connection limit {} limit must be greater than 0",
          connection_limit.name
        );
      }
      http::StatusCode::from_u16(connection_limit.status).with_context(|| {
        format!(
          "connection limit {} has invalid status",
          connection_limit.name
        )
      })?;
    }
    Ok(())
  }

  fn validate_dynamic_policy(&self, route_names: &HashSet<String>) -> anyhow::Result<()> {
    let policy = &self.dynamic_policy;
    policy.validate_basic()?;
    validate_optional_non_empty("dynamic_policy.backend", policy.backend.as_deref())?;
    if policy.automation_api.enabled {
      if !policy.enabled {
        bail!("dynamic_policy.automation_api.enabled requires dynamic_policy.enabled = true");
      }
      if !self.admin.enabled {
        bail!("dynamic_policy.automation_api.enabled requires admin.enabled = true");
      }
      policy.automation_api.validate_signature_key_env()?;
    }
    if !policy.enabled {
      return Ok(());
    }
    if !self.shared_state.enabled {
      bail!("dynamic_policy.enabled requires shared_state.enabled = true");
    }
    let Some(backend_name) = self.dynamic_policy_backend_name() else {
      bail!(
        "dynamic_policy.enabled requires dynamic_policy.backend, shared_state.dynamic_policy_backend, shared_state.default_backend, or at least one shared_state backend"
      );
    };
    let Some(backend) = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
    else {
      bail!("dynamic_policy backend references unknown shared_state backend {backend_name}");
    };
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("dynamic_policy backend {backend_name} must use kind = \"postgres\"");
    }
    if route_names.is_empty() {
      bail!("dynamic_policy requires at least one named route");
    }
    Ok(())
  }

  pub(crate) fn dynamic_policy_backend_name(&self) -> Option<&str> {
    self
      .dynamic_policy
      .backend
      .as_deref()
      .or(self.shared_state.dynamic_policy_backend.as_deref())
      .or(self.shared_state.default_backend.as_deref())
      .or_else(|| {
        self
          .shared_state
          .backends
          .first()
          .map(|backend| backend.name.as_str())
      })
  }

  fn validate_proxy(&self) -> anyhow::Result<()> {
    if self.proxy.retry.tries == 0 {
      bail!("proxy.retry.tries must be greater than 0");
    }
    if self.proxy.retry.timeout_ms == 0 {
      bail!("proxy.retry.timeout_ms must be greater than 0");
    }
    self.validate_buffering()?;
    for cidr in &self.proxy.real_ip.trusted_proxies {
      crate::identity::Cidr::parse(cidr)
        .with_context(|| format!("invalid proxy.real_ip.trusted_proxies entry {cidr}"))?;
    }
    Ok(())
  }

  fn validate_buffering(&self) -> anyhow::Result<()> {
    let mut requires_temp_dir = false;
    validate_effective_buffering(
      "proxy.buffering",
      self.proxy.buffering.request,
      self.proxy.buffering.max_temp_file_bytes,
      &mut requires_temp_dir,
    )?;
    validate_effective_buffering(
      "proxy.buffering",
      self.proxy.buffering.response,
      self.proxy.buffering.max_temp_file_bytes,
      &mut requires_temp_dir,
    )?;

    for route in &self.routes {
      let request = route
        .buffering
        .request
        .unwrap_or(self.proxy.buffering.request);
      let response = route
        .buffering
        .response
        .unwrap_or(self.proxy.buffering.response);
      let max_temp_file_bytes = route
        .buffering
        .max_temp_file_bytes
        .unwrap_or(self.proxy.buffering.max_temp_file_bytes);
      validate_effective_buffering(
        &format!("route {} buffering", route.name),
        request,
        max_temp_file_bytes,
        &mut requires_temp_dir,
      )?;
      validate_effective_buffering(
        &format!("route {} buffering", route.name),
        response,
        max_temp_file_bytes,
        &mut requires_temp_dir,
      )?;
    }

    if requires_temp_dir {
      let dir =
        self.proxy.buffering.temp_dir.as_ref().ok_or_else(|| {
          anyhow!("proxy.buffering.temp_dir is required when buffering uses spool")
        })?;
      crate::cache::validate_disk_dir(dir)?;
    }
    Ok(())
  }

  fn validate_compression(&self) -> anyhow::Result<()> {
    validate_compression_statuses("compression.statuses", &self.compression.statuses)?;
    validate_compression_mime_types("compression.mime_types", &self.compression.mime_types)?;

    let mut names = HashSet::new();
    for policy in &self.compression.policies {
      if policy.name.trim().is_empty() {
        bail!("compression policy name must not be empty");
      }
      if matches!(policy.name.as_str(), "default" | "off") {
        bail!("compression policy name {} is reserved", policy.name);
      }
      if !names.insert(policy.name.as_str()) {
        bail!("duplicate compression policy name {}", policy.name);
      }
      validate_compression_statuses(
        &format!("compression policy {} statuses", policy.name),
        &policy.statuses,
      )?;
      validate_compression_mime_types(
        &format!("compression policy {} mime_types", policy.name),
        &policy.mime_types,
      )?;
    }

    Ok(())
  }

  fn validate_cache(&self) -> anyhow::Result<()> {
    if self.cache.max_size_bytes == 0 {
      bail!("cache.max_size_bytes must be greater than 0");
    }
    if let Some(memory_max_size_bytes) = self.cache.memory_max_size_bytes
      && memory_max_size_bytes == 0
    {
      bail!("cache.memory_max_size_bytes must be greater than 0 when configured");
    }
    if let Some(disk_max_size_bytes) = self.cache.disk_max_size_bytes
      && disk_max_size_bytes == 0
    {
      bail!("cache.disk_max_size_bytes must be greater than 0 when configured");
    }
    if !(0.0..=1.0).contains(&self.cache.memory_auto_fraction)
      || self.cache.memory_auto_fraction == 0.0
    {
      bail!("cache.memory_auto_fraction must be greater than 0.0 and less than or equal to 1.0");
    }
    if self.cache.default_ttl_seconds == 0 {
      bail!("cache.default_ttl_seconds must be greater than 0");
    }
    if self.cache.store == CacheStore::Tmpfs && self.cache.enabled {
      let dir = self
        .cache
        .tmpfs_dir
        .clone()
        .unwrap_or_else(default_cache_tmpfs_dir);
      crate::cache::validate_tmpfs_dir(&dir)?;
    }
    if self.cache.enabled && self.cache.store.uses_disk() {
      let dir = self
        .cache
        .disk_dir
        .as_ref()
        .ok_or_else(|| anyhow!("cache.disk_dir is required when cache.store uses disk"))?;
      crate::cache::validate_disk_dir(dir)?;
      if self.cache.disk_max_size_bytes.is_none() {
        bail!("cache.disk_max_size_bytes is required when cache.store uses disk");
      }
    }
    for status in &self.cache.negative_statuses {
      http::StatusCode::from_u16(*status)
        .with_context(|| format!("cache.negative_statuses contains invalid status {status}"))?;
    }
    if !self.cache.negative_statuses.is_empty() && self.cache.negative_ttl_seconds == 0 {
      bail!("cache.negative_ttl_seconds must be greater than 0 when negative_statuses is set");
    }
    validate_cache_tag_headers("cache.tag_headers", &self.cache.tag_headers)?;
    if self.cache.max_tags_per_entry == 0 {
      bail!("cache.max_tags_per_entry must be greater than 0");
    }
    if self.cache.max_tag_bytes == 0 {
      bail!("cache.max_tag_bytes must be greater than 0");
    }
    if self.cache.max_vary_fields == 0 {
      bail!("cache.max_vary_fields must be greater than 0");
    }
    if self.cache.max_vary_variants_per_key == 0 {
      bail!("cache.max_vary_variants_per_key must be greater than 0");
    }
    validate_cache_bypass_headers(
      "cache.bypass_request_headers",
      &self.cache.bypass_request_headers,
    )?;
    if self.cache.stream_chunk_bytes == 0 {
      bail!("cache.stream_chunk_bytes must be greater than 0");
    }
    if self.cache.background_refresh_max_concurrent == 0 {
      bail!("cache.background_refresh_max_concurrent must be greater than 0");
    }
    if self.cache.lock_wait_timeout_ms == 0 {
      bail!("cache.lock_wait_timeout_ms must be greater than 0");
    }
    validate_cache_admission("cache.admission", &self.cache.admission, &self.cache)?;
    validate_cache_stale_if_error("cache.stale_if_error", &self.cache.stale_if_error)?;

    let mut names = HashSet::new();
    for policy in &self.cache.policies {
      if policy.name.trim().is_empty() {
        bail!("cache policy name must not be empty");
      }
      if policy.name == "default" {
        bail!("cache policy name default is reserved");
      }
      if !names.insert(policy.name.as_str()) {
        bail!("duplicate cache policy name {}", policy.name);
      }
      if let Some(default_ttl_seconds) = policy.default_ttl_seconds
        && default_ttl_seconds == 0
      {
        bail!(
          "cache policy {} default_ttl_seconds must be greater than 0",
          policy.name
        );
      }
      if let Some(negative_statuses) = &policy.negative_statuses {
        for status in negative_statuses {
          http::StatusCode::from_u16(*status).with_context(|| {
            format!(
              "cache policy {} negative_statuses contains invalid status {status}",
              policy.name
            )
          })?;
        }
        if !negative_statuses.is_empty() && policy.negative_ttl_seconds.unwrap_or(0) == 0 {
          bail!(
            "cache policy {} negative_ttl_seconds must be greater than 0 when negative_statuses is set",
            policy.name
          );
        }
      } else if policy.negative_ttl_seconds.is_some() {
        bail!(
          "cache policy {} negative_ttl_seconds requires negative_statuses",
          policy.name
        );
      }
      if let Some(memory_max_size_bytes) = policy.memory_max_size_bytes
        && memory_max_size_bytes == 0
      {
        bail!(
          "cache policy {} memory_max_size_bytes must be greater than 0",
          policy.name
        );
      }
      if let Some(disk_max_size_bytes) = policy.disk_max_size_bytes
        && disk_max_size_bytes == 0
      {
        bail!(
          "cache policy {} disk_max_size_bytes must be greater than 0",
          policy.name
        );
      }
      if let Some(tag_headers) = &policy.tag_headers {
        validate_cache_tag_headers(
          &format!("cache policy {} tag_headers", policy.name),
          tag_headers,
        )?;
      }
      if policy.max_tags_per_entry == Some(0) {
        bail!(
          "cache policy {} max_tags_per_entry must be greater than 0",
          policy.name
        );
      }
      if policy.max_tag_bytes == Some(0) {
        bail!(
          "cache policy {} max_tag_bytes must be greater than 0",
          policy.name
        );
      }
      if policy.max_vary_fields == Some(0) {
        bail!(
          "cache policy {} max_vary_fields must be greater than 0",
          policy.name
        );
      }
      if policy.max_vary_variants_per_key == Some(0) {
        bail!(
          "cache policy {} max_vary_variants_per_key must be greater than 0",
          policy.name
        );
      }
      if policy.background_refresh_max_concurrent == Some(0) {
        bail!(
          "cache policy {} background_refresh_max_concurrent must be greater than 0",
          policy.name
        );
      }
      if policy.lock_wait_timeout_ms == Some(0) {
        bail!(
          "cache policy {} lock_wait_timeout_ms must be greater than 0",
          policy.name
        );
      }
      if let Some(admission) = &policy.admission {
        validate_cache_admission(
          &format!("cache policy {} admission", policy.name),
          admission,
          &self.cache,
        )?;
      }
      if let Some(stale_if_error) = &policy.stale_if_error {
        validate_cache_stale_if_error(
          &format!("cache policy {} stale_if_error", policy.name),
          stale_if_error,
        )?;
      }
      if policy.store == Some(CacheStore::Tmpfs) && self.cache.enabled {
        let dir = self
          .cache
          .tmpfs_dir
          .clone()
          .unwrap_or_else(default_cache_tmpfs_dir);
        crate::cache::validate_tmpfs_dir(&dir)?;
      }
      if policy.store.is_some_and(CacheStore::uses_disk) {
        let dir = self
          .cache
          .disk_dir
          .as_ref()
          .ok_or_else(|| anyhow!("cache.disk_dir is required when cache policy uses disk"))?;
        if self.cache.enabled {
          crate::cache::validate_disk_dir(dir)?;
        }
        if policy
          .disk_max_size_bytes
          .or(self.cache.disk_max_size_bytes)
          .is_none()
        {
          bail!(
            "cache.disk_max_size_bytes or cache policy {} disk_max_size_bytes is required when policy uses disk",
            policy.name
          );
        }
      }
      for rule in &policy.rules {
        if rule.mime_types.is_empty() {
          bail!(
            "cache policy {} rule must include at least one MIME pattern",
            policy.name
          );
        }
        validate_compression_mime_types(
          &format!("cache policy {} rule mime_types", policy.name),
          &rule.mime_types,
        )?;
        if rule.store.uses_disk() {
          let dir = self.cache.disk_dir.as_ref().ok_or_else(|| {
            anyhow!("cache.disk_dir is required when cache policy rule uses disk")
          })?;
          if self.cache.enabled {
            crate::cache::validate_disk_dir(dir)?;
          }
          if policy
            .disk_max_size_bytes
            .or(self.cache.disk_max_size_bytes)
            .is_none()
          {
            bail!(
              "cache.disk_max_size_bytes or cache policy {} disk_max_size_bytes is required when rule uses disk",
              policy.name
            );
          }
        }
      }
    }
    Ok(())
  }

  fn validate_admin(&self) -> anyhow::Result<()> {
    if !self.admin.enabled {
      return Ok(());
    }
    if self.admin.bearer_token_env.trim().is_empty() {
      bail!("admin.bearer_token_env must not be empty when admin is enabled");
    }
    if std::env::var(&self.admin.bearer_token_env)
      .ok()
      .is_none_or(|token| token.is_empty())
    {
      bail!(
        "admin bearer token environment variable {} must be set and non-empty",
        self.admin.bearer_token_env
      );
    }
    for cidr in &self.admin.plaintext_allowed_source_cidrs {
      crate::identity::Cidr::parse(cidr)
        .with_context(|| format!("invalid admin.plaintext_allowed_source_cidrs entry {cidr}"))?;
    }
    if self.admin.cache_purge_signing.enabled {
      validate_base64_32_byte_env(
        "admin.cache_purge_signing.key_env",
        &self.admin.cache_purge_signing.key_env,
      )?;
      if self.admin.cache_purge_signing.max_skew_seconds == 0 {
        bail!("admin.cache_purge_signing.max_skew_seconds must be greater than 0");
      }
      if self.admin.cache_purge_signing.nonce_ttl_seconds == 0 {
        bail!("admin.cache_purge_signing.nonce_ttl_seconds must be greater than 0");
      }
    }
    if self.admin.transport == AdminTransportMode::Plaintext && !self.admin.allow_insecure_plaintext
    {
      bail!("admin.allow_insecure_plaintext must be true when admin.transport = \"plaintext\"");
    }
    if matches!(
      self.admin.transport,
      AdminTransportMode::Auto | AdminTransportMode::Tls
    ) && !self.admin.bind.ip().is_loopback()
      && !self.admin.tls.enabled
    {
      bail!(
        "admin.tls.enabled must be true for non-loopback admin.bind when admin.transport requires TLS"
      );
    }
    self.validate_admin_rbac()?;
    self.admin.tls.validate()
  }

  fn validate_admin_rbac(&self) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    for token in &self.admin.rbac.tokens {
      validate_optional_non_empty("admin.rbac.tokens.name", Some(&token.name))?;
      validate_optional_non_empty(
        "admin.rbac.tokens.bearer_token_env",
        Some(&token.bearer_token_env),
      )?;
      if !names.insert(token.name.as_str()) {
        bail!("duplicate admin.rbac.tokens name {}", token.name);
      }
      if token.roles.is_empty() {
        bail!("admin.rbac.tokens {} roles must not be empty", token.name);
      }
      if std::env::var(&token.bearer_token_env)
        .ok()
        .is_none_or(|value| value.is_empty())
      {
        bail!(
          "admin RBAC bearer token environment variable {} must be set and non-empty",
          token.bearer_token_env
        );
      }
    }
    Ok(())
  }

  fn validate_metrics_and_health(&self) -> anyhow::Result<()> {
    if !self.health.ready_path.starts_with('/') || !self.health.live_path.starts_with('/') {
      bail!("health ready_path and live_path must start with '/'");
    }
    Ok(())
  }

  fn validate_security_headers(&self) -> anyhow::Result<()> {
    validate_optional_header_value(
      "security.headers.x_content_type_options",
      self.security.headers.x_content_type_options.as_deref(),
    )?;
    validate_optional_header_value(
      "security.headers.referrer_policy",
      self.security.headers.referrer_policy.as_deref(),
    )?;
    validate_optional_header_value(
      "security.headers.permissions_policy",
      self.security.headers.permissions_policy.as_deref(),
    )?;
    Ok(())
  }

  fn validate_tls(&self) -> anyhow::Result<()> {
    if self.tls.min_version > self.tls.max_version {
      bail!("tls.min_version must be less than or equal to tls.max_version");
    }
    if self.tls.remote_signer.enabled {
      if self.tls.private_key.is_some() {
        bail!("tls.private_key must not be set when tls.remote_signer.enabled = true");
      }
      self.tls.remote_signer.validate("tls.remote_signer")?;
      if self.tls.min_version == TlsVersion::Tls12
        && !self.tls.remote_signer.allow_tls12_unstructured_signing
      {
        bail!(
          "tls.remote_signer.allow_tls12_unstructured_signing must be true when remote signing is enabled with tls.min_version = \"tls1.2\""
        );
      }
    } else if self.tls.private_key.is_none() {
      bail!("tls.private_key is required unless tls.remote_signer.enabled = true");
    }
    if self.tls.session_ticket_rotation_seconds == 0 {
      bail!("tls.session_ticket_rotation_seconds must be greater than 0");
    }
    if self.listeners.http3 && self.tls.min_version != TlsVersion::Tls13 {
      bail!("HTTP/3 requires tls.min_version = \"tls1.3\"");
    }
    if self.tls.client_auth.mode != TlsClientAuthMode::Off
      && self.tls.client_auth.ca_certs.is_empty()
    {
      bail!("tls.client_auth.ca_certs is required when client_auth mode is not off");
    }
    for listener in &self.webrtc_turn_listeners {
      if listener.tls.remote_signer_key_id.is_some() && !self.tls.remote_signer.enabled {
        bail!(
          "WebRTC TURN listener {} tls.remote_signer_key_id requires tls.remote_signer.enabled = true",
          listener.name
        );
      }
    }
    Ok(())
  }
}

fn validate_route_path_value(
  route_name: &str,
  field_name: &str,
  value: &str,
) -> anyhow::Result<()> {
  if !value.starts_with('/') {
    bail!("route {route_name} {field_name} must start with '/'");
  }
  if value
    .bytes()
    .any(|byte| byte.is_ascii_control() || matches!(byte, b'\\' | b'?' | b'#'))
  {
    bail!(
      "route {route_name} {field_name} must not contain control characters, backslashes, queries, or fragments"
    );
  }

  for segment in value.split('/') {
    if matches!(segment, "." | "..") {
      bail!("route {route_name} {field_name} must not contain dot segments");
    }
  }

  let lower = value.to_ascii_lowercase();
  if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
    bail!("route {route_name} {field_name} must not contain encoded dot or slash separators");
  }

  Ok(())
}

fn validate_compression_statuses(field_name: &str, statuses: &[u16]) -> anyhow::Result<()> {
  if statuses.is_empty() {
    bail!("{field_name} must include at least one status");
  }
  for status in statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name} contains invalid status {status}"))?;
  }
  Ok(())
}

fn validate_compression_mime_types(field_name: &str, mime_types: &[String]) -> anyhow::Result<()> {
  if mime_types.is_empty() {
    bail!("{field_name} must include at least one MIME pattern");
  }
  for mime_type in mime_types {
    validate_compression_mime_type(field_name, mime_type)?;
  }
  Ok(())
}

fn validate_compression_mime_type(field_name: &str, mime_type: &str) -> anyhow::Result<()> {
  if mime_type.trim() != mime_type || mime_type.is_empty() {
    bail!("{field_name} contains an empty or padded MIME pattern");
  }
  if mime_type.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{field_name} contains a control character in {mime_type}");
  }
  let Some((type_part, subtype_part)) = mime_type.split_once('/') else {
    bail!("{field_name} MIME pattern {mime_type} must contain '/'");
  };
  if type_part.is_empty() || subtype_part.is_empty() {
    bail!("{field_name} MIME pattern {mime_type} must have type and subtype");
  }
  if type_part.contains('*') && type_part != "*" {
    bail!("{field_name} MIME pattern {mime_type} has invalid wildcard type");
  }
  if type_part == "*" && subtype_part != "*" {
    bail!("{field_name} MIME pattern {mime_type} must use */* for wildcard type");
  }
  if subtype_part.matches('*').count() > 1 {
    bail!("{field_name} MIME pattern {mime_type} has too many wildcards");
  }
  if subtype_part.contains('*') && subtype_part != "*" && !subtype_part.starts_with("*+") {
    bail!("{field_name} MIME pattern {mime_type} has invalid wildcard subtype");
  }
  Ok(())
}

fn validate_cache_tag_headers(field_name: &str, headers: &[String]) -> anyhow::Result<()> {
  if headers.is_empty() {
    bail!("{field_name} must include at least one header name");
  }
  for header in headers {
    if header.trim() != header || header.is_empty() {
      bail!("{field_name} contains an empty or padded header name");
    }
    http::header::HeaderName::from_bytes(header.as_bytes())
      .with_context(|| format!("{field_name} contains invalid header name {header}"))?;
  }
  Ok(())
}

fn validate_cache_bypass_headers(field_name: &str, headers: &[String]) -> anyhow::Result<()> {
  if headers.is_empty() {
    bail!("{field_name} must include at least one header");
  }
  let mut names = HashSet::new();
  for header in headers {
    if header.trim() != header || header.is_empty() {
      bail!("{field_name} contains an empty or padded header name");
    }
    let name = http::header::HeaderName::from_bytes(header.as_bytes())
      .with_context(|| format!("{field_name} contains invalid header name {header}"))?;
    let normalized = name.as_str().to_ascii_lowercase();
    if !names.insert(normalized.clone()) {
      bail!("{field_name} contains duplicate header {normalized}");
    }
  }
  Ok(())
}

fn validate_cache_admission(
  field_name: &str,
  admission: &CacheAdmissionConfig,
  cache: &CacheConfig,
) -> anyhow::Result<()> {
  if admission.statuses.is_empty() && cache.negative_statuses.is_empty() {
    bail!("{field_name}.statuses must include at least one status");
  }
  for status in &admission.statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name}.statuses contains invalid status {status}"))?;
  }
  if !admission.content_types.is_empty() {
    validate_compression_mime_types(
      &format!("{field_name}.content_types"),
      &admission.content_types,
    )?;
  }
  if admission.min_hits == 0 {
    bail!("{field_name}.min_hits must be greater than 0");
  }
  if admission.max_tracked_keys == 0 {
    bail!("{field_name}.max_tracked_keys must be greater than 0");
  }
  Ok(())
}

fn validate_cache_stale_if_error(
  field_name: &str,
  stale_if_error: &CacheStaleIfErrorConfig,
) -> anyhow::Result<()> {
  for status in &stale_if_error.statuses {
    http::StatusCode::from_u16(*status)
      .with_context(|| format!("{field_name}.statuses contains invalid status {status}"))?;
  }
  Ok(())
}

fn validate_base64_32_byte_env(field_name: &str, env_name: &str) -> anyhow::Result<()> {
  if env_name.trim().is_empty() {
    bail!("{field_name} must not be empty");
  }
  let raw =
    std::env::var(env_name).with_context(|| format!("failed to read {field_name} {env_name}"))?;
  let bytes = base64::engine::general_purpose::STANDARD
    .decode(raw.trim())
    .with_context(|| format!("{field_name} must contain base64"))?;
  if bytes.len() != 32 {
    bail!("{field_name} must contain exactly 32 bytes");
  }
  Ok(())
}

fn validate_admin_server_name(name: &str) -> anyhow::Result<()> {
  if name.trim() != name || name.is_empty() {
    bail!("admin.tls certificate server name must not be empty or padded");
  }
  if name.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("admin.tls certificate server name {name} contains a control character");
  }
  let name = name.strip_prefix("*.").unwrap_or(name);
  if name.is_empty() || name.contains('*') {
    bail!("admin.tls certificate server name may only use a leftmost wildcard");
  }
  if name
    .split('.')
    .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
  {
    bail!("admin.tls certificate server name {name} is not a valid DNS pattern");
  }
  if !name
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
  {
    bail!("admin.tls certificate server name {name} contains invalid characters");
  }
  Ok(())
}

fn validate_pool_discovery(pool: &UpstreamPoolConfig) -> anyhow::Result<()> {
  let mut providers = HashSet::new();
  for discovery in &pool.discovery {
    if !providers.insert(discovery.provider) {
      bail!(
        "upstream pool {} must not configure duplicate {:?} discovery providers",
        pool.name,
        discovery.provider
      );
    }
    if discovery.refresh_interval_ms == 0 || discovery.min_ttl_ms == 0 {
      bail!(
        "upstream pool {} discovery refresh_interval_ms and min_ttl_ms must be greater than 0",
        pool.name
      );
    }
    match discovery.provider {
      UpstreamDiscoveryProvider::Dns => {
        let Some(name) = discovery.name.as_deref() else {
          bail!("upstream pool {} DNS discovery requires name", pool.name);
        };
        validate_optional_non_empty("upstream_pools.discovery.name", Some(name))?;
        if discovery.record_type != DnsDiscoveryRecordType::Srv && discovery.port.is_none() {
          bail!(
            "upstream pool {} DNS A/AAAA discovery requires port",
            pool.name
          );
        }
      }
      UpstreamDiscoveryProvider::File => {
        if discovery.file.is_none() {
          bail!("upstream pool {} file discovery requires file", pool.name);
        }
      }
      UpstreamDiscoveryProvider::Kubernetes
      | UpstreamDiscoveryProvider::Consul
      | UpstreamDiscoveryProvider::Etcd => {
        bail!(
          "upstream pool {} discovery provider {:?} is reserved and not implemented yet",
          pool.name,
          discovery.provider
        );
      }
    }
  }
  Ok(())
}

pub(crate) fn upstream_pool_server_id(index: usize, server: &UpstreamPoolServerConfig) -> String {
  server.id.clone().unwrap_or_else(|| index.to_string())
}

pub(crate) fn turn_upstream_pool_server_id(
  index: usize,
  server: &TurnUpstreamPoolServerConfig,
) -> String {
  server.id.clone().unwrap_or_else(|| index.to_string())
}

pub(crate) fn validate_runtime_identifier(field_name: &str, value: &str) -> anyhow::Result<()> {
  if value.trim() != value || value.is_empty() {
    bail!("{field_name} must not be empty or padded");
  }
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
  {
    bail!("{field_name} must contain only ASCII letters, digits, '-', '_' or '.'");
  }
  Ok(())
}

fn routes_without_waf_are_equivalent(left: &[RouteConfig], right: &[RouteConfig]) -> bool {
  left.len() == right.len()
    && left.iter().zip(right).all(|(left, right)| {
      left.name == right.name
        && left.hosts == right.hosts
        && left.path_prefix == right.path_prefix
        && left.replace_prefix_with == right.replace_prefix_with
        && left.upstream == right.upstream
        && left.upstream_pool == right.upstream_pool
        && left.static_root == right.static_root
        && left.upstream_http_version == right.upstream_http_version
        && left.generic_http_upgrade == right.generic_http_upgrade
        && left.connect_tunneling == right.connect_tunneling
        && left.grpc_web == right.grpc_web
        && left.cache == right.cache
        && left.compression == right.compression
        && left.buffering == right.buffering
    })
}

fn validate_effective_buffering(
  field_name: &str,
  mode: BufferingMode,
  max_temp_file_bytes: usize,
  requires_temp_dir: &mut bool,
) -> anyhow::Result<()> {
  if mode == BufferingMode::Spool {
    if max_temp_file_bytes == 0 {
      bail!("{field_name}.max_temp_file_bytes must be greater than 0 when buffering uses spool");
    }
    *requires_temp_dir = true;
  }
  Ok(())
}

fn route_waf_configs_are_equivalent(left: &[RouteConfig], right: &[RouteConfig]) -> bool {
  left.len() == right.len()
    && left
      .iter()
      .zip(right)
      .all(|(left, right)| left.name == right.name && left.waf == right.waf)
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
  if !paths.contains(&path) {
    paths.push(path);
  }
}

fn dedup_paths(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
  paths.sort();
  paths.dedup();
  paths
}

struct LoadedToml {
  value: toml::Value,
  files: Vec<PathBuf>,
}

fn validate_merged_toml_shape(value: &toml::Value) -> anyhow::Result<()> {
  let strict = value
    .get("config")
    .and_then(|config| config.get("strict_unknown_fields"))
    .and_then(toml::Value::as_bool)
    .unwrap_or(true);
  if !strict {
    return Ok(());
  }

  let mut unknown = Vec::new();
  collect_unknown_keys(value, "", &mut unknown);
  if !unknown.is_empty() {
    unknown.sort();
    bail!(
      "configuration contains unknown field(s): {}",
      unknown.join(", ")
    );
  }
  Ok(())
}

fn collect_unknown_keys(value: &toml::Value, path: &str, unknown: &mut Vec<String>) {
  if path == "waf" || path.ends_with(".waf") || path.contains(".waf.") {
    return;
  }
  match value {
    toml::Value::Table(table) => {
      let Some(allowed) = allowed_config_keys(path) else {
        return;
      };
      for (key, child) in table {
        let child_path = join_key_path(path, key);
        if allowed.contains(key.as_str()) {
          collect_unknown_keys(child, &child_path, unknown);
        } else {
          unknown.push(child_path);
        }
      }
    }
    toml::Value::Array(items) => {
      for item in items {
        collect_unknown_keys(item, path, unknown);
      }
    }
    _ => {}
  }
}

fn join_key_path(parent: &str, key: &str) -> String {
  if parent.is_empty() {
    key.to_string()
  } else {
    format!("{parent}.{key}")
  }
}

fn allowed_config_keys(path: &str) -> Option<BTreeSet<&'static str>> {
  let keys = match path {
    "" => &[
      "admin",
      "cache",
      "compression",
      "config",
      "connection_limits",
      "database",
      "dynamic_policy",
      "health",
      "limits",
      "listeners",
      "logging",
      "metrics",
      "proxy",
      "quic",
      "rate_limits",
      "routes",
      "runtime",
      "security",
      "shared_state",
      "stream_listeners",
      "tls",
      "turn_upstream_pools",
      "upstream_pools",
      "upstreams",
      "waf",
      "webrtc_turn_listeners",
    ][..],
    "config" => &["strict_unknown_fields", "warn_on_deprecated_fields"][..],
    "logging" => &["access_log", "level"][..],
    "logging.access_log" => &["database", "enabled", "fields", "stdout"][..],
    "logging.access_log.fields" => &["expression", "name", "value"][..],
    "logging.access_log.database" => &[
      "connect_timeout_ms",
      "connection_url",
      "connection_url_env",
      "enabled",
      "max_connections",
      "queue_capacity",
      "table",
      "tls",
    ][..],
    "logging.access_log.database.tls" => &["ca_cert", "client_cert", "client_key", "mode"][..],
    "runtime" => &[
      "accept",
      "drain",
      "hot_reload",
      "linux_only",
      "memory_only_state",
      "read_only_rootfs_compatible",
      "unprivileged_mode",
      "worker_multipliers",
      "worker_threads",
    ][..],
    "runtime.worker_multipliers" => &["accept", "quic_socket", "runtime"][..],
    "runtime.accept" => &[
      "accept_error_backoff_ms",
      "backlog",
      "reuse_port",
      "workers",
    ][..],
    "runtime.drain" => &[
      "graceful_timeout_ms",
      "long_connection_close_delay_ms",
      "shutdown_delay_ms",
    ][..],
    "runtime.hot_reload" => &["mode", "poll_interval_ms"][..],
    "listeners" => &[
      "http1",
      "http2",
      "http3",
      "http_bind",
      "http_mode",
      "https_bind",
      "proxy_protocol",
    ][..],
    "listeners.proxy_protocol" => &["enabled", "trusted_sources", "version"][..],
    "tls" => &[
      "cert_chain",
      "client_auth",
      "max_version",
      "min_version",
      "ocsp",
      "private_key",
      "remote_signer",
      "session_ticket_rotation_seconds",
      "session_tickets",
    ][..],
    "tls.remote_signer" => &[
      "allow_tls12_unstructured_signing",
      "connect_timeout_ms",
      "enabled",
      "key_id",
      "sign_timeout_ms",
      "socket_path",
      "token_env",
    ][..],
    "tls.ocsp" => &["mode", "response_file"][..],
    "tls.client_auth" => &["ca_certs", "mode", "verify_depth"][..],
    "quic" => &[
      "alt_svc",
      "host_key_file",
      "retry",
      "socket",
      "transport",
      "upstream_pool",
      "zero_rtt",
    ][..],
    "quic.alt_svc" => &["enabled", "max_age_seconds", "persist"][..],
    "quic.transport" => &[
      "datagram_receive_buffer_bytes",
      "datagram_send_buffer_bytes",
      "gso",
      "idle_timeout_ms",
      "max_concurrent_bidi_streams",
      "max_concurrent_uni_streams",
      "max_udp_payload_size",
    ][..],
    "quic.socket" => &[
      "receive_buffer_bytes",
      "reuse_port",
      "send_buffer_bytes",
      "workers",
    ][..],
    "quic.upstream_pool" => &["enabled", "max_connections_per_upstream", "max_lifetime_ms"][..],
    "proxy" => &[
      "auto_upgrade",
      "buffering",
      "forwarded_headers",
      "grpc_web",
      "http",
      "real_ip",
      "retry",
      "trusted_ca_certs",
      "upgrades",
    ][..],
    "proxy.forwarded_headers" => &["mode"][..],
    "proxy.auto_upgrade" => &["enabled", "max_http_version"][..],
    "proxy.real_ip" => &[
      "enabled",
      "fail_on_untrusted_forwarded_headers",
      "header",
      "recursive",
      "trusted_proxies",
    ][..],
    "proxy.upgrades" => &["connect_tunneling", "generic_http_upgrade", "websocket"][..],
    "proxy.grpc_web" => &["enabled"][..],
    "proxy.retry" => &[
      "enabled",
      "on",
      "retry_non_idempotent",
      "timeout_ms",
      "tries",
    ][..],
    "proxy.buffering" => &[
      "max_memory_body_bytes",
      "max_temp_file_bytes",
      "request",
      "response",
      "temp_dir",
    ][..],
    "proxy.http" => &[
      "early_hints",
      "trailers",
      "expect_continue",
      "priority",
      "sse_auto_streaming",
      "grpc",
      "errors",
    ][..],
    "proxy.http.grpc" => &["enabled", "respect_grpc_timeout", "retry"][..],
    "proxy.http.errors" => &["mode"][..],
    "limits" => &[
      "client_body_timeout_ms",
      "client_header_timeout_ms",
      "client_idle_timeout_ms",
      "connection_limit_identity",
      "max_connections",
      "max_connections_per_ip",
      "max_webtransport_sessions",
      "max_webtransport_sessions_per_connection",
      "max_webtransport_sessions_per_ip",
      "max_header_name_bytes",
      "max_header_value_bytes",
      "max_headers",
      "max_request_body_bytes",
      "max_requests_per_connection",
      "max_total_header_bytes",
      "max_uri_bytes",
      "response_send_timeout_ms",
      "tls_handshake_timeout_ms",
      "websocket_idle_timeout_ms",
      "webtransport_idle_timeout_ms",
    ][..],
    "compression" => &[
      "br",
      "deflate",
      "enabled",
      "gzip",
      "max_concurrent_responses",
      "mime_types",
      "min_size_bytes",
      "policies",
      "statuses",
      "zstd",
    ][..],
    "compression.policies" => &[
      "br",
      "deflate",
      "enabled",
      "gzip",
      "mime_types",
      "min_size_bytes",
      "name",
      "statuses",
      "zstd",
    ][..],
    "cache" => &[
      "admission",
      "background_refresh",
      "background_refresh_max_concurrent",
      "bypass_request_headers",
      "cache_key",
      "cache_methods",
      "default_ttl_seconds",
      "disk_dir",
      "disk_max_size_bytes",
      "enabled",
      "lock",
      "lock_wait_timeout_ms",
      "max_tag_bytes",
      "max_tags_per_entry",
      "max_vary_fields",
      "max_vary_variants_per_key",
      "max_size_bytes",
      "memory_auto_fraction",
      "memory_max_size_bytes",
      "negative_statuses",
      "negative_ttl_seconds",
      "partition_key",
      "policies",
      "respect_cache_control",
      "stale_if_error",
      "stale_if_error_seconds",
      "stale_while_revalidate_seconds",
      "store",
      "stream_chunk_bytes",
      "stream_large_objects",
      "surrogate",
      "tag_headers",
      "tmpfs_dir",
    ][..],
    "cache.admission" => &[
      "content_types",
      "max_body_bytes",
      "max_tracked_keys",
      "min_hits",
      "statuses",
    ][..],
    "cache.surrogate" => &["enabled", "strip_response_header"][..],
    "cache.stale_if_error" => &[
      "connect_error",
      "max_upstream_stale_seconds",
      "read_timeout",
      "statuses",
    ][..],
    "cache.policies" => &[
      "admission",
      "background_refresh",
      "background_refresh_max_concurrent",
      "cache_key",
      "default_ttl_seconds",
      "disk_max_size_bytes",
      "lock_wait_timeout_ms",
      "max_tag_bytes",
      "max_tags_per_entry",
      "max_vary_fields",
      "max_vary_variants_per_key",
      "memory_max_size_bytes",
      "name",
      "negative_statuses",
      "negative_ttl_seconds",
      "partition_key",
      "rules",
      "stale_if_error",
      "store",
      "tag_headers",
    ][..],
    "cache.policies.admission" => &[
      "content_types",
      "max_body_bytes",
      "max_tracked_keys",
      "min_hits",
      "statuses",
    ][..],
    "cache.policies.stale_if_error" => &[
      "connect_error",
      "max_upstream_stale_seconds",
      "read_timeout",
      "statuses",
    ][..],
    "cache.policies.rules" => &["mime_types", "store"][..],
    "admin" => &[
      "allow_insecure_plaintext",
      "bearer_token_env",
      "bind",
      "cache_purge_signing",
      "enabled",
      "plaintext_allowed_source_cidrs",
      "rbac",
      "tls",
      "transport",
    ][..],
    "admin.cache_purge_signing" => &[
      "enabled",
      "key_env",
      "max_skew_seconds",
      "nonce_ttl_seconds",
    ][..],
    "admin.rbac" => &["tokens"][..],
    "admin.rbac.tokens" => &["bearer_token_env", "name", "roles"][..],
    "admin.tls" => &[
      "certificates",
      "client_auth",
      "enabled",
      "max_version",
      "min_version",
      "reject_unknown_sni",
      "require_sni",
      "session_tickets",
    ][..],
    "admin.tls.certificates" => &["cert_chain", "default", "private_key", "server_names"][..],
    "admin.tls.client_auth" => &["ca_certs", "mode", "verify_depth"][..],
    "metrics" => &["bind", "enabled", "format"][..],
    "health" => &["bind", "enabled", "live_path", "ready_path"][..],
    "security" => &["headers"][..],
    "security.headers" => &[
      "hsts",
      "hsts_include_subdomains",
      "hsts_max_age_seconds",
      "hsts_preload",
      "permissions_policy",
      "referrer_policy",
      "x_content_type_options",
    ][..],
    "database" => &["access_log"][..],
    "database.access_log" => &[
      "connect_timeout_ms",
      "connection_url",
      "connection_url_env",
      "enabled",
      "max_connections",
      "queue_capacity",
      "table",
      "tls",
    ][..],
    "database.access_log.tls" => &["ca_cert", "client_cert", "client_key", "mode"][..],
    "dynamic_policy" => &[
      "automation_api",
      "backend",
      "default_body",
      "default_status",
      "enabled",
      "fail_policy",
      "matching",
      "max_policies",
      "refresh_interval_ms",
    ][..],
    "dynamic_policy.automation_api" => &[
      "default_source_quota",
      "enabled",
      "require_ttl",
      "signature_key_env",
      "source_quotas",
    ][..],
    "dynamic_policy.automation_api.source_quotas" => &["max_active_policies", "source"][..],
    "dynamic_policy.matching" => &["normalize_path", "trust_route_name"][..],
    "shared_state" => &[
      "backends",
      "cache_backend",
      "cache_lock_ms",
      "connection_lease_ms",
      "connection_limits_backend",
      "default_backend",
      "dynamic_policy_backend",
      "enabled",
      "instance_id_env",
      "namespace",
      "operation_timeout_ms",
      "person_proof_backend",
      "rate_limits_backend",
      "reload_backend",
      "upstream_health_backend",
    ][..],
    "shared_state.backends" => &[
      "connect_timeout_ms",
      "connection_url",
      "connection_url_env",
      "kind",
      "max_connections",
      "name",
      "tls",
    ][..],
    "shared_state.backends.tls" => &["ca_cert", "client_cert", "client_key", "mode"][..],
    "upstreams" => &[
      "connect_timeout_ms",
      "first_byte_timeout_ms",
      "idle_timeout_ms",
      "max_http_version",
      "name",
      "origin",
      "preserve_host",
      "proxy_protocol_egress",
      "read_timeout_ms",
      "request_timeout_ms",
      "send_timeout_ms",
      "tls",
      "webrtc",
      "websocket",
      "webtransport",
    ][..],
    "upstreams.tls" => &["ech"][..],
    "upstreams.tls.ech" => &["config_list_file", "mode"][..],
    "upstream_pools" => &[
      "algorithm",
      "discovery",
      "hash_key",
      "health_check",
      "keepalive",
      "name",
      "servers",
    ][..],
    "upstream_pools.discovery" => &[
      "file",
      "min_ttl_ms",
      "name",
      "port",
      "provider",
      "record_type",
      "refresh_interval_ms",
      "scheme",
    ][..],
    "upstream_pools.keepalive" => &["idle_timeout_ms", "max_idle", "max_lifetime_ms"][..],
    "upstream_pools.health_check" => &[
      "enabled",
      "expected_status",
      "healthy_threshold",
      "interval_ms",
      "mode",
      "path",
      "timeout_ms",
      "unhealthy_threshold",
      "protocol",
      "grpc_expected_statuses",
      "grpc_service",
    ][..],
    "upstream_pools.servers" => &["backup", "id", "max_conns", "origin", "state", "weight"][..],
    "routes" => &[
      "buffering",
      "cache",
      "compression",
      "hosts",
      "name",
      "path_prefix",
      "replace_prefix_with",
      "connect_tunneling",
      "generic_http_upgrade",
      "grpc_web",
      "static_root",
      "upstream",
      "upstream_http_version",
      "upstream_pool",
      "timeouts",
      "waf",
    ][..],
    "routes.buffering" => &[
      "max_memory_body_bytes",
      "max_temp_file_bytes",
      "request",
      "response",
    ][..],
    "routes.timeouts" => &[
      "client_body_timeout_ms",
      "response_send_timeout_ms",
      "upstream_connect_timeout_ms",
      "upstream_first_byte_timeout_ms",
      "upstream_read_timeout_ms",
      "upstream_request_timeout_ms",
      "upstream_send_timeout_ms",
      "websocket_idle_timeout_ms",
      "webtransport_idle_timeout_ms",
    ][..],
    "stream_listeners" => &[
      "bind",
      "connect_timeout_ms",
      "idle_timeout_ms",
      "name",
      "proxy_protocol_egress",
      "target",
    ][..],
    "turn_upstream_pools" => &["algorithm", "hash_key", "health_check", "name", "servers"][..],
    "turn_upstream_pools.health_check" => &[
      "enabled",
      "healthy_threshold",
      "interval_ms",
      "timeout_ms",
      "unhealthy_threshold",
    ][..],
    "turn_upstream_pools.servers" => {
      &["backup", "id", "max_conns", "origin", "state", "weight"][..]
    }
    "webrtc_turn_listeners" => &[
      "auth",
      "bind_tcp",
      "bind_tls",
      "bind_udp",
      "idle_timeout_ms",
      "mode",
      "name",
      "public_ip",
      "realm",
      "relay_bind_ip",
      "relay_port_range",
      "tcp_pool",
      "tls",
      "tls_pool",
      "udp_pool",
    ][..],
    "webrtc_turn_listeners.auth" => &[
      "mode",
      "nonce_ttl_seconds",
      "rest_shared_secret",
      "rest_shared_secret_env",
      "static_credentials",
    ][..],
    "webrtc_turn_listeners.auth.static_credentials" => {
      &["password", "password_env", "username"][..]
    }
    "webrtc_turn_listeners.relay_port_range" => &["end", "start"][..],
    "webrtc_turn_listeners.tls" => &["cert_chain", "private_key", "remote_signer_key_id"][..],
    "rate_limits" => &[
      "burst",
      "key",
      "max_buckets",
      "mode",
      "name",
      "rate",
      "routes",
      "status",
      "token_header",
    ][..],
    "connection_limits" => &["key", "limit", "name", "status"][..],
    _ => return None,
  };
  Some(keys.iter().copied().collect())
}

fn redact_effective_toml(value: &mut toml::Value) {
  if let Some(connection_url) = value
    .get_mut("database")
    .and_then(|database| database.get_mut("access_log"))
    .and_then(|access_log| access_log.get_mut("connection_url"))
  {
    *connection_url = toml::Value::String("<redacted>".to_string());
  }
  if let Some(connection_url) = value
    .get_mut("logging")
    .and_then(|logging| logging.get_mut("access_log"))
    .and_then(|access_log| access_log.get_mut("database"))
    .and_then(|database| database.get_mut("connection_url"))
  {
    *connection_url = toml::Value::String("<redacted>".to_string());
  }
  if let Some(backends) = value
    .get_mut("shared_state")
    .and_then(|shared_state| shared_state.get_mut("backends"))
    .and_then(toml::Value::as_array_mut)
  {
    for backend in backends {
      if let Some(connection_url) = backend.get_mut("connection_url") {
        *connection_url = toml::Value::String("<redacted>".to_string());
      }
    }
  }
}

fn set_toml_integer_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: usize,
) -> anyhow::Result<()> {
  let resolved = i64::try_from(resolved).context("resolved worker count is too large")?;
  set_toml_value_path(value, path, toml::Value::Integer(resolved))
}

fn set_toml_float_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: f64,
) -> anyhow::Result<()> {
  set_toml_value_path(value, path, toml::Value::Float(resolved))
}

fn set_toml_value_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: toml::Value,
) -> anyhow::Result<()> {
  let Some((leaf, parents)) = path.split_last() else {
    return Ok(());
  };
  let mut current = value
    .as_table_mut()
    .ok_or_else(|| anyhow!("effective TOML root must be a table"))?;
  for key in parents {
    let entry = current
      .entry((*key).to_string())
      .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    current = entry
      .as_table_mut()
      .ok_or_else(|| anyhow!("effective TOML path {} must be a table", parents.join(".")))?;
  }
  current.insert((*leaf).to_string(), resolved);
  Ok(())
}

fn load_toml_with_includes(path: &Path) -> anyhow::Result<LoadedToml> {
  let mut stack = Vec::new();
  load_toml_document(path, &mut stack)
}

fn load_toml_document(path: &Path, stack: &mut Vec<PathBuf>) -> anyhow::Result<LoadedToml> {
  let absolute_path = absolute_config_path(path)?;
  let canonical_path = absolute_path.canonicalize().with_context(|| {
    format!(
      "failed to resolve configuration file {}",
      absolute_path.display()
    )
  })?;
  let canonical_parent = absolute_path
    .parent()
    .unwrap_or_else(|| Path::new("."))
    .canonicalize()
    .with_context(|| {
      format!(
        "failed to resolve configuration directory for {}",
        absolute_path.display()
      )
    })?;

  if !canonical_path.starts_with(&canonical_parent) {
    bail!(
      "configuration file {} must stay within its declaring directory",
      absolute_path.display()
    );
  }

  if let Some(index) = stack.iter().position(|entry| entry == &canonical_path) {
    let mut cycle = stack[index..]
      .iter()
      .map(|entry| entry.display().to_string())
      .collect::<Vec<_>>();
    cycle.push(canonical_path.display().to_string());
    bail!(
      "configuration include cycle detected: {}",
      cycle.join(" -> ")
    );
  }

  stack.push(canonical_path.clone());
  let mut files = vec![canonical_path.clone()];

  let raw = std::fs::read_to_string(&canonical_path)
    .with_context(|| format!("failed to read {}", canonical_path.display()))?;
  let mut value: toml::Value = toml::from_str(&raw)
    .with_context(|| format!("failed to parse TOML from {}", absolute_path.display()))?;
  let include_entries = take_include_entries(&mut value, &absolute_path)?;
  let base_dir = absolute_path.parent().unwrap_or_else(|| Path::new("."));

  let mut merged = toml::Value::Table(toml::map::Map::new());
  for entry in include_entries {
    for include_path in expand_include_entry(&entry, base_dir, &absolute_path)? {
      let included = load_toml_document(&include_path, stack)?;
      files.extend(included.files);
      merge_toml_values(&mut merged, included.value, "")?;
    }
  }
  merge_toml_values(&mut merged, value, "")?;

  stack.pop();
  files.sort();
  files.dedup();
  Ok(LoadedToml {
    value: merged,
    files,
  })
}

fn take_include_entries(value: &mut toml::Value, path: &Path) -> anyhow::Result<Vec<String>> {
  let Some(table) = value.as_table_mut() else {
    bail!(
      "configuration root in {} must be a TOML table",
      path.display()
    );
  };
  let Some(include) = table.remove("include") else {
    return Ok(Vec::new());
  };

  match include {
    toml::Value::String(entry) => Ok(vec![entry]),
    toml::Value::Array(entries) => entries
      .into_iter()
      .map(|entry| match entry {
        toml::Value::String(entry) => Ok(entry),
        _ => bail!(
          "configuration include entries in {} must be strings",
          path.display()
        ),
      })
      .collect(),
    _ => bail!(
      "configuration include in {} must be a string or array of strings",
      path.display()
    ),
  }
}

fn expand_include_entry(
  entry: &str,
  base_dir: &Path,
  source_path: &Path,
) -> anyhow::Result<Vec<PathBuf>> {
  if entry.trim().is_empty() {
    bail!(
      "configuration include in {} must not be empty",
      source_path.display()
    );
  }

  let include_path = Path::new(entry);
  let pattern_path =
    resolve_local_config_file_path("configuration include", base_dir, include_path)?;
  let canonical_base_dir = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve configuration include base directory {}",
      base_dir.display()
    )
  })?;

  if !has_glob_pattern(entry) {
    return Ok(vec![canonicalize_local_config_file(
      "configuration include",
      &pattern_path,
      &canonical_base_dir,
      source_path,
    )?]);
  }

  let pattern = pattern_path.to_str().ok_or_else(|| {
    anyhow!(
      "configuration include pattern in {} is not valid UTF-8: {}",
      source_path.display(),
      pattern_path.display()
    )
  })?;
  let mut paths = Vec::new();
  for path in glob::glob(pattern).with_context(|| {
    format!(
      "invalid configuration include pattern {}",
      pattern_path.display()
    )
  })? {
    let path = path.with_context(|| {
      format!(
        "failed to expand configuration include pattern {}",
        pattern_path.display()
      )
    })?;
    if path.is_file() {
      paths.push(canonicalize_local_config_file(
        "configuration include",
        &path,
        &canonical_base_dir,
        source_path,
      )?);
    }
  }
  paths.sort();
  Ok(paths)
}

fn has_glob_pattern(entry: &str) -> bool {
  entry.chars().any(|ch| matches!(ch, '*' | '?' | '['))
}

fn merge_toml_values(
  target: &mut toml::Value,
  source: toml::Value,
  key_path: &str,
) -> anyhow::Result<()> {
  match (target, source) {
    (toml::Value::Table(target), toml::Value::Table(source)) => {
      for (key, value) in source {
        let child_path = if key_path.is_empty() {
          key.clone()
        } else {
          format!("{key_path}.{key}")
        };

        if let Some(existing) = target.get_mut(&key) {
          merge_toml_values(existing, value, &child_path)?;
        } else {
          target.insert(key, value);
        }
      }
      Ok(())
    }
    (toml::Value::Array(target), toml::Value::Array(mut source)) => {
      target.append(&mut source);
      Ok(())
    }
    (target, source) => {
      let key = if key_path.is_empty() {
        "<root>"
      } else {
        key_path
      };
      bail!(
        "configuration key {key} is defined more than once across included TOML files or uses incompatible value types ({} vs {})",
        toml_type_name(target),
        toml_type_name(&source)
      );
    }
  }
}

fn toml_type_name(value: &toml::Value) -> &'static str {
  match value {
    toml::Value::String(_) => "string",
    toml::Value::Integer(_) => "integer",
    toml::Value::Float(_) => "float",
    toml::Value::Boolean(_) => "boolean",
    toml::Value::Datetime(_) => "datetime",
    toml::Value::Array(_) => "array",
    toml::Value::Table(_) => "table",
  }
}

fn absolute_config_path(path: &Path) -> anyhow::Result<PathBuf> {
  if path.is_absolute() {
    Ok(path.to_path_buf())
  } else {
    Ok(
      std::env::current_dir()
        .context("failed to determine current working directory")?
        .join(path),
    )
  }
}

fn config_base_dir(path: &Path) -> anyhow::Result<PathBuf> {
  let absolute_path = absolute_config_path(path)?;

  Ok(
    absolute_path
      .parent()
      .unwrap_or_else(|| Path::new("."))
      .to_path_buf(),
  )
}

struct ConfigPathRoots {
  config_dir: PathBuf,
  cert_dir: PathBuf,
  oxirule_dir: PathBuf,
}

fn config_path_roots(path: &Path) -> anyhow::Result<ConfigPathRoots> {
  let config_dir = config_base_dir(path)?;
  let layout_root = config_dir
    .parent()
    .unwrap_or_else(|| Path::new("."))
    .to_path_buf();

  Ok(ConfigPathRoots {
    config_dir,
    cert_dir: layout_root.join("cert"),
    oxirule_dir: layout_root.join("oxirule"),
  })
}

pub(crate) fn resolve_local_config_file_path(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  if path.is_absolute() {
    bail!("{field_name} must be a relative path under the configured directory");
  }

  validate_relative_path(field_name, path)?;
  Ok(base_dir.join(path))
}

pub(crate) fn resolve_existing_local_config_file_path_with_logical(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
  let resolved_path = resolve_local_config_file_path(field_name, base_dir, path)?;
  let canonical_base_dir = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve configured directory {}",
      base_dir.display()
    )
  })?;
  let canonical_path = resolved_path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", resolved_path.display()))?;

  if !canonical_path.starts_with(&canonical_base_dir) {
    bail!("{field_name} must stay within the configured directory");
  }
  ensure_regular_file(field_name, &canonical_path)?;

  Ok((canonical_path, resolved_path))
}

pub(crate) fn canonicalize_existing_file(field_name: &str, path: &Path) -> anyhow::Result<PathBuf> {
  let canonical_path = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
  ensure_regular_file(field_name, &canonical_path)?;

  Ok(canonical_path)
}

fn ensure_regular_file(field_name: &str, path: &Path) -> anyhow::Result<()> {
  let metadata = path
    .metadata()
    .with_context(|| format!("failed to inspect {field_name} {}", path.display()))?;

  if !metadata.is_file() {
    bail!("{field_name} must point to a regular file");
  }

  Ok(())
}

fn canonicalize_local_config_file(
  field_name: &str,
  path: &Path,
  canonical_base_dir: &Path,
  source_path: &Path,
) -> anyhow::Result<PathBuf> {
  let canonical_path = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;

  if !canonical_path.starts_with(canonical_base_dir) {
    bail!(
      "{field_name} in {} must stay within the declaring directory",
      source_path.display()
    );
  }

  Ok(canonical_path)
}

fn validate_relative_path(field_name: &str, path: &Path) -> anyhow::Result<()> {
  if path.as_os_str().is_empty() {
    bail!("{field_name} must not be empty");
  }

  for component in path.components() {
    match component {
      Component::Normal(_) => {}
      Component::CurDir | Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
        bail!(
          "{field_name} must not contain absolute, current-directory, or parent-directory components"
        );
      }
    }
  }

  Ok(())
}

fn validate_optional_non_empty(field_name: &str, value: Option<&str>) -> anyhow::Result<()> {
  if matches!(value, Some(value) if value.trim().is_empty()) {
    bail!("{field_name} must not be empty");
  }
  Ok(())
}

fn validate_optional_header_value(field_name: &str, value: Option<&str>) -> anyhow::Result<()> {
  if let Some(value) = value {
    validate_optional_non_empty(field_name, Some(value))?;
    http::HeaderValue::from_str(value)
      .with_context(|| format!("{field_name} is not a valid header value"))?;
  }
  Ok(())
}

pub(crate) fn quote_postgres_identifier_path(
  field_name: &str,
  value: &str,
) -> anyhow::Result<String> {
  validate_postgres_identifier_path(field_name, value)?;

  Ok(
    value
      .split('.')
      .map(|segment| format!("\"{segment}\""))
      .collect::<Vec<_>>()
      .join("."),
  )
}

fn validate_postgres_identifier_path(field_name: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field_name} must not be empty");
  }

  let parts = value.split('.').collect::<Vec<_>>();
  if parts.len() > 2 || parts.iter().any(|part| part.is_empty()) {
    bail!("{field_name} must be an unqualified table name or schema-qualified table name");
  }

  for part in parts {
    validate_postgres_identifier(field_name, part)?;
  }

  Ok(())
}

fn validate_postgres_identifier(field_name: &str, value: &str) -> anyhow::Result<()> {
  let mut bytes = value.bytes();
  let Some(first) = bytes.next() else {
    bail!("{field_name} must not contain empty identifier segments");
  };
  if !(first.is_ascii_alphabetic() || first == b'_') {
    bail!("{field_name} identifier segments must start with an ASCII letter or underscore");
  }
  if value.len() > 63 {
    bail!("{field_name} identifier segments must be 63 bytes or shorter");
  }
  if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
    bail!(
      "{field_name} identifier segments must contain only ASCII letters, digits, or underscores"
    );
  }
  Ok(())
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LoggingConfig {
  #[serde(default = "default_log_level")]
  pub level: String,
  #[serde(default)]
  pub access_log: LoggingAccessLogConfig,
}

impl Default for LoggingConfig {
  fn default() -> Self {
    Self {
      level: default_log_level(),
      access_log: LoggingAccessLogConfig::default(),
    }
  }
}

impl LoggingConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.level.trim().is_empty() {
      bail!("logging.level must not be empty");
    }
    crate::waf::validate_access_log_field_configs("logging.access_log", &self.access_log.fields)?;
    self
      .access_log
      .database
      .validate_with_prefix("logging.access_log.database")?;
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LoggingAccessLogConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub stdout: bool,
  #[serde(default = "default_system_access_log_field_configs")]
  pub fields: Vec<AccessLogFieldConfig>,
  #[serde(default)]
  pub database: DatabaseAccessLogConfig,
}

impl Default for LoggingAccessLogConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      stdout: true,
      fields: default_system_access_log_field_configs(),
      database: DatabaseAccessLogConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RuntimeDrainConfig {
  #[serde(default = "default_drain_graceful_timeout_ms")]
  pub graceful_timeout_ms: u64,
  #[serde(default = "default_drain_long_connection_close_delay_ms")]
  pub long_connection_close_delay_ms: u64,
  #[serde(default)]
  pub shutdown_delay_ms: u64,
}

impl Default for RuntimeDrainConfig {
  fn default() -> Self {
    Self {
      graceful_timeout_ms: default_drain_graceful_timeout_ms(),
      long_connection_close_delay_ms: default_drain_long_connection_close_delay_ms(),
      shutdown_delay_ms: 0,
    }
  }
}

impl RuntimeDrainConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.graceful_timeout_ms == 0 {
      bail!("runtime.drain.graceful_timeout_ms must be greater than 0");
    }
    if self.long_connection_close_delay_ms == 0 {
      bail!("runtime.drain.long_connection_close_delay_ms must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct HotReloadConfig {
  #[serde(default)]
  pub mode: HotReloadMode,
  #[serde(default = "default_hot_reload_poll_interval_ms")]
  pub poll_interval_ms: u64,
}

impl Default for HotReloadConfig {
  fn default() -> Self {
    Self {
      mode: HotReloadMode::Off,
      poll_interval_ms: default_hot_reload_poll_interval_ms(),
    }
  }
}

impl HotReloadConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.poll_interval_ms == 0 {
      bail!("runtime.hot_reload.poll_interval_ms must be greater than 0");
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HotReloadMode {
  #[default]
  Off,
  #[serde(rename = "oxirule")]
  OxiRule,
  Full,
  DownstreamTls,
}

impl HotReloadMode {
  pub fn enabled(self) -> bool {
    self != Self::Off
  }
}

impl std::fmt::Display for HotReloadMode {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(match self {
      Self::Off => "off",
      Self::OxiRule => "oxirule",
      Self::Full => "full",
      Self::DownstreamTls => "downstream_tls",
    })
  }
}

impl FromStr for HotReloadMode {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "off" => Ok(Self::Off),
      "oxirule" => Ok(Self::OxiRule),
      "full" => Ok(Self::Full),
      "downstream_tls" => Ok(Self::DownstreamTls),
      _ => {
        bail!("unsupported hot reload mode {value}; expected off, oxirule, full, or downstream_tls")
      }
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ListenerConfig {
  pub https_bind: SocketAddr,
  #[serde(default)]
  pub http_bind: Option<SocketAddr>,
  #[serde(default)]
  pub http_mode: HttpListenerMode,
  #[serde(default = "default_true")]
  pub http1: bool,
  #[serde(default = "default_true")]
  pub http2: bool,
  #[serde(default)]
  pub http3: bool,
  #[serde(default)]
  pub proxy_protocol: ProxyProtocolConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HttpListenerMode {
  #[default]
  Off,
  RedirectToHttps,
  Proxy,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyProtocolConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub version: ProxyProtocolVersion,
  #[serde(default)]
  pub trusted_sources: Vec<String>,
}

impl Default for ProxyProtocolConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      version: ProxyProtocolVersion::Any,
      trusted_sources: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocolVersion {
  V1,
  V2,
  #[default]
  Any,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QuicZeroRttMode {
  #[default]
  Off,
  SafeMethods,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicAltSvcConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_quic_alt_svc_max_age_seconds")]
  pub max_age_seconds: u64,
  #[serde(default)]
  pub persist: bool,
}

impl Default for QuicAltSvcConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      max_age_seconds: default_quic_alt_svc_max_age_seconds(),
      persist: false,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicTransportConfig {
  #[serde(default = "default_quic_max_concurrent_streams")]
  pub max_concurrent_bidi_streams: u64,
  #[serde(default = "default_quic_max_concurrent_streams")]
  pub max_concurrent_uni_streams: u64,
  #[serde(default = "default_quic_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default = "default_quic_datagram_buffer_bytes")]
  pub datagram_receive_buffer_bytes: usize,
  #[serde(default = "default_quic_datagram_buffer_bytes")]
  pub datagram_send_buffer_bytes: usize,
  #[serde(default = "default_quic_max_udp_payload_size")]
  pub max_udp_payload_size: u16,
  #[serde(default = "default_true")]
  pub gso: bool,
}

impl Default for QuicTransportConfig {
  fn default() -> Self {
    Self {
      max_concurrent_bidi_streams: default_quic_max_concurrent_streams(),
      max_concurrent_uni_streams: default_quic_max_concurrent_streams(),
      idle_timeout_ms: default_quic_idle_timeout_ms(),
      datagram_receive_buffer_bytes: default_quic_datagram_buffer_bytes(),
      datagram_send_buffer_bytes: default_quic_datagram_buffer_bytes(),
      max_udp_payload_size: default_quic_max_udp_payload_size(),
      gso: true,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicUpstreamPoolConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_quic_upstream_pool_max_connections")]
  pub max_connections_per_upstream: usize,
  #[serde(default = "default_quic_upstream_pool_max_lifetime_ms")]
  pub max_lifetime_ms: u64,
}

impl Default for QuicUpstreamPoolConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      max_connections_per_upstream: default_quic_upstream_pool_max_connections(),
      max_lifetime_ms: default_quic_upstream_pool_max_lifetime_ms(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProxyConfig {
  #[serde(default)]
  pub auto_upgrade: AutoUpgradeConfig,
  #[serde(default)]
  pub forwarded_headers: ForwardedHeadersConfig,
  #[serde(default)]
  pub real_ip: RealIpConfig,
  #[serde(default)]
  pub upgrades: ProxyUpgradesConfig,
  #[serde(default)]
  pub grpc_web: ProxyGrpcWebConfig,
  #[serde(default)]
  pub retry: ProxyRetryConfig,
  #[serde(default)]
  pub buffering: ProxyBufferingConfig,
  #[serde(default)]
  pub http: ProxyHttpConfig,
  #[serde(default)]
  pub trusted_ca_certs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
pub struct ForwardedHeadersConfig {
  #[serde(default)]
  pub mode: ForwardedHeaderMode,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedHeaderMode {
  #[default]
  Overwrite,
  Append,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RealIpConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub trusted_proxies: Vec<String>,
  #[serde(default)]
  pub header: RealIpHeader,
  #[serde(default = "default_true")]
  pub recursive: bool,
  #[serde(default)]
  pub fail_on_untrusted_forwarded_headers: bool,
}

impl Default for RealIpConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      trusted_proxies: Vec::new(),
      header: RealIpHeader::XForwardedFor,
      recursive: true,
      fail_on_untrusted_forwarded_headers: false,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RealIpHeader {
  #[default]
  XForwardedFor,
  XRealIp,
  Forwarded,
  CfConnectingIp,
}

impl RealIpHeader {
  pub fn header_name(self) -> &'static str {
    match self {
      Self::XForwardedFor => "x-forwarded-for",
      Self::XRealIp => "x-real-ip",
      Self::Forwarded => "forwarded",
      Self::CfConnectingIp => "cf-connecting-ip",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyUpgradesConfig {
  #[serde(default = "default_true")]
  pub websocket: bool,
  #[serde(default)]
  pub generic_http_upgrade: bool,
  #[serde(default)]
  pub connect_tunneling: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
pub struct ProxyGrpcWebConfig {
  #[serde(default)]
  pub enabled: bool,
}

impl Default for ProxyUpgradesConfig {
  fn default() -> Self {
    Self {
      websocket: true,
      generic_http_upgrade: false,
      connect_tunneling: false,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyRetryConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_retry_tries")]
  pub tries: usize,
  #[serde(default = "default_retry_timeout_ms")]
  pub timeout_ms: u64,
  #[serde(default = "default_retry_on")]
  pub on: Vec<RetryCondition>,
  #[serde(default)]
  pub retry_non_idempotent: bool,
}

impl Default for ProxyRetryConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      tries: default_retry_tries(),
      timeout_ms: default_retry_timeout_ms(),
      on: default_retry_on(),
      retry_non_idempotent: false,
    }
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RetryCondition {
  ConnectError,
  ReadTimeout,
  #[serde(rename = "502")]
  Status502,
  #[serde(rename = "503")]
  Status503,
  #[serde(rename = "504")]
  Status504,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyBufferingConfig {
  #[serde(default)]
  pub request: BufferingMode,
  #[serde(default)]
  pub response: BufferingMode,
  #[serde(default = "default_buffering_max_memory_body_bytes")]
  pub max_memory_body_bytes: usize,
  #[serde(default)]
  pub max_temp_file_bytes: usize,
  #[serde(default)]
  pub temp_dir: Option<PathBuf>,
}

impl Default for ProxyBufferingConfig {
  fn default() -> Self {
    Self {
      request: BufferingMode::Streaming,
      response: BufferingMode::Streaming,
      max_memory_body_bytes: default_buffering_max_memory_body_bytes(),
      max_temp_file_bytes: 0,
      temp_dir: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BufferingMode {
  #[default]
  Streaming,
  Memory,
  Spool,
  RejectIfTooLarge,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyHttpConfig {
  #[serde(default)]
  pub early_hints: EarlyHintsMode,
  #[serde(default)]
  pub trailers: TrailerMode,
  #[serde(default)]
  pub expect_continue: ExpectContinueMode,
  #[serde(default)]
  pub priority: PriorityMode,
  #[serde(default = "default_true")]
  pub sse_auto_streaming: bool,
  #[serde(default)]
  pub grpc: ProxyHttpGrpcConfig,
  #[serde(default)]
  pub errors: ProxyHttpErrorsConfig,
}

impl Default for ProxyHttpConfig {
  fn default() -> Self {
    Self {
      early_hints: EarlyHintsMode::Drop,
      trailers: TrailerMode::Pass,
      expect_continue: ExpectContinueMode::Auto,
      priority: PriorityMode::Pass,
      sse_auto_streaming: true,
      grpc: ProxyHttpGrpcConfig::default(),
      errors: ProxyHttpErrorsConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EarlyHintsMode {
  #[default]
  Drop,
  Pass,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrailerMode {
  #[default]
  Pass,
  Drop,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectContinueMode {
  #[default]
  Auto,
  Reject,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PriorityMode {
  #[default]
  Pass,
  Ignore,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ProxyHttpGrpcConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub respect_grpc_timeout: bool,
  #[serde(default)]
  pub retry: GrpcRetryMode,
}

impl Default for ProxyHttpGrpcConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      respect_grpc_timeout: true,
      retry: GrpcRetryMode::Off,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrpcRetryMode {
  #[default]
  Off,
  SafeUnary,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProxyHttpErrorsConfig {
  #[serde(default)]
  pub mode: ErrorResponseMode,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorResponseMode {
  #[default]
  LegacyPlain,
  Plain,
  Json,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AutoUpgradeConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
}

impl Default for AutoUpgradeConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      max_http_version: HttpVersion::H2,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompressionConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub gzip: bool,
  #[serde(default = "default_true")]
  pub deflate: bool,
  #[serde(default = "default_true")]
  pub zstd: bool,
  #[serde(default = "default_true")]
  pub br: bool,
  #[serde(default = "default_compression_min_size_bytes")]
  pub min_size_bytes: u64,
  #[serde(default = "default_compression_statuses")]
  pub statuses: Vec<u16>,
  #[serde(default = "default_compression_mime_types")]
  pub mime_types: Vec<String>,
  #[serde(default)]
  pub max_concurrent_responses: usize,
  #[serde(default)]
  pub policies: Vec<CompressionPolicyConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompressionPolicyConfig {
  pub name: String,
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub gzip: bool,
  #[serde(default = "default_true")]
  pub deflate: bool,
  #[serde(default = "default_true")]
  pub zstd: bool,
  #[serde(default = "default_true")]
  pub br: bool,
  #[serde(default = "default_compression_min_size_bytes")]
  pub min_size_bytes: u64,
  #[serde(default = "default_compression_statuses")]
  pub statuses: Vec<u16>,
  #[serde(default = "default_compression_mime_types")]
  pub mime_types: Vec<String>,
}

impl CompressionConfig {
  pub fn accept_encoding_value(&self) -> Option<String> {
    if !self.enabled {
      return None;
    }

    let mut values = Vec::new();
    if self.br {
      values.push("br");
    }
    if self.zstd {
      values.push("zstd");
    }
    if self.gzip {
      values.push("gzip");
    }
    if self.deflate {
      values.push("deflate");
    }

    if values.is_empty() {
      None
    } else {
      Some(values.join(", "))
    }
  }
}

impl Default for CompressionConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      gzip: true,
      deflate: true,
      zstd: true,
      br: true,
      min_size_bytes: default_compression_min_size_bytes(),
      statuses: default_compression_statuses(),
      mime_types: default_compression_mime_types(),
      max_concurrent_responses: 0,
      policies: Vec::new(),
    }
  }
}

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
pub struct RateLimitConfig {
  pub name: String,
  #[serde(default)]
  pub key: RateLimitKey,
  #[serde(default)]
  pub routes: Vec<String>,
  #[serde(default)]
  pub token_header: Option<String>,
  pub rate: String,
  #[serde(default)]
  pub burst: u32,
  #[serde(default = "crate::limits::default_rate_limit_max_buckets")]
  pub max_buckets: usize,
  #[serde(default)]
  pub mode: LimitMode,
  #[serde(default = "default_rate_limit_status")]
  pub status: u16,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
  #[default]
  #[serde(alias = "client-ip")]
  ClientIp,
  #[serde(alias = "client-ip-route")]
  ClientIpRoute,
  #[serde(alias = "client-ip-path")]
  ClientIpPath,
  #[serde(alias = "access-token")]
  AccessToken,
  #[serde(alias = "access-token-route")]
  AccessTokenRoute,
  #[serde(alias = "access-token-path")]
  AccessTokenPath,
}

impl RateLimitKey {
  pub fn uses_access_token(self) -> bool {
    matches!(
      self,
      Self::AccessToken | Self::AccessTokenRoute | Self::AccessTokenPath
    )
  }
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
  pub admission: CacheAdmissionConfig,
  #[serde(default)]
  pub stale_if_error: CacheStaleIfErrorConfig,
  #[serde(default)]
  pub policies: Vec<CachePolicyConfig>,
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
      admission: CacheAdmissionConfig::default(),
      stale_if_error: CacheStaleIfErrorConfig::default(),
      policies: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CacheSurrogateConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub strip_response_header: bool,
}

impl Default for CacheSurrogateConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      strip_response_header: true,
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
  pub rules: Vec<CachePolicyRuleConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CacheAdmissionConfig {
  #[serde(default = "default_cache_admission_statuses")]
  pub statuses: Vec<u16>,
  #[serde(default)]
  pub content_types: Vec<String>,
  #[serde(default)]
  pub max_body_bytes: usize,
  #[serde(default = "default_cache_admission_min_hits")]
  pub min_hits: usize,
  #[serde(default = "default_cache_admission_max_tracked_keys")]
  pub max_tracked_keys: usize,
}

impl Default for CacheAdmissionConfig {
  fn default() -> Self {
    Self {
      statuses: default_cache_admission_statuses(),
      content_types: Vec::new(),
      max_body_bytes: 0,
      min_hits: default_cache_admission_min_hits(),
      max_tracked_keys: default_cache_admission_max_tracked_keys(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CacheStaleIfErrorConfig {
  #[serde(default = "default_true")]
  pub connect_error: bool,
  #[serde(default = "default_true")]
  pub read_timeout: bool,
  #[serde(default)]
  pub statuses: Vec<u16>,
  #[serde(default)]
  pub max_upstream_stale_seconds: u64,
}

impl Default for CacheStaleIfErrorConfig {
  fn default() -> Self {
    Self {
      connect_error: true,
      read_timeout: true,
      statuses: Vec::new(),
      max_upstream_stale_seconds: 0,
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CachePolicyRuleConfig {
  #[serde(default)]
  pub mime_types: Vec<String>,
  pub store: CacheStore,
}

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
  pub tls: AdminTlsConfig,
  #[serde(default)]
  pub rbac: AdminRbacConfig,
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
      tls: AdminTlsConfig::default(),
      rbac: AdminRbacConfig::default(),
    }
  }
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

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct AdminRbacConfig {
  #[serde(default)]
  pub tokens: Vec<AdminRbacTokenConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminRbacTokenConfig {
  pub name: String,
  pub bearer_token_env: String,
  pub roles: Vec<AdminRole>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
  Viewer,
  CacheOperator,
  UpstreamOperator,
  SecurityOperator,
  Admin,
}

impl AdminRole {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Viewer => "viewer",
      Self::CacheOperator => "cache_operator",
      Self::UpstreamOperator => "upstream_operator",
      Self::SecurityOperator => "security_operator",
      Self::Admin => "admin",
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
pub struct AdminTlsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_tls_min_version")]
  pub min_version: TlsVersion,
  #[serde(default = "default_tls_max_version")]
  pub max_version: TlsVersion,
  #[serde(default)]
  pub session_tickets: bool,
  #[serde(default = "default_true")]
  pub require_sni: bool,
  #[serde(default = "default_true")]
  pub reject_unknown_sni: bool,
  #[serde(default)]
  pub certificates: Vec<AdminTlsCertificateConfig>,
  #[serde(default)]
  pub client_auth: TlsClientAuthConfig,
}

impl Default for AdminTlsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      min_version: TlsVersion::Tls13,
      max_version: TlsVersion::Tls13,
      session_tickets: false,
      require_sni: true,
      reject_unknown_sni: true,
      certificates: Vec::new(),
      client_auth: TlsClientAuthConfig::default(),
    }
  }
}

impl AdminTlsConfig {
  fn resolve_relative_paths(&mut self, cert_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut resolved_paths = Vec::new();
    for certificate in &mut self.certificates {
      let (cert_chain, cert_logical) = resolve_existing_local_config_file_path_with_logical(
        "admin.tls.certificates.cert_chain",
        cert_dir,
        &certificate.cert_chain,
      )?;
      certificate.cert_chain = cert_chain;
      resolved_paths.push(cert_logical);
      let (private_key, key_logical) = resolve_existing_local_config_file_path_with_logical(
        "admin.tls.certificates.private_key",
        cert_dir,
        &certificate.private_key,
      )?;
      certificate.private_key = private_key;
      resolved_paths.push(key_logical);
    }
    self.client_auth.ca_certs = self
      .client_auth
      .ca_certs
      .iter()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "admin.tls.client_auth.ca_certs",
          cert_dir,
          path,
        )?;
        resolved_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .collect::<anyhow::Result<_>>()?;
    Ok(resolved_paths)
  }

  fn validate(&self) -> anyhow::Result<()> {
    if self.min_version > self.max_version {
      bail!("admin.tls.min_version must be less than or equal to admin.tls.max_version");
    }
    if self.client_auth.mode != TlsClientAuthMode::Off && self.client_auth.ca_certs.is_empty() {
      bail!("admin.tls.client_auth.ca_certs is required when client_auth mode is not off");
    }
    if !self.enabled {
      return Ok(());
    }
    if self.certificates.is_empty() {
      bail!(
        "admin.tls.certificates must include at least one certificate when admin TLS is enabled"
      );
    }
    let defaults = self
      .certificates
      .iter()
      .filter(|certificate| certificate.default)
      .count();
    if self.certificates.len() > 1 && defaults != 1 {
      bail!(
        "exactly one admin.tls.certificates entry must set default = true when multiple certificates are configured"
      );
    }
    let mut names = HashSet::new();
    for certificate in &self.certificates {
      if certificate.server_names.is_empty() {
        bail!("admin.tls.certificates server_names must not be empty");
      }
      for name in &certificate.server_names {
        validate_admin_server_name(name)?;
        if !names.insert(name.to_ascii_lowercase()) {
          bail!("duplicate admin.tls certificate server_name {name}");
        }
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminTlsCertificateConfig {
  #[serde(default)]
  pub server_names: Vec<String>,
  pub cert_chain: PathBuf,
  pub private_key: PathBuf,
  #[serde(default)]
  pub default: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MetricsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_metrics_bind")]
  pub bind: SocketAddr,
  #[serde(default)]
  pub format: MetricsFormat,
}

impl Default for MetricsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      bind: default_metrics_bind(),
      format: MetricsFormat::Prometheus,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MetricsFormat {
  #[default]
  Prometheus,
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

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct SecurityConfig {
  #[serde(default)]
  pub headers: SecurityHeadersConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SecurityHeadersConfig {
  #[serde(default)]
  pub hsts: bool,
  #[serde(default = "default_hsts_max_age_seconds")]
  pub hsts_max_age_seconds: u64,
  #[serde(default = "default_true")]
  pub hsts_include_subdomains: bool,
  #[serde(default)]
  pub hsts_preload: bool,
  #[serde(default)]
  pub x_content_type_options: Option<String>,
  #[serde(default)]
  pub referrer_policy: Option<String>,
  #[serde(default)]
  pub permissions_policy: Option<String>,
}

impl Default for SecurityHeadersConfig {
  fn default() -> Self {
    Self {
      hsts: false,
      hsts_max_age_seconds: default_hsts_max_age_seconds(),
      hsts_include_subdomains: true,
      hsts_preload: false,
      x_content_type_options: None,
      referrer_policy: None,
      permissions_policy: None,
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct DatabaseConfig {
  #[serde(default)]
  pub access_log: DatabaseAccessLogConfig,
}

impl DatabaseConfig {
  fn validate(&self) -> anyhow::Result<()> {
    self.access_log.validate()
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SharedStateConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_shared_state_namespace")]
  pub namespace: String,
  #[serde(default = "default_shared_state_instance_id_env")]
  pub instance_id_env: String,
  #[serde(default)]
  pub default_backend: Option<String>,
  #[serde(default = "default_shared_state_operation_timeout_ms")]
  pub operation_timeout_ms: u64,
  #[serde(default = "default_shared_state_connection_lease_ms")]
  pub connection_lease_ms: u64,
  #[serde(default = "default_shared_state_cache_lock_ms")]
  pub cache_lock_ms: u64,
  #[serde(default)]
  pub rate_limits_backend: Option<String>,
  #[serde(default)]
  pub connection_limits_backend: Option<String>,
  #[serde(default)]
  pub person_proof_backend: Option<String>,
  #[serde(default)]
  pub upstream_health_backend: Option<String>,
  #[serde(default)]
  pub cache_backend: Option<String>,
  #[serde(default)]
  pub reload_backend: Option<String>,
  #[serde(default)]
  pub dynamic_policy_backend: Option<String>,
  #[serde(default)]
  pub backends: Vec<SharedStateBackendConfig>,
}

impl Default for SharedStateConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      namespace: default_shared_state_namespace(),
      instance_id_env: default_shared_state_instance_id_env(),
      default_backend: None,
      operation_timeout_ms: default_shared_state_operation_timeout_ms(),
      connection_lease_ms: default_shared_state_connection_lease_ms(),
      cache_lock_ms: default_shared_state_cache_lock_ms(),
      rate_limits_backend: None,
      connection_limits_backend: None,
      person_proof_backend: None,
      upstream_health_backend: None,
      cache_backend: None,
      reload_backend: None,
      dynamic_policy_backend: None,
      backends: Vec::new(),
    }
  }
}

impl SharedStateConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if !self.enabled {
      return Ok(());
    }
    validate_optional_non_empty("shared_state.namespace", Some(&self.namespace))?;
    validate_optional_non_empty("shared_state.instance_id_env", Some(&self.instance_id_env))?;
    if self.operation_timeout_ms == 0 || self.connection_lease_ms == 0 || self.cache_lock_ms == 0 {
      bail!("shared_state timeout and lease values must be greater than 0");
    }
    if self.backends.is_empty() {
      bail!("shared_state.backends must include at least one backend when enabled=true");
    }
    let mut names = HashSet::new();
    for backend in &self.backends {
      backend.validate()?;
      if !names.insert(backend.name.as_str()) {
        bail!("duplicate shared_state backend name {}", backend.name);
      }
    }
    for (field, name) in [
      (
        "shared_state.default_backend",
        self.default_backend.as_deref(),
      ),
      (
        "shared_state.rate_limits_backend",
        self.rate_limits_backend.as_deref(),
      ),
      (
        "shared_state.connection_limits_backend",
        self.connection_limits_backend.as_deref(),
      ),
      (
        "shared_state.person_proof_backend",
        self.person_proof_backend.as_deref(),
      ),
      (
        "shared_state.upstream_health_backend",
        self.upstream_health_backend.as_deref(),
      ),
      ("shared_state.cache_backend", self.cache_backend.as_deref()),
      (
        "shared_state.reload_backend",
        self.reload_backend.as_deref(),
      ),
      (
        "shared_state.dynamic_policy_backend",
        self.dynamic_policy_backend.as_deref(),
      ),
    ] {
      if let Some(name) = name
        && !names.contains(name)
      {
        bail!("{field} references unknown shared_state backend {name}");
      }
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SharedStateBackendConfig {
  pub name: String,
  pub kind: SharedStateBackendKind,
  #[serde(default)]
  pub connection_url: Option<String>,
  #[serde(default)]
  pub connection_url_env: Option<String>,
  #[serde(default = "default_shared_state_max_connections")]
  pub max_connections: u32,
  #[serde(default = "default_database_access_log_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default)]
  pub tls: DatabaseTlsConfig,
}

impl SharedStateBackendConfig {
  fn validate(&self) -> anyhow::Result<()> {
    validate_optional_non_empty(
      &format!("shared_state.backends.{}.connection_url", self.name),
      self.connection_url.as_deref(),
    )?;
    validate_optional_non_empty(
      &format!("shared_state.backends.{}.connection_url_env", self.name),
      self.connection_url_env.as_deref(),
    )?;
    if self.name.trim().is_empty() {
      bail!("shared_state backend name must not be empty");
    }
    if !self
      .name
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
      bail!("shared_state backend name must contain only ASCII letters, digits, '.', '_' or '-'");
    }
    if self.max_connections == 0 || self.connect_timeout_ms == 0 {
      bail!(
        "shared_state backend {} numeric values must be greater than 0",
        self.name
      );
    }
    match (&self.connection_url, &self.connection_url_env) {
      (Some(_), Some(_)) => {
        bail!(
          "shared_state backend {} must set only one of connection_url or connection_url_env",
          self.name
        )
      }
      (None, None) => {
        bail!(
          "shared_state backend {} requires connection_url or connection_url_env",
          self.name
        )
      }
      _ => {}
    }
    if self.kind == SharedStateBackendKind::Redis
      && (self.tls.ca_cert.is_some()
        || self.tls.client_cert.is_some()
        || self.tls.client_key.is_some()
        || self.tls.mode != DatabaseTlsMode::Off)
    {
      bail!(
        "shared_state Redis backend {} does not support tls settings",
        self.name
      );
    }
    if self.kind == SharedStateBackendKind::Postgres {
      self
        .tls
        .validate_with_prefix(&format!("shared_state.backends.{}.tls", self.name))?;
    }
    Ok(())
  }

  pub(crate) fn connection_url_with_prefix(&self, prefix: &str) -> anyhow::Result<String> {
    if let Some(env_name) = &self.connection_url_env {
      let value = std::env::var(env_name)
        .with_context(|| format!("failed to read {prefix}.connection_url_env {env_name}"))?;
      if value.trim().is_empty() {
        bail!("{prefix}.connection_url_env {env_name} resolved to an empty value");
      }
      return Ok(value);
    }
    self
      .connection_url
      .clone()
      .ok_or_else(|| anyhow!("{prefix}.connection_url is required"))
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SharedStateBackendKind {
  Redis,
  Postgres,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DatabaseAccessLogConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub connection_url: Option<String>,
  #[serde(default)]
  pub connection_url_env: Option<String>,
  #[serde(default)]
  pub table: Option<String>,
  #[serde(default = "default_database_access_log_max_connections")]
  pub max_connections: u32,
  #[serde(default = "default_database_access_log_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_database_access_log_queue_capacity")]
  pub queue_capacity: usize,
  #[serde(default)]
  pub tls: DatabaseTlsConfig,
}

impl Default for DatabaseAccessLogConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      connection_url: None,
      connection_url_env: None,
      table: None,
      max_connections: default_database_access_log_max_connections(),
      connect_timeout_ms: default_database_access_log_connect_timeout_ms(),
      queue_capacity: default_database_access_log_queue_capacity(),
      tls: DatabaseTlsConfig::default(),
    }
  }
}

impl DatabaseAccessLogConfig {
  fn validate(&self) -> anyhow::Result<()> {
    self.validate_with_prefix("database.access_log")
  }

  pub(crate) fn validate_with_prefix(&self, prefix: &str) -> anyhow::Result<()> {
    validate_optional_non_empty(
      &format!("{prefix}.connection_url"),
      self.connection_url.as_deref(),
    )?;
    validate_optional_non_empty(
      &format!("{prefix}.connection_url_env"),
      self.connection_url_env.as_deref(),
    )?;
    if let Some(table) = &self.table {
      validate_postgres_identifier_path(&format!("{prefix}.table"), table)?;
    }
    if self.max_connections == 0 {
      bail!("{prefix}.max_connections must be greater than 0");
    }
    if self.connect_timeout_ms == 0 {
      bail!("{prefix}.connect_timeout_ms must be greater than 0");
    }
    if self.queue_capacity == 0 {
      bail!("{prefix}.queue_capacity must be greater than 0");
    }
    self.tls.validate_with_prefix(&format!("{prefix}.tls"))?;

    if !self.enabled {
      return Ok(());
    }

    match (&self.connection_url, &self.connection_url_env) {
      (Some(_), Some(_)) => {
        bail!("{prefix} must set only one of connection_url or connection_url_env")
      }
      (None, None) => {
        bail!("{prefix} requires connection_url or connection_url_env when enabled=true")
      }
      _ => {}
    }
    if self.table.is_none() {
      bail!("{prefix}.table is required when enabled=true");
    }

    Ok(())
  }

  pub(crate) fn connection_url_with_prefix(&self, prefix: &str) -> anyhow::Result<Option<String>> {
    if let Some(env_name) = &self.connection_url_env {
      let value = std::env::var(env_name)
        .with_context(|| format!("failed to read {prefix}.connection_url_env {env_name}"))?;
      if value.trim().is_empty() {
        bail!("{prefix}.connection_url_env {env_name} resolved to an empty value");
      }
      return Ok(Some(value));
    }
    Ok(self.connection_url.clone())
  }

  pub(crate) fn table_name_with_prefix(&self, prefix: &str) -> anyhow::Result<Option<String>> {
    self
      .table
      .as_deref()
      .map(|table| quote_postgres_identifier_path(&format!("{prefix}.table"), table))
      .transpose()
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DatabaseTlsConfig {
  #[serde(default)]
  pub mode: DatabaseTlsMode,
  #[serde(default)]
  pub ca_cert: Option<PathBuf>,
  #[serde(default)]
  pub client_cert: Option<PathBuf>,
  #[serde(default)]
  pub client_key: Option<PathBuf>,
}

impl Default for DatabaseTlsConfig {
  fn default() -> Self {
    Self {
      mode: DatabaseTlsMode::Off,
      ca_cert: None,
      client_cert: None,
      client_key: None,
    }
  }
}

impl DatabaseTlsConfig {
  fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    self.ca_cert = self
      .ca_cert
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "database.access_log.tls.ca_cert",
          base_dir,
          &path,
        )?;
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    self.client_cert = self
      .client_cert
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "database.access_log.tls.client_cert",
          base_dir,
          &path,
        )?;
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    self.client_key = self
      .client_key
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "database.access_log.tls.client_key",
          base_dir,
          &path,
        )?;
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    Ok(source_paths)
  }

  fn validate_with_prefix(&self, prefix: &str) -> anyhow::Result<()> {
    if self.ca_cert.is_some() && self.mode != DatabaseTlsMode::VerifyFull {
      bail!("{prefix}.ca_cert is only valid when {prefix}.mode is \"verify_full\"");
    }
    match (&self.client_cert, &self.client_key) {
      (Some(_), Some(_)) if self.mode == DatabaseTlsMode::VerifyFull => {}
      (Some(_), Some(_)) => bail!(
        "{prefix}.client_cert and client_key are only valid when {prefix}.mode is \"verify_full\""
      ),
      (Some(_), None) => {
        bail!("{prefix}.client_key is required when client_cert is configured")
      }
      (None, Some(_)) => {
        bail!("{prefix}.client_cert is required when client_key is configured")
      }
      (None, None) => {}
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseTlsMode {
  #[default]
  Off,
  VerifyFull,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamConfig {
  pub name: String,
  pub origin: Url,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
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
  pub keepalive: UpstreamPoolKeepaliveConfig,
  #[serde(default)]
  pub servers: Vec<UpstreamPoolServerConfig>,
  #[serde(default)]
  pub discovery: Vec<UpstreamPoolDiscoveryConfig>,
  #[serde(default)]
  pub health_check: UpstreamPoolHealthCheckConfig,
}

impl UpstreamPoolConfig {
  fn resolve_discovery_paths(&mut self, config_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
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
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolDiscoveryConfig {
  pub provider: UpstreamDiscoveryProvider,
  #[serde(default)]
  pub name: Option<String>,
  #[serde(default)]
  pub file: Option<PathBuf>,
  #[serde(default)]
  pub record_type: DnsDiscoveryRecordType,
  #[serde(default)]
  pub scheme: DiscoveryUpstreamScheme,
  #[serde(default)]
  pub port: Option<u16>,
  #[serde(default = "default_discovery_refresh_interval_ms")]
  pub refresh_interval_ms: u64,
  #[serde(default = "default_discovery_min_ttl_ms")]
  pub min_ttl_ms: u64,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamDiscoveryProvider {
  Dns,
  File,
  Kubernetes,
  Consul,
  Etcd,
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

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
  #[default]
  RoundRobin,
  LeastConn,
  Random,
  Hash,
  IpHash,
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
  #[serde(skip)]
  pub source: UpstreamPoolServerSource,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
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
  Admin,
}

impl UpstreamPoolServerSource {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Static => "static",
      Self::Dns => "dns",
      Self::File => "file",
      Self::Admin => "admin",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct UpstreamPoolHealthCheckConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub mode: HealthCheckMode,
  #[serde(default = "default_health_check_path")]
  pub path: String,
  #[serde(default = "default_health_check_interval_ms")]
  pub interval_ms: u64,
  #[serde(default = "default_health_check_timeout_ms")]
  pub timeout_ms: u64,
  #[serde(default = "default_health_check_healthy_threshold")]
  pub healthy_threshold: u32,
  #[serde(default = "default_health_check_unhealthy_threshold")]
  pub unhealthy_threshold: u32,
  #[serde(default = "default_health_check_expected_status")]
  pub expected_status: Vec<u16>,
  #[serde(default)]
  pub protocol: HealthCheckProtocol,
  #[serde(default)]
  pub grpc_service: String,
  #[serde(default = "default_grpc_health_expected_statuses")]
  pub grpc_expected_statuses: Vec<GrpcHealthServingStatus>,
}

impl Default for UpstreamPoolHealthCheckConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: HealthCheckMode::Passive,
      path: default_health_check_path(),
      interval_ms: default_health_check_interval_ms(),
      timeout_ms: default_health_check_timeout_ms(),
      healthy_threshold: default_health_check_healthy_threshold(),
      unhealthy_threshold: default_health_check_unhealthy_threshold(),
      expected_status: default_health_check_expected_status(),
      protocol: HealthCheckProtocol::Http,
      grpc_service: String::new(),
      grpc_expected_statuses: default_grpc_health_expected_statuses(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckProtocol {
  #[default]
  Http,
  Grpc,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GrpcHealthServingStatus {
  Unknown,
  Serving,
  NotServing,
  ServiceUnknown,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckMode {
  #[default]
  Passive,
  Active,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct UpstreamTlsConfig {
  #[serde(default)]
  pub ech: UpstreamEchConfig,
}

impl UpstreamTlsConfig {
  fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    self.ech.config_list_file = self
      .ech
      .config_list_file
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          "upstreams.tls.ech.config_list_file",
          base_dir,
          &path,
        )?;
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    Ok(source_paths)
  }

  fn validate(&self, upstream_name: &str) -> anyhow::Result<()> {
    match self.ech.mode {
      UpstreamEchMode::Disabled | UpstreamEchMode::Grease => {
        if self.ech.config_list_file.is_some() {
          bail!(
            "upstream {} tls.ech.config_list_file is only valid when tls.ech.mode = \"config_list\"",
            upstream_name
          );
        }
      }
      UpstreamEchMode::ConfigList => {
        if self.ech.config_list_file.is_none() {
          bail!(
            "upstream {} tls.ech.config_list_file is required when tls.ech.mode = \"config_list\"",
            upstream_name
          );
        }
      }
    }

    Ok(())
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RouteConfig {
  pub name: String,
  #[serde(default = "default_hosts")]
  pub hosts: Vec<String>,
  #[serde(default = "default_path_prefix")]
  pub path_prefix: String,
  #[serde(default)]
  pub replace_prefix_with: Option<String>,
  #[serde(default)]
  pub upstream: Option<String>,
  #[serde(default)]
  pub upstream_pool: Option<String>,
  #[serde(default)]
  pub static_root: Option<PathBuf>,
  #[serde(default)]
  pub upstream_http_version: Option<HttpVersion>,
  #[serde(default)]
  pub generic_http_upgrade: bool,
  #[serde(default)]
  pub connect_tunneling: bool,
  #[serde(default)]
  pub grpc_web: bool,
  #[serde(default)]
  pub cache: Option<String>,
  #[serde(default)]
  pub compression: Option<String>,
  #[serde(default)]
  pub buffering: RouteBufferingConfig,
  #[serde(default)]
  pub timeouts: RouteTimeoutConfig,
  #[serde(default)]
  pub waf: RouteWafConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteBufferingConfig {
  #[serde(default)]
  pub request: Option<BufferingMode>,
  #[serde(default)]
  pub response: Option<BufferingMode>,
  #[serde(default)]
  pub max_memory_body_bytes: Option<usize>,
  #[serde(default)]
  pub max_temp_file_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteTimeoutConfig {
  #[serde(default)]
  pub client_body_timeout_ms: Option<u64>,
  #[serde(default)]
  pub response_send_timeout_ms: Option<u64>,
  #[serde(default)]
  pub websocket_idle_timeout_ms: Option<u64>,
  #[serde(default)]
  pub webtransport_idle_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_connect_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_request_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_first_byte_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_read_timeout_ms: Option<u64>,
  #[serde(default)]
  pub upstream_send_timeout_ms: Option<u64>,
}

impl RouteTimeoutConfig {
  fn validate(&self, route_name: &str) -> anyhow::Result<()> {
    for (field, value) in [
      ("client_body_timeout_ms", self.client_body_timeout_ms),
      ("response_send_timeout_ms", self.response_send_timeout_ms),
      ("websocket_idle_timeout_ms", self.websocket_idle_timeout_ms),
      (
        "webtransport_idle_timeout_ms",
        self.webtransport_idle_timeout_ms,
      ),
      (
        "upstream_connect_timeout_ms",
        self.upstream_connect_timeout_ms,
      ),
      (
        "upstream_request_timeout_ms",
        self.upstream_request_timeout_ms,
      ),
      (
        "upstream_first_byte_timeout_ms",
        self.upstream_first_byte_timeout_ms,
      ),
      ("upstream_read_timeout_ms", self.upstream_read_timeout_ms),
      ("upstream_send_timeout_ms", self.upstream_send_timeout_ms),
    ] {
      if value == Some(0) {
        bail!("route {route_name} timeouts.{field} must be greater than 0");
      }
    }
    Ok(())
  }
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

fn default_true() -> bool {
  true
}

fn default_log_level() -> String {
  "info".to_string()
}

fn default_system_access_log_field_configs() -> Vec<AccessLogFieldConfig> {
  [
    ("request_id", "Request.Id"),
    ("response_id", "Response.Id"),
    ("transaction_id", "Context.TransactionId"),
    ("method", "Request.Http.Method"),
    ("uri", "Request.Http.Uri"),
    ("path", "Request.Http.Path"),
    ("query", "Request.Http.Query"),
    ("request_version", "Request.Http.Version"),
    ("host", "Request.Http.Host"),
    ("user_agent", "Request.Headers.getAll('User-Agent')"),
    ("client_ip", "Request.Client.Ip"),
    ("client_port", "Request.Client.Port"),
    ("protocol", "Request.Protocol"),
    ("transport", "Request.Transport.Network"),
    ("tls", "Request.Tls.Enabled"),
    ("route", "Context.RouteName"),
    ("status", "Response.Http.Status"),
    ("reason", "Response.Http.Reason"),
    ("response_body_bytes", "Response.Body.Size"),
    ("upstream", "Response.Upstream.Name"),
    ("upstream_pool", "Response.Upstream.Pool"),
    ("upstream_scheme", "Response.Upstream.Scheme"),
    (
      "upstream_connect_time_ms",
      "Response.Upstream.ConnectTimeMs",
    ),
    (
      "upstream_first_byte_time_ms",
      "Response.Upstream.FirstByteTimeMs",
    ),
    ("request_received_at_unix_ms", "Request.ReceivedAtUnixMs"),
    ("response_received_at_unix_ms", "Response.ReceivedAtUnixMs"),
  ]
  .into_iter()
  .map(|(name, value)| AccessLogFieldConfig {
    name: name.to_string(),
    value: value.to_string(),
  })
  .collect()
}

fn default_hot_reload_poll_interval_ms() -> u64 {
  2_000
}

fn default_drain_graceful_timeout_ms() -> u64 {
  30_000
}

fn default_drain_long_connection_close_delay_ms() -> u64 {
  300_000
}

fn default_runtime_accept_backlog() -> u32 {
  1_024
}

fn default_accept_error_backoff_ms() -> u64 {
  50
}

fn default_hosts() -> Vec<String> {
  vec!["*".to_string()]
}

fn default_path_prefix() -> String {
  "/".to_string()
}

fn default_connect_timeout_ms() -> u64 {
  3_000
}

fn default_request_timeout_ms() -> u64 {
  30_000
}

fn default_proxy_max_http_version() -> HttpVersion {
  HttpVersion::H2
}

fn default_quic_alt_svc_max_age_seconds() -> u64 {
  86_400
}

fn default_quic_max_concurrent_streams() -> u64 {
  100
}

fn default_quic_idle_timeout_ms() -> u64 {
  30_000
}

fn default_quic_datagram_buffer_bytes() -> usize {
  1024 * 1024
}

fn default_quic_max_udp_payload_size() -> u16 {
  1472
}

fn default_quic_upstream_pool_max_connections() -> usize {
  1
}

fn default_quic_upstream_pool_max_lifetime_ms() -> u64 {
  600_000
}

fn default_compression_min_size_bytes() -> u64 {
  1_024
}

fn default_compression_statuses() -> Vec<u16> {
  vec![200]
}

fn default_compression_mime_types() -> Vec<String> {
  [
    "text/*",
    "application/json",
    "application/*+json",
    "application/javascript",
    "application/xml",
    "application/*+xml",
    "image/svg+xml",
  ]
  .into_iter()
  .map(str::to_string)
  .collect()
}

fn default_client_header_timeout_ms() -> u64 {
  10_000
}

fn default_client_body_timeout_ms() -> u64 {
  30_000
}

fn default_client_idle_timeout_ms() -> u64 {
  75_000
}

fn default_tls_handshake_timeout_ms() -> u64 {
  10_000
}

fn default_response_send_timeout_ms() -> u64 {
  60_000
}

fn default_max_headers() -> usize {
  128
}

fn default_max_header_name_bytes() -> usize {
  128
}

fn default_max_header_value_bytes() -> usize {
  8_192
}

fn default_max_total_header_bytes() -> usize {
  65_536
}

fn default_max_uri_bytes() -> usize {
  8_192
}

fn default_max_request_body_bytes() -> u64 {
  10_485_760
}

fn default_retry_tries() -> usize {
  2
}

fn default_retry_timeout_ms() -> u64 {
  5_000
}

fn default_retry_on() -> Vec<RetryCondition> {
  vec![
    RetryCondition::ConnectError,
    RetryCondition::ReadTimeout,
    RetryCondition::Status502,
    RetryCondition::Status503,
    RetryCondition::Status504,
  ]
}

fn default_buffering_max_memory_body_bytes() -> usize {
  1_048_576
}

fn default_rate_limit_status() -> u16 {
  429
}

fn default_connection_limit_status() -> u16 {
  429
}

fn default_cache_max_size_bytes() -> usize {
  1_073_741_824
}

fn default_cache_memory_auto_fraction() -> f64 {
  0.5
}

fn default_cache_default_ttl_seconds() -> u64 {
  60
}

fn default_cache_methods() -> Vec<String> {
  vec!["GET".to_string(), "HEAD".to_string()]
}

fn default_cache_key() -> String {
  "{scheme}:{host}:{uri}".to_string()
}

fn default_cache_tag_headers() -> Vec<String> {
  vec!["Surrogate-Key".to_string(), "Cache-Tag".to_string()]
}

fn default_cache_max_tags_per_entry() -> usize {
  32
}

fn default_cache_max_tag_bytes() -> usize {
  128
}

fn default_cache_max_vary_fields() -> usize {
  8
}

fn default_cache_max_vary_variants_per_key() -> usize {
  64
}

fn default_cache_bypass_request_headers() -> Vec<String> {
  vec![
    "Authorization".to_string(),
    "Cookie".to_string(),
    "Proxy-Authorization".to_string(),
  ]
}

fn default_cache_stream_chunk_bytes() -> usize {
  1_048_576
}

fn default_cache_background_refresh_max_concurrent() -> usize {
  16
}

fn default_cache_lock_wait_timeout_ms() -> u64 {
  10_000
}

fn default_cache_admission_statuses() -> Vec<u16> {
  vec![200, 203, 204, 301, 308]
}

fn default_cache_admission_min_hits() -> usize {
  1
}

fn default_cache_admission_max_tracked_keys() -> usize {
  16_384
}

pub(crate) fn default_cache_tmpfs_dir() -> PathBuf {
  PathBuf::from("/dev/shm/oxibelt-cache")
}

fn default_admin_bind() -> SocketAddr {
  "127.0.0.1:9092".parse().expect("valid admin bind default")
}

fn default_admin_bearer_token_env() -> String {
  "OXIBELT_ADMIN_TOKEN".to_string()
}

fn default_cache_purge_signing_key_env() -> String {
  "OXIBELT_CACHE_PURGE_HMAC_KEY".to_string()
}

fn default_cache_purge_signing_max_skew_seconds() -> u64 {
  300
}

fn default_cache_purge_signing_nonce_ttl_seconds() -> u64 {
  600
}

fn default_admin_plaintext_allowed_source_cidrs() -> Vec<String> {
  vec!["127.0.0.0/8".to_string(), "::1/128".to_string()]
}

fn default_metrics_bind() -> SocketAddr {
  "127.0.0.1:9090"
    .parse()
    .expect("valid metrics bind default")
}

fn default_health_bind() -> SocketAddr {
  "127.0.0.1:9091".parse().expect("valid health bind default")
}

fn default_ready_path() -> String {
  "/ready".to_string()
}

fn default_live_path() -> String {
  "/live".to_string()
}

fn default_hsts_max_age_seconds() -> u64 {
  31_536_000
}

fn default_pool_keepalive_max_idle() -> usize {
  32
}

fn default_pool_keepalive_max_lifetime_ms() -> u64 {
  3_600_000
}

fn default_pool_server_weight() -> u32 {
  1
}

fn default_discovery_refresh_interval_ms() -> u64 {
  30_000
}

fn default_discovery_min_ttl_ms() -> u64 {
  1_000
}

fn default_health_check_path() -> String {
  "/healthz".to_string()
}

fn default_health_check_interval_ms() -> u64 {
  5_000
}

fn default_health_check_timeout_ms() -> u64 {
  1_000
}

fn default_health_check_healthy_threshold() -> u32 {
  2
}

fn default_health_check_unhealthy_threshold() -> u32 {
  3
}

fn default_health_check_expected_status() -> Vec<u16> {
  vec![200, 204]
}

fn default_grpc_health_expected_statuses() -> Vec<GrpcHealthServingStatus> {
  vec![GrpcHealthServingStatus::Serving]
}

fn default_database_access_log_max_connections() -> u32 {
  4
}

fn default_database_access_log_connect_timeout_ms() -> u64 {
  3_000
}

fn default_database_access_log_queue_capacity() -> usize {
  1024
}

fn default_shared_state_namespace() -> String {
  "oxibelt".to_string()
}

fn default_shared_state_instance_id_env() -> String {
  "OXIBELT_INSTANCE_ID".to_string()
}

fn default_shared_state_operation_timeout_ms() -> u64 {
  500
}

fn default_shared_state_connection_lease_ms() -> u64 {
  120_000
}

fn default_shared_state_cache_lock_ms() -> u64 {
  10_000
}

fn default_shared_state_max_connections() -> u32 {
  4
}
