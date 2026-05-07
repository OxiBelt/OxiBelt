use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use url::Url;

use crate::waf::{AccessLogFieldConfig, RouteWafConfig, WafConfig};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Config {
  #[serde(default)]
  pub config: ConfigBehaviorConfig,
  #[serde(default)]
  pub logging: LoggingConfig,
  #[serde(default)]
  pub runtime: RuntimeConfig,
  pub listeners: ListenerConfig,
  pub tls: TlsConfig,
  #[serde(default)]
  pub quic: QuicConfig,
  #[serde(default)]
  pub proxy: ProxyConfig,
  #[serde(default)]
  pub limits: LimitsConfig,
  #[serde(default)]
  pub rate_limits: Vec<RateLimitConfig>,
  #[serde(default)]
  pub connection_limits: Vec<ConnectionLimitConfig>,
  #[serde(default)]
  pub compression: CompressionConfig,
  #[serde(default)]
  pub cache: CacheConfig,
  #[serde(default)]
  pub metrics: MetricsConfig,
  #[serde(default)]
  pub health: HealthConfig,
  #[serde(default)]
  pub security: SecurityConfig,
  #[serde(default)]
  pub database: DatabaseConfig,
  #[serde(default)]
  pub upstreams: Vec<UpstreamConfig>,
  #[serde(default)]
  pub upstream_pools: Vec<UpstreamPoolConfig>,
  #[serde(default)]
  pub stream_listeners: Vec<StreamListenerConfig>,
  #[serde(default)]
  pub routes: Vec<RouteConfig>,
  #[serde(default)]
  pub waf: WafConfig,
  #[serde(skip)]
  pub source_paths: ConfigSourcePaths,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConfigSourcePaths {
  pub config_entry: Option<PathBuf>,
  pub cert_dir: Option<PathBuf>,
  pub config_files: Vec<PathBuf>,
  pub runtime_files: Vec<PathBuf>,
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
    redact_effective_toml(&mut value);
    Ok(value)
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
      && self.metrics == other.metrics
      && self.health == other.health
      && self.security == other.security
      && self.database == other.database
      && self.upstreams == other.upstreams
      && self.upstream_pools == other.upstream_pools
      && self.stream_listeners == other.stream_listeners
      && routes_without_waf_are_equivalent(&self.routes, &other.routes)
  }

  pub fn waf_equivalent(&self, other: &Self) -> bool {
    self.waf == other.waf && route_waf_configs_are_equivalent(&self.routes, &other.routes)
  }

  fn resolve_relative_paths(&mut self, path_roots: &ConfigPathRoots) -> anyhow::Result<()> {
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

    let (tls_private_key, tls_private_key_logical) =
      resolve_existing_local_config_file_path_with_logical(
        "tls.private_key",
        &path_roots.cert_dir,
        &self.tls.private_key,
      )?;
    self.tls.private_key = tls_private_key;
    self
      .source_paths
      .remember_runtime_file(tls_private_key_logical.clone());
    self
      .source_paths
      .remember_downstream_tls_file(tls_private_key_logical.clone());
    self.source_paths.downstream_tls_private_key = Some(tls_private_key_logical);

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
    self.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    for route in &mut self.routes {
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

    self.runtime.hot_reload.validate()?;
    self.validate_limits()?;
    self.validate_proxy()?;
    self.validate_compression()?;
    self.validate_cache()?;
    self.validate_metrics_and_health()?;
    self.validate_security_headers()?;
    self.validate_tls()?;
    self.quic.validate()?;
    self.logging.validate()?;

    if self.runtime.linux_only && !cfg!(target_os = "linux") {
      bail!("this build is configured for Linux only");
    }

    if !self.routes.is_empty() && self.upstreams.is_empty() && self.upstream_pools.is_empty() {
      bail!("at least one upstream or upstream pool must be configured");
    }

    if self.routes.is_empty() && self.stream_listeners.is_empty() {
      bail!("at least one route must be configured");
    }

    self.database.validate()?;

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
      if pool.servers.is_empty() {
        bail!(
          "upstream pool {} must define at least one server",
          pool.name
        );
      }
      for server in &pool.servers {
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
      match (&route.upstream, &route.upstream_pool) {
        (Some(upstream), None) => {
          if !upstream_names.contains(upstream) {
            bail!(
              "route {} references unknown upstream {}",
              route.name,
              upstream
            );
          }
        }
        (None, Some(pool)) => {
          if !pool_names.contains(pool) {
            bail!(
              "route {} references unknown upstream_pool {}",
              route.name,
              pool
            );
          }
        }
        (Some(_), Some(_)) => {
          bail!(
            "route {} must set exactly one of upstream or upstream_pool, not both",
            route.name
          );
        }
        (None, None) => {
          bail!(
            "route {} must set exactly one of upstream or upstream_pool",
            route.name
          );
        }
      }
      if let Some(cache) = &route.cache
        && cache != "default"
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
    }

    self.validate_stream_listeners()?;

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
      || self.limits.max_requests_per_connection == 0
      || self.limits.client_header_timeout_ms == 0
      || self.limits.client_body_timeout_ms == 0
      || self.limits.client_idle_timeout_ms == 0
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
      http::StatusCode::from_u16(rate_limit.status)
        .with_context(|| format!("rate limit {} has invalid status", rate_limit.name))?;
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

  fn validate_proxy(&self) -> anyhow::Result<()> {
    if self.proxy.http.early_hints == EarlyHintsMode::Pass {
      bail!("proxy.http.early_hints = \"pass\" is reserved but not implemented yet");
    }
    if self.proxy.retry.tries == 0 {
      bail!("proxy.retry.tries must be greater than 0");
    }
    if self.proxy.retry.timeout_ms == 0 {
      bail!("proxy.retry.timeout_ms must be greater than 0");
    }
    if self.proxy.buffering.max_temp_file_bytes != 0 {
      bail!("proxy.buffering.max_temp_file_bytes must be 0; disk buffering is not implemented");
    }
    for cidr in &self.proxy.real_ip.trusted_proxies {
      crate::identity::Cidr::parse(cidr)
        .with_context(|| format!("invalid proxy.real_ip.trusted_proxies entry {cidr}"))?;
    }
    Ok(())
  }

  fn validate_stream_listeners(&self) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    let mut binds = HashSet::new();
    for listener in &self.stream_listeners {
      if listener.name.trim().is_empty() {
        bail!("stream listener name must not be empty");
      }
      if !names.insert(listener.name.clone()) {
        bail!("duplicate stream listener name: {}", listener.name);
      }
      if !binds.insert(listener.bind) {
        bail!(
          "duplicate stream listener bind {} on listener {}",
          listener.bind,
          listener.name
        );
      }
      if listener.connect_timeout_ms == 0 || listener.idle_timeout_ms == 0 {
        bail!(
          "stream listener {} timeout values must be greater than 0",
          listener.name
        );
      }
      validate_stream_target(&listener.name, &listener.target)?;
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

fn validate_stream_target(listener_name: &str, target: &str) -> anyhow::Result<()> {
  let (host, port) = parse_stream_target(target)
    .with_context(|| format!("stream listener {listener_name} target must be in host:port form"))?;
  if host.trim().is_empty() {
    bail!("stream listener {listener_name} target host must not be empty");
  }
  if port == 0 {
    bail!("stream listener {listener_name} target port must be greater than 0");
  }
  Ok(())
}

pub fn parse_stream_target(target: &str) -> anyhow::Result<(String, u16)> {
  if let Some(stripped) = target.strip_prefix('[') {
    let Some(end) = stripped.find(']') else {
      bail!("missing closing ']' in IPv6 stream target");
    };
    let host = stripped[..end].to_string();
    let port = stripped
      .get(end + 1..)
      .and_then(|rest| rest.strip_prefix(':'))
      .ok_or_else(|| anyhow!("missing port in stream target"))?
      .parse::<u16>()
      .context("invalid stream target port")?;
    return Ok((host, port));
  }

  let (host, port) = target
    .rsplit_once(':')
    .ok_or_else(|| anyhow!("missing port in stream target"))?;
  if host.contains(':') {
    bail!("IPv6 stream targets must use [addr]:port form");
  }
  Ok((
    host.to_string(),
    port.parse::<u16>().context("invalid stream target port")?,
  ))
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

fn routes_without_waf_are_equivalent(left: &[RouteConfig], right: &[RouteConfig]) -> bool {
  left.len() == right.len()
    && left.iter().zip(right).all(|(left, right)| {
      left.name == right.name
        && left.hosts == right.hosts
        && left.path_prefix == right.path_prefix
        && left.replace_prefix_with == right.replace_prefix_with
        && left.upstream == right.upstream
        && left.upstream_pool == right.upstream_pool
        && left.upstream_http_version == right.upstream_http_version
        && left.generic_http_upgrade == right.generic_http_upgrade
        && left.connect_tunneling == right.connect_tunneling
        && left.grpc_web == right.grpc_web
        && left.cache == right.cache
        && left.compression == right.compression
    })
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
      "cache",
      "compression",
      "config",
      "connection_limits",
      "database",
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
      "stream_listeners",
      "tls",
      "upstream_pools",
      "upstreams",
      "waf",
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
      "hot_reload",
      "linux_only",
      "memory_only_state",
      "read_only_rootfs_compatible",
      "unprivileged_mode",
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
      "session_ticket_rotation_seconds",
      "session_tickets",
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
    "quic.socket" => &["receive_buffer_bytes", "send_buffer_bytes"][..],
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
    ][..],
    "proxy.http" => &["early_hints", "trailers"][..],
    "limits" => &[
      "client_body_timeout_ms",
      "client_header_timeout_ms",
      "client_idle_timeout_ms",
      "max_connections",
      "max_connections_per_ip",
      "max_header_name_bytes",
      "max_header_value_bytes",
      "max_headers",
      "max_request_body_bytes",
      "max_requests_per_connection",
      "max_total_header_bytes",
      "max_uri_bytes",
      "response_send_timeout_ms",
      "tls_handshake_timeout_ms",
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
      "cache_key",
      "cache_methods",
      "default_ttl_seconds",
      "enabled",
      "lock",
      "max_size_bytes",
      "respect_cache_control",
      "stale_if_error_seconds",
      "store",
      "tmpfs_dir",
    ][..],
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
    "upstreams" => &[
      "connect_timeout_ms",
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
      "hash_key",
      "health_check",
      "keepalive",
      "name",
      "servers",
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
    "upstream_pools.servers" => &["backup", "max_conns", "origin", "weight"][..],
    "routes" => &[
      "cache",
      "compression",
      "hosts",
      "name",
      "path_prefix",
      "replace_prefix_with",
      "connect_tunneling",
      "generic_http_upgrade",
      "grpc_web",
      "upstream",
      "upstream_http_version",
      "upstream_pool",
      "waf",
    ][..],
    "stream_listeners" => &[
      "bind",
      "connect_timeout_ms",
      "idle_timeout_ms",
      "name",
      "proxy_protocol_egress",
      "target",
    ][..],
    "rate_limits" => &["burst", "key", "mode", "name", "rate", "status"][..],
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
  cert_dir: PathBuf,
  oxirule_dir: PathBuf,
}

fn config_path_roots(path: &Path) -> anyhow::Result<ConfigPathRoots> {
  let config_dir = config_base_dir(path)?;
  let layout_root = config_dir.parent().unwrap_or_else(|| Path::new("."));

  Ok(ConfigPathRoots {
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
pub struct RuntimeConfig {
  #[serde(default = "default_true")]
  pub linux_only: bool,
  #[serde(default = "default_true")]
  pub read_only_rootfs_compatible: bool,
  #[serde(default = "default_true")]
  pub memory_only_state: bool,
  #[serde(default = "default_true")]
  pub unprivileged_mode: bool,
  #[serde(default)]
  pub hot_reload: HotReloadConfig,
}

impl Default for RuntimeConfig {
  fn default() -> Self {
    Self {
      linux_only: true,
      read_only_rootfs_compatible: true,
      memory_only_state: true,
      unprivileged_mode: true,
      hot_reload: HotReloadConfig::default(),
    }
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsConfig {
  pub cert_chain: PathBuf,
  pub private_key: PathBuf,
  #[serde(default = "default_tls_min_version")]
  pub min_version: TlsVersion,
  #[serde(default = "default_tls_max_version")]
  pub max_version: TlsVersion,
  #[serde(default = "default_true")]
  pub session_tickets: bool,
  #[serde(default = "default_session_ticket_rotation_seconds")]
  pub session_ticket_rotation_seconds: u64,
  #[serde(default)]
  pub client_auth: TlsClientAuthConfig,
  #[serde(default)]
  pub ocsp: OcspConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
  #[serde(rename = "tls1.2")]
  Tls12,
  #[serde(rename = "tls1.3")]
  Tls13,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TlsClientAuthConfig {
  #[serde(default)]
  pub mode: TlsClientAuthMode,
  #[serde(default)]
  pub ca_certs: Vec<PathBuf>,
  #[serde(default = "default_tls_client_auth_verify_depth")]
  pub verify_depth: u8,
}

impl Default for TlsClientAuthConfig {
  fn default() -> Self {
    Self {
      mode: TlsClientAuthMode::Off,
      ca_certs: Vec::new(),
      verify_depth: default_tls_client_auth_verify_depth(),
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TlsClientAuthMode {
  #[default]
  Off,
  Optional,
  Require,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OcspConfig {
  #[serde(default)]
  pub mode: OcspMode,
  #[serde(default)]
  pub response_file: Option<PathBuf>,
}

impl Default for OcspConfig {
  fn default() -> Self {
    Self {
      mode: OcspMode::Disabled,
      response_file: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OcspMode {
  #[default]
  Disabled,
  StaticFile,
  LiveFetch,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct QuicConfig {
  #[serde(default)]
  pub retry: bool,
  #[serde(default)]
  pub zero_rtt: QuicZeroRttMode,
  #[serde(default)]
  pub host_key_file: Option<PathBuf>,
  #[serde(default)]
  pub alt_svc: QuicAltSvcConfig,
  #[serde(default)]
  pub transport: QuicTransportConfig,
  #[serde(default)]
  pub socket: QuicSocketConfig,
  #[serde(default)]
  pub upstream_pool: QuicUpstreamPoolConfig,
}

impl Default for QuicConfig {
  fn default() -> Self {
    Self {
      retry: false,
      zero_rtt: QuicZeroRttMode::Off,
      host_key_file: None,
      alt_svc: QuicAltSvcConfig::default(),
      transport: QuicTransportConfig::default(),
      socket: QuicSocketConfig::default(),
      upstream_pool: QuicUpstreamPoolConfig::default(),
    }
  }
}

impl QuicConfig {
  pub fn validate(&self) -> anyhow::Result<()> {
    if self.alt_svc.max_age_seconds == 0 {
      bail!("quic.alt_svc.max_age_seconds must be greater than 0");
    }
    if self.transport.max_concurrent_bidi_streams == 0
      || self.transport.max_concurrent_uni_streams == 0
      || self.transport.idle_timeout_ms == 0
      || self.transport.datagram_receive_buffer_bytes == 0
      || self.transport.datagram_send_buffer_bytes == 0
    {
      bail!("quic.transport numeric values must be greater than 0");
    }
    if !(1200..=65_527).contains(&self.transport.max_udp_payload_size) {
      bail!("quic.transport.max_udp_payload_size must be between 1200 and 65527");
    }
    if self.upstream_pool.max_connections_per_upstream == 0 {
      bail!("quic.upstream_pool.max_connections_per_upstream must be greater than 0");
    }
    if self.upstream_pool.max_lifetime_ms == 0 {
      bail!("quic.upstream_pool.max_lifetime_ms must be greater than 0");
    }
    Ok(())
  }
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

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct QuicSocketConfig {
  #[serde(default)]
  pub receive_buffer_bytes: usize,
  #[serde(default)]
  pub send_buffer_bytes: usize,
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
}

impl Default for ProxyBufferingConfig {
  fn default() -> Self {
    Self {
      request: BufferingMode::Streaming,
      response: BufferingMode::Streaming,
      max_memory_body_bytes: default_buffering_max_memory_body_bytes(),
      max_temp_file_bytes: 0,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BufferingMode {
  #[default]
  Streaming,
  Memory,
  RejectIfTooLarge,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct ProxyHttpConfig {
  #[serde(default)]
  pub early_hints: EarlyHintsMode,
  #[serde(default)]
  pub trailers: TrailerMode,
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
  #[serde(default = "default_max_requests_per_connection")]
  pub max_requests_per_connection: usize,
  #[serde(default = "default_client_header_timeout_ms")]
  pub client_header_timeout_ms: u64,
  #[serde(default = "default_client_body_timeout_ms")]
  pub client_body_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub client_idle_timeout_ms: u64,
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
      max_requests_per_connection: default_max_requests_per_connection(),
      client_header_timeout_ms: default_client_header_timeout_ms(),
      client_body_timeout_ms: default_client_body_timeout_ms(),
      client_idle_timeout_ms: default_client_idle_timeout_ms(),
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

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RateLimitConfig {
  pub name: String,
  #[serde(default)]
  pub key: LimitKey,
  pub rate: String,
  #[serde(default)]
  pub burst: u32,
  #[serde(default)]
  pub mode: LimitMode,
  #[serde(default = "default_rate_limit_status")]
  pub status: u16,
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
  #[serde(default = "default_cache_max_size_bytes")]
  pub max_size_bytes: usize,
  #[serde(default = "default_cache_default_ttl_seconds")]
  pub default_ttl_seconds: u64,
  #[serde(default = "default_cache_methods")]
  pub cache_methods: Vec<String>,
  #[serde(default = "default_cache_key")]
  pub cache_key: String,
  #[serde(default = "default_true")]
  pub respect_cache_control: bool,
  #[serde(default)]
  pub stale_if_error_seconds: u64,
  #[serde(default = "default_true")]
  pub lock: bool,
}

impl Default for CacheConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      store: CacheStore::Memory,
      tmpfs_dir: None,
      max_size_bytes: default_cache_max_size_bytes(),
      default_ttl_seconds: default_cache_default_ttl_seconds(),
      cache_methods: default_cache_methods(),
      cache_key: default_cache_key(),
      respect_cache_control: true,
      stale_if_error_seconds: 0,
      lock: true,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CacheStore {
  #[default]
  Memory,
  Tmpfs,
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
  pub health_check: UpstreamPoolHealthCheckConfig,
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
  pub origin: Url,
  #[serde(default = "default_pool_server_weight")]
  pub weight: u32,
  #[serde(default)]
  pub max_conns: usize,
  #[serde(default)]
  pub backup: bool,
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
  pub waf: RouteWafConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct StreamListenerConfig {
  pub name: String,
  pub bind: SocketAddr,
  pub target: String,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_client_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default)]
  pub proxy_protocol_egress: ProxyProtocolEgressMode,
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
    ("user_agent", "Request.Headers.get('User-Agent')"),
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

fn default_tls_min_version() -> TlsVersion {
  TlsVersion::Tls13
}

fn default_tls_max_version() -> TlsVersion {
  TlsVersion::Tls13
}

fn default_session_ticket_rotation_seconds() -> u64 {
  86_400
}

fn default_tls_client_auth_verify_depth() -> u8 {
  4
}

fn default_max_connections() -> usize {
  65_536
}

fn default_max_connections_per_ip() -> usize {
  128
}

fn default_max_requests_per_connection() -> usize {
  1_000
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

fn default_cache_default_ttl_seconds() -> u64 {
  60
}

fn default_cache_methods() -> Vec<String> {
  vec!["GET".to_string(), "HEAD".to_string()]
}

fn default_cache_key() -> String {
  "{scheme}:{host}:{uri}".to_string()
}

pub(crate) fn default_cache_tmpfs_dir() -> PathBuf {
  PathBuf::from("/dev/shm/oxibelt-cache")
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
