//! Shared-state backend configuration and Redis pool tuning.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use url::Url;

use super::{
  DatabaseTlsConfig, DatabaseTlsMode, default_database_postgres_connect_timeout_ms,
  validate_optional_non_empty,
};

mod redis_security;

pub use redis_security::{RedisAuthConfig, RedisPlaintextPolicy, RedisTlsConfig, RedisTrustStore};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SharedStateConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_shared_state_namespace")]
  pub namespace: String,
  #[serde(default)]
  pub redis_plaintext_policy: RedisPlaintextPolicy,
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
  pub sticky_sessions_backend: Option<String>,
  #[serde(default)]
  pub cache_backend: Option<String>,
  #[serde(default)]
  pub reload_backend: Option<String>,
  #[serde(default)]
  pub dynamic_policy_backend: Option<String>,
  #[serde(default, rename = "admin_tokens_backend")]
  legacy_admin_tokens_backend: Option<String>,
  #[serde(default)]
  pub backends: Vec<SharedStateBackendConfig>,
}

impl Default for SharedStateConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      namespace: default_shared_state_namespace(),
      redis_plaintext_policy: RedisPlaintextPolicy::default(),
      instance_id_env: default_shared_state_instance_id_env(),
      default_backend: None,
      operation_timeout_ms: default_shared_state_operation_timeout_ms(),
      connection_lease_ms: default_shared_state_connection_lease_ms(),
      cache_lock_ms: default_shared_state_cache_lock_ms(),
      rate_limits_backend: None,
      connection_limits_backend: None,
      person_proof_backend: None,
      upstream_health_backend: None,
      sticky_sessions_backend: None,
      cache_backend: None,
      reload_backend: None,
      dynamic_policy_backend: None,
      legacy_admin_tokens_backend: None,
      backends: Vec::new(),
    }
  }
}

impl SharedStateConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    if !self.enabled {
      return Ok(());
    }
    validate_optional_non_empty("shared_state.namespace", Some(&self.namespace))?;
    validate_shared_state_namespace(&self.namespace)?;
    validate_optional_non_empty("shared_state.instance_id_env", Some(&self.instance_id_env))?;
    if self.operation_timeout_ms == 0 || self.connection_lease_ms == 0 || self.cache_lock_ms == 0 {
      bail!("shared_state timeout and lease values must be greater than 0");
    }
    if self.backends.is_empty() {
      bail!("shared_state.backends must include at least one backend when enabled=true");
    }
    if self.legacy_admin_tokens_backend.is_some() {
      bail!("shared_state.admin_tokens_backend is legacy Admin token syntax; use ipm.backend");
    }
    let mut names = HashSet::new();
    for backend in &self.backends {
      backend.validate(self.operation_timeout_ms, self.redis_plaintext_policy)?;
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
      (
        "shared_state.sticky_sessions_backend",
        self.sticky_sessions_backend.as_deref(),
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
  #[serde(default = "default_database_postgres_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default)]
  pub redis_pool: Option<RedisPoolConfig>,
  #[serde(default)]
  pub redis_tls: RedisTlsConfig,
  #[serde(default)]
  pub redis_auth: RedisAuthConfig,
  #[serde(default)]
  pub tls: DatabaseTlsConfig,
}

impl SharedStateBackendConfig {
  fn validate(
    &self,
    operation_timeout_ms: u64,
    redis_plaintext_policy: RedisPlaintextPolicy,
  ) -> anyhow::Result<()> {
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
    if self.kind == SharedStateBackendKind::Redis {
      if self.tls.ca_cert.is_some()
        || self.tls.client_cert.is_some()
        || self.tls.client_key.is_some()
        || self.tls.mode != DatabaseTlsMode::Off
      {
        bail!(
          "shared_state Redis backend {} does not support tls settings",
          self.name
        );
      }
      self
        .redis_tls
        .validate(&format!("shared_state.backends.{}.redis_tls", self.name))?;
      self
        .redis_auth
        .validate(&format!("shared_state.backends.{}.redis_auth", self.name))?;
      if let Some(connection_url) = self.connection_url.as_deref() {
        validate_redis_connection_url(
          connection_url,
          &self.name,
          redis_plaintext_policy,
          &self.redis_tls,
          &self.redis_auth,
        )?;
      }
      let _ = self.redis_pool_settings(operation_timeout_ms)?;
    } else {
      if self.redis_pool.is_some() {
        bail!(
          "shared_state PostgreSQL backend {} does not support redis_pool settings",
          self.name
        );
      }
      if self.redis_tls.is_configured() {
        bail!(
          "shared_state PostgreSQL backend {} does not support redis_tls settings",
          self.name
        );
      }
      if self.redis_auth.is_configured() {
        bail!(
          "shared_state PostgreSQL backend {} does not support redis_auth settings",
          self.name
        );
      }
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

  pub(crate) fn redis_pool_settings(
    &self,
    operation_timeout_ms: u64,
  ) -> anyhow::Result<RedisPoolSettings> {
    if self.kind != SharedStateBackendKind::Redis {
      bail!("shared_state backend {} is not Redis", self.name);
    }
    self.redis_pool.clone().unwrap_or_default().resolve(
      self.max_connections,
      operation_timeout_ms,
      &self.name,
    )
  }
}

pub(crate) fn validate_redis_connection_url(
  connection_url: &str,
  backend_name: &str,
  plaintext_policy: RedisPlaintextPolicy,
  redis_tls: &RedisTlsConfig,
  redis_auth: &RedisAuthConfig,
) -> anyhow::Result<()> {
  let url = Url::parse(connection_url)
    .with_context(|| format!("failed to parse shared_state Redis URL {backend_name}"))?;
  if url.scheme() != "redis" && url.scheme() != "rediss" {
    bail!("shared_state Redis backend {backend_name} must use redis:// or rediss://");
  }
  if url.query().is_some() || url.fragment().is_some() {
    bail!("shared_state Redis backend {backend_name} URL must not include a query or fragment");
  }
  if url.host_str().is_none_or(str::is_empty) {
    bail!("shared_state Redis backend {backend_name} URL is missing host");
  }
  let has_url_username = !url.username().is_empty();
  let has_url_password = url.password().is_some_and(|password| !password.is_empty());
  if has_url_username && !has_url_password {
    bail!("shared_state Redis backend {backend_name} URL username requires a password");
  }
  if (has_url_username || has_url_password) && redis_auth.is_configured() {
    bail!(
      "shared_state Redis backend {backend_name} must not combine URL credentials with redis_auth files"
    );
  }
  match url.scheme() {
    "redis" => {
      if redis_tls.is_configured() {
        bail!(
          "shared_state Redis backend {backend_name} redis_tls settings require a rediss:// URL"
        );
      }
      plaintext_policy.validate_url_host(url.host_str().unwrap_or_default(), backend_name)?;
    }
    "rediss" => {}
    _ => {}
  }
  match url.path() {
    "" | "/" => Ok(()),
    path
      if path.strip_prefix('/').is_some_and(|database| {
        !database.is_empty() && !database.contains('/') && database.parse::<u32>().is_ok()
      }) =>
    {
      Ok(())
    }
    _ => {
      bail!("shared_state Redis backend {backend_name} URL database must be an unsigned integer")
    }
  }
}

fn validate_shared_state_namespace(namespace: &str) -> anyhow::Result<()> {
  if namespace.len() > 128
    || namespace.starts_with(':')
    || namespace.ends_with(':')
    || !namespace
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
  {
    bail!(
      "shared_state.namespace must be 1-128 ASCII letters, digits, '.', '_', '-', or ':' and must not start or end with ':'"
    );
  }
  Ok(())
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SharedStateBackendKind {
  Redis,
  Postgres,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RedisPoolConfig {
  #[serde(default)]
  pub min_idle_connections: u32,
  #[serde(default)]
  pub max_waiters: Option<u32>,
  #[serde(default)]
  pub pool_wait_timeout_ms: Option<u64>,
  #[serde(default)]
  pub command_timeout_ms: Option<u64>,
  #[serde(default = "default_redis_pool_idle_timeout_ms")]
  pub idle_timeout_ms: u64,
  #[serde(default = "default_redis_pool_health_check_interval_ms")]
  pub health_check_interval_ms: u64,
  #[serde(default = "default_redis_pool_reconnect_min_backoff_ms")]
  pub reconnect_min_backoff_ms: u64,
  #[serde(default = "default_redis_pool_reconnect_max_backoff_ms")]
  pub reconnect_max_backoff_ms: u64,
  #[serde(default = "default_redis_pool_circuit_breaker_failure_threshold")]
  pub circuit_breaker_failure_threshold: u32,
  #[serde(default = "default_redis_pool_circuit_breaker_open_timeout_ms")]
  pub circuit_breaker_open_timeout_ms: u64,
}

impl Default for RedisPoolConfig {
  fn default() -> Self {
    Self {
      min_idle_connections: 0,
      max_waiters: None,
      pool_wait_timeout_ms: None,
      command_timeout_ms: None,
      idle_timeout_ms: default_redis_pool_idle_timeout_ms(),
      health_check_interval_ms: default_redis_pool_health_check_interval_ms(),
      reconnect_min_backoff_ms: default_redis_pool_reconnect_min_backoff_ms(),
      reconnect_max_backoff_ms: default_redis_pool_reconnect_max_backoff_ms(),
      circuit_breaker_failure_threshold: default_redis_pool_circuit_breaker_failure_threshold(),
      circuit_breaker_open_timeout_ms: default_redis_pool_circuit_breaker_open_timeout_ms(),
    }
  }
}

impl RedisPoolConfig {
  fn resolve(
    self,
    max_connections: u32,
    operation_timeout_ms: u64,
    backend_name: &str,
  ) -> anyhow::Result<RedisPoolSettings> {
    let max_waiters = self
      .max_waiters
      .unwrap_or_else(|| max_connections.saturating_mul(4));
    let pool_wait_timeout_ms = self.pool_wait_timeout_ms.unwrap_or(operation_timeout_ms);
    let command_timeout_ms = self.command_timeout_ms.unwrap_or(operation_timeout_ms);
    if self.min_idle_connections > max_connections {
      bail!(
        "shared_state Redis backend {backend_name} redis_pool.min_idle_connections must not exceed max_connections"
      );
    }
    if pool_wait_timeout_ms == 0
      || command_timeout_ms == 0
      || self.idle_timeout_ms == 0
      || self.health_check_interval_ms == 0
      || self.reconnect_min_backoff_ms == 0
      || self.reconnect_max_backoff_ms == 0
      || self.circuit_breaker_failure_threshold == 0
      || self.circuit_breaker_open_timeout_ms == 0
    {
      bail!("shared_state Redis backend {backend_name} redis_pool values must be greater than 0");
    }
    if pool_wait_timeout_ms > operation_timeout_ms || command_timeout_ms > operation_timeout_ms {
      bail!(
        "shared_state Redis backend {backend_name} redis_pool timeouts must not exceed shared_state.operation_timeout_ms"
      );
    }
    if self.health_check_interval_ms > self.idle_timeout_ms {
      bail!(
        "shared_state Redis backend {backend_name} redis_pool.health_check_interval_ms must not exceed idle_timeout_ms"
      );
    }
    if self.reconnect_min_backoff_ms > self.reconnect_max_backoff_ms {
      bail!(
        "shared_state Redis backend {backend_name} redis_pool.reconnect_min_backoff_ms must not exceed reconnect_max_backoff_ms"
      );
    }
    let max_connections = usize::try_from(max_connections).map_err(|_| {
      anyhow!("shared_state Redis backend {backend_name} max_connections is too large")
    })?;
    let max_waiters = usize::try_from(max_waiters)
      .map_err(|_| anyhow!("shared_state Redis backend {backend_name} max_waiters is too large"))?;
    let _ = max_connections.checked_add(max_waiters).ok_or_else(|| {
      anyhow!("shared_state Redis backend {backend_name} connection and waiter limits overflow")
    })?;
    Ok(RedisPoolSettings {
      min_idle_connections: self.min_idle_connections as usize,
      max_waiters,
      pool_wait_timeout: Duration::from_millis(pool_wait_timeout_ms),
      command_timeout: Duration::from_millis(command_timeout_ms),
      idle_timeout: Duration::from_millis(self.idle_timeout_ms),
      health_check_interval: Duration::from_millis(self.health_check_interval_ms),
      reconnect_min_backoff: Duration::from_millis(self.reconnect_min_backoff_ms),
      reconnect_max_backoff: Duration::from_millis(self.reconnect_max_backoff_ms),
      circuit_breaker_failure_threshold: self.circuit_breaker_failure_threshold,
      circuit_breaker_open_timeout: Duration::from_millis(self.circuit_breaker_open_timeout_ms),
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedisPoolSettings {
  pub(crate) min_idle_connections: usize,
  pub(crate) max_waiters: usize,
  pub(crate) pool_wait_timeout: Duration,
  pub(crate) command_timeout: Duration,
  pub(crate) idle_timeout: Duration,
  pub(crate) health_check_interval: Duration,
  pub(crate) reconnect_min_backoff: Duration,
  pub(crate) reconnect_max_backoff: Duration,
  pub(crate) circuit_breaker_failure_threshold: u32,
  pub(crate) circuit_breaker_open_timeout: Duration,
}

pub(crate) fn default_shared_state_namespace() -> String {
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

fn default_redis_pool_idle_timeout_ms() -> u64 {
  60_000
}

fn default_redis_pool_health_check_interval_ms() -> u64 {
  15_000
}

fn default_redis_pool_reconnect_min_backoff_ms() -> u64 {
  50
}

fn default_redis_pool_reconnect_max_backoff_ms() -> u64 {
  5_000
}

fn default_redis_pool_circuit_breaker_failure_threshold() -> u32 {
  5
}

fn default_redis_pool_circuit_breaker_open_timeout_ms() -> u64 {
  1_000
}
