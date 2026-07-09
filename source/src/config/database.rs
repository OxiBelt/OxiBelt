//! Database configuration validation.
//! Paths and TLS modes are resolved before shared-state or audit stores connect.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

use super::{
  default_database_postgres_connect_timeout_ms, default_database_postgres_max_connections,
  default_shared_state_namespace, quote_postgres_identifier_path,
  resolve_existing_local_config_file_path_with_logical, validate_optional_non_empty,
  validate_postgres_identifier_path,
};

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct DatabaseConfig {
  #[serde(default)]
  pub mitigation: DatabaseMitigationConfig,
}

impl DatabaseConfig {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    self.mitigation.validate()
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseMitigationMode {
  #[default]
  Managed,
  Existing,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MitigationFailurePolicy {
  #[default]
  Open,
  Closed,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DatabaseMitigationConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub mode: DatabaseMitigationMode,
  #[serde(default = "default_database_mitigation_table")]
  pub table: String,
  #[serde(default = "default_shared_state_namespace")]
  pub namespace: String,
  #[serde(default)]
  pub backend: Option<String>,
  #[serde(default)]
  pub connection_url: Option<String>,
  #[serde(default)]
  pub connection_url_env: Option<String>,
  #[serde(default = "default_database_postgres_max_connections")]
  pub max_connections: u32,
  #[serde(default = "default_database_postgres_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_database_mitigation_queue_capacity")]
  pub queue_capacity: usize,
  #[serde(default = "default_database_mitigation_dedupe_window_ms")]
  pub dedupe_window_ms: u64,
  #[serde(default = "default_database_mitigation_ttl_seconds")]
  pub ttl_seconds: u64,
  #[serde(default)]
  pub failure_policy: MitigationFailurePolicy,
  #[serde(default)]
  pub tls: DatabaseTlsConfig,
}

impl Default for DatabaseMitigationConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      mode: DatabaseMitigationMode::Managed,
      table: default_database_mitigation_table(),
      namespace: default_shared_state_namespace(),
      backend: None,
      connection_url: None,
      connection_url_env: None,
      max_connections: default_database_postgres_max_connections(),
      connect_timeout_ms: default_database_postgres_connect_timeout_ms(),
      queue_capacity: default_database_mitigation_queue_capacity(),
      dedupe_window_ms: default_database_mitigation_dedupe_window_ms(),
      ttl_seconds: default_database_mitigation_ttl_seconds(),
      failure_policy: MitigationFailurePolicy::Open,
      tls: DatabaseTlsConfig::default(),
    }
  }
}

impl DatabaseMitigationConfig {
  fn validate(&self) -> anyhow::Result<()> {
    self.validate_with_prefix("database.mitigation")
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
    validate_optional_non_empty(&format!("{prefix}.backend"), self.backend.as_deref())?;
    validate_optional_non_empty(&format!("{prefix}.namespace"), Some(&self.namespace))?;
    validate_postgres_identifier_path(&format!("{prefix}.table"), &self.table)?;
    if self.max_connections == 0 {
      bail!("{prefix}.max_connections must be greater than 0");
    }
    if self.connect_timeout_ms == 0 {
      bail!("{prefix}.connect_timeout_ms must be greater than 0");
    }
    if self.queue_capacity == 0 {
      bail!("{prefix}.queue_capacity must be greater than 0");
    }
    if self.dedupe_window_ms == 0 {
      bail!("{prefix}.dedupe_window_ms must be greater than 0");
    }
    if self.ttl_seconds == 0 {
      bail!("{prefix}.ttl_seconds must be greater than 0");
    }
    self.tls.validate_with_prefix(&format!("{prefix}.tls"))?;

    if !self.enabled {
      return Ok(());
    }

    let direct_sources =
      usize::from(self.connection_url.is_some()) + usize::from(self.connection_url_env.is_some());
    if self.backend.is_some() && direct_sources > 0 {
      bail!("{prefix} must set backend or a direct connection source, not both");
    }
    if self.backend.is_none() && direct_sources == 0 {
      bail!("{prefix} requires backend, connection_url, or connection_url_env when enabled=true");
    }
    if direct_sources > 1 {
      bail!("{prefix} must set only one of connection_url or connection_url_env");
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

  pub(crate) fn table_name_with_prefix(&self, prefix: &str) -> anyhow::Result<String> {
    quote_postgres_identifier_path(&format!("{prefix}.table"), &self.table)
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
  pub(super) fn resolve_relative_paths(
    &mut self,
    prefix: &str,
    base_dir: &Path,
  ) -> anyhow::Result<Vec<PathBuf>> {
    let mut source_paths = Vec::new();
    self.ca_cert = self
      .ca_cert
      .take()
      .map(|path| {
        let (resolved, logical) = resolve_existing_local_config_file_path_with_logical(
          &format!("{prefix}.ca_cert"),
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
          &format!("{prefix}.client_cert"),
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
          &format!("{prefix}.client_key"),
          base_dir,
          &path,
        )?;
        source_paths.push(logical);
        Ok::<PathBuf, anyhow::Error>(resolved)
      })
      .transpose()?;
    Ok(source_paths)
  }

  pub(crate) fn validate_with_prefix(&self, prefix: &str) -> anyhow::Result<()> {
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

fn default_database_mitigation_table() -> String {
  "oxibelt_mitigation_events".to_string()
}

fn default_database_mitigation_queue_capacity() -> usize {
  8192
}

fn default_database_mitigation_dedupe_window_ms() -> u64 {
  60_000
}

fn default_database_mitigation_ttl_seconds() -> u64 {
  300
}
