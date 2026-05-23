use anyhow::{Context, bail};
use base64::Engine;
use serde::Deserialize;

use super::{Config, SharedStateBackendKind, validate_optional_non_empty};

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminRole {
  Viewer,
  CacheOperator,
  UpstreamOperator,
  SecurityOperator,
  ConfigOperator,
  Admin,
}

impl AdminRole {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Viewer => "viewer",
      Self::CacheOperator => "cache_operator",
      Self::UpstreamOperator => "upstream_operator",
      Self::SecurityOperator => "security_operator",
      Self::ConfigOperator => "config_operator",
      Self::Admin => "admin",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum AdminPermission {
  ConfigRead,
  ConfigValidate,
  ConfigDiff,
  ConfigLoad,
  ConfigRollback,
  FilesSyncConfig,
  FilesSyncOxiRule,
  FilesSyncOxiRuleGroup,
  FilesDelete,
  TlsDownstreamRead,
  TlsDownstreamReload,
  AdminTokensRead,
  AdminTokensWrite,
}

impl AdminPermission {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::ConfigRead => "config.read",
      Self::ConfigValidate => "config.validate",
      Self::ConfigDiff => "config.diff",
      Self::ConfigLoad => "config.load",
      Self::ConfigRollback => "config.rollback",
      Self::FilesSyncConfig => "files.sync.config",
      Self::FilesSyncOxiRule => "files.sync.oxirule",
      Self::FilesSyncOxiRuleGroup => "files.sync.oxirule_group",
      Self::FilesDelete => "files.delete",
      Self::TlsDownstreamRead => "tls.downstream.read",
      Self::TlsDownstreamReload => "tls.downstream.reload",
      Self::AdminTokensRead => "admin.tokens.read",
      Self::AdminTokensWrite => "admin.tokens.write",
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct AdminTokenStoreConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub backend: Option<String>,
  #[serde(default = "default_admin_token_store_issuer")]
  pub issuer: String,
  #[serde(default = "default_admin_token_store_audience")]
  pub audience: String,
  #[serde(default = "default_admin_token_store_public_key_env")]
  pub public_key_env: String,
  #[serde(default = "default_admin_token_store_snapshot_refresh_interval_ms")]
  pub snapshot_refresh_interval_ms: u64,
  #[serde(default = "default_admin_token_store_token_ttl_seconds")]
  pub token_ttl_seconds: u64,
  #[serde(default = "default_true")]
  pub fail_closed: bool,
}

impl Default for AdminTokenStoreConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      backend: None,
      issuer: default_admin_token_store_issuer(),
      audience: default_admin_token_store_audience(),
      public_key_env: default_admin_token_store_public_key_env(),
      snapshot_refresh_interval_ms: default_admin_token_store_snapshot_refresh_interval_ms(),
      token_ttl_seconds: default_admin_token_store_token_ttl_seconds(),
      fail_closed: true,
    }
  }
}

impl AdminTokenStoreConfig {
  pub(crate) fn validate_basic(&self) -> anyhow::Result<()> {
    validate_non_empty("admin.token_store.issuer", &self.issuer)?;
    validate_non_empty("admin.token_store.audience", &self.audience)?;
    validate_non_empty("admin.token_store.public_key_env", &self.public_key_env)?;
    if self.snapshot_refresh_interval_ms == 0 {
      bail!("admin.token_store.snapshot_refresh_interval_ms must be greater than 0");
    }
    if self.token_ttl_seconds == 0 {
      bail!("admin.token_store.token_ttl_seconds must be greater than 0");
    }
    if self.enabled {
      self.validate_public_key_env()?;
    }
    Ok(())
  }

  pub(crate) fn validate_public_key_env(&self) -> anyhow::Result<()> {
    let raw = std::env::var(&self.public_key_env).with_context(|| {
      format!(
        "failed to read admin.token_store.public_key_env {}",
        self.public_key_env
      )
    })?;
    decode_public_key(raw.trim()).map(|_| ())
  }
}

impl Config {
  pub(super) fn validate_admin_token_store(&self) -> anyhow::Result<()> {
    let token_store = &self.admin.token_store;
    token_store.validate_basic()?;
    validate_optional_non_empty("admin.token_store.backend", token_store.backend.as_deref())?;
    if !token_store.enabled {
      return Ok(());
    }
    if !self.admin.enabled {
      bail!("admin.token_store.enabled requires admin.enabled = true");
    }
    if !self.shared_state.enabled {
      bail!("admin.token_store.enabled requires shared_state.enabled = true");
    }
    let Some(backend_name) = self.admin_tokens_backend_name() else {
      bail!(
        "admin.token_store.enabled requires admin.token_store.backend, shared_state.admin_tokens_backend, shared_state.default_backend, or at least one shared_state backend"
      );
    };
    let Some(backend) = self
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == backend_name)
    else {
      bail!("admin token store backend references unknown shared_state backend {backend_name}");
    };
    if backend.kind != SharedStateBackendKind::Postgres {
      bail!("admin token store backend {backend_name} must use kind = \"postgres\"");
    }
    Ok(())
  }

  pub(crate) fn admin_tokens_backend_name(&self) -> Option<&str> {
    self
      .admin
      .token_store
      .backend
      .as_deref()
      .or(self.shared_state.admin_tokens_backend.as_deref())
      .or(self.shared_state.default_backend.as_deref())
      .or_else(|| {
        self
          .shared_state
          .backends
          .first()
          .map(|backend| backend.name.as_str())
      })
  }
}

impl std::str::FromStr for AdminRole {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "viewer" => Ok(Self::Viewer),
      "cache_operator" => Ok(Self::CacheOperator),
      "upstream_operator" => Ok(Self::UpstreamOperator),
      "security_operator" => Ok(Self::SecurityOperator),
      "config_operator" => Ok(Self::ConfigOperator),
      "admin" => Ok(Self::Admin),
      _ => bail!("unknown admin role {value}"),
    }
  }
}

impl serde::Serialize for AdminPermission {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}

impl std::str::FromStr for AdminPermission {
  type Err = anyhow::Error;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "config.read" => Ok(Self::ConfigRead),
      "config.validate" => Ok(Self::ConfigValidate),
      "config.diff" => Ok(Self::ConfigDiff),
      "config.load" => Ok(Self::ConfigLoad),
      "config.rollback" => Ok(Self::ConfigRollback),
      "files.sync.config" => Ok(Self::FilesSyncConfig),
      "files.sync.oxirule" => Ok(Self::FilesSyncOxiRule),
      "files.sync.oxirule_group" => Ok(Self::FilesSyncOxiRuleGroup),
      "files.delete" => Ok(Self::FilesDelete),
      "tls.downstream.read" => Ok(Self::TlsDownstreamRead),
      "tls.downstream.reload" => Ok(Self::TlsDownstreamReload),
      "admin.tokens.read" => Ok(Self::AdminTokensRead),
      "admin.tokens.write" => Ok(Self::AdminTokensWrite),
      _ => bail!("unknown admin permission {value}"),
    }
  }
}

impl<'de> Deserialize<'de> for AdminPermission {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let value = String::deserialize(deserializer)?;
    value.parse().map_err(serde::de::Error::custom)
  }
}

pub(crate) fn load_public_key(env_name: &str) -> anyhow::Result<[u8; 32]> {
  let raw = std::env::var(env_name)
    .with_context(|| format!("failed to read admin.token_store.public_key_env {env_name}"))?;
  decode_public_key(raw.trim())
}

fn decode_public_key(raw: &str) -> anyhow::Result<[u8; 32]> {
  let bytes = base64::engine::general_purpose::STANDARD
    .decode(raw)
    .context("admin.token_store.public_key_env must contain base64")?;
  bytes
    .try_into()
    .map_err(|_| anyhow::anyhow!("admin.token_store.public_key_env must contain exactly 32 bytes"))
}

fn validate_non_empty(field: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field} must not be empty");
  }
  Ok(())
}

fn default_admin_token_store_issuer() -> String {
  "oxibelt-admin".to_string()
}

fn default_admin_token_store_audience() -> String {
  "oxibelt-admin-api".to_string()
}

fn default_admin_token_store_public_key_env() -> String {
  "OXIBELT_ADMIN_TOKEN_PUBLIC_KEY".to_string()
}

fn default_admin_token_store_snapshot_refresh_interval_ms() -> u64 {
  2_000
}

fn default_admin_token_store_token_ttl_seconds() -> u64 {
  3_600
}

fn default_true() -> bool {
  true
}
