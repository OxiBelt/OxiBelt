use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::cli::RulepackRepoAddArgs;

pub(crate) const RULEPACK_REPOS_FILE_ENV: &str = "OXIBELT_RULEPACK_REPOS_FILE";

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RulepackRepoRegistry {
  #[serde(default)]
  pub(crate) repos: BTreeMap<String, RulepackRepoConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RulepackRepoConfig {
  pub(crate) url: Url,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub(crate) ca_certs: Vec<PathBuf>,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub(crate) token_env: Option<String>,
  #[serde(default)]
  pub(crate) allow_insecure_rulepack_url: bool,
  #[serde(default)]
  pub(crate) require_openpgp_signature: bool,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub(crate) openpgp_key_files: Vec<PathBuf>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub(crate) openpgp_keyring_dirs: Vec<PathBuf>,
  #[serde(default, skip_serializing_if = "Vec::is_empty")]
  pub(crate) openpgp_fingerprints: Vec<String>,
}

impl RulepackRepoConfig {
  pub(crate) fn from_add_args(args: &RulepackRepoAddArgs) -> Self {
    Self {
      url: args.url.clone(),
      ca_certs: args.ca_certs.clone(),
      token_env: args.token_env.clone(),
      allow_insecure_rulepack_url: args.allow_insecure_rulepack_url,
      require_openpgp_signature: args.require_openpgp_signature,
      openpgp_key_files: args.openpgp_key_files.clone(),
      openpgp_keyring_dirs: args.openpgp_keyring_dirs.clone(),
      openpgp_fingerprints: args.openpgp_fingerprints.clone(),
    }
  }
}

pub(crate) fn load_registry() -> anyhow::Result<RulepackRepoRegistry> {
  load_registry_from_path(&registry_path()?)
}

pub(crate) fn save_registry(registry: &RulepackRepoRegistry) -> anyhow::Result<PathBuf> {
  let path = registry_path()?;
  save_registry_to_path(&path, registry)?;
  Ok(path)
}

pub(crate) fn registry_path() -> anyhow::Result<PathBuf> {
  if let Some(path) = env_path(RULEPACK_REPOS_FILE_ENV)? {
    return Ok(path);
  }
  let base = if let Some(path) = env_path("XDG_CONFIG_HOME")? {
    path
  } else if let Some(home) = env_path("HOME")? {
    home.join(".config")
  } else {
    bail!(
      "rulepack repo registry path requires {RULEPACK_REPOS_FILE_ENV}, XDG_CONFIG_HOME, or HOME"
    );
  };
  Ok(base.join("oxibelt").join("rulepack-repos.toml"))
}

pub(crate) fn load_registry_from_path(path: &Path) -> anyhow::Result<RulepackRepoRegistry> {
  match std::fs::read_to_string(path) {
    Ok(raw) => toml::from_str(&raw)
      .with_context(|| format!("failed to parse rulepack repo registry {}", path.display())),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      Ok(RulepackRepoRegistry::default())
    }
    Err(error) => Err(error)
      .with_context(|| format!("failed to read rulepack repo registry {}", path.display())),
  }
}

pub(crate) fn save_registry_to_path(
  path: &Path,
  registry: &RulepackRepoRegistry,
) -> anyhow::Result<()> {
  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent).with_context(|| {
      format!(
        "failed to create rulepack repo registry directory {}",
        parent.display()
      )
    })?;
  }
  let raw = toml::to_string_pretty(registry).context("failed to encode rulepack repo registry")?;
  let temp_path = path.with_extension(format!(
    "toml.tmp.{}.{}",
    std::process::id(),
    monotonic_suffix()
  ));
  write_user_private_file(&temp_path, raw.as_bytes()).with_context(|| {
    format!(
      "failed to write temporary rulepack repo registry {}",
      temp_path.display()
    )
  })?;
  std::fs::rename(&temp_path, path).with_context(|| {
    format!(
      "failed to replace rulepack repo registry {}",
      path.display()
    )
  })?;
  Ok(())
}

pub(crate) fn ensure_repo_name(name: &str) -> anyhow::Result<()> {
  if name.trim().is_empty() {
    bail!("rulepack repo name must not be empty");
  }
  if name.len() > 128 {
    bail!("rulepack repo name must not exceed 128 bytes");
  }
  if !name
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
  {
    bail!("rulepack repo name may contain only ASCII letters, digits, '.', '-', and '_'");
  }
  Ok(())
}

fn env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
  match std::env::var(name) {
    Ok(value) if value.trim().is_empty() => bail!("{name} must not be empty when set"),
    Ok(value) => Ok(Some(PathBuf::from(value))),
    Err(std::env::VarError::NotPresent) => Ok(None),
    Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid Unicode"),
  }
}

fn monotonic_suffix() -> u128 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|duration| duration.as_nanos())
    .unwrap_or_default()
}

fn write_user_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
  let mut options = std::fs::OpenOptions::new();
  options.write(true).create_new(true).truncate(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
  }
  let mut file = options.open(path)?;
  file.write_all(bytes)?;
  file.sync_all()?;
  Ok(())
}
