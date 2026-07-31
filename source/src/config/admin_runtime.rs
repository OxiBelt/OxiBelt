//! Admin runtime configuration validation.
//! Operation and transport limits are checked before the admin listener starts.

use anyhow::{Context, anyhow, bail};

use super::{Config, ConfigPathRoots, operational_profile, validate_merged_toml_shape};

impl Config {
  pub fn load_admin_inline_toml(raw: &str, active: &Self) -> anyhow::Result<Self> {
    let value: toml::Value = toml::from_str(raw).context("failed to parse inline TOML")?;
    reject_inline_include(&value)?;
    validate_merged_toml_shape(&value)?;
    let mut config: Self = value.try_into().context("failed to decode inline TOML")?;
    config.source_paths.config_entry = active.source_paths.config_entry.clone();
    config.source_paths.config_files = active.source_paths.config_files.clone();
    config.rollout = active.rollout.clone();
    let path_roots = active_config_path_roots(active)?;
    config.resolve_relative_paths(&path_roots)?;
    config.load_external_waf_rules()?;
    config.collect_loaded_waf_rule_paths();
    Ok(config)
  }

  pub fn load_admin_inline_effective_toml_redacted(
    raw: &str,
    active: &Self,
  ) -> anyhow::Result<toml::Value> {
    Ok(Self::redact_effective_toml_value(
      &Self::load_admin_inline_effective_toml_for_activation(raw, active)?,
    ))
  }

  pub(crate) fn load_admin_inline_effective_toml_for_activation(
    raw: &str,
    active: &Self,
  ) -> anyhow::Result<toml::Value> {
    let mut value: toml::Value = toml::from_str(raw).context("failed to parse inline TOML")?;
    reject_inline_include(&value)?;
    operational_profile::apply_to_toml(&mut value)?;
    validate_merged_toml_shape(&value)?;
    let config = Self::load_admin_inline_toml(raw, active)?;
    config.validate()?;
    config.write_resolved_workers_to_toml(&mut value)?;
    Ok(value)
  }
}

fn active_config_path_roots(config: &Config) -> anyhow::Result<ConfigPathRoots> {
  let config_dir = config
    .source_paths
    .config_dir
    .clone()
    .ok_or_else(|| anyhow!("active configuration does not have a config directory"))?;
  let cert_dir = config
    .source_paths
    .cert_dir
    .clone()
    .ok_or_else(|| anyhow!("active configuration does not have a certificate directory"))?;
  let oxirule_dir = config
    .source_paths
    .oxirule_dir
    .clone()
    .ok_or_else(|| anyhow!("active configuration does not have an OxiRule directory"))?;
  Ok(ConfigPathRoots {
    config_dir,
    cert_dir,
    oxirule_dir,
  })
}

fn reject_inline_include(value: &toml::Value) -> anyhow::Result<()> {
  if value.get("include").is_some() {
    bail!("inline admin config payloads must not contain include");
  }
  Ok(())
}
