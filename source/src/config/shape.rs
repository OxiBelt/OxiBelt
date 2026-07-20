//! Strict merged-TOML shape validation and compatibility normalization.

use super::*;

#[path = "shape/core.rs"]
mod core;
#[path = "shape/routing.rs"]
mod routing;
#[path = "shape/services.rs"]
mod services;

pub(super) fn normalize_merged_lb_policy_compat(value: &mut toml::Value) -> anyhow::Result<()> {
  let diagnostics = lb_policy_compat::normalize_toml_from_config(value)?;
  lb_policy_compat::ensure_supported(&diagnostics)
}

pub(super) fn validate_merged_toml_shape(value: &toml::Value) -> anyhow::Result<()> {
  reject_removed_access_log_config(value)?;
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
pub(super) fn reject_removed_access_log_config(value: &toml::Value) -> anyhow::Result<()> {
  if value
    .get("database")
    .and_then(|database| database.get("access_log"))
    .is_some()
  {
    bail!(
      "database.access_log PostgreSQL access-log sink has been removed; use access_log.stdout or access_log.otlp with schema = \"ocsf\" or \"ecs\""
    );
  }
  if value
    .get("logging")
    .and_then(|logging| logging.get("access_log"))
    .and_then(|access_log| access_log.get("database"))
    .is_some()
  {
    bail!(
      "logging.access_log.database PostgreSQL access-log sink has been removed; use access_log.stdout or access_log.otlp with schema = \"ocsf\" or \"ecs\""
    );
  }
  Ok(())
}
pub(super) fn collect_unknown_keys(value: &toml::Value, path: &str, unknown: &mut Vec<String>) {
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

pub(super) fn allowed_config_keys(path: &str) -> Option<BTreeSet<&'static str>> {
  let keys = core::allowed_keys(path)
    .or_else(|| services::allowed_keys(path))
    .or_else(|| routing::allowed_keys(path))?;
  Some(keys.iter().copied().collect())
}
