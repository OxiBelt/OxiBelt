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

pub(super) fn normalize_merged_upstream_resolution_compat(
  value: &mut toml::Value,
) -> anyhow::Result<()> {
  const DIRECT_FIELDS: &[&str] = &[
    "max_endpoint_count",
    "min_ttl_ms",
    "max_ttl_ms",
    "negative_ttl_ms",
    "cooldown_base_ms",
    "cooldown_max_ms",
  ];

  let Some(legacy) = value
    .get("quic")
    .and_then(|quic| quic.get("upstream"))
    .and_then(|upstream| upstream.get("resolution"))
    .and_then(toml::Value::as_table)
    .cloned()
  else {
    return Ok(());
  };

  for field in DIRECT_FIELDS {
    if let Some(field_value) = legacy.get(*field).cloned() {
      move_compat_leaf(
        value,
        &["quic", "upstream", "resolution", field],
        &["proxy", "upstream_resolution", field],
        field_value,
      )?;
    }
  }
  if let Some(delay) = legacy.get("address_family_stagger_ms").cloned() {
    move_compat_leaf(
      value,
      &[
        "quic",
        "upstream",
        "resolution",
        "address_family_stagger_ms",
      ],
      &[
        "proxy",
        "upstream_resolution",
        "happy_eyeballs",
        "connection_attempt_delay_ms",
      ],
      delay,
    )?;
    insert_compat_default(
      value,
      &[
        "proxy",
        "upstream_resolution",
        "happy_eyeballs",
        "minimum_connection_attempt_delay_ms",
      ],
      toml::Value::Integer(10),
    )?;
    insert_compat_default(
      value,
      &[
        "proxy",
        "upstream_resolution",
        "happy_eyeballs",
        "maximum_connection_attempt_delay_ms",
      ],
      toml::Value::Integer(5_000),
    )?;
  }
  if let Some(attempts) = legacy.get("max_connect_attempts").cloned() {
    move_compat_leaf(
      value,
      &["quic", "upstream", "resolution", "max_connect_attempts"],
      &[
        "proxy",
        "upstream_resolution",
        "happy_eyeballs",
        "max_connect_attempts",
      ],
      attempts,
    )?;
  }
  remove_empty_compat_tables(value);
  Ok(())
}

fn move_compat_leaf(
  root: &mut toml::Value,
  legacy_path: &[&str],
  canonical_path: &[&str],
  value: toml::Value,
) -> anyhow::Result<()> {
  if lookup_toml_path(root, canonical_path).is_some() {
    bail!(
      "configuration defines both compatibility field `{}` and canonical field `{}`; no precedence is selected",
      legacy_path.join("."),
      canonical_path.join(".")
    );
  }
  insert_toml_path(root, canonical_path, value)?;
  remove_toml_path(root, legacy_path);
  Ok(())
}

fn insert_compat_default(
  root: &mut toml::Value,
  path: &[&str],
  value: toml::Value,
) -> anyhow::Result<()> {
  if lookup_toml_path(root, path).is_none() {
    insert_toml_path(root, path, value)?;
  }
  Ok(())
}

fn lookup_toml_path<'a>(mut value: &'a toml::Value, path: &[&str]) -> Option<&'a toml::Value> {
  for segment in path {
    value = value.get(*segment)?;
  }
  Some(value)
}

fn insert_toml_path(
  root: &mut toml::Value,
  path: &[&str],
  value: toml::Value,
) -> anyhow::Result<()> {
  let Some((leaf, parents)) = path.split_last() else {
    bail!("configuration compatibility target path must not be empty");
  };
  let mut current = root;
  for segment in parents {
    let table = current.as_table_mut().ok_or_else(|| {
      anyhow!(
        "configuration compatibility parent `{}` must be a table",
        parents.join(".")
      )
    })?;
    current = table
      .entry((*segment).to_string())
      .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
  }
  let table = current.as_table_mut().ok_or_else(|| {
    anyhow!(
      "configuration compatibility parent `{}` must be a table",
      parents.join(".")
    )
  })?;
  table.insert((*leaf).to_string(), value);
  Ok(())
}

fn remove_toml_path(root: &mut toml::Value, path: &[&str]) {
  let Some((leaf, parents)) = path.split_last() else {
    return;
  };
  let mut current = root;
  for segment in parents {
    let Some(next) = current.get_mut(*segment) else {
      return;
    };
    current = next;
  }
  if let Some(table) = current.as_table_mut() {
    table.remove(*leaf);
  }
}

fn remove_empty_compat_tables(root: &mut toml::Value) {
  let resolution_empty = root
    .get("quic")
    .and_then(|quic| quic.get("upstream"))
    .and_then(|upstream| upstream.get("resolution"))
    .and_then(toml::Value::as_table)
    .is_some_and(toml::map::Map::is_empty);
  if !resolution_empty {
    return;
  }
  if let Some(upstream) = root
    .get_mut("quic")
    .and_then(|quic| quic.get_mut("upstream"))
    .and_then(toml::Value::as_table_mut)
  {
    upstream.remove("resolution");
  }
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

pub(super) fn join_key_path(parent: &str, key: &str) -> String {
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn legacy_quic_resolution_leaves_normalize_to_the_canonical_policy() {
    let mut value: toml::Value = toml::from_str(
      r#"
[quic.upstream.resolution]
max_endpoint_count = 8
address_family_stagger_ms = 10
max_connect_attempts = 3
"#,
    )
    .unwrap();
    normalize_merged_upstream_resolution_compat(&mut value).unwrap();
    assert_eq!(
      lookup_toml_path(
        &value,
        &["proxy", "upstream_resolution", "max_endpoint_count"]
      )
      .and_then(toml::Value::as_integer),
      Some(8)
    );
    assert_eq!(
      lookup_toml_path(
        &value,
        &[
          "proxy",
          "upstream_resolution",
          "happy_eyeballs",
          "connection_attempt_delay_ms"
        ]
      )
      .and_then(toml::Value::as_integer),
      Some(10)
    );
    assert_eq!(
      lookup_toml_path(
        &value,
        &[
          "proxy",
          "upstream_resolution",
          "happy_eyeballs",
          "minimum_connection_attempt_delay_ms"
        ]
      )
      .and_then(toml::Value::as_integer),
      Some(10)
    );
    assert!(lookup_toml_path(&value, &["quic", "upstream", "resolution"]).is_none());
  }

  #[test]
  fn compatibility_and_canonical_leaf_collision_is_rejected_even_when_equal() {
    let mut value: toml::Value = toml::from_str(
      r#"
[quic.upstream.resolution]
max_endpoint_count = 8

[proxy.upstream_resolution]
max_endpoint_count = 8
"#,
    )
    .unwrap();
    let error = normalize_merged_upstream_resolution_compat(&mut value).unwrap_err();
    assert!(error.to_string().contains("no precedence is selected"));
  }

  #[test]
  fn disjoint_compatibility_and_canonical_leaves_are_merged() {
    let mut value: toml::Value = toml::from_str(
      r#"
[quic.upstream.resolution]
max_endpoint_count = 8

[proxy.upstream_resolution]
min_ttl_ms = 2000
"#,
    )
    .unwrap();
    normalize_merged_upstream_resolution_compat(&mut value).unwrap();
    assert_eq!(
      lookup_toml_path(
        &value,
        &["proxy", "upstream_resolution", "max_endpoint_count"]
      )
      .and_then(toml::Value::as_integer),
      Some(8)
    );
    assert_eq!(
      lookup_toml_path(&value, &["proxy", "upstream_resolution", "min_ttl_ms"])
        .and_then(toml::Value::as_integer),
      Some(2_000)
    );
  }
}
