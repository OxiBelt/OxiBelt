use std::net::IpAddr;

use anyhow::{Context, bail};
use serde::Serialize;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Key, Table, Value, value};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct MigrationChange {
  pub(crate) file: String,
  pub(crate) field_path: String,
  pub(crate) action: &'static str,
  pub(crate) replacement: String,
}

pub(crate) fn transform_document(
  raw: &str,
  file: &str,
) -> anyhow::Result<(String, Vec<MigrationChange>)> {
  let mut document = raw
    .parse::<DocumentMut>()
    .with_context(|| format!("failed to parse TOML from {file}"))?;
  let mut changes = Vec::new();
  let root = document.as_table_mut();

  if let Some(listeners) = child_table_mut(root, "listeners") {
    migrate_scalar_bind(
      listeners,
      "https_bind",
      "https_binds",
      "listeners",
      file,
      &mut changes,
    )?;
    migrate_scalar_bind(
      listeners,
      "http_bind",
      "http_binds",
      "listeners",
      file,
      &mut changes,
    )?;
  }

  if let Some(tls) = child_table_mut(root, "tls") {
    migrate_tls(tls, "tls", file, &mut changes)?;
  }
  if let Some(admin) = child_table_mut(root, "admin") {
    if let Some(tls) = child_table_mut(admin, "tls") {
      migrate_tls_resumption(tls, "admin.tls", file, &mut changes)?;
    }
    if let Some(audit) = child_table_mut(admin, "audit") {
      migrate_string_alias(
        audit,
        "mode",
        &[("enforcing", "durable_required")],
        "admin.audit.mode",
        file,
        &mut changes,
      );
    }
  }

  migrate_pool_health_checks(root, file, &mut changes)?;
  migrate_rate_limits(root, file, &mut changes);
  migrate_crypto(root, file, &mut changes);
  migrate_turn_listeners(root, file, &mut changes)?;

  if changes.is_empty() {
    Ok((raw.to_string(), changes))
  } else {
    Ok((document.to_string(), changes))
  }
}

fn migrate_tls(
  tls: &mut Table,
  path: &str,
  file: &str,
  changes: &mut Vec<MigrationChange>,
) -> anyhow::Result<()> {
  if let Some(legacy) = tls.get("key_exchange_groups").cloned() {
    let tls13 = ensure_child_table(tls, "1_3")?;
    move_to_table(
      tls13,
      "key_exchange_groups",
      &legacy,
      &format!("{path}.key_exchange_groups"),
      &format!("{path}.1_3.key_exchange_groups"),
    )?;
    tls.remove("key_exchange_groups");
    changes.push(change(
      file,
      &format!("{path}.key_exchange_groups"),
      "rename",
      &format!("{path}.1_3.key_exchange_groups"),
    ));
  }
  migrate_tls_resumption(tls, path, file, changes)
}

fn migrate_tls_resumption(
  tls: &mut Table,
  path: &str,
  file: &str,
  changes: &mut Vec<MigrationChange>,
) -> anyhow::Result<()> {
  if let Some(legacy) = tls.get("session_tickets").cloned() {
    let enabled = legacy
      .as_value()
      .and_then(Value::as_bool)
      .with_context(|| format!("{path}.session_tickets must be a boolean"))?;
    let replacement = decorated_value(if enabled { "stateful" } else { "off" }, &legacy)?;
    let resumption = ensure_child_table(tls, "resumption")?;
    move_to_table(
      resumption,
      "mode",
      &replacement,
      &format!("{path}.session_tickets"),
      &format!("{path}.resumption.mode"),
    )?;
    tls.remove("session_tickets");
    changes.push(change(
      file,
      &format!("{path}.session_tickets"),
      "replace",
      &format!("{path}.resumption.mode"),
    ));
  }

  if let Some(legacy) = tls.get("session_ticket_rotation_seconds").cloned() {
    let resumption = ensure_child_table(tls, "resumption")?;
    move_to_table(
      resumption,
      "rotation_seconds",
      &legacy,
      &format!("{path}.session_ticket_rotation_seconds"),
      &format!("{path}.resumption.rotation_seconds"),
    )?;
    tls.remove("session_ticket_rotation_seconds");
    changes.push(change(
      file,
      &format!("{path}.session_ticket_rotation_seconds"),
      "rename",
      &format!("{path}.resumption.rotation_seconds"),
    ));
  }
  Ok(())
}

fn migrate_scalar_bind(
  table: &mut Table,
  legacy_key: &str,
  canonical_key: &str,
  table_path: &str,
  file: &str,
  changes: &mut Vec<MigrationChange>,
) -> anyhow::Result<()> {
  let Some(legacy) = table.get(legacy_key).cloned() else {
    return Ok(());
  };
  let scalar = legacy
    .as_value()
    .with_context(|| format!("{table_path}.{legacy_key} must be a scalar value"))?;
  let mut element = scalar.clone();
  *element.decor_mut() = Default::default();
  let mut array = Array::new();
  array.push_formatted(element);
  *array.decor_mut() = scalar.decor().clone();
  let replacement = Item::Value(Value::Array(array));
  let legacy_path = format!("{table_path}.{legacy_key}");
  let canonical_path = format!("{table_path}.{canonical_key}");
  move_to_table(
    table,
    canonical_key,
    &replacement,
    &legacy_path,
    &canonical_path,
  )?;
  table.remove(legacy_key);
  changes.push(change(file, &legacy_path, "replace", &canonical_path));
  Ok(())
}

fn migrate_pool_health_checks(
  root: &mut Table,
  file: &str,
  changes: &mut Vec<MigrationChange>,
) -> anyhow::Result<()> {
  let Some(pools) = root
    .get_mut("upstream_pools")
    .and_then(Item::as_array_of_tables_mut)
  else {
    return Ok(());
  };
  for (index, pool) in pools.iter_mut().enumerate() {
    let Some(health) = child_table_mut(pool, "health_check") else {
      continue;
    };
    let prefix = format!("upstream_pools[{index}].health_check");
    migrate_key(health, "rise", "healthy_threshold", &prefix, file, changes)?;
    migrate_key(
      health,
      "fall",
      "unhealthy_threshold",
      &prefix,
      file,
      changes,
    )?;
  }
  Ok(())
}

fn migrate_rate_limits(root: &mut Table, file: &str, changes: &mut Vec<MigrationChange>) {
  const ALIASES: &[(&str, &str)] = &[
    ("client-ip", "client_ip"),
    ("client-ip-route", "client_ip_route"),
    ("client-ip-path", "client_ip_path"),
    ("access-token", "access_token"),
    ("access-token-route", "access_token_route"),
    ("access-token-path", "access_token_path"),
    ("client-ip-prefix", "client_ip_prefix"),
    ("client-ip-prefix-route", "client_ip_prefix_route"),
    ("client-ip-prefix-path", "client_ip_prefix_path"),
    ("tls-fingerprint", "tls_fingerprint"),
    ("tls-fingerprint-route", "tls_fingerprint_route"),
    ("token-binding-hash", "token_binding_hash"),
    ("token-binding-hash-route", "token_binding_hash_route"),
    ("person-proof-clearance", "person_proof_clearance"),
    (
      "person-proof-clearance-route",
      "person_proof_clearance_route",
    ),
    ("composite-client", "composite_client"),
    ("composite-client-route", "composite_client_route"),
  ];
  let Some(limits) = root
    .get_mut("rate_limits")
    .and_then(Item::as_array_of_tables_mut)
  else {
    return;
  };
  for (index, limit) in limits.iter_mut().enumerate() {
    migrate_string_alias(
      limit,
      "key",
      ALIASES,
      &format!("rate_limits[{index}].key"),
      file,
      changes,
    );
  }
}

fn migrate_crypto(root: &mut Table, file: &str, changes: &mut Vec<MigrationChange>) {
  const PROVIDER: &[(&str, &str)] = &[("rust_crypto", "rustcrypto")];
  const BACKEND: &[(&str, &str)] = &[
    ("x86_sha", "x86-sha"),
    ("x86_avx2", "x86-avx2"),
    ("aarch64_sha2", "aarch64-sha2"),
    ("aarch64_sha3", "aarch64-sha3"),
    ("riscv_zknh", "riscv-zknh"),
    ("aes_avx256", "aes-avx256"),
    ("aes_avx512", "aes-avx512"),
    ("chacha20_sse2", "chacha20-sse2"),
    ("sse2", "chacha20-sse2"),
    ("chacha20_avx2", "chacha20-avx2"),
    ("avx2", "chacha20-avx2"),
    ("chacha20_avx512", "chacha20-avx512"),
    ("avx512", "chacha20-avx512"),
  ];
  let Some(crypto) = child_table_mut(root, "crypto") else {
    return;
  };
  migrate_string_alias(
    crypto,
    "primitive_provider",
    PROVIDER,
    "crypto.primitive_provider",
    file,
    changes,
  );
  migrate_string_alias(
    crypto,
    "primitive_backend",
    BACKEND,
    "crypto.primitive_backend",
    file,
    changes,
  );
  if let Some(primitives) = child_table_mut(crypto, "primitives") {
    migrate_table_strings(primitives, PROVIDER, "crypto.primitives", file, changes);
  }
  if let Some(backends) = child_table_mut(crypto, "primitive_backends") {
    migrate_table_strings(
      backends,
      BACKEND,
      "crypto.primitive_backends",
      file,
      changes,
    );
  }
}

fn migrate_turn_listeners(
  root: &mut Table,
  file: &str,
  changes: &mut Vec<MigrationChange>,
) -> anyhow::Result<()> {
  let Some(listeners) = root
    .get_mut("webrtc_turn_listeners")
    .and_then(Item::as_array_of_tables_mut)
  else {
    return Ok(());
  };
  for (index, listener) in listeners.iter_mut().enumerate() {
    let prefix = format!("webrtc_turn_listeners[{index}]");
    let legacy_present = ["public_ip", "relay_bind_ip", "relay_port_range"]
      .iter()
      .filter(|key| listener.contains_key(key))
      .count();
    if legacy_present == 0 {
      continue;
    }
    if listener.contains_key("relay_families") {
      bail!("{prefix} mixes legacy relay fields with relay_families; migration is ambiguous");
    }
    if legacy_present != 3 {
      bail!("{prefix} has an incomplete legacy relay field set; migration is ambiguous");
    }
    let public_ip = listener
      .get("public_ip")
      .and_then(Item::as_value)
      .and_then(Value::as_str)
      .with_context(|| format!("{prefix}.public_ip must be a string"))?
      .parse::<IpAddr>()
      .with_context(|| format!("{prefix}.public_ip must be an IP address"))?;
    let mut family = Table::new();
    family.insert(
      "family",
      value(if public_ip.is_ipv4() { "ipv4" } else { "ipv6" }),
    );
    for key in ["public_ip", "relay_bind_ip", "relay_port_range"] {
      let item = listener
        .remove(key)
        .with_context(|| format!("missing {prefix}.{key}"))?;
      family.insert(key, item);
    }
    let mut families = ArrayOfTables::new();
    families.push(family);
    listener.insert("relay_families", Item::ArrayOfTables(families));
    changes.push(change(
      file,
      &format!("{prefix}.public_ip"),
      "group",
      &format!("{prefix}.relay_families[0]"),
    ));
  }
  Ok(())
}

fn migrate_key(
  table: &mut Table,
  legacy_key: &str,
  canonical_key: &str,
  prefix: &str,
  file: &str,
  changes: &mut Vec<MigrationChange>,
) -> anyhow::Result<()> {
  let Some(legacy) = table.get(legacy_key).cloned() else {
    return Ok(());
  };
  let legacy_path = format!("{prefix}.{legacy_key}");
  let canonical_path = format!("{prefix}.{canonical_key}");
  move_to_table(table, canonical_key, &legacy, &legacy_path, &canonical_path)?;
  let (old_key, _) = table
    .remove_entry(legacy_key)
    .with_context(|| format!("missing {legacy_path}"))?;
  if !table.contains_key(canonical_key) {
    let key = Key::new(canonical_key)
      .with_leaf_decor(old_key.leaf_decor().clone())
      .with_dotted_decor(old_key.dotted_decor().clone());
    table.insert_formatted(&key, legacy);
  }
  changes.push(change(file, &legacy_path, "rename", &canonical_path));
  Ok(())
}

fn move_to_table(
  target: &mut Table,
  canonical_key: &str,
  replacement: &Item,
  legacy_path: &str,
  canonical_path: &str,
) -> anyhow::Result<()> {
  if let Some(existing) = target.get(canonical_key) {
    if items_equivalent(existing, replacement) {
      return Ok(());
    }
    bail!("{legacy_path} conflicts with {canonical_path}; migration is ambiguous");
  }
  target.insert(canonical_key, replacement.clone());
  Ok(())
}

fn migrate_table_strings(
  table: &mut Table,
  aliases: &[(&str, &str)],
  prefix: &str,
  file: &str,
  changes: &mut Vec<MigrationChange>,
) {
  let keys = table
    .iter()
    .map(|(key, _)| key.to_string())
    .collect::<Vec<_>>();
  for key in keys {
    migrate_string_alias(
      table,
      &key,
      aliases,
      &format!("{prefix}.{key}"),
      file,
      changes,
    );
  }
}

fn migrate_string_alias(
  table: &mut Table,
  key: &str,
  aliases: &[(&str, &str)],
  path: &str,
  file: &str,
  changes: &mut Vec<MigrationChange>,
) {
  let Some(item) = table.get_mut(key) else {
    return;
  };
  let Some(current) = item.as_value().and_then(Value::as_str) else {
    return;
  };
  let Some((_, canonical)) = aliases.iter().find(|(legacy, _)| current == *legacy) else {
    return;
  };
  let old = item.as_value().expect("string value checked above");
  let mut replacement = Value::from(*canonical);
  *replacement.decor_mut() = old.decor().clone();
  *item = Item::Value(replacement);
  changes.push(change(file, path, "canonicalize", path));
}

fn ensure_child_table<'a>(table: &'a mut Table, key: &str) -> anyhow::Result<&'a mut Table> {
  if !table.contains_key(key) {
    table.insert(key, Item::Table(Table::new()));
  }
  table
    .get_mut(key)
    .and_then(Item::as_table_mut)
    .with_context(|| format!("{key} must be a table"))
}

fn child_table_mut<'a>(table: &'a mut Table, key: &str) -> Option<&'a mut Table> {
  table.get_mut(key).and_then(Item::as_table_mut)
}

fn decorated_value(value: &str, source: &Item) -> anyhow::Result<Item> {
  let decor = source
    .as_value()
    .context("legacy value must be a scalar")?
    .decor()
    .clone();
  let mut replacement = Value::from(value);
  *replacement.decor_mut() = decor;
  Ok(Item::Value(replacement))
}

fn items_equivalent(left: &Item, right: &Item) -> bool {
  match (left.as_value(), right.as_value()) {
    (Some(left), Some(right)) => values_equivalent(left, right),
    _ => false,
  }
}

fn values_equivalent(left: &Value, right: &Value) -> bool {
  match (left, right) {
    (Value::String(left), Value::String(right)) => left.value() == right.value(),
    (Value::Integer(left), Value::Integer(right)) => left.value() == right.value(),
    (Value::Float(left), Value::Float(right)) => left.value() == right.value(),
    (Value::Boolean(left), Value::Boolean(right)) => left.value() == right.value(),
    (Value::Datetime(left), Value::Datetime(right)) => left.value() == right.value(),
    (Value::Array(left), Value::Array(right)) => {
      left.len() == right.len()
        && left
          .iter()
          .zip(right.iter())
          .all(|(left, right)| values_equivalent(left, right))
    }
    (Value::InlineTable(left), Value::InlineTable(right)) => {
      left.len() == right.len()
        && left.iter().all(|(key, left)| {
          right
            .get(key)
            .is_some_and(|right| values_equivalent(left, right))
        })
    }
    _ => false,
  }
}

fn change(
  file: &str,
  field_path: &str,
  action: &'static str,
  replacement: &str,
) -> MigrationChange {
  MigrationChange {
    file: file.to_string(),
    field_path: field_path.to_string(),
    action,
    replacement: replacement.to_string(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn preserves_comments_while_migrating_exact_aliases() {
    let raw = r#"# listener comment
[listeners]
https_bind = "127.0.0.1:8443" # bind comment

[admin.audit]
mode = "enforcing" # mode comment
"#;
    let (migrated, changes) = transform_document(raw, "config.toml").expect("migration");
    assert!(migrated.contains("# listener comment"));
    assert!(migrated.contains("# bind comment"));
    assert!(migrated.contains("https_binds = [\"127.0.0.1:8443\"]"));
    assert!(migrated.contains("mode = \"durable_required\" # mode comment"));
    assert_eq!(changes.len(), 2);
  }

  #[test]
  fn rejects_conflicting_legacy_and_canonical_values() {
    let raw = r#"[listeners]
https_bind = "127.0.0.1:8443"
https_binds = ["127.0.0.1:9443"]
"#;
    let error = transform_document(raw, "config.toml").expect_err("conflict must fail");
    assert!(error.to_string().contains("migration is ambiguous"));
  }

  #[test]
  fn a_second_transform_is_idempotent() {
    let raw = r#"[[rate_limits]]
name = "clients"
key = "client-ip"
rate = "10/s"
"#;
    let (once, first) = transform_document(raw, "config.toml").expect("first migration");
    let (twice, second) = transform_document(&once, "config.toml").expect("second migration");
    assert_eq!(once, twice);
    assert_eq!(first.len(), 1);
    assert!(second.is_empty());
  }
}
