use super::*;

pub(super) fn validate_generated_source(
  source: &Value,
  managed_path: &str,
  expected_revision: &str,
) -> anyhow::Result<()> {
  let config_map = exact_config_map_source(source, "generated")?
    .as_object()
    .context("immutable rollout generated ConfigMap source must be an object")?;
  validate_object_keys(
    config_map,
    &["name", "items"],
    "immutable rollout generated ConfigMap source",
  )?;
  if config_map.get("name").and_then(Value::as_str) != Some(expected_revision) {
    bail!(
      "immutable rollout generated ConfigMap source is not owned by the recorded desired revision"
    );
  }
  let data_key = Path::new(managed_path)
    .file_name()
    .and_then(|value| value.to_str())
    .context("managed configuration path must name a UTF-8 file")?;
  let items = config_map
    .get("items")
    .and_then(Value::as_array)
    .context("immutable rollout generated ConfigMap source items must be an array")?;
  if items.is_empty() || items.len() > 65 {
    bail!("immutable rollout generated ConfigMap source must contain 1..=65 bounded items");
  }
  let mut seen = HashSet::new();
  let mut found_config = false;
  for item in items {
    let item = item
      .as_object()
      .context("immutable rollout generated ConfigMap source item must be an object")?;
    validate_object_keys(
      item,
      &["key", "path"],
      "immutable rollout generated ConfigMap source item",
    )?;
    let key = item
      .get("key")
      .and_then(Value::as_str)
      .context("immutable rollout generated ConfigMap item key is required")?;
    let path = item
      .get("path")
      .and_then(Value::as_str)
      .context("immutable rollout generated ConfigMap item path is required")?;
    if !seen.insert((key, path)) {
      bail!("immutable rollout generated ConfigMap source contains duplicate items");
    }
    if key == data_key && path == managed_path {
      found_config = true;
      continue;
    }
    let digest = key
      .strip_prefix("gateway-api-ca-")
      .and_then(|value| value.strip_suffix(".pem"));
    if digest.is_none_or(|digest| {
      digest.len() != 64
        || !digest
          .bytes()
          .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || path != format!("gateway-api-ca/{digest}.pem")
    }) {
      bail!("immutable rollout generated ConfigMap source contains an unsafe CA asset mapping");
    }
  }
  if !found_config {
    bail!("immutable rollout generated ConfigMap source item does not match the managed path");
  }
  Ok(())
}
