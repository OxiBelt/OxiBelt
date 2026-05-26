use serde_json::json;

pub(super) fn diff_toml_values(
  path: &str,
  left: Option<&toml::Value>,
  right: Option<&toml::Value>,
  changes: &mut Vec<serde_json::Value>,
) {
  match (left, right) {
    (Some(toml::Value::Table(left)), Some(toml::Value::Table(right))) => {
      let keys = left
        .keys()
        .chain(right.keys())
        .collect::<std::collections::BTreeSet<_>>();
      for key in keys {
        let child = if path.is_empty() {
          key.to_string()
        } else {
          format!("{path}.{key}")
        };
        diff_toml_values(&child, left.get(key), right.get(key), changes);
      }
    }
    (Some(left), Some(right)) if left == right => {}
    (None, Some(_)) => changes.push(json!({ "path": path, "op": "add" })),
    (Some(_), None) => changes.push(json!({ "path": path, "op": "remove" })),
    (Some(_), Some(_)) => changes.push(json!({ "path": path, "op": "change" })),
    (None, None) => {}
  }
}
