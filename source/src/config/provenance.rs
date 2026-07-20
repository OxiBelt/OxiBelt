use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Source classification for a native configuration value.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigOriginKind {
  Entry,
  Include,
  Profile,
  Default,
  Computed,
  RuntimeOverride,
  Admin,
}

/// Origin retained for an individual canonical native configuration path.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct ConfigValueOrigin {
  pub kind: ConfigOriginKind,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub file: Option<PathBuf>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub line: Option<u32>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub column: Option<u32>,
}

impl ConfigValueOrigin {
  pub(crate) fn file(kind: ConfigOriginKind, file: PathBuf) -> Self {
    Self {
      kind,
      file: Some(file),
      line: None,
      column: None,
    }
  }

  #[cfg(test)]
  pub(crate) fn synthetic(kind: ConfigOriginKind) -> Self {
    Self {
      kind,
      file: None,
      line: None,
      column: None,
    }
  }

  pub fn logical_file(&self, root: &Path) -> Option<String> {
    let file = self.file.as_deref()?;
    Some(
      file
        .strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/"),
    )
  }
}

/// Canonical field path to source metadata.
pub type ConfigOriginIndex = BTreeMap<String, ConfigValueOrigin>;

pub(crate) fn index_document_origins(
  value: &toml::Value,
  file: &Path,
  kind: ConfigOriginKind,
) -> ConfigOriginIndex {
  let mut origins = ConfigOriginIndex::new();
  index_value(value, "", file, kind, &mut origins);
  origins
}

fn index_value(
  value: &toml::Value,
  path: &str,
  file: &Path,
  kind: ConfigOriginKind,
  origins: &mut ConfigOriginIndex,
) {
  if !path.is_empty() {
    origins.insert(
      path.to_string(),
      ConfigValueOrigin::file(kind, file.to_path_buf()),
    );
  }
  match value {
    toml::Value::Table(table) => {
      for (key, child) in table {
        let child_path = if path.is_empty() {
          key.clone()
        } else {
          format!("{path}.{key}")
        };
        index_value(child, &child_path, file, kind, origins);
      }
    }
    toml::Value::Array(items) => {
      for (index, child) in items.iter().enumerate() {
        let child_path = format!("{path}[{index}]");
        index_value(child, &child_path, file, kind, origins);
      }
    }
    _ => {}
  }
}

pub(crate) fn shift_array_origins(
  origins: &mut ConfigOriginIndex,
  array_path: &str,
  offset: usize,
) {
  if offset == 0 {
    return;
  }
  let prefix = format!("{array_path}[");
  let shifted = origins
    .iter()
    .map(|(path, origin)| {
      let Some(rest) = path.strip_prefix(&prefix) else {
        return (path.clone(), origin.clone());
      };
      let Some(end) = rest.find(']') else {
        return (path.clone(), origin.clone());
      };
      let Ok(index) = rest[..end].parse::<usize>() else {
        return (path.clone(), origin.clone());
      };
      (
        format!("{prefix}{}{}", index.saturating_add(offset), &rest[end..]),
        origin.clone(),
      )
    })
    .collect();
  *origins = shifted;
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn shifts_only_the_selected_array_path() {
    let mut origins = ConfigOriginIndex::from([
      (
        "routes[0].name".to_string(),
        ConfigValueOrigin::synthetic(ConfigOriginKind::Include),
      ),
      (
        "upstreams[0].name".to_string(),
        ConfigValueOrigin::synthetic(ConfigOriginKind::Include),
      ),
    ]);
    shift_array_origins(&mut origins, "routes", 3);
    assert!(origins.contains_key("routes[3].name"));
    assert!(origins.contains_key("upstreams[0].name"));
  }
}
