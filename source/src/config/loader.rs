//! TOML loading, include processing, and runtime override application.
//! Includes are resolved deliberately so config assembly cannot escape expected roots.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};

use super::{canonicalize_local_config_file_target, resolve_local_config_file_path};

pub(super) struct LoadedToml {
  pub(super) value: toml::Value,
  pub(super) files: Vec<PathBuf>,
}

pub(super) fn load_toml_with_includes(path: &Path) -> anyhow::Result<LoadedToml> {
  let mut stack = Vec::new();
  load_toml_document(path, &HashMap::new(), &mut stack)
}

pub(super) fn load_toml_with_includes_and_overrides(
  path: &Path,
  overrides: &HashMap<PathBuf, Option<String>>,
) -> anyhow::Result<LoadedToml> {
  let mut stack = Vec::new();
  load_toml_document(path, overrides, &mut stack)
}

fn load_toml_document(
  path: &Path,
  overrides: &HashMap<PathBuf, Option<String>>,
  stack: &mut Vec<PathBuf>,
) -> anyhow::Result<LoadedToml> {
  let absolute_path = absolute_config_path(path)?;
  let canonical_path = canonicalize_config_file_or_override(&absolute_path, overrides)?;
  let canonical_parent = absolute_path
    .parent()
    .unwrap_or_else(|| Path::new("."))
    .canonicalize()
    .with_context(|| {
      format!(
        "failed to resolve configuration directory for {}",
        absolute_path.display()
      )
    })?;

  if !canonical_path.starts_with(&canonical_parent) {
    bail!(
      "configuration file {} must stay within its declaring directory",
      absolute_path.display()
    );
  }

  if let Some(index) = stack.iter().position(|entry| entry == &canonical_path) {
    let mut cycle = stack[index..]
      .iter()
      .map(|entry| entry.display().to_string())
      .collect::<Vec<_>>();
    cycle.push(canonical_path.display().to_string());
    bail!(
      "configuration include cycle detected: {}",
      cycle.join(" -> ")
    );
  }

  stack.push(canonical_path.clone());
  let mut files = vec![canonical_path.clone()];

  let raw = read_config_file_with_overrides(&canonical_path, &absolute_path, overrides)?;
  let mut value: toml::Value = toml::from_str(&raw)
    .with_context(|| format!("failed to parse TOML from {}", absolute_path.display()))?;
  let include_entries = take_include_entries(&mut value, &absolute_path)?;
  let base_dir = absolute_path.parent().unwrap_or_else(|| Path::new("."));

  let mut merged = toml::Value::Table(toml::map::Map::new());
  for entry in include_entries {
    for include_path in expand_include_entry(&entry, base_dir, &absolute_path, overrides)? {
      let included = load_toml_document(&include_path, overrides, stack)?;
      files.extend(included.files);
      merge_toml_values(&mut merged, included.value, "")?;
    }
  }
  merge_toml_values(&mut merged, value, "")?;

  stack.pop();
  files.sort();
  files.dedup();
  Ok(LoadedToml {
    value: merged,
    files,
  })
}

fn canonicalize_config_file_or_override(
  absolute_path: &Path,
  overrides: &HashMap<PathBuf, Option<String>>,
) -> anyhow::Result<PathBuf> {
  match absolute_path.canonicalize() {
    Ok(path) => Ok(path),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      let canonical_path =
        canonicalize_local_config_file_target("configuration file", absolute_path)?;
      if overrides.contains_key(&canonical_path) || overrides.contains_key(absolute_path) {
        return Ok(canonical_path);
      }
      Err(error).with_context(|| {
        format!(
          "failed to resolve configuration file {}",
          absolute_path.display()
        )
      })
    }
    Err(error) => Err(error).with_context(|| {
      format!(
        "failed to resolve configuration file {}",
        absolute_path.display()
      )
    }),
  }
}

fn read_config_file_with_overrides(
  canonical_path: &Path,
  absolute_path: &Path,
  overrides: &HashMap<PathBuf, Option<String>>,
) -> anyhow::Result<String> {
  match overrides
    .get(canonical_path)
    .or_else(|| overrides.get(absolute_path))
  {
    Some(Some(raw)) => Ok(raw.clone()),
    Some(None) => bail!(
      "configuration file {} is deleted by pending file sync",
      absolute_path.display()
    ),
    None => std::fs::read_to_string(canonical_path)
      .with_context(|| format!("failed to read {}", canonical_path.display())),
  }
}

fn take_include_entries(value: &mut toml::Value, path: &Path) -> anyhow::Result<Vec<String>> {
  let Some(table) = value.as_table_mut() else {
    bail!(
      "configuration root in {} must be a TOML table",
      path.display()
    );
  };
  let Some(include) = table.remove("include") else {
    return Ok(Vec::new());
  };

  match include {
    toml::Value::String(entry) => Ok(vec![entry]),
    toml::Value::Array(entries) => entries
      .into_iter()
      .map(|entry| match entry {
        toml::Value::String(entry) => Ok(entry),
        _ => bail!(
          "configuration include entries in {} must be strings",
          path.display()
        ),
      })
      .collect(),
    _ => bail!(
      "configuration include in {} must be a string or array of strings",
      path.display()
    ),
  }
}

fn expand_include_entry(
  entry: &str,
  base_dir: &Path,
  source_path: &Path,
  overrides: &HashMap<PathBuf, Option<String>>,
) -> anyhow::Result<Vec<PathBuf>> {
  if entry.trim().is_empty() {
    bail!(
      "configuration include in {} must not be empty",
      source_path.display()
    );
  }

  let include_path = Path::new(entry);
  let pattern_path =
    resolve_local_config_file_path("configuration include", base_dir, include_path)?;
  let canonical_base_dir = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve configuration include base directory {}",
      base_dir.display()
    )
  })?;

  if !has_glob_pattern(entry) {
    return Ok(vec![canonicalize_local_config_file_with_overrides(
      "configuration include",
      &pattern_path,
      &canonical_base_dir,
      source_path,
      overrides,
    )?]);
  }

  let pattern_text = pattern_path.to_str().ok_or_else(|| {
    anyhow!(
      "configuration include pattern in {} is not valid UTF-8: {}",
      source_path.display(),
      pattern_path.display()
    )
  })?;
  let mut paths = Vec::new();
  for path in glob::glob(pattern_text).with_context(|| {
    format!(
      "invalid configuration include pattern {}",
      pattern_path.display()
    )
  })? {
    let path = path.with_context(|| {
      format!(
        "failed to expand configuration include pattern {}",
        pattern_path.display()
      )
    })?;
    if path.is_file() {
      let canonical_path = canonicalize_local_config_file(
        "configuration include",
        &path,
        &canonical_base_dir,
        source_path,
      )?;
      if !matches!(overrides.get(&canonical_path), Some(None)) {
        paths.push(canonical_path);
      }
    }
  }
  let mut override_patterns = vec![glob::Pattern::new(pattern_text).with_context(|| {
    format!(
      "invalid configuration include pattern {}",
      pattern_path.display()
    )
  })?];
  if let Some(canonical_pattern_text) = canonicalize_glob_pattern_prefix(&pattern_path)?
    && canonical_pattern_text != pattern_text
  {
    override_patterns.push(
      glob::Pattern::new(&canonical_pattern_text).with_context(|| {
        format!(
          "invalid canonical configuration include pattern {}",
          canonical_pattern_text
        )
      })?,
    );
  }
  for (path, content) in overrides {
    if content.is_some()
      && override_patterns
        .iter()
        .any(|pattern| pattern.matches_path(path))
    {
      paths.push(canonicalize_local_config_file_with_overrides(
        "configuration include",
        path,
        &canonical_base_dir,
        source_path,
        overrides,
      )?);
    }
  }
  paths.sort();
  paths.dedup();
  Ok(paths)
}

fn has_glob_pattern(entry: &str) -> bool {
  entry.chars().any(|ch| matches!(ch, '*' | '?' | '['))
}

fn canonicalize_glob_pattern_prefix(pattern_path: &Path) -> anyhow::Result<Option<String>> {
  let mut fixed_prefix = PathBuf::new();
  let mut glob_suffix = PathBuf::new();
  let mut found_glob_component = false;

  for component in pattern_path.components() {
    let component_text = component.as_os_str().to_str().ok_or_else(|| {
      anyhow!(
        "configuration include pattern is not valid UTF-8: {}",
        pattern_path.display()
      )
    })?;
    let component_path = Path::new(component.as_os_str());
    if !found_glob_component && !has_glob_pattern(component_text) {
      fixed_prefix.push(component_path);
    } else {
      found_glob_component = true;
      glob_suffix.push(component_path);
    }
  }

  if !found_glob_component {
    return Ok(None);
  }

  let prefix = if fixed_prefix.as_os_str().is_empty() {
    Path::new(".")
  } else {
    fixed_prefix.as_path()
  };
  let mut canonical_pattern =
    canonicalize_local_config_file_target("configuration include pattern", prefix)?;
  canonical_pattern.push(glob_suffix);
  let canonical_pattern = canonical_pattern.to_str().ok_or_else(|| {
    anyhow!(
      "canonical configuration include pattern is not valid UTF-8: {}",
      canonical_pattern.display()
    )
  })?;
  Ok(Some(canonical_pattern.to_string()))
}

fn merge_toml_values(
  target: &mut toml::Value,
  source: toml::Value,
  key_path: &str,
) -> anyhow::Result<()> {
  match (target, source) {
    (toml::Value::Table(target), toml::Value::Table(source)) => {
      for (key, value) in source {
        let child_path = if key_path.is_empty() {
          key.clone()
        } else {
          format!("{key_path}.{key}")
        };

        if let Some(existing) = target.get_mut(&key) {
          merge_toml_values(existing, value, &child_path)?;
        } else {
          target.insert(key, value);
        }
      }
      Ok(())
    }
    (toml::Value::Array(target), toml::Value::Array(mut source)) => {
      target.append(&mut source);
      Ok(())
    }
    (target, source) => {
      let key = if key_path.is_empty() {
        "<root>"
      } else {
        key_path
      };
      bail!(
        "configuration key {key} is defined more than once across included TOML files or uses incompatible value types ({} vs {})",
        toml_type_name(target),
        toml_type_name(&source)
      );
    }
  }
}

fn toml_type_name(value: &toml::Value) -> &'static str {
  match value {
    toml::Value::String(_) => "string",
    toml::Value::Integer(_) => "integer",
    toml::Value::Float(_) => "float",
    toml::Value::Boolean(_) => "boolean",
    toml::Value::Datetime(_) => "datetime",
    toml::Value::Array(_) => "array",
    toml::Value::Table(_) => "table",
  }
}

pub(super) fn absolute_config_path(path: &Path) -> anyhow::Result<PathBuf> {
  if path.is_absolute() {
    Ok(path.to_path_buf())
  } else {
    Ok(
      std::env::current_dir()
        .context("failed to determine current working directory")?
        .join(path),
    )
  }
}

fn canonicalize_local_config_file(
  field_name: &str,
  path: &Path,
  canonical_base_dir: &Path,
  source_path: &Path,
) -> anyhow::Result<PathBuf> {
  let canonical_path = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;

  if !canonical_path.starts_with(canonical_base_dir) {
    bail!(
      "{field_name} in {} must stay within the declaring directory",
      source_path.display()
    );
  }

  Ok(canonical_path)
}

fn canonicalize_local_config_file_with_overrides(
  field_name: &str,
  path: &Path,
  canonical_base_dir: &Path,
  source_path: &Path,
  overrides: &HashMap<PathBuf, Option<String>>,
) -> anyhow::Result<PathBuf> {
  let canonical_path = match path.canonicalize() {
    Ok(path) => path,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      let canonical_path = canonicalize_local_config_file_target(field_name, path)?;
      if overrides.contains_key(&canonical_path) || overrides.contains_key(path) {
        canonical_path
      } else {
        return Err(error)
          .with_context(|| format!("failed to resolve {field_name} {}", path.display()));
      }
    }
    Err(error) => {
      return Err(error)
        .with_context(|| format!("failed to resolve {field_name} {}", path.display()));
    }
  };

  if !canonical_path.starts_with(canonical_base_dir) {
    bail!(
      "{field_name} in {} must stay within the declaring directory",
      source_path.display()
    );
  }

  Ok(canonical_path)
}
