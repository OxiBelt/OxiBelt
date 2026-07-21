//! TOML loading, include processing, and runtime override application.
//! Includes are resolved deliberately so config assembly cannot escape expected roots.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};

use super::provenance::{index_document_origins, shift_array_origins};
use super::{
  ConfigOriginIndex, ConfigOriginKind, canonicalize_local_config_file_target,
  resolve_local_config_file_path,
};

pub(super) struct LoadedToml {
  pub(super) value: toml::Value,
  pub(super) files: Vec<PathBuf>,
  pub(super) origins: ConfigOriginIndex,
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
  let origin_kind = if stack.len() == 1 {
    ConfigOriginKind::Entry
  } else {
    ConfigOriginKind::Include
  };
  let value_origins = index_document_origins(&value, &canonical_path, origin_kind);
  let base_dir = absolute_path.parent().unwrap_or_else(|| Path::new("."));

  let mut merged = toml::Value::Table(toml::map::Map::new());
  let mut merged_origins = ConfigOriginIndex::new();
  for entry in include_entries {
    for include_path in expand_include_entry(&entry, base_dir, &absolute_path, overrides)? {
      let included = load_toml_document(&include_path, overrides, stack)?;
      files.extend(included.files);
      merge_toml_values(
        &mut merged,
        included.value,
        "",
        &mut merged_origins,
        included.origins,
      )?;
    }
  }
  merge_toml_values(&mut merged, value, "", &mut merged_origins, value_origins)?;

  stack.pop();
  files.sort();
  files.dedup();
  Ok(LoadedToml {
    value: merged,
    files,
    origins: merged_origins,
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
  target_origins: &mut ConfigOriginIndex,
  mut source_origins: ConfigOriginIndex,
) -> anyhow::Result<()> {
  merge_toml_value_tree(target, source, key_path, &mut source_origins)?;
  target_origins.extend(source_origins);
  Ok(())
}

fn merge_toml_value_tree(
  target: &mut toml::Value,
  source: toml::Value,
  key_path: &str,
  source_origins: &mut ConfigOriginIndex,
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
          merge_toml_value_tree(existing, value, &child_path, source_origins)?;
        } else {
          target.insert(key, value);
        }
      }
      Ok(())
    }
    (toml::Value::Array(target), toml::Value::Array(mut source)) => {
      shift_array_origins(source_origins, key_path, target.len());
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

#[cfg(feature = "fuzzing")]
fn deterministic_toml_values_equal(left: &toml::Value, right: &toml::Value) -> bool {
  match (left, right) {
    (toml::Value::Float(left), toml::Value::Float(right)) => left.to_bits() == right.to_bits(),
    (toml::Value::Array(left), toml::Value::Array(right)) => {
      left.len() == right.len()
        && left
          .iter()
          .zip(right)
          .all(|(left, right)| deterministic_toml_values_equal(left, right))
    }
    (toml::Value::Table(left), toml::Value::Table(right)) => {
      left.len() == right.len()
        && left.iter().all(|(key, left)| {
          right
            .get(key)
            .is_some_and(|right| deterministic_toml_values_equal(left, right))
        })
    }
    _ => left == right,
  }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_virtual_toml_documents(data: &[u8]) {
  const MAX_TOTAL_BYTES: usize = 64 * 1024;
  let data = &data[..data.len().min(MAX_TOTAL_BYTES)];
  let Some((entry, documents)) = decode_text_virtual_documents(data)
    .or_else(|| decode_virtual_documents(data))
    .or_else(|| decode_single_virtual_document(data))
  else {
    return;
  };
  let first = load_virtual_toml_document(&entry, &documents, &mut Vec::new());
  let second = load_virtual_toml_document(&entry, &documents, &mut Vec::new());
  match (first, second) {
    (Ok(first), Ok(second)) => {
      assert!(
        deterministic_toml_values_equal(&first.0, &second.0),
        "virtual include loading was not deterministic: left={:?}, right={:?}",
        first.0,
        second.0
      );
      assert_eq!(
        first.1, second.1,
        "virtual include order was not deterministic"
      );
      let _: Result<super::Config, _> = first.0.try_into();
    }
    (Err(first), Err(second)) => {
      assert_eq!(
        first.to_string(),
        second.to_string(),
        "virtual include errors were not deterministic"
      );
    }
    _ => panic!("virtual include loading changed result for identical input"),
  }
}

#[cfg(feature = "fuzzing")]
fn decode_text_virtual_documents(data: &[u8]) -> Option<(PathBuf, HashMap<PathBuf, String>)> {
  const ROOT: &str = "/oxibelt-fuzz-config";
  const MARKER: &str = "@@document ";
  const MAX_DOCUMENT_BYTES: usize = 8 * 1024;
  let raw = std::str::from_utf8(data).ok()?;
  if !raw.starts_with(MARKER) {
    return None;
  }
  let mut entry = None;
  let mut current_path = None;
  let mut current_document = String::new();
  let mut documents = HashMap::new();
  for line in raw.lines() {
    if let Some(name) = line.strip_prefix(MARKER) {
      if let Some(path) = current_path.take() {
        if current_document.len() > MAX_DOCUMENT_BYTES {
          return None;
        }
        documents.insert(path, std::mem::take(&mut current_document));
      }
      let path = Path::new(ROOT).join(safe_virtual_relative_path(name.trim())?);
      entry.get_or_insert_with(|| path.clone());
      current_path = Some(path);
    } else {
      current_document.push_str(line);
      current_document.push('\n');
    }
  }
  if let Some(path) = current_path {
    if current_document.len() > MAX_DOCUMENT_BYTES {
      return None;
    }
    documents.insert(path, current_document);
  }
  (documents.len() <= 8).then_some((entry?, documents))
}

#[cfg(feature = "fuzzing")]
fn decode_single_virtual_document(data: &[u8]) -> Option<(PathBuf, HashMap<PathBuf, String>)> {
  const ENTRY: &str = "/oxibelt-fuzz-config/main.toml";
  let raw = std::str::from_utf8(data).ok()?;
  let entry = PathBuf::from(ENTRY);
  Some((entry.clone(), HashMap::from([(entry, raw.to_string())])))
}

#[cfg(feature = "fuzzing")]
fn decode_virtual_documents(data: &[u8]) -> Option<(PathBuf, HashMap<PathBuf, String>)> {
  const ROOT: &str = "/oxibelt-fuzz-config";
  const MAX_DOCUMENTS: usize = 8;
  const MAX_DOCUMENT_BYTES: usize = 8 * 1024;
  const MAX_NAME_BYTES: usize = 64;

  let mut offset = 0_usize;
  let count = usize::from(*data.get(offset)? % MAX_DOCUMENTS as u8).saturating_add(1);
  offset += 1;
  let mut documents = HashMap::new();
  let mut entry = None;
  for _ in 0..count {
    let name_len = usize::from(*data.get(offset)?).min(MAX_NAME_BYTES);
    offset += 1;
    let name_end = offset.checked_add(name_len)?;
    let name = std::str::from_utf8(data.get(offset..name_end)?).ok()?;
    offset = name_end;
    let length_bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    offset += 2;
    let document_len = usize::from(u16::from_be_bytes(length_bytes)).min(MAX_DOCUMENT_BYTES);
    let document_end = offset.checked_add(document_len)?;
    let raw = std::str::from_utf8(data.get(offset..document_end)?).ok()?;
    offset = document_end;
    let relative = safe_virtual_relative_path(name)?;
    let path = Path::new(ROOT).join(relative);
    if entry.is_none() {
      entry = Some(path.clone());
    }
    documents.insert(path, raw.to_string());
  }
  Some((entry?, documents))
}

#[cfg(feature = "fuzzing")]
fn safe_virtual_relative_path(raw: &str) -> Option<PathBuf> {
  let path = Path::new(raw);
  if raw.is_empty()
    || path.is_absolute()
    || path
      .components()
      .any(|component| !matches!(component, std::path::Component::Normal(_)))
  {
    return None;
  }
  Some(path.to_path_buf())
}

#[cfg(feature = "fuzzing")]
fn load_virtual_toml_document(
  path: &Path,
  documents: &HashMap<PathBuf, String>,
  stack: &mut Vec<PathBuf>,
) -> anyhow::Result<(toml::Value, Vec<PathBuf>)> {
  const ROOT: &str = "/oxibelt-fuzz-config";
  if !path.starts_with(ROOT) {
    bail!("virtual configuration path escaped its root");
  }
  if let Some(index) = stack.iter().position(|entry| entry == path) {
    let mut cycle = stack[index..]
      .iter()
      .map(|entry| entry.display().to_string())
      .collect::<Vec<_>>();
    cycle.push(path.display().to_string());
    bail!(
      "configuration include cycle detected: {}",
      cycle.join(" -> ")
    );
  }
  let raw = documents
    .get(path)
    .ok_or_else(|| anyhow!("virtual configuration document is missing"))?;
  stack.push(path.to_path_buf());
  let mut value: toml::Value = toml::from_str(raw)?;
  let includes = take_include_entries(&mut value, path)?;
  let origin_kind = if stack.len() == 1 {
    ConfigOriginKind::Entry
  } else {
    ConfigOriginKind::Include
  };
  let value_origins = index_document_origins(&value, path, origin_kind);
  let base_dir = path.parent().unwrap_or_else(|| Path::new(ROOT));
  let mut merged = toml::Value::Table(toml::map::Map::new());
  let mut merged_origins = ConfigOriginIndex::new();
  let mut files = vec![path.to_path_buf()];

  for include in includes {
    if include.trim().is_empty() || Path::new(&include).is_absolute() {
      bail!("virtual configuration include is invalid");
    }
    let pattern_path = base_dir.join(&include);
    if pattern_path
      .components()
      .any(|component| matches!(component, std::path::Component::ParentDir))
      || !pattern_path.starts_with(ROOT)
    {
      bail!("virtual configuration include escaped its root");
    }
    let pattern = glob::Pattern::new(pattern_path.to_string_lossy().as_ref())?;
    let mut matches = documents
      .keys()
      .filter(|candidate| pattern.matches_path(candidate))
      .cloned()
      .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    if matches.is_empty() && !has_glob_pattern(&include) {
      bail!("virtual configuration include is missing");
    }
    for included_path in matches {
      let (included, included_files) =
        load_virtual_toml_document(&included_path, documents, stack)?;
      files.extend(included_files);
      let included_origins =
        index_document_origins(&included, &included_path, ConfigOriginKind::Include);
      merge_toml_values(
        &mut merged,
        included,
        "",
        &mut merged_origins,
        included_origins,
      )?;
    }
  }
  merge_toml_values(&mut merged, value, "", &mut merged_origins, value_origins)?;
  stack.pop();
  files.sort();
  files.dedup();
  Ok((merged, files))
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

#[cfg(all(test, feature = "fuzzing"))]
mod fuzz_tests {
  use super::*;

  #[test]
  fn virtual_documents_expand_sorted_includes_without_filesystem_access() {
    let raw = b"@@document main.toml\ninclude = ['routes/*.toml']\n[server]\nworkers = 1\n@@document routes/b.toml\n[[routes]]\nname = 'b'\n@@document routes/a.toml\n[[routes]]\nname = 'a'\n";
    let (entry, documents) =
      decode_text_virtual_documents(raw).expect("virtual documents should decode");
    let (value, files) = load_virtual_toml_document(&entry, &documents, &mut Vec::new())
      .expect("virtual includes should load");
    assert_eq!(files.len(), 3);
    let routes = value
      .get("routes")
      .and_then(toml::Value::as_array)
      .expect("routes should merge as an array");
    assert_eq!(
      routes[0].get("name").and_then(toml::Value::as_str),
      Some("a")
    );
    assert_eq!(
      routes[1].get("name").and_then(toml::Value::as_str),
      Some("b")
    );
  }

  #[test]
  fn virtual_documents_compare_nan_by_exact_float_representation() {
    fuzz_virtual_toml_documents(b"i=-nan");

    let nan = toml::Value::Float(f64::from_bits(0x7ff8_0000_0000_0001));
    let different_nan = toml::Value::Float(f64::from_bits(0x7ff8_0000_0000_0002));
    assert!(deterministic_toml_values_equal(&nan, &nan));
    assert!(!deterministic_toml_values_equal(&nan, &different_nan));
  }
}
