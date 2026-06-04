use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::Value;

use super::model::KubernetesObject;

pub fn load_objects(path: &Path) -> anyhow::Result<Vec<KubernetesObject>> {
  let mut files = Vec::new();
  collect_input_files(path, &mut files)?;
  let mut objects = Vec::new();
  for file in files {
    objects.extend(load_file_objects(&file)?);
  }
  Ok(objects)
}

pub fn write_rendered(output: &str, content: &str) -> anyhow::Result<()> {
  if output == "-" {
    print!("{content}");
    return Ok(());
  }
  fs::write(output, content).with_context(|| format!("failed to write rendered TOML to {output}"))
}

fn collect_input_files(path: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
  if path.is_file() {
    files.push(path.to_path_buf());
    return Ok(());
  }
  if !path.is_dir() {
    bail!("input {} is neither a file nor directory", path.display());
  }
  for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
    let entry = entry?;
    let path = entry.path();
    if path.is_dir() {
      collect_input_files(&path, files)?;
    } else if is_manifest_file(&path) {
      files.push(path);
    }
  }
  files.sort();
  Ok(())
}

fn is_manifest_file(path: &Path) -> bool {
  matches!(
    path.extension().and_then(|value| value.to_str()),
    Some("yaml" | "yml" | "json")
  )
}

fn load_file_objects(path: &Path) -> anyhow::Result<Vec<KubernetesObject>> {
  let raw =
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
  if path.extension().and_then(|value| value.to_str()) == Some("json") {
    let value: Value = serde_json::from_str(&raw)
      .with_context(|| format!("failed to parse JSON from {}", path.display()))?;
    return KubernetesObject::from_value(value);
  }
  let mut objects = Vec::new();
  for document in serde_yaml::Deserializer::from_str(&raw) {
    let value = Value::deserialize(document)
      .with_context(|| format!("failed to parse YAML from {}", path.display()))?;
    objects.extend(KubernetesObject::from_value(value)?);
  }
  Ok(objects)
}
