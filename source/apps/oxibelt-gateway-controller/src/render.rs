use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde_json::Value;

use super::model::KubernetesObject;

const MAX_INPUT_FILES: usize = 1_024;
const MAX_INPUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INPUT_OBJECTS: usize = 10_000;

pub fn load_objects(path: &Path) -> anyhow::Result<Vec<KubernetesObject>> {
  let mut files = Vec::new();
  collect_input_files(path, &mut files)?;
  let mut objects = Vec::new();
  for file in files {
    objects.extend(load_file_objects(&file)?);
    if objects.len() > MAX_INPUT_OBJECTS {
      bail!("offline input contains more than {MAX_INPUT_OBJECTS} Kubernetes objects");
    }
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
  let metadata =
    fs::symlink_metadata(path).with_context(|| format!("failed to inspect {}", path.display()))?;
  if metadata.file_type().is_symlink() {
    bail!(
      "offline input must not contain symbolic links: {}",
      path.display()
    );
  }
  if metadata.is_file() {
    if metadata.len() > MAX_INPUT_FILE_BYTES {
      bail!(
        "offline input file {} exceeds the {MAX_INPUT_FILE_BYTES}-byte limit",
        path.display()
      );
    }
    files.push(path.to_path_buf());
    if files.len() > MAX_INPUT_FILES {
      bail!("offline input contains more than {MAX_INPUT_FILES} manifest files");
    }
    return Ok(());
  }
  if !metadata.is_dir() {
    bail!("input {} is neither a file nor directory", path.display());
  }
  for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
    let entry = entry?;
    let path = entry.path();
    let file_type = entry
      .file_type()
      .with_context(|| format!("failed to inspect {}", path.display()))?;
    if file_type.is_symlink() {
      bail!(
        "offline input must not contain symbolic links: {}",
        path.display()
      );
    }
    if file_type.is_dir() || (file_type.is_file() && is_manifest_file(&path)) {
      collect_input_files(&path, files)?;
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
  let file = fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
  let metadata = file
    .metadata()
    .with_context(|| format!("failed to inspect opened input {}", path.display()))?;
  if metadata.len() > MAX_INPUT_FILE_BYTES {
    bail!(
      "offline input file {} exceeds the {MAX_INPUT_FILE_BYTES}-byte limit",
      path.display()
    );
  }
  let mut bytes = Vec::new();
  file
    .take(MAX_INPUT_FILE_BYTES + 1)
    .read_to_end(&mut bytes)
    .with_context(|| format!("failed to read {}", path.display()))?;
  if bytes.len() as u64 > MAX_INPUT_FILE_BYTES {
    bail!(
      "offline input file {} exceeds the {MAX_INPUT_FILE_BYTES}-byte limit",
      path.display()
    );
  }
  let raw = String::from_utf8(bytes)
    .with_context(|| format!("offline input {} must be UTF-8", path.display()))?;
  if path.extension().and_then(|value| value.to_str()) == Some("json") {
    let value: Value = serde_json::from_str(&raw)
      .with_context(|| format!("failed to parse JSON from {}", path.display()))?;
    return KubernetesObject::from_value(value);
  }
  let mut objects = Vec::new();
  for value in serde_saphyr::from_multiple::<Value>(&raw)
    .with_context(|| format!("failed to parse YAML from {}", path.display()))?
  {
    objects.extend(KubernetesObject::from_value(value)?);
  }
  Ok(objects)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
      "oxibelt-gateway-controller-render-{name}-{}",
      std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("temporary render directory should be created");
    path
  }

  #[cfg(unix)]
  #[test]
  fn directory_input_rejects_manifest_and_directory_symlinks() {
    use std::os::unix::fs::symlink;

    let root = temp_dir("symlink");
    let outside = root.with_extension("outside.yaml");
    fs::write(
      &outside,
      "apiVersion: v1\nkind: Service\nmetadata: {name: outside}\n",
    )
    .expect("outside manifest should be written");
    symlink(&outside, root.join("linked.yaml")).expect("manifest symlink should be created");
    let error = load_objects(&root).expect_err("manifest symlink must be rejected");
    assert!(error.to_string().contains("symbolic links"));
    fs::remove_file(root.join("linked.yaml")).expect("manifest symlink should be removed");

    let nested = root.with_extension("nested");
    fs::create_dir_all(&nested).expect("nested directory should be created");
    symlink(&nested, root.join("linked-directory")).expect("directory symlink should be created");
    let error = load_objects(&root).expect_err("directory symlink must be rejected");
    assert!(error.to_string().contains("symbolic links"));

    fs::remove_dir_all(&root).expect("temporary directory should be removed");
    fs::remove_dir_all(&nested).expect("nested directory should be removed");
    fs::remove_file(&outside).expect("outside manifest should be removed");
  }

  #[test]
  fn directory_input_enforces_per_file_size_and_file_count() {
    let oversized_root = temp_dir("oversized");
    let oversized = oversized_root.join("oversized.yaml");
    let file = fs::File::create(&oversized).expect("oversized manifest should be created");
    file
      .set_len(MAX_INPUT_FILE_BYTES + 1)
      .expect("oversized manifest should be extended sparsely");
    let error = load_objects(&oversized_root).expect_err("oversized manifest must be rejected");
    assert!(error.to_string().contains("exceeds the"));
    fs::remove_dir_all(&oversized_root).expect("oversized directory should be removed");

    let many_root = temp_dir("many");
    for index in 0..=MAX_INPUT_FILES {
      fs::write(many_root.join(format!("{index:04}.yaml")), "")
        .expect("manifest should be written");
    }
    let error = load_objects(&many_root).expect_err("excess manifests must be rejected");
    assert!(error.to_string().contains("more than 1024 manifest files"));
    fs::remove_dir_all(&many_root).expect("many-file directory should be removed");
  }
}
