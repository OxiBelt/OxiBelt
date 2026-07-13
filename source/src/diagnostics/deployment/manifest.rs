//! Bounded, non-symlink deployment input loading.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use kube::{Config, config::KubeConfigOptions};
use serde_json::Value;

use super::{
  KubernetesDoctorOptions, MAX_MANIFEST_BYTES, MAX_MANIFEST_DOCUMENTS, MAX_MANIFEST_FILES, Manifest,
};

pub(super) fn collect_manifest_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
  let metadata = fs::symlink_metadata(root).with_context(|| {
    format!(
      "failed to inspect rendered manifest directory {}",
      root.display()
    )
  })?;
  if metadata.file_type().is_symlink() {
    bail!("rendered manifest directory must not be a symlink");
  }
  if !metadata.is_dir() {
    bail!(
      "rendered manifest path {} is not a directory",
      root.display()
    );
  }
  let mut directories = vec![root.to_path_buf()];
  let mut files = Vec::new();
  while let Some(directory) = directories.pop() {
    for entry in fs::read_dir(&directory).with_context(|| {
      format!(
        "failed to read rendered manifest directory {}",
        directory.display()
      )
    })? {
      let entry = entry?;
      let path = entry.path();
      let metadata = fs::symlink_metadata(&path).with_context(|| {
        format!(
          "failed to inspect rendered manifest input {}",
          path.display()
        )
      })?;
      if metadata.file_type().is_symlink() {
        bail!(
          "rendered manifest input must not be a symlink: {}",
          path.display()
        );
      }
      if metadata.is_dir() {
        directories.push(path);
      } else if metadata.is_file() && is_yaml_path(&path) {
        files.push(path);
      }
    }
  }
  files.sort();
  if files.len() > MAX_MANIFEST_FILES {
    bail!("rendered manifest directory exceeds the {MAX_MANIFEST_FILES} file inspection limit");
  }
  Ok(files)
}

pub(super) fn read_bounded_file(path: &Path, total_bytes: &mut usize) -> anyhow::Result<String> {
  let metadata =
    fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
  let size = usize::try_from(metadata.len()).context("manifest file size does not fit usize")?;
  *total_bytes = total_bytes.saturating_add(size);
  if *total_bytes > MAX_MANIFEST_BYTES {
    bail!("rendered manifest input exceeds the {MAX_MANIFEST_BYTES} byte inspection limit");
  }
  let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
  if bytes.len() > size || bytes.len() > MAX_MANIFEST_BYTES {
    bail!(
      "manifest file grew beyond the inspection limit while reading {}",
      path.display()
    );
  }
  String::from_utf8(bytes).with_context(|| format!("manifest {} is not UTF-8 YAML", path.display()))
}

pub(super) fn append_yaml_manifests(
  manifests: &mut Vec<Manifest>,
  source: &str,
  default_namespace: &str,
  raw: &str,
) -> anyhow::Result<()> {
  let values = serde_saphyr::from_multiple::<Value>(raw)
    .with_context(|| format!("failed to parse Kubernetes YAML from {source}"))?;
  for (index, value) in values.into_iter().enumerate() {
    append_manifest_value(manifests, source, default_namespace, index + 1, value)?;
  }
  if manifests.len() > MAX_MANIFEST_DOCUMENTS {
    bail!("rendered input exceeds the {MAX_MANIFEST_DOCUMENTS} document inspection limit");
  }
  Ok(())
}

fn append_manifest_value(
  manifests: &mut Vec<Manifest>,
  source: &str,
  default_namespace: &str,
  document: usize,
  value: Value,
) -> anyhow::Result<()> {
  if value.is_null() {
    return Ok(());
  }
  if value.get("kind").and_then(Value::as_str) == Some("List") {
    let items = value
      .get("items")
      .and_then(Value::as_array)
      .ok_or_else(|| {
        anyhow::anyhow!("{source} document {document} has kind List without an items array")
      })?;
    if manifests.len().saturating_add(items.len()) > MAX_MANIFEST_DOCUMENTS {
      bail!("rendered input exceeds the {MAX_MANIFEST_DOCUMENTS} document inspection limit");
    }
    for (index, item) in items.iter().cloned().enumerate() {
      manifests.push(Manifest {
        source: format!("{source}#document-{document}/item-{}", index + 1),
        document,
        default_namespace: default_namespace.to_string(),
        value: item,
      });
    }
  } else {
    manifests.push(Manifest {
      source: source.to_string(),
      document,
      default_namespace: default_namespace.to_string(),
      value,
    });
  }
  Ok(())
}

pub(super) fn validate_chart_tree(chart: &Path) -> anyhow::Result<()> {
  let metadata = fs::symlink_metadata(chart)
    .with_context(|| format!("failed to inspect Helm chart {}", chart.display()))?;
  if metadata.file_type().is_symlink() || !metadata.is_dir() {
    bail!("Helm chart must be a local non-symlink directory");
  }
  ensure_regular_file(&chart.join("Chart.yaml"), "Helm Chart.yaml")?;
  let mut directories = vec![chart.to_path_buf()];
  let mut files = 0_usize;
  let mut bytes = 0_usize;
  while let Some(directory) = directories.pop() {
    for entry in fs::read_dir(&directory).with_context(|| {
      format!(
        "failed to read Helm chart directory {}",
        directory.display()
      )
    })? {
      let entry = entry?;
      let path = entry.path();
      let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("failed to inspect Helm chart input {}", path.display()))?;
      if metadata.file_type().is_symlink() {
        bail!("Helm chart input must not be a symlink: {}", path.display());
      }
      if metadata.is_dir() {
        directories.push(path);
      } else if metadata.is_file() {
        files = files.saturating_add(1);
        bytes = bytes.saturating_add(usize::try_from(metadata.len()).unwrap_or(usize::MAX));
        if files > MAX_MANIFEST_FILES || bytes > MAX_MANIFEST_BYTES {
          bail!("Helm chart exceeds doctor inspection safety limits");
        }
      }
    }
  }
  Ok(())
}

pub(super) fn ensure_regular_file(path: &Path, label: &str) -> anyhow::Result<()> {
  let metadata = fs::symlink_metadata(path)
    .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
  if metadata.file_type().is_symlink() || !metadata.is_file() {
    bail!(
      "{label} must be a regular non-symlink file: {}",
      path.display()
    );
  }
  Ok(())
}

pub(super) fn validate_helm_identifier(label: &str, value: &str) -> anyhow::Result<()> {
  let valid = !value.is_empty()
    && value.len() <= 63
    && value
      .bytes()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    && !value.starts_with('-')
    && !value.ends_with('-');
  if !valid {
    bail!("Helm {label} must be a lowercase DNS label");
  }
  Ok(())
}

pub(super) async fn load_safe_kubernetes_config(
  options: &KubernetesDoctorOptions,
) -> anyhow::Result<Config> {
  let kubeconfig_paths = configured_kubeconfig_paths()?;
  if kubeconfig_paths.iter().all(|path| !path.exists()) {
    if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
      return Config::incluster().context("failed to load in-cluster Kubernetes configuration");
    }
    bail!("no readable kubeconfig was found and no in-cluster service account is available");
  }
  reject_command_based_credentials(&kubeconfig_paths)?;
  Config::from_kubeconfig(&KubeConfigOptions {
    context: options.context.clone(),
    ..Default::default()
  })
  .await
  .context("failed to load Kubernetes configuration")
}

fn configured_kubeconfig_paths() -> anyhow::Result<Vec<PathBuf>> {
  if let Some(value) = std::env::var_os("KUBECONFIG") {
    let paths = std::env::split_paths(&value)
      .filter(|path| !path.as_os_str().is_empty())
      .collect::<Vec<_>>();
    if !paths.is_empty() {
      return Ok(paths);
    }
  }
  let home = std::env::var_os("HOME")
    .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot locate the default kubeconfig"))?;
  Ok(vec![PathBuf::from(home).join(".kube/config")])
}

fn reject_command_based_credentials(paths: &[PathBuf]) -> anyhow::Result<()> {
  for path in paths {
    ensure_regular_file(path, "kubeconfig")?;
    let bytes =
      fs::read(path).with_context(|| format!("failed to read kubeconfig {}", path.display()))?;
    if bytes.len() > MAX_MANIFEST_BYTES {
      bail!(
        "kubeconfig {} exceeds the doctor inspection limit",
        path.display()
      );
    }
    let raw = std::str::from_utf8(&bytes)
      .with_context(|| format!("kubeconfig {} is not UTF-8 YAML", path.display()))?;
    for value in serde_saphyr::from_multiple::<Value>(raw)
      .with_context(|| format!("failed to parse kubeconfig {}", path.display()))?
    {
      if contains_command_credential(&value) {
        bail!(
          "kubeconfig {} contains exec or auth-provider credentials; doctor refuses command-based Kubernetes authentication",
          path.display()
        );
      }
    }
  }
  Ok(())
}

pub(super) fn contains_command_credential(value: &Value) -> bool {
  match value {
    Value::Array(values) => values.iter().any(contains_command_credential),
    Value::Object(values) => values.iter().any(|(key, value)| {
      key == "exec" || key == "auth-provider" || contains_command_credential(value)
    }),
    _ => false,
  }
}

pub(super) fn safe_path_label(path: &Path) -> String {
  path
    .to_string_lossy()
    .chars()
    .flat_map(char::escape_default)
    .collect()
}

fn is_yaml_path(path: &Path) -> bool {
  matches!(
    path.extension().and_then(|extension| extension.to_str()),
    Some("yaml" | "yml")
  )
}
