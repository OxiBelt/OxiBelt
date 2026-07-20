//! Config-root confinement, canonicalization, and identifier validation.

use super::*;

pub(super) fn config_base_dir(path: &Path) -> anyhow::Result<PathBuf> {
  let absolute_path = absolute_config_path(path)?;

  Ok(
    absolute_path
      .parent()
      .unwrap_or_else(|| Path::new("."))
      .to_path_buf(),
  )
}

pub(super) struct ConfigPathRoots {
  pub(super) config_dir: PathBuf,
  pub(super) cert_dir: PathBuf,
  pub(super) oxirule_dir: PathBuf,
}

pub(super) fn config_path_roots(path: &Path) -> anyhow::Result<ConfigPathRoots> {
  let config_dir = config_base_dir(path)?;
  let layout_root = config_dir
    .parent()
    .unwrap_or_else(|| Path::new("."))
    .to_path_buf();

  Ok(ConfigPathRoots {
    config_dir,
    cert_dir: layout_root.join("cert"),
    oxirule_dir: layout_root.join("oxirule"),
  })
}

pub(crate) fn resolve_local_config_file_path(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  if path.is_absolute() {
    bail!("{field_name} must be a relative path under the configured directory");
  }

  validate_relative_path(field_name, path)?;
  Ok(base_dir.join(path))
}

pub(crate) fn canonicalize_local_config_file_target(
  field_name: &str,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  match path.canonicalize() {
    Ok(path) => Ok(path),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      canonicalize_missing_local_config_file_target(field_name, path)
    }
    Err(error) => {
      Err(error).with_context(|| format!("failed to resolve {field_name} {}", path.display()))
    }
  }
}

pub(super) fn canonicalize_missing_local_config_file_target(
  field_name: &str,
  path: &Path,
) -> anyhow::Result<PathBuf> {
  let mut missing_components = Vec::new();
  let mut current = path;
  loop {
    if current
      .try_exists()
      .with_context(|| format!("failed to inspect {field_name} {}", current.display()))?
    {
      let mut canonical = current
        .canonicalize()
        .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
      for component in missing_components.iter().rev() {
        canonical.push(component);
      }
      return Ok(canonical);
    }
    let file_name = current.file_name().ok_or_else(|| {
      anyhow!(
        "failed to resolve {field_name} {} because no existing ancestor was found",
        path.display()
      )
    })?;
    missing_components.push(PathBuf::from(file_name));
    current = current.parent().ok_or_else(|| {
      anyhow!(
        "failed to resolve {field_name} {} because no parent directory was found",
        path.display()
      )
    })?;
  }
}

pub(crate) fn resolve_existing_local_config_file_path_with_logical(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
  let resolved_path = resolve_local_config_file_path(field_name, base_dir, path)?;
  let canonical_base_dir = base_dir.canonicalize().with_context(|| {
    format!(
      "failed to resolve configured directory {}",
      base_dir.display()
    )
  })?;
  let canonical_path = resolved_path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", resolved_path.display()))?;

  if !canonical_path.starts_with(&canonical_base_dir) {
    bail!("{field_name} must stay within the configured directory");
  }
  ensure_regular_file(field_name, &canonical_path)?;

  Ok((canonical_path, resolved_path))
}

pub(crate) fn canonicalize_existing_file(field_name: &str, path: &Path) -> anyhow::Result<PathBuf> {
  let canonical_path = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
  ensure_regular_file(field_name, &canonical_path)?;

  Ok(canonical_path)
}

pub(super) fn ensure_regular_file(field_name: &str, path: &Path) -> anyhow::Result<()> {
  let metadata = path
    .metadata()
    .with_context(|| format!("failed to inspect {field_name} {}", path.display()))?;

  if !metadata.is_file() {
    bail!("{field_name} must point to a regular file");
  }

  Ok(())
}

pub(super) fn validate_relative_path(field_name: &str, path: &Path) -> anyhow::Result<()> {
  if path.as_os_str().is_empty() {
    bail!("{field_name} must not be empty");
  }

  for component in path.components() {
    match component {
      Component::Normal(_) => {}
      Component::CurDir | Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
        bail!(
          "{field_name} must not contain absolute, current-directory, or parent-directory components"
        );
      }
    }
  }

  Ok(())
}

pub(super) fn validate_optional_non_empty(
  field_name: &str,
  value: Option<&str>,
) -> anyhow::Result<()> {
  if matches!(value, Some(value) if value.trim().is_empty()) {
    bail!("{field_name} must not be empty");
  }
  Ok(())
}

pub(crate) fn quote_postgres_identifier_path(
  field_name: &str,
  value: &str,
) -> anyhow::Result<String> {
  validate_postgres_identifier_path(field_name, value)?;

  Ok(
    value
      .split('.')
      .map(|segment| format!("\"{segment}\""))
      .collect::<Vec<_>>()
      .join("."),
  )
}

pub(super) fn validate_postgres_identifier_path(
  field_name: &str,
  value: &str,
) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field_name} must not be empty");
  }

  let parts = value.split('.').collect::<Vec<_>>();
  if parts.len() > 2 || parts.iter().any(|part| part.is_empty()) {
    bail!("{field_name} must be an unqualified table name or schema-qualified table name");
  }

  for part in parts {
    validate_postgres_identifier(field_name, part)?;
  }

  Ok(())
}

pub(super) fn validate_postgres_identifier(field_name: &str, value: &str) -> anyhow::Result<()> {
  let mut bytes = value.bytes();
  let Some(first) = bytes.next() else {
    bail!("{field_name} must not contain empty identifier segments");
  };
  if !(first.is_ascii_alphabetic() || first == b'_') {
    bail!("{field_name} identifier segments must start with an ASCII letter or underscore");
  }
  if value.len() > 63 {
    bail!("{field_name} identifier segments must be 63 bytes or shorter");
  }
  if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
    bail!(
      "{field_name} identifier segments must contain only ASCII letters, digits, or underscores"
    );
  }
  Ok(())
}
