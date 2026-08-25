use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, bail};
use serde_json::Value;

pub(crate) const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;

pub(crate) fn read_bounded(path: &Path, limit: u64, label: &str) -> anyhow::Result<Vec<u8>> {
  read_bounded_inner(path, limit, label, false)
}

pub(crate) fn read_integrity_bounded(
  path: &Path,
  limit: u64,
  label: &str,
) -> anyhow::Result<Vec<u8>> {
  read_bounded_inner(path, limit, label, true)
}

fn read_bounded_inner(
  path: &Path,
  limit: u64,
  label: &str,
  protect_integrity: bool,
) -> anyhow::Result<Vec<u8>> {
  let file =
    File::open(path).with_context(|| format!("failed to open {label} {}", path.display()))?;
  let metadata = file
    .metadata()
    .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
  if !metadata.is_file() {
    bail!("{label} {} must be a regular file", path.display());
  }
  validate_integrity_metadata(path, label, &metadata, protect_integrity)?;
  if metadata.len() > limit {
    bail!("{label} {} exceeds {limit} bytes", path.display());
  }
  let capacity = usize::try_from(metadata.len()).context("input size does not fit memory")?;
  let mut bytes = Vec::with_capacity(capacity);
  file
    .take(limit.saturating_add(1))
    .read_to_end(&mut bytes)
    .with_context(|| format!("failed to read {label} {}", path.display()))?;
  if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
    bail!("{label} {} exceeds {limit} bytes", path.display());
  }
  Ok(bytes)
}

#[cfg(unix)]
fn validate_integrity_metadata(
  path: &Path,
  label: &str,
  metadata: &std::fs::Metadata,
  protect_integrity: bool,
) -> anyhow::Result<()> {
  use std::os::unix::fs::MetadataExt as _;

  if protect_integrity && metadata.mode() & 0o022 != 0 {
    bail!(
      "{label} {} must not be writable by group or other",
      path.display()
    );
  }
  Ok(())
}

#[cfg(not(unix))]
fn validate_integrity_metadata(
  _path: &Path,
  _label: &str,
  _metadata: &std::fs::Metadata,
  _protect_integrity: bool,
) -> anyhow::Result<()> {
  Ok(())
}

pub(crate) fn write_new(path: &Path, bytes: &[u8], label: &str) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .filter(|parent| !parent.as_os_str().is_empty())
    .unwrap_or_else(|| Path::new("."));
  let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
    format!(
      "failed to create temporary {label} beside {}",
      path.display()
    )
  })?;
  temporary
    .write_all(bytes)
    .with_context(|| format!("failed to write {label} {}", path.display()))?;
  temporary
    .as_file()
    .sync_all()
    .with_context(|| format!("failed to sync {label} {}", path.display()))?;
  temporary
    .persist_noclobber(path)
    .map_err(|error| error.error)
    .with_context(|| format!("failed to create {label} {}", path.display()))?;
  sync_parent_directory(path, label)?;
  Ok(())
}

#[cfg(unix)]
pub(crate) fn sync_parent_directory(path: &Path, label: &str) -> anyhow::Result<()> {
  let parent = path
    .parent()
    .filter(|parent| !parent.as_os_str().is_empty())
    .unwrap_or_else(|| Path::new("."));
  std::fs::File::open(parent)
    .with_context(|| format!("failed to open {label} directory {}", parent.display()))?
    .sync_all()
    .with_context(|| format!("failed to sync {label} directory {}", parent.display()))
}

#[cfg(not(unix))]
pub(crate) fn sync_parent_directory(_path: &Path, _label: &str) -> anyhow::Result<()> {
  Ok(())
}

pub(crate) fn canonical_json_bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
  let mut output = Vec::new();
  write_canonical_json(value, &mut output)?;
  Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> anyhow::Result<()> {
  match value {
    Value::Null => output.extend_from_slice(b"null"),
    Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
    Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
    Value::String(value) => serde_json::to_writer(output, value)?,
    Value::Array(values) => {
      output.push(b'[');
      for (index, value) in values.iter().enumerate() {
        if index != 0 {
          output.push(b',');
        }
        write_canonical_json(value, output)?;
      }
      output.push(b']');
    }
    Value::Object(values) => {
      output.push(b'{');
      let mut keys = values.keys().collect::<Vec<_>>();
      keys.sort_unstable();
      for (index, key) in keys.into_iter().enumerate() {
        if index != 0 {
          output.push(b',');
        }
        serde_json::to_writer(&mut *output, key)?;
        output.push(b':');
        write_canonical_json(&values[key], output)?;
      }
      output.push(b'}');
    }
  }
  Ok(())
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
  use std::fmt::Write as _;

  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
  }
  output
}

pub(crate) fn parse_hex_32(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
  let value = value.strip_prefix("sha256:").unwrap_or(value);
  if value.len() != 64
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    bail!("{label} must contain 64 lowercase hexadecimal characters");
  }
  let mut output = [0_u8; 32];
  for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
    let pair = std::str::from_utf8(pair).context("invalid hexadecimal encoding")?;
    output[index] = u8::from_str_radix(pair, 16).context("invalid hexadecimal encoding")?;
  }
  Ok(output)
}

pub(crate) fn validate_identifier(value: &str, label: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value.len() > 128
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
  {
    bail!("{label} must be a bounded portable identifier");
  }
  Ok(())
}
