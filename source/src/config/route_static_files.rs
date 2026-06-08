//! Per-route static-file convenience options.
//! Validation keeps candidate paths simple before the static resolver applies root confinement.

use std::collections::HashMap;

use anyhow::{Context, bail};
use http::HeaderValue;
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteStaticFilesConfig {
  #[serde(default)]
  pub directory_index: Vec<String>,
  #[serde(default)]
  pub try_files: Vec<String>,
  #[serde(default)]
  pub spa_fallback: Option<String>,
  #[serde(default)]
  pub precompressed: Vec<StaticPrecompressedEncoding>,
  #[serde(default)]
  pub cache_control: Option<String>,
  #[serde(default)]
  pub cache_control_by_extension: HashMap<String, String>,
  #[serde(default)]
  pub mime_overrides: HashMap<String, String>,
  #[serde(default)]
  pub error_pages: RouteStaticFileErrorPagesConfig,
}

impl RouteStaticFilesConfig {
  pub fn has_convenience_options(&self) -> bool {
    !self.directory_index.is_empty()
      || !self.try_files.is_empty()
      || self.spa_fallback.is_some()
      || !self.precompressed.is_empty()
      || self.cache_control.is_some()
      || !self.cache_control_by_extension.is_empty()
      || !self.mime_overrides.is_empty()
      || self.error_pages.has_pages()
  }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StaticPrecompressedEncoding {
  Br,
  Zstd,
  Gzip,
}

impl StaticPrecompressedEncoding {
  pub fn content_encoding(self) -> &'static str {
    match self {
      Self::Br => "br",
      Self::Zstd => "zstd",
      Self::Gzip => "gzip",
    }
  }

  pub fn extension(self) -> &'static str {
    match self {
      Self::Br => "br",
      Self::Zstd => "zst",
      Self::Gzip => "gz",
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteStaticFileErrorPagesConfig {
  #[serde(default)]
  pub not_found: Option<String>,
  #[serde(default)]
  pub server_error: Option<String>,
}

impl RouteStaticFileErrorPagesConfig {
  fn has_pages(&self) -> bool {
    self.not_found.is_some() || self.server_error.is_some()
  }
}

pub(crate) fn validate_route_static_files_config(
  route_name: &str,
  config: &RouteStaticFilesConfig,
) -> anyhow::Result<()> {
  let label = |field: &str| format!("route {route_name} static_files.{field}");

  for value in &config.directory_index {
    validate_simple_filename(&label("directory_index"), value)?;
  }
  for value in &config.try_files {
    validate_try_file_candidate(&label("try_files"), value)?;
  }
  if let Some(value) = &config.spa_fallback {
    validate_root_relative_path(&label("spa_fallback"), value)?;
  }
  if let Some(value) = &config.cache_control {
    validate_header_value(&label("cache_control"), value)?;
  }
  validate_unique_precompressed_encodings(route_name, config)?;
  validate_extension_map(
    &label("cache_control_by_extension"),
    &config.cache_control_by_extension,
  )?;
  for (extension, value) in &config.cache_control_by_extension {
    validate_header_value(
      &format!("{}.{extension}", label("cache_control_by_extension")),
      value,
    )?;
  }
  validate_extension_map(&label("mime_overrides"), &config.mime_overrides)?;
  for (extension, value) in &config.mime_overrides {
    validate_header_value(&format!("{}.{extension}", label("mime_overrides")), value)?;
  }
  if let Some(value) = &config.error_pages.not_found {
    validate_root_relative_path(&label("error_pages.not_found"), value)?;
  }
  if let Some(value) = &config.error_pages.server_error {
    validate_root_relative_path(&label("error_pages.server_error"), value)?;
  }
  Ok(())
}

fn validate_unique_precompressed_encodings(
  route_name: &str,
  config: &RouteStaticFilesConfig,
) -> anyhow::Result<()> {
  let mut seen = std::collections::HashSet::new();
  for encoding in &config.precompressed {
    if !seen.insert(*encoding) {
      bail!(
        "route {} static_files.precompressed contains duplicate encoding {}",
        route_name,
        encoding.content_encoding()
      );
    }
  }
  Ok(())
}

fn validate_simple_filename(label: &str, value: &str) -> anyhow::Result<()> {
  if value.is_empty()
    || value == "."
    || value == ".."
    || value
      .bytes()
      .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
  {
    bail!("{label} entry {value:?} must be a simple filename");
  }
  Ok(())
}

fn validate_try_file_candidate(label: &str, value: &str) -> anyhow::Result<()> {
  let placeholder_count = value.matches("{path}").count();
  let unknown_braces = value.replace("{path}", "");
  if placeholder_count > 1 || unknown_braces.contains('{') || unknown_braces.contains('}') {
    bail!("{label} entry {value:?} may only use the {{path}} placeholder");
  }
  if placeholder_count == 0 {
    return validate_root_relative_path(label, value);
  }

  let Some((prefix, suffix)) = value.split_once("{path}") else {
    bail!("{label} entry {value:?} may only use the {{path}} placeholder");
  };
  if !(prefix.is_empty() || prefix == "/") {
    bail!("{label} entry {value:?} may only prefix {{path}} with /");
  }
  if suffix.is_empty() {
    return Ok(());
  }
  if !suffix.starts_with('.')
    || suffix[1..].is_empty()
    || suffix[1..]
      .bytes()
      .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\' | b'{' | b'}'))
  {
    bail!("{label} entry {value:?} may only add a safe extension after {{path}}");
  }
  Ok(())
}

fn validate_root_relative_path(label: &str, value: &str) -> anyhow::Result<()> {
  if !value.starts_with('/') || value == "/" {
    bail!("{label} must be an absolute path under static_root");
  }
  for segment in value.trim_start_matches('/').split('/') {
    if segment.is_empty() || segment == "." || segment == ".." {
      bail!("{label} contains an invalid path segment in {value:?}");
    }
    if segment
      .bytes()
      .any(|byte| byte.is_ascii_control() || matches!(byte, b'\\' | b'{' | b'}'))
    {
      bail!("{label} contains an invalid character in {value:?}");
    }
  }
  Ok(())
}

fn validate_extension_map(label: &str, values: &HashMap<String, String>) -> anyhow::Result<()> {
  for extension in values.keys() {
    validate_extension_key(label, extension)?;
  }
  Ok(())
}

fn validate_extension_key(label: &str, extension: &str) -> anyhow::Result<()> {
  if extension.is_empty()
    || extension.starts_with('.')
    || extension.bytes().any(|byte| {
      byte.is_ascii_control()
        || !(byte.is_ascii_lowercase()
          || byte.is_ascii_digit()
          || matches!(byte, b'+' | b'-' | b'_'))
    })
  {
    bail!("{label} key {extension:?} must be a lowercase extension without a leading dot");
  }
  Ok(())
}

fn validate_header_value(label: &str, value: &str) -> anyhow::Result<()> {
  HeaderValue::from_str(value).with_context(|| format!("{label} has invalid header value"))?;
  Ok(())
}
