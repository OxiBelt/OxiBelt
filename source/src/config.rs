use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use url::Url;

use crate::waf::{RouteWafConfig, WafConfig};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
  #[serde(default)]
  pub logging: LoggingConfig,
  #[serde(default)]
  pub runtime: RuntimeConfig,
  pub listeners: ListenerConfig,
  pub tls: TlsConfig,
  #[serde(default)]
  pub proxy: ProxyConfig,
  #[serde(default)]
  pub compression: CompressionConfig,
  pub upstreams: Vec<UpstreamConfig>,
  pub routes: Vec<RouteConfig>,
  #[serde(default)]
  pub waf: WafConfig,
}

impl Config {
  pub fn load(path: &Path) -> anyhow::Result<Self> {
    let path_roots = config_path_roots(path)?;
    let merged = load_toml_with_includes(path)?;
    let mut config: Self = merged
      .try_into()
      .with_context(|| format!("failed to decode merged TOML from {}", path.display()))?;
    config.resolve_relative_paths(&path_roots)?;
    config.load_external_waf_rules()?;
    Ok(config)
  }

  fn resolve_relative_paths(&mut self, path_roots: &ConfigPathRoots) -> anyhow::Result<()> {
    self.tls.cert_chain = resolve_existing_local_config_file_path(
      "tls.cert_chain",
      &path_roots.cert_dir,
      &self.tls.cert_chain,
    )?;
    self.tls.private_key = resolve_existing_local_config_file_path(
      "tls.private_key",
      &path_roots.cert_dir,
      &self.tls.private_key,
    )?;
    self.tls.ocsp.response_file = self
      .tls
      .ocsp
      .response_file
      .take()
      .map(|path| {
        resolve_existing_local_config_file_path(
          "tls.ocsp.response_file",
          &path_roots.cert_dir,
          &path,
        )
      })
      .transpose()?;
    self.proxy.trusted_ca_certs = self
      .proxy
      .trusted_ca_certs
      .iter()
      .map(|path| {
        resolve_existing_local_config_file_path(
          "proxy.trusted_ca_certs",
          &path_roots.cert_dir,
          path,
        )
      })
      .collect::<anyhow::Result<_>>()?;
    for upstream in &mut self.upstreams {
      upstream.tls.resolve_relative_paths(&path_roots.cert_dir)?;
    }
    self.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    for route in &mut self.routes {
      route.waf.resolve_relative_paths(&path_roots.oxirule_dir)?;
    }
    Ok(())
  }

  fn load_external_waf_rules(&mut self) -> anyhow::Result<()> {
    self.waf.load_external_rules()?;
    for route in &mut self.routes {
      route.waf.load_external_rules()?;
    }
    Ok(())
  }

  pub fn validate(&self) -> anyhow::Result<()> {
    if !self.listeners.http1 && !self.listeners.http2 && !self.listeners.http3 {
      bail!("at least one downstream HTTP version must be enabled");
    }

    if self.runtime.unprivileged_mode && self.listeners.https_bind.port() < 1024 {
      bail!(
        "https_bind {} requires a privileged port but unprivileged_mode=true",
        self.listeners.https_bind
      );
    }

    if self.runtime.linux_only && !cfg!(target_os = "linux") {
      bail!("this build is configured for Linux only");
    }

    if self.upstreams.is_empty() {
      bail!("at least one upstream must be configured");
    }

    if self.routes.is_empty() {
      bail!("at least one route must be configured");
    }

    let mut upstream_names = HashSet::new();
    for upstream in &self.upstreams {
      if upstream.name.trim().is_empty() {
        bail!("upstream name must not be empty");
      }
      if !upstream_names.insert(upstream.name.clone()) {
        bail!("duplicate upstream name: {}", upstream.name);
      }

      if upstream.origin.scheme() != "http" && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use http:// or https:// origin, got {}",
          upstream.name,
          upstream.origin
        );
      }

      if upstream.max_http_version == HttpVersion::H3 && upstream.origin.scheme() != "https" {
        bail!(
          "upstream {} must use https:// origin when max_http_version = \"h3\"",
          upstream.name
        );
      }

      upstream.tls.validate(&upstream.name)?;
    }

    let mut route_names = HashSet::new();
    for route in &self.routes {
      if route.name.trim().is_empty() {
        bail!("route name must not be empty");
      }
      if !route_names.insert(route.name.clone()) {
        bail!("duplicate route name: {}", route.name);
      }
      if route.hosts.is_empty() {
        bail!("route {} must have at least one host match", route.name);
      }
      validate_route_path_value(&route.name, "path_prefix", &route.path_prefix)?;
      if let Some(replacement) = &route.replace_prefix_with {
        validate_route_path_value(&route.name, "replace_prefix_with", replacement)?;
      }
      if !upstream_names.contains(&route.upstream) {
        bail!(
          "route {} references unknown upstream {}",
          route.name,
          route.upstream
        );
      }
    }

    match self.tls.ocsp.mode {
      OcspMode::Disabled => {}
      OcspMode::StaticFile => {
        if self.tls.ocsp.response_file.is_none() {
          bail!("tls.ocsp.response_file is required when tls.ocsp.mode = \"static_file\"");
        }
      }
      OcspMode::LiveFetch => {
        return Err(anyhow!(
          "tls.ocsp.mode = \"live_fetch\" is reserved but not implemented yet"
        ));
      }
    }

    crate::waf::validate_config(self)?;

    Ok(())
  }
}

fn validate_route_path_value(
  route_name: &str,
  field_name: &str,
  value: &str,
) -> anyhow::Result<()> {
  if !value.starts_with('/') {
    bail!("route {route_name} {field_name} must start with '/'");
  }
  if value
    .bytes()
    .any(|byte| byte.is_ascii_control() || matches!(byte, b'\\' | b'?' | b'#'))
  {
    bail!(
      "route {route_name} {field_name} must not contain control characters, backslashes, queries, or fragments"
    );
  }

  for segment in value.split('/') {
    if matches!(segment, "." | "..") {
      bail!("route {route_name} {field_name} must not contain dot segments");
    }
  }

  let lower = value.to_ascii_lowercase();
  if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
    bail!("route {route_name} {field_name} must not contain encoded dot or slash separators");
  }

  Ok(())
}

fn load_toml_with_includes(path: &Path) -> anyhow::Result<toml::Value> {
  let mut stack = Vec::new();
  load_toml_document(path, &mut stack)
}

fn load_toml_document(path: &Path, stack: &mut Vec<PathBuf>) -> anyhow::Result<toml::Value> {
  let absolute_path = absolute_config_path(path)?;
  let canonical_path = absolute_path.canonicalize().with_context(|| {
    format!(
      "failed to resolve configuration file {}",
      absolute_path.display()
    )
  })?;
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

  let raw = std::fs::read_to_string(&canonical_path)
    .with_context(|| format!("failed to read {}", canonical_path.display()))?;
  let mut value: toml::Value = toml::from_str(&raw)
    .with_context(|| format!("failed to parse TOML from {}", absolute_path.display()))?;
  let include_entries = take_include_entries(&mut value, &absolute_path)?;
  let base_dir = absolute_path.parent().unwrap_or_else(|| Path::new("."));

  let mut merged = toml::Value::Table(toml::map::Map::new());
  for entry in include_entries {
    for include_path in expand_include_entry(&entry, base_dir, &absolute_path)? {
      let included = load_toml_document(&include_path, stack)?;
      merge_toml_values(&mut merged, included, "")?;
    }
  }
  merge_toml_values(&mut merged, value, "")?;

  stack.pop();
  Ok(merged)
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
    return Ok(vec![canonicalize_local_config_file(
      "configuration include",
      &pattern_path,
      &canonical_base_dir,
      source_path,
    )?]);
  }

  let pattern = pattern_path.to_str().ok_or_else(|| {
    anyhow!(
      "configuration include pattern in {} is not valid UTF-8: {}",
      source_path.display(),
      pattern_path.display()
    )
  })?;
  let mut paths = Vec::new();
  for path in glob::glob(pattern).with_context(|| {
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
      paths.push(canonicalize_local_config_file(
        "configuration include",
        &path,
        &canonical_base_dir,
        source_path,
      )?);
    }
  }
  paths.sort();
  Ok(paths)
}

fn has_glob_pattern(entry: &str) -> bool {
  entry.chars().any(|ch| matches!(ch, '*' | '?' | '['))
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

fn absolute_config_path(path: &Path) -> anyhow::Result<PathBuf> {
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

fn config_base_dir(path: &Path) -> anyhow::Result<PathBuf> {
  let absolute_path = absolute_config_path(path)?;

  Ok(
    absolute_path
      .parent()
      .unwrap_or_else(|| Path::new("."))
      .to_path_buf(),
  )
}

struct ConfigPathRoots {
  cert_dir: PathBuf,
  oxirule_dir: PathBuf,
}

fn config_path_roots(path: &Path) -> anyhow::Result<ConfigPathRoots> {
  let config_dir = config_base_dir(path)?;
  let layout_root = config_dir.parent().unwrap_or_else(|| Path::new("."));

  Ok(ConfigPathRoots {
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

pub(crate) fn resolve_existing_local_config_file_path(
  field_name: &str,
  base_dir: &Path,
  path: &Path,
) -> anyhow::Result<PathBuf> {
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

  Ok(canonical_path)
}

pub(crate) fn canonicalize_existing_file(field_name: &str, path: &Path) -> anyhow::Result<PathBuf> {
  let canonical_path = path
    .canonicalize()
    .with_context(|| format!("failed to resolve {field_name} {}", path.display()))?;
  ensure_regular_file(field_name, &canonical_path)?;

  Ok(canonical_path)
}

fn ensure_regular_file(field_name: &str, path: &Path) -> anyhow::Result<()> {
  let metadata = path
    .metadata()
    .with_context(|| format!("failed to inspect {field_name} {}", path.display()))?;

  if !metadata.is_file() {
    bail!("{field_name} must point to a regular file");
  }

  Ok(())
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

fn validate_relative_path(field_name: &str, path: &Path) -> anyhow::Result<()> {
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

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
  #[serde(default = "default_log_level")]
  pub level: String,
}

impl Default for LoggingConfig {
  fn default() -> Self {
    Self {
      level: default_log_level(),
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
  #[serde(default = "default_true")]
  pub linux_only: bool,
  #[serde(default = "default_true")]
  pub read_only_rootfs_compatible: bool,
  #[serde(default = "default_true")]
  pub memory_only_state: bool,
  #[serde(default = "default_true")]
  pub unprivileged_mode: bool,
}

impl Default for RuntimeConfig {
  fn default() -> Self {
    Self {
      linux_only: true,
      read_only_rootfs_compatible: true,
      memory_only_state: true,
      unprivileged_mode: true,
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
  pub https_bind: SocketAddr,
  #[serde(default = "default_true")]
  pub http1: bool,
  #[serde(default = "default_true")]
  pub http2: bool,
  #[serde(default)]
  pub http3: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
  pub cert_chain: PathBuf,
  pub private_key: PathBuf,
  #[serde(default)]
  pub ocsp: OcspConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OcspConfig {
  #[serde(default)]
  pub mode: OcspMode,
  #[serde(default)]
  pub response_file: Option<PathBuf>,
}

impl Default for OcspConfig {
  fn default() -> Self {
    Self {
      mode: OcspMode::Disabled,
      response_file: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OcspMode {
  #[default]
  Disabled,
  StaticFile,
  LiveFetch,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProxyConfig {
  #[serde(default)]
  pub auto_upgrade: AutoUpgradeConfig,
  #[serde(default)]
  pub trusted_ca_certs: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoUpgradeConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
}

impl Default for AutoUpgradeConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      max_http_version: HttpVersion::H2,
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompressionConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub gzip: bool,
  #[serde(default = "default_true")]
  pub deflate: bool,
  #[serde(default = "default_true")]
  pub zstd: bool,
}

impl CompressionConfig {
  pub fn accept_encoding_value(&self) -> Option<String> {
    if !self.enabled {
      return None;
    }

    let mut values = Vec::new();
    if self.zstd {
      values.push("zstd");
    }
    if self.gzip {
      values.push("gzip");
    }
    if self.deflate {
      values.push("deflate");
    }

    if values.is_empty() {
      None
    } else {
      Some(values.join(", "))
    }
  }
}

impl Default for CompressionConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      gzip: true,
      deflate: true,
      zstd: true,
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
  pub name: String,
  pub origin: Url,
  #[serde(default = "default_proxy_max_http_version")]
  pub max_http_version: HttpVersion,
  #[serde(default = "default_connect_timeout_ms")]
  pub connect_timeout_ms: u64,
  #[serde(default = "default_request_timeout_ms")]
  pub request_timeout_ms: u64,
  #[serde(default)]
  pub preserve_host: bool,
  #[serde(default = "default_true")]
  pub websocket: bool,
  #[serde(default = "default_true")]
  pub webrtc: bool,
  #[serde(default = "default_true")]
  pub webtransport: bool,
  #[serde(default)]
  pub tls: UpstreamTlsConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpstreamTlsConfig {
  #[serde(default)]
  pub ech: UpstreamEchConfig,
}

impl UpstreamTlsConfig {
  fn resolve_relative_paths(&mut self, base_dir: &Path) -> anyhow::Result<()> {
    self.ech.config_list_file = self
      .ech
      .config_list_file
      .take()
      .map(|path| {
        resolve_existing_local_config_file_path(
          "upstreams.tls.ech.config_list_file",
          base_dir,
          &path,
        )
      })
      .transpose()?;
    Ok(())
  }

  fn validate(&self, upstream_name: &str) -> anyhow::Result<()> {
    match self.ech.mode {
      UpstreamEchMode::Disabled | UpstreamEchMode::Grease => {
        if self.ech.config_list_file.is_some() {
          bail!(
            "upstream {} tls.ech.config_list_file is only valid when tls.ech.mode = \"config_list\"",
            upstream_name
          );
        }
      }
      UpstreamEchMode::ConfigList => {
        if self.ech.config_list_file.is_none() {
          bail!(
            "upstream {} tls.ech.config_list_file is required when tls.ech.mode = \"config_list\"",
            upstream_name
          );
        }
      }
    }

    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamEchConfig {
  #[serde(default)]
  pub mode: UpstreamEchMode,
  #[serde(default)]
  pub config_list_file: Option<PathBuf>,
}

impl Default for UpstreamEchConfig {
  fn default() -> Self {
    Self {
      mode: UpstreamEchMode::Disabled,
      config_list_file: None,
    }
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamEchMode {
  #[default]
  Disabled,
  Grease,
  ConfigList,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
  pub name: String,
  #[serde(default = "default_hosts")]
  pub hosts: Vec<String>,
  #[serde(default = "default_path_prefix")]
  pub path_prefix: String,
  #[serde(default)]
  pub replace_prefix_with: Option<String>,
  pub upstream: String,
  #[serde(default)]
  pub waf: RouteWafConfig,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
pub enum HttpVersion {
  #[serde(rename = "h1")]
  H1,
  #[serde(rename = "h2")]
  H2,
  #[serde(rename = "h3")]
  H3,
}

impl HttpVersion {
  pub fn as_alpn(self) -> &'static [u8] {
    match self {
      Self::H1 => b"http/1.1",
      Self::H2 => b"h2",
      Self::H3 => b"h3",
    }
  }
}

fn default_true() -> bool {
  true
}

fn default_log_level() -> String {
  "info".to_string()
}

fn default_hosts() -> Vec<String> {
  vec!["*".to_string()]
}

fn default_path_prefix() -> String {
  "/".to_string()
}

fn default_connect_timeout_ms() -> u64 {
  3_000
}

fn default_request_timeout_ms() -> u64 {
  30_000
}

fn default_proxy_max_http_version() -> HttpVersion {
  HttpVersion::H2
}
