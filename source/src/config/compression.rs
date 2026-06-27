use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompressionConfig {
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub gzip: bool,
  #[serde(default = "default_true")]
  pub deflate: bool,
  #[serde(default = "default_true")]
  pub zstd: bool,
  #[serde(default = "default_true")]
  pub br: bool,
  #[serde(default = "default_compression_min_size_bytes")]
  pub min_size_bytes: u64,
  #[serde(default = "default_compression_statuses")]
  pub statuses: Vec<u16>,
  #[serde(default = "default_compression_mime_types")]
  pub mime_types: Vec<String>,
  #[serde(default = "default_compression_level")]
  pub level: u8,
  #[serde(default = "default_true")]
  pub vary: bool,
  #[serde(default = "default_compression_proxied")]
  pub proxied: Vec<CompressionProxiedPredicate>,
  #[serde(default)]
  pub upstream_accept_encoding: CompressionUpstreamAcceptEncodingMode,
  #[serde(default)]
  pub max_concurrent_responses: usize,
  #[serde(default)]
  pub policies: Vec<CompressionPolicyConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct CompressionPolicyConfig {
  pub name: String,
  #[serde(default = "default_true")]
  pub enabled: bool,
  #[serde(default = "default_true")]
  pub gzip: bool,
  #[serde(default = "default_true")]
  pub deflate: bool,
  #[serde(default = "default_true")]
  pub zstd: bool,
  #[serde(default = "default_true")]
  pub br: bool,
  #[serde(default = "default_compression_min_size_bytes")]
  pub min_size_bytes: u64,
  #[serde(default = "default_compression_statuses")]
  pub statuses: Vec<u16>,
  #[serde(default = "default_compression_mime_types")]
  pub mime_types: Vec<String>,
  #[serde(default = "default_compression_level")]
  pub level: u8,
  #[serde(default = "default_true")]
  pub vary: bool,
  #[serde(default = "default_compression_proxied")]
  pub proxied: Vec<CompressionProxiedPredicate>,
  #[serde(default)]
  pub upstream_accept_encoding: CompressionUpstreamAcceptEncodingMode,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum CompressionProxiedPredicate {
  Off,
  Expired,
  NoCache,
  NoStore,
  Private,
  NoLastModified,
  NoEtag,
  Auth,
  Any,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CompressionUpstreamAcceptEncodingMode {
  #[default]
  Strip,
  Preserve,
  Configured,
}

impl CompressionConfig {
  pub fn accept_encoding_value(&self) -> Option<String> {
    compression_accept_encoding_value(self.enabled, self.br, self.zstd, self.gzip, self.deflate)
  }

  pub fn accept_encoding_value_for_route(&self, route_compression: Option<&str>) -> Option<String> {
    match route_compression {
      Some("off") => None,
      Some("default") | None => self.accept_encoding_value(),
      Some(name) => self
        .policies
        .iter()
        .find(|policy| policy.name == name)
        .and_then(CompressionPolicyConfig::accept_encoding_value),
    }
  }

  pub fn upstream_accept_encoding_for_route(
    &self,
    route_compression: Option<&str>,
  ) -> Option<CompressionUpstreamAcceptEncodingMode> {
    if !self.enabled || route_compression == Some("off") {
      return None;
    }
    match route_compression {
      Some("default") | None => Some(self.upstream_accept_encoding),
      Some(name) => self
        .policies
        .iter()
        .find(|policy| policy.name == name)
        .map(|policy| policy.upstream_accept_encoding),
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
      br: true,
      min_size_bytes: default_compression_min_size_bytes(),
      statuses: default_compression_statuses(),
      mime_types: default_compression_mime_types(),
      level: default_compression_level(),
      vary: true,
      proxied: default_compression_proxied(),
      upstream_accept_encoding: CompressionUpstreamAcceptEncodingMode::Strip,
      max_concurrent_responses: 0,
      policies: Vec::new(),
    }
  }
}

impl CompressionPolicyConfig {
  pub fn accept_encoding_value(&self) -> Option<String> {
    compression_accept_encoding_value(self.enabled, self.br, self.zstd, self.gzip, self.deflate)
  }
}

fn compression_accept_encoding_value(
  enabled: bool,
  br: bool,
  zstd: bool,
  gzip: bool,
  deflate: bool,
) -> Option<String> {
  if !enabled {
    return None;
  }

  let mut values = Vec::new();
  if br {
    values.push("br");
  }
  if zstd {
    values.push("zstd");
  }
  if gzip {
    values.push("gzip");
  }
  if deflate {
    values.push("deflate");
  }

  if values.is_empty() {
    None
  } else {
    Some(values.join(", "))
  }
}

fn default_true() -> bool {
  true
}

fn default_compression_min_size_bytes() -> u64 {
  1_024
}

fn default_compression_level() -> u8 {
  1
}

fn default_compression_statuses() -> Vec<u16> {
  vec![200]
}

fn default_compression_proxied() -> Vec<CompressionProxiedPredicate> {
  vec![
    CompressionProxiedPredicate::Expired,
    CompressionProxiedPredicate::NoCache,
  ]
}

fn default_compression_mime_types() -> Vec<String> {
  [
    "text/*",
    "application/json",
    "application/*+json",
    "application/javascript",
    "application/xml",
    "application/*+xml",
    "image/svg+xml",
  ]
  .into_iter()
  .map(str::to_string)
  .collect()
}
