use std::collections::HashSet;

use anyhow::bail;
use serde::Deserialize;

use crate::config::{Config, RouteConfig};

use super::{WafActionConfig, WafRuleConfig, WafRuleGroupConfig};

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafHttpBodyCompressionMode {
  #[default]
  Off,
  Transform,
}

impl WafHttpBodyCompressionMode {
  pub(crate) fn transform_enabled(self) -> bool {
    self == Self::Transform
  }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RouteWafHttpBodyCompressionMode {
  #[default]
  Inherit,
  Off,
  Transform,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WafHttpBodyEncoding {
  Gzip,
  Deflate,
  Br,
  Zstd,
}

impl WafHttpBodyEncoding {
  pub(crate) fn as_content_encoding(self) -> &'static str {
    match self {
      Self::Gzip => "gzip",
      Self::Deflate => "deflate",
      Self::Br => "br",
      Self::Zstd => "zstd",
    }
  }
}

fn default_http_body_compression_encodings() -> Vec<WafHttpBodyEncoding> {
  vec![
    WafHttpBodyEncoding::Gzip,
    WafHttpBodyEncoding::Deflate,
    WafHttpBodyEncoding::Br,
    WafHttpBodyEncoding::Zstd,
  ]
}

fn default_http_body_compression_max_decoded_body_bytes() -> usize {
  10_485_760
}

fn default_http_body_compression_max_expansion_ratio() -> usize {
  20
}

fn default_http_body_compression_decode_timeout_ms() -> u64 {
  1_000
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafHttpBodyCompressionConfig {
  #[serde(default)]
  pub mode: WafHttpBodyCompressionMode,
  #[serde(default = "default_http_body_compression_encodings")]
  pub encodings: Vec<WafHttpBodyEncoding>,
  #[serde(default = "default_http_body_compression_max_decoded_body_bytes")]
  pub max_decoded_body_bytes: usize,
  #[serde(default = "default_http_body_compression_max_expansion_ratio")]
  pub max_expansion_ratio: usize,
  #[serde(default = "default_http_body_compression_decode_timeout_ms")]
  pub decode_timeout_ms: u64,
  #[serde(default)]
  pub max_concurrent_bodies: usize,
}

impl Default for WafHttpBodyCompressionConfig {
  fn default() -> Self {
    Self {
      mode: WafHttpBodyCompressionMode::Off,
      encodings: default_http_body_compression_encodings(),
      max_decoded_body_bytes: default_http_body_compression_max_decoded_body_bytes(),
      max_expansion_ratio: default_http_body_compression_max_expansion_ratio(),
      decode_timeout_ms: default_http_body_compression_decode_timeout_ms(),
      max_concurrent_bodies: 0,
    }
  }
}

impl WafHttpBodyCompressionConfig {
  pub(crate) fn effective_mode(
    &self,
    route: &RouteWafHttpBodyCompressionConfig,
  ) -> WafHttpBodyCompressionMode {
    match route.mode {
      RouteWafHttpBodyCompressionMode::Inherit => self.mode,
      RouteWafHttpBodyCompressionMode::Off => WafHttpBodyCompressionMode::Off,
      RouteWafHttpBodyCompressionMode::Transform => WafHttpBodyCompressionMode::Transform,
    }
  }

  pub(crate) fn allows_encoding(&self, encoding: &str) -> bool {
    self
      .encodings
      .iter()
      .any(|item| item.as_content_encoding().eq_ignore_ascii_case(encoding))
  }
}

pub(crate) fn route_http_body_compression_transform_enabled(
  config: &Config,
  route: &RouteConfig,
) -> bool {
  config
    .waf
    .http_body_compression
    .effective_mode(&route.waf.http_body_compression)
    .transform_enabled()
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RouteWafHttpBodyCompressionConfig {
  #[serde(default)]
  pub mode: RouteWafHttpBodyCompressionMode,
}

impl Default for RouteWafHttpBodyCompressionConfig {
  fn default() -> Self {
    Self {
      mode: RouteWafHttpBodyCompressionMode::Inherit,
    }
  }
}

pub(super) fn validate_http_body_compression_config(config: &Config) -> anyhow::Result<()> {
  let compression = &config.waf.http_body_compression;
  if compression.encodings.is_empty() {
    bail!("waf.http_body_compression.encodings must not be empty");
  }
  let mut encodings = HashSet::new();
  for encoding in &compression.encodings {
    if !encodings.insert(*encoding) {
      bail!(
        "waf.http_body_compression.encodings contains duplicate encoding {}",
        encoding.as_content_encoding()
      );
    }
  }
  if compression.max_decoded_body_bytes == 0
    || compression.max_expansion_ratio == 0
    || compression.decode_timeout_ms == 0
  {
    bail!(
      "waf.http_body_compression max_decoded_body_bytes, max_expansion_ratio, and decode_timeout_ms must be greater than 0"
    );
  }

  let any_transform_route = config
    .routes
    .iter()
    .any(|route| route_http_body_compression_transform_enabled(config, route));
  if !any_transform_route {
    return Ok(());
  }

  validate_no_content_encoding_waf_mutations("global WAF", &config.waf.rules)?;
  validate_no_content_encoding_rule_group_mutations("global WAF", &config.waf.rule_groups)?;
  for route in &config.routes {
    if route_http_body_compression_transform_enabled(config, route) {
      validate_no_content_encoding_route_actions(route)?;
      validate_no_content_encoding_waf_mutations(
        &format!("route {} WAF", route.name),
        &route.waf.rules,
      )?;
      validate_no_content_encoding_rule_group_mutations(
        &format!("route {} WAF", route.name),
        &route.waf.rule_groups,
      )?;
    }
  }
  Ok(())
}

fn validate_no_content_encoding_route_actions(route: &RouteConfig) -> anyhow::Result<()> {
  for action in &route.actions.request_headers.set {
    reject_content_encoding_header(
      &format!("route {} actions.request_headers.set", route.name),
      &action.name,
    )?;
  }
  for action in &route.actions.request_headers.add {
    reject_content_encoding_header(
      &format!("route {} actions.request_headers.add", route.name),
      &action.name,
    )?;
  }
  for name in &route.actions.request_headers.remove {
    reject_content_encoding_header(
      &format!("route {} actions.request_headers.remove", route.name),
      name,
    )?;
  }
  for action in &route.actions.response_headers.set {
    reject_content_encoding_header(
      &format!("route {} actions.response_headers.set", route.name),
      &action.name,
    )?;
  }
  for action in &route.actions.response_headers.add {
    reject_content_encoding_header(
      &format!("route {} actions.response_headers.add", route.name),
      &action.name,
    )?;
  }
  for name in &route.actions.response_headers.remove {
    reject_content_encoding_header(
      &format!("route {} actions.response_headers.remove", route.name),
      name,
    )?;
  }
  Ok(())
}

fn validate_no_content_encoding_rule_group_mutations(
  scope: &str,
  groups: &[WafRuleGroupConfig],
) -> anyhow::Result<()> {
  for group in groups {
    for action in &group.actions {
      reject_content_encoding_waf_action(&format!("{scope} rule group {}", group.name), action)?;
    }
  }
  Ok(())
}

fn validate_no_content_encoding_waf_mutations(
  scope: &str,
  rules: &[WafRuleConfig],
) -> anyhow::Result<()> {
  for rule in rules {
    for action in &rule.actions {
      reject_content_encoding_waf_action(&format!("{scope} rule {}", rule.name), action)?;
    }
    validate_no_content_encoding_rule_group_mutations(
      &format!("{scope} rule {} external file", rule.name),
      &rule.local_rule_groups,
    )?;
  }
  Ok(())
}

fn reject_content_encoding_waf_action(scope: &str, action: &WafActionConfig) -> anyhow::Result<()> {
  match action {
    WafActionConfig::SetRequestHeader { name, .. }
    | WafActionConfig::RemoveRequestHeader { name, .. }
    | WafActionConfig::SetResponseHeader { name, .. }
    | WafActionConfig::RemoveResponseHeader { name, .. } => {
      reject_content_encoding_header(scope, name)
    }
    _ => Ok(()),
  }
}

fn reject_content_encoding_header(scope: &str, name: &str) -> anyhow::Result<()> {
  if name.eq_ignore_ascii_case("content-encoding") {
    bail!(
      "{scope} cannot mutate Content-Encoding when WAF HTTP body compression transform is enabled"
    );
  }
  Ok(())
}
