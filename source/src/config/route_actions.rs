//! Route action configuration and validation.
//! Rewrite and redirect templates are validated before the HTTP data path renders them.

use std::collections::HashSet;

use anyhow::{Context, bail};
use http::{HeaderValue, Method};
use serde::Deserialize;

use super::route::{RouteBufferingConfig, RouteConfig};
use super::route_header_policy::{
  is_forbidden_route_action_header, is_reserved_route_request_header,
  normalize_route_action_header_name,
};

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteActionsConfig {
  #[serde(default)]
  pub rewrite: Option<RouteRewriteActionConfig>,
  #[serde(default)]
  pub redirect: Option<RouteRedirectActionConfig>,
  #[serde(default)]
  pub request_headers: RouteHeaderModifierConfig,
  #[serde(default)]
  pub response_headers: RouteHeaderModifierConfig,
  #[serde(default)]
  pub cors: Option<RouteCorsActionConfig>,
  #[serde(default)]
  pub request_mirrors: Vec<RouteRequestMirrorConfig>,
}

impl RouteActionsConfig {
  pub fn has_actions(&self) -> bool {
    self.rewrite.is_some()
      || self.redirect.is_some()
      || self.request_headers.has_actions()
      || self.response_headers.has_actions()
      || self.cors.is_some()
      || !self.request_mirrors.is_empty()
  }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteRewriteActionConfig {
  #[serde(default)]
  pub path: Option<String>,
  #[serde(default)]
  pub query: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteRedirectActionConfig {
  #[serde(default)]
  pub status: Option<u16>,
  #[serde(default)]
  pub location_template: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteHeaderModifierConfig {
  #[serde(default)]
  pub set: Vec<RouteHeaderValueConfig>,
  #[serde(default)]
  pub add: Vec<RouteHeaderValueConfig>,
  #[serde(default)]
  pub remove: Vec<String>,
}

impl RouteHeaderModifierConfig {
  pub fn has_actions(&self) -> bool {
    !self.set.is_empty() || !self.add.is_empty() || !self.remove.is_empty()
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RouteHeaderValueConfig {
  pub name: String,
  pub value: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RouteCorsActionConfig {
  #[serde(default)]
  pub allow_origins: Vec<String>,
  #[serde(default)]
  pub allow_methods: Vec<String>,
  #[serde(default)]
  pub allow_headers: Vec<String>,
  #[serde(default)]
  pub expose_headers: Vec<String>,
  #[serde(default)]
  pub allow_credentials: bool,
  #[serde(default)]
  pub max_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RouteRequestMirrorConfig {
  pub upstream_pool: String,
  #[serde(default = "default_request_mirror_sample_percent")]
  pub sample_percent: f64,
  #[serde(default)]
  pub max_body_bytes: usize,
}

pub(crate) fn validate_route_actions_config(route: &RouteConfig) -> anyhow::Result<()> {
  let route_name = &route.name;
  if route.actions.rewrite.is_some() && route.actions.redirect.is_some() {
    bail!("route {route_name} cannot configure both actions.rewrite and actions.redirect");
  }

  if let Some(rewrite) = &route.actions.rewrite {
    if rewrite.path.is_none() && rewrite.query.is_none() {
      bail!("route {route_name} actions.rewrite must set path or query");
    }
    if route.replace_prefix_with.is_some() {
      bail!("route {route_name} cannot set replace_prefix_with when actions.rewrite is configured");
    }
    if let Some(path) = &rewrite.path {
      validate_route_action_path_template(route, "actions.rewrite.path", path)?;
    }
    if let Some(query) = &rewrite.query {
      validate_route_action_query_template(route, "actions.rewrite.query", query)?;
    }
  }

  if let Some(redirect) = &route.actions.redirect {
    match redirect.status {
      Some(301 | 302 | 303 | 307 | 308) => {}
      Some(status) => bail!(
        "route {route_name} actions.redirect.status {status} must be one of 301, 302, 303, 307, or 308"
      ),
      None => bail!("route {route_name} actions.redirect.status is required"),
    }
    let Some(location_template) = redirect.location_template.as_deref() else {
      bail!("route {route_name} actions.redirect.location_template is required");
    };
    validate_route_action_redirect_template(
      route,
      "actions.redirect.location_template",
      location_template,
    )?;
  }

  validate_header_modifier(
    route_name,
    "actions.request_headers",
    &route.actions.request_headers,
    HeaderActionScope::Request,
  )?;
  validate_header_modifier(
    route_name,
    "actions.response_headers",
    &route.actions.response_headers,
    HeaderActionScope::Response,
  )?;
  if let Some(cors) = &route.actions.cors {
    validate_cors_action(route_name, cors)?;
  }
  validate_request_mirrors(route_name, &route.actions.request_mirrors)?;

  Ok(())
}

pub(crate) fn validate_route_external_auth_identity_header_conflicts(
  route: &RouteConfig,
  identity_headers: &[String],
) -> anyhow::Result<()> {
  if identity_headers.is_empty() || !route.actions.request_headers.has_actions() {
    return Ok(());
  }

  let identity_headers = identity_headers
    .iter()
    .map(|name| normalize_route_action_header_name(name))
    .collect::<anyhow::Result<HashSet<_>>>()?;
  validate_request_header_identity_conflict(
    &route.name,
    "actions.request_headers.set",
    route
      .actions
      .request_headers
      .set
      .iter()
      .map(|entry| entry.name.as_str()),
    &identity_headers,
  )?;
  validate_request_header_identity_conflict(
    &route.name,
    "actions.request_headers.add",
    route
      .actions
      .request_headers
      .add
      .iter()
      .map(|entry| entry.name.as_str()),
    &identity_headers,
  )?;
  validate_request_header_identity_conflict(
    &route.name,
    "actions.request_headers.remove",
    route
      .actions
      .request_headers
      .remove
      .iter()
      .map(String::as_str),
    &identity_headers,
  )
}

pub(crate) fn validate_redirect_route_features(route: &RouteConfig) -> anyhow::Result<()> {
  if route.external_auth.is_some() {
    bail!(
      "route {} cannot set external_auth when actions.redirect is configured",
      route.name
    );
  }
  if route_waf_is_configured(route) {
    bail!(
      "route {} cannot set route-level WAF config when actions.redirect is configured",
      route.name
    );
  }
  if route.cache.is_some() {
    bail!(
      "route {} cannot set cache when actions.redirect is configured",
      route.name
    );
  }
  if route.compression.is_some() {
    bail!(
      "route {} cannot set compression when actions.redirect is configured",
      route.name
    );
  }
  if route.buffering != RouteBufferingConfig::default() {
    bail!(
      "route {} cannot set buffering when actions.redirect is configured",
      route.name
    );
  }
  if route.retry.is_some() {
    bail!(
      "route {} cannot set retry when actions.redirect is configured",
      route.name
    );
  }
  if route.upstream_http_version.is_some() {
    bail!(
      "route {} cannot set upstream_http_version when actions.redirect is configured",
      route.name
    );
  }
  if route.generic_http_upgrade || route.connect_tunneling || route.grpc_web {
    bail!(
      "route {} cannot enable upstream-only route features when actions.redirect is configured",
      route.name
    );
  }
  Ok(())
}

fn route_waf_is_configured(route: &RouteConfig) -> bool {
  !route.waf.functions.is_empty()
    || !route.waf.rulepack_files.is_empty()
    || !route.waf.rule_group_files.is_empty()
    || !route.waf.rule_groups.is_empty()
    || !route.waf.rules.is_empty()
}

pub(crate) fn validate_route_action_target_compatibility(
  route: &RouteConfig,
) -> anyhow::Result<()> {
  if route.actions.rewrite.is_some() {
    if route.static_root.is_some() {
      bail!(
        "route {} cannot set actions.rewrite when static_root is configured",
        route.name
      );
    }
    if route.upstream.is_none() && route.upstream_pool.is_none() {
      bail!(
        "route {} actions.rewrite requires upstream or upstream_pool",
        route.name
      );
    }
  }
  if route.actions.redirect.is_some() {
    validate_redirect_route_features(route)?;
    if route.actions.request_headers.has_actions()
      || route.actions.response_headers.has_actions()
      || route.actions.cors.is_some()
      || !route.actions.request_mirrors.is_empty()
    {
      bail!(
        "route {} cannot combine actions.redirect with header, CORS, or mirror actions",
        route.name
      );
    }
  }
  if route.actions.request_headers.has_actions()
    || route.actions.cors.is_some()
    || !route.actions.request_mirrors.is_empty()
  {
    if route.static_root.is_some() {
      bail!(
        "route {} cannot set upstream request actions when static_root is configured",
        route.name
      );
    }
    if route.upstream.is_none() && route.upstream_pool.is_none() {
      bail!(
        "route {} upstream request actions require upstream or upstream_pool",
        route.name
      );
    }
  }
  Ok(())
}

pub(crate) fn validate_route_action_pool_references(
  route: &RouteConfig,
  pool_names: &HashSet<String>,
) -> anyhow::Result<()> {
  for mirror in &route.actions.request_mirrors {
    if !pool_names.contains(&mirror.upstream_pool) {
      bail!(
        "route {} actions.request_mirrors references unknown upstream_pool {}",
        route.name,
        mirror.upstream_pool
      );
    }
  }
  Ok(())
}

fn validate_header_modifier(
  route_name: &str,
  field_name: &str,
  modifier: &RouteHeaderModifierConfig,
  scope: HeaderActionScope,
) -> anyhow::Result<()> {
  let mut seen = HashSet::new();
  for entry in &modifier.set {
    validate_header_value(
      route_name,
      &format!("{field_name}.set"),
      &entry.name,
      &entry.value,
      scope,
    )?;
    let normalized = normalize_route_action_header_name(&entry.name)?;
    if !seen.insert(("set", normalized.clone())) {
      bail!("route {route_name} {field_name}.set contains duplicate header {normalized}");
    }
  }
  for entry in &modifier.add {
    validate_header_value(
      route_name,
      &format!("{field_name}.add"),
      &entry.name,
      &entry.value,
      scope,
    )?;
    let normalized = normalize_route_action_header_name(&entry.name)?;
    if !seen.insert(("add", normalized.clone())) {
      bail!("route {route_name} {field_name}.add contains duplicate header {normalized}");
    }
  }
  let mut removes = HashSet::new();
  for name in &modifier.remove {
    validate_header_name(route_name, &format!("{field_name}.remove"), name, scope)?;
    let normalized = normalize_route_action_header_name(name)?;
    if !removes.insert(normalized.clone()) {
      bail!("route {route_name} {field_name}.remove contains duplicate header {normalized}");
    }
  }
  Ok(())
}

fn validate_header_value(
  route_name: &str,
  field_name: &str,
  name: &str,
  value: &str,
  scope: HeaderActionScope,
) -> anyhow::Result<()> {
  validate_header_name(route_name, field_name, name, scope)?;
  HeaderValue::from_str(value)
    .with_context(|| format!("route {route_name} {field_name} has invalid value for {name}"))?;
  Ok(())
}

#[derive(Clone, Copy)]
enum HeaderActionScope {
  Request,
  Response,
}

fn validate_header_name(
  route_name: &str,
  field_name: &str,
  name: &str,
  scope: HeaderActionScope,
) -> anyhow::Result<()> {
  if name.trim() != name || name.is_empty() {
    bail!("route {route_name} {field_name} contains an empty or padded header name");
  }
  let normalized = normalize_route_action_header_name(name)?;
  let forbidden = match scope {
    HeaderActionScope::Request => is_reserved_route_request_header(&normalized),
    HeaderActionScope::Response => is_forbidden_route_action_header(&normalized),
  };
  if forbidden {
    bail!("route {route_name} {field_name} cannot mutate header {normalized}");
  }
  Ok(())
}

fn validate_request_header_identity_conflict<'a>(
  route_name: &str,
  field_name: &str,
  names: impl Iterator<Item = &'a str>,
  identity_headers: &HashSet<String>,
) -> anyhow::Result<()> {
  for name in names {
    let normalized = normalize_route_action_header_name(name)?;
    if identity_headers.contains(&normalized) {
      bail!(
        "route {route_name} {field_name} cannot mutate external_auth identity header {normalized}"
      );
    }
  }
  Ok(())
}

fn validate_cors_action(route_name: &str, cors: &RouteCorsActionConfig) -> anyhow::Result<()> {
  if cors.allow_origins.is_empty() {
    bail!("route {route_name} actions.cors.allow_origins must include at least one origin");
  }
  if cors.allow_methods.is_empty() {
    bail!("route {route_name} actions.cors.allow_methods must include at least one method");
  }
  if cors.allow_credentials && cors.allow_origins.iter().any(|origin| origin == "*") {
    bail!(
      "route {route_name} actions.cors.allow_credentials cannot be true when allow_origins contains '*'"
    );
  }
  let mut origins = HashSet::new();
  for origin in &cors.allow_origins {
    if origin.trim() != origin || origin.is_empty() {
      bail!("route {route_name} actions.cors.allow_origins contains an empty or padded origin");
    }
    if !origins.insert(origin.as_str()) {
      bail!("route {route_name} actions.cors.allow_origins contains duplicate origin {origin}");
    }
  }
  let mut methods = HashSet::new();
  for method in &cors.allow_methods {
    Method::from_bytes(method.as_bytes()).with_context(|| {
      format!("route {route_name} actions.cors.allow_methods contains invalid method {method}")
    })?;
    let normalized = method.to_ascii_uppercase();
    if !methods.insert(normalized.clone()) {
      bail!("route {route_name} actions.cors.allow_methods contains duplicate method {normalized}");
    }
  }
  validate_cors_header_list(
    route_name,
    "actions.cors.allow_headers",
    &cors.allow_headers,
  )?;
  validate_cors_header_list(
    route_name,
    "actions.cors.expose_headers",
    &cors.expose_headers,
  )?;
  Ok(())
}

fn validate_cors_header_list(
  route_name: &str,
  field_name: &str,
  headers: &[String],
) -> anyhow::Result<()> {
  let mut names = HashSet::new();
  for header in headers {
    if header == "*" {
      if !names.insert("*".to_string()) {
        bail!("route {route_name} {field_name} contains duplicate header *");
      }
      continue;
    }
    if header.trim() != header || header.is_empty() {
      bail!("route {route_name} {field_name} contains an empty or padded header name");
    }
    let normalized = normalize_route_action_header_name(header)?;
    if !names.insert(normalized.clone()) {
      bail!("route {route_name} {field_name} contains duplicate header {normalized}");
    }
  }
  Ok(())
}

fn validate_request_mirrors(
  route_name: &str,
  mirrors: &[RouteRequestMirrorConfig],
) -> anyhow::Result<()> {
  let mut pools = HashSet::new();
  for mirror in mirrors {
    if mirror.upstream_pool.trim() != mirror.upstream_pool || mirror.upstream_pool.is_empty() {
      bail!(
        "route {route_name} actions.request_mirrors.upstream_pool must be a non-empty identifier"
      );
    }
    if !mirror.sample_percent.is_finite()
      || mirror.sample_percent <= 0.0
      || mirror.sample_percent > 100.0
    {
      bail!(
        "route {route_name} actions.request_mirrors.sample_percent must be greater than 0 and at most 100"
      );
    }
    if !pools.insert(mirror.upstream_pool.as_str()) {
      bail!(
        "route {route_name} actions.request_mirrors contains duplicate upstream_pool {}",
        mirror.upstream_pool
      );
    }
  }
  Ok(())
}

fn default_request_mirror_sample_percent() -> f64 {
  100.0
}

fn validate_route_action_path_template(
  route: &RouteConfig,
  field_name: &str,
  template: &str,
) -> anyhow::Result<()> {
  validate_route_action_template_safety(&route.name, field_name, template)?;
  if !template.starts_with('/') || template.starts_with("//") {
    bail!("route {} {field_name} must start with one '/'", route.name);
  }
  if template.bytes().any(|byte| matches!(byte, b'?' | b'#')) {
    bail!(
      "route {} {field_name} must not contain queries or fragments",
      route.name
    );
  }
  validate_route_action_template_separators(&route.name, field_name, template)?;
  let usage = inspect_route_action_template(&route.name, field_name, template)?;
  validate_route_action_capture_refs(route, field_name, usage.max_capture_index)
}

fn validate_route_action_query_template(
  route: &RouteConfig,
  field_name: &str,
  template: &str,
) -> anyhow::Result<()> {
  validate_route_action_template_safety(&route.name, field_name, template)?;
  if template.bytes().any(|byte| byte == b'#') {
    bail!(
      "route {} {field_name} must not contain fragments",
      route.name
    );
  }
  validate_route_action_template_separators(&route.name, field_name, template)?;
  let usage = inspect_route_action_template(&route.name, field_name, template)?;
  validate_route_action_capture_refs(route, field_name, usage.max_capture_index)
}

fn validate_route_action_redirect_template(
  route: &RouteConfig,
  field_name: &str,
  template: &str,
) -> anyhow::Result<()> {
  validate_route_action_template_safety(&route.name, field_name, template)?;
  if !template.starts_with('/') || template.starts_with("//") {
    bail!(
      "route {} {field_name} must render to an origin-relative location starting with one '/'",
      route.name
    );
  }
  if template.bytes().any(|byte| byte == b'#') {
    bail!(
      "route {} {field_name} must not contain fragments",
      route.name
    );
  }
  let usage = inspect_route_action_template(&route.name, field_name, template)?;
  validate_route_action_capture_refs(route, field_name, usage.max_capture_index)
}

fn validate_route_action_template_safety(
  route_name: &str,
  field_name: &str,
  template: &str,
) -> anyhow::Result<()> {
  if template
    .bytes()
    .any(|byte| byte.is_ascii_control() || matches!(byte, b'\\' | b'\r' | b'\n'))
  {
    bail!("route {route_name} {field_name} must not contain unsafe characters");
  }
  Ok(())
}

fn validate_route_action_template_separators(
  route_name: &str,
  field_name: &str,
  template: &str,
) -> anyhow::Result<()> {
  let lower = template.to_ascii_lowercase();
  if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
    bail!("route {route_name} {field_name} must not contain encoded dot or slash separators");
  }
  Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
struct RouteActionTemplateUsage {
  max_capture_index: Option<usize>,
}

fn inspect_route_action_template(
  route_name: &str,
  field_name: &str,
  template: &str,
) -> anyhow::Result<RouteActionTemplateUsage> {
  let mut usage = RouteActionTemplateUsage::default();
  let mut index = 0;
  let bytes = template.as_bytes();
  while index < bytes.len() {
    match bytes[index] {
      b'{' => {
        let Some(close_offset) = memchr::memchr(b'}', &bytes[index + 1..]) else {
          bail!("route {route_name} {field_name} contains an unterminated template token");
        };
        let close = index + 1 + close_offset;
        let token = &template[index + 1..close];
        validate_route_action_template_token(route_name, field_name, token, &mut usage)?;
        index = close + 1;
      }
      b'}' => bail!("route {route_name} {field_name} contains an unmatched '}}'"),
      _ => {
        let Some(ch) = template[index..].chars().next() else {
          break;
        };
        index += ch.len_utf8();
      }
    }
  }
  Ok(usage)
}

fn validate_route_action_template_token(
  route_name: &str,
  field_name: &str,
  token: &str,
  usage: &mut RouteActionTemplateUsage,
) -> anyhow::Result<()> {
  match token {
    "scheme" | "host" | "path" | "path_suffix" | "query" => return Ok(()),
    _ => {}
  }
  if let Some(name) = token.strip_prefix("query:") {
    if name.is_empty() || name.bytes().any(|byte| byte.is_ascii_control()) {
      bail!("route {route_name} {field_name} contains invalid query token {{{token}}}");
    }
    return Ok(());
  }
  if let Some(index) = token.strip_prefix("capture:") {
    let index = index.parse::<usize>().with_context(|| {
      format!("route {route_name} {field_name} contains invalid capture token {{{token}}}")
    })?;
    usage.max_capture_index = usage
      .max_capture_index
      .map_or(Some(index), |current| Some(current.max(index)));
    return Ok(());
  }
  bail!("route {route_name} {field_name} contains unsupported template token {{{token}}}");
}

fn validate_route_action_capture_refs(
  route: &RouteConfig,
  field_name: &str,
  max_capture_index: Option<usize>,
) -> anyhow::Result<()> {
  let Some(max_capture_index) = max_capture_index else {
    return Ok(());
  };
  let Some(regex) = route.r#match.path.regex.as_deref() else {
    bail!(
      "route {} {field_name} cannot reference captures without match.path.regex",
      route.name
    );
  };
  let capture_count = regex::Regex::new(regex)
    .with_context(|| {
      format!(
        "route {} match.path.regex contains invalid regex",
        route.name
      )
    })?
    .captures_len();
  if max_capture_index >= capture_count {
    bail!(
      "route {} {field_name} references capture {max_capture_index}, but match.path.regex exposes {} captures",
      route.name,
      capture_count.saturating_sub(1)
    );
  }
  Ok(())
}
