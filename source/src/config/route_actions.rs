//! Route action configuration and validation.
//! Rewrite and redirect templates are validated before the HTTP data path renders them.

use anyhow::{Context, bail};
use serde::Deserialize;

use super::route::{RouteBufferingConfig, RouteConfig};

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct RouteActionsConfig {
  #[serde(default)]
  pub rewrite: Option<RouteRewriteActionConfig>,
  #[serde(default)]
  pub redirect: Option<RouteRedirectActionConfig>,
}

impl RouteActionsConfig {
  pub fn has_actions(&self) -> bool {
    self.rewrite.is_some() || self.redirect.is_some()
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

  Ok(())
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
  }
  Ok(())
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
        let Some(close_offset) = bytes[index + 1..].iter().position(|byte| *byte == b'}') else {
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
