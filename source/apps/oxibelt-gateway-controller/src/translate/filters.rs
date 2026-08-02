use std::collections::HashSet;

use anyhow::{Context, bail};
use serde_json::Value;

use super::{
  CorsAction, HeaderModifierAction, HeaderValueAction, RedirectAction, RequestMirrorAction,
  RewriteAction, route_policy, string_at, u64_at,
};

#[derive(Debug, Clone, Default)]
pub(super) struct ParsedRouteFilters {
  pub(super) rewrite: Option<RewriteAction>,
  pub(super) redirect: Option<RedirectAction>,
  pub(super) request_headers: HeaderModifierAction,
  pub(super) response_headers: HeaderModifierAction,
  pub(super) cors: Option<CorsAction>,
  pub(super) request_mirrors: Vec<ParsedRequestMirror>,
  pub(super) external_auth: Option<ParsedExternalAuth>,
  pub(super) route_policy: Option<route_policy::ParsedRoutePolicyRef>,
}

#[derive(Debug, Clone)]
pub(super) struct ParsedRequestMirror {
  pub(super) backend_ref: Value,
  pub(super) action: RequestMirrorAction,
}

#[derive(Debug, Clone)]
pub(super) struct ParsedExternalAuth {
  pub(super) backend_ref: Value,
  pub(super) forward_headers: Vec<String>,
  pub(super) identity_headers: Vec<String>,
  pub(super) terminal_response_headers: Vec<String>,
  pub(super) path_prefix: Option<String>,
  pub(super) max_request_body_bytes: usize,
}

pub(super) fn parse_route_filters(
  rule: &Value,
  path_prefix: &str,
  path_match_type: &str,
  listener_port: Option<u16>,
  route_kind: &str,
) -> anyhow::Result<ParsedRouteFilters> {
  let mut parsed = ParsedRouteFilters::default();
  for filter in rule
    .get("filters")
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default()
  {
    match string_at(&filter, &["type"]).unwrap_or("") {
      "URLRewrite" if route_kind == "HTTPRoute" => {
        if parsed.rewrite.is_some() {
          bail!("only one URLRewrite filter is supported per rule");
        }
        if parsed.redirect.is_some() {
          bail!("URLRewrite and RequestRedirect filters cannot be combined");
        }
        parsed.rewrite = Some(parse_rewrite(&filter, path_prefix, path_match_type)?);
      }
      "RequestRedirect" if route_kind == "HTTPRoute" => {
        if parsed.redirect.is_some() {
          bail!("only one RequestRedirect filter is supported per rule");
        }
        if parsed.rewrite.is_some() {
          bail!("URLRewrite and RequestRedirect filters cannot be combined");
        }
        parsed.redirect = Some(parse_redirect(
          &filter,
          path_prefix,
          path_match_type,
          listener_port,
        )?);
      }
      "RequestHeaderModifier" => {
        merge_header_modifier(
          &mut parsed.request_headers,
          filter
            .get("requestHeaderModifier")
            .context("RequestHeaderModifier filter requires requestHeaderModifier")?,
        )?;
      }
      "ResponseHeaderModifier" => {
        merge_header_modifier(
          &mut parsed.response_headers,
          filter
            .get("responseHeaderModifier")
            .context("ResponseHeaderModifier filter requires responseHeaderModifier")?,
        )?;
      }
      "RequestMirror" => parsed.request_mirrors.push(parse_request_mirror(&filter)?),
      "CORS" if route_kind == "HTTPRoute" => {
        if parsed.cors.is_some() {
          bail!("only one CORS filter is supported per rule");
        }
        parsed.cors = Some(parse_cors(&filter)?);
      }
      "ExternalAuth" => {
        if parsed.external_auth.is_some() {
          bail!("only one ExternalAuth filter is supported per rule");
        }
        parsed.external_auth = Some(parse_external_auth(&filter)?);
      }
      "URLRewrite" | "RequestRedirect" | "CORS" => {
        bail!("{route_kind} filter type is not applicable to this route kind");
      }
      "ExtensionRef" => {
        if parsed.route_policy.is_some() {
          bail!("only one OxiBeltRoutePolicy ExtensionRef is supported per rule");
        }
        parsed.route_policy = Some(route_policy::parse_route_policy_ref(&filter)?);
      }
      "" => bail!("{route_kind} filter type is required"),
      other => bail!("{route_kind} filter type {other} is unsupported"),
    }
  }
  if parsed.redirect.is_some()
    && (!parsed.request_headers.is_empty()
      || !parsed.response_headers.is_empty()
      || parsed.cors.is_some()
      || !parsed.request_mirrors.is_empty()
      || parsed.external_auth.is_some()
      || parsed.route_policy.is_some())
  {
    bail!("RequestRedirect cannot be combined with other route filters");
  }
  validate_request_header_modifier(&parsed.request_headers, parsed.external_auth.as_ref())?;
  Ok(parsed)
}

fn parse_rewrite(
  filter: &Value,
  path_prefix: &str,
  path_match_type: &str,
) -> anyhow::Result<RewriteAction> {
  let rewrite = filter
    .get("urlRewrite")
    .context("URLRewrite filter requires urlRewrite")?;
  if let Some(field) = super::unsupported_field(rewrite, &["hostname", "path"]) {
    bail!("URLRewrite field {field} is unsupported");
  }
  let authority = string_at(filter, &["urlRewrite", "hostname"])
    .map(validate_gateway_hostname)
    .transpose()?;
  let path = match filter
    .get("urlRewrite")
    .and_then(|rewrite| rewrite.get("path"))
  {
    Some(path) => Some(path_modifier_template(path, path_prefix, path_match_type)?),
    None => None,
  };
  if authority.is_none() && path.is_none() {
    bail!("URLRewrite requires hostname or path");
  }
  Ok(RewriteAction {
    authority,
    path,
    query: None,
  })
}

fn parse_redirect(
  filter: &Value,
  path_prefix: &str,
  path_match_type: &str,
  listener_port: Option<u16>,
) -> anyhow::Result<RedirectAction> {
  let redirect = filter
    .get("requestRedirect")
    .context("RequestRedirect filter requires requestRedirect")?;
  if let Some(field) = super::unsupported_field(
    redirect,
    &["scheme", "hostname", "port", "statusCode", "path"],
  ) {
    bail!("RequestRedirect field {field} is unsupported");
  }
  let scheme = string_at(redirect, &["scheme"])
    .map(|scheme| match scheme {
      "http" | "https" => Ok(scheme.to_string()),
      _ => bail!("RequestRedirect scheme must be http or https"),
    })
    .transpose()?;
  let hostname = string_at(redirect, &["hostname"])
    .map(validate_gateway_hostname)
    .transpose()?;
  let port = strict_optional_u16(redirect, "port")?.or_else(|| {
    (string_at(redirect, &["scheme"]).is_none())
      .then_some(listener_port)
      .flatten()
  });
  if port == Some(0) {
    bail!("RequestRedirect port must be between 1 and 65535");
  }
  let status = strict_optional_u16(redirect, "statusCode")?.unwrap_or(302);
  if !matches!(status, 301 | 302 | 303 | 307 | 308) {
    bail!("RequestRedirect statusCode must be one of 301, 302, 303, 307, or 308");
  }
  let path = match redirect.get("path") {
    Some(path) => Some(path_modifier_template(path, path_prefix, path_match_type)?),
    None => None,
  };
  Ok(RedirectAction {
    status,
    scheme,
    hostname,
    port,
    path,
  })
}

fn parse_request_mirror(filter: &Value) -> anyhow::Result<ParsedRequestMirror> {
  let mirror = filter
    .get("requestMirror")
    .context("RequestMirror filter requires requestMirror")?;
  let backend_ref = mirror
    .get("backendRef")
    .cloned()
    .context("RequestMirror filter requires requestMirror.backendRef")?;
  Ok(ParsedRequestMirror {
    backend_ref,
    action: RequestMirrorAction {
      upstream_pool: String::new(),
      sample_percent: mirror_percent(mirror),
      max_body_bytes: 0,
    },
  })
}

fn parse_external_auth(filter: &Value) -> anyhow::Result<ParsedExternalAuth> {
  let auth = filter
    .get("externalAuth")
    .context("ExternalAuth filter requires externalAuth")?;
  if let Some(field) =
    super::unsupported_field(auth, &["protocol", "backendRef", "http", "forwardBody"])
  {
    bail!("Gateway ExternalAuth field {field} is unsupported");
  }
  let protocol = string_at(auth, &["protocol"]).unwrap_or("HTTP");
  match protocol {
    "HTTP" => {}
    "GRPC" => bail!("Gateway ExternalAuth protocol GRPC is unsupported; use HTTP"),
    other => bail!("Gateway ExternalAuth protocol {other} is unsupported"),
  }
  let max_request_body_bytes = match auth.pointer("/forwardBody/maxSize") {
    Some(value) => usize::try_from(
      value
        .as_u64()
        .context("Gateway ExternalAuth forwardBody.maxSize must be an unsigned integer")?,
    )
    .context("Gateway ExternalAuth forwardBody.maxSize exceeds the native size range")?,
    None => 0,
  };
  if max_request_body_bytes > u16::MAX as usize {
    bail!("Gateway ExternalAuth forwardBody.maxSize must not exceed 65535");
  }
  if let Some(forward_body) = auth.get("forwardBody")
    && let Some(field) = super::unsupported_field(forward_body, &["maxSize"])
  {
    bail!("Gateway ExternalAuth forwardBody.{field} is unsupported");
  }
  let http = auth
    .get("http")
    .context("Gateway ExternalAuth protocol HTTP requires externalAuth.http")?;
  {
    if let Some(field) =
      super::unsupported_field(http, &["path", "allowedHeaders", "allowedResponseHeaders"])
    {
      bail!("Gateway ExternalAuth http.{field} is unsupported");
    }
    if let Some(path) = string_at(http, &["path"])
      && (!path.starts_with('/')
        || path.starts_with("//")
        || path.contains('?')
        || path.contains('#'))
    {
      bail!(
        "Gateway ExternalAuth http.path must start with one '/' and contain no query or fragment"
      );
    }
  }
  let backend_ref = auth
    .get("backendRef")
    .cloned()
    .context("ExternalAuth filter requires externalAuth.backendRef")?;
  Ok(ParsedExternalAuth {
    backend_ref,
    forward_headers: strict_string_array_at(http, "allowedHeaders")?,
    identity_headers: strict_string_array_at(http, "allowedResponseHeaders")?,
    terminal_response_headers: strict_string_array_at(http, "allowedResponseHeaders")?,
    path_prefix: string_at(http, &["path"]).map(str::to_string),
    max_request_body_bytes,
  })
}

fn parse_cors(filter: &Value) -> anyhow::Result<CorsAction> {
  let cors = filter.get("cors").context("CORS filter requires cors")?;
  Ok(CorsAction {
    allow_origins: string_array_at(cors, &["allowOrigins"]),
    allow_methods: string_array_at(cors, &["allowMethods"]),
    allow_headers: string_array_at(cors, &["allowHeaders"]),
    expose_headers: string_array_at(cors, &["exposeHeaders"]),
    allow_credentials: cors
      .get("allowCredentials")
      .and_then(Value::as_bool)
      .unwrap_or(false),
    max_age_seconds: u64_at(cors, &["maxAgeSeconds"]).or_else(|| duration_seconds(cors, "maxAge")),
  })
}

fn merge_header_modifier(target: &mut HeaderModifierAction, value: &Value) -> anyhow::Result<()> {
  target.set.extend(header_value_actions(value, "set")?);
  target.add.extend(header_value_actions(value, "add")?);
  target.remove.extend(string_array_at(value, &["remove"]));
  Ok(())
}

fn validate_request_header_modifier(
  modifier: &HeaderModifierAction,
  external_auth: Option<&ParsedExternalAuth>,
) -> anyhow::Result<()> {
  let identity_headers = external_auth
    .map(|auth| normalized_identity_headers(&auth.identity_headers))
    .transpose()?
    .unwrap_or_default();
  for entry in &modifier.set {
    validate_request_header_modifier_name("set", &entry.name, &identity_headers)?;
  }
  for entry in &modifier.add {
    validate_request_header_modifier_name("add", &entry.name, &identity_headers)?;
  }
  for name in &modifier.remove {
    validate_request_header_modifier_name("remove", name, &identity_headers)?;
  }
  Ok(())
}

fn normalized_identity_headers(headers: &[String]) -> anyhow::Result<HashSet<String>> {
  headers
    .iter()
    .map(|name| {
      oxibelt_control_protocol::normalize_route_action_header_name(name).with_context(|| {
        format!("ExternalAuth http.allowedResponseHeaders contains invalid header {name}")
      })
    })
    .collect()
}

fn validate_request_header_modifier_name(
  field_name: &str,
  name: &str,
  identity_headers: &HashSet<String>,
) -> anyhow::Result<()> {
  let normalized = oxibelt_control_protocol::normalize_route_action_header_name(name)
    .with_context(|| {
      format!("RequestHeaderModifier {field_name} contains invalid header {name}")
    })?;
  if oxibelt_control_protocol::is_reserved_route_request_header(&normalized) {
    bail!("RequestHeaderModifier {field_name} cannot mutate header {normalized}");
  }
  if identity_headers.contains(&normalized) {
    bail!(
      "RequestHeaderModifier {field_name} cannot mutate ExternalAuth identity header {normalized}"
    );
  }
  Ok(())
}

fn header_value_actions(value: &Value, key: &str) -> anyhow::Result<Vec<HeaderValueAction>> {
  let mut actions = Vec::new();
  for entry in value
    .get(key)
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default()
  {
    let name = string_at(&entry, &["name"]).context("header modifier entry requires name")?;
    let value = string_at(&entry, &["value"]).context("header modifier entry requires value")?;
    actions.push(HeaderValueAction {
      name: name.to_string(),
      value: value.to_string(),
    });
  }
  Ok(actions)
}

fn path_modifier_template(
  path: &Value,
  path_prefix: &str,
  path_match_type: &str,
) -> anyhow::Result<String> {
  let template = match string_at(path, &["type"]).unwrap_or("") {
    "ReplaceFullPath" => {
      if let Some(field) = super::unsupported_field(path, &["type", "replaceFullPath"]) {
        bail!("ReplaceFullPath field {field} is unsupported");
      }
      string_at(path, &["replaceFullPath"])
        .map(str::to_string)
        .context("ReplaceFullPath requires replaceFullPath")
    }
    "ReplacePrefixMatch" => {
      if let Some(field) = super::unsupported_field(path, &["type", "replacePrefixMatch"]) {
        bail!("ReplacePrefixMatch field {field} is unsupported");
      }
      if path_match_type != "PathPrefix" {
        bail!("ReplacePrefixMatch requires a PathPrefix route match");
      }
      let replacement = string_at(path, &["replacePrefixMatch"])
        .context("ReplacePrefixMatch requires replacePrefixMatch")?;
      if path_prefix == "/" {
        Ok(format!("{replacement}{{path_suffix}}"))
      } else if replacement == "/" {
        Ok("/{path_suffix}".to_string())
      } else {
        Ok(format!("{replacement}{{path_suffix}}"))
      }
    }
    other => bail!("unsupported path modifier type {other}"),
  }?;
  if !template.starts_with('/')
    || template.starts_with("//")
    || template.contains('?')
    || template.contains('#')
  {
    bail!("path replacement must start with one '/' and contain no query or fragment");
  }
  Ok(template)
}

fn validate_gateway_hostname(hostname: &str) -> anyhow::Result<String> {
  let valid = !hostname.is_empty()
    && hostname.len() <= 253
    && !hostname.ends_with('.')
    && !hostname.contains('*')
    && hostname.split('.').all(|label| {
      !label.is_empty()
        && label.len() <= 63
        && label
          .as_bytes()
          .first()
          .is_some_and(u8::is_ascii_alphanumeric)
        && label
          .as_bytes()
          .last()
          .is_some_and(u8::is_ascii_alphanumeric)
        && label
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
  if !valid {
    bail!("Gateway hostname must be a valid precise DNS hostname");
  }
  Ok(hostname.to_ascii_lowercase())
}

fn strict_optional_u16(value: &Value, field: &str) -> anyhow::Result<Option<u16>> {
  let Some(value) = value.get(field) else {
    return Ok(None);
  };
  let raw = value
    .as_u64()
    .with_context(|| format!("{field} must be an unsigned integer"))?;
  Ok(Some(u16::try_from(raw).with_context(|| {
    format!("{field} must be between 0 and 65535")
  })?))
}

fn string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
  let mut current = value;
  for key in path {
    let Some(next) = current.get(*key) else {
      return Vec::new();
    };
    current = next;
  }
  current
    .as_array()
    .map(|items| {
      items
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
    })
    .unwrap_or_default()
}

fn strict_string_array_at(value: &Value, key: &str) -> anyhow::Result<Vec<String>> {
  let Some(raw) = value.get(key) else {
    return Ok(Vec::new());
  };
  let items = raw
    .as_array()
    .with_context(|| format!("{key} must be an array"))?;
  items
    .iter()
    .map(|item| {
      item
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("{key} entries must be strings"))
    })
    .collect()
}

fn duration_seconds(value: &Value, key: &str) -> Option<u64> {
  let text = string_at(value, &[key])?;
  let seconds = text.strip_suffix('s').unwrap_or(text);
  seconds.parse().ok()
}

fn mirror_percent(value: &Value) -> Option<f64> {
  value
    .get("percent")
    .and_then(Value::as_f64)
    .or_else(|| value.get("percentage").and_then(Value::as_f64))
    .or_else(|| {
      let fraction = value.get("fraction")?;
      let numerator = fraction.get("numerator")?.as_f64()?;
      let denominator = fraction.get("denominator")?.as_f64()?;
      (denominator > 0.0).then_some((numerator / denominator) * 100.0)
    })
}
