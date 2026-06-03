//! Route-level rewrite and redirect actions.
//! Templates combine validated config with untrusted request metadata, so rendered outputs are rechecked before use.

use std::str::FromStr;

use anyhow::{Context, bail};
use http::header::LOCATION;
use http::uri::PathAndQuery;
use http::{HeaderValue, Response, StatusCode, Uri};

use crate::config::RouteConfig;
use crate::routes::ResolvedRoute;

use super::body::ProxyBody;
use super::response::text_response;
use super::uri::{UpstreamUriParts, build_uri, join_paths, rewrite_uri, validate_downstream_path};

#[derive(Clone, Copy)]
pub(super) struct RouteActionRenderContext<'a> {
  pub(super) route_prefix: &'a str,
  pub(super) path_captures: &'a [String],
  pub(super) downstream_scheme: &'a str,
  pub(super) downstream_host: &'a str,
  pub(super) downstream_uri: &'a Uri,
}

pub(super) fn build_resolved_upstream_uri(
  origin: &UpstreamUriParts,
  resolved: &ResolvedRoute<'_>,
  downstream_scheme: &str,
  downstream_host: &str,
  downstream_uri: &Uri,
) -> anyhow::Result<Uri> {
  build_upstream_uri(
    origin,
    resolved.route,
    resolved_context(resolved, downstream_scheme, downstream_host, downstream_uri),
  )
}

pub(super) fn build_upstream_uri(
  origin: &UpstreamUriParts,
  route: &RouteConfig,
  context: RouteActionRenderContext<'_>,
) -> anyhow::Result<Uri> {
  let Some(rewrite) = route.actions.rewrite.as_ref() else {
    return rewrite_uri(
      origin,
      context.route_prefix,
      route.replace_prefix_with.as_deref(),
      context.downstream_uri,
    );
  };

  let rendered_path = if let Some(template) = rewrite.path.as_deref() {
    render_template(template, context)
      .with_context(|| format!("route {} actions.rewrite.path failed to render", route.name))?
  } else {
    context.downstream_uri.path().to_string()
  };
  validate_rendered_path(&rendered_path).with_context(|| {
    format!(
      "route {} actions.rewrite.path rendered an unsafe path",
      route.name
    )
  })?;

  let rendered_query = match rewrite.query.as_deref() {
    Some(template) => Some(render_query_template(template, context).with_context(|| {
      format!(
        "route {} actions.rewrite.query failed to render",
        route.name
      )
    })?),
    None => context.downstream_uri.query().map(str::to_string),
  };
  if let Some(query) = rendered_query.as_deref() {
    validate_rendered_query(query).with_context(|| {
      format!(
        "route {} actions.rewrite.query rendered an unsafe query",
        route.name
      )
    })?;
  }

  let upstream_path = join_paths(origin.base_path(), &rendered_path);
  let path_and_query = match rendered_query {
    Some(query) if !query.is_empty() => {
      let mut value = String::with_capacity(upstream_path.len() + 1 + query.len());
      value.push_str(&upstream_path);
      value.push('?');
      value.push_str(&query);
      value
    }
    _ => upstream_path,
  };
  let path_and_query = PathAndQuery::from_str(path_and_query.as_str())
    .map_err(|error| anyhow::anyhow!("failed to build route action URI: {error}"))?;
  build_uri(origin, path_and_query)
}

pub(super) fn resolved_redirect_response(
  resolved: &ResolvedRoute<'_>,
  downstream_scheme: &str,
  downstream_host: &str,
  downstream_uri: &Uri,
) -> anyhow::Result<Option<Response<ProxyBody>>> {
  redirect_response(
    resolved.route,
    resolved_context(resolved, downstream_scheme, downstream_host, downstream_uri),
  )
}

pub(super) fn redirect_response(
  route: &RouteConfig,
  context: RouteActionRenderContext<'_>,
) -> anyhow::Result<Option<Response<ProxyBody>>> {
  let Some(redirect) = route.actions.redirect.as_ref() else {
    return Ok(None);
  };
  let status = redirect
    .status
    .ok_or_else(|| anyhow::anyhow!("actions.redirect.status is missing after validation"))?;
  let status = StatusCode::from_u16(status)
    .map_err(|error| anyhow::anyhow!("actions.redirect.status is invalid: {error}"))?;
  let template = redirect.location_template.as_deref().ok_or_else(|| {
    anyhow::anyhow!("actions.redirect.location_template is missing after validation")
  })?;
  let location = render_template(template, context).with_context(|| {
    format!(
      "route {} actions.redirect.location_template failed to render",
      route.name
    )
  })?;
  validate_redirect_location(&location).with_context(|| {
    format!(
      "route {} actions.redirect.location_template rendered an unsafe location",
      route.name
    )
  })?;

  let mut response = text_response(status, "");
  let location = HeaderValue::from_str(&location).map_err(|error| {
    anyhow::anyhow!("rendered redirect location is not a header value: {error}")
  })?;
  response.headers_mut().insert(LOCATION, location);
  Ok(Some(response))
}

fn resolved_context<'a>(
  resolved: &'a ResolvedRoute<'_>,
  downstream_scheme: &'a str,
  downstream_host: &'a str,
  downstream_uri: &'a Uri,
) -> RouteActionRenderContext<'a> {
  RouteActionRenderContext {
    route_prefix: resolved.route.effective_path_prefix(),
    path_captures: &resolved.path_captures,
    downstream_scheme,
    downstream_host,
    downstream_uri,
  }
}

fn render_template(
  template: &str,
  context: RouteActionRenderContext<'_>,
) -> anyhow::Result<String> {
  render_template_with(template, context, RouteActionTemplateTarget::Raw)
}

fn render_query_template(
  template: &str,
  context: RouteActionRenderContext<'_>,
) -> anyhow::Result<String> {
  render_template_with(template, context, RouteActionTemplateTarget::QueryComponent)
}

#[derive(Clone, Copy)]
enum RouteActionTemplateTarget {
  Raw,
  QueryComponent,
}

fn render_template_with(
  template: &str,
  context: RouteActionRenderContext<'_>,
  target: RouteActionTemplateTarget,
) -> anyhow::Result<String> {
  let mut rendered = String::with_capacity(template.len());
  let mut index = 0;
  let mut literal_start = 0;
  let bytes = template.as_bytes();
  while index < bytes.len() {
    match bytes[index] {
      b'{' => {
        rendered.push_str(&template[literal_start..index]);
        let Some(close_offset) = bytes[index + 1..].iter().position(|byte| *byte == b'}') else {
          bail!("unterminated route action template token");
        };
        let close = index + 1 + close_offset;
        let token = &template[index + 1..close];
        rendered.push_str(&render_template_token(token, context, target)?);
        index = close + 1;
        literal_start = index;
      }
      b'}' => bail!("unmatched route action template token close"),
      _ => {
        let Some(ch) = template[index..].chars().next() else {
          break;
        };
        index += ch.len_utf8();
      }
    }
  }
  rendered.push_str(&template[literal_start..]);
  Ok(rendered)
}

fn render_template_token(
  token: &str,
  context: RouteActionRenderContext<'_>,
  target: RouteActionTemplateTarget,
) -> anyhow::Result<String> {
  match token {
    "scheme" => Ok(render_token_value(context.downstream_scheme, target)),
    "host" => Ok(render_token_value(context.downstream_host, target)),
    "path" => Ok(render_token_value(context.downstream_uri.path(), target)),
    "path_suffix" => Ok(render_token_value(
      path_suffix(context.route_prefix, context.downstream_uri.path()),
      target,
    )),
    "query" => Ok(render_token_value(
      context.downstream_uri.query().unwrap_or(""),
      target,
    )),
    _ => {
      if let Some(name) = token.strip_prefix("query:") {
        let value = query_value(context.downstream_uri.query().unwrap_or(""), name);
        return Ok(encode_query_component(&value));
      }
      if let Some(index) = token.strip_prefix("capture:") {
        let index = index
          .parse::<usize>()
          .map_err(|error| anyhow::anyhow!("invalid capture token {{{token}}}: {error}"))?;
        let capture = context.path_captures.get(index).ok_or_else(|| {
          anyhow::anyhow!("capture token {{{token}}} is unavailable for this route match")
        })?;
        return Ok(encode_query_component(capture));
      }
      bail!("unsupported route action template token {{{token}}}");
    }
  }
}

fn render_token_value(value: &str, target: RouteActionTemplateTarget) -> String {
  match target {
    RouteActionTemplateTarget::Raw => value.to_string(),
    RouteActionTemplateTarget::QueryComponent => encode_query_component(value),
  }
}

fn path_suffix<'a>(route_prefix: &str, path: &'a str) -> &'a str {
  if route_prefix == "/" {
    return path;
  }
  if path == route_prefix {
    return "";
  }
  path.strip_prefix(route_prefix).unwrap_or(path)
}

fn query_value(query: &str, name: &str) -> String {
  url::form_urlencoded::parse(query.as_bytes())
    .find_map(|(candidate, value)| (candidate.as_ref() == name).then(|| value.into_owned()))
    .unwrap_or_default()
}

fn encode_query_component(value: &str) -> String {
  url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn validate_rendered_path(path: &str) -> anyhow::Result<()> {
  if !path.starts_with('/') || path.starts_with("//") {
    bail!("rendered route action path must start with one '/'");
  }
  if path.bytes().any(|byte| matches!(byte, b'?' | b'#')) {
    bail!("rendered route action path must not contain queries or fragments");
  }
  validate_downstream_path(path)
}

fn validate_rendered_query(query: &str) -> anyhow::Result<()> {
  if query
    .bytes()
    .any(|byte| byte.is_ascii_control() || matches!(byte, b'#'))
  {
    bail!("rendered route action query contains unsafe characters");
  }
  Ok(())
}

fn validate_redirect_location(location: &str) -> anyhow::Result<()> {
  if !location.starts_with('/') || location.starts_with("//") {
    bail!("rendered redirect location must start with one '/'");
  }
  if location
    .bytes()
    .any(|byte| byte.is_ascii_control() || matches!(byte, b'\\' | b'#'))
  {
    bail!("rendered redirect location contains unsafe characters");
  }
  PathAndQuery::from_str(location)
    .map_err(|error| anyhow::anyhow!("rendered redirect location is not path/query: {error}"))?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use http::Uri;

  use super::*;
  use crate::config::{RouteActionsConfig, RouteRedirectActionConfig, RouteRewriteActionConfig};

  fn route_with_rewrite(path: Option<&str>, query: Option<&str>) -> RouteConfig {
    RouteConfig {
      name: "route".to_string(),
      hosts: vec!["example.test".to_string()],
      path_prefix: "/api".to_string(),
      r#match: Default::default(),
      replace_prefix_with: None,
      actions: RouteActionsConfig {
        rewrite: Some(RouteRewriteActionConfig {
          path: path.map(str::to_string),
          query: query.map(str::to_string),
        }),
        redirect: None,
      },
      upstream: Some("app".to_string()),
      upstream_pool: None,
      static_root: None,
      upstream_http_version: None,
      generic_http_upgrade: false,
      connect_tunneling: false,
      grpc_web: false,
      external_auth: None,
      ipm: Default::default(),
      cache: None,
      compression: None,
      buffering: Default::default(),
      timeouts: Default::default(),
      retry: None,
      waf: Default::default(),
    }
  }

  fn context<'a>(
    route: &'a RouteConfig,
    captures: &'a [String],
    uri: &'a Uri,
  ) -> RouteActionRenderContext<'a> {
    RouteActionRenderContext {
      route_prefix: route.effective_path_prefix(),
      path_captures: captures,
      downstream_scheme: "https",
      downstream_host: "example.test",
      downstream_uri: uri,
    }
  }

  #[test]
  fn rewrite_preserves_query_when_omitted() {
    let origin =
      UpstreamUriParts::from_url(&url::Url::parse("http://upstream/base").unwrap()).unwrap();
    let route = route_with_rewrite(Some("/edge{path_suffix}"), None);
    let uri = Uri::from_static("/api/orders?id=42");

    let rewritten = build_upstream_uri(&origin, &route, context(&route, &[], &uri)).unwrap();

    assert_eq!(
      rewritten.to_string(),
      "http://upstream/base/edge/orders?id=42"
    );
  }

  #[test]
  fn rewrite_empty_query_removes_query() {
    let origin = UpstreamUriParts::from_url(&url::Url::parse("http://upstream").unwrap()).unwrap();
    let route = route_with_rewrite(Some("/edge{path_suffix}"), Some(""));
    let uri = Uri::from_static("/api/orders?id=42");

    let rewritten = build_upstream_uri(&origin, &route, context(&route, &[], &uri)).unwrap();

    assert_eq!(rewritten.to_string(), "http://upstream/edge/orders");
  }

  #[test]
  fn rewrite_replaces_query_from_tokens() {
    let origin = UpstreamUriParts::from_url(&url::Url::parse("http://upstream").unwrap()).unwrap();
    let route = route_with_rewrite(Some("/edge"), Some("id={capture:1}&debug={query:debug}"));
    let captures = vec!["/api/123".to_string(), "123".to_string()];
    let uri = Uri::from_static("/api/123?debug=a%20b");

    let rewritten = build_upstream_uri(&origin, &route, context(&route, &captures, &uri)).unwrap();

    assert_eq!(
      rewritten.to_string(),
      "http://upstream/edge?id=123&debug=a+b"
    );
  }

  #[test]
  fn rewrite_query_encodes_path_suffix_as_component() {
    let origin = UpstreamUriParts::from_url(&url::Url::parse("http://upstream").unwrap()).unwrap();
    let route = route_with_rewrite(Some("/edge"), Some("item={path_suffix}"));
    let uri = Uri::from_static("/api/foo&admin=true");

    let rewritten = build_upstream_uri(&origin, &route, context(&route, &[], &uri)).unwrap();

    assert_eq!(
      rewritten.to_string(),
      "http://upstream/edge?item=%2Ffoo%26admin%3Dtrue"
    );
  }

  #[test]
  fn rewrite_query_encodes_original_query_as_component() {
    let origin = UpstreamUriParts::from_url(&url::Url::parse("http://upstream").unwrap()).unwrap();
    let route = route_with_rewrite(Some("/edge"), Some("original={query}"));
    let uri = Uri::from_static("/api/orders?a=1&admin=true");

    let rewritten = build_upstream_uri(&origin, &route, context(&route, &[], &uri)).unwrap();

    assert_eq!(
      rewritten.to_string(),
      "http://upstream/edge?original=a%3D1%26admin%3Dtrue"
    );
  }

  #[test]
  fn rewrite_absolute_form_downstream_uri_uses_path_and_query() {
    let origin = UpstreamUriParts::from_url(&url::Url::parse("http://upstream").unwrap()).unwrap();
    let route = route_with_rewrite(Some("/edge{path_suffix}"), None);
    let uri: Uri = "http://example.test/api/orders?id=42".parse().unwrap();

    let rewritten = build_upstream_uri(&origin, &route, context(&route, &[], &uri)).unwrap();

    assert_eq!(rewritten.to_string(), "http://upstream/edge/orders?id=42");
  }

  #[test]
  fn rewrite_fails_closed_on_unsafe_rendered_path() {
    let origin = UpstreamUriParts::from_url(&url::Url::parse("http://upstream").unwrap()).unwrap();
    let route = route_with_rewrite(Some("//edge"), None);
    let uri = Uri::from_static("/api/orders");

    assert!(build_upstream_uri(&origin, &route, context(&route, &[], &uri)).is_err());
  }

  #[test]
  fn redirect_builds_origin_relative_location() {
    let mut route = route_with_rewrite(None, None);
    route.actions = RouteActionsConfig {
      rewrite: None,
      redirect: Some(RouteRedirectActionConfig {
        status: Some(308),
        location_template: Some("/new{path_suffix}?{query}".to_string()),
      }),
    };
    let uri = Uri::from_static("/api/orders?id=42");

    let response = redirect_response(&route, context(&route, &[], &uri))
      .unwrap()
      .unwrap();

    assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(response.headers()[LOCATION], "/new/orders?id=42");
  }

  #[test]
  fn redirect_rejects_absolute_network_path_location() {
    let mut route = route_with_rewrite(None, None);
    route.actions = RouteActionsConfig {
      rewrite: None,
      redirect: Some(RouteRedirectActionConfig {
        status: Some(302),
        location_template: Some("/{path}".to_string()),
      }),
    };
    let uri = Uri::from_static("/api/orders");

    assert!(redirect_response(&route, context(&route, &[], &uri)).is_err());
  }
}
