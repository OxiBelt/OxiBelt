use anyhow::{Context, bail};
use serde_json::Value;

use super::{
  GeneratedPool, GeneratedRoute, GeneratedServer, NamedExactMatch, ObjectKey, RedirectAction,
  RewriteAction, TranslationState, backend_port, backend_ref_is_service, intersect_hosts,
  sanitize_name, string_at, u16_at, u32_at,
};
use crate::model::{KubernetesObject, object_ref as model_object_ref};

impl TranslationState {
  pub(super) fn translate_http_route(&mut self, route: &KubernetesObject) {
    let attachments = self.attachments_for(route, &["HTTP", "HTTPS"]);
    if attachments.is_empty() {
      self.diagnostics.push(crate::model::Diagnostic::warning(
        model_object_ref(route),
        "route is not attached to an in-scope HTTP or HTTPS Gateway listener",
      ));
      return;
    }

    let route_hosts = super::string_array_at(&route.spec, &["hostnames"]);
    let rules = route.spec.get("rules").and_then(Value::as_array);
    let Some(rules) = rules else {
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        "HTTPRoute spec.rules is required",
      ));
      return;
    };

    for attachment in attachments {
      let hosts = intersect_hosts(&route_hosts, attachment.listener.hostname.as_deref());
      for (rule_index, rule) in rules.iter().enumerate() {
        let matches = rule
          .get("matches")
          .and_then(Value::as_array)
          .filter(|matches| !matches.is_empty())
          .cloned()
          .unwrap_or_else(|| vec![Value::Object(Default::default())]);
        for (match_index, route_match) in matches.iter().enumerate() {
          let source = format!(
            "HTTPRoute/{}/{} rule {} match {} via Gateway/{}/{}",
            route.namespace(),
            route.name(),
            rule_index,
            match_index,
            attachment.gateway.namespace,
            attachment.gateway.name,
          );
          let object_label = model_object_ref(route);
          let Ok(mut generated) = http_match_route(
            route,
            rule,
            route_match,
            &hosts,
            rule_index,
            match_index,
            &source,
          )
          .inspect_err(|error| {
            self.diagnostics.push(crate::model::Diagnostic::error(
              object_label.clone(),
              error.to_string(),
            ));
          }) else {
            continue;
          };

          if let Some(pool) = self.backend_pool(
            route,
            "HTTPRoute",
            rule.get("backendRefs").and_then(Value::as_array),
            &generated.name,
            &source,
          ) {
            generated.upstream_pool = Some(pool.name.clone());
            self.pools.insert(pool.name.clone(), pool);
          } else if generated.redirect.is_none() {
            continue;
          }
          self.routes.push(generated);
        }
      }
    }
  }

  fn backend_pool(
    &mut self,
    route: &KubernetesObject,
    from_kind: &str,
    backend_refs: Option<&Vec<Value>>,
    route_name: &str,
    source: &str,
  ) -> Option<GeneratedPool> {
    let Some(backend_refs) = backend_refs else {
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        "rule.backendRefs is required unless the route redirects",
      ));
      return None;
    };
    let mut servers = Vec::new();
    for (index, backend) in backend_refs.iter().enumerate() {
      let weight = u32_at(backend, &["weight"]).unwrap_or(1);
      if weight == 0 {
        continue;
      }
      let Some(server) = self.backend_server(route, from_kind, backend, index, weight) else {
        continue;
      };
      servers.push(server);
    }
    if servers.is_empty() {
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        "rule.backendRefs has no usable nonzero Service backend",
      ));
      return None;
    }
    let name = sanitize_name(&format!("{route_name}-pool"));
    Some(GeneratedPool {
      source: source.to_string(),
      name,
      servers,
    })
  }

  fn backend_server(
    &mut self,
    route: &KubernetesObject,
    from_kind: &str,
    backend: &Value,
    index: usize,
    weight: u32,
  ) -> Option<GeneratedServer> {
    if !backend_ref_is_service(backend) {
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        "only Kubernetes Service backendRefs are supported",
      ));
      return None;
    }
    let name = string_at(backend, &["name"])?;
    let namespace = string_at(backend, &["namespace"]).unwrap_or(route.namespace());
    if namespace != route.namespace()
      && !self.reference_allowed(route, from_kind, namespace, "Service", name)
    {
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        format!("cross-namespace backendRef to {namespace}/{name} requires ReferenceGrant"),
      ));
      return None;
    }
    let key = ObjectKey {
      namespace: namespace.to_string(),
      name: name.to_string(),
    };
    let Some(service) = self.services.get(&key) else {
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        format!("backend Service {namespace}/{name} was not found in input snapshot"),
      ));
      return None;
    };
    let Some(port) = backend_port(backend, service) else {
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        format!("backend Service {namespace}/{name} does not expose the referenced port"),
      ));
      return None;
    };
    let origin = format!(
      "{}://{}.{}.svc.cluster.local:{}",
      service.scheme, service.name, service.namespace, port
    );
    Some(GeneratedServer {
      id: sanitize_name(&format!("{namespace}-{name}-{port}-{index}")),
      origin,
      weight,
    })
  }
}

fn http_match_route(
  route: &KubernetesObject,
  rule: &Value,
  route_match: &Value,
  hosts: &[String],
  rule_index: usize,
  match_index: usize,
  source: &str,
) -> anyhow::Result<GeneratedRoute> {
  let path = route_match.get("path");
  let path_type = path
    .and_then(|path| string_at(path, &["type"]))
    .unwrap_or("PathPrefix");
  let path_value = path
    .and_then(|path| string_at(path, &["value"]))
    .unwrap_or("/");
  let mut path_prefix = path_value.to_string();
  let mut path_exact = None;
  match path_type {
    "PathPrefix" => {}
    "Exact" => path_exact = Some(path_value.to_string()),
    "RegularExpression" => bail!("RegularExpression path matches are unsupported in v1"),
    other => bail!("unsupported HTTPRoute path match type {other}"),
  }
  if path_prefix.is_empty() {
    path_prefix = "/".to_string();
  }
  let mut methods = Vec::new();
  if let Some(method) = string_at(route_match, &["method"]) {
    if method == "*" {
      bail!("HTTPRoute wildcard method matches are unsupported in v1");
    }
    methods.push(method.to_string());
  }
  let headers = exact_named_matches(route_match, &["headers"], "header")?;
  let queries = exact_named_matches(route_match, &["queryParams"], "query")?;
  let (rewrite, redirect) = route_actions(rule, &path_prefix)?;
  Ok(GeneratedRoute {
    source: source.to_string(),
    name: sanitize_name(&format!(
      "gwapi-http-{}-{}-{}-{}",
      route.namespace(),
      route.name(),
      rule_index,
      match_index
    )),
    hosts: if hosts.is_empty() {
      vec!["*".to_string()]
    } else {
      hosts.to_vec()
    },
    path_prefix,
    path_exact,
    methods,
    headers,
    queries,
    priority: 10_000 - (rule_index as i32 * 100) - match_index as i32,
    upstream_pool: None,
    rewrite,
    redirect,
  })
}

fn route_actions(
  rule: &Value,
  path_prefix: &str,
) -> anyhow::Result<(Option<RewriteAction>, Option<RedirectAction>)> {
  let mut rewrite = None;
  let mut redirect = None;
  for filter in rule
    .get("filters")
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default()
  {
    match string_at(&filter, &["type"]).unwrap_or("") {
      "URLRewrite" => {
        if rewrite.is_some() {
          bail!("only one URLRewrite filter is supported per rule");
        }
        if redirect.is_some() {
          bail!("URLRewrite and RequestRedirect filters cannot be combined");
        }
        rewrite = Some(parse_rewrite(&filter, path_prefix)?);
      }
      "RequestRedirect" => {
        if redirect.is_some() {
          bail!("only one RequestRedirect filter is supported per rule");
        }
        if rewrite.is_some() {
          bail!("URLRewrite and RequestRedirect filters cannot be combined");
        }
        redirect = Some(parse_redirect(&filter, path_prefix)?);
      }
      "RequestHeaderModifier"
      | "ResponseHeaderModifier"
      | "RequestMirror"
      | "CORS"
      | "ExtensionRef"
      | "ExternalAuth" => bail!("HTTPRoute filter is unsupported in v1"),
      "" => bail!("HTTPRoute filter type is required"),
      other => bail!("HTTPRoute filter type {other} is unsupported in v1"),
    }
  }
  Ok((rewrite, redirect))
}

fn parse_rewrite(filter: &Value, path_prefix: &str) -> anyhow::Result<RewriteAction> {
  if string_at(filter, &["urlRewrite", "hostname"]).is_some() {
    bail!("URLRewrite hostname is unsupported in v1");
  }
  let path = match filter
    .get("urlRewrite")
    .and_then(|rewrite| rewrite.get("path"))
  {
    Some(path) => Some(path_modifier_template(path, path_prefix)?),
    None => None,
  };
  Ok(RewriteAction { path, query: None })
}

fn parse_redirect(filter: &Value, path_prefix: &str) -> anyhow::Result<RedirectAction> {
  let redirect = filter
    .get("requestRedirect")
    .context("RequestRedirect filter requires requestRedirect")?;
  if string_at(redirect, &["scheme"]).is_some()
    || string_at(redirect, &["hostname"]).is_some()
    || u16_at(redirect, &["port"]).is_some()
  {
    bail!("RequestRedirect scheme, hostname, and port are unsupported in v1");
  }
  let status = u16_at(redirect, &["statusCode"]).unwrap_or(302);
  if !matches!(status, 301 | 302 | 303 | 307 | 308) {
    bail!("RequestRedirect statusCode must be one of 301, 302, 303, 307, or 308");
  }
  let location_template = match redirect.get("path") {
    Some(path) => path_modifier_template(path, path_prefix)?,
    None => "{path}".to_string(),
  };
  Ok(RedirectAction {
    status,
    location_template,
  })
}

fn path_modifier_template(path: &Value, path_prefix: &str) -> anyhow::Result<String> {
  match string_at(path, &["type"]).unwrap_or("") {
    "ReplaceFullPath" => string_at(path, &["replaceFullPath"])
      .map(str::to_string)
      .context("ReplaceFullPath requires replaceFullPath"),
    "ReplacePrefixMatch" => {
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
  }
}

fn exact_named_matches(
  value: &Value,
  field: &[&str],
  label: &str,
) -> anyhow::Result<Vec<NamedExactMatch>> {
  let mut matches = Vec::new();
  for item in value
    .pointer(&format!("/{}", field.join("/")))
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default()
  {
    let match_type = string_at(&item, &["type"]).unwrap_or("Exact");
    if match_type != "Exact" {
      bail!("only Exact {label} matches are supported in v1");
    }
    let name = string_at(&item, &["name"]).context("named match requires name")?;
    let value = string_at(&item, &["value"]).context("Exact named match requires value")?;
    matches.push(NamedExactMatch {
      name: name.to_string(),
      value: value.to_string(),
    });
  }
  Ok(matches)
}
