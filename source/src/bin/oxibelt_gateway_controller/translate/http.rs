use anyhow::{Context, bail};
use serde_json::Value;

use super::{
  GeneratedExternalAuth, GeneratedPool, GeneratedRoute, GeneratedServer, NamedExactMatch,
  ObjectKey, TranslationState, backend_port, backend_ref_is_service, filters::ParsedRouteFilters,
  filters::parse_route_filters, intersect_hosts, sanitize_name, string_at, u32_at,
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
          let Ok((mut generated, filters)) = http_match_route(
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

          if !self.apply_parsed_route_filters(route, "HTTPRoute", &mut generated, filters, &source)
          {
            continue;
          }
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

  pub(super) fn backend_pool(
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

  pub(super) fn backend_server(
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

  pub(super) fn apply_parsed_route_filters(
    &mut self,
    route: &KubernetesObject,
    from_kind: &str,
    generated: &mut GeneratedRoute,
    filters: ParsedRouteFilters,
    source: &str,
  ) -> bool {
    generated.request_headers = filters.request_headers;
    generated.response_headers = filters.response_headers;
    generated.cors = filters.cors;
    generated.rewrite = filters.rewrite;
    generated.redirect = filters.redirect;
    for (index, mirror) in filters.request_mirrors.into_iter().enumerate() {
      let backend_refs = vec![mirror.backend_ref];
      let route_name = sanitize_name(&format!("{}-mirror-{index}", generated.name));
      let Some(pool) =
        self.backend_pool(route, from_kind, Some(&backend_refs), &route_name, source)
      else {
        return false;
      };
      let mut action = mirror.action;
      action.upstream_pool = pool.name.clone();
      generated.request_mirrors.push(action);
      self.pools.insert(pool.name.clone(), pool);
    }
    if let Some(auth) = filters.external_auth {
      let Some(server) = self.backend_server(route, from_kind, &auth.backend_ref, 0, 1) else {
        return false;
      };
      let name = sanitize_name(&format!("{}-ext-auth", generated.name));
      self.external_auth.insert(
        name.clone(),
        GeneratedExternalAuth {
          source: source.to_string(),
          name: name.clone(),
          endpoint: server.origin,
          forward_headers: auth.forward_headers,
          identity_headers: auth.identity_headers,
          terminal_response_headers: auth.terminal_response_headers,
        },
      );
      generated.external_auth = Some(name);
    }
    true
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
) -> anyhow::Result<(GeneratedRoute, ParsedRouteFilters)> {
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
  let filters = parse_route_filters(rule, &path_prefix, "HTTPRoute")?;
  Ok((
    GeneratedRoute {
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
      rewrite: None,
      redirect: None,
      request_headers: Default::default(),
      response_headers: Default::default(),
      cors: None,
      request_mirrors: Vec::new(),
      external_auth: None,
    },
    filters,
  ))
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
