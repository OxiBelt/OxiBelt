use anyhow::{Context, bail};
use serde_json::Value;

use super::{
  GeneratedRoute, NamedExactMatch, TranslationState, filters::ParsedRouteFilters,
  filters::parse_route_filters, intersect_hosts, sanitize_name, string_at,
};
use crate::model::{KubernetesObject, object_ref as model_object_ref};

impl TranslationState {
  pub(super) fn translate_grpc_route(&mut self, route: &KubernetesObject) {
    let attachments = self.attachments_for(route, &["HTTP", "HTTPS"]);
    if attachments.is_empty() {
      self.diagnostics.push(crate::model::Diagnostic::warning(
        model_object_ref(route),
        "route is not attached to an in-scope HTTP or HTTPS Gateway listener",
      ));
      return;
    }
    let client_identity = self.gateway_client_identity_for_route(route, &attachments);
    let tombstone = client_identity.is_tombstone();

    let route_hosts = super::string_array_at(&route.spec, &["hostnames"]);
    let rules = route.spec.get("rules").and_then(Value::as_array);
    let Some(rules) = rules else {
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        "GRPCRoute spec.rules is required",
      ));
      return;
    };

    for attachment in attachments {
      let Some(hosts) = intersect_hosts(&route_hosts, attachment.listener.hostname.as_deref())
      else {
        continue;
      };
      for (rule_index, rule) in rules.iter().enumerate() {
        let matches = rule
          .get("matches")
          .and_then(Value::as_array)
          .filter(|matches| !matches.is_empty())
          .cloned()
          .unwrap_or_else(|| vec![Value::Object(Default::default())]);
        for (match_index, route_match) in matches.iter().enumerate() {
          let source = format!(
            "GRPCRoute/{}/{} rule {} match {} via Gateway/{}/{}",
            route.namespace(),
            route.name(),
            rule_index,
            match_index,
            attachment.gateway.namespace,
            attachment.gateway.name,
          );
          let object_label = model_object_ref(route);
          let Ok((mut generated, filters)) = grpc_match_route(
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
          let tombstone_checkpoint = tombstone.then(|| self.generated_checkpoint());
          let tombstone_route = tombstone.then(|| generated.clone());
          if !self.apply_parsed_route_filters(
            route,
            "GRPCRoute",
            &mut generated,
            filters,
            &source,
            client_identity.as_identity(),
          ) {
            continue;
          }
          if let Some(pool) = self.backend_pool(
            route,
            "GRPCRoute",
            rule.get("backendRefs").and_then(Value::as_array),
            &generated.name,
            &source,
            client_identity.as_identity(),
          ) {
            if let (Some(checkpoint), Some(route)) = (tombstone_checkpoint, tombstone_route) {
              self.restore_generated(checkpoint);
              self.push_client_identity_tombstone(route);
              continue;
            }
            generated.upstream_pool = Some(pool.name.clone());
            self.pools.insert(pool.name.clone(), pool);
          } else {
            continue;
          }
          self.routes.push(generated);
        }
      }
    }
  }
}

fn grpc_match_route(
  route: &KubernetesObject,
  rule: &Value,
  route_match: &Value,
  hosts: &[String],
  rule_index: usize,
  match_index: usize,
  source: &str,
) -> anyhow::Result<(GeneratedRoute, ParsedRouteFilters)> {
  let (path_prefix, path_exact) = grpc_path_match(route_match)?;
  let headers = exact_named_matches(route_match, &["headers"], "header")?;
  let filters = parse_route_filters(rule, &path_prefix, "", None, "GRPCRoute")?;
  Ok((
    GeneratedRoute {
      source: source.to_string(),
      name: sanitize_name(&format!(
        "gwapi-grpc-{}-{}-{}-{}",
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
      methods: vec!["POST".to_string()],
      headers,
      queries: Vec::new(),
      priority: 11_000 - (rule_index as i32 * 100) - match_index as i32,
      upstream_pool: None,
      direct_response_status: None,
      rewrite: None,
      redirect: None,
      request_headers: Default::default(),
      response_headers: Default::default(),
      cors: None,
      request_mirrors: Vec::new(),
      external_auth: None,
      policy_source: None,
      waf_request_rule_groups: Vec::new(),
      max_request_body_bytes: None,
      upstream_request_timeout_ms: None,
    },
    filters,
  ))
}

fn grpc_path_match(route_match: &Value) -> anyhow::Result<(String, Option<String>)> {
  let Some(method_match) = route_match.get("method") else {
    return Ok(("/".to_string(), None));
  };
  let match_type = string_at(method_match, &["type"]).unwrap_or("Exact");
  if match_type != "Exact" {
    bail!("GRPCRoute RegularExpression method matches are unsupported in v1");
  }
  let service = string_at(method_match, &["service"]);
  let method = string_at(method_match, &["method"]);
  match (service, method) {
    (Some(service), Some(method)) => {
      let path = format!("/{service}/{method}");
      Ok((path.clone(), Some(path)))
    }
    (Some(service), None) => Ok((format!("/{service}/"), None)),
    (None, Some(_)) => bail!("GRPCRoute method-only matches are unsupported in v1"),
    (None, None) => Ok(("/".to_string(), None)),
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
