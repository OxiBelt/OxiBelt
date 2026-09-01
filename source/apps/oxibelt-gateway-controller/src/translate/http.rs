use anyhow::{Context, bail};
use serde_json::Value;

use super::{
  GeneratedClientIdentity, GeneratedExternalAuth, GeneratedKubernetesDiscovery, GeneratedPool,
  GeneratedRoute, GeneratedServer, NamedExactMatch, ObjectKey, TranslationState, backend_port,
  backend_service_port, endpoint_slice_discovery_port, exact_service_backend_ref,
  filters::ParsedRouteFilters, filters::parse_route_filters, intersect_hosts, sanitize_name,
  string_at,
};
use crate::cli::BackendResolution;
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
    let client_identity = self.gateway_client_identity_for_route(route, &attachments);
    let tombstone = client_identity.is_tombstone();

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
            "HTTPRoute/{}/{} rule {} match {} via Gateway/{}/{}",
            route.namespace(),
            route.name(),
            rule_index,
            match_index,
            attachment.gateway.namespace,
            attachment.gateway.name,
          );
          let object_label = model_object_ref(route);
          let context = HttpMatchContext {
            rule_index,
            match_index,
            source: &source,
            listener_port: attachment.listener.port,
          };
          let Ok((mut generated, filters)) =
            http_match_route(route, rule, route_match, &hosts, context).inspect_err(|error| {
              self.diagnostics.push(crate::model::Diagnostic::error(
                object_label.clone(),
                error.to_string(),
              ));
            })
          else {
            continue;
          };
          let tombstone_checkpoint = self.generated_checkpoint();
          let tombstone_route = generated.clone();

          if let Err(failure) = self.apply_parsed_route_filters(
            route,
            "HTTPRoute",
            &mut generated,
            filters,
            &source,
            client_identity.as_identity(),
          ) {
            self.complete_fail_closed_tombstone(tombstone_checkpoint, tombstone_route, failure);
            continue;
          }
          if generated.redirect.is_some()
            && rule
              .get("backendRefs")
              .and_then(Value::as_array)
              .is_some_and(|backends| !backends.is_empty())
          {
            self.diagnostics.push(crate::model::Diagnostic::error(
              model_object_ref(route),
              "RequestRedirect rules cannot also configure backendRefs",
            ));
            continue;
          }
          if generated.redirect.is_some() {
            if tombstone {
              self.restore_generated(tombstone_checkpoint);
              self.push_fail_closed_tombstone(tombstone_route);
            } else {
              self.routes.push(generated);
            }
            continue;
          }
          let pool = match self.backend_pool(
            route,
            "HTTPRoute",
            rule.get("backendRefs").and_then(Value::as_array),
            &generated.name,
            &source,
            client_identity.as_identity(),
          ) {
            Ok(pool) => pool,
            Err(failure) => {
              self.complete_fail_closed_tombstone(tombstone_checkpoint, tombstone_route, failure);
              continue;
            }
          };
          if tombstone {
            self.restore_generated(tombstone_checkpoint);
            self.push_fail_closed_tombstone(tombstone_route);
            continue;
          }
          generated.upstream_pool = Some(pool.name.clone());
          self.pools.insert(pool.name.clone(), pool);
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
    client_identity: Option<&GeneratedClientIdentity>,
  ) -> Result<GeneratedPool, super::TranslationFailure> {
    let Some(backend_refs) = backend_refs else {
      return Err(self.preserve_last_good_error(
        model_object_ref(route),
        "rule.backendRefs is required unless the route redirects",
      ));
    };
    let mut nonzero_backends = Vec::new();
    for (index, backend) in backend_refs.iter().enumerate() {
      let weight = match gateway_backend_weight(backend) {
        Ok(weight) => weight,
        Err(message) => {
          return Err(self.preserve_last_good_error(
            model_object_ref(route),
            format!("rule.backendRefs[{index}].weight {message}"),
          ));
        }
      };
      if weight > 0 {
        nonzero_backends.push((index, backend, weight));
      }
    }
    if nonzero_backends.is_empty() {
      return Err(self.preserve_last_good_error(
        model_object_ref(route),
        "rule.backendRefs has no usable nonzero Service backend",
      ));
    }
    if self.backend_resolution == BackendResolution::EndpointSliceWatch {
      let mut discoveries = Vec::with_capacity(nonzero_backends.len());
      for (index, backend, weight) in nonzero_backends {
        let discovery = self.backend_discovery(
          route,
          from_kind,
          (backend, index, weight),
          route_name,
          client_identity,
        )?;
        discoveries.push(discovery);
      }
      let name = sanitize_name(&format!("{route_name}-pool"));
      return Ok(GeneratedPool {
        source: source.to_string(),
        name,
        servers: Vec::new(),
        discoveries,
      });
    }

    let mut servers = Vec::new();
    for (index, backend, weight) in nonzero_backends {
      let server =
        self.backend_server(route, from_kind, backend, index, weight, client_identity)?;
      servers.push(server);
    }
    let name = sanitize_name(&format!("{route_name}-pool"));
    Ok(GeneratedPool {
      source: source.to_string(),
      name,
      servers,
      discoveries: Vec::new(),
    })
  }

  pub(super) fn backend_server(
    &mut self,
    route: &KubernetesObject,
    from_kind: &str,
    backend: &Value,
    index: usize,
    weight: u32,
    client_identity: Option<&GeneratedClientIdentity>,
  ) -> Result<GeneratedServer, super::TranslationFailure> {
    let (namespace, name) =
      exact_service_backend_ref(backend, route.namespace()).map_err(|error| {
        self.preserve_last_good_error(
          model_object_ref(route),
          format!("backendRef is not an exact Kubernetes Service reference: {error}"),
        )
      })?;
    if namespace != route.namespace()
      && !self.reference_allowed(route, from_kind, &namespace, "Service", &name)
    {
      return Err(self.fail_closed_error(
        model_object_ref(route),
        format!("cross-namespace backendRef to {namespace}/{name} requires ReferenceGrant"),
      ));
    }
    let key = ObjectKey {
      namespace: namespace.clone(),
      name: name.clone(),
    };
    let Some(service) = self.services.get(&key).cloned() else {
      let failure = self.fail_closed_error(
        model_object_ref(route),
        format!("backend Service {namespace}/{name} was not found in input snapshot"),
      );
      return Err(failure.with_covered_diagnostics(self.backend_tls_covered_diagnostics(&key)));
    };
    let Some(port) = backend_port(backend, &service) else {
      let failure = self.fail_closed_error(
        model_object_ref(route),
        format!("backend Service {namespace}/{name} does not expose the referenced port"),
      );
      return Err(failure.with_covered_diagnostics(self.backend_tls_covered_diagnostics(&key)));
    };
    let mut tls = self.backend_tls_for_service(route, &key)?;
    if let (Some(tls), Some(client_identity)) = (&mut tls, client_identity) {
      tls.client_identity = Some(client_identity.clone());
    }
    let scheme = if tls.is_some() {
      "https"
    } else {
      service.scheme.as_str()
    };
    let origin = format!(
      "{}://{}.{}.svc.cluster.local:{}",
      scheme, service.name, service.namespace, port
    );
    Ok(GeneratedServer {
      id: sanitize_name(&format!("{namespace}-{name}-{port}-{index}")),
      origin,
      weight,
      tls,
    })
  }

  fn backend_discovery(
    &mut self,
    route: &KubernetesObject,
    from_kind: &str,
    backend: (&Value, usize, u32),
    route_name: &str,
    client_identity: Option<&GeneratedClientIdentity>,
  ) -> Result<GeneratedKubernetesDiscovery, super::TranslationFailure> {
    let (backend, index, weight) = backend;
    let (namespace, name) =
      exact_service_backend_ref(backend, route.namespace()).map_err(|error| {
        self.preserve_last_good_error(
          model_object_ref(route),
          format!("backendRef is not an exact Kubernetes Service reference: {error}"),
        )
      })?;
    if namespace != route.namespace()
      && !self.reference_allowed(route, from_kind, &namespace, "Service", &name)
    {
      return Err(self.fail_closed_error(
        model_object_ref(route),
        format!("cross-namespace backendRef to {namespace}/{name} requires ReferenceGrant"),
      ));
    }
    let key = ObjectKey {
      namespace: namespace.clone(),
      name: name.clone(),
    };
    let Some(service) = self.services.get(&key).cloned() else {
      let failure = self.fail_closed_error(
        model_object_ref(route),
        format!("backend Service {namespace}/{name} was not found in input snapshot"),
      );
      return Err(failure.with_covered_diagnostics(self.backend_tls_covered_diagnostics(&key)));
    };
    let Some(service_port) = backend_service_port(backend, &service) else {
      let failure = self.fail_closed_error(
        model_object_ref(route),
        format!("backend Service {namespace}/{name} does not expose the referenced port"),
      );
      return Err(failure.with_covered_diagnostics(self.backend_tls_covered_diagnostics(&key)));
    };
    let port = match endpoint_slice_discovery_port(service_port) {
      Ok(port) => port,
      Err(message) => {
        let failure = self.fail_closed_error(
          model_object_ref(route),
          format!("backend Service {namespace}/{name} {message}"),
        );
        return Err(failure.with_covered_diagnostics(self.backend_tls_covered_diagnostics(&key)));
      }
    };
    let mut tls = self.backend_tls_for_service(route, &key)?;
    if let (Some(tls), Some(client_identity)) = (&mut tls, client_identity) {
      tls.client_identity = Some(client_identity.clone());
    }
    Ok(GeneratedKubernetesDiscovery {
      id: sanitize_name(&format!("{route_name}-backend-{index}-{namespace}-{name}")),
      weight_multiplier: weight,
      endpoint: "https://kubernetes.default.svc".to_string(),
      namespace: service.namespace.clone(),
      service: service.name.clone(),
      scheme: if tls.is_some() {
        "https".to_string()
      } else {
        service.scheme.clone()
      },
      port,
      tls,
    })
  }

  pub(super) fn apply_parsed_route_filters(
    &mut self,
    route: &KubernetesObject,
    from_kind: &str,
    generated: &mut GeneratedRoute,
    filters: ParsedRouteFilters,
    source: &str,
    client_identity: Option<&GeneratedClientIdentity>,
  ) -> Result<(), super::TranslationFailure> {
    if let Some(policy_ref) = filters.route_policy.as_ref()
      && let Err(error) =
        super::route_policy::apply_route_policy(&self.route_policies, policy_ref, route, generated)
    {
      let diagnostic = self.diagnostics.len();
      self.diagnostics.push(crate::model::Diagnostic::error(
        model_object_ref(route),
        error.message,
      ));
      return Err(match error.covered_diagnostics {
        Some(covered) => {
          super::TranslationFailure::fail_closed(diagnostic).with_covered_diagnostics(covered)
        }
        None => super::TranslationFailure::PreserveLastGood,
      });
    }
    generated.request_headers = filters.request_headers;
    generated.response_headers = filters.response_headers;
    generated.cors = filters.cors;
    generated.rewrite = filters.rewrite;
    generated.redirect = filters.redirect;
    for (index, mirror) in filters.request_mirrors.into_iter().enumerate() {
      let backend_refs = vec![mirror.backend_ref];
      let route_name = sanitize_name(&format!("{}-mirror-{index}", generated.name));
      let pool = self.backend_pool(
        route,
        from_kind,
        Some(&backend_refs),
        &route_name,
        source,
        client_identity,
      )?;
      let mut action = mirror.action;
      action.max_body_bytes = self.request_mirror_max_body_bytes;
      action.upstream_pool = pool.name.clone();
      generated.request_mirrors.push(action);
      self.pools.insert(pool.name.clone(), pool);
    }
    if let Some(auth) = filters.external_auth {
      let auth = match self.authorized_external_auth(auth) {
        Ok(auth) => auth,
        Err(error) => {
          return Err(self.preserve_last_good_error(model_object_ref(route), error.to_string()));
        }
      };
      let server = self.backend_server(route, from_kind, &auth.backend_ref, 0, 1, None)?;
      let endpoint = match external_auth_endpoint(&server.origin, auth.path_prefix.as_deref()) {
        Ok(endpoint) => endpoint,
        Err(error) => {
          return Err(self.preserve_last_good_error(model_object_ref(route), error.to_string()));
        }
      };
      let name = sanitize_name(&format!("{}-ext-auth", generated.name));
      self.external_auth.insert(
        name.clone(),
        GeneratedExternalAuth {
          source: source.to_string(),
          name: name.clone(),
          endpoint,
          forward_headers: auth.forward_headers,
          identity_headers: auth.identity_headers,
          terminal_response_headers: auth.terminal_response_headers,
          max_request_body_bytes: auth.max_request_body_bytes,
          allowed_content_types: if auth.max_request_body_bytes > 0 {
            let mut content_types = self
              .external_auth_allowed_content_types
              .iter()
              .cloned()
              .collect::<Vec<_>>();
            content_types.sort();
            content_types
          } else {
            Vec::new()
          },
        },
      );
      generated.external_auth = Some(name);
    }
    Ok(())
  }

  fn authorized_external_auth(
    &self,
    mut auth: super::filters::ParsedExternalAuth,
  ) -> anyhow::Result<super::filters::ParsedExternalAuth> {
    if !self.external_auth_allow_credentials {
      bail!("Gateway ExternalAuth requires the operator to set --external-auth-allow-credentials");
    }
    if auth.max_request_body_bytes > self.external_auth_max_body_bytes {
      bail!(
        "Gateway ExternalAuth forwardBody.maxSize {} exceeds the operator cap of {}",
        auth.max_request_body_bytes,
        self.external_auth_max_body_bytes
      );
    }
    if auth.max_request_body_bytes > 0 && self.external_auth_allowed_content_types.is_empty() {
      bail!(
        "Gateway ExternalAuth body forwarding requires an explicit operator content-type allowlist"
      );
    }
    validate_header_subset(
      "Gateway ExternalAuth http.allowedHeaders",
      &auth.forward_headers,
      &self.external_auth_allowed_request_headers,
      ExternalAuthHeaderScope::ProtectedRequest,
    )?;
    if auth.identity_headers.is_empty() {
      bail!("Gateway ExternalAuth http.allowedResponseHeaders must name an explicit safe subset");
    }
    validate_header_subset(
      "Gateway ExternalAuth http.allowedResponseHeaders for the protected backend",
      &auth.identity_headers,
      &self.external_auth_allowed_identity_headers,
      ExternalAuthHeaderScope::ProtectedRequest,
    )?;
    validate_header_subset(
      "Gateway ExternalAuth http.allowedResponseHeaders for terminal responses",
      &auth.terminal_response_headers,
      &self.external_auth_allowed_terminal_headers,
      ExternalAuthHeaderScope::TerminalResponse,
    )?;
    auth
      .forward_headers
      .sort_by_key(|header| header.to_ascii_lowercase());
    auth
      .forward_headers
      .dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    Ok(auth)
  }
}

fn validate_header_subset(
  field: &str,
  values: &[String],
  allowed: &std::collections::HashSet<String>,
  scope: ExternalAuthHeaderScope,
) -> anyhow::Result<()> {
  for value in values {
    let normalized = oxibelt_control_protocol::normalize_route_action_header_name(value)
      .with_context(|| format!("{field} contains invalid header {value}"))?;
    let forbidden = match scope {
      ExternalAuthHeaderScope::ProtectedRequest => {
        oxibelt_control_protocol::is_reserved_route_request_header(&normalized)
      }
      ExternalAuthHeaderScope::TerminalResponse => {
        oxibelt_control_protocol::is_forbidden_route_action_header(&normalized)
      }
    };
    if forbidden {
      bail!("{field} contains forbidden header {normalized}");
    }
    if !allowed.contains(&normalized) {
      bail!("{field} header {normalized} is not admitted by operator policy");
    }
  }
  Ok(())
}

#[derive(Clone, Copy)]
enum ExternalAuthHeaderScope {
  ProtectedRequest,
  TerminalResponse,
}

fn external_auth_endpoint(origin: &str, path_prefix: Option<&str>) -> anyhow::Result<String> {
  let mut endpoint = url::Url::parse(origin).context("external auth Service origin is invalid")?;
  if let Some(path_prefix) = path_prefix {
    if !path_prefix.starts_with('/')
      || path_prefix.starts_with("//")
      || path_prefix.contains('?')
      || path_prefix.contains('#')
    {
      bail!(
        "Gateway ExternalAuth http.path must start with one '/' and contain no query or fragment"
      );
    }
    endpoint.set_path(path_prefix);
  }
  Ok(endpoint.to_string())
}

const MAX_GATEWAY_BACKEND_WEIGHT: u32 = 1_000_000;

fn gateway_backend_weight(backend: &Value) -> Result<u32, &'static str> {
  let Some(value) = backend.get("weight") else {
    return Ok(1);
  };
  let Some(raw) = value.as_u64() else {
    return Err("must be an unsigned integer");
  };
  let weight = u32::try_from(raw).map_err(|_| "does not fit the supported integer range")?;
  if weight > MAX_GATEWAY_BACKEND_WEIGHT {
    return Err("must not exceed the Gateway API maximum of 1000000");
  }
  Ok(weight)
}

#[derive(Clone, Copy)]
struct HttpMatchContext<'a> {
  rule_index: usize,
  match_index: usize,
  source: &'a str,
  listener_port: u16,
}

fn http_match_route(
  route: &KubernetesObject,
  rule: &Value,
  route_match: &Value,
  hosts: &[String],
  context: HttpMatchContext<'_>,
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
  let filters = parse_route_filters(
    rule,
    &path_prefix,
    path_type,
    Some(context.listener_port),
    "HTTPRoute",
  )?;
  Ok((
    GeneratedRoute {
      source: context.source.to_string(),
      name: sanitize_name(&format!(
        "gwapi-http-{}-{}-{}-{}",
        route.namespace(),
        route.name(),
        context.rule_index,
        context.match_index
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
      priority: 10_000 - (context.rule_index as i32 * 100) - context.match_index as i32,
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
