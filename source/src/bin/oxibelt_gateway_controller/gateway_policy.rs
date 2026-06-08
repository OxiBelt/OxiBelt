use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

use super::model::KubernetesObject;

pub const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";

#[derive(Debug, Clone)]
pub struct ListenerPolicy {
  namespaces: NamespacePolicy,
  kinds: Vec<RouteGroupKind>,
}

#[derive(Debug, Clone)]
enum NamespacePolicy {
  All,
  Same,
  Selector(LabelSelector),
  Unsupported(String),
}

#[derive(Debug, Clone)]
struct RouteGroupKind {
  group: String,
  kind: String,
}

#[derive(Debug, Clone)]
struct LabelSelector {
  match_labels: BTreeMap<String, String>,
  match_expressions: Vec<LabelRequirement>,
}

#[derive(Debug, Clone)]
struct LabelRequirement {
  key: String,
  operator: LabelOperator,
  values: Vec<String>,
}

#[derive(Debug, Clone)]
enum LabelOperator {
  In,
  NotIn,
  Exists,
  DoesNotExist,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RoutePolicyDecision {
  Allowed,
  Denied,
  Invalid(String),
}

#[derive(Debug, Clone)]
pub struct ReferenceGrantInfo {
  namespace: String,
  from: Vec<ReferenceGrantFrom>,
  to: Vec<ReferenceGrantTo>,
}

#[derive(Debug, Clone)]
struct ReferenceGrantFrom {
  group: String,
  kind: String,
  namespace: String,
}

#[derive(Debug, Clone)]
struct ReferenceGrantTo {
  group: String,
  kind: String,
  name: Option<String>,
}

pub fn namespace_labels(objects: &[KubernetesObject]) -> HashMap<String, BTreeMap<String, String>> {
  objects
    .iter()
    .filter(|object| object.kind == "Namespace")
    .map(|object| (object.name().to_string(), object.metadata.labels.clone()))
    .collect()
}

pub fn parse_listener_policy(listener: &Value) -> ListenerPolicy {
  let allowed_routes = listener.get("allowedRoutes");
  let namespaces = allowed_routes
    .and_then(|allowed_routes| allowed_routes.get("namespaces"))
    .map(parse_namespace_policy)
    .unwrap_or(NamespacePolicy::Same);
  let kinds = allowed_routes
    .and_then(|allowed_routes| allowed_routes.get("kinds"))
    .and_then(Value::as_array)
    .map(|kinds| {
      kinds
        .iter()
        .filter_map(|kind| {
          Some(RouteGroupKind {
            group: string_at(kind, &["group"])
              .unwrap_or(GATEWAY_GROUP)
              .to_string(),
            kind: string_at(kind, &["kind"])?.to_string(),
          })
        })
        .collect()
    })
    .unwrap_or_default();
  ListenerPolicy { namespaces, kinds }
}

pub fn listener_default_route_kinds(
  protocol: &str,
  tls_mode: Option<&str>,
) -> &'static [&'static str] {
  match protocol {
    "HTTP" | "HTTPS" => &["HTTPRoute", "GRPCRoute"],
    "TLS" if tls_mode == Some("Passthrough") => &["TLSRoute"],
    _ => &[],
  }
}

pub fn listener_allows_route(
  policy: &ListenerPolicy,
  route: &KubernetesObject,
  gateway_namespace: &str,
  listener_protocol: &str,
  listener_tls_mode: Option<&str>,
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
) -> RoutePolicyDecision {
  if !policy.allows_kind(route.kind.as_str(), listener_protocol, listener_tls_mode) {
    return RoutePolicyDecision::Denied;
  }
  match &policy.namespaces {
    NamespacePolicy::All => RoutePolicyDecision::Allowed,
    NamespacePolicy::Same => {
      if route.namespace() == gateway_namespace {
        RoutePolicyDecision::Allowed
      } else {
        RoutePolicyDecision::Denied
      }
    }
    NamespacePolicy::Selector(selector) => {
      let Some(labels) = namespace_labels.get(route.namespace()) else {
        return RoutePolicyDecision::Invalid(format!(
          "route namespace {} was not present in the Kubernetes snapshot",
          route.namespace()
        ));
      };
      match selector.matches(labels) {
        Ok(true) => RoutePolicyDecision::Allowed,
        Ok(false) => RoutePolicyDecision::Denied,
        Err(error) => RoutePolicyDecision::Invalid(error),
      }
    }
    NamespacePolicy::Unsupported(value) => RoutePolicyDecision::Invalid(format!(
      "unsupported allowedRoutes.namespaces.from value {value}"
    )),
  }
}

pub fn parse_reference_grant(object: &KubernetesObject) -> Option<ReferenceGrantInfo> {
  let mut from_entries = Vec::new();
  for from in object.spec.get("from")?.as_array()? {
    let group = string_at(from, &["group"]).unwrap_or("");
    if group != GATEWAY_GROUP {
      continue;
    }
    let Some(namespace) = string_at(from, &["namespace"]) else {
      continue;
    };
    let Some(kind) = string_at(from, &["kind"]) else {
      continue;
    };
    from_entries.push(ReferenceGrantFrom {
      group: group.to_string(),
      kind: kind.to_string(),
      namespace: namespace.to_string(),
    });
  }
  let mut to_entries = Vec::new();
  for to in object.spec.get("to")?.as_array()? {
    let group = string_at(to, &["group"]).unwrap_or("");
    let Some(kind) = string_at(to, &["kind"]) else {
      continue;
    };
    to_entries.push(ReferenceGrantTo {
      group: group.to_string(),
      kind: kind.to_string(),
      name: string_at(to, &["name"]).map(str::to_string),
    });
  }
  Some(ReferenceGrantInfo {
    namespace: object.namespace().to_string(),
    from: from_entries,
    to: to_entries,
  })
}

pub fn reference_allowed(
  grants: &[ReferenceGrantInfo],
  route: &KubernetesObject,
  from_kind: &str,
  target_namespace: &str,
  target_kind: &str,
  target_name: &str,
) -> bool {
  grants.iter().any(|grant| {
    grant.namespace == target_namespace
      && grant.from.iter().any(|from| {
        from.group == GATEWAY_GROUP && from.kind == from_kind && from.namespace == route.namespace()
      })
      && grant.to.iter().any(|to| {
        to.group.is_empty()
          && to.kind == target_kind
          && to.name.as_deref().is_none_or(|name| name == target_name)
      })
  })
}

impl ListenerPolicy {
  fn allows_kind(&self, route_kind: &str, listener_protocol: &str, tls_mode: Option<&str>) -> bool {
    if self.kinds.is_empty() {
      return listener_default_route_kinds(listener_protocol, tls_mode).contains(&route_kind);
    }
    self
      .kinds
      .iter()
      .any(|kind| kind.group == GATEWAY_GROUP && kind.kind == route_kind)
  }
}

impl LabelSelector {
  fn matches(&self, labels: &BTreeMap<String, String>) -> Result<bool, String> {
    for (key, value) in &self.match_labels {
      if labels.get(key) != Some(value) {
        return Ok(false);
      }
    }
    for requirement in &self.match_expressions {
      if !requirement.matches(labels)? {
        return Ok(false);
      }
    }
    Ok(true)
  }
}

impl LabelRequirement {
  fn matches(&self, labels: &BTreeMap<String, String>) -> Result<bool, String> {
    match self.operator {
      LabelOperator::In => {
        if self.values.is_empty() {
          return Err(format!(
            "selector requirement {} uses In without values",
            self.key
          ));
        }
        Ok(
          labels
            .get(&self.key)
            .is_some_and(|value| self.values.iter().any(|candidate| candidate == value)),
        )
      }
      LabelOperator::NotIn => {
        if self.values.is_empty() {
          return Err(format!(
            "selector requirement {} uses NotIn without values",
            self.key
          ));
        }
        Ok(
          labels
            .get(&self.key)
            .is_none_or(|value| !self.values.iter().any(|candidate| candidate == value)),
        )
      }
      LabelOperator::Exists => {
        if !self.values.is_empty() {
          return Err(format!(
            "selector requirement {} uses Exists with values",
            self.key
          ));
        }
        Ok(labels.contains_key(&self.key))
      }
      LabelOperator::DoesNotExist => {
        if !self.values.is_empty() {
          return Err(format!(
            "selector requirement {} uses DoesNotExist with values",
            self.key
          ));
        }
        Ok(!labels.contains_key(&self.key))
      }
    }
  }
}

fn parse_namespace_policy(value: &Value) -> NamespacePolicy {
  match string_at(value, &["from"]).unwrap_or("Same") {
    "All" => NamespacePolicy::All,
    "Same" => NamespacePolicy::Same,
    "Selector" => match value.get("selector").map(parse_label_selector) {
      Some(Ok(selector)) => NamespacePolicy::Selector(selector),
      Some(Err(error)) => NamespacePolicy::Unsupported(error),
      None => NamespacePolicy::Unsupported("Selector without selector".to_string()),
    },
    other => NamespacePolicy::Unsupported(other.to_string()),
  }
}

fn parse_label_selector(value: &Value) -> Result<LabelSelector, String> {
  let mut match_labels = BTreeMap::new();
  if let Some(labels) = value.get("matchLabels") {
    let labels = labels
      .as_object()
      .ok_or_else(|| "selector.matchLabels must be an object".to_string())?;
    for (key, value) in labels {
      let Some(value) = value.as_str() else {
        return Err(format!("selector.matchLabels.{key} must be a string"));
      };
      match_labels.insert(key.clone(), value.to_string());
    }
  }
  let mut match_expressions = Vec::new();
  if let Some(expressions) = value.get("matchExpressions") {
    let expressions = expressions
      .as_array()
      .ok_or_else(|| "selector.matchExpressions must be an array".to_string())?;
    for expression in expressions {
      match_expressions.push(parse_label_requirement(expression)?);
    }
  }
  Ok(LabelSelector {
    match_labels,
    match_expressions,
  })
}

fn parse_label_requirement(value: &Value) -> Result<LabelRequirement, String> {
  let key = string_at(value, &["key"])
    .ok_or_else(|| "selector.matchExpressions item must set key".to_string())?;
  let operator = match string_at(value, &["operator"])
    .ok_or_else(|| format!("selector requirement {key} must set operator"))?
  {
    "In" => LabelOperator::In,
    "NotIn" => LabelOperator::NotIn,
    "Exists" => LabelOperator::Exists,
    "DoesNotExist" => LabelOperator::DoesNotExist,
    other => {
      return Err(format!(
        "selector requirement {key} uses unsupported operator {other}"
      ));
    }
  };
  let values = value
    .get("values")
    .and_then(Value::as_array)
    .map(|values| {
      values
        .iter()
        .map(|value| {
          value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("selector requirement {key} values must be strings"))
        })
        .collect::<Result<Vec<_>, _>>()
    })
    .transpose()?
    .unwrap_or_default();
  Ok(LabelRequirement {
    key: key.to_string(),
    operator,
    values,
  })
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
  let mut current = value;
  for key in path {
    current = current.get(*key)?;
  }
  current.as_str()
}
