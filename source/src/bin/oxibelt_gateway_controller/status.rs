use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use super::cli::SharedArgs;
use super::gateway_policy::{self, ListenerPolicy, RoutePolicyDecision};
use super::model::{
  Diagnostic, DiagnosticSeverity, KubernetesObject, ObjectKey, object_ref as model_object_ref,
};

const CONDITION_TRUE: &str = "True";
const CONDITION_FALSE: &str = "False";

#[cfg(test)]
#[path = "status/tests.rs"]
mod tests;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StatusPatch {
  pub api_prefix: &'static str,
  pub resource: &'static str,
  pub namespace: Option<String>,
  pub name: String,
  pub status: Value,
}

#[derive(Debug, Clone)]
struct GatewaySummary {
  listeners: Vec<ListenerSummary>,
}

#[derive(Debug, Clone)]
struct ListenerSummary {
  name: String,
  protocol: String,
  hostname: Option<String>,
  port: Option<u16>,
  tls_mode: Option<String>,
  allowed_routes: ListenerPolicy,
}

pub fn print_diagnostics(diagnostics: &[Diagnostic]) {
  for diagnostic in diagnostics {
    let level = match diagnostic.severity {
      DiagnosticSeverity::Warning => "warning",
      DiagnosticSeverity::Error => "error",
    };
    eprintln!("{level}: {}: {}", diagnostic.object, diagnostic.message);
  }
}

pub fn build_status_patches(
  objects: &[KubernetesObject],
  args: &SharedArgs,
  diagnostics: &[Diagnostic],
) -> Vec<StatusPatch> {
  let now = rfc3339_now();
  let accepted_classes = accepted_gateway_classes(objects, args);
  let gateways = gateway_summaries(objects, &accepted_classes);
  let namespace_labels = gateway_policy::namespace_labels(objects);
  let diagnostics_by_object = diagnostics_by_object(diagnostics);
  let mut patches = Vec::new();

  for object in objects {
    match object.kind.as_str() {
      "GatewayClass"
        if string_at(&object.spec, &["controllerName"]) == Some(args.controller_name.as_str()) =>
      {
        patches.push(gateway_class_patch(object, &now));
      }
      "Gateway" if gateways.contains_key(&object.key()) => {
        patches.push(gateway_patch(
          object,
          gateways.get(&object.key()).expect("checked gateway key"),
          args,
          &now,
        ));
      }
      "HTTPRoute" | "TLSRoute" | "TCPRoute" => {
        if let Some(patch) = route_patch(
          object,
          args,
          &gateways,
          &namespace_labels,
          &diagnostics_by_object,
          &now,
        ) {
          patches.push(patch);
        }
      }
      _ => {}
    }
  }

  patches
}

fn gateway_class_patch(object: &KubernetesObject, now: &str) -> StatusPatch {
  StatusPatch {
    api_prefix: "/apis/gateway.networking.k8s.io/v1",
    resource: "gatewayclasses",
    namespace: None,
    name: object.name().to_string(),
    status: json!({
      "conditions": [
        condition(
          "Accepted",
          CONDITION_TRUE,
          "Accepted",
          "GatewayClass is managed by OxiBelt",
          object.metadata.generation,
          now,
        )
      ]
    }),
  }
}

fn gateway_patch(
  object: &KubernetesObject,
  gateway: &GatewaySummary,
  args: &SharedArgs,
  now: &str,
) -> StatusPatch {
  let listener_conflicts = listener_conflicts(&gateway.listeners);
  let listeners = gateway
    .listeners
    .iter()
    .map(|listener| {
      listener_status(
        listener,
        &listener_conflicts,
        object.metadata.generation,
        now,
      )
    })
    .collect::<Vec<_>>();
  let accepted = listeners
    .iter()
    .all(|listener| listener_condition_status(listener, "Accepted") == Some(CONDITION_TRUE));
  let programmed = accepted;
  let mut status = json!({
    "conditions": [
      condition(
        "Accepted",
        bool_status(accepted),
        if accepted { "Accepted" } else { "ListenersNotValid" },
        if accepted {
          "Gateway listeners are supported by OxiBelt"
        } else {
          "One or more Gateway listeners are not supported by OxiBelt"
        },
        object.metadata.generation,
        now,
      ),
      condition(
        "Programmed",
        bool_status(programmed),
        if programmed { "Programmed" } else { "Pending" },
        if programmed {
          "Gateway has been translated into generated OxiBelt configuration"
        } else {
          "Gateway is waiting for all listeners to become accepted"
        },
        object.metadata.generation,
        now,
      )
    ],
    "listeners": listeners,
  });
  if !args.status_address.is_empty() {
    status["addresses"] = Value::Array(
      args
        .status_address
        .iter()
        .map(|address| {
          json!({
            "type": if address.parse::<IpAddr>().is_ok() { "IPAddress" } else { "Hostname" },
            "value": address,
          })
        })
        .collect(),
    );
  }
  StatusPatch {
    api_prefix: "/apis/gateway.networking.k8s.io/v1",
    resource: "gateways",
    namespace: Some(object.namespace().to_string()),
    name: object.name().to_string(),
    status,
  }
}

fn listener_status(
  listener: &ListenerSummary,
  conflicts: &HashSet<(Option<u16>, String, Option<String>)>,
  generation: Option<i64>,
  now: &str,
) -> Value {
  let supported_kind = listener_supported_kind(listener);
  let conflict_key = (
    listener.port,
    listener.protocol.clone(),
    listener.hostname.clone(),
  );
  let conflicted = conflicts.contains(&conflict_key);
  let accepted = supported_kind.is_some() && !conflicted;
  let mut supported_kinds = Vec::new();
  if let Some(kind) = supported_kind {
    supported_kinds.push(json!({
      "group": gateway_policy::GATEWAY_GROUP,
      "kind": kind,
    }));
  }
  json!({
    "name": listener.name,
    "supportedKinds": supported_kinds,
    "attachedRoutes": 0,
    "conditions": [
      condition(
        "Accepted",
        bool_status(accepted),
        if accepted { "Accepted" } else if conflicted { "Conflicted" } else { "UnsupportedProtocol" },
        if accepted {
          "Listener is supported by OxiBelt"
        } else if conflicted {
          "Listener conflicts with another listener on hostname, port, and protocol"
        } else {
          "Listener protocol is not supported by OxiBelt Gateway API controller v1"
        },
        generation,
        now,
      ),
      condition(
        "Programmed",
        bool_status(accepted),
        if accepted { "Programmed" } else { "Pending" },
        if accepted {
          "Listener has been translated into generated OxiBelt configuration"
        } else {
          "Listener is not programmed because it is not accepted"
        },
        generation,
        now,
      ),
      condition(
        "ResolvedRefs",
        CONDITION_TRUE,
        "ResolvedRefs",
        "Listener references are resolved",
        generation,
        now,
      ),
      condition(
        "Conflicted",
        bool_status(conflicted),
        if conflicted { "HostnamePortProtocolConflict" } else { "NoConflicts" },
        if conflicted {
          "Listener conflicts with another listener on hostname, port, and protocol"
        } else {
          "No listener conflicts were detected"
        },
        generation,
        now,
      )
    ]
  })
}

fn route_patch(
  object: &KubernetesObject,
  args: &SharedArgs,
  gateways: &HashMap<ObjectKey, GatewaySummary>,
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
  diagnostics: &HashMap<String, Vec<&Diagnostic>>,
  now: &str,
) -> Option<StatusPatch> {
  let mut parents = preserved_parent_statuses(object, &args.controller_name);
  let mut added = 0_usize;
  for parent in parent_refs(object) {
    if !parent_ref_is_gateway(&parent) {
      continue;
    }
    let Some(parent_name) = string_at(&parent, &["name"]) else {
      continue;
    };
    let parent_namespace = string_at(&parent, &["namespace"]).unwrap_or(object.namespace());
    let key = ObjectKey {
      namespace: parent_namespace.to_string(),
      name: parent_name.to_string(),
    };
    let Some(gateway) = gateways.get(&key) else {
      continue;
    };
    let parent_status = route_parent_status(
      object,
      &parent,
      gateway,
      namespace_labels,
      &args.controller_name,
      diagnostics,
      now,
    );
    parents.push(parent_status);
    added += 1;
  }
  if added == 0 {
    return None;
  }
  Some(StatusPatch {
    api_prefix: api_prefix_for_route(object),
    resource: resource_for_route(object),
    namespace: Some(object.namespace().to_string()),
    name: object.name().to_string(),
    status: json!({ "parents": parents }),
  })
}

fn route_parent_status(
  object: &KubernetesObject,
  parent: &Value,
  gateway: &GatewaySummary,
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
  controller_name: &str,
  diagnostics: &HashMap<String, Vec<&Diagnostic>>,
  now: &str,
) -> Value {
  if object.kind == "TCPRoute" {
    return json!({
      "parentRef": normalized_parent_ref(parent),
      "controllerName": controller_name,
      "conditions": [
        condition("Accepted", CONDITION_FALSE, "UnsupportedKind", "TCPRoute is unsupported by OxiBelt Gateway API controller v1", object.metadata.generation, now),
        condition("ResolvedRefs", CONDITION_TRUE, "ResolvedRefs", "References were not translated because TCPRoute is unsupported", object.metadata.generation, now),
        condition("Programmed", CONDITION_FALSE, "UnsupportedKind", "TCPRoute is status-only in OxiBelt Gateway API controller v1", object.metadata.generation, now),
      ]
    });
  }

  let object_ref = model_object_ref(object);
  let object_errors = diagnostics.get(&object_ref).cloned().unwrap_or_default();
  let listener_matches = route_has_matching_listener(object, parent, gateway, namespace_labels);
  let has_error = object_errors
    .iter()
    .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error);
  let resolved_refs = !object_errors.iter().any(|diagnostic| {
    diagnostic.message.contains("ReferenceGrant")
      || diagnostic.message.contains("was not found")
      || diagnostic.message.contains("does not expose")
      || diagnostic.message.contains("references")
  });
  let accepted = listener_matches && !has_error;
  json!({
    "parentRef": normalized_parent_ref(parent),
    "controllerName": controller_name,
    "conditions": [
      condition(
        "Accepted",
        bool_status(accepted),
        if accepted { "Accepted" } else if !listener_matches { "NoMatchingListener" } else { "InvalidRoute" },
        if accepted {
          "Route is accepted by OxiBelt"
        } else if !listener_matches {
          "Route does not match an in-scope listener on the parent Gateway"
        } else {
          "Route contains unsupported or invalid fields for OxiBelt Gateway API controller v1"
        },
        object.metadata.generation,
        now,
      ),
      condition(
        "ResolvedRefs",
        bool_status(resolved_refs),
        if resolved_refs { "ResolvedRefs" } else { "RefNotPermitted" },
        if resolved_refs {
          "Route references are resolved"
        } else {
          "Route references could not be resolved or are not permitted"
        },
        object.metadata.generation,
        now,
      ),
      condition(
        "Programmed",
        bool_status(accepted),
        if accepted { "Programmed" } else { "Pending" },
        if accepted {
          "Route has been translated into generated OxiBelt configuration"
        } else {
          "Route is not programmed because it is not accepted"
        },
        object.metadata.generation,
        now,
      )
    ]
  })
}

fn accepted_gateway_classes(objects: &[KubernetesObject], args: &SharedArgs) -> HashSet<String> {
  objects
    .iter()
    .filter(|object| object.kind == "GatewayClass")
    .filter(|object| {
      string_at(&object.spec, &["controllerName"]) == Some(args.controller_name.as_str())
    })
    .map(|object| object.name().to_string())
    .collect()
}

fn gateway_summaries(
  objects: &[KubernetesObject],
  accepted_classes: &HashSet<String>,
) -> HashMap<ObjectKey, GatewaySummary> {
  let mut gateways = HashMap::new();
  for object in objects.iter().filter(|object| object.kind == "Gateway") {
    let Some(class_name) = string_at(&object.spec, &["gatewayClassName"]) else {
      continue;
    };
    if !accepted_classes.contains(class_name) {
      continue;
    }
    let listeners = object
      .spec
      .get("listeners")
      .and_then(Value::as_array)
      .cloned()
      .unwrap_or_default()
      .into_iter()
      .filter_map(|listener| {
        let name = string_at(&listener, &["name"])?.to_string();
        let protocol = string_at(&listener, &["protocol"])?.to_string();
        Some(ListenerSummary {
          name,
          protocol,
          hostname: string_at(&listener, &["hostname"]).map(str::to_string),
          port: u16_at(&listener, &["port"]),
          tls_mode: string_at(&listener, &["tls", "mode"]).map(str::to_string),
          allowed_routes: gateway_policy::parse_listener_policy(&listener),
        })
      })
      .collect();
    gateways.insert(object.key(), GatewaySummary { listeners });
  }
  gateways
}

fn listener_supported_kind(listener: &ListenerSummary) -> Option<&'static str> {
  gateway_policy::listener_default_route_kind(&listener.protocol, listener.tls_mode.as_deref())
}

fn route_has_matching_listener(
  route: &KubernetesObject,
  parent: &Value,
  gateway: &GatewaySummary,
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
) -> bool {
  let section_name = string_at(parent, &["sectionName"]);
  gateway.listeners.iter().any(|listener| {
    if section_name.is_some() && Some(listener.name.as_str()) != section_name {
      return false;
    }
    (match route.kind.as_str() {
      "HTTPRoute" => matches!(listener.protocol.as_str(), "HTTP" | "HTTPS"),
      "TLSRoute" => {
        listener.protocol == "TLS" && listener.tls_mode.as_deref() == Some("Passthrough")
      }
      "TCPRoute" => true,
      _ => false,
    }) && matches!(
      gateway_policy::listener_allows_route(
        &listener.allowed_routes,
        route,
        parent
          .get("namespace")
          .and_then(Value::as_str)
          .unwrap_or(route.namespace()),
        &listener.protocol,
        listener.tls_mode.as_deref(),
        namespace_labels,
      ),
      RoutePolicyDecision::Allowed
    )
  })
}

fn preserved_parent_statuses(object: &KubernetesObject, controller_name: &str) -> Vec<Value> {
  object
    .status
    .get("parents")
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default()
    .into_iter()
    .filter(|parent| string_at(parent, &["controllerName"]) != Some(controller_name))
    .collect()
}

fn normalized_parent_ref(parent: &Value) -> Value {
  let mut out = Map::new();
  out.insert(
    "group".to_string(),
    Value::String(
      string_at(parent, &["group"])
        .unwrap_or(gateway_policy::GATEWAY_GROUP)
        .to_string(),
    ),
  );
  out.insert(
    "kind".to_string(),
    Value::String(
      string_at(parent, &["kind"])
        .unwrap_or("Gateway")
        .to_string(),
    ),
  );
  if let Some(namespace) = string_at(parent, &["namespace"]) {
    out.insert(
      "namespace".to_string(),
      Value::String(namespace.to_string()),
    );
  }
  if let Some(name) = string_at(parent, &["name"]) {
    out.insert("name".to_string(), Value::String(name.to_string()));
  }
  if let Some(section_name) = string_at(parent, &["sectionName"]) {
    out.insert(
      "sectionName".to_string(),
      Value::String(section_name.to_string()),
    );
  }
  Value::Object(out)
}

fn parent_refs(object: &KubernetesObject) -> Vec<Value> {
  object
    .spec
    .get("parentRefs")
    .and_then(Value::as_array)
    .cloned()
    .unwrap_or_default()
}

fn parent_ref_is_gateway(parent: &Value) -> bool {
  let group = string_at(parent, &["group"]).unwrap_or(gateway_policy::GATEWAY_GROUP);
  let kind = string_at(parent, &["kind"]).unwrap_or("Gateway");
  group == gateway_policy::GATEWAY_GROUP && kind == "Gateway"
}

fn listener_conflicts(
  listeners: &[ListenerSummary],
) -> HashSet<(Option<u16>, String, Option<String>)> {
  let mut counts = BTreeMap::new();
  for listener in listeners {
    *counts
      .entry((
        listener.port,
        listener.protocol.clone(),
        listener.hostname.clone(),
      ))
      .or_insert(0_usize) += 1;
  }
  counts
    .into_iter()
    .filter_map(|(key, count)| (count > 1).then_some(key))
    .collect()
}

fn listener_condition_status<'a>(listener: &'a Value, condition_type: &str) -> Option<&'a str> {
  listener
    .get("conditions")
    .and_then(Value::as_array)?
    .iter()
    .find(|condition| string_at(condition, &["type"]) == Some(condition_type))
    .and_then(|condition| string_at(condition, &["status"]))
}

fn diagnostics_by_object(diagnostics: &[Diagnostic]) -> HashMap<String, Vec<&Diagnostic>> {
  let mut out: HashMap<String, Vec<&Diagnostic>> = HashMap::new();
  for diagnostic in diagnostics {
    out
      .entry(diagnostic.object.clone())
      .or_default()
      .push(diagnostic);
  }
  out
}

fn api_prefix_for_route(object: &KubernetesObject) -> &'static str {
  match object.kind.as_str() {
    "TCPRoute" => "/apis/gateway.networking.k8s.io/v1alpha2",
    _ => "/apis/gateway.networking.k8s.io/v1",
  }
}

fn resource_for_route(object: &KubernetesObject) -> &'static str {
  match object.kind.as_str() {
    "HTTPRoute" => "httproutes",
    "TLSRoute" => "tlsroutes",
    "TCPRoute" => "tcproutes",
    _ => "routes",
  }
}

fn condition(
  condition_type: &str,
  status: &str,
  reason: &str,
  message: &str,
  generation: Option<i64>,
  now: &str,
) -> Value {
  let mut out = json!({
    "type": condition_type,
    "status": status,
    "reason": reason,
    "message": message,
    "lastTransitionTime": now,
  });
  if let Some(generation) = generation {
    out["observedGeneration"] = Value::Number(generation.into());
  }
  out
}

fn bool_status(value: bool) -> &'static str {
  if value {
    CONDITION_TRUE
  } else {
    CONDITION_FALSE
  }
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
  let mut current = value;
  for key in path {
    current = current.get(*key)?;
  }
  current.as_str()
}

fn u16_at(value: &Value, path: &[&str]) -> Option<u16> {
  let mut current = value;
  for key in path {
    current = current.get(*key)?;
  }
  current.as_u64().and_then(|value| u16::try_from(value).ok())
}

fn rfc3339_now() -> String {
  let seconds = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs() as i64)
    .unwrap_or_default();
  let days = seconds.div_euclid(86_400);
  let seconds_of_day = seconds.rem_euclid(86_400);
  let (year, month, day) = civil_from_days(days);
  let hour = seconds_of_day / 3_600;
  let minute = seconds_of_day % 3_600 / 60;
  let second = seconds_of_day % 60;
  format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
  let days = days_since_epoch + 719_468;
  let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
  let day_of_era = days - era * 146_097;
  let year_of_era =
    (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
  let mut year = year_of_era + era * 400;
  let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  let month_prime = (5 * day_of_year + 2) / 153;
  let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
  let month = month_prime + if month_prime < 10 { 3 } else { -9 };
  if month <= 2 {
    year += 1;
  }
  (year, month as u32, day as u32)
}
