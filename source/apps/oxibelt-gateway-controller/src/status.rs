use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use serde_json::{Map, Value, json};

use super::cli::SharedArgs;
use super::gateway_policy::{self, ListenerPolicy, RoutePolicyDecision};
use super::kubernetes_time::rfc3339_now;
use super::model::{
  Diagnostic, DiagnosticCode, DiagnosticSeverity, KubernetesObject, ObjectKey,
  object_ref as model_object_ref,
};
use super::rollout_status::RolloutStatus;
use super::translate::UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC;

const CONDITION_TRUE: &str = "True";
const CONDITION_FALSE: &str = "False";

#[path = "status/attachment.rs"]
mod attachment;
#[path = "status/backend_tls.rs"]
mod backend_tls;
#[path = "status/route_policy.rs"]
mod route_policy;
#[cfg(test)]
#[path = "status/tests.rs"]
mod tests;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StatusPatch {
  pub api_prefix: &'static str,
  pub resource: &'static str,
  pub namespace: Option<String>,
  pub name: String,
  pub resource_version: Option<String>,
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
  rollout_status: &RolloutStatus,
) -> Vec<StatusPatch> {
  let now = rfc3339_now();
  let accepted_classes = accepted_gateway_classes(objects, args);
  let gateways = gateway_summaries(objects, &accepted_classes);
  let namespace_labels = gateway_policy::namespace_labels(objects);
  let diagnostics_by_object = diagnostics_by_object(diagnostics);
  let status_addresses = controller_status_addresses(objects, args);
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
          objects,
          &namespace_labels,
          &status_addresses,
          (&diagnostics_by_object, rollout_status),
          &now,
        ));
      }
      "GRPCRoute" | "HTTPRoute" | "TLSRoute" | "TCPRoute" | "UDPRoute" => {
        if let Some(patch) = route_patch(
          object,
          args,
          &gateways,
          &namespace_labels,
          &diagnostics_by_object,
          rollout_status,
          &now,
        ) {
          patches.push(patch);
        }
      }
      "BackendTLSPolicy" => patches.push(backend_tls::patch(
        object,
        args,
        &diagnostics_by_object,
        &now,
      )),
      "OxiBeltRoutePolicy" => patches.push(route_policy::patch(
        object,
        objects,
        &diagnostics_by_object,
        rollout_status,
        route_policy_target_was_translated(
          object,
          objects,
          &gateways,
          &namespace_labels,
          &diagnostics_by_object,
        ),
        &now,
      )),
      _ => {}
    }
  }

  patches
}

fn route_policy_target_was_translated(
  policy: &KubernetesObject,
  objects: &[KubernetesObject],
  gateways: &HashMap<ObjectKey, GatewaySummary>,
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
  diagnostics: &HashMap<String, Vec<&Diagnostic>>,
) -> bool {
  let Some(kind) = string_at(&policy.spec, &["targetRef", "kind"]) else {
    return false;
  };
  let Some(name) = string_at(&policy.spec, &["targetRef", "name"]) else {
    return false;
  };
  let Some(route) = objects.iter().find(|object| {
    object.kind == kind && object.namespace() == policy.namespace() && object.name() == name
  }) else {
    return false;
  };
  if diagnostics
    .get(&model_object_ref(route))
    .into_iter()
    .flatten()
    .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
  {
    return false;
  }
  parent_refs(route).iter().any(|parent| {
    if !parent_ref_is_gateway(parent) {
      return false;
    }
    let namespace = string_at(parent, &["namespace"]).unwrap_or(route.namespace());
    let Some(name) = string_at(parent, &["name"]) else {
      return false;
    };
    gateways
      .get(&ObjectKey {
        namespace: namespace.to_string(),
        name: name.to_string(),
      })
      .is_some_and(|gateway| {
        attachment::route_has_matching_listener(route, parent, gateway, namespace_labels)
      })
  })
}

fn gateway_class_patch(object: &KubernetesObject, now: &str) -> StatusPatch {
  StatusPatch {
    api_prefix: "/apis/gateway.networking.k8s.io/v1",
    resource: "gatewayclasses",
    namespace: None,
    name: object.name().to_string(),
    resource_version: object.metadata.resource_version.clone(),
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
  objects: &[KubernetesObject],
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
  status_addresses: &[Value],
  status: (&HashMap<String, Vec<&Diagnostic>>, &RolloutStatus),
  now: &str,
) -> StatusPatch {
  let (diagnostics, rollout_status) = status;
  let listener_conflicts = listener_conflicts(&gateway.listeners);
  let gateway_errors = diagnostics
    .get(&model_object_ref(object))
    .into_iter()
    .flatten()
    .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    .collect::<Vec<_>>();
  let resolved_refs = !gateway_errors.iter().any(|diagnostic| {
    matches!(
      diagnostic.code,
      DiagnosticCode::RefNotPermitted | DiagnosticCode::InvalidClientCertificateRef
    )
  });
  let resolved_reason = if gateway_errors
    .iter()
    .any(|diagnostic| diagnostic.code == DiagnosticCode::RefNotPermitted)
  {
    "RefNotPermitted"
  } else {
    "InvalidClientCertificateRef"
  };
  let listeners = gateway
    .listeners
    .iter()
    .map(|listener| {
      listener_status(
        listener,
        &listener_conflicts,
        attachment::attached_route_count(objects, object, listener, namespace_labels),
        rollout_status,
        object.metadata.generation,
        now,
      )
    })
    .collect::<Vec<_>>();
  let accepted = listeners
    .iter()
    .all(|listener| listener_condition_status(listener, "Accepted") == Some(CONDITION_TRUE));
  let programmed = rollout_status.programmed(accepted);
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
        bool_status(programmed.programmed),
        programmed.reason,
        &programmed.message,
        object.metadata.generation,
        now,
      ),
      condition(
        "ResolvedRefs",
        bool_status(resolved_refs),
        if resolved_refs { "ResolvedRefs" } else { resolved_reason },
        if resolved_refs {
          "Gateway references are resolved"
        } else {
          "Gateway backend client certificate reference is invalid, unresolved, or not permitted"
        },
        object.metadata.generation,
        now,
      )
    ],
    "listeners": listeners,
  });
  if !status_addresses.is_empty() {
    status["addresses"] = Value::Array(status_addresses.to_vec());
  }
  StatusPatch {
    api_prefix: "/apis/gateway.networking.k8s.io/v1",
    resource: "gateways",
    namespace: Some(object.namespace().to_string()),
    name: object.name().to_string(),
    resource_version: object.metadata.resource_version.clone(),
    status,
  }
}

fn controller_status_addresses(objects: &[KubernetesObject], args: &SharedArgs) -> Vec<Value> {
  if !args.status_address.is_empty() {
    return args
      .status_address
      .iter()
      .map(|address| gateway_address(address))
      .collect();
  }
  let Some((namespace, name)) = args.status_service.as_deref().and_then(parse_service_ref) else {
    return Vec::new();
  };
  let Some(service) = objects.iter().find(|object| {
    object.kind == "Service" && object.namespace() == namespace && object.name() == name
  }) else {
    return Vec::new();
  };
  service
    .status
    .get("loadBalancer")
    .and_then(|load_balancer| load_balancer.get("ingress"))
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(|ingress| {
      ingress
        .get("ip")
        .and_then(Value::as_str)
        .or_else(|| ingress.get("hostname").and_then(Value::as_str))
    })
    .map(gateway_address)
    .collect()
}

fn gateway_address(address: &str) -> Value {
  json!({
    "type": if address.parse::<IpAddr>().is_ok() { "IPAddress" } else { "Hostname" },
    "value": address,
  })
}

fn parse_service_ref(value: &str) -> Option<(&str, &str)> {
  let (namespace, name) = value.split_once('/')?;
  (!namespace.is_empty() && !name.is_empty() && !name.contains('/')).then_some((namespace, name))
}

fn listener_status(
  listener: &ListenerSummary,
  conflicts: &HashSet<String>,
  attached_routes: usize,
  rollout_status: &RolloutStatus,
  generation: Option<i64>,
  now: &str,
) -> Value {
  let supported_kinds = listener_supported_kinds(listener);
  let conflicted = conflicts.contains(&listener.name);
  let accepted = !supported_kinds.is_empty() && !conflicted;
  let programmed = rollout_status.programmed(accepted);
  let supported_kinds = supported_kinds
    .iter()
    .map(|kind| {
      json!({
      "group": gateway_policy::GATEWAY_GROUP,
      "kind": kind,
      })
    })
    .collect::<Vec<_>>();
  json!({
    "name": listener.name,
    "supportedKinds": supported_kinds,
    "attachedRoutes": attached_routes,
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
        bool_status(programmed.programmed),
        programmed.reason,
        &programmed.message,
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
  rollout_status: &RolloutStatus,
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
      (diagnostics, rollout_status),
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
    resource_version: object.metadata.resource_version.clone(),
    status: json!({ "parents": parents }),
  })
}

fn route_parent_status(
  object: &KubernetesObject,
  parent: &Value,
  gateway: &GatewaySummary,
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
  controller_name: &str,
  status: (&HashMap<String, Vec<&Diagnostic>>, &RolloutStatus),
  now: &str,
) -> Value {
  let (diagnostics, rollout_status) = status;
  let object_ref = model_object_ref(object);
  let object_errors = diagnostics.get(&object_ref).cloned().unwrap_or_default();
  let listener_matches =
    attachment::route_has_matching_listener(object, parent, gateway, namespace_labels);
  let has_reference_error = object_errors.iter().any(|diagnostic| {
    matches!(diagnostic.severity, DiagnosticSeverity::Error)
      && matches!(
        diagnostic.code,
        DiagnosticCode::RefNotPermitted | DiagnosticCode::InvalidClientCertificateRef
      )
  });
  let not_programmed_by_precedence = object_errors.iter().any(|diagnostic| {
    diagnostic
      .message
      .contains("Accepted but not Programmed because older")
  });
  let udp_flow_state_disabled = object.kind == "UDPRoute"
    && object_errors
      .iter()
      .any(|diagnostic| diagnostic.message == UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC);
  let error_reason = route_error_reason(&object_errors);
  let resolved_refs = !has_reference_error;
  let has_nonreference_error = object_errors.iter().any(|diagnostic| {
    matches!(diagnostic.severity, DiagnosticSeverity::Error)
      && !matches!(
        diagnostic.code,
        DiagnosticCode::RefNotPermitted | DiagnosticCode::InvalidClientCertificateRef
      )
  });
  let accepted = listener_matches && !has_nonreference_error;
  let programmed =
    rollout_status.programmed(accepted && resolved_refs && !not_programmed_by_precedence);
  let resolved_reason = resolved_refs_reason(&object_errors);
  json!({
    "parentRef": normalized_parent_ref(parent),
    "controllerName": controller_name,
    "conditions": [
      condition(
        "Accepted",
        bool_status(accepted),
        if accepted {
          "Accepted"
        } else if !listener_matches {
          "NoMatchingListener"
        } else if udp_flow_state_disabled {
          "UnsupportedValue"
        } else {
          error_reason
        },
        if accepted {
          "Route is accepted by OxiBelt"
        } else if !listener_matches {
          "Route does not match an in-scope listener on the parent Gateway"
        } else if udp_flow_state_disabled {
          UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC
        } else {
          "Route contains unsupported or invalid fields for OxiBelt Gateway API controller v1"
        },
        object.metadata.generation,
        now,
      ),
      condition(
        "ResolvedRefs",
        bool_status(resolved_refs),
        if resolved_refs { "ResolvedRefs" } else { resolved_reason },
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
        bool_status(programmed.programmed),
        if not_programmed_by_precedence || udp_flow_state_disabled {
          "NotProgrammed"
        } else {
          programmed.reason
        },
        if not_programmed_by_precedence {
          "An older TCPRoute/UDPRoute owns this listener; the route remains Accepted"
        } else if udp_flow_state_disabled {
          UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC
        } else {
          &programmed.message
        },
        object.metadata.generation,
        now,
      )
    ]
  })
}

fn route_error_reason(errors: &[&Diagnostic]) -> &'static str {
  errors
    .iter()
    .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    .map_or("InvalidRoute", |diagnostic| diagnostic.code.as_str())
}

fn resolved_refs_reason(errors: &[&Diagnostic]) -> &'static str {
  if errors
    .iter()
    .any(|diagnostic| diagnostic.code == DiagnosticCode::RefNotPermitted)
  {
    "RefNotPermitted"
  } else if errors
    .iter()
    .any(|diagnostic| diagnostic.code == DiagnosticCode::InvalidClientCertificateRef)
  {
    "InvalidClientCertificateRef"
  } else if errors
    .iter()
    .any(|diagnostic| diagnostic.message.contains("protocol"))
  {
    "UnsupportedProtocol"
  } else {
    "BackendNotFound"
  }
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

fn listener_supported_kinds(listener: &ListenerSummary) -> &'static [&'static str] {
  gateway_policy::listener_default_route_kinds(&listener.protocol, listener.tls_mode.as_deref())
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
  if let Some(port) = u16_at(parent, &["port"]) {
    out.insert("port".to_string(), Value::Number(port.into()));
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

fn listener_conflicts(listeners: &[ListenerSummary]) -> HashSet<String> {
  let mut conflicts = HashSet::new();
  for (index, left) in listeners.iter().enumerate() {
    for right in listeners.iter().skip(index + 1) {
      if listener_pair_conflicts(left, right) {
        conflicts.insert(left.name.clone());
        conflicts.insert(right.name.clone());
      }
    }
  }
  conflicts
}

fn listener_pair_conflicts(left: &ListenerSummary, right: &ListenerSummary) -> bool {
  if left.port != right.port {
    return false;
  }
  if left.protocol == "UDP" || right.protocol == "UDP" {
    return left.protocol == "UDP" && right.protocol == "UDP";
  }
  if left.protocol == "TCP" || right.protocol == "TCP" {
    return true;
  }
  left.protocol == right.protocol && left.hostname == right.hostname
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
  let _ = object;
  "/apis/gateway.networking.k8s.io/v1"
}

fn resource_for_route(object: &KubernetesObject) -> &'static str {
  match object.kind.as_str() {
    "HTTPRoute" => "httproutes",
    "GRPCRoute" => "grpcroutes",
    "TLSRoute" => "tlsroutes",
    "TCPRoute" => "tcproutes",
    "UDPRoute" => "udproutes",
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
