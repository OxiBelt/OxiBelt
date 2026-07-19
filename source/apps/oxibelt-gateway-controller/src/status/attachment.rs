use super::*;

pub(super) fn attached_route_count(
  objects: &[KubernetesObject],
  gateway_object: &KubernetesObject,
  listener: &ListenerSummary,
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
) -> usize {
  let single_listener_gateway = GatewaySummary {
    listeners: vec![listener.clone()],
  };
  objects
    .iter()
    .filter(|route| {
      matches!(
        route.kind.as_str(),
        "GRPCRoute" | "HTTPRoute" | "TLSRoute" | "TCPRoute" | "UDPRoute"
      )
    })
    .filter(|route| {
      parent_refs(route).iter().any(|parent| {
        if !parent_ref_is_gateway(parent) {
          return false;
        }
        let parent_namespace = string_at(parent, &["namespace"]).unwrap_or(route.namespace());
        string_at(parent, &["name"]) == Some(gateway_object.name())
          && parent_namespace == gateway_object.namespace()
          && route_has_matching_listener(route, parent, &single_listener_gateway, namespace_labels)
      })
    })
    .count()
}

pub(super) fn route_has_matching_listener(
  route: &KubernetesObject,
  parent: &Value,
  gateway: &GatewaySummary,
  namespace_labels: &HashMap<String, BTreeMap<String, String>>,
) -> bool {
  let section_name = string_at(parent, &["sectionName"]);
  let parent_port = u16_at(parent, &["port"]);
  gateway.listeners.iter().any(|listener| {
    if section_name.is_some() && Some(listener.name.as_str()) != section_name {
      return false;
    }
    if parent_port.is_some() && parent_port != listener.port {
      return false;
    }
    (match route.kind.as_str() {
      "GRPCRoute" | "HTTPRoute" => matches!(listener.protocol.as_str(), "HTTP" | "HTTPS"),
      "TLSRoute" => {
        listener.protocol == "TLS" && listener.tls_mode.as_deref() == Some("Passthrough")
      }
      "TCPRoute" => listener.protocol == "TCP",
      "UDPRoute" => listener.protocol == "UDP",
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
