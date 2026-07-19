use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::super::cli::SharedArgs;
use super::super::model::{Diagnostic, KubernetesObject, ObjectKey, object_ref};
use super::{
  GeneratedStreamListener, GeneratedStreamPool, GeneratedStreamServer, RouteAttachment,
  ServiceTargetPort, TranslationState, backend_ref_is_service, backend_service_port, sanitize_name,
  string_at, u32_at, unsupported_field,
};

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ListenerKey {
  gateway_namespace: String,
  gateway_name: String,
  listener_name: String,
  listener_port: u16,
  network: String,
}

#[derive(Debug, Clone)]
struct Candidate {
  route: KubernetesObject,
  attachment: RouteAttachment,
  key: ListenerKey,
  bind_port: Option<u16>,
  servers: Option<Vec<GeneratedStreamServer>>,
}

impl TranslationState {
  pub(super) fn translate_l4_routes(&mut self, objects: &[KubernetesObject], args: &SharedArgs) {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for route in objects
      .iter()
      .filter(|object| matches!(object.kind.as_str(), "TCPRoute" | "UDPRoute"))
    {
      let (protocol, network) = if route.kind == "TCPRoute" {
        ("TCP", "tcp")
      } else {
        ("UDP", "udp")
      };
      let attachments = self.attachments_for(route, &[protocol]);
      if attachments.is_empty() {
        self.diagnostics.push(Diagnostic::warning(
          object_ref(route),
          format!("route is not attached to an in-scope {protocol} Gateway listener"),
        ));
        continue;
      }
      let servers = self.l4_backend_servers(route, network);
      for attachment in attachments {
        let listener_name = attachment
          .listener
          .name
          .clone()
          .unwrap_or_else(|| attachment.listener.port.to_string());
        let key = ListenerKey {
          gateway_namespace: attachment.gateway.namespace.clone(),
          gateway_name: attachment.gateway.name.clone(),
          listener_name,
          listener_port: attachment.listener.port,
          network: network.to_string(),
        };
        if !seen.insert((
          route.namespace().to_string(),
          route.name().to_string(),
          key.clone(),
        )) {
          continue;
        }
        let bind_port = self.status_service_target_port(route, &attachment, args);
        candidates.push(Candidate {
          route: route.clone(),
          attachment,
          key,
          bind_port,
          servers: servers.clone(),
        });
      }
    }

    let mut by_listener = BTreeMap::<ListenerKey, Vec<Candidate>>::new();
    for candidate in candidates {
      by_listener
        .entry(candidate.key.clone())
        .or_default()
        .push(candidate);
    }
    let mut winners = Vec::new();
    for mut attached in by_listener.into_values() {
      attached
        .sort_by(|left, right| route_precedence(&left.route).cmp(&route_precedence(&right.route)));
      let Some(winner) = attached.first().cloned() else {
        continue;
      };
      for loser in attached.iter().skip(1) {
        self.diagnostics.push(Diagnostic::warning(
          object_ref(&loser.route),
          format!(
            "route is Accepted but not Programmed because older {}/{} owns Gateway/{}/{} listener {}",
            winner.route.namespace(),
            winner.route.name(),
            winner.attachment.gateway.namespace,
            winner.attachment.gateway.name,
            winner.key.listener_name,
          ),
        ));
      }
      winners.push(winner);
    }

    let mut by_bind = BTreeMap::<(String, String), Vec<Candidate>>::new();
    for winner in winners {
      let (Some(bind_port), Some(_)) = (winner.bind_port, winner.servers.as_ref()) else {
        continue;
      };
      let bind = format!("{}:{bind_port}", args.l4_bind_address);
      by_bind
        .entry((winner.key.network.clone(), bind))
        .or_default()
        .push(winner);
    }
    for ((_, bind), bound) in by_bind {
      if bound.len() != 1 {
        for candidate in bound {
          self.diagnostics.push(Diagnostic::error(
            object_ref(&candidate.route),
            format!(
              "Gateway listener maps to duplicate process bind {bind}; each TCP/UDP listener needs a distinct status Service targetPort"
            ),
          ));
        }
        continue;
      }
      if let Some(candidate) = bound.into_iter().next() {
        self.install_l4_candidate(candidate, bind);
      }
    }
  }

  fn l4_backend_servers(
    &mut self,
    route: &KubernetesObject,
    network: &str,
  ) -> Option<Vec<GeneratedStreamServer>> {
    if let Some(field) = unsupported_field(&route.spec, &["parentRefs", "rules"]) {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!("{} spec.{field} is unsupported", route.kind),
      ));
      return None;
    }
    let Some(rules) = route.spec.get("rules").and_then(Value::as_array) else {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!("{} spec.rules is required", route.kind),
      ));
      return None;
    };
    if rules.len() != 1 {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!("{} supports exactly one rule", route.kind),
      ));
      return None;
    }
    let rule = &rules[0];
    if let Some(field) = unsupported_field(rule, &["backendRefs", "filters"]) {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!("{} rule.{field} is unsupported", route.kind),
      ));
      return None;
    }
    if rule
      .get("filters")
      .and_then(Value::as_array)
      .is_some_and(|filters| !filters.is_empty())
    {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!("{} filters are unsupported", route.kind),
      ));
      return None;
    }
    let Some(backends) = rule.get("backendRefs").and_then(Value::as_array) else {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!("{} rule.backendRefs is required", route.kind),
      ));
      return None;
    };
    let mut servers = Vec::new();
    for (index, backend) in backends.iter().enumerate() {
      if let Some(field) = unsupported_field(
        backend,
        &["group", "kind", "name", "namespace", "port", "weight"],
      ) {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!("{} backendRef.{field} is unsupported", route.kind),
        ));
        continue;
      }
      let weight = u32_at(backend, &["weight"]).unwrap_or(1);
      if weight == 0 {
        continue;
      }
      if !backend_ref_is_service(backend) {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!(
            "{} only supports Kubernetes Service backendRefs",
            route.kind
          ),
        ));
        continue;
      }
      let Some(name) = string_at(backend, &["name"]) else {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!("{} backendRef.name is required", route.kind),
        ));
        continue;
      };
      let namespace = string_at(backend, &["namespace"]).unwrap_or(route.namespace());
      if namespace != route.namespace()
        && !self.reference_allowed(route, &route.kind, namespace, "Service", name)
      {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!("cross-namespace backendRef to {namespace}/{name} requires ReferenceGrant"),
        ));
        continue;
      }
      let key = ObjectKey {
        namespace: namespace.to_string(),
        name: name.to_string(),
      };
      let Some(service) = self.services.get(&key) else {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!("backend Service {namespace}/{name} was not found in input snapshot"),
        ));
        continue;
      };
      let Some(service_port) = backend_service_port(backend, service) else {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!("backend Service {namespace}/{name} does not expose the referenced port"),
        ));
        continue;
      };
      if service_port.protocol.to_ascii_lowercase() != network {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!(
            "backend Service {namespace}/{name} port {} uses protocol {}, not {}",
            service_port.port,
            service_port.protocol,
            network.to_ascii_uppercase(),
          ),
        ));
        continue;
      }
      servers.push(GeneratedStreamServer {
        id: sanitize_name(&format!(
          "{}-{}-{}-{}",
          namespace, name, service_port.port, index
        )),
        origin: format!(
          "{network}://{}.{}.svc.cluster.local:{}",
          service.name, service.namespace, service_port.port
        ),
        weight,
      });
    }
    if servers.is_empty() {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!(
          "{} must have at least one valid nonzero backendRef",
          route.kind
        ),
      ));
      return None;
    }
    Some(servers)
  }

  fn status_service_target_port(
    &mut self,
    route: &KubernetesObject,
    attachment: &RouteAttachment,
    args: &SharedArgs,
  ) -> Option<u16> {
    let Some(raw_ref) = args.status_service.as_deref() else {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        "TCPRoute/UDPRoute requires --status-service namespace/name for external-port mapping",
      ));
      return None;
    };
    let Some((namespace, name)) = raw_ref.split_once('/') else {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        "--status-service must use namespace/name syntax",
      ));
      return None;
    };
    if namespace.is_empty() || name.is_empty() || name.contains('/') {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        "--status-service must use namespace/name syntax",
      ));
      return None;
    }
    let key = ObjectKey {
      namespace: namespace.to_string(),
      name: name.to_string(),
    };
    let Some(service) = self.services.get(&key) else {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!("status Service {raw_ref} was not found in input snapshot"),
      ));
      return None;
    };
    let mut ports = service.ports.iter().filter(|port| {
      port.port == attachment.listener.port && port.protocol == attachment.listener.protocol
    });
    let Some(port) = ports.next() else {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!(
          "status Service {raw_ref} does not expose {} port {} for Gateway listener {}",
          attachment.listener.protocol,
          attachment.listener.port,
          attachment.listener.name.as_deref().unwrap_or("<unnamed>"),
        ),
      ));
      return None;
    };
    if ports.next().is_some() {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!("status Service {raw_ref} has ambiguous duplicate port mappings"),
      ));
      return None;
    }
    let target = match port.target_port {
      Some(ServiceTargetPort::Number(target)) => target,
      None => port.port,
      Some(ServiceTargetPort::Name) => {
        self.diagnostics.push(Diagnostic::error(
          object_ref(route),
          format!(
            "status Service {raw_ref} port {} must use a numeric targetPort",
            port.port
          ),
        ));
        return None;
      }
    };
    if target < 1024 {
      self.diagnostics.push(Diagnostic::error(
        object_ref(route),
        format!(
          "status Service {raw_ref} targetPort {target} must be unprivileged (1024 or higher)"
        ),
      ));
      return None;
    }
    Some(target)
  }

  fn install_l4_candidate(&mut self, candidate: Candidate, bind: String) {
    let Some(servers) = candidate.servers else {
      return;
    };
    let listener_name = sanitize_name(&format!(
      "gwapi-{}-{}-{}-{}",
      candidate.key.network,
      candidate.key.gateway_namespace,
      candidate.key.gateway_name,
      candidate.key.listener_name,
    ));
    let pool_name = format!("{listener_name}-pool");
    let source = format!(
      "{}/{}/{} via Gateway/{}/{} listener {}",
      candidate.route.kind,
      candidate.route.namespace(),
      candidate.route.name(),
      candidate.key.gateway_namespace,
      candidate.key.gateway_name,
      candidate.key.listener_name,
    );
    self.stream_pools.insert(
      pool_name.clone(),
      GeneratedStreamPool {
        source: source.clone(),
        name: pool_name.clone(),
        servers,
      },
    );
    self.stream_listeners.insert(
      listener_name.clone(),
      GeneratedStreamListener {
        source,
        name: listener_name,
        network: candidate.key.network,
        bind,
        upstream_pool: pool_name,
      },
    );
  }
}

fn route_precedence(route: &KubernetesObject) -> (&str, &str, &str) {
  (
    route.metadata.creation_timestamp.as_deref().unwrap_or("~"),
    route.namespace(),
    route.name(),
  )
}
