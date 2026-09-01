use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::super::cli::{SharedArgs, UdpFlowState};
use super::super::model::{Diagnostic, KubernetesObject, ObjectKey, object_ref};
use super::{
  GeneratedStreamListener, GeneratedStreamPool, GeneratedStreamServer, RouteAttachment,
  ServiceTargetPort, TranslationFailure, TranslationState, UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC,
  backend_service_port, exact_service_backend_ref, sanitize_name, unsupported_field,
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
      let mut failures = Vec::new();
      let servers = match self.l4_backend_servers(route, network) {
        Ok(servers) => Some(servers),
        Err(failure) => {
          failures.push(failure);
          None
        }
      };
      if route.kind == "UDPRoute" && args.udp_flow_state == UdpFlowState::Disabled {
        failures
          .push(self.fail_closed_error(object_ref(route), UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC));
      }
      let mut route_candidates = Vec::new();
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
        let bind_port = match self.status_service_target_port(route, &attachment, args) {
          Ok(bind_port) => Some(bind_port),
          Err(failure) => {
            failures.push(failure);
            None
          }
        };
        route_candidates.push(Candidate {
          route: route.clone(),
          attachment,
          key,
          bind_port,
          servers: servers.clone(),
        });
      }
      if !failures.is_empty() {
        for candidate in &mut route_candidates {
          candidate.servers = None;
        }
        let all_fail_closed = failures
          .iter()
          .all(|failure| matches!(failure, TranslationFailure::FailClosedDeprogram { .. }));
        if all_fail_closed {
          for failure in failures {
            self.complete_fail_closed_deprogram(failure);
          }
        }
      }
      candidates.extend(route_candidates);
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
      let Some(bind_port) = winner.bind_port else {
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
          let failure = self.fail_closed_error(
            object_ref(&candidate.route),
            format!(
              "Gateway listener maps to duplicate process bind {bind}; each TCP/UDP listener needs a distinct status Service targetPort"
            ),
          );
          self.complete_fail_closed_deprogram(failure);
        }
        continue;
      }
      if let Some(candidate) = bound.into_iter().next()
        && candidate.servers.is_some()
      {
        self.install_l4_candidate(candidate, bind);
      }
    }
  }

  fn l4_backend_servers(
    &mut self,
    route: &KubernetesObject,
    network: &str,
  ) -> Result<Vec<GeneratedStreamServer>, TranslationFailure> {
    if let Some(field) = unsupported_field(&route.spec, &["parentRefs", "rules"]) {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!("{} spec.{field} is unsupported", route.kind),
      ));
    }
    let Some(rules) = route.spec.get("rules").and_then(Value::as_array) else {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!("{} spec.rules is required", route.kind),
      ));
    };
    if rules.len() != 1 {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!("{} supports exactly one rule", route.kind),
      ));
    }
    let rule = &rules[0];
    if let Some(field) = unsupported_field(rule, &["backendRefs", "filters"]) {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!("{} rule.{field} is unsupported", route.kind),
      ));
    }
    if rule
      .get("filters")
      .and_then(Value::as_array)
      .is_some_and(|filters| !filters.is_empty())
    {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!("{} filters are unsupported", route.kind),
      ));
    }
    let Some(backends) = rule.get("backendRefs").and_then(Value::as_array) else {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!("{} rule.backendRefs is required", route.kind),
      ));
    };
    let mut servers = Vec::new();
    for (index, backend) in backends.iter().enumerate() {
      let weight = match backend.get("weight") {
        None => 1,
        Some(value) => match value.as_u64().and_then(|weight| u32::try_from(weight).ok()) {
          Some(weight) if weight <= 1_000_000 => weight,
          _ => {
            return Err(self.preserve_last_good_error(
              object_ref(route),
              format!(
                "{} backendRef.weight must be an unsigned integer no greater than 1000000",
                route.kind
              ),
            ));
          }
        },
      };
      if weight == 0 {
        continue;
      }
      let (namespace, name) =
        exact_service_backend_ref(backend, route.namespace()).map_err(|error| {
          self.preserve_last_good_error(
            object_ref(route),
            format!(
              "{} backendRef is not an exact Kubernetes Service reference: {error}",
              route.kind
            ),
          )
        })?;
      if namespace != route.namespace()
        && !self.reference_allowed(route, &route.kind, &namespace, "Service", &name)
      {
        return Err(self.fail_closed_error(
          object_ref(route),
          format!("cross-namespace backendRef to {namespace}/{name} requires ReferenceGrant"),
        ));
      }
      let key = ObjectKey {
        namespace: namespace.clone(),
        name: name.clone(),
      };
      let Some(service) = self.services.get(&key) else {
        return Err(self.fail_closed_error(
          object_ref(route),
          format!("backend Service {namespace}/{name} was not found in input snapshot"),
        ));
      };
      let Some(service_port) = backend_service_port(backend, service) else {
        return Err(self.fail_closed_error(
          object_ref(route),
          format!("backend Service {namespace}/{name} does not expose the referenced port"),
        ));
      };
      if service_port.protocol.to_ascii_lowercase() != network {
        return Err(self.fail_closed_error(
          object_ref(route),
          format!(
            "backend Service {namespace}/{name} port {} uses protocol {}, not {}",
            service_port.port,
            service_port.protocol,
            network.to_ascii_uppercase(),
          ),
        ));
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
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!(
          "{} must have at least one valid nonzero backendRef",
          route.kind
        ),
      ));
    }
    Ok(servers)
  }

  fn status_service_target_port(
    &mut self,
    route: &KubernetesObject,
    attachment: &RouteAttachment,
    args: &SharedArgs,
  ) -> Result<u16, TranslationFailure> {
    let Some(raw_ref) = args.status_service.as_deref() else {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        "TCPRoute/UDPRoute requires --status-service namespace/name for external-port mapping",
      ));
    };
    let Some((namespace, name)) = raw_ref.split_once('/') else {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        "--status-service must use namespace/name syntax",
      ));
    };
    if name.contains('/')
      || super::super::rollout::validate_kubernetes_dns_label("status Service namespace", namespace)
        .is_err()
      || super::super::rollout::validate_kubernetes_dns_subdomain("status Service name", name)
        .is_err()
    {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        "--status-service must use namespace/name syntax",
      ));
    }
    let key = ObjectKey {
      namespace: namespace.to_string(),
      name: name.to_string(),
    };
    let Some(service) = self.services.get(&key) else {
      return Err(self.fail_closed_error(
        object_ref(route),
        format!("status Service {raw_ref} was not found in input snapshot"),
      ));
    };
    let mut ports = service.ports.iter().filter(|port| {
      port.port == attachment.listener.port && port.protocol == attachment.listener.protocol
    });
    let Some(port) = ports.next() else {
      return Err(self.fail_closed_error(
        object_ref(route),
        format!(
          "status Service {raw_ref} does not expose {} port {} for Gateway listener {}",
          attachment.listener.protocol,
          attachment.listener.port,
          attachment.listener.name.as_deref().unwrap_or("<unnamed>"),
        ),
      ));
    };
    if ports.next().is_some() {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!("status Service {raw_ref} has ambiguous duplicate port mappings"),
      ));
    }
    let target = match port.target_port {
      Some(ServiceTargetPort::Number(target)) => target,
      None => port.port,
      Some(ServiceTargetPort::Name) => {
        return Err(self.preserve_last_good_error(
          object_ref(route),
          format!(
            "status Service {raw_ref} port {} must use a numeric targetPort",
            port.port
          ),
        ));
      }
    };
    if target < 1024 {
      return Err(self.preserve_last_good_error(
        object_ref(route),
        format!(
          "status Service {raw_ref} targetPort {target} must be unprivileged (1024 or higher)"
        ),
      ));
    }
    Ok(target)
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
