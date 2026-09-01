use super::{RenderedConfig, TranslationDisposition, args, objects, translate_objects};
use crate::cli::SharedArgs;
use crate::model::DiagnosticCode;

const GATEWAY_AND_STATUS_SERVICE: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: frontend}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: web, protocol: HTTP, port: 80}
  - {name: grpc, protocol: HTTPS, port: 443}
  - {name: tcp, protocol: TCP, port: 9000}
  - {name: udp, protocol: UDP, port: 5353}
---
apiVersion: v1
kind: Service
metadata: {name: edge, namespace: frontend}
spec:
  ports:
  - {name: web, protocol: TCP, port: 8080, targetPort: 18080}
  - {name: grpc, protocol: TCP, port: 50051, targetPort: 15051}
  - {name: tcp, protocol: TCP, port: 9000, targetPort: 19000}
  - {name: udp, protocol: UDP, port: 5353, targetPort: 15353}
"#;

fn backend_diagnostic_args() -> SharedArgs {
  let mut args = args();
  args.status_service = Some("frontend/edge".to_string());
  args.udp_flow_state = crate::cli::UdpFlowState::SharedRequired;
  args
}

fn route_diagnostics<'a>(
  rendered: &'a RenderedConfig,
  kind: &str,
  name: &str,
) -> Vec<&'a crate::model::Diagnostic> {
  let object = format!("{kind}/frontend/{name}");
  rendered
    .diagnostics
    .iter()
    .filter(|diagnostic| diagnostic.object == object)
    .collect()
}

fn assert_route_conditions(
  patches: &[crate::status::StatusPatch],
  resource: &str,
  name: &str,
  accepted: &str,
  resolved: &str,
) {
  let patch = patches
    .iter()
    .find(|patch| patch.resource == resource && patch.name == name)
    .unwrap_or_else(|| panic!("missing status patch for {resource}/frontend/{name}"));
  let conditions = patch.status["parents"][0]["conditions"]
    .as_array()
    .expect("route conditions");
  let condition = |condition_type: &str| {
    conditions
      .iter()
      .find(|condition| condition["type"] == condition_type)
      .unwrap_or_else(|| panic!("missing {condition_type} condition for {resource}/{name}"))
  };

  assert_eq!(condition("Accepted")["status"], accepted);
  assert_eq!(condition("ResolvedRefs")["status"], resolved);
  assert_eq!(condition("Programmed")["status"], "False");
  assert_eq!(condition("Accepted")["observedGeneration"], 7);
  assert_eq!(condition("ResolvedRefs")["observedGeneration"], 7);
  assert_eq!(condition("Programmed")["observedGeneration"], 7);
}

#[test]
fn missing_reference_grants_fail_closed_without_partial_backend_pools() {
  let raw = format!(
    r#"{GATEWAY_AND_STATUS_SERVICE}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{name: web, namespace: frontend, generation: 7}}
spec:
  parentRefs: [{{name: edge, sectionName: web}}]
  rules:
  - backendRefs:
    - {{name: web, namespace: backend, port: 8080}}
    - {{name: edge, port: 8080}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata: {{name: grpc, namespace: frontend, generation: 7}}
spec:
  parentRefs: [{{name: edge, sectionName: grpc}}]
  rules:
  - backendRefs:
    - {{name: grpc, namespace: backend, port: 50051}}
    - {{name: edge, port: 50051}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {{name: tcp, namespace: frontend, generation: 7}}
spec:
  parentRefs: [{{name: edge, sectionName: tcp}}]
  rules:
  - backendRefs:
    - {{name: tcp, namespace: backend, port: 7000}}
    - {{name: edge, port: 9000}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata: {{name: udp, namespace: frontend, generation: 7}}
spec:
  parentRefs: [{{name: edge, sectionName: udp}}]
  rules:
  - backendRefs:
    - {{name: udp, namespace: backend, port: 7000}}
    - {{name: edge, port: 5353}}
"#,
  );
  let objects = objects(&raw);
  let args = backend_diagnostic_args();
  let rendered = translate_objects(&objects, &args).expect("translate denied backends");

  for (kind, name) in [
    ("HTTPRoute", "web"),
    ("GRPCRoute", "grpc"),
    ("TCPRoute", "tcp"),
    ("UDPRoute", "udp"),
  ] {
    let diagnostics = route_diagnostics(&rendered, kind, name);
    assert_eq!(diagnostics.len(), 1, "{kind}: {diagnostics:?}");
    assert_eq!(diagnostics[0].code, DiagnosticCode::RefNotPermitted);
    assert!(diagnostics[0].message.contains("requires ReferenceGrant"));
  }
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert_eq!(rendered.toml.matches("[[routes]]").count(), 2);
  assert_eq!(
    rendered
      .toml
      .matches("[routes.actions.direct_response]\nstatus = 503")
      .count(),
    2
  );
  assert!(!rendered.toml.contains("[[upstream_pools]]"));
  assert!(!rendered.toml.contains("[[stream_listeners]]"));
  assert!(!rendered.toml.contains("[[stream_upstream_pools]]"));

  let patches = crate::status::build_status_patches(
    &objects,
    &args,
    &rendered.diagnostics,
    &crate::rollout_status::RolloutStatus::pending("test rollout"),
  );
  for (resource, name) in [
    ("httproutes", "web"),
    ("grpcroutes", "grpc"),
    ("tcproutes", "tcp"),
    ("udproutes", "udp"),
  ] {
    assert_route_conditions(&patches, resource, name, "True", "False");
    let patch = patches
      .iter()
      .find(|patch| patch.resource == resource && patch.name == name)
      .expect("route status patch");
    let conditions = patch.status["parents"][0]["conditions"]
      .as_array()
      .expect("route conditions");
    assert_eq!(conditions[1]["reason"], "RefNotPermitted");
  }
}

#[test]
fn unusable_backends_without_specific_diagnostics_keep_generic_rejections() {
  let raw = format!(
    r#"{GATEWAY_AND_STATUS_SERVICE}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{name: web, namespace: frontend, generation: 7}}
spec:
  parentRefs: [{{name: edge, sectionName: web}}]
  rules:
  - backendRefs: []
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata: {{name: grpc, namespace: frontend, generation: 7}}
spec:
  parentRefs: [{{name: edge, sectionName: grpc}}]
  rules:
  - backendRefs:
    - {{port: 50051}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {{name: tcp, namespace: frontend, generation: 7}}
spec:
  parentRefs: [{{name: edge, sectionName: tcp}}]
  rules:
  - backendRefs:
    - {{name: tcp, port: 7000, weight: 0}}
---
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata: {{name: udp, namespace: frontend, generation: 7}}
spec:
  parentRefs: [{{name: edge, sectionName: udp}}]
  rules:
  - backendRefs: []
"#,
  );
  let objects = objects(&raw);
  let args = backend_diagnostic_args();
  let rendered = translate_objects(&objects, &args).expect("translate unusable backends");

  for (kind, name, message) in [
    (
      "HTTPRoute",
      "web",
      "rule.backendRefs has no usable nonzero Service backend",
    ),
    (
      "GRPCRoute",
      "grpc",
      "backendRef is not an exact Kubernetes Service reference: name is required",
    ),
    (
      "TCPRoute",
      "tcp",
      "TCPRoute must have at least one valid nonzero backendRef",
    ),
    (
      "UDPRoute",
      "udp",
      "UDPRoute must have at least one valid nonzero backendRef",
    ),
  ] {
    let diagnostics = route_diagnostics(&rendered, kind, name);
    assert_eq!(diagnostics.len(), 1, "{kind}: {diagnostics:?}");
    assert_eq!(diagnostics[0].code, DiagnosticCode::InvalidResource);
    assert_eq!(diagnostics[0].message, message);
  }
  assert!(!rendered.toml.contains("[[routes]]"));
  assert!(!rendered.toml.contains("[[stream_listeners]]"));
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::PreserveLastGood
  );

  let mut endpoint_args = backend_diagnostic_args();
  endpoint_args.backend_resolution = crate::cli::BackendResolution::EndpointSliceWatch;
  let endpoint_rendered =
    translate_objects(&objects, &endpoint_args).expect("translate unusable discovery backends");
  let diagnostics = route_diagnostics(&endpoint_rendered, "GRPCRoute", "grpc");
  assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
  assert_eq!(diagnostics[0].code, DiagnosticCode::InvalidResource);
  assert_eq!(
    diagnostics[0].message,
    "backendRef is not an exact Kubernetes Service reference: name is required"
  );
  assert!(!endpoint_rendered.toml.contains("[[routes]]"));
  assert!(!endpoint_rendered.toml.contains("[[upstream_pools]]"));

  let patches = crate::status::build_status_patches(
    &objects,
    &args,
    &rendered.diagnostics,
    &crate::rollout_status::RolloutStatus::pending("test rollout"),
  );
  for (resource, name) in [
    ("httproutes", "web"),
    ("grpcroutes", "grpc"),
    ("tcproutes", "tcp"),
    ("udproutes", "udp"),
  ] {
    assert_route_conditions(&patches, resource, name, "False", "True");
  }
}
