use super::*;

#[test]
fn tcp_route_uses_status_service_target_port_and_oldest_route_wins() {
  let raw = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: tcp, protocol: TCP, port: 9000}
---
apiVersion: v1
kind: Service
metadata: {name: edge, namespace: default}
spec:
  ports:
  - {name: tcp, protocol: TCP, port: 9000, targetPort: 19000}
---
apiVersion: v1
kind: Service
metadata: {name: old, namespace: default}
spec:
  ports:
  - {protocol: TCP, port: 7000}
---
apiVersion: v1
kind: Service
metadata: {name: new, namespace: default}
spec:
  ports:
  - {protocol: TCP, port: 7001}
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: old
  namespace: default
  creationTimestamp: "2026-01-01T00:00:00Z"
spec:
  parentRefs:
  - {name: edge, sectionName: tcp, port: 9000}
  rules:
  - backendRefs:
    - {name: old, port: 7000, weight: 3}
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: new
  namespace: default
  creationTimestamp: "2026-01-02T00:00:00Z"
spec:
  parentRefs:
  - {name: edge, sectionName: tcp, port: 9000}
  rules:
  - backendRefs:
    - {name: new, port: 7001}
"#;
  let mut args = args();
  args.status_service = Some("default/edge".to_string());
  let rendered = translate_objects(&objects(raw), &args).expect("translate");

  assert!(rendered.toml.contains("[[stream_upstream_pools]]"));
  assert!(rendered.toml.contains("[[stream_listeners]]"));
  assert!(rendered.toml.contains("bind = \"0.0.0.0:19000\""));
  assert!(
    rendered
      .toml
      .contains("tcp://old.default.svc.cluster.local:7000")
  );
  assert!(
    !rendered
      .toml
      .contains("tcp://new.default.svc.cluster.local:7001")
  );
  assert!(rendered.diagnostics.iter().any(|diagnostic| {
    diagnostic.object == "TCPRoute/default/new"
      && diagnostic.message.contains("Accepted but not Programmed")
  }));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn invalid_oldest_tcp_route_does_not_fall_back_to_a_younger_route() {
  let raw = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: tcp, protocol: TCP, port: 9000}
---
apiVersion: v1
kind: Service
metadata: {name: edge, namespace: default}
spec:
  ports:
  - {name: tcp, protocol: TCP, port: 9000, targetPort: 19000}
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: default}
spec:
  ports:
  - {protocol: TCP, port: 7000}
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: invalid-oldest
  namespace: default
  creationTimestamp: "2026-01-01T00:00:00Z"
spec:
  parentRefs:
  - {name: edge, sectionName: tcp}
  rules:
  - backendRefs:
    - {name: app, port: 7000}
  - backendRefs:
    - {name: app, port: 7000}
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: valid-younger
  namespace: default
  creationTimestamp: "2026-01-02T00:00:00Z"
spec:
  parentRefs:
  - {name: edge, sectionName: tcp}
  rules:
  - backendRefs:
    - {name: app, port: 7000}
"#;
  let mut args = args();
  args.status_service = Some("default/edge".to_string());
  let rendered = translate_objects(&objects(raw), &args).expect("translate");

  assert!(!rendered.toml.contains("[[stream_listeners]]"));
  assert!(rendered.diagnostics.iter().any(|diagnostic| {
    diagnostic.object == "TCPRoute/default/invalid-oldest"
      && diagnostic.message.contains("supports exactly one rule")
  }));
  assert!(rendered.diagnostics.iter().any(|diagnostic| {
    diagnostic.object == "TCPRoute/default/valid-younger"
      && diagnostic.message.contains("Accepted but not Programmed")
  }));
  pretty_assertions::assert_eq!(
    rendered.disposition,
    TranslationDisposition::PreserveLastGood
  );
}

#[test]
fn udp_route_requires_shared_flow_state_and_renders_bounded_admission_settings() {
  let raw = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: dns, protocol: UDP, port: 5353}
---
apiVersion: v1
kind: Service
metadata: {name: edge, namespace: default}
spec:
  ports:
  - {name: dns, protocol: UDP, port: 5353, targetPort: 15353}
---
apiVersion: v1
kind: Service
metadata: {name: dns, namespace: default}
spec:
  ports:
  - {protocol: UDP, port: 53}
---
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata: {name: dns, namespace: default}
spec:
  parentRefs:
  - {name: edge, sectionName: dns}
  rules:
  - backendRefs:
    - {name: dns, port: 53}
"#;
  let mut args = args();
  args.status_service = Some("default/edge".to_string());
  let disabled = translate_objects(&objects(raw), &args).expect("translate disabled UDPRoute");

  assert!(!disabled.toml.contains("network = \"udp\""));
  assert!(!disabled.toml.contains("[[stream_upstream_pools]]"));
  assert!(!disabled.toml.contains("udp_flow_state"));
  assert!(disabled.diagnostics.iter().any(|diagnostic| {
    diagnostic.object == "UDPRoute/default/dns"
      && diagnostic.severity == crate::model::DiagnosticSeverity::Error
      && diagnostic.message == crate::translate::UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC
  }));
  pretty_assertions::assert_eq!(
    disabled.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  generated_toml_validates(&disabled.toml);

  args.udp_flow_state = crate::cli::UdpFlowState::SharedRequired;
  let rendered = translate_objects(&objects(raw), &args).expect("translate");

  assert!(rendered.toml.contains("network = \"udp\""));
  assert!(
    rendered
      .toml
      .contains("udp_flow_state = \"shared_required\"")
  );
  assert!(rendered.toml.contains("udp_new_flow_rate = \"200r/s\""));
  assert!(rendered.toml.contains("udp_new_flow_burst = 400"));
  assert!(rendered.toml.contains("max_udp_flows = 8192"));
  assert!(rendered.toml.contains("udp_batch_size = 16"));
  generated_toml_parses(&rendered.toml);
}

#[test]
fn tcp_and_udp_listeners_can_share_a_numeric_target_port() {
  let raw = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: tcp, protocol: TCP, port: 9000}
  - {name: udp, protocol: UDP, port: 9000}
---
apiVersion: v1
kind: Service
metadata: {name: edge, namespace: default}
spec:
  ports:
  - {name: tcp, protocol: TCP, port: 9000, targetPort: 19000}
  - {name: udp, protocol: UDP, port: 9000, targetPort: 19000}
---
apiVersion: v1
kind: Service
metadata: {name: tcp-app, namespace: default}
spec:
  ports:
  - {protocol: TCP, port: 7000}
---
apiVersion: v1
kind: Service
metadata: {name: udp-app, namespace: default}
spec:
  ports:
  - {protocol: UDP, port: 7000}
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: tcp, namespace: default}
spec:
  parentRefs:
  - {name: edge, sectionName: tcp}
  rules:
  - backendRefs:
    - {name: tcp-app, port: 7000}
---
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata: {name: udp, namespace: default}
spec:
  parentRefs:
  - {name: edge, sectionName: udp}
  rules:
  - backendRefs:
    - {name: udp-app, port: 7000}
"#;
  let mut args = args();
  args.status_service = Some("default/edge".to_string());
  args.udp_flow_state = crate::cli::UdpFlowState::SharedRequired;
  let rendered = translate_objects(&objects(raw), &args).expect("translate");

  pretty_assertions::assert_eq!(rendered.toml.matches("bind = \"0.0.0.0:19000\"").count(), 2);
  assert!(rendered.toml.contains("network = \"tcp\""));
  assert!(rendered.toml.contains("network = \"udp\""));
  assert!(
    !rendered
      .diagnostics
      .iter()
      .any(|diagnostic| { diagnostic.message.contains("duplicate process bind") })
  );
  generated_toml_parses(&rendered.toml);
}

#[test]
fn duplicate_tcp_binds_deprogram_only_the_colliding_listeners() {
  let raw = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: first, protocol: TCP, port: 9000}
  - {name: second, protocol: TCP, port: 9001}
  - {name: independent, protocol: TCP, port: 9002}
---
apiVersion: v1
kind: Service
metadata: {name: edge, namespace: default}
spec:
  ports:
  - {name: first, protocol: TCP, port: 9000, targetPort: 19000}
  - {name: second, protocol: TCP, port: 9001, targetPort: 19000}
  - {name: independent, protocol: TCP, port: 9002, targetPort: 19002}
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: default}
spec:
  ports:
  - {protocol: TCP, port: 7000}
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: first, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: first}]
  rules: [{backendRefs: [{name: app, port: 7000}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: second, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: second}]
  rules: [{backendRefs: [{name: app, port: 7000}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: independent, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: independent}]
  rules: [{backendRefs: [{name: app, port: 7000}]}]
"#;
  let mut args = args();
  args.status_service = Some("default/edge".to_string());
  let rendered = translate_objects(&objects(raw), &args).expect("translate duplicate binds");

  pretty_assertions::assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  pretty_assertions::assert_eq!(rendered.toml.matches("[[stream_listeners]]").count(), 1);
  assert!(!rendered.toml.contains("bind = \"0.0.0.0:19000\""));
  assert!(rendered.toml.contains("bind = \"0.0.0.0:19002\""));
  pretty_assertions::assert_eq!(
    rendered
      .diagnostics
      .iter()
      .filter(|diagnostic| diagnostic.message.contains("duplicate process bind"))
      .count(),
    2
  );
  generated_toml_parses(&rendered.toml);
}

#[test]
fn invalid_listener_still_reserves_its_known_process_bind() {
  let raw = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: invalid, protocol: TCP, port: 9000}
  - {name: colliding, protocol: TCP, port: 9001}
  - {name: independent, protocol: TCP, port: 9002}
---
apiVersion: v1
kind: Service
metadata: {name: edge, namespace: default}
spec:
  ports:
  - {name: invalid, protocol: TCP, port: 9000, targetPort: 19000}
  - {name: colliding, protocol: TCP, port: 9001, targetPort: 19000}
  - {name: independent, protocol: TCP, port: 9002, targetPort: 19002}
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: default}
spec:
  ports: [{protocol: TCP, port: 7000}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: invalid, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: invalid}]
  rules: [{backendRefs: [{name: missing, port: 7000}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: colliding, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: colliding}]
  rules: [{backendRefs: [{name: app, port: 7000}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: independent, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: independent}]
  rules: [{backendRefs: [{name: app, port: 7000}]}]
"#;
  let mut args = args();
  args.status_service = Some("default/edge".to_string());
  let rendered = translate_objects(&objects(raw), &args).expect("translate reserved bind");

  pretty_assertions::assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  pretty_assertions::assert_eq!(rendered.toml.matches("[[stream_listeners]]").count(), 1);
  assert!(!rendered.toml.contains("bind = \"0.0.0.0:19000\""));
  assert!(rendered.toml.contains("bind = \"0.0.0.0:19002\""));
  assert!(rendered.diagnostics.iter().any(|diagnostic| {
    diagnostic
      .message
      .contains("backend Service default/missing was not found")
  }));
  pretty_assertions::assert_eq!(
    rendered
      .diagnostics
      .iter()
      .filter(|diagnostic| diagnostic.message.contains("duplicate process bind"))
      .count(),
    2
  );
  generated_toml_parses(&rendered.toml);
}

#[test]
fn withdrawn_status_service_mapping_deprograms_the_selected_listener() {
  let raw = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners: [{name: tcp, protocol: TCP, port: 9000}]
---
apiVersion: v1
kind: Service
metadata: {name: edge, namespace: default}
spec:
  ports: [{name: other, protocol: TCP, port: 9001, targetPort: 19001}]
---
apiVersion: v1
kind: Service
metadata: {name: app, namespace: default}
spec:
  ports: [{protocol: TCP, port: 7000}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: app, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: tcp}]
  rules: [{backendRefs: [{name: app, port: 7000}]}]
"#;
  let mut args = args();
  args.status_service = Some("default/edge".to_string());
  let rendered = translate_objects(&objects(raw), &args).expect("translate withdrawn mapping");

  pretty_assertions::assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(!rendered.toml.contains("[[stream_listeners]]"));
  assert!(!rendered.toml.contains("[[stream_upstream_pools]]"));
  assert!(rendered.diagnostics.iter().any(|diagnostic| {
    diagnostic
      .message
      .contains("does not expose TCP port 9000 for Gateway listener tcp")
  }));
}
