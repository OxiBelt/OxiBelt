use super::*;

fn args() -> SharedArgs {
  SharedArgs {
    controller_name: "oxibelt.dev/gateway-controller".to_string(),
    managed_config_path: "conf.d/gateway-api.generated.toml".to_string(),
    watch_namespace: None,
    status_address: vec!["203.0.113.10".to_string()],
    status_service: None,
    l4_bind_address: std::net::Ipv4Addr::UNSPECIFIED.into(),
    l4_connect_timeout_ms: 3000,
    l4_idle_timeout_ms: 75_000,
    udp_flow_state: crate::cli::UdpFlowState::Disabled,
    udp_max_flows: 8192,
    udp_new_flow_rate: "200r/s".to_string(),
    udp_new_flow_burst: 400,
    udp_datagram_rate: "200r/s".to_string(),
    udp_datagram_burst: 400,
    udp_batch: crate::cli::UdpBatchMode::Auto,
    udp_batch_size: 16,
    backend_resolution: crate::cli::BackendResolution::ClusterDns,
    dry_run: false,
    health_bind: None,
  }
}

fn object(raw: &str) -> KubernetesObject {
  let value: Value = serde_saphyr::from_str(raw).expect("yaml");
  KubernetesObject::from_value(value)
    .expect("object")
    .into_iter()
    .next()
    .expect("one object")
}

fn committed_rollout() -> RolloutStatus {
  RolloutStatus {
    phase: crate::rollout::RolloutPhase::Committed,
    desired_revision: Some("revision".to_string()),
    desired_content_digest: Some("digest".to_string()),
    reason: None,
    proof: Some(crate::rollout_status::CommitProof::test()),
  }
}

#[test]
fn gateway_status_reports_supported_listener_and_address() {
  let objects = vec![
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
"#,
    ),
  ];
  let patches = build_status_patches(&objects, &args(), &[], &committed_rollout());

  let gateway = patches
    .iter()
    .find(|patch| patch.resource == "gateways")
    .expect("gateway patch");
  assert_eq!(gateway.status["addresses"][0]["value"], "203.0.113.10");
  assert_eq!(
    gateway.status["listeners"][0]["supportedKinds"][0]["kind"],
    "HTTPRoute"
  );
  assert_eq!(
    gateway.status["listeners"][0]["conditions"][0]["status"],
    CONDITION_TRUE
  );
}

#[test]
fn gateway_status_can_use_data_plane_service_load_balancer_address() {
  let mut args = args();
  args.status_address.clear();
  args.status_service = Some("oxibelt/edge".to_string());
  let objects = vec![
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
"#,
    ),
    object(
      r#"
apiVersion: v1
kind: Service
metadata:
  name: edge
  namespace: oxibelt
status:
  loadBalancer:
    ingress:
    - hostname: edge.example.net
"#,
    ),
  ];
  let patches = build_status_patches(&objects, &args, &[], &committed_rollout());

  let gateway = patches
    .iter()
    .find(|patch| patch.resource == "gateways")
    .expect("gateway patch");
  assert_eq!(gateway.status["addresses"][0]["type"], "Hostname");
  assert_eq!(gateway.status["addresses"][0]["value"], "edge.example.net");
}

#[test]
fn tcproute_status_accepts_matching_v1_parent() {
  let objects = vec![
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: tcp
    protocol: TCP
    port: 443
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata:
  name: passthrough
  namespace: default
spec:
  parentRefs:
  - name: edge
"#,
    ),
  ];
  let patches = build_status_patches(&objects, &args(), &[], &committed_rollout());

  let route = patches
    .iter()
    .find(|patch| patch.resource == "tcproutes")
    .expect("route patch");
  assert_eq!(
    route.status["parents"][0]["conditions"][0]["reason"],
    "Accepted"
  );
  assert_eq!(
    route.status["parents"][0]["conditions"][0]["status"],
    CONDITION_TRUE
  );
}

#[test]
fn competing_tcp_routes_are_attached_and_only_the_oldest_is_programmed() {
  let objects = vec![
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: tcp, protocol: TCP, port: 9000}
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: oldest, namespace: default}
spec:
  parentRefs:
  - {name: edge, sectionName: tcp}
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: TCPRoute
metadata: {name: younger, namespace: default}
spec:
  parentRefs:
  - {name: edge, sectionName: tcp}
"#,
    ),
  ];
  let diagnostics = vec![Diagnostic::warning(
    "TCPRoute/default/younger",
    "route is Accepted but not Programmed because older default/oldest owns the listener",
  )];
  let patches = build_status_patches(&objects, &args(), &diagnostics, &committed_rollout());

  let gateway = patches
    .iter()
    .find(|patch| patch.resource == "gateways")
    .expect("gateway patch");
  assert_eq!(gateway.status["listeners"][0]["attachedRoutes"], 2);

  let oldest = patches
    .iter()
    .find(|patch| patch.resource == "tcproutes" && patch.name == "oldest")
    .expect("oldest route patch");
  assert_eq!(
    oldest.status["parents"][0]["conditions"][2]["status"],
    CONDITION_TRUE
  );

  let younger = patches
    .iter()
    .find(|patch| patch.resource == "tcproutes" && patch.name == "younger")
    .expect("younger route patch");
  assert_eq!(
    younger.status["parents"][0]["conditions"][0]["status"],
    CONDITION_TRUE
  );
  assert_eq!(
    younger.status["parents"][0]["conditions"][2]["status"],
    CONDITION_FALSE
  );
  assert_eq!(
    younger.status["parents"][0]["conditions"][2]["reason"],
    "NotProgrammed"
  );
}

#[test]
fn udp_route_status_reports_shared_flow_state_activation_requirement() {
  let objects = vec![
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners:
  - {name: dns, protocol: UDP, port: 5353}
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: UDPRoute
metadata: {name: dns, namespace: default}
spec:
  parentRefs:
  - {name: edge, sectionName: dns}
"#,
    ),
  ];
  let diagnostics = vec![Diagnostic::error(
    "UDPRoute/default/dns",
    crate::translate::UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC,
  )];
  let patches = build_status_patches(&objects, &args(), &diagnostics, &committed_rollout());
  let route = patches
    .iter()
    .find(|patch| patch.resource == "udproutes" && patch.name == "dns")
    .expect("UDPRoute patch");
  let conditions = route.status["parents"][0]["conditions"]
    .as_array()
    .expect("route conditions");

  assert_eq!(conditions[0]["status"], CONDITION_FALSE);
  assert_eq!(conditions[0]["reason"], "UnsupportedValue");
  assert_eq!(
    conditions[0]["message"],
    crate::translate::UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC
  );
  assert_eq!(conditions[1]["status"], CONDITION_TRUE);
  assert_eq!(conditions[1]["reason"], "ResolvedRefs");
  assert_eq!(conditions[2]["status"], CONDITION_FALSE);
  assert_eq!(conditions[2]["reason"], "NotProgrammed");
  assert_eq!(
    conditions[2]["message"],
    crate::translate::UDP_FLOW_STATE_REQUIRED_DIAGNOSTIC
  );
}

#[test]
fn route_status_rejects_parent_disallowed_by_allowed_routes() {
  let objects = vec![
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: platform
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app
  namespace: tenant
spec:
  parentRefs:
  - name: edge
    namespace: platform
    sectionName: http
"#,
    ),
  ];
  let patches = build_status_patches(&objects, &args(), &[], &committed_rollout());

  let route = patches
    .iter()
    .find(|patch| patch.resource == "httproutes")
    .expect("route patch");
  assert_eq!(
    route.status["parents"][0]["conditions"][0]["reason"],
    "NoMatchingListener"
  );
  assert_eq!(
    route.status["parents"][0]["conditions"][0]["status"],
    CONDITION_FALSE
  );
}

#[test]
fn route_status_marks_reference_grant_name_mismatch_as_unresolved() {
  let objects = vec![
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: frontend
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: secret
  namespace: frontend
spec:
  parentRefs:
  - name: edge
"#,
    ),
  ];
  let diagnostics = vec![Diagnostic::error(
    "HTTPRoute/frontend/secret",
    "cross-namespace backendRef to backend/secret requires ReferenceGrant",
  )];
  let patches = build_status_patches(&objects, &args(), &diagnostics, &committed_rollout());

  let route = patches
    .iter()
    .find(|patch| patch.resource == "httproutes")
    .expect("route patch");
  assert_eq!(
    route.status["parents"][0]["conditions"][1]["reason"],
    "RefNotPermitted"
  );
  assert_eq!(
    route.status["parents"][0]["conditions"][1]["status"],
    CONDITION_FALSE
  );
}
