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
    request_mirror_max_body_bytes: 0,
    external_auth_max_body_bytes: 0,
    external_auth_allowed_content_types: Vec::new(),
    external_auth_allowed_request_headers: Vec::new(),
    external_auth_allowed_identity_headers: Vec::new(),
    external_auth_allowed_terminal_headers: Vec::new(),
    external_auth_allow_credentials: false,
    route_policy_max_request_body_bytes: 10_485_760,
    route_policy_max_timeout_ms: 30_000,
    upstream_client_tls_source_secrets: Vec::new(),
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
    target_summary: None,
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
fn gateway_client_certificate_errors_use_top_level_resolved_refs_only() {
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
metadata: {name: edge, namespace: frontend}
spec:
  gatewayClassName: oxibelt
  tls:
    backend:
      clientCertificateRef: {name: client, namespace: credentials}
  listeners:
  - {name: https, protocol: HTTPS, port: 443}
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: app, namespace: frontend}
spec:
  parentRefs: [{name: edge, sectionName: https}]
"#,
    ),
  ];

  for (message, expected_reason) in [
    (
      "client certificate Secret leaf certificate is malformed",
      "InvalidClientCertificateRef",
    ),
    (
      "Gateway backend client certificate Secret cross-namespace reference requires ReferenceGrant",
      "RefNotPermitted",
    ),
  ] {
    let diagnostics = vec![
      Diagnostic::error("Gateway/frontend/edge", message),
      Diagnostic::error("HTTPRoute/frontend/app", message),
    ];
    let patches = build_status_patches(&objects, &args(), &diagnostics, &committed_rollout());
    let gateway = patches
      .iter()
      .find(|patch| patch.resource == "gateways")
      .expect("Gateway patch");
    let gateway_conditions = gateway.status["conditions"].as_array().expect("conditions");
    let condition = |condition_type: &str| {
      gateway_conditions
        .iter()
        .find(|condition| condition["type"] == condition_type)
        .expect("Gateway condition")
    };
    assert_eq!(condition("ResolvedRefs")["status"], CONDITION_FALSE);
    assert_eq!(condition("ResolvedRefs")["reason"], expected_reason);
    assert_eq!(condition("Accepted")["status"], CONDITION_TRUE);
    assert_eq!(condition("Programmed")["status"], CONDITION_TRUE);

    let listener_conditions = gateway.status["listeners"][0]["conditions"]
      .as_array()
      .expect("listener conditions");
    assert_eq!(listener_conditions[1]["status"], CONDITION_TRUE);
    assert_eq!(listener_conditions[2]["status"], CONDITION_TRUE);
    assert_eq!(listener_conditions[2]["reason"], "ResolvedRefs");

    let route = patches
      .iter()
      .find(|patch| patch.resource == "httproutes")
      .expect("HTTPRoute patch");
    assert_eq!(
      route.status["parents"][0]["conditions"][1]["status"],
      CONDITION_FALSE
    );
    assert_eq!(
      route.status["parents"][0]["conditions"][1]["reason"],
      expected_reason
    );
    assert_eq!(
      route.status["parents"][0]["conditions"][2]["status"],
      CONDITION_FALSE
    );
  }
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
fn route_status_rejects_disjoint_route_and_listener_hostnames() {
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
  - {name: http, protocol: HTTP, port: 80, hostname: owned.example.com}
"#,
    ),
    object(
      r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: redirect, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: http}]
  hostnames: [outside.example.com]
  rules: []
"#,
    ),
  ];
  let patches = build_status_patches(&objects, &args(), &[], &committed_rollout());
  let gateway = patches
    .iter()
    .find(|patch| patch.resource == "gateways")
    .expect("gateway patch");
  assert_eq!(gateway.status["listeners"][0]["attachedRoutes"], 0);
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

#[test]
fn route_policy_status_reports_resolution_caps_and_proven_artifact() {
  let gateway_class = object(
    r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: {name: oxibelt}
spec: {controllerName: oxibelt.dev/gateway-controller}
"#,
  );
  let gateway = object(
    r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: default}
spec:
  gatewayClassName: oxibelt
  listeners: [{name: http, protocol: HTTP, port: 80}]
"#,
  );
  let route = object(
    r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: app, namespace: default}
spec:
  parentRefs: [{name: edge, sectionName: http}]
  rules:
  - filters:
    - type: ExtensionRef
      extensionRef:
        group: gateway.oxibelt.dev
        kind: OxiBeltRoutePolicy
        name: app-security
"#,
  );
  let policy = object(
    r#"
apiVersion: gateway.oxibelt.dev/v1alpha1
kind: OxiBeltRoutePolicy
metadata: {name: app-security, namespace: default, generation: 3, resourceVersion: "9"}
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: app}
  limits: {maxRequestBodyBytes: 1024}
"#,
  );
  let mut rollout = committed_rollout();
  rollout.proof.as_mut().expect("proof").revision =
    "oxibelt-config-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
  let objects = vec![gateway_class, gateway, route, policy];
  let patches = build_status_patches(&objects, &args(), &[], &rollout);
  let policy = patches
    .iter()
    .find(|patch| patch.resource == "oxibeltroutepolicies")
    .expect("route policy status patch");

  assert_eq!(policy.api_prefix, "/apis/gateway.oxibelt.dev/v1alpha1");
  assert_eq!(policy.resource_version.as_deref(), Some("9"));
  assert_eq!(policy.status["conditions"][0]["status"], CONDITION_TRUE);
  assert_eq!(policy.status["conditions"][1]["status"], CONDITION_TRUE);
  assert_eq!(policy.status["conditions"][2]["status"], CONDITION_FALSE);
  assert_eq!(policy.status["conditions"][3]["status"], CONDITION_TRUE);
  assert_eq!(
    policy.status["artifactDigest"],
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  );

  let diagnostics = vec![Diagnostic::error(
    "OxiBeltRoutePolicy/default/app-security",
    "invalid OxiBeltRoutePolicy: spec.limits.maxRequestBodyBytes exceeds the operator cap of 1024",
  )];
  let patches = build_status_patches(&objects, &args(), &diagnostics, &rollout);
  let rejected = patches
    .iter()
    .find(|patch| patch.resource == "oxibeltroutepolicies")
    .expect("rejected route policy status patch");
  assert_eq!(rejected.status["conditions"][0]["status"], CONDITION_FALSE);
  assert_eq!(
    rejected.status["conditions"][0]["reason"],
    "ExceedsOperatorLimit"
  );
  assert_eq!(rejected.status["conditions"][3]["status"], CONDITION_FALSE);
}

#[test]
fn route_policy_status_does_not_program_an_omitted_target_route() {
  let route = object(
    r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: app, namespace: default}
spec:
  rules:
  - filters:
    - type: ExtensionRef
      extensionRef:
        group: gateway.oxibelt.dev
        kind: OxiBeltRoutePolicy
        name: app-security
"#,
  );
  let policy = object(
    r#"
apiVersion: gateway.oxibelt.dev/v1alpha1
kind: OxiBeltRoutePolicy
metadata: {name: app-security, namespace: default}
spec:
  targetRef: {group: gateway.networking.k8s.io, kind: HTTPRoute, name: app}
  waf: {requestRuleGroups: [baseline]}
"#,
  );
  let patches = build_status_patches(&[route, policy], &args(), &[], &committed_rollout());
  let policy = patches
    .iter()
    .find(|patch| patch.resource == "oxibeltroutepolicies")
    .expect("route policy status patch");
  assert_eq!(policy.status["conditions"][0]["status"], CONDITION_TRUE);
  assert_eq!(policy.status["conditions"][1]["status"], CONDITION_TRUE);
  assert_eq!(policy.status["conditions"][3]["status"], CONDITION_FALSE);
  assert_eq!(
    policy.status["conditions"][3]["reason"],
    "TranslationOmitted"
  );
}
