use super::*;

fn args() -> SharedArgs {
  SharedArgs {
    controller_name: "oxibelt.dev/gateway-controller".to_string(),
    managed_config_path: "conf.d/gateway-api.generated.toml".to_string(),
    admin_url: "http://127.0.0.1:9092".parse().expect("url"),
    admin_token_env: "OXIBELT_ADMIN_TOKEN".to_string(),
    admin_token_file: None,
    ca_certs: Vec::new(),
    client_cert: None,
    client_key: None,
    watch_namespace: None,
    status_address: vec!["203.0.113.10".to_string()],
    dry_run: false,
    health_bind: None,
  }
}

fn object(raw: &str) -> KubernetesObject {
  let value: Value = serde_yaml::from_str(raw).expect("yaml");
  KubernetesObject::from_value(value)
    .expect("object")
    .into_iter()
    .next()
    .expect("one object")
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
  let patches = build_status_patches(&objects, &args(), &[]);

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
fn tcproute_status_marks_parent_unsupported() {
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
apiVersion: gateway.networking.k8s.io/v1alpha2
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
  let patches = build_status_patches(&objects, &args(), &[]);

  let route = patches
    .iter()
    .find(|patch| patch.resource == "tcproutes")
    .expect("route patch");
  assert_eq!(
    route.status["parents"][0]["conditions"][0]["reason"],
    "UnsupportedKind"
  );
  assert_eq!(
    route.status["parents"][0]["conditions"][0]["status"],
    CONDITION_FALSE
  );
}
