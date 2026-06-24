use serde_json::Value;

use super::super::{RenderedConfig, translate_objects};
use crate::cli::SharedArgs;
use crate::model::{DiagnosticSeverity, KubernetesObject};

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
    status_address: Vec::new(),
    dry_run: false,
    health_bind: None,
  }
}

fn objects(raw: &str) -> Vec<KubernetesObject> {
  let mut objects = Vec::new();
  for value in serde_saphyr::from_multiple::<Value>(raw).expect("yaml should parse") {
    objects.extend(KubernetesObject::from_value(value).expect("object should parse"));
  }
  objects
}

fn has_error_containing(rendered: &RenderedConfig, needle: &str) -> bool {
  rendered.diagnostics.iter().any(|diagnostic| {
    diagnostic.severity == DiagnosticSeverity::Error && diagnostic.message.contains(needle)
  })
}

#[test]
fn cross_namespace_http_route_respects_default_allowed_routes_same() {
  let raw = cross_namespace_http_fixture("");
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(!rendered.toml.contains("[[routes]]"));
  assert!(
    rendered
      .diagnostics
      .iter()
      .any(|diagnostic| diagnostic.message.contains("not attached")),
    "{:?}",
    rendered.diagnostics
  );
}

#[test]
fn cross_namespace_http_route_allowed_by_all_namespaces() {
  let raw = cross_namespace_http_fixture(
    r#"
    allowedRoutes:
      namespaces:
        from: All
"#,
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(
    rendered
      .toml
      .contains("origin = \"http://app.tenant.svc.cluster.local:8080\"")
  );
}

#[test]
fn cross_namespace_http_route_allowed_by_namespace_selector_only_when_matching() {
  let raw = format!(
    "{}{}",
    NAMESPACES_FOR_SELECTOR,
    cross_namespace_http_fixture(SELECTOR_POLICY)
      .replace("namespace: tenant", "namespace: tenant-allowed")
      .replace("name: app", "name: allowed")
  );
  let denied = cross_namespace_http_fixture(SELECTOR_POLICY)
    .replace("namespace: tenant", "namespace: tenant-denied")
    .replace("name: app", "name: denied");
  let rendered =
    translate_objects(&objects(&format!("{raw}\n---\n{denied}")), &args()).expect("translate");

  assert!(
    rendered
      .toml
      .contains("origin = \"http://allowed.tenant-allowed.svc.cluster.local:8080\""),
    "{}",
    rendered.toml
  );
  assert!(
    !rendered
      .toml
      .contains("origin = \"http://denied.tenant-denied.svc.cluster.local:8080\"")
  );
}

#[test]
fn tls_route_respects_default_allowed_routes_same() {
  let raw = cross_namespace_tls_fixture("");
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(!rendered.toml.contains("[[sni_forward.rules]]"));
  assert!(
    rendered
      .diagnostics
      .iter()
      .any(|diagnostic| diagnostic.message.contains("not attached")),
    "{:?}",
    rendered.diagnostics
  );
}

#[test]
fn tls_route_allowed_by_all_namespaces() {
  let raw = cross_namespace_tls_fixture(
    r#"
    allowedRoutes:
      namespaces:
        from: All
"#,
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(
    rendered
      .toml
      .contains("target = \"db.tenant.svc.cluster.local:5432\"")
  );
}

#[test]
fn allowed_routes_kinds_can_exclude_http_route() {
  let raw = cross_namespace_http_fixture(
    r#"
    allowedRoutes:
      namespaces:
        from: All
      kinds:
      - kind: TLSRoute
"#,
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(!rendered.toml.contains("[[routes]]"));
  assert!(
    rendered
      .diagnostics
      .iter()
      .any(|diagnostic| diagnostic.message.contains("not attached")),
    "{:?}",
    rendered.diagnostics
  );
}

#[test]
fn reference_grant_to_name_limits_cross_namespace_service() {
  let rendered = translate_objects(&objects(REFERENCE_GRANT_TO_NAME_LIMITS_SERVICE), &args())
    .expect("translate");

  assert!(has_error_containing(
    &rendered,
    "backend/secret requires ReferenceGrant"
  ));
  assert!(
    rendered
      .toml
      .contains("origin = \"http://public.backend.svc.cluster.local:8080\"")
  );
  assert!(
    !rendered
      .toml
      .contains("origin = \"http://secret.backend.svc.cluster.local:9090\"")
  );
}

fn cross_namespace_http_fixture(listener_policy: &str) -> String {
  format!(
    r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
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
{listener_policy}
---
apiVersion: v1
kind: Service
metadata:
  name: app
  namespace: tenant
spec:
  ports:
  - port: 8080
---
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
  rules:
  - backendRefs:
    - name: app
      port: 8080
"#
  )
}

fn cross_namespace_tls_fixture(listener_policy: &str) -> String {
  format!(
    r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: platform
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: tls
    protocol: TLS
    port: 443
    hostname: db.example.com
    tls:
      mode: Passthrough
{listener_policy}
---
apiVersion: v1
kind: Service
metadata:
  name: db
  namespace: tenant
spec:
  ports:
  - port: 5432
---
apiVersion: gateway.networking.k8s.io/v1
kind: TLSRoute
metadata:
  name: db
  namespace: tenant
spec:
  parentRefs:
  - name: edge
    namespace: platform
    sectionName: tls
  hostnames:
  - db.example.com
  rules:
  - backendRefs:
    - name: db
      port: 5432
"#
  )
}

const SELECTOR_POLICY: &str = r#"
    allowedRoutes:
      namespaces:
        from: Selector
        selector:
          matchLabels:
            shared-gateway: "true"
"#;

const NAMESPACES_FOR_SELECTOR: &str = r#"
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-allowed
  labels:
    shared-gateway: "true"
---
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-denied
  labels:
    shared-gateway: "false"
---
"#;

const REFERENCE_GRANT_TO_NAME_LIMITS_SERVICE: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: oxibelt
spec:
  controllerName: oxibelt.dev/gateway-controller
---
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
---
apiVersion: gateway.networking.k8s.io/v1
kind: ReferenceGrant
metadata:
  name: allow-public
  namespace: backend
spec:
  from:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    namespace: frontend
  to:
  - group: ""
    kind: Service
    name: public
---
apiVersion: v1
kind: Service
metadata:
  name: public
  namespace: backend
spec:
  ports:
  - port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: secret
  namespace: backend
spec:
  ports:
  - port: 9090
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: public
  namespace: frontend
spec:
  parentRefs:
  - name: edge
  rules:
  - backendRefs:
    - name: public
      namespace: backend
      port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: secret
  namespace: frontend
spec:
  parentRefs:
  - name: edge
  rules:
  - backendRefs:
    - name: secret
      namespace: backend
      port: 9090
"#;
