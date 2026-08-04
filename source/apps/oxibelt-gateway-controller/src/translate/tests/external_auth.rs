use super::{
  HTTP_FILTER_FIXTURE, args, generated_toml_validates, has_error_containing, objects,
  translate_objects,
};

const ROUTE_AUTHORIZATION_ALLOWLIST: &str =
  "          allowedHeaders:\n          - authorization\n";

const GRPC_EXTERNAL_AUTH_WITHOUT_REQUEST_HEADERS: &str = r#"
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
  namespace: default
spec:
  gatewayClassName: oxibelt
  listeners:
  - name: http
    protocol: HTTP
    port: 80
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: default
spec:
  ports:
  - port: 50051
---
apiVersion: v1
kind: Service
metadata:
  name: auth
  namespace: default
spec:
  ports:
  - port: 9000
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: echo
  namespace: default
spec:
  parentRefs:
  - name: edge
  rules:
  - filters:
    - type: ExternalAuth
      externalAuth:
        protocol: HTTP
        backendRef:
          name: auth
          port: 9000
        http:
          allowedResponseHeaders:
          - x-auth-user
    backendRefs:
    - name: echo
      port: 50051
"#;

#[test]
fn http_external_auth_requires_route_and_operator_request_header_admission() {
  let route_omits_authorization = HTTP_FILTER_FIXTURE.replace(ROUTE_AUTHORIZATION_ALLOWLIST, "");
  assert_ne!(route_omits_authorization, HTTP_FILTER_FIXTURE);

  for operator_request_headers in [Vec::new(), vec!["authorization".to_string()]] {
    let mut policy = args();
    policy.external_auth_allowed_request_headers = operator_request_headers;
    let rendered = translate_objects(&objects(&route_omits_authorization), &policy)
      .expect("translate omitted request headers");

    assert!(
      rendered.diagnostics.is_empty(),
      "{:?}",
      rendered.diagnostics
    );
    assert!(rendered.toml.contains("forward_headers = []"));
    generated_toml_validates(&rendered.toml);
  }

  let mut operator_omits_authorization = args();
  operator_omits_authorization
    .external_auth_allowed_request_headers
    .clear();
  let rejected = translate_objects(&objects(HTTP_FILTER_FIXTURE), &operator_omits_authorization)
    .expect("translate rejected request headers");
  assert!(has_error_containing(
    &rejected,
    "http.allowedHeaders header authorization is not admitted by operator policy"
  ));
  assert!(!rejected.toml.contains("[[external_auth]]"));
  assert!(!rejected.toml.contains("[[routes]]"));

  let admitted =
    translate_objects(&objects(HTTP_FILTER_FIXTURE), &args()).expect("translate admitted headers");
  assert!(
    admitted
      .toml
      .contains("forward_headers = [\"authorization\"]")
  );
  generated_toml_validates(&admitted.toml);
}

#[test]
fn grpc_external_auth_omitted_request_headers_remain_empty() {
  let rendered = translate_objects(
    &objects(GRPC_EXTERNAL_AUTH_WITHOUT_REQUEST_HEADERS),
    &args(),
  )
  .expect("translate GRPCRoute external auth");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(
    rendered
      .toml
      .contains("provider = \"gateway_ext_auth_http\"")
  );
  assert!(rendered.toml.contains("forward_headers = []"));
  generated_toml_validates(&rendered.toml);
}
