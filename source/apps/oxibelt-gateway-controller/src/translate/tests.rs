use pretty_assertions::assert_eq;
use serde_json::Value;

use super::{RenderedConfig, translate_objects};
use crate::cli::SharedArgs;
use crate::model::{DiagnosticSeverity, KubernetesObject};
use oxibelt::config::Config;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/rust/common/mod.rs"
  ));
}

#[path = "fixtures.rs"]
mod fixtures;
#[path = "tests/l4.rs"]
mod l4_tests;
#[path = "policy_tests.rs"]
mod policy_tests;

use fixtures::*;

fn args() -> SharedArgs {
  SharedArgs {
    controller_name: "oxibelt.dev/gateway-controller".to_string(),
    managed_config_path: "conf.d/gateway-api.generated.toml".to_string(),
    watch_namespace: None,
    status_address: Vec::new(),
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
    external_auth_max_body_bytes: 4_096,
    external_auth_allowed_content_types: vec!["application/json".to_string()],
    external_auth_allowed_request_headers: vec!["authorization".to_string()],
    external_auth_allowed_identity_headers: vec![
      "www-authenticate".to_string(),
      "x-auth-user".to_string(),
    ],
    external_auth_allowed_terminal_headers: vec![
      "www-authenticate".to_string(),
      "x-auth-user".to_string(),
    ],
    external_auth_allow_credentials: true,
    route_policy_max_request_body_bytes: 10_485_760,
    route_policy_max_timeout_ms: 30_000,
    dry_run: false,
    health_bind: None,
  }
}

fn endpoint_slice_args() -> SharedArgs {
  let mut args = args();
  args.backend_resolution = crate::cli::BackendResolution::EndpointSliceWatch;
  args
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
fn http_route_generates_weighted_pool_and_route() {
  let rendered = translate_objects(&objects(HTTP_FIXTURE), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("[[upstream_pools]]"));
  assert!(
    rendered
      .toml
      .contains("origin = \"http://app.default.svc.cluster.local:8080\"")
  );
  assert!(
    rendered
      .toml
      .contains("origin = \"http://canary.default.svc.cluster.local:8080\"")
  );
  assert!(rendered.toml.contains("weight = 80"));
  assert!(rendered.toml.contains("weight = 20"));
  assert!(rendered.toml.contains("[[routes]]"));
  assert!(rendered.toml.contains("hosts = [\"api.example.com\"]"));
  assert!(rendered.toml.contains("path_prefix = \"/api\""));
  assert!(rendered.toml.contains("methods = [\"GET\"]"));
}

#[test]
fn route_hostnames_are_narrowed_to_listener_ownership_and_disjoint_routes_are_omitted() {
  let wildcard_route = HTTP_FIXTURE.replace("  - api.example.com", "  - '*.example.com'");
  let rendered = translate_objects(&objects(&wildcard_route), &args()).expect("translate");
  assert!(rendered.toml.contains("hosts = [\"api.example.com\"]"));
  assert!(!rendered.toml.contains("hosts = [\"*.example.com\"]"));

  let disjoint_redirect = HTTP_FIXTURE
    .replace("hostname: api.example.com", "hostname: owned.example.com")
    .replace(
      "  - matches:\n",
      "  - filters:\n    - type: RequestRedirect\n      requestRedirect:\n        hostname: login.example.test\n    matches:\n",
    )
    .replace(
      "    backendRefs:\n    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20\n",
      "",
    );
  let rendered = translate_objects(&objects(&disjoint_redirect), &args()).expect("translate");
  assert!(
    !rendered.toml.contains("[[routes]]"),
    "a route outside listener hostname ownership must not become a wildcard redirect"
  );
  assert!(!rendered.toml.contains("login.example.test"));
}

#[test]
fn cross_namespace_backend_requires_reference_grant() {
  let rendered =
    translate_objects(&objects(CROSS_NAMESPACE_WITHOUT_GRANT), &args()).expect("translate");

  assert!(
    rendered.diagnostics.iter().any(
      |diagnostic| diagnostic.severity == DiagnosticSeverity::Error
        && diagnostic.message.contains("requires ReferenceGrant")
    ),
    "{:?}",
    rendered.diagnostics
  );
  assert!(
    rendered
      .toml
      .contains("Generated by oxibelt-gateway-controller")
  );
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn cross_namespace_backend_with_reference_grant_is_allowed() {
  let rendered =
    translate_objects(&objects(CROSS_NAMESPACE_WITH_GRANT), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(
    rendered
      .toml
      .contains("origin = \"http://app.backend.svc.cluster.local:8080\"")
  );
}

#[test]
fn unsupported_header_regex_reports_error() {
  let rendered = translate_objects(&objects(UNSUPPORTED_HEADER_REGEX), &args()).expect("translate");

  assert_eq!(rendered.diagnostics.len(), 1);
  assert!(
    rendered.diagnostics[0]
      .message
      .contains("only Exact header matches")
  );
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn tls_route_generates_sni_forward_rule() {
  let rendered = translate_objects(&objects(TLS_FIXTURE), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("[[sni_forward.rules]]"));
  assert!(
    rendered
      .toml
      .contains("server_names = [\"db.example.com\"]")
  );
  assert!(
    rendered
      .toml
      .contains("target = \"db.default.svc.cluster.local:5432\"")
  );
  assert!(rendered.toml.contains("protocols = [\"tcp_tls\"]"));
}

#[test]
fn unattached_tcproute_is_visible_without_emitting_stream_config() {
  let rendered = translate_objects(&objects(TCP_ROUTE_FIXTURE), &args()).expect("translate");

  assert_eq!(rendered.diagnostics.len(), 1);
  assert_eq!(
    rendered.diagnostics[0].severity,
    DiagnosticSeverity::Warning
  );
  assert!(rendered.diagnostics[0].message.contains("not attached"));
  assert!(!rendered.toml.contains("[[stream_listeners]]"));
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn http_route_filters_generate_native_actions() {
  let rendered = translate_objects(&objects(HTTP_FILTER_FIXTURE), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("[[external_auth]]"));
  assert!(
    rendered
      .toml
      .contains("provider = \"gateway_ext_auth_http\"")
  );
  assert!(
    rendered
      .toml
      .contains("endpoint = \"http://auth.default.svc.cluster.local:9000/verify\"")
  );
  assert!(
    rendered
      .toml
      .contains("forward_headers = [\"authorization\"]")
  );
  assert!(
    rendered
      .toml
      .contains("identity_headers = [\"x-auth-user\", \"www-authenticate\"]")
  );
  assert!(
    rendered
      .toml
      .contains("[[routes.actions.request_headers.set]]")
  );
  assert!(rendered.toml.contains("name = \"x-gateway-route\""));
  assert!(
    rendered
      .toml
      .contains("[[routes.actions.response_headers.add]]")
  );
  assert!(rendered.toml.contains("[routes.actions.cors]"));
  assert!(
    rendered
      .toml
      .contains("allow_origins = [\"https://app.example.com\"]")
  );
  assert!(rendered.toml.contains("[[routes.actions.request_mirrors]]"));
  assert!(rendered.toml.contains("sample_percent = 25"));
  assert!(
    rendered
      .toml
      .contains("external_auth = \"gwapi-http-default-app-0-0-ext-auth\"")
  );
  generated_toml_validates(&rendered.toml);
}

#[test]
fn http_route_rewrite_and_redirect_render_exact_authority_and_location_fields() {
  let rewrite = HTTP_FIXTURE.replace(
    "  - matches:\n",
    "  - filters:\n    - type: URLRewrite\n      urlRewrite:\n        hostname: upstream.example.test\n        path:\n          type: ReplacePrefixMatch\n          replacePrefixMatch: /edge\n    matches:\n",
  );
  let rendered = translate_objects(&objects(&rewrite), &args()).expect("translate");
  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(
    rendered
      .toml
      .contains("authority = \"upstream.example.test\"")
  );
  assert!(rendered.toml.contains("path = \"/edge{path_suffix}\""));
  generated_toml_validates(&rendered.toml);

  let redirect = HTTP_FIXTURE
    .replace(
      "  - matches:\n",
      "  - filters:\n    - type: RequestRedirect\n      requestRedirect:\n        scheme: https\n        hostname: login.example.test\n        port: 8443\n        statusCode: 308\n        path:\n          type: ReplaceFullPath\n          replaceFullPath: /moved\n    matches:\n",
    )
    .replace(
      "    backendRefs:\n    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20\n",
      "",
    );
  let rendered = translate_objects(&objects(&redirect), &args()).expect("translate");
  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("status = 308"));
  assert!(rendered.toml.contains("scheme = \"https\""));
  assert!(rendered.toml.contains("hostname = \"login.example.test\""));
  assert!(rendered.toml.contains("port = 8443"));
  assert!(rendered.toml.contains("path = \"/moved\""));
  assert!(!rendered.toml.contains("location_template"));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn request_redirect_without_scheme_or_port_binds_the_gateway_listener_port() {
  let redirect = HTTP_FIXTURE
    .replace(
      "  - matches:\n",
      "  - filters:\n    - type: RequestRedirect\n      requestRedirect:\n        hostname: login.example.test\n    matches:\n",
    )
    .replace(
      "    backendRefs:\n    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20\n",
      "",
    );
  let rendered = translate_objects(&objects(&redirect), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("hostname = \"login.example.test\""));
  assert!(rendered.toml.contains("port = 443"));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn gateway_request_header_modifier_rejects_reserved_identity_headers() {
  let http = HTTP_FILTER_FIXTURE.replace("name: x-gateway-route", "name: Host");
  let rendered = translate_objects(&objects(&http), &args()).expect("translate");

  assert!(
    has_error_containing(&rendered, "cannot mutate header host"),
    "{:?}",
    rendered.diagnostics
  );
  assert!(!rendered.toml.contains("[[routes]]"));

  let grpc = GRPC_FIXTURE.replace("name: x-grpc-route", "name: X-Forwarded-For");
  let rendered = translate_objects(&objects(&grpc), &args()).expect("translate");

  assert!(
    has_error_containing(&rendered, "cannot mutate header x-forwarded-for"),
    "{:?}",
    rendered.diagnostics
  );
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn gateway_external_auth_rejects_identity_header_modifier_conflicts() {
  let raw = HTTP_FILTER_FIXTURE.replace("name: x-gateway-route", "name: x-auth-user");
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(
    has_error_containing(
      &rendered,
      "cannot mutate ExternalAuth identity header x-auth-user"
    ),
    "{:?}",
    rendered.diagnostics
  );
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn gateway_external_auth_rejects_framing_headers_even_when_operator_listed() {
  let raw = HTTP_FILTER_FIXTURE.replace(
    "          - x-auth-user\n          - www-authenticate",
    "          - content-length",
  );
  let mut args = args();
  args
    .external_auth_allowed_identity_headers
    .push("content-length".to_string());
  args
    .external_auth_allowed_terminal_headers
    .push("content-length".to_string());
  let rendered = translate_objects(&objects(&raw), &args).expect("translate");

  assert!(
    has_error_containing(&rendered, "contains forbidden header content-length"),
    "{:?}",
    rendered.diagnostics
  );
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn grpc_route_generates_service_method_route_and_shared_filters() {
  let rendered = translate_objects(&objects(GRPC_FIXTURE), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("name = \"gwapi-grpc-rpc-echo-0-0\""));
  assert!(rendered.toml.contains("path_prefix = \"/pkg.Echo/Say\""));
  assert!(
    rendered
      .toml
      .contains("[routes.match.path]\nexact = \"/pkg.Echo/Say\"")
  );
  assert!(rendered.toml.contains("methods = [\"POST\"]"));
  assert!(rendered.toml.contains("name = \"x-tenant\""));
  assert!(rendered.toml.contains("exact = \"acme\""));
  assert!(
    rendered
      .toml
      .contains("[[routes.actions.request_headers.add]]")
  );
  assert!(rendered.toml.contains("[[routes.actions.request_mirrors]]"));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn grpc_route_generates_weighted_multi_service_endpoint_slice_discoveries() {
  let raw = GRPC_FIXTURE.replace(
    "    - name: echo\n      namespace: default\n      port: 50051",
    "    - name: echo\n      namespace: default\n      port: 50051\n      weight: 75\n    - name: mirror\n      namespace: default\n      port: 50052\n      weight: 25",
  );
  let rendered = translate_objects(&objects(&raw), &endpoint_slice_args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert_eq!(
    rendered
      .toml
      .matches("[[upstream_pools.discovery]]")
      .count(),
    3,
    "the primary two-Service pool and one mirror pool must each retain discovery ownership"
  );
  assert!(rendered.toml.contains("weight_multiplier = 75"));
  assert!(rendered.toml.contains("weight_multiplier = 25"));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn grpc_external_auth_protocol_is_blocking_diagnostic() {
  let rendered =
    translate_objects(&objects(UNSUPPORTED_GRPC_EXTERNAL_AUTH), &args()).expect("translate");

  assert!(
    rendered.diagnostics.iter().any(
      |diagnostic| diagnostic.severity == DiagnosticSeverity::Error
        && diagnostic
          .message
          .contains("Gateway ExternalAuth protocol GRPC is unsupported")
    ),
    "{:?}",
    rendered.diagnostics
  );
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn oxibelt_route_policy_applies_bounded_waf_body_and_timeout_controls() {
  let route = HTTP_FIXTURE.replace(
    "  - matches:\n",
    "  - filters:\n    - type: ExtensionRef\n      extensionRef:\n        group: gateway.oxibelt.dev\n        kind: OxiBeltRoutePolicy\n        name: app-security\n    matches:\n",
  );
  let raw = format!(
    "{route}\n---\napiVersion: gateway.oxibelt.dev/v1alpha1\nkind: OxiBeltRoutePolicy\nmetadata:\n  name: app-security\n  namespace: default\nspec:\n  targetRef:\n    group: gateway.networking.k8s.io\n    kind: HTTPRoute\n    name: app\n  waf:\n    requestRuleGroups: [edge-baseline]\n  limits:\n    maxRequestBodyBytes: 1048576\n  timeouts:\n    upstreamRequestMilliseconds: 2500\n"
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
      .contains("# Policy: OxiBeltRoutePolicy/default/app-security")
  );
  assert!(rendered.toml.contains("max_request_body_bytes = 1048576"));
  assert!(rendered.toml.contains("upstream_request_timeout_ms = 2500"));
  assert!(rendered.toml.contains("groups = [\"edge-baseline\"]"));
  generated_toml_validates_with_waf_group(&rendered.toml, "edge-baseline");
}

#[test]
fn oxibelt_route_policy_is_fail_closed_for_caps_targets_and_missing_objects() {
  let route = HTTP_FIXTURE.replace(
    "  - matches:\n",
    "  - filters:\n    - type: ExtensionRef\n      extensionRef:\n        group: gateway.oxibelt.dev\n        kind: OxiBeltRoutePolicy\n        name: app-security\n    matches:\n",
  );
  let policy = "\n---\napiVersion: gateway.oxibelt.dev/v1alpha1\nkind: OxiBeltRoutePolicy\nmetadata:\n  name: app-security\n  namespace: default\nspec:\n  targetRef:\n    group: gateway.networking.k8s.io\n    kind: HTTPRoute\n    name: app\n  limits:\n    maxRequestBodyBytes: 10485761\n";
  let mut capped_args = args();
  capped_args.route_policy_max_request_body_bytes = 10_485_760;
  let rendered =
    translate_objects(&objects(&format!("{route}{policy}")), &capped_args).expect("translate");
  assert!(has_error_containing(&rendered, "exceeds the operator cap"));
  assert!(!rendered.toml.contains("[[routes]]"));

  let wrong_target = format!(
    "{route}{}",
    policy
      .replace("name: app\n  limits", "name: other\n  limits")
      .replace("10485761", "1024")
  );
  let rendered = translate_objects(&objects(&wrong_target), &args()).expect("translate");
  assert!(has_error_containing(&rendered, "targetRef does not select"));
  assert!(!rendered.toml.contains("[[routes]]"));

  let rendered = translate_objects(&objects(&route), &args()).expect("translate");
  assert!(has_error_containing(&rendered, "was not found"));
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn generated_http_toml_validates_with_oxibelt_config() {
  let rendered = translate_objects(&objects(HTTP_FIXTURE), &args()).expect("translate");
  generated_toml_validates(&rendered.toml);
}

#[test]
fn endpoint_slice_backend_resolution_generates_discovery_pool() {
  let raw = HTTP_FIXTURE.replace(
    "    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20",
    "    - name: app\n      port: 8080",
  );
  let rendered = translate_objects(&objects(&raw), &endpoint_slice_args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("[[upstream_pools.discovery]]"));
  assert!(rendered.toml.contains("provider = \"kubernetes\""));
  assert!(rendered.toml.contains("service = \"app\""));
  assert!(rendered.toml.contains("port_name = \"http\""));
  assert!(!rendered.toml.contains("port = 8080"));
  assert!(
    rendered
      .toml
      .contains("kubernetes_resource = \"endpoint_slice\"")
  );
  assert!(rendered.toml.contains("watch = true"));
  assert!(
    rendered
      .toml
      .contains("token_file = \"/var/run/secrets/kubernetes.io/serviceaccount/token\"")
  );
  assert!(!rendered.toml.contains("[[upstream_pools.servers]]"));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn endpoint_slice_backend_resolution_generates_weighted_multi_service_discoveries() {
  let rendered =
    translate_objects(&objects(HTTP_FIXTURE), &endpoint_slice_args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert_eq!(
    rendered
      .toml
      .matches("[[upstream_pools.discovery]]")
      .count(),
    2
  );
  assert!(rendered.toml.contains("service = \"app\""));
  assert!(rendered.toml.contains("service = \"canary\""));
  assert!(rendered.toml.contains("weight_multiplier = 80"));
  assert!(rendered.toml.contains("weight_multiplier = 20"));
  assert!(
    rendered
      .toml
      .contains("id = \"gwapi-http-default-app-0-0-backend-0-default-app\"")
  );
  assert!(
    rendered
      .toml
      .contains("id = \"gwapi-http-default-app-0-0-backend-1-default-canary\"")
  );
  assert!(!rendered.toml.contains("[[upstream_pools.servers]]"));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn backend_weight_is_parsed_strictly_instead_of_defaulting_invalid_values() {
  let raw = HTTP_FIXTURE.replace("weight: 80", "weight: invalid");
  let rendered = translate_objects(&objects(&raw), &endpoint_slice_args()).expect("translate");

  assert!(
    has_error_containing(
      &rendered,
      "backendRefs[0].weight must be an unsigned integer"
    ),
    "{:?}",
    rendered.diagnostics
  );
  assert!(!rendered.toml.contains("[[routes]]"));
  assert!(!rendered.toml.contains("[[upstream_pools.discovery]]"));
}

#[test]
fn endpoint_slice_backend_resolution_uses_numeric_target_port_for_unnamed_service_port() {
  let raw = HTTP_FIXTURE
    .replace(
      "  - name: http\n    port: 8080",
      "  - port: 80\n    targetPort: 8080",
    )
    .replace(
      "    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20",
      "    - name: app\n      port: 80",
    );
  let rendered = translate_objects(&objects(&raw), &endpoint_slice_args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("service = \"app\""));
  assert!(rendered.toml.contains("port = 8080"));
  assert!(!rendered.toml.contains("port_name = "));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn endpoint_slice_backend_resolution_prefers_port_name_when_target_port_differs() {
  let raw = HTTP_FIXTURE
    .replace(
      "  - name: http\n    port: 8080",
      "  - name: http\n    port: 80\n    targetPort: 8080",
    )
    .replace(
      "    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20",
      "    - name: app\n      port: 80",
    );
  let rendered = translate_objects(&objects(&raw), &endpoint_slice_args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert!(rendered.toml.contains("service = \"app\""));
  assert!(rendered.toml.contains("port_name = \"http\""));
  assert!(!rendered.toml.contains("port = 8080"));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn cluster_dns_backend_resolution_keeps_service_port_when_target_port_differs() {
  let raw = HTTP_FIXTURE
    .replace(
      "  - name: http\n    port: 8080",
      "  - name: http\n    port: 80\n    targetPort: 8080",
    )
    .replace(
      "    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20",
      "    - name: app\n      port: 80\n      weight: 80\n    - name: canary\n      port: 80\n      weight: 20",
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
      .contains("origin = \"http://app.default.svc.cluster.local:80\"")
  );
  assert!(
    rendered
      .toml
      .contains("origin = \"http://canary.default.svc.cluster.local:80\"")
  );
  assert!(!rendered.toml.contains("[[upstream_pools.discovery]]"));
  generated_toml_validates(&rendered.toml);
}

#[test]
fn endpoint_slice_backend_resolution_rejects_named_target_port_without_service_port_name() {
  let raw = HTTP_FIXTURE
    .replace(
      "  - name: http\n    port: 8080",
      "  - port: 80\n    targetPort: web",
    )
    .replace(
      "    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20",
      "    - name: app\n      port: 80",
    );
  let rendered = translate_objects(&objects(&raw), &endpoint_slice_args()).expect("translate");

  assert!(
    has_error_containing(
      &rendered,
      "EndpointSlice backend resolution requires unnamed Service ports to use numeric targetPort"
    ),
    "{:?}",
    rendered.diagnostics
  );
  assert!(!rendered.toml.contains("[[upstream_pools.discovery]]"));
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn equivalent_kubernetes_input_order_keeps_the_generated_content_digest_stable() {
  let objects = objects(HTTP_FIXTURE);
  let mut reordered = objects.clone();
  reordered.reverse();

  let first = translate_objects(&crate::rollout::canonicalize_objects(&objects), &args())
    .expect("canonical translation should succeed");
  let second = translate_objects(&crate::rollout::canonicalize_objects(&reordered), &args())
    .expect("reordered canonical translation should succeed");

  assert!(
    first.toml.contains("[[upstream_pools]]"),
    "canonical input must retain the Gateway-backed upstream pools"
  );
  assert!(
    first.toml.contains("[[routes]]"),
    "canonical input must retain the Gateway-backed routes"
  );
  assert_eq!(first.toml, second.toml);
  assert_eq!(
    crate::rollout::digest_content(first.toml.as_bytes()),
    crate::rollout::digest_content(second.toml.as_bytes()),
    "the immutable artifact content digest must not depend on Kubernetes list order"
  );
}

#[test]
fn explain_evidence_is_deterministic_bounded_and_redacts_secret_objects() {
  let mut snapshot = objects(HTTP_FIXTURE);
  snapshot.extend(objects(
    r#"
---
apiVersion: v1
kind: Secret
metadata: {name: controller-token, namespace: default, uid: secret-uid}
data: {token: dG9wLXNlY3JldA==}
"#,
  ));
  let mut reordered = snapshot.clone();
  reordered.reverse();

  let first = translate_objects(&snapshot, &endpoint_slice_args()).expect("translate");
  let second = translate_objects(&reordered, &endpoint_slice_args()).expect("translate");
  let first_json = serde_json::to_value(&first.explanation).expect("serialize explain");
  let second_json = serde_json::to_value(&second.explanation).expect("serialize explain");

  assert_eq!(first_json, second_json);
  assert_eq!(
    first_json["schemaVersion"],
    "gateway.oxibelt.dev/explain-v1alpha1"
  );
  assert_eq!(first_json["experimental"], true);
  assert_eq!(first_json["validation"]["valid"], true);
  assert_eq!(first_json["validation"]["requiresExactDataPlane"], true);
  assert!(
    first_json["artifactDigest"]
      .as_str()
      .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71)
  );
  let encoded = serde_json::to_string(&first_json).expect("encode explain");
  assert!(!encoded.contains("controller-token"));
  assert!(!encoded.contains("dG9wLXNlY3JldA"));
  assert!(encoded.contains("normalizedWeight"));

  let selected = first
    .explanation
    .clone()
    .select(Some("default/edge"), Some("default/app"))
    .expect("select explain evidence");
  let selected = serde_json::to_value(selected).expect("serialize selected explain");
  assert!(
    selected["sources"]
      .as_array()
      .is_some_and(|items| !items.is_empty())
  );
  assert!(
    selected["fragments"]
      .as_array()
      .is_some_and(|items| !items.is_empty())
  );
}

#[test]
fn backend_tls_policy_system_roots_sets_fixed_sni_and_https() {
  let raw = format!(
    "{}\n---\n{}",
    HTTP_FIXTURE,
    r#"apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata: {name: app-tls, namespace: default}
spec:
  targetRefs:
  - {group: "", kind: Service, name: app}
  validation:
    hostname: backend.example.test
    wellKnownCACertificates: System
"#
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(
    rendered
      .toml
      .contains("origin = \"https://app.default.svc.cluster.local:8080\"")
  );
  assert!(rendered.toml.contains("[upstream_pools.servers.tls]"));
  assert!(
    rendered
      .toml
      .contains("server_name = \"backend.example.test\"")
  );
  assert!(rendered.toml.contains("trust = \"system\""));
  assert!(rendered.assets.is_empty());
}

#[test]
fn backend_tls_policy_config_map_ca_is_content_addressed() {
  let raw = format!(
    "{}\n---\n{}",
    HTTP_FIXTURE,
    r#"apiVersion: v1
kind: ConfigMap
metadata: {name: app-ca, namespace: default}
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ZmFrZQ==
    -----END CERTIFICATE-----
---
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata: {name: app-tls, namespace: default}
spec:
  targetRefs:
  - {group: "", kind: Service, name: app}
  validation:
    hostname: backend.example.test
    caCertificateRefs:
    - {group: "", kind: ConfigMap, name: app-ca}
"#
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert_eq!(rendered.assets.len(), 1);
  let asset = &rendered.assets[0];
  assert!(asset.data_key.starts_with("gateway-api-ca-"));
  assert!(asset.managed_path.starts_with("gateway-api-ca/"));
  assert!(rendered.toml.contains("trust = \"exclusive\""));
  assert!(rendered.toml.contains(&asset.managed_path));
}

#[test]
fn backend_tls_policy_merges_multiple_ca_refs_and_enforces_exact_sans() {
  let raw = format!(
    "{}\n---\n{}",
    HTTP_FIXTURE,
    r#"apiVersion: v1
kind: ConfigMap
metadata: {name: app-ca-primary, namespace: default}
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    cHJpbWFyeQ==
    -----END CERTIFICATE-----
---
apiVersion: v1
kind: ConfigMap
metadata: {name: app-ca-rotation, namespace: default}
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    cm90YXRpb24=
    -----END CERTIFICATE-----
---
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata: {name: app-tls, namespace: default}
spec:
  targetRefs: [{group: "", kind: Service, name: app}]
  validation:
    hostname: backend.example.test
    caCertificateRefs:
    - {group: "", kind: ConfigMap, name: app-ca-rotation}
    - {group: "", kind: ConfigMap, name: app-ca-primary}
    subjectAltNames:
    - {type: URI, uri: "spiffe://cluster.example.test/ns/default/sa/app"}
    - {type: Hostname, hostname: "identity.example.test"}
"#
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert_eq!(rendered.assets.len(), 2);
  assert!(rendered.toml.contains(
    "subject_alt_names = [{ type = \"uri\", value = \"spiffe://cluster.example.test/ns/default/sa/app\" }, { type = \"dns\", value = \"identity.example.test\" }]"
  ));
  let mut paths = rendered
    .assets
    .iter()
    .map(|asset| asset.managed_path.as_str())
    .collect::<Vec<_>>();
  paths.sort();
  assert!(
    rendered.toml.find(paths[0]).expect("first path")
      < rendered.toml.find(paths[1]).expect("second path")
  );
}

#[test]
fn backend_tls_policy_rejects_ambiguous_or_unsupported_sans() {
  let raw = format!(
    "{}\n---\n{}",
    HTTP_FIXTURE,
    r#"apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata: {name: app-tls, namespace: default}
spec:
  targetRefs: [{group: "", kind: Service, name: app}]
  validation:
    hostname: backend.example.test
    wellKnownCACertificates: System
    subjectAltNames:
    - {type: Hostname, hostname: "*.example.test"}
"#
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");
  assert!(has_error_containing(&rendered, "without wildcards"));
  assert!(!rendered.toml.contains("[[routes]]"));
}

#[test]
fn conflicting_backend_tls_policies_fail_closed_without_shipping_unused_ca() {
  let raw = format!(
    "{}\n---\n{}",
    HTTP_FIXTURE,
    r#"apiVersion: v1
kind: ConfigMap
metadata: {name: app-ca, namespace: default}
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ZmFrZQ==
    -----END CERTIFICATE-----
---
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: first
  namespace: default
  creationTimestamp: "2026-01-01T00:00:00Z"
spec:
  targetRefs: [{group: "", kind: Service, name: app}]
  validation:
    hostname: first.example.test
    caCertificateRefs: [{group: "", kind: ConfigMap, name: app-ca}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata:
  name: second
  namespace: default
  creationTimestamp: "2026-01-02T00:00:00Z"
spec:
  targetRefs: [{group: "", kind: Service, name: app}]
  validation:
    hostname: second.example.test
    wellKnownCACertificates: System
"#
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate");

  assert!(has_error_containing(&rendered, "Conflicted"));
  assert!(!rendered.toml.contains("[[routes]]"));
  assert!(rendered.assets.is_empty());
}

fn generated_toml_validates(rendered_toml: &str) {
  let temp_dir = common::TempDir::new("gateway-api-generated-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "gateway-api-generated-config");
  let raw = format!(
    "{}\n[runtime.hardening.seccomp]\nexpectation = \"required\"\n{}",
    common::minimal_config_toml(&cert_path, &key_path),
    rendered_toml
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config.validate().expect("generated config should validate");
}

fn generated_toml_validates_with_waf_group(rendered_toml: &str, group: &str) {
  let temp_dir = common::TempDir::new("gateway-api-generated-policy-config");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "gateway-api-generated-policy-config");
  let raw = format!(
    "{}\n[runtime.hardening.seccomp]\nexpectation = \"required\"\n[[waf.rule_groups]]\nname = {:?}\nphase = \"request\"\nwhen = \"true\"\n[[waf.rule_groups.actions]]\ntype = \"set_tag\"\nkey = \"gateway-route-policy\"\nvalue = \"applied\"\n{}",
    common::minimal_config_toml(&cert_path, &key_path),
    group,
    rendered_toml
  );

  let config: Config = toml::from_str(&raw).expect("config should parse");
  config
    .validate()
    .expect("generated policy config should validate");
}

fn generated_toml_parses(rendered_toml: &str) {
  toml::from_str::<toml::Value>(rendered_toml).expect("generated TOML should parse");
}
