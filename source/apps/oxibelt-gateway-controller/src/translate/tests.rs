use pretty_assertions::assert_eq;
use serde_json::Value;

use super::{RenderedConfig, TranslationDisposition, translate_objects};
use crate::cli::{SharedArgs, SourceSecretAllowlistEntry};
use crate::model::{DiagnosticSeverity, KubernetesObject};
use oxibelt::config::Config;
use oxibelt::routes::RouteTable;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/rust/common/mod.rs"
  ));
}

#[path = "tests/backend_diagnostics.rs"]
mod backend_diagnostic_tests;
#[path = "tests/external_auth.rs"]
mod external_auth_tests;
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
    upstream_client_tls_source_secrets: Vec::new(),
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

fn base64_encode(bytes: &[u8]) -> String {
  const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
  for chunk in bytes.chunks(3) {
    let first = chunk[0];
    let second = chunk.get(1).copied().unwrap_or(0);
    let third = chunk.get(2).copied().unwrap_or(0);
    encoded.push(ALPHABET[(first >> 2) as usize] as char);
    encoded.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
    encoded.push(if chunk.len() > 1 {
      ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char
    } else {
      '='
    });
    encoded.push(if chunk.len() > 2 {
      ALPHABET[(third & 0x3f) as usize] as char
    } else {
      '='
    });
  }
  encoded
}

#[test]
fn http_route_generates_weighted_pool_and_route() {
  let rendered = translate_objects(&objects(HTTP_FIXTURE), &args()).expect("translate");

  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert_eq!(rendered.disposition, TranslationDisposition::Clean);
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
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(
    rendered
      .toml
      .contains("[routes.actions.direct_response]\nstatus = 503")
  );
  assert!(!rendered.toml.contains("[[upstream_pools]]"));
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
fn tls_route_dependency_failures_preserve_last_good_without_sni_tombstones() {
  let raw = TLS_FIXTURE.replace(
    "name: db\n  namespace: default\nspec:\n  ports:",
    "name: other\n  namespace: default\nspec:\n  ports:",
  );
  let rendered = translate_objects(&objects(&raw), &args()).expect("translate missing TLS backend");

  assert!(has_error_containing(
    &rendered,
    "backend Service default/db was not found"
  ));
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::PreserveLastGood
  );
  assert!(!rendered.toml.contains("[[sni_forward.rules]]"));
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

  let invalid_identity = raw.replace(
    "  gatewayClassName: oxibelt",
    "  gatewayClassName: oxibelt\n  tls:\n    backend:\n      clientCertificateRef: {name: gateway-client}",
  );
  let tombstone =
    translate_objects(&objects(&invalid_identity), &args()).expect("translate policy tombstone");
  assert_eq!(
    tombstone.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(
    tombstone
      .toml
      .contains("[routes.actions.direct_response]\nstatus = 503")
  );
  assert!(!tombstone.toml.contains("# Policy:"));
  assert!(!tombstone.toml.contains("max_request_body_bytes"));
  assert!(!tombstone.toml.contains("upstream_request_timeout_ms"));
  assert!(!tombstone.toml.contains("[routes.waf.request]"));
  generated_toml_validates(&tombstone.toml);
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
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(rendered.toml.contains("status = 503"));

  let wrong_target = format!(
    "{route}{}",
    policy
      .replace("name: app\n  limits", "name: other\n  limits")
      .replace("10485761", "1024")
  );
  let rendered = translate_objects(&objects(&wrong_target), &args()).expect("translate");
  assert!(has_error_containing(&rendered, "targetRef does not select"));
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(rendered.toml.contains("status = 503"));

  let rendered = translate_objects(&objects(&route), &args()).expect("translate");
  assert!(has_error_containing(&rendered, "was not found"));
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(rendered.toml.contains("status = 503"));

  let ambiguous_policy = format!(
    "{route}{}",
    policy.replace("group: gateway.networking.k8s.io", "group: 7")
  );
  let rendered = translate_objects(&objects(&ambiguous_policy), &args()).expect("translate");
  assert!(has_error_containing(&rendered, "targetRef.group"));
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::PreserveLastGood
  );
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
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(rendered.toml.contains("status = 503"));
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
fn gateway_client_certificate_is_validated_and_rendered_only_for_tls_backends() {
  let temp_dir = common::TempDir::new("gateway-api-upstream-client");
  let (certificate_path, private_key_path) =
    common::create_self_signed_cert(temp_dir.path(), "gateway-client.example.test");
  let certificate = base64_encode(&std::fs::read(certificate_path).expect("certificate"));
  let private_key = base64_encode(&std::fs::read(private_key_path).expect("private key"));
  let gateway = HTTP_FIXTURE
    .replace(
      "  gatewayClassName: oxibelt",
      "  gatewayClassName: oxibelt\n  tls:\n    backend:\n      clientCertificateRef: {name: gateway-client}",
    )
    .replace(
      "    - name: canary\n      port: 8080\n      weight: 20\n",
      "",
    );
  let raw = format!(
    "{gateway}\n---\napiVersion: v1\nkind: Secret\nmetadata: {{name: gateway-client, namespace: default, uid: source-uid, resourceVersion: \"17\"}}\ntype: kubernetes.io/tls\ndata:\n  tls.crt: {certificate}\n  tls.key: {private_key}\n---\napiVersion: gateway.networking.k8s.io/v1\nkind: BackendTLSPolicy\nmetadata: {{name: app-tls, namespace: default}}\nspec:\n  targetRefs: [{{group: \"\", kind: Service, name: app}}]\n  validation:\n    hostname: backend.example.test\n    wellKnownCACertificates: System\n"
  );
  let mut allowed_args = args();
  allowed_args
    .upstream_client_tls_source_secrets
    .push(SourceSecretAllowlistEntry {
      namespace: "default".to_string(),
      name: "gateway-client".to_string(),
      certificate_key: "tls.crt".to_string(),
      private_key_key: "tls.key".to_string(),
    });

  let rendered = translate_objects(&objects(&raw), &allowed_args).expect("translate");
  assert!(
    rendered.diagnostics.is_empty(),
    "{:?}",
    rendered.diagnostics
  );
  assert_eq!(rendered.client_identities.len(), 1);
  let identity = &rendered.client_identities[0];
  assert!(
    rendered
      .toml
      .contains("[upstream_pools.servers.tls.client_identity]")
  );
  assert!(
    rendered
      .toml
      .contains(&format!("cert_chain = \"{}\"", identity.cert_chain_path()))
  );
  assert!(rendered.toml.contains(&format!(
    "private_key = \"{}\"",
    identity.private_key_path()
  )));
  assert!(!rendered.toml.contains(&private_key));
  assert!(!format!("{identity:?}").contains(&private_key));

  let denied = translate_objects(&objects(&raw), &args()).expect("translate denied source");
  assert!(has_error_containing(
    &denied,
    "operator source Secret allowlist"
  ));
  assert_eq!(
    denied.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(denied.client_identities.is_empty());
  assert!(denied.toml.contains("[[routes]]"));
  assert!(
    denied
      .toml
      .contains("[routes.actions.direct_response]\nstatus = 503")
  );
  assert!(denied.toml.contains("hosts = [\"api.example.com\"]"));
  assert!(denied.toml.contains("path_prefix = \"/api\""));
  assert!(denied.toml.contains("methods = [\"GET\"]"));
  assert!(!denied.toml.contains("upstream_pool ="));
  assert!(!denied.toml.contains("client_identity"));
  assert!(denied.requires_exact_data_plane);
  generated_toml_validates(&denied.toml);

  let methodless = translate_objects(&objects(&raw.replace("      method: GET\n", "")), &args())
    .expect("translate methodless denied source");
  let route_table_temp = common::TempDir::new("gateway-api-tombstone-routing");
  let (route_table_cert, route_table_key) =
    common::create_self_signed_cert(route_table_temp.path(), "gateway-api-tombstone-routing");
  let route_table_raw = format!(
    "{}\n[runtime.hardening.seccomp]\nexpectation = \"required\"\n{}",
    common::minimal_config_toml(&route_table_cert, &route_table_key)
      .replace("hosts = [\"example.com\"]", "hosts = [\"api.example.com\"]"),
    methodless.toml
  );
  let route_table_config: Config =
    toml::from_str(&route_table_raw).expect("tombstone routing config should parse");
  route_table_config
    .validate()
    .expect("tombstone routing config should validate");
  let route_table = RouteTable::new(&route_table_config);
  let narrow = route_table
    .resolve(
      "api.example.com",
      "/api/private",
      &route_table_config.upstreams,
    )
    .expect("narrow tombstone should resolve");
  assert_eq!(narrow.route.name, "gwapi-http-default-app-0-0");
  assert_eq!(
    narrow
      .route
      .actions
      .direct_response
      .as_ref()
      .map(|action| action.status),
    Some(503)
  );
  let broad = route_table
    .resolve("api.example.com", "/public", &route_table_config.upstreams)
    .expect("broad fallback should remain available outside the narrow match");
  assert_eq!(broad.route.name, "app-root");

  let detailed_raw = raw.replace(
    "    - path:\n        type: PathPrefix\n        value: /api\n      method: GET",
    "    - path:\n        type: Exact\n        value: /api/admin\n      method: POST\n      headers:\n      - name: x-tenant\n        value: acme\n      queryParams:\n      - name: mode\n        value: admin",
  );
  let detailed =
    translate_objects(&objects(&detailed_raw), &args()).expect("translate detailed tombstone");
  assert_eq!(
    detailed.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(detailed.toml.contains("path_prefix = \"/api/admin\""));
  assert!(
    detailed
      .toml
      .contains("[routes.match.path]\nexact = \"/api/admin\"")
  );
  assert!(detailed.toml.contains("methods = [\"POST\"]"));
  assert!(detailed.toml.contains("priority = 10000"));
  assert!(detailed.toml.contains("name = \"x-tenant\""));
  assert!(detailed.toml.contains("exact = \"acme\""));
  assert!(detailed.toml.contains("name = \"mode\""));
  assert!(detailed.toml.contains("exact = \"admin\""));
  generated_toml_validates(&detailed.toml);

  let mixed_raw = format!(
    "{raw}\n---\napiVersion: gateway.networking.k8s.io/v1\nkind: BackendTLSPolicy\nmetadata: {{name: conflicting-app-tls, namespace: default}}\nspec:\n  targetRefs: [{{group: \"\", kind: Service, name: app}}]\n  validation:\n    hostname: conflicting-backend.example.test\n    wellKnownCACertificates: System\n"
  );
  let mixed = translate_objects(&objects(&mixed_raw), &args()).expect("translate mixed errors");
  assert!(has_error_containing(
    &mixed,
    "operator source Secret allowlist"
  ));
  assert!(has_error_containing(&mixed, "Conflicted"));
  assert_eq!(
    mixed.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(mixed.disposition.is_publishable());
  assert!(mixed.client_identities.is_empty());
  assert!(mixed.toml.contains("status = 503"));

  let malformed_match = translate_objects(
    &objects(&raw.replace("type: PathPrefix", "type: RegularExpression")),
    &args(),
  )
  .expect("translate invalid identity with malformed match");
  assert!(has_error_containing(
    &malformed_match,
    "RegularExpression path matches are unsupported in v1"
  ));
  assert_eq!(
    malformed_match.disposition,
    TranslationDisposition::PreserveLastGood
  );
  assert!(!malformed_match.disposition.is_publishable());
  assert!(!malformed_match.toml.contains("[[routes]]"));

  let mismatched = translate_objects(
    &objects(&raw.replace(&private_key, &certificate)),
    &allowed_args,
  )
  .expect("translate mismatched key");
  assert_eq!(
    mismatched.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(mismatched.client_identities.is_empty());
  assert!(
    mismatched
      .toml
      .contains("[routes.actions.direct_response]\nstatus = 503")
  );
  assert!(!mismatched.toml.contains("upstream_pool ="));
  generated_toml_validates(&mismatched.toml);

  let conflicting_raw = raw.replace(
    "  parentRefs:\n  - name: edge\n    sectionName: https",
    "  parentRefs:\n  - name: edge\n    sectionName: https\n  - name: edge-two\n    sectionName: https",
  );
  let conflicting_raw = format!(
    "{conflicting_raw}\n---\napiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\nmetadata: {{name: edge-two, namespace: default}}\nspec:\n  gatewayClassName: oxibelt\n  tls:\n    backend:\n      clientCertificateRef: {{name: gateway-client-two}}\n  listeners:\n  - name: https\n    protocol: HTTPS\n    port: 443\n    hostname: api.example.com\n---\napiVersion: v1\nkind: Secret\nmetadata: {{name: gateway-client-two, namespace: default, uid: source-uid-two, resourceVersion: \"17\"}}\ntype: kubernetes.io/tls\ndata:\n  tls.crt: {certificate}\n  tls.key: {private_key}\n"
  );
  allowed_args
    .upstream_client_tls_source_secrets
    .push(SourceSecretAllowlistEntry {
      namespace: "default".to_string(),
      name: "gateway-client-two".to_string(),
      certificate_key: "tls.crt".to_string(),
      private_key_key: "tls.key".to_string(),
    });
  let conflicted =
    translate_objects(&objects(&conflicting_raw), &allowed_args).expect("translate conflict");
  assert_eq!(
    conflicted.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(has_error_containing(
    &conflicted,
    "Gateways select different backend client identities"
  ));
  assert!(conflicted.client_identities.is_empty());
  assert_eq!(conflicted.toml.matches("[[routes]]").count(), 1);
  assert!(
    conflicted
      .toml
      .contains("[routes.actions.direct_response]\nstatus = 503")
  );
  assert!(!conflicted.toml.contains("upstream_pool ="));
  generated_toml_validates(&conflicted.toml);
}

#[test]
fn invalid_gateway_client_certificate_generates_match_equivalent_grpc_tombstone() {
  let raw = GRPC_FIXTURE.replace(
    "  gatewayClassName: oxibelt",
    "  gatewayClassName: oxibelt\n  tls:\n    backend:\n      clientCertificateRef: {name: gateway-client}",
  );

  let rendered = translate_objects(&objects(&raw), &args()).expect("translate gRPC tombstone");

  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(rendered.requires_exact_data_plane);
  assert!(
    rendered
      .toml
      .contains("[routes.actions.direct_response]\nstatus = 503")
  );
  assert!(rendered.toml.contains("path_prefix = \"/pkg.Echo/Say\""));
  assert!(rendered.toml.contains("exact = \"/pkg.Echo/Say\""));
  assert!(rendered.toml.contains("methods = [\"POST\"]"));
  assert!(rendered.toml.contains("name = \"x-tenant\""));
  assert!(rendered.toml.contains("exact = \"acme\""));
  assert!(!rendered.toml.contains("upstream_pool ="));
  assert!(!rendered.toml.contains("[routes.actions.request_headers]"));
  assert!(!rendered.toml.contains("request_mirrors"));
  assert!(rendered.client_identities.is_empty());
  generated_toml_validates(&rendered.toml);
}

#[test]
fn client_identity_tombstone_name_collisions_preserve_last_good() {
  let invalid_gateway_tls = "  gatewayClassName: oxibelt\n  tls:\n    backend:\n      clientCertificateRef: {name: gateway-client}";
  let http = HTTP_FIXTURE
    .replace("  gatewayClassName: oxibelt", invalid_gateway_tls)
    .replace(
      "kind: HTTPRoute\nmetadata:\n  name: app\n  namespace: default",
      "kind: HTTPRoute\nmetadata:\n  name: foo--bar\n  namespace: default",
    );
  let http = format!(
    "{http}\n---\n{}",
    r#"apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: foo-bar
  namespace: default
spec:
  parentRefs:
  - name: edge
    sectionName: https
  hostnames:
  - api.example.com
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /other
      method: GET
    backendRefs:
    - name: app
      port: 8080
"#
  );
  let rendered = translate_objects(&objects(&http), &args()).expect("translate HTTP collision");
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::PreserveLastGood
  );
  assert!(!rendered.disposition.is_publishable());
  assert!(has_error_containing(
    &rendered,
    "fail-closed tombstone name `gwapi-http-default-foo-bar-0-0` collides with a distinct route"
  ));

  let grpc = GRPC_FIXTURE
    .replace("  gatewayClassName: oxibelt", invalid_gateway_tls)
    .replace(
      "kind: GRPCRoute\nmetadata:\n  name: echo\n  namespace: rpc",
      "kind: GRPCRoute\nmetadata:\n  name: echo--route\n  namespace: rpc",
    );
  let grpc = format!(
    "{grpc}\n---\n{}",
    r#"apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: echo-route
  namespace: rpc
spec:
  parentRefs:
  - name: edge
    namespace: default
  rules:
  - matches:
    - method:
        service: pkg.Echo
        method: Other
    backendRefs:
    - name: echo
      namespace: default
      port: 50051
"#
  );
  let rendered = translate_objects(&objects(&grpc), &args()).expect("translate gRPC collision");
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::PreserveLastGood
  );
  assert!(!rendered.disposition.is_publishable());
  assert!(has_error_containing(
    &rendered,
    "fail-closed tombstone name `gwapi-grpc-rpc-echo-route-0-0` collides with a distinct route"
  ));
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
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(rendered.toml.contains("status = 503"));
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
  assert_eq!(
    rendered.disposition,
    TranslationDisposition::FailClosedDeprogram
  );
  assert!(rendered.toml.contains("status = 503"));
  assert!(!rendered.toml.contains("[[upstream_pools]]"));
  assert!(rendered.assets.is_empty());
}

#[test]
fn malformed_backend_tls_target_types_preserve_last_good() {
  for target_ref in [
    "{group: 7, kind: Service, name: app}",
    "{group: \"\", kind: 7, name: app}",
  ] {
    let raw = format!(
      "{}\n---\napiVersion: gateway.networking.k8s.io/v1\nkind: BackendTLSPolicy\nmetadata: {{name: app-tls, namespace: default}}\nspec:\n  targetRefs: [{target_ref}]\n  validation:\n    hostname: backend.example.test\n    wellKnownCACertificates: System\n",
      HTTP_FIXTURE
    );
    let rendered = translate_objects(&objects(&raw), &args()).expect("translate malformed target");

    assert_eq!(
      rendered.disposition,
      TranslationDisposition::PreserveLastGood
    );
    assert!(!rendered.disposition.is_publishable());
    assert!(!rendered.toml.contains("status = 503"));
    assert!(has_error_containing(&rendered, "must be a string"));
  }
}

#[test]
fn fail_closed_route_tombstone_drops_now_unreachable_backend_tls_ca_assets() {
  let fixture = HTTP_FIXTURE.replacen(
    "  name: canary\n  namespace: default\nspec:\n  ports:",
    "  name: unreferenced-canary\n  namespace: default\nspec:\n  ports:",
    1,
  );
  let raw = format!(
    "{fixture}\n---\n{}",
    r#"apiVersion: v1
kind: ConfigMap
metadata: {name: app-ca, namespace: default}
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    ZmFrZQ==
    -----END CERTIFICATE-----
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: app-v4
  namespace: default
  labels: {kubernetes.io/service-name: app}
addressType: IPv4
ports: [{name: http, port: 8080, protocol: TCP}]
endpoints: [{addresses: [10.0.0.8], conditions: {ready: true}}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: BackendTLSPolicy
metadata: {name: app-tls, namespace: default}
spec:
  targetRefs: [{group: "", kind: Service, name: app}]
  validation:
    hostname: backend.example.test
    caCertificateRefs: [{group: "", kind: ConfigMap, name: app-ca}]
"#
  );

  for resolution_args in [args(), endpoint_slice_args()] {
    let rendered =
      translate_objects(&objects(&raw), &resolution_args).expect("translate failed backend");
    assert_eq!(
      rendered.disposition,
      TranslationDisposition::FailClosedDeprogram
    );
    assert!(rendered.toml.contains("status = 503"));
    assert!(!rendered.toml.contains("[[upstream_pools]]"));
    assert!(rendered.assets.is_empty());
  }
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
