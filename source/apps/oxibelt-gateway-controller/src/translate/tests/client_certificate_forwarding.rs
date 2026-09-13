use super::{
  GRPC_FIXTURE, HTTP_FILTER_FIXTURE, HTTP_FIXTURE, args, generated_toml_validates,
  has_error_containing, objects, translate_objects,
};

fn policy(kind: &str, name: &str, forwarding: &str) -> String {
  format!(
    "\n---\napiVersion: gateway.oxibelt.dev/v1alpha1\nkind: OxiBeltRoutePolicy\nmetadata: {{name: client-cert, namespace: default}}\nspec:\n  targetRef: {{group: gateway.networking.k8s.io, kind: {kind}, name: {name}}}\n  clientCertificateForwarding:\n{forwarding}\n"
  )
}

fn extension_ref() -> &'static str {
  "  - filters:\n    - type: ExtensionRef\n      extensionRef:\n        group: gateway.oxibelt.dev\n        kind: OxiBeltRoutePolicy\n        name: client-cert\n    matches:\n"
}

#[test]
fn http_and_grpc_route_policies_render_admitted_verified_client_leaf_forwarding() {
  let http = HTTP_FIXTURE.replace("  - matches:\n", extension_ref());
  let grpc = GRPC_FIXTURE.replace(
    "    filters:\n",
    "    filters:\n    - type: ExtensionRef\n      extensionRef:\n        group: gateway.oxibelt.dev\n        kind: OxiBeltRoutePolicy\n        name: client-cert\n",
  );
  let mut policy_args = args();
  policy_args.client_certificate_forward_allowed_headers =
    vec!["X-Verified-Client-Cert".to_string()];

  let http = translate_objects(
    &objects(&format!(
      "{http}{}",
      policy("HTTPRoute", "app", "    header: X-Verified-Client-Cert")
    )),
    &policy_args,
  )
  .expect("translate HTTPRoute");
  assert!(http.toml.contains("[routes.client_certificate_forwarding]"));
  assert!(http.toml.contains("header = \"x-verified-client-cert\""));
  assert!(http.toml.contains("format = \"url_encoded_pem\""));

  let grpc = translate_objects(
    &objects(&format!(
      "{grpc}{}",
      policy(
        "GRPCRoute",
        "echo",
        "    header: x-verified-client-cert\n    format: rfc9440",
      )
      .replacen("namespace: default", "namespace: rpc", 1)
    )),
    &policy_args,
  )
  .expect("translate GRPCRoute");
  assert!(grpc.toml.contains("header = \"x-verified-client-cert\""));
  assert!(grpc.toml.contains("format = \"rfc9440\""));
}

#[test]
fn forwarding_and_external_auth_render_as_native_route_siblings() {
  let route = HTTP_FILTER_FIXTURE.replace(
    "    filters:\n",
    "    filters:\n    - type: ExtensionRef\n      extensionRef:\n        group: gateway.oxibelt.dev\n        kind: OxiBeltRoutePolicy\n        name: client-cert\n",
  );
  let mut policy_args = args();
  policy_args.client_certificate_forward_allowed_headers =
    vec!["x-verified-client-cert".to_string()];
  let rendered = translate_objects(
    &objects(&format!(
      "{route}{}",
      policy("HTTPRoute", "app", "    header: x-verified-client-cert")
    )),
    &policy_args,
  )
  .expect("translate forwarding plus external auth");
  assert!(
    rendered
      .toml
      .contains("external_auth = \"gwapi-http-default-app-0-0-ext-auth\"")
  );
  assert!(
    rendered
      .toml
      .contains("[routes.client_certificate_forwarding]")
  );
  generated_toml_validates(&rendered.toml);
}

#[test]
fn client_certificate_forwarding_requires_operator_admission_and_safe_header_syntax() {
  let route = HTTP_FIXTURE.replace("  - matches:\n", extension_ref());
  let unadmitted = translate_objects(
    &objects(&format!(
      "{route}{}",
      policy("HTTPRoute", "app", "    header: x-verified-client-cert")
    )),
    &args(),
  )
  .expect("translate denied policy");
  assert!(has_error_containing(
    &unadmitted,
    "not admitted by operator policy"
  ));
  assert!(unadmitted.toml.contains("[routes.actions.direct_response]"));
  assert!(
    !unadmitted
      .toml
      .contains("[routes.client_certificate_forwarding]")
  );
  assert!(!unadmitted.toml.contains("[[upstream_pools]]"));

  let malformed = translate_objects(
    &objects(&format!(
      "{route}{}",
      policy("HTTPRoute", "app", "    header: bad header")
    )),
    &args(),
  )
  .expect("translate malformed policy");
  assert!(has_error_containing(&malformed, "header is invalid"));

  let wrong_format_type = translate_objects(
    &objects(&format!(
      "{route}{}",
      policy(
        "HTTPRoute",
        "app",
        "    header: x-client-cert\n    format: false"
      )
    )),
    &args(),
  )
  .expect("translate malformed format type");
  assert!(has_error_containing(
    &wrong_format_type,
    "format must be a string"
  ));

  let client_cert = translate_objects(
    &objects(&format!(
      "{route}{}",
      policy("HTTPRoute", "app", "    header: client-cert")
    )),
    &args(),
  )
  .expect("translate incompatible client-cert policy");
  assert!(has_error_containing(
    &client_cert,
    "client-cert requires format rfc9440"
  ));

  for header in ["Accept-Encoding", "early-data", "traceparent", "priority"] {
    let reserved = translate_objects(
      &objects(&format!(
        "{route}{}",
        policy("HTTPRoute", "app", &format!("    header: {header}"))
      )),
      &args(),
    )
    .expect("translate reserved forwarding header");
    assert!(has_error_containing(
      &reserved,
      &format!(
        "spec.clientCertificateForwarding.header {} is reserved",
        header.to_ascii_lowercase()
      )
    ));
  }
}

#[test]
fn forwarding_headers_are_reserved_across_route_filters_and_external_auth() {
  let route = HTTP_FIXTURE.replace(
    "  - matches:\n",
    "  - filters:\n    - type: ExtensionRef\n      extensionRef:\n        group: gateway.oxibelt.dev\n        kind: OxiBeltRoutePolicy\n        name: client-cert\n    - type: RequestHeaderModifier\n      requestHeaderModifier:\n        remove: [x-verified-client-cert]\n    matches:\n",
  );
  let raw = format!(
    "{route}{}",
    policy("HTTPRoute", "app", "    header: x-verified-client-cert")
  );
  let mut policy_args = args();
  policy_args.client_certificate_forward_allowed_headers =
    vec!["x-verified-client-cert".to_string()];
  let rendered = translate_objects(&objects(&raw), &policy_args).expect("translate conflict");
  assert!(has_error_containing(
    &rendered,
    "cannot mutate or expose client certificate forwarding header x-verified-client-cert"
  ));
  assert!(rendered.disposition.is_publishable());
}

#[test]
fn forwarding_with_request_redirect_fails_closed_as_a_direct_response() {
  let route = HTTP_FIXTURE
    .replace(
      "  - matches:\n",
      "  - filters:\n    - type: ExtensionRef\n      extensionRef:\n        group: gateway.oxibelt.dev\n        kind: OxiBeltRoutePolicy\n        name: client-cert\n    - type: RequestRedirect\n      requestRedirect:\n        hostname: login.example.test\n    matches:\n",
    )
    .replace(
      "    backendRefs:\n    - name: app\n      port: 8080\n      weight: 80\n    - name: canary\n      port: 8080\n      weight: 20\n",
      "",
    );
  let mut policy_args = args();
  policy_args.client_certificate_forward_allowed_headers =
    vec!["x-verified-client-cert".to_string()];
  let rendered = translate_objects(
    &objects(&format!(
      "{route}{}",
      policy("HTTPRoute", "app", "    header: x-verified-client-cert")
    )),
    &policy_args,
  )
  .expect("translate forwarding redirect conflict");
  assert!(has_error_containing(
    &rendered,
    "RequestRedirect cannot be combined with client certificate forwarding"
  ));
  assert!(
    rendered
      .toml
      .contains("[routes.actions.direct_response]\nstatus = 503")
  );
  assert!(
    !rendered
      .toml
      .contains("[routes.client_certificate_forwarding]")
  );
  assert!(!rendered.toml.contains("login.example.test"));
}

#[test]
fn rfc9440_names_are_reserved_across_routes_and_external_auth() {
  let forwarding = HTTP_FIXTURE.replace("  - matches:\n", extension_ref());
  let conflicting_route = HTTP_FILTER_FIXTURE
    .replace("name: app\n", "name: auth-app\n")
    .replace("    filters:\n", "    filters:\n    - type: RequestHeaderModifier\n      requestHeaderModifier:\n        set:\n        - name: Client-Cert\n          value: forged\n");
  let external_auth_conflict = HTTP_FILTER_FIXTURE
    .replace("name: app\n", "name: external-auth-app\n")
    .replace("- authorization", "- client-cert");
  let raw = format!(
    "{forwarding}{}\n---\n{conflicting_route}\n---\n{external_auth_conflict}",
    policy("HTTPRoute", "app", "    header: x-verified-client-cert")
  );
  let mut policy_args = args();
  policy_args.client_certificate_forward_allowed_headers =
    vec!["x-verified-client-cert".to_string()];
  policy_args
    .external_auth_allowed_request_headers
    .push("client-cert".to_string());
  let rendered = translate_objects(&objects(&raw), &policy_args).expect("translate conflicts");
  assert_eq!(
    rendered
      .diagnostics
      .iter()
      .filter(|diagnostic| {
        diagnostic
          .message
          .contains("cannot mutate or expose client certificate forwarding header client-cert")
      })
      .count(),
    2
  );
  assert!(rendered.disposition.is_publishable());
}
