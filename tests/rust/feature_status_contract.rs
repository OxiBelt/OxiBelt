use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use oxibelt::config::{
  CRLITE_COVERAGE_POLICY_WIRE_VALUES, CRLITE_FAILURE_POLICY_WIRE_VALUES, CRLITE_MODE_WIRE_VALUES,
  HTTP_POOL_LOAD_BALANCING_ALGORITHM_WIRE_VALUES, OCSP_MODE_WIRE_VALUES,
  OUTBOUND_OCSP_MODE_WIRE_VALUES, SNI_FORWARD_CLIENT_HELLO_PARSE_METHOD_WIRE_VALUES,
  SNI_FORWARD_PROTOCOL_WIRE_VALUES, STICKY_COOKIE_FALLBACK_ALGORITHM_WIRE_VALUES,
  UPSTREAM_DISCOVERY_PROVIDER_WIRE_VALUES, UPSTREAM_POOL_SERVER_STATE_WIRE_VALUES,
};
use oxibelt::server::{
  ADMIN_CAPABILITY_FEATURE_KEYS, ADMIN_OPERATION_KIND_WIRE_VALUES,
  ADMIN_OPERATION_STATE_WIRE_VALUES,
};
use serde_json::Value;

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source crate should live under the repository root")
    .to_path_buf()
}

fn read_repo_file(path: &str) -> String {
  fs::read_to_string(repo_root().join(path))
    .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
}

fn openapi() -> Value {
  serde_json::from_str(&read_repo_file("source/assets/admin-openapi.json"))
    .expect("Admin OpenAPI document should parse as JSON")
}

#[test]
fn feature_matrix_uses_known_lifecycle_statuses_and_required_ids() {
  let statuses = feature_statuses();
  let allowed_statuses = string_set(&["supported", "experimental", "reserved", "removed"]);
  for (feature_id, status) in &statuses {
    assert!(
      allowed_statuses.contains(status),
      "{feature_id} uses unsupported lifecycle status {status}"
    );
  }

  for (feature_id, expected_status) in [
    ("downstream-http-protocols", "supported"),
    ("upstream-http-protocols", "supported"),
    ("compio-direct-h1-io", "experimental"),
    ("owned-embedded-runtime-api", "experimental"),
    ("route-matchers", "supported"),
    ("route-actions", "supported"),
    ("upstream-pool-algorithms", "supported"),
    ("upstream-discovery", "supported"),
    ("upstream-pool-runtime-state", "supported"),
    ("static-files", "supported"),
    ("tls-ocsp", "supported"),
    ("tls-upstream-revocation", "experimental"),
    ("tls-remote-signer", "supported"),
    ("root-netport-switcher", "experimental"),
    ("tls-mtls-client-auth", "supported"),
    ("upstream-ech", "supported"),
    ("stream-listener-tcp", "supported"),
    ("sni-forward", "supported"),
    ("oxirule-request-response", "supported"),
    ("crs-request-response", "supported"),
    ("person-proof", "supported"),
    ("client-identity-asn", "experimental"),
    ("sybil-rate-limit-identities", "experimental"),
    ("cache", "supported"),
    ("redis-shared-state-tls", "supported"),
    ("admin-api-runtime-control", "supported"),
    ("admin-mutation-replay", "supported"),
    ("admin-mutation-admin-cluster-rollout", "supported"),
    ("observability", "supported"),
    ("gateway-controller", "experimental"),
    ("gateway-api-httproute", "experimental"),
    ("gateway-api-grpcroute", "experimental"),
    ("gateway-api-tlsroute", "experimental"),
    ("gateway-api-tcproute", "experimental"),
    ("gateway-api-udproute", "experimental"),
    ("gateway-api-backendtlspolicy", "experimental"),
    ("helm-data-plane", "experimental"),
    ("helm-gateway-controller", "experimental"),
    ("acme", "reserved"),
    ("crlite", "experimental"),
    ("downstream-ech", "reserved"),
    ("stream-proxy-udp", "supported"),
    ("crs-stream-payload", "reserved"),
    ("general-scripting", "reserved"),
    ("legacy-admin-rbac", "removed"),
    ("legacy-pool-algorithm-aliases", "removed"),
  ] {
    assert_eq!(
      statuses.get(feature_id).map(String::as_str),
      Some(expected_status),
      "docs/FeatureStatus.md must list {feature_id} as {expected_status}"
    );
  }
}

#[test]
fn compio_direct_h1_status_preserves_experimental_no_duplicate_boundary() {
  let description = feature_status_description("compio-direct-h1-io");
  for expected in [
    "persistent bounded worker fleet",
    "Bodyful, chunked, streaming, upgrade, CONNECT",
    "remain on Hyper",
    "pre-dispatch fallback",
    "post-dispatch failure never implicitly replays",
    "at least three paired Hyper/Compio samples",
    "CPU/request and p99",
    "30-minute FD/thread/RSS/active-connection soak gate",
  ] {
    assert!(
      description.contains(expected),
      "compio-direct-h1-io lifecycle notes should preserve {expected:?}"
    );
  }
}

#[test]
fn runtime_confinement_status_tracks_the_filesystem_manifest_schema() {
  let description = feature_status_description("runtime-confinement-contract");
  assert!(
    description.contains("schema-v3 filesystem-access manifest"),
    "runtime-confinement-contract lifecycle notes must name the active manifest schema"
  );
  assert!(
    !description.contains("schema-v2 filesystem-access manifest"),
    "runtime-confinement-contract lifecycle notes must not retain the superseded schema"
  );
}

#[test]
fn owned_and_embedded_runtime_api_is_documented_as_an_explicit_ownership_boundary() {
  let readme = read_repo_file("README.md");
  let embedding = read_repo_file("docs/Embedding.md");
  let configuration = read_repo_file("docs/Configuration.md");
  let upgrading = read_repo_file("docs/Upgrading.md");

  assert!(
    readme.contains("[Rust embedding guide](docs/Embedding.md)"),
    "README.md should publish the Rust embedding guide"
  );
  for expected in [
    "OxiBelt::builder",
    "RuntimePolicy::FromConfig",
    "RuntimePolicy::CurrentRuntime",
    "ProcessPolicy::Standalone",
    "ProcessPolicy::Embedded",
    "ProcessGlobalHooks::CallerManaged",
    "ProcessGlobalHooks::VerifyOnly",
    "ProcessGlobalHooks::ApplySelected",
    "ServerHandle",
    "readiness",
    "runtime_topology",
    "bound_listeners",
    "shutdown",
    "cancel",
    "wait",
    "Drop cannot await",
    "Concurrent instances are not a compatibility guarantee",
  ] {
    assert!(
      embedding.contains(expected),
      "docs/Embedding.md should preserve {expected:?}"
    );
  }
  for status in [
    "Applied",
    "AlreadyMatching",
    "Verified",
    "CallerManaged",
    "Inapplicable",
    "Unverifiable",
    "Rejected",
    "Conflict",
  ] {
    assert!(
      embedding.contains(status),
      "docs/Embedding.md should preserve process-global status {status:?}"
    );
  }
  for document in [&configuration, &upgrading] {
    for expected in [
      "RuntimePolicy::CurrentRuntime",
      "ProcessPolicy::Embedded",
      "ProcessGlobalHooks::CallerManaged",
      "Landlock",
    ] {
      assert!(
        document.contains(expected),
        "configuration and upgrade docs should preserve {expected:?}"
      );
    }
  }
}

#[test]
fn compio_direct_h1_operator_docs_define_service_upgrade_and_evidence_contracts() {
  let configuration = read_repo_file("docs/Configuration.md");
  for expected in [
    "persistent service at subsystem startup",
    "bounded submission queue",
    "worker count is the only independent public Compio allocation in this release",
    "before an upstream request byte is written",
    "never implicitly replays the operation through Hyper",
    "returned to the bounded idle pool only after complete unambiguous response framing",
  ] {
    assert!(
      configuration.contains(expected),
      "docs/Configuration.md should preserve {expected:?}"
    );
  }

  let upgrading = read_repo_file("docs/Upgrading.md");
  for expected in [
    "internal resource-model change, not a configuration migration",
    "Bodyful, chunked, streaming, upgrade, CONNECT",
    "does not implicitly replay the request",
    "runtime.direct_h1_io = \"auto\"",
    "oxibelt_http_compio_direct_h1_*",
  ] {
    assert!(
      upgrading.contains(expected),
      "docs/Upgrading.md should preserve {expected:?}"
    );
  }

  let performance = read_repo_file("docs/Performance.md");
  for expected in [
    "Aggregate schema `31` requires at least three complete control samples",
    "CPU-time-per-request ratio at `<= 1.03`",
    "median p99 ratio at `<= 1.05`",
    "RPS remains visible but informational",
    "FD delta `0`",
    "thread delta `0`",
    "active Compio connections `0`",
    "max(16 MiB, 5% of baseline)",
  ] {
    assert!(
      performance.contains(expected),
      "docs/Performance.md should preserve {expected:?}"
    );
  }
}

#[test]
fn reserved_sections_do_not_reclassify_supported_features() {
  for path in ["README.md", "docs/Specification.md"] {
    let text = read_repo_file(path);
    for line in text.lines() {
      let lower = line.to_ascii_lowercase();
      if lower.contains("reserved") || lower.contains("deferred") {
        assert!(
          !lower.contains("sticky-cookie"),
          "{path} reserved text must not list sticky-cookie as reserved: {line}"
        );
        assert!(
          !lower.contains("live ocsp"),
          "{path} reserved text must not list live OCSP as reserved: {line}"
        );
        assert!(
          !lower.contains("live_fetch"),
          "{path} reserved text must not list live_fetch as reserved: {line}"
        );
      }
    }
  }
}

#[test]
fn config_wire_values_are_documented_in_config_reference_and_feature_matrix() {
  let configuration = read_repo_file("docs/Configuration.md");
  let feature_status = read_repo_file("docs/FeatureStatus.md");

  for values in [
    HTTP_POOL_LOAD_BALANCING_ALGORITHM_WIRE_VALUES,
    STICKY_COOKIE_FALLBACK_ALGORITHM_WIRE_VALUES,
    OCSP_MODE_WIRE_VALUES,
    OUTBOUND_OCSP_MODE_WIRE_VALUES,
    CRLITE_MODE_WIRE_VALUES,
    CRLITE_FAILURE_POLICY_WIRE_VALUES,
    CRLITE_COVERAGE_POLICY_WIRE_VALUES,
    SNI_FORWARD_CLIENT_HELLO_PARSE_METHOD_WIRE_VALUES,
    SNI_FORWARD_PROTOCOL_WIRE_VALUES,
    UPSTREAM_DISCOVERY_PROVIDER_WIRE_VALUES,
    UPSTREAM_POOL_SERVER_STATE_WIRE_VALUES,
  ] {
    assert_values_appear("docs/Configuration.md", &configuration, values);
    assert_values_appear("docs/FeatureStatus.md", &feature_status, values);
  }
}

#[test]
fn configuration_route_target_docs_include_all_exclusive_targets() {
  let configuration = read_repo_file("docs/Configuration.md");
  for value in [
    "`upstream`",
    "`upstream_pool`",
    "`static_root`",
    "`ct_log`",
    "`actions.redirect`",
    "`actions.direct_response`",
  ] {
    assert!(
      configuration.contains(value),
      "docs/Configuration.md route target docs must mention {value}"
    );
  }
  assert!(
    configuration.contains(
      "exactly one of `upstream`, `upstream_pool`, `static_root`, `ct_log`, terminal `actions.redirect`, or terminal `actions.direct_response`"
    ),
    "docs/Configuration.md must document the route target exclusivity set"
  );
}

#[test]
fn admin_openapi_enums_match_runtime_wire_contracts() {
  let spec = openapi();
  assert_eq!(
    schema_enum(&spec, "AdminOperationKind"),
    string_set(ADMIN_OPERATION_KIND_WIRE_VALUES)
  );
  assert_eq!(
    schema_enum(&spec, "AdminOperationState"),
    string_set(ADMIN_OPERATION_STATE_WIRE_VALUES)
  );
  assert_eq!(
    schema_enum(&spec, "UpstreamPoolServerState"),
    string_set(UPSTREAM_POOL_SERVER_STATE_WIRE_VALUES)
  );

  let features = &spec["components"]["schemas"]["AdminCapabilities"]["properties"]["features"];
  let required =
    json_string_array_set(&features["required"], "AdminCapabilities.features.required");
  let properties = features["properties"]
    .as_object()
    .expect("AdminCapabilities.features.properties should be an object")
    .keys()
    .cloned()
    .collect::<BTreeSet<_>>();
  let expected = string_set(ADMIN_CAPABILITY_FEATURE_KEYS);
  assert_eq!(required, expected);
  assert_eq!(properties, expected);
}

#[test]
fn admin_wire_values_are_documented_in_feature_matrix() {
  let feature_status = read_repo_file("docs/FeatureStatus.md");
  for values in [
    ADMIN_OPERATION_KIND_WIRE_VALUES,
    ADMIN_OPERATION_STATE_WIRE_VALUES,
  ] {
    assert_values_appear("docs/FeatureStatus.md", &feature_status, values);
  }

  let description = feature_status_description("admin-api-runtime-control");
  let capabilities = description
    .strip_prefix("Admin capabilities: ")
    .expect("admin-api-runtime-control must start with its capability inventory")
    .split_once(". ")
    .expect("Admin capability inventory must end before its explanatory text")
    .0
    .split(", ")
    .map(markdown_code_value)
    .collect::<BTreeSet<_>>();
  assert_eq!(
    capabilities,
    string_set(ADMIN_CAPABILITY_FEATURE_KEYS),
    "admin-api-runtime-control must document the exact runtime capability inventory"
  );
}

fn feature_statuses() -> BTreeMap<String, String> {
  let mut statuses = BTreeMap::new();
  for line in read_repo_file("docs/FeatureStatus.md").lines() {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') {
      continue;
    }
    let cells = trimmed
      .trim_matches('|')
      .split('|')
      .map(str::trim)
      .collect::<Vec<_>>();
    if cells.len() < 4 || cells[0] == "Feature ID" || cells[0].starts_with("---") {
      continue;
    }

    let feature_id = markdown_code_value(cells[0]);
    let status = markdown_code_value(cells[1]);
    assert!(
      statuses.insert(feature_id.clone(), status).is_none(),
      "docs/FeatureStatus.md must not duplicate feature ID {feature_id}"
    );
  }
  statuses
}

fn feature_status_description(feature_id: &str) -> String {
  for line in read_repo_file("docs/FeatureStatus.md").lines() {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') {
      continue;
    }
    let cells = trimmed
      .trim_matches('|')
      .split('|')
      .map(str::trim)
      .collect::<Vec<_>>();
    if cells.len() >= 4 && markdown_code_value(cells[0]) == feature_id {
      return cells[3].to_string();
    }
  }
  panic!("docs/FeatureStatus.md must include feature ID {feature_id}");
}

fn markdown_code_value(value: &str) -> String {
  value.trim().trim_matches('`').to_string()
}

fn assert_values_appear(path: &str, text: &str, values: &[&str]) {
  for value in values {
    assert!(text.contains(value), "{path} must document `{value}`");
  }
}

fn schema_enum(spec: &Value, schema_name: &str) -> BTreeSet<String> {
  json_string_array_set(
    &spec["components"]["schemas"][schema_name]["enum"],
    &format!("{schema_name}.enum"),
  )
}

fn json_string_array_set(value: &Value, label: &str) -> BTreeSet<String> {
  value
    .as_array()
    .unwrap_or_else(|| panic!("{label} should be an array"))
    .iter()
    .map(|item| {
      item
        .as_str()
        .unwrap_or_else(|| panic!("{label} entries should be strings"))
        .to_string()
    })
    .collect()
}

fn string_set(values: &[&str]) -> BTreeSet<String> {
  values.iter().map(|value| (*value).to_string()).collect()
}
