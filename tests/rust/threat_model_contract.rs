use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

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

#[test]
fn threat_model_is_published_and_cross_linked() {
  assert!(
    repo_root().join("docs/ThreatModel.md").is_file(),
    "docs/ThreatModel.md should be a tracked product document"
  );

  let readme = read_repo_file("README.md");
  let security = read_repo_file("SECURITY.md");
  let threat_model = read_repo_file("docs/ThreatModel.md");

  assert!(
    readme.contains("[Product threat model](docs/ThreatModel.md)"),
    "README.md should publish the product threat model"
  );
  assert!(
    security.contains("[product threat model](docs/ThreatModel.md)"),
    "SECURITY.md should designate the product threat model"
  );
  assert_contains_all(
    "docs/ThreatModel.md",
    &threat_model,
    &[
      "[security policy](../SECURITY.md)",
      "[feature lifecycle matrix](FeatureStatus.md)",
      "[technical specification](Specification.md)",
      "[configuration reference](Configuration.md)",
      "[Admin API reference](AdminAPI.md)",
      "[Admin OpenAPI document](../source/assets/admin-openapi.json)",
      "[Gateway API reference](GatewayAPI.md)",
    ],
  );
  assert!(
    !threat_model.lines().any(|line| {
      line.starts_with("Repository:") || line.starts_with("Version: codex-security-snapshot/")
    }),
    "the public living document must not include a scan-cache footer"
  );
}

#[test]
fn threat_model_has_required_repository_scope_and_boundaries() {
  let threat_model = read_repo_file("docs/ThreatModel.md");
  let headings = threat_model
    .lines()
    .filter(|line| line.starts_with("## "))
    .collect::<Vec<_>>();
  assert_eq!(
    headings,
    vec![
      "## Overview",
      "## Threat Model, Trust Boundaries, and Assumptions",
      "## Attack Surface, Mitigations, and Attacker Stories",
      "## Severity Calibration",
    ],
    "the threat model should keep the repository-scoped Codex Security structure"
  );

  assert_contains_all(
    "docs/ThreatModel.md",
    &threat_model,
    &[
      "Untrusted Internet Client",
      "Public Listener",
      "Protocol Parsing",
      "Routing / WAF / Identity",
      "Upstream Services",
      "Management Network",
      "Admin Listener",
      "Configuration and Secret Mutation",
      "OxiBelt Instances",
      "Redis or PostgreSQL Shared State",
      "Gateway Controller",
      "Desired Configuration",
      "Data-Plane Rollout",
      "Build System",
      "Container Registry",
      "Kubernetes Admission",
    ],
  );

  for listener_class in [
    "Public HTTP data plane",
    "SNI forwarding and raw stream proxy",
    "WebRTC TURN",
    "Admin API",
    "Metrics",
    "Health",
    "Gateway Controller health",
    "Local privileged IPC",
  ] {
    assert!(
      threat_model.contains(listener_class),
      "docs/ThreatModel.md must document listener class {listener_class}"
    );
  }
}

#[test]
fn threat_model_covers_every_p1_7_threat() {
  let threat_model = read_repo_file("docs/ThreatModel.md");
  assert_contains_all(
    "docs/ThreatModel.md",
    &threat_model,
    &[
      "HTTP request smuggling",
      "Header ambiguity",
      "H2 and H3 stream abuse",
      "Decompression bombs",
      "WAF bypass and parser mismatch",
      "Cache poisoning",
      "Host and SNI confusion",
      "Forwarded-header spoofing",
      "TLS key compromise",
      "QUIC token-key instability",
      "Admin credential replay",
      "Configuration rollback attack",
      "Partial cluster rollout",
      "Redis compromise",
      "PostgreSQL compromise",
      "Audit sink failure",
      "Tenant isolation failure",
      "Retry amplification",
      "Queue exhaustion",
      "Cache-fill stampede",
      "Plugin or custom frontend compromise",
      "Compromised build pipeline",
      "Malicious or stale container image",
    ],
  );
}

#[test]
fn threat_model_states_claims_failure_modes_and_compromise_impact() {
  let threat_model = read_repo_file("docs/ThreatModel.md");
  assert_contains_all(
    "docs/ThreatModel.md",
    &threat_model,
    &[
      "### Mandatory deployment assumptions",
      "### Conditional guarantees",
      "### Explicit non-guarantees",
      "### Failure semantics",
      "### Externally protected secrets",
      "### Experimental features",
      "### Shared-state compromise impact",
      "### Admin mutation authorization and audit",
      "`fail_closed`",
      "`reject_new_only`",
      "`stale_snapshot`",
      "`local_fallback`",
      "`fail_open`",
      "cluster-wide security decision",
      "All Admin requests require bearer authentication",
      "a verified Admin mTLS identity maps to exactly one principal",
      "best_effort",
      "enforcing",
    ],
  );

  for shared_feature in [
    "Distributed rate limits",
    "Connection and upstream-pool leases",
    "Person proof",
    "Upstream health and active counts",
    "Sticky sessions",
    "Shared cache, tags, fill locks, and purge state",
    "Reload heartbeat and instance generation",
    "Dynamic policy",
    "IPM principals, credentials, policies, and bindings",
    "Admin audit",
    "Mitigation intents",
  ] {
    assert!(
      threat_model.contains(shared_feature),
      "docs/ThreatModel.md must document compromise impact for {shared_feature}"
    );
  }

  for mutation_family in [
    "Configuration load/rollback",
    "Cache purge/warm",
    "Upstream and stream pool server mutations",
    "Dynamic policy create/apply/import/update/delete",
    "IPM principal, credential, policy, and binding changes",
    "OxiRule/rulepack file management and reload",
    "Lifecycle drain/undrain and runtime session drain",
    "Person proof clearance revocation",
    "Async operation cancellation and control",
  ] {
    assert!(
      threat_model.contains(mutation_family),
      "docs/ThreatModel.md must define authorization and audit for {mutation_family}"
    );
  }
}

#[test]
fn experimental_feature_table_matches_canonical_lifecycle_matrix() {
  let feature_status = read_repo_file("docs/FeatureStatus.md");
  let threat_model = read_repo_file("docs/ThreatModel.md");
  let expected = feature_ids_with_status(&feature_status, "experimental");
  let documented = threat_model_experimental_feature_ids(&threat_model);

  assert!(
    !expected.is_empty(),
    "the canonical experimental set should not be empty"
  );
  assert_eq!(
    documented, expected,
    "docs/ThreatModel.md experimental features must match docs/FeatureStatus.md"
  );
}

#[test]
fn compio_direct_h1_threat_model_preserves_dispatch_and_reuse_boundaries() {
  let threat_model = read_repo_file("docs/ThreatModel.md");
  for expected in [
    "persistent worker fleet bounds queues, waiters, connections, and retained buffers",
    "only before an upstream request byte is written",
    "retires the connection instead of reusing it",
    "Bodyful and streaming requests stay on Hyper",
    "no-duplicate-dispatch boundary",
    "30-minute FD/thread/RSS/active-connection soak",
  ] {
    assert!(
      threat_model.contains(expected),
      "Compio direct-H1 threat model should preserve {expected:?}"
    );
  }
}

fn feature_ids_with_status(document: &str, expected_status: &str) -> BTreeSet<String> {
  document
    .lines()
    .filter_map(|line| {
      let cells = markdown_table_cells(line);
      if cells.len() < 2 || markdown_code_value(cells[1]) != expected_status {
        return None;
      }
      Some(markdown_code_value(cells[0]).to_string())
    })
    .collect()
}

fn threat_model_experimental_feature_ids(document: &str) -> BTreeSet<String> {
  let section = document
    .split_once("### Experimental features")
    .expect("docs/ThreatModel.md should contain the experimental features section")
    .1
    .split_once("\n## ")
    .map_or_else(|| document, |(section, _)| section);

  section
    .lines()
    .filter_map(|line| {
      let cells = markdown_table_cells(line);
      if cells.len() < 2 || !cells[0].starts_with('`') {
        return None;
      }
      Some(markdown_code_value(cells[0]).to_string())
    })
    .collect()
}

fn markdown_table_cells(line: &str) -> Vec<&str> {
  let trimmed = line.trim();
  if !trimmed.starts_with('|') {
    return Vec::new();
  }
  trimmed
    .trim_matches('|')
    .split('|')
    .map(str::trim)
    .collect()
}

fn markdown_code_value(value: &str) -> &str {
  value.trim().trim_matches('`')
}

fn assert_contains_all(path: &str, document: &str, required: &[&str]) {
  for value in required {
    assert!(document.contains(value), "{path} must contain {value:?}");
  }
}
