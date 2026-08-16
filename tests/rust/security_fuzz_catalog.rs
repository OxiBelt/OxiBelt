use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Deserialize)]
struct Catalog {
  schema_version: u32,
  replay_schema_version: u32,
  owner: String,
  pr_max_cases: usize,
  pr_max_seconds: u64,
  sustained_default_seconds: u64,
  sustained_max_cases: usize,
  case_timeout_seconds: u64,
  recovery_timeout_seconds: u64,
  failure_artifact_max_bytes: usize,
  failure_artifact_metadata: Vec<String>,
  target: Vec<Target>,
}

#[derive(Clone, Debug)]
pub(crate) struct Defaults {
  pub(crate) schema_version: u32,
  pub(crate) replay_schema_version: u32,
  pub(crate) owner: String,
  pub(crate) pr_max_cases: usize,
  pub(crate) pr_max_seconds: u64,
  pub(crate) sustained_default_seconds: u64,
  pub(crate) sustained_max_cases: usize,
  pub(crate) case_timeout_seconds: u64,
  pub(crate) recovery_timeout_seconds: u64,
  pub(crate) failure_artifact_max_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Target {
  pub(crate) id: String,
  pub(crate) description: String,
  pub(crate) protocols: Vec<String>,
  pub(crate) payload_max_bytes: usize,
  pub(crate) session_max_cases: usize,
  pub(crate) max_concurrent_sessions: usize,
  pub(crate) required_helpers: Vec<String>,
  pub(crate) oracle: String,
  pub(crate) meaning_preserving_transforms: Vec<String>,
}

pub(crate) fn targets() -> Result<Vec<Target>> {
  Ok(load()?.target)
}

pub(crate) fn defaults() -> Result<Defaults> {
  let catalog = load()?;
  Ok(Defaults {
    schema_version: catalog.schema_version,
    replay_schema_version: catalog.replay_schema_version,
    owner: catalog.owner,
    pr_max_cases: catalog.pr_max_cases,
    pr_max_seconds: catalog.pr_max_seconds,
    sustained_default_seconds: catalog.sustained_default_seconds,
    sustained_max_cases: catalog.sustained_max_cases,
    case_timeout_seconds: catalog.case_timeout_seconds,
    recovery_timeout_seconds: catalog.recovery_timeout_seconds,
    failure_artifact_max_bytes: catalog.failure_artifact_max_bytes,
  })
}

fn load() -> Result<Catalog> {
  let catalog_path = catalog_path();
  let raw = fs::read_to_string(&catalog_path)
    .map_err(|error| format!("failed to read {}: {error}", catalog_path.display()))?;
  let catalog: Catalog = toml::from_str(&raw)
    .map_err(|error| format!("failed to parse {}: {error}", catalog_path.display()))?;
  validate_catalog(&catalog)?;
  Ok(catalog)
}

pub(crate) fn target(id: &str) -> Result<Target> {
  targets()?
    .into_iter()
    .find(|target| target.id == id)
    .ok_or_else(|| format!("unknown security-fuzz target: {id}").into())
}

fn catalog_path() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/docker/security_fuzz/targets.toml")
}

fn validate_catalog(catalog: &Catalog) -> Result<()> {
  if catalog.schema_version != 1 {
    return Err(
      format!(
        "unsupported security-fuzz catalog schema {}",
        catalog.schema_version
      )
      .into(),
    );
  }
  if catalog.replay_schema_version != 1 || catalog.owner != "security-fuzz" {
    return Err("security-fuzz catalog has an unsupported replay or owner contract".into());
  }
  if catalog.pr_max_cases != 1024
    || catalog.pr_max_seconds != 120
    || catalog.sustained_default_seconds != 900
    || catalog.sustained_max_cases != 1_048_576
    || catalog.case_timeout_seconds != 5
    || catalog.recovery_timeout_seconds != 15
    || catalog.failure_artifact_max_bytes != 32 * 1024 * 1024
  {
    return Err("security-fuzz catalog must preserve the approved execution bounds".into());
  }
  let expected_artifact_metadata = BTreeSet::from([
    "case",
    "case_seed",
    "input_sha256",
    "max_concurrent_sessions",
    "meaning_preserving_transforms",
    "oracle",
    "protocols",
    "replay",
    "required_helpers",
    "schema_version",
    "source_revision",
    "target",
  ]);
  if catalog
    .failure_artifact_metadata
    .iter()
    .map(String::as_str)
    .collect::<BTreeSet<_>>()
    != expected_artifact_metadata
    || catalog.failure_artifact_metadata.len() != expected_artifact_metadata.len()
  {
    return Err("security-fuzz failure artifact metadata contract is incomplete".into());
  }
  let expected = BTreeSet::from([
    "path_security",
    "tls_quic_sni",
    "http_framing",
    "waf_bypass",
    "auth_bypass",
    "websocket_webtransport",
    "turn_runtime",
    "admin_authz",
  ]);
  let actual = catalog
    .target
    .iter()
    .map(|target| target.id.as_str())
    .collect::<BTreeSet<_>>();
  if actual != expected || catalog.target.len() != expected.len() {
    return Err("security-fuzz catalog must contain each canonical target exactly once".into());
  }

  for target in &catalog.target {
    if !valid_identifier(&target.id) || target.description.trim().is_empty() {
      return Err(format!("invalid security-fuzz target metadata for {}", target.id).into());
    }
    if target.payload_max_bytes == 0 || target.payload_max_bytes > 64 * 1024 {
      return Err(format!("{} has an invalid payload bound", target.id).into());
    }
    if target.session_max_cases == 0 || target.session_max_cases > 16 {
      return Err(format!("{} has an invalid session case bound", target.id).into());
    }
    if target.max_concurrent_sessions == 0 || target.max_concurrent_sessions > 16 {
      return Err(format!("{} has an invalid concurrent session bound", target.id).into());
    }
    if target.required_helpers.is_empty()
      || target
        .required_helpers
        .iter()
        .any(|helper| !valid_identifier(helper))
      || target
        .required_helpers
        .iter()
        .collect::<BTreeSet<_>>()
        .len()
        != target.required_helpers.len()
    {
      return Err(format!("{} has invalid required helper metadata", target.id).into());
    }
    if target.protocols.is_empty()
      || target
        .protocols
        .iter()
        .any(|protocol| !valid_identifier(protocol))
      || target.protocols.iter().collect::<BTreeSet<_>>().len() != target.protocols.len()
    {
      return Err(format!("{} has invalid protocol coverage", target.id).into());
    }
    if !valid_identifier(&target.oracle)
      || target
        .meaning_preserving_transforms
        .iter()
        .any(|transform| !valid_identifier(transform))
      || target
        .meaning_preserving_transforms
        .iter()
        .collect::<BTreeSet<_>>()
        .len()
        != target.meaning_preserving_transforms.len()
    {
      return Err(format!("{} has invalid oracle metadata", target.id).into());
    }
  }

  let lookup = |id: &str| {
    catalog
      .target
      .iter()
      .find(|target| target.id == id)
      .expect("validated target exists")
  };
  assert_eq!(lookup("path_security").payload_max_bytes, 4 * 1024);
  assert_eq!(lookup("tls_quic_sni").payload_max_bytes, 16 * 1024);
  assert_eq!(lookup("http_framing").payload_max_bytes, 64 * 1024);
  assert_eq!(lookup("waf_bypass").payload_max_bytes, 64 * 1024);
  assert_eq!(lookup("auth_bypass").payload_max_bytes, 16 * 1024);
  assert_eq!(
    lookup("websocket_webtransport").payload_max_bytes,
    64 * 1024
  );
  assert_eq!(lookup("turn_runtime").payload_max_bytes, 8 * 1024);
  assert_eq!(lookup("admin_authz").payload_max_bytes, 64 * 1024);
  assert_eq!(lookup("path_security").session_max_cases, 4);
  assert_eq!(lookup("tls_quic_sni").session_max_cases, 8);
  assert_eq!(lookup("http_framing").session_max_cases, 8);
  assert_eq!(lookup("waf_bypass").session_max_cases, 8);
  assert_eq!(lookup("auth_bypass").session_max_cases, 8);
  assert_eq!(lookup("websocket_webtransport").session_max_cases, 16);
  assert_eq!(lookup("turn_runtime").session_max_cases, 16);
  assert_eq!(lookup("admin_authz").session_max_cases, 4);
  assert_eq!(lookup("path_security").max_concurrent_sessions, 1);
  assert_eq!(lookup("tls_quic_sni").max_concurrent_sessions, 1);
  assert_eq!(lookup("http_framing").max_concurrent_sessions, 1);
  assert_eq!(lookup("waf_bypass").max_concurrent_sessions, 1);
  assert_eq!(lookup("auth_bypass").max_concurrent_sessions, 1);
  assert_eq!(lookup("websocket_webtransport").max_concurrent_sessions, 2);
  assert_eq!(lookup("turn_runtime").max_concurrent_sessions, 1);
  assert_eq!(lookup("admin_authz").max_concurrent_sessions, 1);
  Ok(())
}

fn valid_identifier(value: &str) -> bool {
  !value.is_empty()
    && value
      .bytes()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn repository_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
      .join("..")
      .join(path)
  }

  #[test]
  fn catalog_is_complete_and_bounded() {
    let targets = targets().expect("catalog must parse and validate");
    assert_eq!(targets.len(), 8);
  }

  #[test]
  fn catalog_targets_are_bound_to_executor_and_documentation() {
    let executor = fs::read_to_string(repository_path("tests/docker/security_fuzz/executor.sh"))
      .expect("security-fuzz executor should be readable");
    let documentation = fs::read_to_string(repository_path("docs/Fuzzing.md"))
      .expect("fuzzing documentation should be readable");

    for target in targets().expect("catalog must parse and validate") {
      let implementation = format!("case_{}() {{", target.id);
      assert_eq!(
        executor.matches(&implementation).count(),
        1,
        "{} must have exactly one executor adapter",
        target.id
      );
      let dispatch = format!("{}) case_{} ;;", target.id, target.id);
      assert!(
        executor.contains(&dispatch),
        "{} must be dispatched by the executor",
        target.id
      );

      let row_prefix = format!("| `{}` | ", target.id);
      let rows = documentation
        .lines()
        .filter(|line| line.starts_with(&row_prefix))
        .collect::<Vec<_>>();
      assert_eq!(
        rows.len(),
        1,
        "{} must have exactly one Docker fuzz documentation row",
        target.id
      );
      let documented_protocols = target
        .protocols
        .iter()
        .map(|protocol| format!("`{protocol}`"))
        .collect::<Vec<_>>()
        .join(", ");
      assert!(
        rows[0].contains(&format!("| {documented_protocols} |")),
        "{} documentation protocols drifted from the catalog",
        target.id
      );
    }
  }

  #[test]
  fn waf_bypass_fixture_binds_encoded_path_mutations_to_normalized_matching() {
    let fixture = fs::read_to_string(repository_path(
      "tests/docker/security_fuzz/config/waf_bypass.toml",
    ))
    .expect("WAF security-fuzz fixture should be readable");
    let waf_bypass = targets()
      .expect("catalog must parse and validate")
      .into_iter()
      .find(|target| target.id == "waf_bypass")
      .expect("catalog must define the WAF bypass target");

    assert!(
      waf_bypass
        .meaning_preserving_transforms
        .iter()
        .any(|transform| transform == "unreserved-percent-encoding"),
      "the WAF bypass target must exercise percent-encoded path variants"
    );
    assert!(
      fixture.contains("Request.Normalized.Http.Path.endsWith('/sf-known-attack')"),
      "the WAF fixture must apply its encoded-path oracle to the normalized path view"
    );
    assert!(
      !fixture.contains("Request.Http.Path.endsWith('/sf-known-attack')"),
      "the WAF fixture must not apply its encoded-path oracle to the raw path view"
    );
  }

  #[test]
  fn turn_runtime_observes_and_reaps_a_bounded_live_allocation() {
    let fixture = fs::read_to_string(repository_path(
      "tests/docker/security_fuzz/config/turn_runtime.toml",
    ))
    .expect("TURN security-fuzz fixture should be readable");
    let executor = fs::read_to_string(repository_path("tests/docker/security_fuzz/executor.sh"))
      .expect("security-fuzz executor should be readable");

    assert!(
      fixture.contains("max_allocation_lifetime_seconds = 5"),
      "the TURN fixture must leave bounded headroom for live allocation introspection"
    );
    assert!(
      executor.contains("--allocation-hold-ms 4000")
        && executor.contains("wait_for_turn_allocation_visibility \"${client}\""),
      "the TURN case must retain its allocation probe while polling runtime visibility"
    );
    assert!(
      executor.contains(
        "finish_turn_allocation_probe\n      turn_probe \"$(cat \"${work_dir}/last-turn-transport\""
      ) && executor.contains("for _attempt in $(seq 1 100); do"),
      "TURN recovery must reap the held probe before its bounded zero-count poll"
    );
    assert_eq!(
      defaults()
        .expect("catalog must parse and validate")
        .recovery_timeout_seconds,
      15,
      "TURN allocation expiry must remain bounded by the catalog recovery timeout"
    );
  }

  #[test]
  fn fuzz_session_lifecycle_preserves_fail_closed_restart_state() {
    let executor = fs::read_to_string(repository_path("tests/docker/security_fuzz/executor.sh"))
      .expect("security-fuzz executor should be readable");
    let runner = fs::read_to_string(repository_path("tests/scripts/run-docker-security-fuzz.sh"))
      .expect("security-fuzz runner should be readable");

    assert!(
      executor.contains(
        "ln -sfn ../should-never-be-readable/canary.txt \"${config_dir}/public/canary-link.txt\""
      ),
      "path-security fixture preparation must remain idempotent across session restarts"
    );
    for phase in ["case", "recovery", "start", "stop"] {
      assert!(
        runner.contains(&format!(
          "security-fuzz executor phase={phase} exit_status=%s"
        )),
        "security-fuzz lifecycle failures must retain phase and exit-status diagnostics"
      );
    }
    assert!(
      runner.contains("if ((start_status != 0)); then")
        && runner.contains("return \"${start_status}\"")
        && runner.contains("if ((stop_status != 0)); then")
        && runner.contains("return \"${stop_status}\""),
      "session markers must not mask failed executor start or stop commands"
    );
    assert!(
      runner.contains("final_lifecycle_log=\"${work_dir}/session-final-stop.log\"")
        && runner.contains("if ! stop_executor_session 10"),
      "a successful fuzz command must verify final session teardown"
    );
    assert!(
      executor.contains("assert_topology_absent() {")
        && executor.contains("security-fuzz topology already contains scoped resources")
        && executor.contains("  assert_topology_absent\n  generate_certificates"),
      "a restarted fuzz session must reject stale scoped topology before creating resources"
    );
    let stop_topology = executor
      .split_once("stop_topology() {")
      .and_then(|(_, suffix)| suffix.split_once("\n}\n\ncase \"${command}\" in"))
      .map(|(body, _)| body)
      .expect("security-fuzz executor must define stop_topology before command dispatch");
    assert!(
      stop_topology.contains("cleanup_status=1")
        && stop_topology.contains("security-fuzz topology cleanup left scoped resources")
        && stop_topology.contains("return 1")
        && !stop_topology.contains("docker network rm \"${network}\" >/dev/null 2>&1 || true"),
      "topology teardown must be convergent and fail closed"
    );
  }
}
