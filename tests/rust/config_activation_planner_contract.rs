//! Public schema-v3 and side-effect-free activation-planner qualification contract.

use std::sync::{Arc, Barrier};

use oxibelt::activation_plan::{
  ACTIVATION_PLAN_SCHEMA_VERSION, ConfigActivationReport, MAX_ACTIVATION_CHANGES, PlanningBasis,
  ResolvedActivationOperation, plan_toml_values,
};
use serde_json::json;

fn parsed(value: &str) -> toml::Value {
  toml::from_str(value).expect("qualification TOML should parse")
}

fn representative_report() -> ConfigActivationReport {
  plan_toml_values(
    &parsed(
      r#"
      [admin]
      bearer_token_env = "PLANNER_CURRENT_SECRET"
      [compression]
      enabled = true
      "#,
    ),
    &parsed(
      r#"
      [admin]
      bearer_token_env = "PLANNER_CANDIDATE_SECRET"
      [compression]
      enabled = false
      "#,
    ),
    PlanningBasis::OfflineConfig,
  )
  .expect("representative activation report should plan")
}

#[test]
fn public_schema_v3_report_matches_the_exact_api_snapshot() {
  assert_eq!(ACTIVATION_PLAN_SCHEMA_VERSION, 3);
  let report = representative_report();
  assert_eq!(
    serde_json::to_value(&report).expect("activation report should serialize"),
    json!({
      "activation_plan_schema_version": 3,
      "native_schema_epoch": 1,
      "ok": true,
      "basis": "offline_config",
      "changes": [
        {
          "path": "admin.bearer_token_env",
          "op": "change",
          "secret": true,
          "native_activation": "full_reload",
          "metadata_provenance": "explicit",
          "resolved_operation": "full_snapshot_reload",
          "reason_code": "full_snapshot_reload",
          "conditional": false,
          "prerequisite_missing": false,
          "missing_prerequisites": [],
          "long_connections_affected": true,
          "rollback": "conditional"
        },
        {
          "path": "compression.enabled",
          "op": "change",
          "secret": false,
          "native_activation": "full_reload",
          "metadata_provenance": "conservative_default",
          "resolved_operation": "full_snapshot_reload",
          "reason_code": "full_snapshot_reload",
          "conditional": false,
          "prerequisite_missing": false,
          "missing_prerequisites": [],
          "long_connections_affected": true,
          "rollback": "conditional"
        }
      ],
      "activation_plan": {
        "minimum_required_operation": "full_snapshot_reload",
        "selected_operation": "full_snapshot_reload",
        "reason_codes": ["full_snapshot_reload"],
        "can_apply_in_process": true,
        "conditional": false,
        "prerequisites": [],
        "listener": {
          "unchanged": [],
          "additions": [],
          "removals": [],
          "rebinds": [],
          "bind_conflicts": [],
          "external_port_availability": "unknown"
        },
        "connections": {
          "http1_keepalive": "unaffected",
          "http2": "unaffected",
          "http3": "unaffected",
          "websocket": "unaffected",
          "connect_tunnel": "unaffected",
          "webtransport": "unaffected",
          "tcp_streams": "unaffected",
          "udp_flows": "unaffected",
          "configured_drain_timeout_ms": null,
          "effective_force_close_timeout_ms": null
        },
        "confinement": {
          "filesystem": "unknown",
          "landlock": "unknown",
          "seccomp": "unknown",
          "mount_policy": "unknown",
          "requires_policy_expansion": false,
          "restart_required": false,
          "digests_withheld": true,
          "differences": [],
          "differences_truncated": false,
          "missing_prerequisites": []
        },
        "deployment": {
          "mode": "standalone",
          "target_count": null,
          "target_identities": [],
          "identities_withheld": false,
          "membership_revision": null,
          "signed_artifact_required": false,
          "durable_artifact_required": false,
          "all_members_acknowledgement_required": false,
          "missing_prerequisites": []
        },
        "rollback": "conditional"
      }
    })
  );
}

#[test]
fn invalid_schema_v3_report_fails_closed_with_the_public_vocabulary() {
  let report = ConfigActivationReport::invalid_configuration(PlanningBasis::OfflineConfig);
  assert!(!report.is_success());
  assert_eq!(report.activation_plan_schema_version, 3);
  assert_eq!(
    report.activation_plan.minimum_required_operation,
    ResolvedActivationOperation::InvalidOrUnsupported
  );
  assert_eq!(
    report.activation_plan.selected_operation,
    ResolvedActivationOperation::InvalidOrUnsupported
  );
  let encoded = serde_json::to_string(&report).expect("invalid report should serialize");
  assert!(encoded.contains("\"invalid_configuration\""));
  assert!(encoded.contains("\"rollback\":\"unavailable\""));
}

#[test]
fn concurrent_plans_are_deterministic_bounded_and_secret_safe() {
  const WORKERS: usize = 32;
  let expected = representative_report();
  let barrier = Arc::new(Barrier::new(WORKERS));
  let handles = (0..WORKERS)
    .map(|_| {
      let barrier = Arc::clone(&barrier);
      std::thread::spawn(move || {
        barrier.wait();
        representative_report()
      })
    })
    .collect::<Vec<_>>();

  for handle in handles {
    let report = handle.join().expect("planner worker should not panic");
    assert_eq!(report, expected);
    assert_eq!(report.changes.len(), 2);
    let encoded = serde_json::to_string(&report).expect("report should serialize");
    for secret in ["PLANNER_CURRENT_SECRET", "PLANNER_CANDIDATE_SECRET"] {
      assert!(!encoded.contains(secret), "planner output leaked {secret}");
    }
  }
}

#[test]
fn concurrent_overflow_failures_remain_empty_and_fail_closed() {
  const WORKERS: usize = 8;
  const CURRENT_SECRET: &str = "PLANNER_OVERFLOW_CURRENT_SECRET";
  const CANDIDATE_SECRET: &str = "PLANNER_OVERFLOW_CANDIDATE_SECRET";
  let mut current_fields = toml::map::Map::new();
  current_fields.insert(
    "admin".to_string(),
    toml::Value::Table(toml::map::Map::from_iter([(
      "bearer_token_env".to_string(),
      toml::Value::String(CURRENT_SECRET.to_string()),
    )])),
  );
  let current = Arc::new(toml::Value::Table(current_fields));
  let mut fields = toml::map::Map::new();
  fields.insert(
    "admin".to_string(),
    toml::Value::Table(toml::map::Map::from_iter([(
      "bearer_token_env".to_string(),
      toml::Value::String(CANDIDATE_SECRET.to_string()),
    )])),
  );
  for index in 0..=MAX_ACTIVATION_CHANGES {
    fields.insert(
      format!("field_{index:04}"),
      toml::Value::Integer(index as i64),
    );
  }
  let candidate = Arc::new(toml::Value::Table(fields));
  let barrier = Arc::new(Barrier::new(WORKERS));
  let handles = (0..WORKERS)
    .map(|_| {
      let barrier = Arc::clone(&barrier);
      let current = Arc::clone(&current);
      let candidate = Arc::clone(&candidate);
      std::thread::spawn(move || {
        barrier.wait();
        plan_toml_values(&current, &candidate, PlanningBasis::OnlineActive)
          .expect("bounded overflow planning should return a typed report")
      })
    })
    .collect::<Vec<_>>();

  for handle in handles {
    let report = handle
      .join()
      .expect("overflow planner worker should not panic");
    assert!(!report.is_success());
    assert!(report.changes.is_empty(), "overflow must never truncate");
    assert_eq!(
      report.activation_plan.selected_operation,
      ResolvedActivationOperation::InvalidOrUnsupported
    );
    assert_eq!(
      serde_json::to_value(&report.activation_plan.reason_codes)
        .expect("overflow reasons should serialize"),
      json!(["change_limit_exceeded"])
    );
    let encoded = serde_json::to_string(&report).expect("overflow report should serialize");
    let debug = format!("{report:?}");
    for secret in [CURRENT_SECRET, CANDIDATE_SECRET] {
      assert!(!encoded.contains(secret), "overflow report leaked {secret}");
      assert!(
        !debug.contains(secret),
        "overflow debug text leaked {secret}"
      );
    }
  }
}
