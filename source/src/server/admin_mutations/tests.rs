use super::*;
use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use http_body_util::BodyExt;
use sha2::{Digest as _, Sha256};

use crate::admin_audit::{AdminAuditHandle, AdminAuditRuntime};
use crate::admin_mutation::{
  MutationAdmission, MutationSignature, MutationTarget, SignatureSuite, SignerBinding,
  SignerRegistry, TranscriptContext, UnsignedMutationEnvelope, encode_mutation_header,
  mutation_transcript,
};
use crate::config::{IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig};
use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};

const CLUSTER_PRINCIPAL: &str = "spiffe://example.test/planner-controller";
const CLUSTER_MUTATION_PATH: &str = "/admin/v1/config/load";

fn test_digest(value: &[u8]) -> String {
  let mut output = String::from("sha256:");
  for byte in Sha256::digest(value) {
    write!(output, "{byte:02x}").expect("write digest to string");
  }
  output
}

#[test]
fn inactive_break_glass_credentials_are_limited_to_activation_bootstrap_routes() {
  assert!(break_glass_activation_bootstrap_route(
    &Method::GET,
    "/admin/v1/break-glass/activations/self",
  ));
  assert!(break_glass_activation_bootstrap_route(
    &Method::POST,
    "/admin/v1/break-glass/activations",
  ));
  assert!(!break_glass_activation_bootstrap_route(
    &Method::POST,
    "/admin/v1/config/load",
  ));
}

#[test]
fn protected_route_set_covers_every_p1_13_operation_family() {
  for path in [
    "/admin/v1/config/load",
    "/admin/v1/config/rollback",
    "/admin/v1/files/sync",
    "/admin/v1/tls/downstream/reload",
    "/admin/v1/keys/rotate",
    "/admin/v1/config/secret-references/update",
    "/admin/v1/break-glass/activations",
    "/admin/v1/ipm/policies",
  ] {
    assert!(is_protected_write(&Method::POST, path), "missing {path}");
  }
  assert!(!is_protected_write(&Method::POST, "/admin/v1/ipm/simulate"));
  assert!(!is_protected_write(&Method::GET, "/admin/v1/config"));
}

#[test]
fn if_match_requires_one_strong_quoted_revision() {
  let mut headers = HeaderMap::new();
  assert_eq!(
    normalized_if_match(&headers)
      .expect_err("missing If-Match")
      .status(),
    StatusCode::PRECONDITION_REQUIRED
  );
  headers.insert(header::IF_MATCH, "\"r-2041\"".parse().expect("header"));
  assert_eq!(
    normalized_if_match(&headers).expect("strong ETag"),
    "r-2041"
  );
  headers.insert(header::IF_MATCH, "W/\"r-2041\"".parse().expect("header"));
  assert_eq!(
    normalized_if_match(&headers)
      .expect_err("weak ETag")
      .status(),
    StatusCode::BAD_REQUEST
  );
  headers.insert(header::IF_MATCH, "\"r-2041\"".parse().expect("header"));
  headers.append(header::IF_MATCH, "\"r-2042\"".parse().expect("header"));
  assert_eq!(
    normalized_if_match(&headers)
      .expect_err("duplicate If-Match")
      .status(),
    StatusCode::BAD_REQUEST
  );
}

#[test]
fn one_time_response_is_dropped_for_every_noncommitted_terminal() {
  assert!(winner_response_allowed(MutationState::Committed));
  for state in [
    MutationState::RolledBack,
    MutationState::RollbackFailed,
    MutationState::Indeterminate,
    MutationState::Failed,
  ] {
    assert!(
      !winner_response_allowed(state),
      "unexpected winner for {state:?}"
    );
  }
}

#[tokio::test]
async fn operational_precondition_failure_preserves_legacy_response() {
  let response = precondition_failed_response("r-2042");
  assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
  assert!(
    !response
      .headers()
      .contains_key(crate::admin_mutation::IDEMPOTENT_REPLAY_HEADER)
  );
  assert!(
    !response
      .headers()
      .contains_key(crate::admin_mutation::MUTATION_REQUEST_ID_HEADER)
  );
  let body = response
    .into_body()
    .collect()
    .await
    .expect("collect precondition response")
    .to_bytes();
  let payload: serde_json::Value =
    serde_json::from_slice(&body).expect("precondition response JSON");
  assert_eq!(
    payload,
    json!({
      "error": "If-Match does not match the active revision",
      "details": { "expected": "r-2042" },
    })
  );
}

#[tokio::test]
async fn cluster_dispatch_admission_persists_a_routable_durable_receipt() {
  let Some(pool) =
    crate::admin_mutation::postgres_test_support::connect("planner cluster dispatch admission")
      .await
  else {
    return;
  };
  crate::admin_mutation::init_mutation_postgres(&pool)
    .await
    .expect("cluster planner mutation schema initialization");
  let namespace = format!(
    "planner-cluster-dispatch-{}-{}",
    std::process::id(),
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("test clock")
      .as_nanos()
  );
  let audit_runtime = AdminAuditRuntime::test_with_postgres(pool.clone(), namespace.clone())
    .await
    .expect("cluster planner audit schema initialization");
  let key_pair = Ed25519KeyPair::generate().expect("test signer generation");
  let public_key: [u8; 32] = key_pair
    .public_key()
    .as_ref()
    .try_into()
    .expect("Ed25519 public key length");
  let signers = SignerRegistry::new([SignerBinding::ed25519(
    "planner-controller",
    CLUSTER_PRINCIPAL,
    public_key,
  )
  .expect("test signer binding")])
  .expect("test signer registry");
  let target = MutationTarget {
    cluster_id: "planner-edge".to_string(),
    membership_revision: test_digest(b"planner-edge/node-a,node-b"),
  };
  let baseline_digest = test_digest(b"planner cluster baseline");
  let runtime = AdminMutationRuntime::fixed_cluster_for_dispatch_test(
    pool.clone(),
    namespace.clone(),
    signers,
    target.clone(),
    vec!["node-a".to_string(), "node-b".to_string()],
    "node-a".to_string(),
    [23; 32],
    "r-1".to_string(),
    baseline_digest,
  )
  .await
  .expect("ready fixed-member cluster test runtime");

  let body = br#"{"format":"toml","config":"[compression]\\nenabled = false"}"#;
  let (now, issued_at, expires_at): (i64, String, String) = sqlx::query_as(
    "SELECT extract(epoch FROM now())::bigint,
            to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
            to_char((now() + interval '10 minutes') AT TIME ZONE 'UTC',
                    'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
  )
  .fetch_one(&pool)
  .await
  .expect("authoritative mutation test time");
  let unsigned = UnsignedMutationEnvelope {
    version: "1".to_string(),
    signer_id: "planner-controller".to_string(),
    request_id: "018f47a2-7b2c-7b25-8f31-d13db7b4ca71".to_string(),
    issued_at,
    expires_at,
    expected_previous_revision: "r-1".to_string(),
    new_revision: "r-2".to_string(),
    content_digest: test_digest(body),
    target,
  };
  let transcript = mutation_transcript(
    &unsigned,
    SignatureSuite::Ed25519,
    &TranscriptContext {
      method: &Method::POST,
      path_and_query: CLUSTER_MUTATION_PATH,
      ipm_namespace: &namespace,
      authenticated_principal: CLUSTER_PRINCIPAL,
      body,
      precondition_revision: "r-1",
      now_unix_seconds: now,
      maximum_validity_seconds: 900,
      maximum_clock_skew_seconds: 30,
    },
  )
  .expect("cluster mutation transcript");
  let signature = MutationSignature::Ed25519(
    key_pair
      .sign(&transcript)
      .as_ref()
      .try_into()
      .expect("Ed25519 signature length"),
  );
  let encoded = encode_mutation_header(&unsigned, &signature).expect("mutation header encoding");
  let mut headers = HeaderMap::new();
  headers.insert(
    crate::admin_mutation::MUTATION_HEADER,
    encoded.parse().expect("mutation header value"),
  );
  assert!(handles(
    &runtime,
    &Method::POST,
    CLUSTER_MUTATION_PATH,
    &headers,
  ));
  let receipt_path = format!("/admin/v1/mutations/{}", unsigned.request_id);
  assert!(handles(
    &runtime,
    &Method::GET,
    &receipt_path,
    &HeaderMap::new(),
  ));

  let actor = IpmActor {
    name: "planner-controller".to_string(),
    principal: CLUSTER_PRINCIPAL.to_string(),
    subject: "planner-controller".to_string(),
    groups: vec!["release-qualification".to_string()],
  };
  let checks = super::super::admin_cluster_executor::authorization_checks(
    &Method::POST,
    CLUSTER_MUTATION_PATH,
    body,
    CLUSTER_PRINCIPAL,
  )
  .expect("production cluster authorization derivation");
  let evidence =
    crate::admin_mutation::ClusterCommandAuthorization::from_checks(true, false, &checks)
      .expect("cluster authorization evidence");
  let audit = AdminAuditHandle::new(
    "127.0.0.1:8443".parse().expect("test peer address"),
    "https",
    &Method::POST,
    CLUSTER_MUTATION_PATH,
    None,
  );
  audit.set_actor(
    "planner-controller",
    CLUSTER_PRINCIPAL,
    "planner-controller",
    &["release-qualification".to_string()],
  );
  let admission = runtime
    .admit_cluster(
      &headers,
      &Method::POST,
      &CLUSTER_MUTATION_PATH.parse().expect("cluster mutation URI"),
      CLUSTER_PRINCIPAL,
      &actor,
      "mtls",
      false,
      body,
      "config.load",
      "config",
      "r-1",
      "r-1",
      evidence,
      &audit,
      &audit_runtime,
    )
    .await
    .expect("durable cluster dispatch admission");
  let MutationAdmission::Claimed(execution) = admission else {
    panic!("cluster mutation was not durably admitted: {admission:?}");
  };
  assert_eq!(execution.request_id, unsigned.request_id);
  let record = runtime
    .load_mutation(&unsigned.request_id)
    .await
    .expect("load durable cluster receipt")
    .expect("durable cluster receipt exists");
  assert_eq!(record.resource, "config");
  assert_eq!(record.cluster_id.as_deref(), Some("planner-edge"));
  assert_eq!(
    runtime
      .cluster_targets(&unsigned.request_id)
      .await
      .expect("load durable cluster targets")
      .len(),
    2
  );

  let policy = IpmPolicyConfig {
    name: "receipt-reader".to_string(),
    version: "2026-08-08".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: vec!["admin:ReadMutations".to_string()],
      resources: vec!["*".to_string()],
      conditions: Vec::new(),
    }],
  };
  let ipm = IpmRuntime::test_with_actor_policy("oxibelt", actor.clone(), policy);
  let context = IpmRequestContext::default();
  let authorization = AdminAuthorization::new(&actor, &ipm, &context);
  let response = receipt_response(&runtime, &authorization, &receipt_path).await;
  assert_eq!(response.status(), StatusCode::OK);
  let receipt: serde_json::Value = serde_json::from_slice(
    &response
      .into_body()
      .collect()
      .await
      .expect("collect durable receipt")
      .to_bytes(),
  )
  .expect("durable receipt JSON");
  assert_eq!(receipt["request_id"], unsigned.request_id);
  assert_eq!(receipt["state"], "claimed");
  assert_eq!(receipt["target"]["cluster_id"], "planner-edge");
  assert_eq!(receipt["members"].as_array().map(Vec::len), Some(2));

  for query in [
    "DELETE FROM oxibelt_admin_instance_resource_heads WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_instance_heartbeats WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_instance_boot_history WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_mutations WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_mutation_revisions WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_audit WHERE namespace=$1",
  ] {
    sqlx::query(query)
      .bind(&namespace)
      .execute(&pool)
      .await
      .expect("cluster planner integration cleanup");
  }
}
