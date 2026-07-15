use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use http::HeaderValue;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

use crate::admin_mutation::envelope::sha256_labelled;
use crate::admin_mutation::{
  MutationSignature, SignatureSuite, UnsignedMutationEnvelope, encode_mutation_header,
  mutation_transcript,
};

const PRINCIPAL: &str = "spiffe://example.test/admin-controller";
const MUTATION_PATH: &str = "/admin/v1/config/load";

#[test]
fn disabled_runtime_exposes_no_cluster_artifact_capability() {
  let runtime = AdminMutationRuntime::disabled("default");
  assert!(!runtime.cluster_mode());
  assert!(runtime.artifact_cipher().is_err());
  assert!(ensure_cluster_member(&runtime, "edge-a").is_err());
  assert!(runtime.installed_cluster_controller().is_none());
  assert!(runtime.cluster_rollout_ready());
}

#[tokio::test]
async fn committed_replay_precedes_advanced_operational_and_logical_revisions() {
  Box::pin(committed_replay_test_body()).await;
}

async fn committed_replay_test_body() {
  let Ok(url) = std::env::var("OXIBELT_TEST_MUTATION_POSTGRES_URL") else {
    return;
  };
  let pool = PgPoolOptions::new()
    .max_connections(4)
    .connect(&url)
    .await
    .expect("mutation runtime test PostgreSQL connection");
  init_postgres(&pool)
    .await
    .expect("mutation runtime test schema initialization");
  let namespace = format!(
    "mutation-runtime-test-{}-{}",
    std::process::id(),
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("test clock")
      .as_nanos()
  );
  let audit_runtime = AdminAuditRuntime::test_with_postgres(pool.clone(), namespace.clone())
    .await
    .expect("audit runtime test schema initialization");
  let store = MutationStore::new(pool.clone(), namespace.clone()).expect("mutation runtime store");
  let key_pair = Ed25519KeyPair::generate().expect("test key generation");
  let public_key: [u8; 32] = key_pair
    .public_key()
    .as_ref()
    .try_into()
    .expect("Ed25519 public key length");
  let signers =
    SignerRegistry::new([
      SignerBinding::ed25519("controller-1", PRINCIPAL, public_key).expect("test signer binding"),
    ])
    .expect("test signer registry");
  let target = MutationTarget {
    cluster_id: "single".to_string(),
    membership_revision: sha256_labelled(&[], b"single-member"),
  };
  let runtime = AdminMutationRuntime {
    inner: Arc::new(RuntimeInner {
      mode: AdminMutationMode::Required,
      signers,
      store: Some(store.clone()),
      namespace: "default".to_string(),
      maximum_validity_seconds: 900,
      maximum_clock_skew_seconds: 30,
      retention_seconds: 86_400,
      target: target.clone(),
      rollout_mode: AdminMutationRolloutMode::SingleInstance,
      cluster_id: "single".to_string(),
      members: Vec::new(),
      artifact_cipher: None,
      cluster_controller: OnceLock::new(),
    }),
  };
  let (now, issued_at, expires_at): (i64, String, String) = sqlx::query_as(
    "SELECT extract(epoch FROM now())::bigint,
            to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
            to_char((now() + interval '10 minutes') AT TIME ZONE 'UTC',
                    'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')",
  )
  .fetch_one(&pool)
  .await
  .expect("authoritative mutation test time");
  let body = br#"{"config":"safe"}"#;
  let unsigned = UnsignedMutationEnvelope {
    version: "1".to_string(),
    signer_id: "controller-1".to_string(),
    request_id: "018f47a2-7b2c-7b25-8f31-d13db7b4c127".to_string(),
    issued_at: issued_at.clone(),
    expires_at: expires_at.clone(),
    expected_previous_revision: "r-1".to_string(),
    new_revision: "r-2".to_string(),
    content_digest: sha256_labelled(&[], body),
    target: target.clone(),
  };
  let headers = signed_headers(&key_pair, &unsigned, body, "r-1", now);
  let first_audit = test_audit_handle();
  let execution = match admit(
    &runtime,
    &audit_runtime,
    &headers,
    body,
    "r-1",
    "r-1",
    &first_audit,
  )
  .await
  {
    MutationAdmission::Claimed(execution) => execution,
    admission => panic!("first mutation was not claimed: {admission:?}"),
  };

  assert!(matches!(
    admit(
      &runtime,
      &audit_runtime,
      &headers,
      body,
      "r-1",
      "r-1",
      &test_audit_handle(),
    )
    .await,
    MutationAdmission::InProgress(_)
  ));

  runtime
    .finish(
      &execution,
      StatusCode::OK,
      Some(json!({ "ok": true, "applied_revision": "r-2" })),
      &first_audit,
      &audit_runtime,
    )
    .await
    .expect("commit first mutation");
  let logical_revision = store
    .load_revision("config")
    .await
    .expect("load logical revision")
    .expect("logical revision exists");
  assert_eq!(logical_revision.committed_revision, "r-2");
  assert!(logical_revision.pending_request_id.is_none());

  let replay = admit(
    &runtime,
    &audit_runtime,
    &headers,
    body,
    "r-2",
    "r-1",
    &test_audit_handle(),
  )
  .await;
  let MutationAdmission::Replay(record) = replay else {
    panic!("committed retry was not replayed: {replay:?}");
  };
  assert_eq!(record.http_status, Some(200));
  assert_eq!(
    record.safe_response,
    Some(json!({ "ok": true, "applied_revision": "r-2" }))
  );

  let changed_body = br#"{"config":"changed"}"#;
  let mut conflicting = unsigned.clone();
  conflicting.content_digest = sha256_labelled(&[], changed_body);
  let conflicting_headers = signed_headers(&key_pair, &conflicting, changed_body, "r-1", now);
  assert!(matches!(
    admit(
      &runtime,
      &audit_runtime,
      &conflicting_headers,
      changed_body,
      "r-2",
      "r-1",
      &test_audit_handle(),
    )
    .await,
    MutationAdmission::Conflict(MutationConflict::RequestId)
  ));

  let unknown = UnsignedMutationEnvelope {
    request_id: "028f47a2-7b2c-7b25-8f31-d13db7b4c127".to_string(),
    new_revision: "r-3".to_string(),
    ..unsigned.clone()
  };
  let unknown_headers = signed_headers(&key_pair, &unknown, body, "r-1", now);
  assert!(matches!(
    admit(
      &runtime,
      &audit_runtime,
      &unknown_headers,
      body,
      "r-2",
      "r-1",
      &test_audit_handle(),
    )
    .await,
    MutationAdmission::PreconditionFailed { active_revision } if active_revision == "r-2"
  ));
  assert!(
    runtime
      .load_mutation(&unknown.request_id)
      .await
      .expect("load rejected unknown mutation")
      .is_none()
  );
  assert!(
    store
      .load_revision("config")
      .await
      .expect("reload logical revision")
      .expect("logical revision remains")
      .pending_request_id
      .is_none()
  );

  let stale_logical = UnsignedMutationEnvelope {
    request_id: "038f47a2-7b2c-7b25-8f31-d13db7b4c127".to_string(),
    new_revision: "r-3".to_string(),
    ..unsigned
  };
  let stale_logical_headers = signed_headers(&key_pair, &stale_logical, body, "r-2", now);
  assert!(matches!(
    admit(
      &runtime,
      &audit_runtime,
      &stale_logical_headers,
      body,
      "r-2",
      "r-2",
      &test_audit_handle(),
    )
    .await,
    MutationAdmission::Conflict(MutationConflict::Revision { actual_revision })
      if actual_revision.as_deref() == Some("r-2")
  ));
  assert!(
    runtime
      .load_mutation(&stale_logical.request_id)
      .await
      .expect("load stale logical mutation")
      .is_none()
  );

  cleanup(&pool, &namespace).await;
}

fn signed_headers(
  key_pair: &Ed25519KeyPair,
  unsigned: &UnsignedMutationEnvelope,
  body: &[u8],
  precondition_revision: &str,
  now_unix_seconds: i64,
) -> HeaderMap {
  let transcript = mutation_transcript(
    unsigned,
    SignatureSuite::Ed25519,
    &TranscriptContext {
      method: &Method::POST,
      path_and_query: MUTATION_PATH,
      ipm_namespace: "default",
      authenticated_principal: PRINCIPAL,
      body,
      precondition_revision,
      now_unix_seconds,
      maximum_validity_seconds: 900,
      maximum_clock_skew_seconds: 30,
    },
  )
  .expect("test mutation transcript");
  let signature = MutationSignature::Ed25519(
    key_pair
      .sign(&transcript)
      .as_ref()
      .try_into()
      .expect("Ed25519 signature length"),
  );
  let encoded = encode_mutation_header(unsigned, &signature).expect("encode mutation header");
  let mut headers = HeaderMap::new();
  headers.insert(
    crate::admin_mutation::MUTATION_HEADER,
    HeaderValue::from_str(&encoded).expect("mutation header value"),
  );
  headers
}

#[allow(clippy::too_many_arguments)]
async fn admit(
  runtime: &AdminMutationRuntime,
  audit_runtime: &AdminAuditRuntime,
  headers: &HeaderMap,
  body: &[u8],
  current_revision: &str,
  precondition_revision: &str,
  audit: &AdminAuditHandle,
) -> MutationAdmission {
  runtime
    .admit(
      headers,
      &Method::POST,
      &MUTATION_PATH.parse::<Uri>().expect("mutation URI"),
      PRINCIPAL,
      body,
      "config.load",
      "config",
      current_revision,
      precondition_revision,
      audit,
      audit_runtime,
    )
    .await
    .expect("mutation admission")
}

fn test_audit_handle() -> AdminAuditHandle {
  let audit = AdminAuditHandle::new(
    "127.0.0.1:8443".parse().expect("test peer address"),
    "https",
    &Method::POST,
    MUTATION_PATH,
    None,
  );
  audit.set_actor("controller-1", PRINCIPAL, "controller-1", &[]);
  audit
}

async fn cleanup(pool: &sqlx::PgPool, namespace: &str) {
  sqlx::query("DELETE FROM oxibelt_admin_mutations WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete mutation runtime test rows");
  sqlx::query("DELETE FROM oxibelt_admin_mutation_revisions WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete mutation runtime revision test rows");
  sqlx::query("DELETE FROM oxibelt_admin_audit WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete mutation runtime audit rows");
}
