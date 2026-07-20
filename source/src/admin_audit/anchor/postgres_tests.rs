//! Opt-in dual-PostgreSQL checks for the local outbox and external authority.

use std::str::FromStr;
use std::time::Duration;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::local::{
  AnchorCandidateOutcome, AnchorStreamIdentity, initialize_local_anchor, load_pending_outbox,
  observed_position, pending_usage, record_event_in_transaction, seal_candidate,
};
use super::sink::{
  PostgresAnchorSink, load_terminal_confirmation_checkpoints, promote_terminal_confirmations,
  store_receipt, store_signed_checkpoint,
};
use super::{
  AuditCheckpointBodyV1, SignedAuditCheckpointV1, assemble_signed_checkpoint,
  checkpoint_signing_transcript, verify_checkpoint_signature,
};
use crate::admin_audit::event::{
  ADMIN_AUDIT_SCHEMA_VERSION, AdminAuditEvent, AuditPhase, AuditResult, IntegrityAlgorithm,
  IntegrityEnvelope,
};
use crate::admin_mutation::{
  ClaimOutcome, MutationClaim, MutationStore, StoreRolloutMode, claim_tx_with_mode,
  init_mutation_postgres, load_recoverable_mutations,
};

#[tokio::test]
async fn postgres_authority_and_restart_safe_outbox_contract() {
  let Some(environment) = TestEnvironment::connect().await else {
    return;
  };
  let namespace = format!(
    "anchor-test-{}-{}",
    std::process::id(),
    crate::admin_audit::event::generate_event_id().expect("random test namespace suffix")
  );
  let identity = identity(&namespace);

  initialize_local_anchor(&environment.local)
    .await
    .expect("local anchor schema initialization");
  crate::admin_audit::store::init_postgres(&environment.local)
    .await
    .expect("local audit schema initialization");
  init_mutation_postgres(&environment.local)
    .await
    .expect("local mutation schema initialization");
  let mutation_store = MutationStore::new_cluster(environment.local.clone(), namespace.clone())
    .expect("cluster mutation store");
  mutation_store
    .initialize_revision(
      "config",
      "r-1",
      &digest('1'),
      Some("anchor-test-cluster"),
      Some(&digest('2')),
    )
    .await
    .expect("initialize mutation revision");
  let mut tx = environment
    .local
    .begin()
    .await
    .expect("local anchor transaction");
  let event = event();
  let audit_record_id =
    crate::admin_audit::store::insert_record_returning_id_tx(&mut tx, &namespace, &event)
      .await
      .expect("persist admission audit event");
  let claim = mutation_claim(audit_record_id);
  assert!(matches!(
    claim_tx_with_mode(
      &mut tx,
      &namespace,
      StoreRolloutMode::AdminCluster,
      &claim,
      true,
    )
    .await
    .expect("persist anchor-gated cluster claim"),
    ClaimOutcome::Claimed(_)
  ));
  let outcome = record_event_in_transaction(&mut tx, &identity, &event, true)
    .await
    .expect("stage checkpoint in the local event transaction");
  let AnchorCandidateOutcome::Sealed(outbox) = outcome else {
    panic!("forced first event should seal one local checkpoint");
  };
  let outbox = *outbox;
  tx.commit().await.expect("commit local checkpoint outbox");
  assert!(
    load_recoverable_mutations(&mutation_store, 16)
      .await
      .expect("load gated cluster mutations")
      .is_empty(),
    "a cluster side effect must not become recoverable before external anchoring"
  );

  // A fresh pool models process restart: the unsigned checkpoint must remain
  // durable and recoverable without access to the independent authority.
  environment.local.close().await;
  let restarted_local =
    TestEnvironment::connect_pool(&environment.local_url, "local restart").await;
  initialize_local_anchor(&restarted_local)
    .await
    .expect("idempotent local anchor schema initialization");
  let pending = load_pending_outbox(&restarted_local, &identity)
    .await
    .expect("reload pending checkpoint after restart");
  assert_eq!(pending.len(), 1);
  assert_eq!(pending[0].ordinal, 1);
  assert_eq!(pending[0].body, outbox.body);
  assert!(pending[0].signed.is_none());
  assert_eq!(
    observed_position(&restarted_local, &identity)
      .await
      .expect("restore observed chain position after restart"),
    Some((outbox.body.chain_id.clone(), outbox.body.last_sequence)),
  );
  assert_eq!(
    pending_usage(&restarted_local, &identity)
      .await
      .expect("pending outbox usage"),
    (
      1,
      u64::try_from(serde_json::to_vec(&outbox.body).unwrap().len()).unwrap(),
      None,
    )
  );

  let (checkpoint, public_key) = sign_valid_checkpoint(outbox.body.clone());
  store_signed_checkpoint(&restarted_local, &checkpoint)
    .await
    .expect("persist signed checkpoint before authority submission");
  let recovery_candidates = load_terminal_confirmation_checkpoints(&restarted_local)
    .await
    .expect("load restart confirmation candidates");
  assert_eq!(recovery_candidates, vec![checkpoint.clone()]);
  verify_checkpoint_signature(&checkpoint, &public_key)
    .expect("restart candidate signature must verify under the deployment pin");
  let mut forged_checkpoint = checkpoint.clone();
  forged_checkpoint.signature =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      .to_string();
  assert!(
    verify_checkpoint_signature(&forged_checkpoint, &public_key).is_err(),
    "a locally forged checkpoint must not pass restart confirmation"
  );
  let sink = PostgresAnchorSink::new(
    environment.authority_runtime.clone(),
    environment.authority_id.clone(),
    Duration::from_secs(3),
  );
  sink.preflight().await.expect("authority preflight");
  assert_eq!(
    sink
      .lookup(&namespace, &identity.stream_id, 1)
      .await
      .expect("pre-submit authority lookup"),
    None,
    "local signed evidence alone must not promote a protected mutation"
  );
  let receipt = sink
    .submit(&checkpoint)
    .await
    .expect("first authority append");
  assert_eq!(receipt.authority_id, environment.authority_id);
  assert_eq!(receipt.checkpoint_digest, checkpoint.checkpoint_digest);

  let external = sink
    .lookup(&namespace, &identity.stream_id, 1)
    .await
    .expect("restart authority lookup")
    .expect("authority receipt after append");
  assert_eq!(external.checkpoint_digest, checkpoint.checkpoint_digest);
  promote_terminal_confirmations(&restarted_local, &checkpoint)
    .await
    .expect("promote admission only after exact external confirmation");
  let restarted_mutation_store =
    MutationStore::new_cluster(restarted_local.clone(), namespace.clone())
      .expect("restarted mutation store");
  assert_eq!(
    load_recoverable_mutations(&restarted_mutation_store, 16)
      .await
      .expect("load externally confirmed cluster mutation")
      .len(),
    1,
    "external confirmation must promote without replaying the side effect"
  );
  sqlx::query(
    "UPDATE oxibelt_admin_mutations
        SET state='failed', http_status=503, error_code='anchor_test_failure',
            terminal_audit_record_id=$3, terminal_audit_confirmed_at=NULL
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(&namespace)
  .bind(&claim.request_id)
  .bind(audit_record_id)
  .execute(&restarted_local)
  .await
  .expect("simulate crash after terminal audit receipt but before visibility marker");
  let hidden_terminal = restarted_mutation_store
    .load_mutation(&claim.request_id)
    .await
    .expect("load hidden terminal mutation")
    .expect("hidden terminal mutation exists");
  assert!(hidden_terminal.terminal_anchor_pending());
  assert!(matches!(
    hidden_terminal.classify_existing_claim(&claim),
    ClaimOutcome::InProgress(_)
  ));
  promote_terminal_confirmations(&restarted_local, &checkpoint)
    .await
    .expect("restart confirmation promotes the terminal marker");
  let visible_terminal = restarted_mutation_store
    .load_mutation(&claim.request_id)
    .await
    .expect("load promoted terminal mutation")
    .expect("promoted terminal mutation exists");
  assert!(visible_terminal.terminal_response_ready());
  assert!(matches!(
    visible_terminal.classify_existing_claim(&claim),
    ClaimOutcome::Replay(_)
  ));

  let replay = sink
    .submit(&checkpoint)
    .await
    .expect("idempotent authority retry");
  assert_eq!(replay, receipt);
  assert_eq!(
    sink
      .lookup(&namespace, &identity.stream_id, 1)
      .await
      .expect("authority lookup"),
    Some(receipt.clone())
  );

  store_receipt(&restarted_local, &checkpoint, &receipt)
    .await
    .expect("store external receipt atomically");
  store_receipt(&restarted_local, &checkpoint, &receipt)
    .await
    .expect("replayed external receipt remains idempotent");
  restarted_local.close().await;
  let drained_local =
    TestEnvironment::connect_pool(&environment.local_url, "drained restart").await;
  assert!(
    load_pending_outbox(&drained_local, &identity)
      .await
      .expect("reload drained outbox")
      .is_empty()
  );
  assert_eq!(
    pending_usage(&drained_local, &identity)
      .await
      .expect("drained outbox usage"),
    (0, 0, Some((checkpoint.body.chain_id.clone(), 0)))
  );

  authority_rejects_conflicts_and_discontinuity(&sink, &checkpoint).await;
  least_privilege_roles_are_separated(&environment, &namespace, &identity.stream_id).await;
  authority_accepts_contiguous_second(&sink, &checkpoint).await;
  external_unavailability_is_reported(&environment.authority_id).await;
  candidate_identity_survives_restart_boundary(&drained_local, &namespace).await;
  pending_checkpoint_chain_is_bounded(&drained_local, &sink, &namespace).await;
  cleanup(&drained_local, &namespace).await;
}

async fn candidate_identity_survives_restart_boundary(pool: &sqlx::PgPool, namespace: &str) {
  let candidate_namespace = format!("{namespace}-candidate");
  let mut original = identity(&candidate_namespace);
  original.record_interval = 10;
  let mut tx = pool.begin().await.expect("candidate transaction");
  assert!(matches!(
    record_event_in_transaction(&mut tx, &original, &event(), false)
      .await
      .expect("record unsealed candidate"),
    AnchorCandidateOutcome::Pending
  ));
  tx.commit().await.expect("commit unsealed candidate");

  let mut rotated = original.clone();
  rotated.membership_epoch = "rotated-membership".to_string();
  rotated.deployment_epoch = "rotated-deployment".to_string();
  rotated.signing_key_id = "rotated-signing-key".to_string();
  let AnchorCandidateOutcome::Sealed(sealed) = seal_candidate(pool, &rotated)
    .await
    .expect("seal recovered candidate")
  else {
    panic!("recovered candidate must seal");
  };
  assert_eq!(sealed.body.membership_epoch, original.membership_epoch);
  assert_eq!(sealed.body.deployment_epoch, original.deployment_epoch);
  assert_eq!(sealed.body.signing_key_id, original.signing_key_id);
  cleanup(pool, &candidate_namespace).await;
}

async fn pending_checkpoint_chain_is_bounded(
  pool: &sqlx::PgPool,
  sink: &PostgresAnchorSink,
  namespace: &str,
) {
  let bounded_namespace = format!("{namespace}-bounded");
  let mut bounded = identity(&bounded_namespace);
  bounded.record_interval = 1;
  bounded.max_pending_checkpoints = 2;

  let mut first_tx = pool.begin().await.expect("first pending transaction");
  let AnchorCandidateOutcome::Sealed(first) =
    record_event_in_transaction(&mut first_tx, &bounded, &event_at(0), true)
      .await
      .expect("seal first pending checkpoint")
  else {
    panic!("first pending checkpoint must seal");
  };
  first_tx
    .commit()
    .await
    .expect("commit first pending checkpoint");
  let (first, _) = sign_valid_checkpoint(first.body);
  store_signed_checkpoint(pool, &first)
    .await
    .expect("sign first pending checkpoint");

  let mut second_tx = pool.begin().await.expect("second pending transaction");
  let AnchorCandidateOutcome::Sealed(second) =
    record_event_in_transaction(&mut second_tx, &bounded, &event_at(1), true)
      .await
      .expect("seal second pending checkpoint")
  else {
    panic!("second pending checkpoint must seal");
  };
  second_tx
    .commit()
    .await
    .expect("commit second pending checkpoint");
  assert_eq!(
    second.body.previous_checkpoint_digest,
    first.checkpoint_digest
  );
  let (second, _) = sign_valid_checkpoint(second.body);
  store_signed_checkpoint(pool, &second)
    .await
    .expect("sign second pending checkpoint");

  let mut full_tx = pool.begin().await.expect("full pending transaction");
  assert!(matches!(
    record_event_in_transaction(&mut full_tx, &bounded, &event_at(2), true)
      .await
      .expect("bounded candidate outcome"),
    AnchorCandidateOutcome::CapacityExceeded
  ));
  full_tx
    .commit()
    .await
    .expect("commit bounded candidate marker");
  let mut still_full_tx = pool.begin().await.expect("still-full transaction");
  assert!(matches!(
    record_event_in_transaction(&mut still_full_tx, &bounded, &event_at(3), true)
      .await
      .expect("stable bounded candidate outcome"),
    AnchorCandidateOutcome::CapacityExceeded
  ));
  still_full_tx
    .commit()
    .await
    .expect("commit stable capacity outcome");
  let candidate_last_sequence: i64 = sqlx::query_scalar(
    "SELECT candidate_last_sequence FROM oxibelt_admin_audit_anchor_state
      WHERE namespace=$1 AND stream_id=$2",
  )
  .bind(&bounded_namespace)
  .bind(&bounded.stream_id)
  .fetch_one(pool)
  .await
  .expect("bounded candidate sequence");
  assert_eq!(
    candidate_last_sequence, 3,
    "best-effort capacity must coalesce the full local tail without a sequence gap"
  );
  assert_eq!(
    pending_usage(pool, &bounded)
      .await
      .expect("bounded pending usage")
      .0,
    2
  );
  let first_receipt = sink
    .submit(&first)
    .await
    .expect("submit first pending checkpoint in order");
  store_receipt(pool, &first, &first_receipt)
    .await
    .expect("store first ordered receipt");
  let second_receipt = sink
    .submit(&second)
    .await
    .expect("submit second pending checkpoint in order");
  store_receipt(pool, &second, &second_receipt)
    .await
    .expect("store second ordered receipt");
  let AnchorCandidateOutcome::Sealed(coalesced) = seal_candidate(pool, &bounded)
    .await
    .expect("seal coalesced capacity tail")
  else {
    panic!("capacity tail must seal after ordered receipts free the outbox");
  };
  assert_eq!(coalesced.body.first_sequence, 2);
  assert_eq!(coalesced.body.last_sequence, 3);
  assert_eq!(
    coalesced.body.previous_checkpoint_digest,
    second.checkpoint_digest
  );
  cleanup(pool, &bounded_namespace).await;
}

async fn authority_accepts_contiguous_second(
  sink: &PostgresAnchorSink,
  first: &SignedAuditCheckpointV1,
) {
  let mut body = first.body.clone();
  body.checkpoint_ordinal = 2;
  body.first_sequence = 1;
  body.last_sequence = 1;
  body.chain_head = digest('d');
  body.previous_checkpoint_digest = first.checkpoint_digest.clone();
  let second = sign_for_authority(body, 10);
  let receipt = sink
    .submit(&second)
    .await
    .expect("contiguous second checkpoint");
  assert_eq!(receipt.checkpoint_ordinal, 2);
  assert_eq!(receipt.checkpoint_digest, second.checkpoint_digest);
}

async fn authority_rejects_conflicts_and_discontinuity(
  sink: &PostgresAnchorSink,
  first: &SignedAuditCheckpointV1,
) {
  let mut conflicting_body = first.body.clone();
  conflicting_body.chain_head = digest('e');
  let conflict = sign_for_authority(conflicting_body, 8);
  let error = sink
    .submit(&conflict)
    .await
    .expect_err("same ordinal with different checkpoint must fail");
  assert!(
    error
      .to_string()
      .contains("conflicting Admin audit checkpoint"),
    "unexpected conflict error: {error:#}"
  );

  let mut discontinuous_body = first.body.clone();
  discontinuous_body.checkpoint_ordinal = 2;
  discontinuous_body.first_sequence = 1;
  discontinuous_body.last_sequence = 1;
  discontinuous_body.chain_head = digest('f');
  discontinuous_body.previous_checkpoint_digest = digest('9');
  let discontinuous = sign_for_authority(discontinuous_body, 9);
  let error = sink
    .submit(&discontinuous)
    .await
    .expect_err("wrong predecessor must fail");
  assert!(
    error
      .to_string()
      .contains("Admin audit checkpoint continuity conflict"),
    "unexpected continuity error: {error:#}"
  );
}

async fn least_privilege_roles_are_separated(
  environment: &TestEnvironment,
  namespace: &str,
  stream_id: &str,
) {
  let rows: i64 =
    sqlx::query_scalar("SELECT count(*)::bigint FROM oxibelt_audit_anchor_v1.checkpoints($1,$2)")
      .bind(namespace)
      .bind(stream_id)
      .fetch_one(&environment.authority_verifier)
      .await
      .expect("verifier can enumerate checkpoints");
  assert_eq!(rows, 1);

  let runtime_read = sqlx::query("SELECT * FROM oxibelt_audit_anchor_v1.checkpoints($1,$2)")
    .bind(namespace)
    .bind(stream_id)
    .fetch_all(&environment.authority_runtime)
    .await
    .expect_err("runtime role must not enumerate the verifier feed");
  assert_insufficient_privilege(&runtime_read);

  let verifier_append =
    sqlx::query("SELECT * FROM oxibelt_audit_anchor_v1.append_checkpoint($1::jsonb)")
      .bind("{}")
      .fetch_all(&environment.authority_verifier)
      .await
      .expect_err("verifier role must not append checkpoints");
  assert_insufficient_privilege(&verifier_append);

  let direct_table_read = sqlx::query("SELECT * FROM oxibelt_audit_anchor_v1.checkpoint_log")
    .fetch_all(&environment.authority_verifier)
    .await
    .expect_err("verifier role must not read authority tables directly");
  assert_insufficient_privilege(&direct_table_read);
}

async fn external_unavailability_is_reported(authority_id: &str) {
  let options =
    PgConnectOptions::from_str("postgres://unavailable:unavailable@127.0.0.1:1/unavailable")
      .expect("unavailable test URL parses");
  let pool = PgPoolOptions::new()
    .max_connections(1)
    .acquire_timeout(Duration::from_millis(250))
    .connect_lazy_with(options);
  let sink = PostgresAnchorSink::new(
    pool.clone(),
    authority_id.to_string(),
    Duration::from_millis(500),
  );
  assert!(
    sink.preflight().await.is_err(),
    "unavailable external authority must fail closed at the sink boundary"
  );
  pool.close().await;
}

fn identity(namespace: &str) -> AnchorStreamIdentity {
  AnchorStreamIdentity {
    namespace: namespace.to_string(),
    stream_id: format!("sha256:{}", "a".repeat(64)),
    instance_id: "anchor-test-instance".to_string(),
    cluster_id: None,
    membership_epoch: "single-instance".to_string(),
    deployment_epoch: "anchor-test-deployment".to_string(),
    signing_key_id: "anchor-test-key".to_string(),
    record_interval: 1,
    time_interval_ms: 60_000,
    max_pending_checkpoints: 4,
    max_pending_bytes: 64 * 1024,
  }
}

fn event() -> AdminAuditEvent {
  event_at(0)
}

fn event_at(sequence: u64) -> AdminAuditEvent {
  AdminAuditEvent {
    schema_version: ADMIN_AUDIT_SCHEMA_VERSION.to_string(),
    event_id: "00112233445566778899aabbccddeeff".to_string(),
    timestamp: "2026-07-19T00:00:00.000Z".to_string(),
    timestamp_unix_ms: 1_774_137_600_000,
    instance_id: "anchor-test-instance".to_string(),
    phase: AuditPhase::Terminal,
    request_id: "018f47a2-7b2c-7b25-8f31-d13db7b4c111".to_string(),
    mutation_request_id: None,
    actor: Some("anchor-test".to_string()),
    principal: None,
    subject: None,
    groups: Vec::new(),
    workload_identity_kind: None,
    workload_identity: None,
    workload_principal: None,
    certificate_fingerprint_sha256: None,
    credential_kind: None,
    credential_identity: None,
    credential_principal: None,
    credential_id: None,
    authentication_reason: None,
    peer: "127.0.0.1:1".to_string(),
    source_ip: Some("127.0.0.1".to_string()),
    source_address: Some("127.0.0.1:1".to_string()),
    scheme: "https".to_string(),
    method: "POST".to_string(),
    path: "/admin/v1/config".to_string(),
    service: Some("admin".to_string()),
    operation: "anchor_test".to_string(),
    durability_action: None,
    action: Some("test".to_string()),
    resource: None,
    target_kind: None,
    target_id: None,
    previous_revision: None,
    desired_revision: None,
    content_digest: None,
    status: 200,
    result: AuditResult::Applied,
    outcome: "applied".to_string(),
    error_code: None,
    error: None,
    request_summary: json!({"test": true}),
    integrity: Some(IntegrityEnvelope {
      algorithm: IntegrityAlgorithm::Sha256,
      chain_id: "00112233445566778899aabbccddeeff".to_string(),
      sequence,
      previous_hash: if sequence == 0 {
        "0".repeat(64)
      } else {
        "c".repeat(64)
      },
      event_hash: "c".repeat(64),
      key_id: None,
      tag: None,
    }),
    durable_required: true,
    lifecycle_managed: true,
  }
}

fn sign_for_authority(body: AuditCheckpointBodyV1, signature_byte: u8) -> SignedAuditCheckpointV1 {
  assemble_signed_checkpoint(body, &[signature_byte; 64]).expect("assemble synthetic checkpoint")
}

fn sign_valid_checkpoint(body: AuditCheckpointBodyV1) -> (SignedAuditCheckpointV1, [u8; 32]) {
  let key = Ed25519KeyPair::generate().expect("generate checkpoint signing key");
  let public_key = key
    .public_key()
    .as_ref()
    .try_into()
    .expect("Ed25519 public key length");
  let transcript = checkpoint_signing_transcript(&body).expect("checkpoint signing transcript");
  let signature = key.sign(&transcript);
  (
    assemble_signed_checkpoint(body, signature.as_ref()).expect("assemble valid checkpoint"),
    public_key,
  )
}

fn mutation_claim(audit_record_id: i64) -> MutationClaim {
  MutationClaim {
    request_id: "018f47a2-7b2c-7b25-8f31-d13db7b4c112".to_string(),
    fingerprint: digest('3'),
    principal: "anchor-test-controller".to_string(),
    signer_id: "anchor-test-signer".to_string(),
    action: "config.apply".to_string(),
    resource: "config".to_string(),
    expected_previous_revision: "r-1".to_string(),
    new_revision: "r-2".to_string(),
    content_digest: digest('4'),
    cluster_id: Some("anchor-test-cluster".to_string()),
    membership_revision: Some(digest('2')),
    issued_at: "2026-01-01T00:00:00Z".to_string(),
    expires_at: "2099-01-01T00:00:00Z".to_string(),
    allowed_clock_skew_seconds: 30,
    retention_seconds: 3600,
    audit_record_id,
  }
}

fn digest(nibble: char) -> String {
  format!("sha256:{}", nibble.to_string().repeat(64))
}

fn assert_insufficient_privilege(error: &sqlx::Error) {
  let code = error.as_database_error().and_then(|error| error.code());
  assert_eq!(code.as_deref(), Some("42501"));
}

async fn cleanup(pool: &sqlx::PgPool, namespace: &str) {
  sqlx::query("DELETE FROM oxibelt_admin_mutations WHERE namespace=$1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete mutation test rows");
  sqlx::query("DELETE FROM oxibelt_admin_mutation_revisions WHERE namespace=$1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete mutation revision test rows");
  sqlx::query("DELETE FROM oxibelt_admin_audit WHERE namespace=$1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete local audit test rows");
  sqlx::query("DELETE FROM oxibelt_admin_audit_anchor_outbox WHERE namespace=$1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete local anchor outbox test rows");
  sqlx::query("DELETE FROM oxibelt_admin_audit_anchor_state WHERE namespace=$1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete local anchor state test rows");
}

struct TestEnvironment {
  local_url: String,
  local: sqlx::PgPool,
  authority_runtime: sqlx::PgPool,
  authority_verifier: sqlx::PgPool,
  authority_id: String,
}

impl TestEnvironment {
  async fn connect() -> Option<Self> {
    let required = std::env::var("OXIBELT_REQUIRE_ADMIN_AUDIT_ANCHOR_POSTGRES_TESTS")
      .ok()
      .is_some_and(|value| value == "1");
    let local_url = match required_url("OXIBELT_TEST_ADMIN_AUDIT_LOCAL_POSTGRES_URL", required) {
      Some(value) => value,
      None => return None,
    };
    let runtime_url = required_url(
      "OXIBELT_TEST_ADMIN_AUDIT_ANCHOR_RUNTIME_POSTGRES_URL",
      required,
    )
    .expect("runtime authority URL accompanies the local URL");
    let verifier_url = required_url(
      "OXIBELT_TEST_ADMIN_AUDIT_ANCHOR_VERIFIER_POSTGRES_URL",
      required,
    )
    .expect("verifier authority URL accompanies the local URL");
    let authority_id = required_url("OXIBELT_TEST_ADMIN_AUDIT_ANCHOR_AUTHORITY_ID", required)
      .expect("authority ID accompanies the local URL");
    Some(Self {
      local: Self::connect_pool(&local_url, "local audit database").await,
      authority_runtime: Self::connect_pool(&runtime_url, "runtime authority role").await,
      authority_verifier: Self::connect_pool(&verifier_url, "verifier authority role").await,
      local_url,
      authority_id,
    })
  }

  async fn connect_pool(url: &str, label: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
      .max_connections(4)
      .acquire_timeout(Duration::from_secs(5))
      .connect(url)
      .await
      .unwrap_or_else(|error| panic!("required {label} connection failed: {error}"))
  }
}

fn required_url(name: &str, required: bool) -> Option<String> {
  match std::env::var(name) {
    Ok(value) if !value.trim().is_empty() => Some(value),
    _ if required => panic!("{name} is required by the Admin audit anchor PostgreSQL harness"),
    _ => None,
  }
}
