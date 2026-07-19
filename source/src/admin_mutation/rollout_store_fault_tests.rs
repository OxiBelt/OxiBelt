use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Acquire;

use super::artifact::sha256_digest;
use super::ledger::{ClaimOutcome, MutationClaim, MutationState, TerminalMutation};
use super::rollout_store::{
  CoordinatorFence, ExactMembership, FencedTargetTransition, HeartbeatUpdate, MemberFence,
  ResourceHeadUpdate, RolloutTransitionPlan, SealedCheckpoint, TargetPlan, TargetState,
  acquire_coordinator_fence, apply_transition_plan, guarded_cluster_finish_tx, heartbeat_fenced,
  load_recoverable_mutations, prove_exact_resource_membership, publish_checkpoint,
  publish_resource_head, register_targets, transition_target_fenced,
};
use super::store::{MutationStore, init_postgres};

mod rollout_store_fault_test_support;
use rollout_store_fault_test_support::ActiveFixture;

const CLUSTER: &str = "fault-cluster";
const MEMBERSHIP: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const BUILD: &str = "fault-build";
const CAPABILITY: &str = "admin-mutation-rollout-v1";
const KEY: &str = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
const OTHER_KEY: &str = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
const RESOURCE: &str = "config";
const PRIOR: &str = "r-1";
const CANDIDATE: &str = "r-2";
const REQUEST_ID: &str = "018f47a2-7b2c-7b25-8f31-d13db7b4d001";

#[tokio::test]
async fn postgres_fixed_member_fault_matrix_is_fenced_and_recoverable() {
  let Some(pool) = super::postgres_test_support::connect("cluster rollout fault matrix").await
  else {
    return;
  };
  init_postgres(&pool)
    .await
    .expect("fault matrix schema migration");
  bootstrap_head_publication_fences_stale_boots(&pool).await;
  wrong_identity_and_digest_bindings_fail_closed(&pool).await;
  member_crashes_before_and_after_apply_are_fenced(&pool).await;
  coordinator_lease_expiry_fences_each_rollout_phase(&pool).await;
  coordinator_recovers_every_durable_state(&pool).await;
  rollback_terminal_guards_are_durable(&pool).await;
  postgres_rollback_and_disconnect_do_not_publish_state(&pool).await;
}
async fn bootstrap_head_publication_fences_stale_boots(pool: &sqlx::PgPool) {
  let namespace = unique_namespace("bootstrap-head");
  let store = MutationStore::new_cluster(pool.clone(), namespace.clone()).expect("cluster store");
  let prior_digest = sha256_digest(b"bootstrap prior");
  let mut update = heartbeat("edge-00", "boot-old", &prior_digest);
  update.ready = false;
  let stale = heartbeat_fenced(&store, &update)
    .await
    .expect("unready heartbeat");
  publish_head(&store, &stale, &prior_digest, true)
    .await
    .expect("unready current boot may bootstrap its resource head");

  expire_member(pool, &namespace, "edge-00").await;
  update.boot_id = "boot-current".to_string();
  let current = heartbeat_fenced(&store, &update)
    .await
    .expect("replacement unready heartbeat");
  assert!(
    publish_head(&store, &stale, &prior_digest, true)
      .await
      .is_err(),
    "retired boot must not overwrite a resource head"
  );
  publish_head(&store, &current, &prior_digest, true)
    .await
    .expect("current unready boot may republish its resource head");
  cleanup(pool, &namespace).await;
}

async fn wrong_identity_and_digest_bindings_fail_closed(pool: &sqlx::PgPool) {
  let fixture = ActiveFixture::new(pool, "wrong-bindings", MutationState::Claimed).await;
  assert!(
    prove_exact_resource_membership(
      &fixture.store,
      "wrong-cluster",
      MEMBERSHIP,
      &fixture.member_ids,
      BUILD,
      CAPABILITY,
      KEY,
      RESOURCE,
    )
    .await
    .is_err(),
    "cluster identity must be exact"
  );
  assert!(
    prove_exact_resource_membership(
      &fixture.store,
      CLUSTER,
      &MEMBERSHIP.replace('3', "4"),
      &fixture.member_ids,
      BUILD,
      CAPABILITY,
      KEY,
      RESOURCE,
    )
    .await
    .is_err(),
    "membership revision must be exact"
  );
  assert!(
    prove_exact_resource_membership(
      &fixture.store,
      CLUSTER,
      MEMBERSHIP,
      &fixture.member_ids,
      BUILD,
      CAPABILITY,
      OTHER_KEY,
      RESOURCE,
    )
    .await
    .is_err(),
    "artifact-key fingerprint must be exact"
  );
  assert!(
    publish_head(&fixture.store, &fixture.members[0], "not-a-digest", true)
      .await
      .is_err(),
    "malformed resource artifact digest must be rejected"
  );
  let mut malformed = claim("not-a-digest");
  malformed.request_id = "018f47a2-7b2c-7b25-8f31-d13db7b4d002".to_string();
  malformed.new_revision = "r-3".to_string();
  malformed.audit_record_id = 21002;
  assert!(
    fixture.store.claim(&malformed).await.is_err(),
    "malformed mutation artifact digest must be rejected"
  );
  fixture.cleanup().await;
}

async fn member_crashes_before_and_after_apply_are_fenced(pool: &sqlx::PgPool) {
  let mut fixture = ActiveFixture::new(pool, "stale-target", MutationState::Claimed).await;
  let validation = RolloutTransitionPlan {
    expected_state: MutationState::Claimed,
    next_state: Some(MutationState::Validating),
    canary_instance_id: None,
    phase_timeout_seconds: 30,
    rollback_timeout_seconds: 30,
    targets: fixture
      .member_ids
      .iter()
      .map(|instance_id| TargetPlan {
        instance_id: instance_id.clone(),
        expected_state: TargetState::Pending,
        expected_state_version: 0,
        next_state: TargetState::Validating,
      })
      .collect(),
  };
  fixture.coordinator = apply_transition_plan(&fixture.store, &fixture.coordinator, &validation)
    .await
    .expect("validation assignment");
  for member in &fixture.members {
    transition_target_fenced(
      &fixture.store,
      member,
      REQUEST_ID,
      &FencedTargetTransition {
        expected_state: TargetState::Validating,
        expected_state_version: 1,
        assignment_epoch: fixture.coordinator.coordinator_epoch,
        next_state: TargetState::Validated,
        effect_started: false,
        validation_revision: Some(CANDIDATE.to_string()),
        validation_digest: Some(fixture.candidate_digest.clone()),
        applied_revision: None,
        applied_digest: None,
        restored_revision: None,
        restored_digest: None,
        error_code: None,
      },
    )
    .await
    .expect("member validation evidence");
  }
  let canary = deterministic_canary(REQUEST_ID, &fixture.member_ids);
  fixture.coordinator = apply_transition_plan(
    &fixture.store,
    &fixture.coordinator,
    &RolloutTransitionPlan {
      expected_state: MutationState::Validating,
      next_state: Some(MutationState::CanaryApplying),
      canary_instance_id: Some(canary.clone()),
      phase_timeout_seconds: 30,
      rollback_timeout_seconds: 30,
      targets: vec![TargetPlan {
        instance_id: canary.clone(),
        expected_state: TargetState::Validated,
        expected_state_version: 2,
        next_state: TargetState::ApplyAssigned,
      }],
    },
  )
  .await
  .expect("canary apply assignment");
  let stale = member(&fixture.members, &canary).clone();
  expire_member(pool, &fixture.namespace, &canary).await;
  let current = heartbeat_fenced(
    &fixture.store,
    &heartbeat(&canary, "boot-restarted", &fixture.prior_digest),
  )
  .await
  .expect("replacement member boot");
  publish_head(&fixture.store, &current, &fixture.prior_digest, true)
    .await
    .expect("replacement resource head");
  let transition = FencedTargetTransition {
    expected_state: TargetState::ApplyAssigned,
    expected_state_version: 3,
    assignment_epoch: fixture.coordinator.coordinator_epoch,
    next_state: TargetState::Applying,
    effect_started: true,
    validation_revision: None,
    validation_digest: None,
    applied_revision: None,
    applied_digest: None,
    restored_revision: None,
    restored_digest: None,
    error_code: None,
  };
  assert!(
    transition_target_fenced(&fixture.store, &stale, REQUEST_ID, &transition)
      .await
      .is_err(),
    "stale boot must not execute a durable apply assignment"
  );
  publish_bound_checkpoint(
    &fixture.store,
    &current,
    fixture.coordinator.coordinator_epoch,
    &fixture.prior_digest,
    &fixture.candidate_digest,
  )
  .await;
  transition_target_fenced(&fixture.store, &current, REQUEST_ID, &transition)
    .await
    .expect("current boot may resume the durable assignment");

  publish_candidate_head(&fixture.store, &current, &fixture.candidate_digest)
    .await
    .expect("candidate head before post-apply crash");
  expire_member(pool, &fixture.namespace, &canary).await;
  let mut replacement_heartbeat = heartbeat(&canary, "boot-after-apply", &fixture.candidate_digest);
  replacement_heartbeat.applied_revision = CANDIDATE.to_string();
  let replacement = heartbeat_fenced(&fixture.store, &replacement_heartbeat)
    .await
    .expect("post-apply replacement boot");
  publish_candidate_head(&fixture.store, &replacement, &fixture.candidate_digest)
    .await
    .expect("replacement observes candidate head");
  let ack = FencedTargetTransition {
    expected_state: TargetState::Applying,
    expected_state_version: 4,
    assignment_epoch: fixture.coordinator.coordinator_epoch,
    next_state: TargetState::Acked,
    effect_started: true,
    validation_revision: None,
    validation_digest: None,
    applied_revision: Some(CANDIDATE.to_string()),
    applied_digest: Some(fixture.candidate_digest.clone()),
    restored_revision: None,
    restored_digest: None,
    error_code: None,
  };
  assert!(
    transition_target_fenced(&fixture.store, &current, REQUEST_ID, &ack)
      .await
      .is_err(),
    "expired post-apply boot must not ACK"
  );
  transition_target_fenced(&fixture.store, &replacement, REQUEST_ID, &ack)
    .await
    .expect("replacement boot may prove and ACK the applied candidate");
  fixture.cleanup().await;
}

async fn coordinator_lease_expiry_fences_each_rollout_phase(pool: &sqlx::PgPool) {
  for state in [
    MutationState::Validating,
    MutationState::CanaryApplying,
    MutationState::Expanding,
    MutationState::RollingBack,
  ] {
    let fixture = ActiveFixture::new(pool, state.as_str(), state).await;
    expire_coordinator(pool, &fixture.namespace).await;
    let plan = phase_probe_plan(state, REQUEST_ID, &fixture.member_ids);
    assert!(
      apply_transition_plan(&fixture.store, &fixture.coordinator, &plan)
        .await
        .is_err(),
      "expired {state:?} coordinator must be fenced"
    );
    let takeover = acquire_coordinator_fence(
      &fixture.store,
      REQUEST_ID,
      &fixture.members[1],
      &fixture.exact,
      300,
    )
    .await
    .expect("phase takeover check")
    .expect("phase coordinator takeover");
    assert!(takeover.coordinator_epoch > fixture.coordinator.coordinator_epoch);
    apply_transition_plan(&fixture.store, &takeover, &plan)
      .await
      .expect("new coordinator resumes the durable phase");
    fixture.cleanup().await;
  }
}

async fn coordinator_recovers_every_durable_state(pool: &sqlx::PgPool) {
  for state in [
    MutationState::Claimed,
    MutationState::Validating,
    MutationState::Applying,
    MutationState::CanaryApplying,
    MutationState::CanaryHealthy,
    MutationState::Expanding,
    MutationState::FullyApplied,
    MutationState::RollingBack,
  ] {
    let fixture = ActiveFixture::new(pool, &format!("recovery-{}", state.as_str()), state).await;
    expire_coordinator(pool, &fixture.namespace).await;
    let recoverable = load_recoverable_mutations(&fixture.store, 16)
      .await
      .expect("durable recovery scan");
    assert_eq!(recoverable.len(), 1);
    assert_eq!(recoverable[0].state, state);
    assert!(!recoverable[0].coordinator_lease_live);
    let takeover = acquire_coordinator_fence(
      &fixture.store,
      REQUEST_ID,
      &fixture.members[1],
      &fixture.exact,
      300,
    )
    .await
    .expect("recovery takeover query")
    .expect("recovery takeover");
    assert!(takeover.coordinator_epoch > fixture.coordinator.coordinator_epoch);
    assert_eq!(
      takeover.mutation_state_version,
      fixture.coordinator.mutation_state_version
    );
    fixture.cleanup().await;
  }
}

async fn rollback_terminal_guards_are_durable(pool: &sqlx::PgPool) {
  let fixture = ActiveFixture::new(pool, "rollback-failed", MutationState::RollingBack).await;
  sqlx::query(
    "UPDATE oxibelt_admin_mutation_targets SET state='rolling_back',state_version=1,
       assignment_epoch=$3,boot_id=$4,instance_epoch=$5,effect_started_at=now()
      WHERE namespace=$1 AND request_id=$2 AND instance_id=$6",
  )
  .bind(&fixture.namespace)
  .bind(REQUEST_ID)
  .bind(fixture.coordinator.coordinator_epoch)
  .bind(&fixture.members[0].boot_id)
  .bind(fixture.members[0].instance_epoch)
  .bind(&fixture.members[0].instance_id)
  .execute(pool)
  .await
  .expect("inject uncertain rollback target");
  for terminal in [
    terminal(
      MutationState::RolledBack,
      "rolled_back_without_evidence",
      22001,
    ),
    terminal(MutationState::Failed, "failed_after_effect", 22002),
  ] {
    let mut tx = pool.begin().await.expect("rollback guard transaction");
    assert!(
      guarded_cluster_finish_tx(&mut tx, &fixture.store, &fixture.coordinator, &terminal)
        .await
        .is_err(),
      "unsafe rollback terminal must be rejected"
    );
    tx.rollback().await.expect("rollback rejected terminal");
  }
  let mut tx = pool.begin().await.expect("rollback-failed transaction");
  guarded_cluster_finish_tx(
    &mut tx,
    &fixture.store,
    &fixture.coordinator,
    &terminal(MutationState::RollbackFailed, "rollback_failed", 22003),
  )
  .await
  .expect("failed rollback terminal");
  tx.commit().await.expect("commit rollback-failed terminal");
  assert_resource_remains_reserved(&fixture, "018f47a2-7b2c-7b25-8f31-d13db7b4d003").await;
  fixture.cleanup().await;

  let fixture = ActiveFixture::new(pool, "rollback-timeout", MutationState::RollingBack).await;
  sqlx::query(
    "UPDATE oxibelt_admin_mutations SET rollback_deadline_at=now()-interval '1 second'
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(&fixture.namespace)
  .bind(REQUEST_ID)
  .execute(pool)
  .await
  .expect("expire rollback deadline");
  let mut tx = pool.begin().await.expect("rollback-timeout transaction");
  guarded_cluster_finish_tx(
    &mut tx,
    &fixture.store,
    &fixture.coordinator,
    &terminal(MutationState::Indeterminate, "rollback_timeout", 22004),
  )
  .await
  .expect("rollback timeout becomes indeterminate");
  tx.commit().await.expect("commit rollback timeout");
  assert_resource_remains_reserved(&fixture, "018f47a2-7b2c-7b25-8f31-d13db7b4d004").await;
  fixture.cleanup().await;
}

async fn postgres_rollback_and_disconnect_do_not_publish_state(pool: &sqlx::PgPool) {
  let fixture = ActiveFixture::new(pool, "transaction-faults", MutationState::Claimed).await;
  let mut tx = pool.begin().await.expect("explicit rollback transaction");
  sqlx::query(
    "UPDATE oxibelt_admin_mutations SET state='validating',state_version=state_version+1
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(&fixture.namespace)
  .bind(REQUEST_ID)
  .execute(&mut *tx)
  .await
  .expect("stage rolled-back state");
  tx.rollback().await.expect("explicit database rollback");
  assert_eq!(load_state(&fixture).await, MutationState::Claimed);

  let mut connection = pool.acquire().await.expect("faulted connection");
  let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
    .fetch_one(&mut *connection)
    .await
    .expect("faulted backend pid");
  let mut tx = connection.begin().await.expect("disconnect transaction");
  sqlx::query(
    "UPDATE oxibelt_admin_mutations SET state='validating',state_version=state_version+1
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(&fixture.namespace)
  .bind(REQUEST_ID)
  .execute(&mut *tx)
  .await
  .expect("stage disconnected state");
  let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
    .bind(backend_pid)
    .fetch_one(pool)
    .await
    .expect("terminate transaction backend");
  assert!(
    terminated,
    "fault injector must terminate the transaction backend"
  );
  assert!(tx.commit().await.is_err(), "disconnected commit must fail");
  assert_eq!(load_state(&fixture).await, MutationState::Claimed);
  fixture.cleanup().await;
}

fn heartbeat(instance_id: &str, boot_id: &str, digest: &str) -> HeartbeatUpdate {
  HeartbeatUpdate {
    cluster_id: CLUSTER.to_string(),
    instance_id: instance_id.to_string(),
    boot_id: boot_id.to_string(),
    build_version: BUILD.to_string(),
    capability_version: CAPABILITY.to_string(),
    artifact_key_fingerprint: KEY.to_string(),
    membership_revision: MEMBERSHIP.to_string(),
    assigned_revision: None,
    applied_revision: PRIOR.to_string(),
    applied_digest: digest.to_string(),
    ready: true,
    lease_seconds: 300,
  }
}

async fn publish_head(
  store: &MutationStore,
  member: &MemberFence,
  digest: &str,
  ready: bool,
) -> anyhow::Result<()> {
  publish_resource_head(
    store,
    member,
    &ResourceHeadUpdate {
      resource: RESOURCE.to_string(),
      assigned_revision: None,
      applied_revision: PRIOR.to_string(),
      applied_digest: digest.to_string(),
      ready,
    },
  )
  .await
}

async fn publish_candidate_head(
  store: &MutationStore,
  member: &MemberFence,
  digest: &str,
) -> anyhow::Result<()> {
  publish_resource_head(
    store,
    member,
    &ResourceHeadUpdate {
      resource: RESOURCE.to_string(),
      assigned_revision: None,
      applied_revision: CANDIDATE.to_string(),
      applied_digest: digest.to_string(),
      ready: true,
    },
  )
  .await
}

async fn publish_bound_checkpoint(
  store: &MutationStore,
  member: &MemberFence,
  assignment_epoch: i64,
  prior_digest: &str,
  candidate_digest: &str,
) {
  // Storage validates the AEAD envelope shape even though this fault-matrix
  // fixture never decrypts it: an empty plaintext still carries a 16-byte tag.
  let ciphertext = vec![7; 16];
  publish_checkpoint(
    store,
    member,
    REQUEST_ID,
    &SealedCheckpoint {
      assignment_epoch,
      candidate_revision: CANDIDATE.to_string(),
      candidate_digest: candidate_digest.to_string(),
      prior_revision: PRIOR.to_string(),
      prior_digest: prior_digest.to_string(),
      nonce: vec![9; 12],
      ciphertext_digest: sha256_digest(&ciphertext),
      ciphertext,
      plaintext_len: 0,
    },
  )
  .await
  .expect("bound rollback checkpoint");
}

fn phase_probe_plan(
  state: MutationState,
  request_id: &str,
  members: &[String],
) -> RolloutTransitionPlan {
  let (next, canary) = match state {
    MutationState::Validating => (
      Some(MutationState::CanaryApplying),
      Some(deterministic_canary(request_id, members)),
    ),
    MutationState::CanaryApplying => (
      Some(MutationState::CanaryHealthy),
      Some(deterministic_canary(request_id, members)),
    ),
    MutationState::Expanding => (Some(MutationState::FullyApplied), None),
    MutationState::RollingBack => (None, None),
    _ => panic!("unsupported phase probe"),
  };
  RolloutTransitionPlan {
    expected_state: state,
    next_state: next,
    canary_instance_id: canary,
    phase_timeout_seconds: 30,
    rollback_timeout_seconds: 30,
    targets: Vec::new(),
  }
}

fn terminal(state: MutationState, error: &str, audit_id: i64) -> TerminalMutation {
  TerminalMutation {
    state,
    http_status: 500,
    safe_response: Some(json!({"ok": false})),
    error_code: Some(error.to_string()),
    terminal_audit_record_id: audit_id,
  }
}

async fn assert_resource_remains_reserved(fixture: &ActiveFixture, request_id: &str) {
  let mut later = claim(&sha256_digest(request_id.as_bytes()));
  later.request_id = request_id.to_string();
  later.new_revision = "r-3".to_string();
  later.audit_record_id += 100;
  assert!(matches!(
    fixture.store.claim(&later).await.expect("later claim"),
    ClaimOutcome::RevisionBusy { .. }
  ));
}

async fn load_state(fixture: &ActiveFixture) -> MutationState {
  fixture
    .store
    .load_mutation(REQUEST_ID)
    .await
    .expect("load mutation")
    .expect("stored mutation")
    .state
}

async fn expire_member(pool: &sqlx::PgPool, namespace: &str, instance_id: &str) {
  sqlx::query(
    "UPDATE oxibelt_admin_instance_heartbeats SET lease_expires_at=now()-interval '1 second'
      WHERE namespace=$1 AND cluster_id=$2 AND instance_id=$3",
  )
  .bind(namespace)
  .bind(CLUSTER)
  .bind(instance_id)
  .execute(pool)
  .await
  .expect("expire member lease");
}

async fn expire_coordinator(pool: &sqlx::PgPool, namespace: &str) {
  sqlx::query(
    "UPDATE oxibelt_admin_mutations SET coordinator_lease_expires_at=now()-interval '1 second'
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(namespace)
  .bind(REQUEST_ID)
  .execute(pool)
  .await
  .expect("expire coordinator lease");
}

fn member<'a>(members: &'a [MemberFence], instance_id: &str) -> &'a MemberFence {
  members
    .iter()
    .find(|member| member.instance_id == instance_id)
    .expect("fixture member")
}

fn deterministic_canary(request_id: &str, members: &[String]) -> String {
  members
    .iter()
    .min_by_key(|member| {
      let mut hasher = Sha256::new();
      hasher.update(b"oxibelt-admin-mutation-canary-v1\0");
      hasher.update(request_id.as_bytes());
      hasher.update(b"\0");
      hasher.update(member.as_bytes());
      hasher.finalize()
    })
    .cloned()
    .expect("fixed membership")
}

fn claim(content_digest: &str) -> MutationClaim {
  MutationClaim {
    request_id: REQUEST_ID.to_string(),
    fingerprint: sha256_digest(b"fault mutation"),
    principal: "controller".to_string(),
    signer_id: "controller-1".to_string(),
    action: "config.load".to_string(),
    resource: RESOURCE.to_string(),
    expected_previous_revision: PRIOR.to_string(),
    new_revision: CANDIDATE.to_string(),
    content_digest: content_digest.to_string(),
    cluster_id: Some(CLUSTER.to_string()),
    membership_revision: Some(MEMBERSHIP.to_string()),
    issued_at: "2020-01-01T00:00:00Z".to_string(),
    expires_at: "2099-01-01T00:00:00Z".to_string(),
    allowed_clock_skew_seconds: 30,
    retention_seconds: 86_400,
    audit_record_id: 21001,
  }
}

fn unique_namespace(prefix: &str) -> String {
  format!(
    "{prefix}-{}-{}",
    std::process::id(),
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("test clock")
      .as_nanos()
  )
}

async fn cleanup(pool: &sqlx::PgPool, namespace: &str) {
  for query in [
    "DELETE FROM oxibelt_admin_instance_resource_heads WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_instance_heartbeats WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_instance_boot_history WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_mutations WHERE namespace=$1",
    "DELETE FROM oxibelt_admin_mutation_revisions WHERE namespace=$1",
  ] {
    sqlx::query(query)
      .bind(namespace)
      .execute(pool)
      .await
      .expect("fault matrix cleanup");
  }
}
