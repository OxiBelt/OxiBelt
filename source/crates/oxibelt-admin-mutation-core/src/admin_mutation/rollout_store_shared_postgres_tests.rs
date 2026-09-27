//! PostgreSQL checks for the fenced shared-resource publisher transaction.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use sha2::{Digest, Sha256};

use super::artifact::sha256_digest;
use super::ledger::{ClaimOutcome, MutationClaim, MutationState};
use super::rollout_store::{
  FencedTargetTransition, HeartbeatUpdate, ResourceHeadUpdate, RolloutTransitionPlan,
  SealedCheckpoint, SharedPublicationClaim, SharedPublicationOutcome, SharedPublicationState,
  TargetPlan, TargetState, acquire_coordinator_fence, apply_transition_plan,
  begin_coordinator_transaction, claim_shared_publication, consume_shared_winner_response,
  finish_shared_publication, heartbeat_fenced, prove_exact_resource_membership,
  publish_checkpoint_in_coordinator_transaction, publish_resource_head, register_targets,
  transition_target_fenced,
};
use super::store::{MutationStore, init_postgres};

const CLUSTER: &str = "shared-cluster";
const MEMBERSHIP: &str = "sha256:7777777777777777777777777777777777777777777777777777777777777777";
const KEY: &str = "sha256:8888888888888888888888888888888888888888888888888888888888888888";
const REQUEST_ID: &str = "018f47a2-7b2c-7b25-8f31-d13db7b4e001";

#[tokio::test]
async fn postgres_shared_publication_is_checkpointed_and_consumed_once() {
  let Some(pool) = super::postgres_test_support::connect("shared publication transaction").await
  else {
    return;
  };
  init_postgres(&pool)
    .await
    .expect("shared publisher schema migration");
  let namespace = unique_namespace();
  let store = MutationStore::new_cluster(pool.clone(), namespace.clone()).expect("cluster store");
  let prior_digest = sha256_digest(b"shared prior");
  let candidate_digest = sha256_digest(b"shared candidate");
  let member_ids = vec!["edge-00".to_string(), "edge-01".to_string()];
  let mut members = Vec::new();
  for instance_id in &member_ids {
    let fence = heartbeat_fenced(
      &store,
      &HeartbeatUpdate {
        cluster_id: CLUSTER.to_string(),
        instance_id: instance_id.clone(),
        boot_id: format!("boot-{instance_id}"),
        build_version: "shared-build".to_string(),
        capability_version: "admin-mutation-rollout-v1".to_string(),
        artifact_key_fingerprint: KEY.to_string(),
        membership_revision: MEMBERSHIP.to_string(),
        assigned_revision: None,
        applied_revision: "r-1".to_string(),
        applied_digest: prior_digest.clone(),
        ready: true,
        lease_seconds: 300,
      },
    )
    .await
    .expect("shared member heartbeat");
    publish_resource_head(
      &store,
      &fence,
      &ResourceHeadUpdate {
        resource: "config".to_string(),
        assigned_revision: None,
        applied_revision: "r-1".to_string(),
        applied_digest: prior_digest.clone(),
        ready: true,
      },
    )
    .await
    .expect("shared resource head");
    members.push(fence);
  }
  store
    .initialize_revision(
      "config",
      "r-1",
      &prior_digest,
      Some(CLUSTER),
      Some(MEMBERSHIP),
    )
    .await
    .expect("shared logical head");
  let claim = MutationClaim {
    request_id: REQUEST_ID.to_string(),
    fingerprint: sha256_digest(b"shared fingerprint"),
    principal: "controller".to_string(),
    signer_id: "controller-1".to_string(),
    action: "config.load".to_string(),
    resource: "config".to_string(),
    expected_previous_revision: "r-1".to_string(),
    new_revision: "r-2".to_string(),
    content_digest: candidate_digest.clone(),
    cluster_id: Some(CLUSTER.to_string()),
    membership_revision: Some(MEMBERSHIP.to_string()),
    issued_at: "2020-01-01T00:00:00Z".to_string(),
    expires_at: "2099-01-01T00:00:00Z".to_string(),
    allowed_clock_skew_seconds: 30,
    retention_seconds: 86_400,
    audit_record_id: 23001,
  };
  assert!(matches!(
    store.claim(&claim).await.expect("shared claim"),
    ClaimOutcome::Claimed(_)
  ));
  register_targets(&store, REQUEST_ID, &member_ids)
    .await
    .expect("shared targets");
  let exact = prove_exact_resource_membership(
    &store,
    CLUSTER,
    MEMBERSHIP,
    &member_ids,
    "shared-build",
    "admin-mutation-rollout-v1",
    KEY,
    "config",
  )
  .await
  .expect("shared exact membership");
  let mut coordinator = acquire_coordinator_fence(&store, REQUEST_ID, &members[0], &exact, 300)
    .await
    .expect("shared coordinator query")
    .expect("shared coordinator");
  coordinator = apply_transition_plan(
    &store,
    &coordinator,
    &RolloutTransitionPlan {
      expected_state: MutationState::Claimed,
      next_state: Some(MutationState::Validating),
      canary_instance_id: None,
      phase_timeout_seconds: 30,
      rollback_timeout_seconds: 30,
      targets: member_ids
        .iter()
        .map(|instance_id| TargetPlan {
          instance_id: instance_id.clone(),
          expected_state: TargetState::Pending,
          expected_state_version: 0,
          next_state: TargetState::Validating,
        })
        .collect(),
    },
  )
  .await
  .expect("shared validation assignment");
  for member in &members {
    transition_target_fenced(
      &store,
      member,
      REQUEST_ID,
      &FencedTargetTransition {
        expected_state: TargetState::Validating,
        expected_state_version: 1,
        assignment_epoch: coordinator.coordinator_epoch,
        next_state: TargetState::Validated,
        effect_started: false,
        validation_revision: Some("r-2".to_string()),
        validation_digest: Some(candidate_digest.clone()),
        applied_revision: None,
        applied_digest: None,
        restored_revision: None,
        restored_digest: None,
        error_code: None,
      },
    )
    .await
    .expect("shared validation evidence");
  }
  let canary = deterministic_canary(&member_ids);
  coordinator = apply_transition_plan(
    &store,
    &coordinator,
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
  .expect("shared canary assignment");
  let owner = members
    .iter()
    .find(|member| member.instance_id == canary)
    .expect("canary owner");
  let publication = SharedPublicationClaim {
    operation_kind: claim.action.clone(),
    operation_fingerprint: claim.fingerprint.clone(),
    candidate_revision: claim.new_revision.clone(),
    candidate_digest: claim.content_digest.clone(),
    checkpoint_reference: owner.instance_id.clone(),
    token_producing: false,
  };
  let ciphertext = vec![4; 48];
  let checkpoint = SealedCheckpoint {
    assignment_epoch: coordinator.coordinator_epoch,
    candidate_revision: claim.new_revision.clone(),
    candidate_digest: candidate_digest.clone(),
    prior_revision: claim.expected_previous_revision.clone(),
    prior_digest,
    nonce: vec![3; 12],
    ciphertext_digest: sha256_digest(&ciphertext),
    ciphertext,
    plaintext_len: 32,
  };
  let mut transaction = begin_coordinator_transaction(&store, &coordinator)
    .await
    .expect("shared fenced transaction");
  assert!(matches!(
    claim_shared_publication(&mut transaction, &publication)
      .await
      .expect("first shared publisher"),
    SharedPublicationOutcome::FirstPublisher
  ));
  assert!(
    finish_shared_publication(
      &mut transaction,
      SharedPublicationState::Applied,
      Some(json!({"ok": true, "token_recoverable": false})),
    )
    .await
    .is_err(),
    "publication cannot finish before its durable checkpoint"
  );
  assert!(
    publish_checkpoint_in_coordinator_transaction(&mut transaction, owner, &checkpoint)
      .await
      .expect("central checkpoint")
  );
  let applied = finish_shared_publication(
    &mut transaction,
    SharedPublicationState::Applied,
    Some(json!({"ok": true, "token_recoverable": false})),
  )
  .await
  .expect("checkpointed publication");
  assert_eq!(applied.checkpoint_reference, owner.instance_id);
  assert!(
    consume_shared_winner_response(&mut transaction)
      .await
      .expect("first winner response")
  );
  assert!(
    !consume_shared_winner_response(&mut transaction)
      .await
      .expect("duplicate winner response")
  );
  transaction.commit().await.expect("shared atomic commit");

  let mut replay_tx = begin_coordinator_transaction(&store, &coordinator)
    .await
    .expect("shared replay transaction");
  let SharedPublicationOutcome::Replay(replay) =
    claim_shared_publication(&mut replay_tx, &publication)
      .await
      .expect("shared replay")
  else {
    panic!("shared side effect must not be republished");
  };
  assert_eq!(replay.state, SharedPublicationState::Applied);
  assert!(replay.winner_response_consumed);
  replay_tx.commit().await.expect("shared replay commit");
  cleanup(&pool, &namespace).await;
}

fn deterministic_canary(members: &[String]) -> String {
  members
    .iter()
    .min_by_key(|member| {
      let mut hasher = Sha256::new();
      hasher.update(b"oxibelt-admin-mutation-canary-v1\0");
      hasher.update(REQUEST_ID.as_bytes());
      hasher.update(b"\0");
      hasher.update(member.as_bytes());
      hasher.finalize()
    })
    .cloned()
    .expect("fixed membership")
}

fn unique_namespace() -> String {
  format!(
    "shared-publication-{}-{}",
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
      .expect("shared publisher cleanup");
  }
}
