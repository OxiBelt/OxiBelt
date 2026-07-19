//! Opt-in PostgreSQL checks for fixed-member fencing and guarded convergence.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use sha2::{Digest, Sha256};

use super::artifact::sha256_digest;
use super::ledger::{ClaimOutcome, MutationClaim, MutationState, TerminalMutation};
use super::rollout_store::{
  FencedTargetTransition, HeartbeatUpdate, ResourceHeadUpdate, RolloutTransitionPlan,
  SealedCheckpoint, TargetPlan, TargetState, acquire_coordinator_fence, apply_transition_plan,
  guarded_cluster_finish_tx, heartbeat_fenced, load_recoverable_mutations,
  prove_exact_resource_membership, publish_checkpoint, publish_resource_head, register_targets,
  transition_target_fenced,
};
use super::store::{MutationStore, init_postgres};

const CLUSTER: &str = "fencing-cluster";
const MEMBERSHIP: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const BUILD: &str = "test-build";
const CAPABILITY: &str = "admin-mutation-rollout-v1";
const KEY: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const RESOURCE: &str = "config";
const PRIOR: &str = "r-1";
const CANDIDATE: &str = "r-2";

#[tokio::test]
async fn postgres_exact_membership_accepts_two_and_larger_fixed_sets() {
  let Some(pool) = super::postgres_test_support::connect("cluster membership size tests").await
  else {
    return;
  };
  init_postgres(&pool)
    .await
    .expect("cluster schema migration");
  let digest = sha256_digest(b"shared baseline");
  for count in [2, 16] {
    let namespace = unique_namespace(&format!("cluster-size-{count}"));
    let store = MutationStore::new_cluster(pool.clone(), namespace.clone()).expect("cluster store");
    let expected = members(count);
    for member in &expected {
      publish_member(&store, member, &format!("boot-{member}"), PRIOR, &digest).await;
    }
    let proof = prove_exact_resource_membership(
      &store, CLUSTER, MEMBERSHIP, &expected, BUILD, CAPABILITY, KEY, RESOURCE,
    )
    .await
    .expect("exact fixed membership");
    assert_eq!(proof.members.len(), count);
    cleanup(&pool, &namespace).await;
  }
}

#[tokio::test]
async fn postgres_cluster_fences_every_phase_and_commits_only_exact_acks() {
  let Some(pool) = super::postgres_test_support::connect("cluster fencing tests").await else {
    return;
  };
  init_postgres(&pool)
    .await
    .expect("cluster schema migration");
  // A second initialization must observe the completed migration instead of
  // rerunning constraint upgrades.
  init_postgres(&pool)
    .await
    .expect("idempotent cluster schema migration");
  let namespace = unique_namespace("cluster-fence");
  let store = MutationStore::new_cluster(pool.clone(), namespace.clone()).expect("cluster store");
  let prior_digest = sha256_digest(b"prior configuration");
  let candidate_digest = sha256_digest(b"candidate configuration");
  let members = members(3);
  let mut fences = Vec::new();
  for member in &members {
    fences.push(
      publish_member(
        &store,
        member,
        &format!("boot-{member}"),
        PRIOR,
        &prior_digest,
      )
      .await,
    );
  }
  let exact = prove_exact_resource_membership(
    &store, CLUSTER, MEMBERSHIP, &members, BUILD, CAPABILITY, KEY, RESOURCE,
  )
  .await
  .expect("exact three-member baseline");
  assert_eq!(exact.baseline_revision, PRIOR);
  assert_eq!(exact.baseline_digest, prior_digest);

  assert!(
    prove_exact_resource_membership(
      &store,
      CLUSTER,
      MEMBERSHIP,
      &members[..2],
      BUILD,
      CAPABILITY,
      KEY,
      RESOURCE,
    )
    .await
    .is_err(),
    "extra live members must fail exact proof"
  );
  let duplicate = vec![members[0].clone(), members[0].clone(), members[2].clone()];
  assert!(
    prove_exact_resource_membership(
      &store, CLUSTER, MEMBERSHIP, &duplicate, BUILD, CAPABILITY, KEY, RESOURCE,
    )
    .await
    .is_err(),
    "duplicate configured identity must fail exact proof"
  );
  assert!(
    heartbeat_fenced(
      &store,
      &heartbeat(&members[0], "different-live-boot", PRIOR, &prior_digest,)
    )
    .await
    .is_err(),
    "a live duplicate boot must be rejected"
  );

  sqlx::query(
    "UPDATE oxibelt_admin_instance_heartbeats SET lease_expires_at=now()-interval '1 second'
      WHERE namespace=$1 AND cluster_id=$2 AND instance_id=$3",
  )
  .bind(&namespace)
  .bind(CLUSTER)
  .bind(&members[2])
  .execute(&pool)
  .await
  .expect("expire member");
  assert!(
    prove_exact_resource_membership(
      &store, CLUSTER, MEMBERSHIP, &members, BUILD, CAPABILITY, KEY, RESOURCE,
    )
    .await
    .is_err(),
    "stale member must fail exact proof"
  );
  let retired_boot = fences[2].boot_id.clone();
  fences[2] = publish_member(&store, &members[2], "boot-restarted", PRIOR, &prior_digest).await;
  assert!(
    fences[2].instance_epoch > 1,
    "replacement boot must advance the member epoch"
  );
  assert!(
    heartbeat_fenced(
      &store,
      &heartbeat(&members[2], &retired_boot, PRIOR, &prior_digest,)
    )
    .await
    .is_err(),
    "retired boot cannot reclaim the resource head"
  );

  store
    .initialize_revision(
      RESOURCE,
      PRIOR,
      &prior_digest,
      Some(CLUSTER),
      Some(MEMBERSHIP),
    )
    .await
    .expect("cluster logical head");
  let claim = sample_claim(&candidate_digest);
  assert!(matches!(
    store.claim(&claim).await.expect("cluster claim"),
    ClaimOutcome::Claimed(_)
  ));
  register_targets(&store, &claim.request_id, &members)
    .await
    .expect("fixed targets");
  let exact = prove_exact_resource_membership(
    &store, CLUSTER, MEMBERSHIP, &members, BUILD, CAPABILITY, KEY, RESOURCE,
  )
  .await
  .expect("exact admission proof");
  let coordinator = acquire_coordinator_fence(&store, &claim.request_id, &fences[0], &exact, 30)
    .await
    .expect("coordinator acquisition")
    .expect("coordinator fence");
  assert!(
    acquire_coordinator_fence(&store, &claim.request_id, &fences[1], &exact, 30)
      .await
      .expect("contending coordinator")
      .is_none()
  );

  let validation = RolloutTransitionPlan {
    expected_state: MutationState::Claimed,
    next_state: Some(MutationState::Validating),
    canary_instance_id: None,
    phase_timeout_seconds: 30,
    rollback_timeout_seconds: 30,
    targets: members
      .iter()
      .map(|instance_id| TargetPlan {
        instance_id: instance_id.clone(),
        expected_state: TargetState::Pending,
        expected_state_version: 0,
        next_state: TargetState::Validating,
      })
      .collect(),
  };
  let coordinator = apply_transition_plan(&store, &coordinator, &validation)
    .await
    .expect("atomic validation assignment");
  assert!(
    apply_transition_plan(&store, &coordinator, &validation)
      .await
      .is_err(),
    "duplicate phase CAS must be rejected"
  );
  assert_eq!(
    load_recoverable_mutations(&store, 16)
      .await
      .expect("recovery scan")
      .len(),
    1
  );

  for fence in &fences {
    transition_target_fenced(
      &store,
      fence,
      &claim.request_id,
      &FencedTargetTransition {
        expected_state: TargetState::Validating,
        expected_state_version: 1,
        assignment_epoch: coordinator.coordinator_epoch,
        next_state: TargetState::Validated,
        effect_started: false,
        validation_revision: Some(CANDIDATE.to_string()),
        validation_digest: Some(candidate_digest.clone()),
        applied_revision: None,
        applied_digest: None,
        restored_revision: None,
        restored_digest: None,
        error_code: None,
      },
    )
    .await
    .expect("validated target");
  }
  sqlx::query(
    "UPDATE oxibelt_admin_mutations SET coordinator_lease_expires_at=now()-interval '1 second'
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(&namespace)
  .bind(&claim.request_id)
  .execute(&pool)
  .await
  .expect("expire coordinator");
  let canary = deterministic_canary(&claim.request_id, &members);
  let canary_plan = RolloutTransitionPlan {
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
  };
  assert!(
    apply_transition_plan(&store, &coordinator, &canary_plan)
      .await
      .is_err(),
    "expired coordinator cannot assign canary"
  );
  let coordinator = acquire_coordinator_fence(&store, &claim.request_id, &fences[1], &exact, 30)
    .await
    .expect("coordinator takeover")
    .expect("new coordinator fence");
  assert!(coordinator.coordinator_epoch > 1);
  let mut coordinator = apply_transition_plan(&store, &coordinator, &canary_plan)
    .await
    .expect("fenced deterministic canary assignment");
  apply_member(
    &store,
    &claim.request_id,
    member_fence(&fences, &canary),
    coordinator.coordinator_epoch,
    &prior_digest,
    &candidate_digest,
  )
  .await;

  coordinator = apply_transition_plan(
    &store,
    &coordinator,
    &RolloutTransitionPlan {
      expected_state: MutationState::CanaryApplying,
      next_state: Some(MutationState::CanaryHealthy),
      canary_instance_id: Some(canary.clone()),
      phase_timeout_seconds: 30,
      rollback_timeout_seconds: 30,
      targets: Vec::new(),
    },
  )
  .await
  .expect("canary observation phase");
  let expansion_members = members
    .iter()
    .filter(|member| **member != canary)
    .cloned()
    .collect::<Vec<_>>();
  coordinator = apply_transition_plan(
    &store,
    &coordinator,
    &RolloutTransitionPlan {
      expected_state: MutationState::CanaryHealthy,
      next_state: Some(MutationState::Expanding),
      canary_instance_id: Some(canary.clone()),
      phase_timeout_seconds: 30,
      rollback_timeout_seconds: 30,
      targets: expansion_members
        .iter()
        .map(|instance_id| TargetPlan {
          instance_id: instance_id.clone(),
          expected_state: TargetState::Validated,
          expected_state_version: 2,
          next_state: TargetState::ApplyAssigned,
        })
        .collect(),
    },
  )
  .await
  .expect("expansion assignment");
  for member in &expansion_members {
    apply_member(
      &store,
      &claim.request_id,
      member_fence(&fences, member),
      coordinator.coordinator_epoch,
      &prior_digest,
      &candidate_digest,
    )
    .await;
  }
  coordinator = apply_transition_plan(
    &store,
    &coordinator,
    &RolloutTransitionPlan {
      expected_state: MutationState::Expanding,
      next_state: Some(MutationState::FullyApplied),
      canary_instance_id: Some(canary),
      phase_timeout_seconds: 30,
      rollback_timeout_seconds: 30,
      targets: Vec::new(),
    },
  )
  .await
  .expect("fully applied transition");
  let mut tx = pool.begin().await.expect("guarded terminal transaction");
  guarded_cluster_finish_tx(
    &mut tx,
    &store,
    &coordinator,
    &TerminalMutation {
      state: MutationState::Committed,
      http_status: 200,
      safe_response: Some(json!({"ok": true, "token_recoverable": false})),
      error_code: None,
      terminal_audit_record_id: 9001,
    },
  )
  .await
  .expect("all-ACK guarded commit");
  tx.commit().await.expect("commit guarded terminal");
  assert!(matches!(
    store.claim(&claim).await.expect("terminal duplicate"),
    ClaimOutcome::Replay(_)
  ));
  assert_eq!(
    store
      .load_revision(RESOURCE)
      .await
      .expect("load head")
      .expect("head")
      .committed_revision,
    CANDIDATE
  );
  let blocked_resource = "blocked-config";
  let blocked_digest = sha256_digest(b"blocked baseline");
  for fence in &fences {
    publish_resource_head(
      &store,
      fence,
      &ResourceHeadUpdate {
        resource: blocked_resource.to_string(),
        assigned_revision: None,
        applied_revision: "b-1".to_string(),
        applied_digest: blocked_digest.clone(),
        ready: true,
      },
    )
    .await
    .expect("blocking resource head");
  }
  store
    .initialize_revision(
      blocked_resource,
      "b-1",
      &blocked_digest,
      Some(CLUSTER),
      Some(MEMBERSHIP),
    )
    .await
    .expect("blocking logical head");
  let mut blocked = sample_claim(&sha256_digest(b"uncertain candidate"));
  blocked.request_id = "018f47a2-7b2c-7b25-8f31-d13db7b4c889".to_string();
  blocked.resource = blocked_resource.to_string();
  blocked.expected_previous_revision = "b-1".to_string();
  blocked.new_revision = "b-2".to_string();
  blocked.audit_record_id = 8002;
  assert!(matches!(
    store.claim(&blocked).await.expect("blocking claim"),
    ClaimOutcome::Claimed(_)
  ));
  register_targets(&store, &blocked.request_id, &members)
    .await
    .expect("blocking targets");
  let blocked_exact = prove_exact_resource_membership(
    &store,
    CLUSTER,
    MEMBERSHIP,
    &members,
    BUILD,
    CAPABILITY,
    KEY,
    blocked_resource,
  )
  .await
  .expect("blocking resource proof");
  let blocked_fence =
    acquire_coordinator_fence(&store, &blocked.request_id, &fences[0], &blocked_exact, 30)
      .await
      .expect("blocking coordinator")
      .expect("blocking fence");
  let mut blocked_tx = pool.begin().await.expect("indeterminate transaction");
  guarded_cluster_finish_tx(
    &mut blocked_tx,
    &store,
    &blocked_fence,
    &TerminalMutation {
      state: MutationState::Indeterminate,
      http_status: 500,
      safe_response: None,
      error_code: Some("mutation_indeterminate".to_string()),
      terminal_audit_record_id: 9002,
    },
  )
  .await
  .expect("indeterminate terminal");
  blocked_tx.commit().await.expect("commit indeterminate");
  let mut later = blocked.clone();
  later.request_id = "018f47a2-7b2c-7b25-8f31-d13db7b4c890".to_string();
  later.new_revision = "b-3".to_string();
  later.audit_record_id = 8003;
  assert!(
    matches!(
      store.claim(&later).await.expect("blocked later claim"),
      ClaimOutcome::RevisionBusy { .. }
    ),
    "indeterminate must retain the reservation"
  );
  sqlx::query(
    "UPDATE oxibelt_admin_mutations SET expires_at='2021-01-02T00:00:00Z',
            retention_until='2021-01-02T00:00:00Z'
      WHERE namespace=$1 AND request_id=$2",
  )
  .bind(&namespace)
  .bind(&claim.request_id)
  .execute(&pool)
  .await
  .expect("expire active committed receipt for pruning test");
  assert_eq!(
    store
      .delete_expired_terminal_records(16)
      .await
      .expect("active-head pruning check"),
    0,
    "the active committed cluster head and its artifact must be retained"
  );
  cleanup(&pool, &namespace).await;
}

async fn publish_member(
  store: &MutationStore,
  instance_id: &str,
  boot_id: &str,
  revision: &str,
  digest: &str,
) -> super::rollout_store::MemberFence {
  let fence = heartbeat_fenced(store, &heartbeat(instance_id, boot_id, revision, digest))
    .await
    .expect("fenced heartbeat");
  publish_resource_head(
    store,
    &fence,
    &ResourceHeadUpdate {
      resource: RESOURCE.to_string(),
      assigned_revision: None,
      applied_revision: revision.to_string(),
      applied_digest: digest.to_string(),
      ready: true,
    },
  )
  .await
  .expect("resource head");
  fence
}

fn heartbeat(instance_id: &str, boot_id: &str, revision: &str, digest: &str) -> HeartbeatUpdate {
  HeartbeatUpdate {
    cluster_id: CLUSTER.to_string(),
    instance_id: instance_id.to_string(),
    boot_id: boot_id.to_string(),
    build_version: BUILD.to_string(),
    capability_version: CAPABILITY.to_string(),
    artifact_key_fingerprint: KEY.to_string(),
    membership_revision: MEMBERSHIP.to_string(),
    assigned_revision: None,
    applied_revision: revision.to_string(),
    applied_digest: digest.to_string(),
    ready: true,
    lease_seconds: 30,
  }
}

async fn apply_member(
  store: &MutationStore,
  request_id: &str,
  fence: &super::rollout_store::MemberFence,
  assignment_epoch: i64,
  prior_digest: &str,
  candidate_digest: &str,
) {
  let ciphertext = vec![u8::try_from(fence.instance_epoch).unwrap_or(1); 16];
  publish_checkpoint(
    store,
    fence,
    request_id,
    &SealedCheckpoint {
      assignment_epoch,
      candidate_revision: CANDIDATE.to_string(),
      candidate_digest: candidate_digest.to_string(),
      prior_revision: PRIOR.to_string(),
      prior_digest: prior_digest.to_string(),
      nonce: vec![7; 12],
      ciphertext_digest: sha256_digest(&ciphertext),
      ciphertext,
      plaintext_len: 0,
    },
  )
  .await
  .expect("rollback checkpoint");
  transition_target_fenced(
    store,
    fence,
    request_id,
    &FencedTargetTransition {
      expected_state: TargetState::ApplyAssigned,
      expected_state_version: 3,
      assignment_epoch,
      next_state: TargetState::Applying,
      effect_started: true,
      validation_revision: None,
      validation_digest: None,
      applied_revision: None,
      applied_digest: None,
      restored_revision: None,
      restored_digest: None,
      error_code: None,
    },
  )
  .await
  .expect("effect checkpoint");
  publish_resource_head(
    store,
    fence,
    &ResourceHeadUpdate {
      resource: RESOURCE.to_string(),
      assigned_revision: Some(CANDIDATE.to_string()),
      applied_revision: CANDIDATE.to_string(),
      applied_digest: candidate_digest.to_string(),
      ready: true,
    },
  )
  .await
  .expect("candidate head");
  transition_target_fenced(
    store,
    fence,
    request_id,
    &FencedTargetTransition {
      expected_state: TargetState::Applying,
      expected_state_version: 4,
      assignment_epoch,
      next_state: TargetState::Acked,
      effect_started: false,
      validation_revision: None,
      validation_digest: None,
      applied_revision: Some(CANDIDATE.to_string()),
      applied_digest: Some(candidate_digest.to_string()),
      restored_revision: None,
      restored_digest: None,
      error_code: None,
    },
  )
  .await
  .expect("candidate ACK");
}

fn member_fence<'a>(
  fences: &'a [super::rollout_store::MemberFence],
  instance_id: &str,
) -> &'a super::rollout_store::MemberFence {
  fences
    .iter()
    .find(|fence| fence.instance_id == instance_id)
    .expect("member fence")
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
    .expect("non-empty membership")
}

fn sample_claim(content_digest: &str) -> MutationClaim {
  MutationClaim {
    request_id: "018f47a2-7b2c-7b25-8f31-d13db7b4c888".to_string(),
    fingerprint: sha256_digest(b"fenced mutation"),
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
    audit_record_id: 8001,
  }
}

fn members(count: usize) -> Vec<String> {
  (0..count).map(|index| format!("edge-{index:02}")).collect()
}
fn unique_namespace(prefix: &str) -> String {
  format!(
    "{prefix}-{}-{}",
    std::process::id(),
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("clock")
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
      .expect("cleanup");
  }
}
