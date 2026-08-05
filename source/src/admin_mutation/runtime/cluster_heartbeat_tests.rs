use std::collections::HashMap;
use std::sync::atomic::AtomicU8;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use sqlx::PgPool;

use super::super::{MembershipAuthority, RuntimeInner};
use super::*;
use crate::admin_mutation::artifact::MutationArtifactCipher;
use crate::admin_mutation::membership::{MembershipEpoch, MembershipMember};
use crate::admin_mutation::membership_store::MembershipArtifactCiphers;
use crate::admin_mutation::rollout::{
  AdminClusterRolloutController, LocalRolloutStatus, RolloutSettings,
};
use crate::admin_mutation::store::{MAX_STORED_ARTIFACT_BYTES, MutationStore};
use crate::admin_mutation::{MutationTarget, SignerRegistry};
use crate::config::{AdminMembershipMode, AdminMutationMode, AdminMutationRolloutMode};

const CLUSTER_ID: &str = "cluster-a";
const INITIAL_MEMBERSHIP: &str =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn member(id: &str, readiness_key: u8, catchup_key: u8) -> MembershipMember {
  MembershipMember {
    id: id.to_string(),
    readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD
      .encode([readiness_key; 32]),
    catchup_x25519_public_key: base64::engine::general_purpose::STANDARD.encode([catchup_key; 32]),
  }
}

fn active_members() -> Vec<MembershipMember> {
  vec![member("edge-a", 1, 2), member("edge-b", 3, 4)]
}

fn namespace(label: &str) -> String {
  format!(
    "cluster-heartbeat-{label}-{}-{}",
    std::process::id(),
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("test clock")
      .as_nanos()
  )
}

async fn connect(label: &str) -> Option<(PgPool, MutationStore)> {
  let pool =
    crate::admin_mutation::postgres_test_support::connect("cluster heartbeat refresh").await?;
  crate::admin_mutation::store::init_postgres(&pool)
    .await
    .expect("cluster heartbeat membership schema");
  let store = MutationStore::new_cluster(pool.clone(), namespace(label)).expect("test store");
  Some((pool, store))
}

async fn install_active_epoch(
  pool: &PgPool,
  store: &MutationStore,
  epoch: &MembershipEpoch,
) -> String {
  let epoch_digest = epoch.digest().expect("active epoch digest");
  let epoch_sequence = i64::try_from(epoch.sequence).expect("active epoch sequence");
  let mut tx = pool.begin().await.expect("active epoch transaction");
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_heads
       (namespace,cluster_id,active_epoch_digest,active_epoch_sequence)
     VALUES($1,$2,$3,$4)",
  )
  .bind(store.namespace())
  .bind(CLUSTER_ID)
  .bind(&epoch_digest)
  .bind(epoch_sequence)
  .execute(&mut *tx)
  .await
  .expect("active membership head");
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_epochs
       (namespace,cluster_id,epoch_digest,epoch_sequence,predecessor_digest,
        artifact_key_fingerprint,document,authorized_request_id,state,activated_at)
     VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,'active',now())",
  )
  .bind(store.namespace())
  .bind(CLUSTER_ID)
  .bind(&epoch_digest)
  .bind(epoch_sequence)
  .bind(epoch.predecessor.as_deref())
  .bind(epoch.artifact_key_fingerprint.as_deref())
  .bind(serde_json::to_string(epoch).expect("active epoch document"))
  .bind(&epoch.authorized_by_request_id)
  .execute(&mut *tx)
  .await
  .expect("active membership epoch");
  for member in &epoch.members {
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_epoch_members
         (namespace,cluster_id,epoch_digest,instance_id,
          readiness_ed25519_public_key,catchup_x25519_public_key)
       VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(store.namespace())
    .bind(CLUSTER_ID)
    .bind(&epoch_digest)
    .bind(&member.id)
    .bind(&member.readiness_ed25519_public_key)
    .bind(&member.catchup_x25519_public_key)
    .execute(&mut *tx)
    .await
    .expect("active membership member");
  }
  tx.commit().await.expect("commit active membership epoch");
  epoch_digest
}

fn runtime(
  store: MutationStore,
  local_instance_id: &str,
  members: Vec<MembershipMember>,
  artifact_ciphers: MembershipArtifactCiphers,
) -> AdminMutationRuntime {
  AdminMutationRuntime {
    inner: Arc::new(RuntimeInner {
      mode: AdminMutationMode::Required,
      signers: SignerRegistry::default(),
      store: Some(store.clone()),
      namespace: store.namespace().to_string(),
      maximum_validity_seconds: 900,
      maximum_clock_skew_seconds: 30,
      retention_seconds: 86_400,
      rollout_mode: AdminMutationRolloutMode::AdminCluster,
      membership_mode: AdminMembershipMode::Staged,
      cluster_id: CLUSTER_ID.to_string(),
      membership_authority: RwLock::new(MembershipAuthority {
        target: MutationTarget {
          cluster_id: CLUSTER_ID.to_string(),
          membership_revision: INITIAL_MEMBERSHIP.to_string(),
        },
        members: members.iter().map(|member| member.id.clone()).collect(),
        artifact_key_fingerprint: super::super::EMPTY_DIGEST.to_string(),
      }),
      membership_bootstrap_members: members,
      local_instance_id: Some(local_instance_id.to_string()),
      membership_private_keys: None,
      artifact_ciphers: RwLock::new(artifact_ciphers),
      local_membership_heads: RwLock::new(HashMap::new()),
      cluster_controller: OnceLock::new(),
      cluster_worker_state: AtomicU8::new(0),
      winner_responses: Mutex::new(HashMap::new()),
      winner_response_wait: Duration::from_secs(30),
    }),
  }
}

fn controller(
  store: MutationStore,
  local_instance_id: &str,
  members: &[MembershipMember],
) -> AdminClusterRolloutController {
  AdminClusterRolloutController::new(
    store,
    RolloutSettings {
      cluster_id: CLUSTER_ID.to_string(),
      membership_revision: INITIAL_MEMBERSHIP.to_string(),
      members: members.iter().map(|member| member.id.clone()).collect(),
      instance_id: local_instance_id.to_string(),
      allow_learner: true,
      boot_id: "boot-test".to_string(),
      build_version: "test-build".to_string(),
      artifact_key_fingerprint: super::super::EMPTY_DIGEST.to_string(),
      heartbeat_interval: Duration::from_secs(1),
      stale_after: Duration::from_secs(5),
      phase_timeout: Duration::from_secs(10),
      rollback_timeout: Duration::from_secs(10),
      canary_observation: Duration::from_secs(1),
    },
    LocalRolloutStatus {
      assigned_revision: None,
      applied_revision: "config-1".to_string(),
      applied_digest: super::super::EMPTY_DIGEST.to_string(),
      ready: false,
    },
  )
  .expect("test rollout controller")
}

async fn heartbeat_count(pool: &PgPool, store: &MutationStore, instance_id: &str) -> i64 {
  sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_admin_instance_heartbeats
      WHERE namespace=$1 AND cluster_id=$2 AND instance_id=$3",
  )
  .bind(store.namespace())
  .bind(CLUSTER_ID)
  .bind(instance_id)
  .fetch_one(pool)
  .await
  .expect("heartbeat count")
}

#[tokio::test]
async fn keyless_legacy_learner_refreshes_without_participating() {
  let Some((pool, store)) = connect("v1-learner").await else {
    return;
  };
  let members = active_members();
  let epoch = MembershipEpoch::new(
    CLUSTER_ID.to_string(),
    0,
    None,
    members.clone(),
    "activate-v1".to_string(),
  )
  .expect("legacy epoch");
  let epoch_digest = install_active_epoch(&pool, &store, &epoch).await;
  let runtime = runtime(
    store.clone(),
    "edge-learner",
    members.clone(),
    MembershipArtifactCiphers::new(),
  );
  let controller = controller(store.clone(), "edge-learner", &members);

  runtime
    .refresh_staged_membership_authority(&controller)
    .await
    .expect("keyless legacy learner refresh");
  controller
    .heartbeat_once()
    .await
    .expect("learner heartbeat remains a no-op");

  assert_eq!(controller.membership_revision(), epoch_digest);
  assert!(!controller.participating());
  assert!(!controller.ready());
  assert!(controller.member_fence().await.is_err());
  assert_eq!(
    runtime.artifact_key_fingerprint(),
    super::super::EMPTY_DIGEST
  );
  assert!(runtime.artifact_ciphers().is_empty());
  assert_eq!(heartbeat_count(&pool, &store, "edge-learner").await, 0);
}

#[tokio::test]
async fn active_legacy_member_without_cipher_still_fails_closed() {
  let Some((pool, store)) = connect("v1-active-missing-key").await else {
    return;
  };
  let members = active_members();
  let epoch = MembershipEpoch::new(
    CLUSTER_ID.to_string(),
    0,
    None,
    members.clone(),
    "activate-v1".to_string(),
  )
  .expect("legacy epoch");
  let epoch_digest = install_active_epoch(&pool, &store, &epoch).await;
  let previous_members = vec![members[1].clone(), member("edge-c", 5, 6)];
  let runtime = runtime(
    store.clone(),
    "edge-a",
    previous_members.clone(),
    MembershipArtifactCiphers::new(),
  );
  let controller = controller(store.clone(), "edge-a", &previous_members);
  assert!(!controller.participating());

  let error = runtime
    .refresh_staged_membership_authority(&controller)
    .await
    .expect_err("active legacy member without its cipher must fail");

  assert_eq!(
    error.to_string(),
    format!("artifact key for membership revision {epoch_digest} is unavailable")
  );
  assert_eq!(controller.membership_revision(), INITIAL_MEMBERSHIP);
  assert!(!controller.participating());
  assert!(controller.member_fence().await.is_err());
  let authority = runtime.membership_authority();
  assert_eq!(authority.target.membership_revision, INITIAL_MEMBERSHIP);
  assert_eq!(
    authority.artifact_key_fingerprint,
    super::super::EMPTY_DIGEST
  );
  assert!(runtime.artifact_ciphers().is_empty());
  assert_eq!(heartbeat_count(&pool, &store, "edge-a").await, 0);
}

#[tokio::test]
async fn keyed_active_legacy_member_refreshes_and_heartbeats() {
  let Some((pool, store)) = connect("v1-active-keyed").await else {
    return;
  };
  let members = active_members();
  let epoch = MembershipEpoch::new(
    CLUSTER_ID.to_string(),
    0,
    None,
    members.clone(),
    "activate-v1".to_string(),
  )
  .expect("legacy epoch");
  let epoch_digest = install_active_epoch(&pool, &store, &epoch).await;
  let cipher = Arc::new(
    MutationArtifactCipher::new(&[42_u8; 32], MAX_STORED_ARTIFACT_BYTES).expect("legacy cipher"),
  );
  let expected_fingerprint = cipher.key_fingerprint().to_string();
  let mut artifact_ciphers = MembershipArtifactCiphers::new();
  artifact_ciphers.insert(epoch_digest.clone(), cipher);
  let runtime = runtime(store.clone(), "edge-a", members.clone(), artifact_ciphers);
  let controller = controller(store.clone(), "edge-a", &members);

  runtime
    .refresh_staged_membership_authority(&controller)
    .await
    .expect("keyed active legacy member refresh");

  let (membership_revision, artifact_key_fingerprint): (String, String) = sqlx::query_as(
    "SELECT membership_revision,artifact_key_fingerprint
       FROM oxibelt_admin_instance_heartbeats
      WHERE namespace=$1 AND cluster_id=$2 AND instance_id='edge-a'",
  )
  .bind(store.namespace())
  .bind(CLUSTER_ID)
  .fetch_one(&pool)
  .await
  .expect("active member heartbeat");
  assert_eq!(membership_revision, epoch_digest);
  assert_eq!(artifact_key_fingerprint, expected_fingerprint);
  assert!(controller.participating());
  assert!(controller.member_fence().await.is_ok());
  assert_eq!(runtime.artifact_key_fingerprint(), expected_fingerprint);
  assert!(
    runtime
      .artifact_ciphers()
      .contains_key(&membership_revision)
  );
}

#[tokio::test]
async fn v2_learner_uses_durable_fingerprint_without_loading_cipher() {
  let Some((pool, store)) = connect("v2-learner").await else {
    return;
  };
  let members = active_members();
  let cipher =
    MutationArtifactCipher::new(&[24_u8; 32], MAX_STORED_ARTIFACT_BYTES).expect("v2 epoch cipher");
  let expected_fingerprint = cipher.key_fingerprint().to_string();
  let epoch = MembershipEpoch::new_v2(
    CLUSTER_ID.to_string(),
    0,
    None,
    expected_fingerprint.clone(),
    members.clone(),
    "activate-v2".to_string(),
  )
  .expect("v2 epoch");
  let epoch_digest = install_active_epoch(&pool, &store, &epoch).await;
  let runtime = runtime(
    store.clone(),
    "edge-learner",
    members.clone(),
    MembershipArtifactCiphers::new(),
  );
  let controller = controller(store.clone(), "edge-learner", &members);

  runtime
    .refresh_staged_membership_authority(&controller)
    .await
    .expect("v2 learner refresh");
  controller
    .heartbeat_once()
    .await
    .expect("v2 learner heartbeat remains a no-op");

  assert_eq!(controller.membership_revision(), epoch_digest);
  assert!(!controller.participating());
  assert!(!controller.ready());
  assert!(controller.member_fence().await.is_err());
  assert_eq!(runtime.artifact_key_fingerprint(), expected_fingerprint);
  assert!(runtime.artifact_ciphers().is_empty());
  assert_eq!(heartbeat_count(&pool, &store, "edge-learner").await, 0);
}
