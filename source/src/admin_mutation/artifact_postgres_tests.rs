//! Opt-in PostgreSQL integration checks for encrypted cluster artifacts.

use std::time::{SystemTime, UNIX_EPOCH};

use super::artifact::{
  ArtifactBinding, MutationArtifactCipher, MutationArtifactPlaintext, sha256_digest,
};
use super::artifact_store;
use super::ledger::{ClaimOutcome, MutationClaim};
use super::rollout_store::{self, HeartbeatUpdate, TargetState, TargetTransition};
use super::store::{MutationStore, init_postgres};

#[tokio::test]
async fn postgres_artifact_is_ciphertext_only_and_bound_to_a_live_member() {
  let Some(pool) = super::postgres_test_support::connect("mutation artifact tests").await else {
    return;
  };
  init_postgres(&pool)
    .await
    .expect("mutation artifact test schema initialization");
  let namespace = format!(
    "artifact-test-{}-{}",
    std::process::id(),
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("test clock")
      .as_nanos()
  );
  let store =
    MutationStore::new_cluster(pool.clone(), namespace.clone()).expect("artifact test store");
  let membership = sha256_digest(b"edge-a,edge-b");
  let old_digest = sha256_digest(b"old config");
  let plaintext = br#"{"config":"exact","secret_reference":"vault://edge/key"}"#;
  let content_digest = sha256_digest(plaintext);
  store
    .initialize_revision(
      "config",
      "r-1",
      &old_digest,
      Some("edge-cluster"),
      Some(&membership),
    )
    .await
    .expect("initial artifact revision");
  let claim = sample_claim(&membership, &content_digest);
  let record = match store.claim(&claim).await.expect("artifact mutation claim") {
    ClaimOutcome::Claimed(record) => record,
    _ => panic!("artifact test must own its mutation claim"),
  };
  let members = vec!["edge-a".to_string(), "edge-b".to_string()];
  rollout_store::register_targets(&store, &claim.request_id, &members)
    .await
    .expect("register artifact targets");
  rollout_store::heartbeat(
    &store,
    &HeartbeatUpdate {
      cluster_id: "edge-cluster".to_string(),
      instance_id: "edge-a".to_string(),
      boot_id: "boot-a".to_string(),
      build_version: oxibelt_build_identity::SHORT_VERSION.to_string(),
      capability_version: "admin-mutation-rollout-v1".to_string(),
      artifact_key_fingerprint: sha256_digest(b"test artifact key"),
      membership_revision: membership.clone(),
      assigned_revision: None,
      applied_revision: "r-1".to_string(),
      applied_digest: old_digest,
      ready: true,
      lease_seconds: 30,
    },
  )
  .await
  .expect("artifact member heartbeat");
  assert!(
    rollout_store::acquire_coordinator_lease(&store, &claim.request_id, "edge-a", 30)
      .await
      .expect("artifact coordinator lease")
  );
  rollout_store::transition_target(
    &store,
    &claim.request_id,
    "edge-a",
    &TargetTransition {
      next: TargetState::Validating,
      boot_id: None,
      applied_revision: None,
      applied_digest: None,
      error_code: None,
    },
  )
  .await
  .expect("artifact member validation assignment");

  let binding = ArtifactBinding::from_record(&namespace, &record).expect("artifact binding");
  let cipher = MutationArtifactCipher::new(&[17; 32], 1024).expect("artifact cipher");
  let sealed = cipher
    .seal(&binding, MutationArtifactPlaintext::new(plaintext.to_vec()))
    .expect("seal artifact");
  assert!(
    artifact_store::publish(&store, "edge-a", "stale-boot", &binding, &sealed)
      .await
      .is_err()
  );
  let first = artifact_store::publish(&store, "edge-a", "boot-a", &binding, &sealed)
    .await
    .expect("publish encrypted artifact");
  assert!(first.published);

  let duplicate = cipher
    .seal(&binding, MutationArtifactPlaintext::new(plaintext.to_vec()))
    .expect("seal duplicate artifact");
  let duplicate = artifact_store::publish(&store, "edge-a", "boot-a", &binding, &duplicate)
    .await
    .expect("idempotent artifact publication");
  assert!(!duplicate.published);
  assert_eq!(duplicate.ciphertext_digest, first.ciphertext_digest);

  assert!(
    artifact_store::fetch_for_member(&store, "edge-a", "stale-boot", &binding, 1024)
      .await
      .is_err()
  );
  let stored = artifact_store::fetch_for_member(&store, "edge-a", "boot-a", &binding, 1024)
    .await
    .expect("fetch member artifact");
  assert_ne!(stored.ciphertext, plaintext);
  let opened = cipher
    .open(&binding, stored)
    .expect("authenticate member artifact");
  assert_eq!(opened.as_bytes(), plaintext);

  cleanup(&pool, &namespace).await;
}

fn sample_claim(membership_revision: &str, content_digest: &str) -> MutationClaim {
  MutationClaim {
    request_id: "018f47a2-7b2c-7b25-8f31-d13db7b4c987".to_string(),
    fingerprint: sha256_digest(b"artifact transcript"),
    principal: "controller".to_string(),
    signer_id: "controller-1".to_string(),
    action: "config.load".to_string(),
    resource: "config".to_string(),
    expected_previous_revision: "r-1".to_string(),
    new_revision: "r-2".to_string(),
    content_digest: content_digest.to_string(),
    cluster_id: Some("edge-cluster".to_string()),
    membership_revision: Some(membership_revision.to_string()),
    issued_at: "2020-01-01T00:00:00Z".to_string(),
    expires_at: "2099-01-01T00:00:00Z".to_string(),
    allowed_clock_skew_seconds: 30,
    retention_seconds: 86_400,
    audit_record_id: 201,
  }
}

async fn cleanup(pool: &sqlx::PgPool, namespace: &str) {
  sqlx::query("DELETE FROM oxibelt_admin_mutations WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete artifact test mutation");
  sqlx::query("DELETE FROM oxibelt_admin_mutation_revisions WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete artifact test revision");
  sqlx::query("DELETE FROM oxibelt_admin_instance_heartbeats WHERE namespace = $1")
    .bind(namespace)
    .execute(pool)
    .await
    .expect("delete artifact test heartbeat");
}
