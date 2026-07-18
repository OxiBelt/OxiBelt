//! Atomic cluster admission and encrypted rollback checkpoints.

use anyhow::{Context, ensure};
use sqlx::{Postgres, Row, Transaction};

use super::fencing::{ExactMembership, MemberFence, lock_exact_membership, require_live_member};
use super::heads::lock_resource_baseline;
use super::shared::FencedCoordinatorTransaction;
use crate::admin_mutation::artifact::{
  ARTIFACT_ALGORITHM, ARTIFACT_NONCE_BYTES, ARTIFACT_TAG_BYTES, ArtifactBinding,
  MutationArtifactReceipt, SealedArtifact, StoredArtifact, is_sha256_digest, sha256_digest,
};
use crate::admin_mutation::ledger::{ClaimOutcome, MutationClaim, validate_identifier};
use crate::admin_mutation::store::{
  MAX_STORED_ARTIFACT_BYTES, MutationStore, StoreRolloutMode, claim_tx_with_mode,
};

pub(crate) struct ClusterAdmission {
  pub(crate) outcome: ClaimOutcome,
  pub(crate) artifact: Option<MutationArtifactReceipt>,
}

#[derive(Debug, Clone)]
pub(crate) struct SealedCheckpoint {
  pub(crate) assignment_epoch: i64,
  pub(crate) candidate_revision: String,
  pub(crate) candidate_digest: String,
  pub(crate) prior_revision: String,
  pub(crate) prior_digest: String,
  pub(crate) nonce: Vec<u8>,
  pub(crate) ciphertext: Vec<u8>,
  pub(crate) ciphertext_digest: String,
  pub(crate) plaintext_len: usize,
}

pub(crate) type StoredCheckpoint = SealedCheckpoint;

pub(crate) async fn is_admission_origin(
  store: &MutationStore,
  request_id: &str,
  member: &MemberFence,
) -> anyhow::Result<bool> {
  validate_identifier("request_id", request_id, 256)?;
  Ok(
    sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_mutations
      WHERE namespace=$1 AND request_id=$2 AND rollout_mode='admin_cluster'
        AND admission_instance_id=$3 AND admission_boot_id=$4
        AND admission_instance_epoch=$5 AND cluster_id=$6 AND membership_revision=$7)",
    )
    .bind(store.namespace())
    .bind(request_id)
    .bind(&member.instance_id)
    .bind(&member.boot_id)
    .bind(member.instance_epoch)
    .bind(&member.cluster_id)
    .bind(&member.membership_revision)
    .fetch_one(store.pool())
    .await?,
  )
}

pub(crate) async fn cluster_admit_tx(
  tx: &mut Transaction<'_, Postgres>,
  store: &MutationStore,
  claim: &MutationClaim,
  exact: &ExactMembership,
  admission_member: &MemberFence,
  sealed: &SealedArtifact,
) -> anyhow::Result<ClusterAdmission> {
  ensure!(
    store.rollout_mode() == StoreRolloutMode::AdminCluster,
    "cluster admission requires cluster store"
  );
  lock_exact_membership(tx, store, exact, false).await?;
  lock_resource_baseline(tx, store, exact).await?;
  ensure!(
    exact.members.contains(admission_member),
    "cluster admission origin is outside exact live membership"
  );
  ensure!(
    claim.cluster_id.as_deref() == Some(exact.cluster_id.as_str())
      && claim.membership_revision.as_deref() == Some(exact.membership_revision.as_str())
      && claim.expected_previous_revision == exact.baseline_revision,
    "cluster admission does not match the exact live baseline"
  );
  let outcome =
    claim_tx_with_mode(tx, store.namespace(), StoreRolloutMode::AdminCluster, claim).await?;
  let ClaimOutcome::Claimed(record) = &outcome else {
    return Ok(ClusterAdmission {
      outcome,
      artifact: None,
    });
  };
  let origin = sqlx::query(
    "UPDATE oxibelt_admin_mutations SET admission_instance_id=$3,admission_boot_id=$4,
       admission_instance_epoch=$5 WHERE namespace=$1 AND request_id=$2
        AND rollout_mode='admin_cluster' AND admission_instance_id IS NULL",
  )
  .bind(store.namespace())
  .bind(&claim.request_id)
  .bind(&admission_member.instance_id)
  .bind(&admission_member.boot_id)
  .bind(admission_member.instance_epoch)
  .execute(&mut **tx)
  .await?;
  ensure!(
    origin.rows_affected() == 1,
    "cluster admission origin was not recorded"
  );
  let durable_digest: String = sqlx::query_scalar(
    "SELECT content_digest FROM oxibelt_admin_mutation_revisions
      WHERE namespace=$1 AND resource=$2 AND pending_request_id=$3",
  )
  .bind(store.namespace())
  .bind(&claim.resource)
  .bind(&claim.request_id)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(
    durable_digest == exact.baseline_digest,
    "cluster member baseline digest differs from the durable logical head"
  );
  let binding = ArtifactBinding::from_record(store.namespace(), record)?;
  ensure!(
    sealed.plaintext_len <= MAX_STORED_ARTIFACT_BYTES
      && sealed.ciphertext.len() == sealed.plaintext_len + ARTIFACT_TAG_BYTES
      && sha256_digest(&sealed.ciphertext) == sealed.ciphertext_digest,
    "invalid sealed cluster artifact"
  );
  for member in &exact.members {
    sqlx::query(
      "INSERT INTO oxibelt_admin_mutation_targets(namespace,request_id,instance_id)
       VALUES($1,$2,$3)",
    )
    .bind(store.namespace())
    .bind(&claim.request_id)
    .bind(&member.instance_id)
    .execute(&mut **tx)
    .await?;
  }
  sqlx::query(
    "INSERT INTO oxibelt_admin_mutation_artifacts(namespace,request_id,fingerprint,resource,
      cluster_id,membership_revision,new_revision,content_digest,algorithm,nonce,ciphertext,
      ciphertext_digest,plaintext_len) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
  )
  .bind(store.namespace())
  .bind(&binding.request_id)
  .bind(&binding.fingerprint)
  .bind(&binding.resource)
  .bind(&binding.cluster_id)
  .bind(&binding.membership_revision)
  .bind(&binding.new_revision)
  .bind(&binding.content_digest)
  .bind(ARTIFACT_ALGORITHM)
  .bind(sealed.nonce.as_slice())
  .bind(sealed.ciphertext.as_slice())
  .bind(&sealed.ciphertext_digest)
  .bind(i32::try_from(sealed.plaintext_len)?)
  .execute(&mut **tx)
  .await?;
  Ok(ClusterAdmission {
    outcome,
    artifact: Some(MutationArtifactReceipt {
      published: true,
      ciphertext_digest: sealed.ciphertext_digest.clone(),
      plaintext_len: sealed.plaintext_len,
    }),
  })
}

pub(crate) async fn publish_checkpoint(
  store: &MutationStore,
  member: &MemberFence,
  request_id: &str,
  checkpoint: &SealedCheckpoint,
) -> anyhow::Result<bool> {
  validate_checkpoint(checkpoint)?;
  let mut tx = store.pool().begin().await?;
  require_live_member(&mut tx, store, member).await?;
  let inserted = insert_checkpoint_tx(
    &mut tx,
    store.namespace(),
    request_id,
    &member.instance_id,
    checkpoint,
    false,
  )
  .await?;
  tx.commit().await?;
  Ok(inserted)
}

/// Persists a central, encrypted typed before-image in the caller's fenced
/// coordinator transaction. The owner is an exact rollout target (normally the
/// deterministic canary), making the publication marker's checkpoint reference
/// stable across coordinator takeover.
pub(crate) async fn publish_checkpoint_in_coordinator_transaction(
  transaction: &mut FencedCoordinatorTransaction<'_>,
  owner: &MemberFence,
  checkpoint: &SealedCheckpoint,
) -> anyhow::Result<bool> {
  validate_checkpoint(checkpoint)?;
  let store_namespace = transaction.store().namespace().to_string();
  let fence = transaction.fence().clone();
  ensure!(
    fence.exact_membership.members.contains(owner),
    "checkpoint owner is outside exact membership"
  );
  insert_checkpoint_tx(
    transaction.transaction(),
    &store_namespace,
    &fence.request_id,
    &owner.instance_id,
    checkpoint,
    true,
  )
  .await
}

async fn insert_checkpoint_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  request_id: &str,
  instance_id: &str,
  checkpoint: &SealedCheckpoint,
  allow_validated_owner: bool,
) -> anyhow::Result<bool> {
  let result = sqlx::query(
    "INSERT INTO oxibelt_admin_mutation_checkpoints(namespace,request_id,instance_id,
      assignment_epoch,candidate_revision,candidate_digest,prior_revision,prior_digest,algorithm,
      nonce,ciphertext,ciphertext_digest,plaintext_len)
     SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
       FROM oxibelt_admin_mutation_targets target
       JOIN oxibelt_admin_mutations mutation USING(namespace,request_id)
       JOIN oxibelt_admin_mutation_revisions revision ON revision.namespace=mutation.namespace
        AND revision.resource=mutation.resource
      WHERE target.namespace=$1 AND target.request_id=$2 AND target.instance_id=$3
        AND target.assignment_epoch=$4
        AND (target.state IN('apply_assigned','applying') OR ($14 AND target.state='validated'))
        AND mutation.new_revision=$5 AND mutation.content_digest=$6
        AND mutation.expected_previous_revision=$7 AND revision.committed_revision=$7
        AND revision.content_digest=$8
     ON CONFLICT(namespace,request_id,instance_id) DO NOTHING",
  )
  .bind(namespace)
  .bind(request_id)
  .bind(instance_id)
  .bind(checkpoint.assignment_epoch)
  .bind(&checkpoint.candidate_revision)
  .bind(&checkpoint.candidate_digest)
  .bind(&checkpoint.prior_revision)
  .bind(&checkpoint.prior_digest)
  .bind(ARTIFACT_ALGORITHM)
  .bind(&checkpoint.nonce)
  .bind(&checkpoint.ciphertext)
  .bind(&checkpoint.ciphertext_digest)
  .bind(i32::try_from(checkpoint.plaintext_len)?)
  .bind(allow_validated_owner)
  .execute(&mut **tx)
  .await?;
  if result.rows_affected() == 1 {
    return Ok(true);
  }
  let exact: bool = sqlx::query_scalar(
    "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_mutation_checkpoints
      WHERE namespace=$1 AND request_id=$2 AND instance_id=$3 AND assignment_epoch=$4
        AND candidate_revision=$5 AND candidate_digest=$6 AND prior_revision=$7
        AND prior_digest=$8 AND nonce=$9 AND ciphertext_digest=$10 AND plaintext_len=$11)",
  )
  .bind(namespace)
  .bind(request_id)
  .bind(instance_id)
  .bind(checkpoint.assignment_epoch)
  .bind(&checkpoint.candidate_revision)
  .bind(&checkpoint.candidate_digest)
  .bind(&checkpoint.prior_revision)
  .bind(&checkpoint.prior_digest)
  .bind(&checkpoint.nonce)
  .bind(&checkpoint.ciphertext_digest)
  .bind(i32::try_from(checkpoint.plaintext_len)?)
  .fetch_one(&mut **tx)
  .await?;
  ensure!(exact, "rollback checkpoint binding conflict");
  Ok(false)
}

pub(crate) async fn fetch_checkpoint(
  store: &MutationStore,
  member: &MemberFence,
  request_id: &str,
  assignment_epoch: i64,
) -> anyhow::Result<StoredCheckpoint> {
  let mut tx = store.pool().begin().await?;
  require_live_member(&mut tx, store, member).await?;
  let row = sqlx::query(
    "SELECT assignment_epoch,candidate_revision,candidate_digest,prior_revision,prior_digest,
      nonce,ciphertext,ciphertext_digest,plaintext_len FROM oxibelt_admin_mutation_checkpoints
     WHERE namespace=$1 AND request_id=$2 AND instance_id=$3 AND assignment_epoch=$4",
  )
  .bind(store.namespace())
  .bind(request_id)
  .bind(&member.instance_id)
  .bind(assignment_epoch)
  .fetch_optional(&mut *tx)
  .await?
  .context("rollback checkpoint unavailable")?;
  tx.commit().await?;
  let checkpoint = SealedCheckpoint {
    assignment_epoch: row.try_get("assignment_epoch")?,
    candidate_revision: row.try_get("candidate_revision")?,
    candidate_digest: row.try_get("candidate_digest")?,
    prior_revision: row.try_get("prior_revision")?,
    prior_digest: row.try_get("prior_digest")?,
    nonce: row.try_get("nonce")?,
    ciphertext: row.try_get("ciphertext")?,
    ciphertext_digest: row.try_get("ciphertext_digest")?,
    plaintext_len: usize::try_from(row.try_get::<i32, _>("plaintext_len")?)?,
  };
  validate_checkpoint(&checkpoint)?;
  Ok(checkpoint)
}

pub(crate) async fn fetch_committed_artifact(
  store: &MutationStore,
  member: &MemberFence,
  resource: &str,
  maximum_plaintext_bytes: usize,
) -> anyhow::Result<Option<StoredArtifact>> {
  validate_identifier("resource", resource, 256)?;
  ensure!(
    maximum_plaintext_bytes <= MAX_STORED_ARTIFACT_BYTES,
    "artifact read bound is too large"
  );
  let mut tx = store.pool().begin().await?;
  require_live_member(&mut tx, store, member).await?;
  let row = sqlx::query(
    "SELECT mutation.request_id,mutation.fingerprint,mutation.principal,mutation.signer_id,
            mutation.action,mutation.resource,mutation.cluster_id,mutation.membership_revision,
            mutation.new_revision,mutation.expected_previous_revision,mutation.content_digest,
            artifact.nonce,artifact.ciphertext,artifact.ciphertext_digest,artifact.plaintext_len
       FROM oxibelt_admin_mutation_revisions revision
       JOIN oxibelt_admin_mutations mutation ON mutation.namespace=revision.namespace
        AND mutation.resource=revision.resource AND mutation.new_revision=revision.committed_revision
        AND mutation.content_digest=revision.content_digest AND mutation.state='committed'
       JOIN oxibelt_admin_mutation_artifacts artifact ON artifact.namespace=mutation.namespace
        AND artifact.request_id=mutation.request_id
       JOIN oxibelt_admin_mutation_targets target ON target.namespace=mutation.namespace
        AND target.request_id=mutation.request_id AND target.instance_id=$5
      WHERE revision.namespace=$1 AND revision.resource=$2 AND revision.cluster_id=$3
        AND revision.membership_revision=$4 AND artifact.plaintext_len<=$6",
  )
  .bind(store.namespace())
  .bind(resource)
  .bind(&member.cluster_id)
  .bind(&member.membership_revision)
  .bind(&member.instance_id)
  .bind(i32::try_from(maximum_plaintext_bytes)?)
  .fetch_optional(&mut *tx)
  .await?;
  let Some(row) = row else {
    tx.commit().await?;
    return Ok(None);
  };
  let binding = ArtifactBinding {
    namespace: store.namespace().to_string(),
    request_id: row.try_get("request_id")?,
    fingerprint: row.try_get("fingerprint")?,
    principal: row.try_get("principal")?,
    signer_id: row.try_get("signer_id")?,
    action: row.try_get("action")?,
    resource: row.try_get("resource")?,
    cluster_id: row.try_get("cluster_id")?,
    membership_revision: row.try_get("membership_revision")?,
    new_revision: row.try_get("new_revision")?,
    expected_previous_revision: row.try_get("expected_previous_revision")?,
    content_digest: row.try_get("content_digest")?,
  };
  binding.validate()?;
  let stored = StoredArtifact {
    binding,
    nonce: row.try_get("nonce")?,
    ciphertext: row.try_get("ciphertext")?,
    ciphertext_digest: row.try_get("ciphertext_digest")?,
    plaintext_len: usize::try_from(row.try_get::<i32, _>("plaintext_len")?)?,
  };
  ensure!(
    stored.nonce.len() == ARTIFACT_NONCE_BYTES
      && stored.ciphertext.len() == stored.plaintext_len + ARTIFACT_TAG_BYTES
      && sha256_digest(&stored.ciphertext) == stored.ciphertext_digest,
    "committed mutation artifact is corrupt"
  );
  tx.commit().await?;
  Ok(Some(stored))
}

fn validate_checkpoint(value: &SealedCheckpoint) -> anyhow::Result<()> {
  ensure!(
    value.assignment_epoch > 0,
    "checkpoint assignment epoch must be positive"
  );
  for (name, field) in [
    ("candidate_revision", &value.candidate_revision),
    ("candidate_digest", &value.candidate_digest),
    ("prior_revision", &value.prior_revision),
    ("prior_digest", &value.prior_digest),
  ] {
    validate_identifier(name, field, 256)?;
  }
  ensure!(
    is_sha256_digest(&value.candidate_digest) && is_sha256_digest(&value.prior_digest),
    "checkpoint digests must be canonical SHA-256"
  );
  ensure!(
    value.nonce.len() == ARTIFACT_NONCE_BYTES
      && value.plaintext_len <= MAX_STORED_ARTIFACT_BYTES
      && value.ciphertext.len() == value.plaintext_len + ARTIFACT_TAG_BYTES
      && sha256_digest(&value.ciphertext) == value.ciphertext_digest,
    "invalid sealed rollback checkpoint"
  );
  Ok(())
}
