//! PostgreSQL persistence for encrypted fixed-member mutation artifacts.

use anyhow::{Context, ensure};
use sqlx::{Postgres, Row, Transaction};

use super::artifact::{
  ARTIFACT_ALGORITHM, ARTIFACT_NONCE_BYTES, ARTIFACT_TAG_BYTES, ArtifactBinding,
  MutationArtifactReceipt, SealedArtifact, StoredArtifact, sha256_digest,
};
use super::ledger::validate_identifier;
use super::store::MutationStore;

pub(super) async fn publish(
  store: &MutationStore,
  coordinator_instance_id: &str,
  coordinator_boot_id: &str,
  binding: &ArtifactBinding,
  sealed: &SealedArtifact,
) -> anyhow::Result<MutationArtifactReceipt> {
  binding.validate()?;
  ensure!(
    binding.namespace == store.namespace(),
    "mutation artifact namespace mismatch"
  );
  validate_identifier("coordinator_instance_id", coordinator_instance_id, 256)?;
  validate_identifier("coordinator_boot_id", coordinator_boot_id, 256)?;
  ensure!(
    sealed.ciphertext.len() == sealed.plaintext_len + ARTIFACT_TAG_BYTES,
    "sealed mutation artifact length mismatch"
  );
  ensure!(
    sha256_digest(&sealed.ciphertext) == sealed.ciphertext_digest,
    "sealed mutation artifact ciphertext digest mismatch"
  );

  let mut tx = store.pool().begin().await?;
  let mutation = lock_publishable_mutation(
    &mut tx,
    store.namespace(),
    &binding.request_id,
    coordinator_instance_id,
    coordinator_boot_id,
  )
  .await?;
  ensure_binding_row(binding, &mutation)?;

  if let Some(row) = sqlx::query(
    "SELECT fingerprint, resource, cluster_id, membership_revision, new_revision,
            content_digest, algorithm, nonce, ciphertext, ciphertext_digest,
            plaintext_len
       FROM oxibelt_admin_mutation_artifacts
      WHERE namespace = $1 AND request_id = $2 FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(&binding.request_id)
  .fetch_optional(&mut *tx)
  .await?
  {
    ensure_binding_row(binding, &row)?;
    ensure!(
      row.try_get::<String, _>("algorithm")? == ARTIFACT_ALGORITHM,
      "stored mutation artifact algorithm mismatch"
    );
    let nonce: Vec<u8> = row.try_get("nonce")?;
    let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
    let ciphertext_digest: String = row.try_get("ciphertext_digest")?;
    let plaintext_len = usize::try_from(row.try_get::<i32, _>("plaintext_len")?)
      .context("stored mutation artifact length is invalid")?;
    ensure!(
      nonce.len() == ARTIFACT_NONCE_BYTES
        && ciphertext.len() == plaintext_len + ARTIFACT_TAG_BYTES
        && sha256_digest(&ciphertext) == ciphertext_digest,
      "stored mutation artifact is corrupt"
    );
    let receipt = MutationArtifactReceipt {
      published: false,
      ciphertext_digest,
      plaintext_len,
    };
    tx.commit().await?;
    return Ok(receipt);
  }

  let plaintext_len = i32::try_from(sealed.plaintext_len)
    .context("mutation artifact length exceeds the PostgreSQL range")?;
  sqlx::query(
    "INSERT INTO oxibelt_admin_mutation_artifacts
       (namespace, request_id, fingerprint, resource, cluster_id,
        membership_revision, new_revision, content_digest, algorithm, nonce,
        ciphertext, ciphertext_digest, plaintext_len)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
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
  .bind(plaintext_len)
  .execute(&mut *tx)
  .await
  .context("failed to persist encrypted mutation artifact")?;
  tx.commit().await?;
  Ok(MutationArtifactReceipt {
    published: true,
    ciphertext_digest: sealed.ciphertext_digest.clone(),
    plaintext_len: sealed.plaintext_len,
  })
}

pub(super) async fn fetch_for_member(
  store: &MutationStore,
  instance_id: &str,
  boot_id: &str,
  expected_binding: &ArtifactBinding,
  maximum_plaintext_bytes: usize,
) -> anyhow::Result<StoredArtifact> {
  expected_binding.validate()?;
  ensure!(
    expected_binding.namespace == store.namespace(),
    "mutation artifact namespace mismatch"
  );
  validate_identifier("instance_id", instance_id, 256)?;
  validate_identifier("boot_id", boot_id, 256)?;
  let maximum_ciphertext_bytes = i64::try_from(
    maximum_plaintext_bytes
      .checked_add(ARTIFACT_TAG_BYTES)
      .context("mutation artifact bound overflow")?,
  )
  .context("mutation artifact bound exceeds the PostgreSQL range")?;
  let row = sqlx::query(
    "SELECT artifact.fingerprint, artifact.resource, artifact.cluster_id,
            artifact.membership_revision, artifact.new_revision,
            artifact.content_digest, artifact.algorithm, artifact.nonce,
            artifact.ciphertext, artifact.ciphertext_digest,
            artifact.plaintext_len
       FROM oxibelt_admin_mutation_artifacts artifact
       JOIN oxibelt_admin_mutations mutation
         ON mutation.namespace = artifact.namespace
        AND mutation.request_id = artifact.request_id
       JOIN oxibelt_admin_mutation_targets target
         ON target.namespace = artifact.namespace
        AND target.request_id = artifact.request_id
        AND target.instance_id = $3
       JOIN oxibelt_admin_instance_heartbeats heartbeat
         ON heartbeat.namespace = artifact.namespace
        AND heartbeat.cluster_id = artifact.cluster_id
        AND heartbeat.membership_revision = artifact.membership_revision
        AND heartbeat.instance_id = target.instance_id
        AND heartbeat.boot_id = $4
      WHERE artifact.namespace = $1 AND artifact.request_id = $2
        AND mutation.state NOT IN
          ('committed', 'failed', 'rolled_back', 'rollback_failed', 'indeterminate')
        AND target.state IN
          ('validating', 'applying', 'acked', 'nacked', 'rolling_back')
        AND heartbeat.lease_expires_at > now()
        AND octet_length(artifact.ciphertext) <= $5",
  )
  .bind(store.namespace())
  .bind(&expected_binding.request_id)
  .bind(instance_id)
  .bind(boot_id)
  .bind(maximum_ciphertext_bytes)
  .fetch_optional(store.pool())
  .await?
  .context("encrypted mutation artifact is unavailable for this member")?;
  ensure_binding_row(expected_binding, &row)?;
  ensure!(
    row.try_get::<String, _>("algorithm")? == ARTIFACT_ALGORITHM,
    "stored mutation artifact algorithm mismatch"
  );
  let plaintext_len = usize::try_from(row.try_get::<i32, _>("plaintext_len")?)
    .context("stored mutation artifact length is invalid")?;
  ensure!(
    plaintext_len <= maximum_plaintext_bytes,
    "stored mutation artifact exceeds the configured bound"
  );
  Ok(StoredArtifact {
    binding: expected_binding.clone(),
    nonce: row.try_get("nonce")?,
    ciphertext: row.try_get("ciphertext")?,
    ciphertext_digest: row.try_get("ciphertext_digest")?,
    plaintext_len,
  })
}

async fn lock_publishable_mutation(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  request_id: &str,
  coordinator_instance_id: &str,
  coordinator_boot_id: &str,
) -> anyhow::Result<sqlx::postgres::PgRow> {
  sqlx::query(
    "SELECT mutation.fingerprint, mutation.resource, mutation.cluster_id,
            mutation.membership_revision, mutation.new_revision,
            mutation.content_digest
       FROM oxibelt_admin_mutations mutation
      WHERE mutation.namespace = $1 AND mutation.request_id = $2
        AND mutation.state IN ('claimed', 'validating')
        AND mutation.coordinator_instance_id = $3
        AND mutation.coordinator_lease_expires_at > now()
        AND EXISTS (
          SELECT 1 FROM oxibelt_admin_mutation_targets target
          JOIN oxibelt_admin_instance_heartbeats heartbeat
            ON heartbeat.namespace = target.namespace
           AND heartbeat.cluster_id = mutation.cluster_id
           AND heartbeat.membership_revision = mutation.membership_revision
           AND heartbeat.instance_id = target.instance_id
           AND heartbeat.boot_id = $4
           AND heartbeat.ready = true
           AND heartbeat.lease_expires_at > now()
         WHERE target.namespace = mutation.namespace
           AND target.request_id = mutation.request_id
           AND target.instance_id = $3
        )
      FOR UPDATE",
  )
  .bind(namespace)
  .bind(request_id)
  .bind(coordinator_instance_id)
  .bind(coordinator_boot_id)
  .fetch_optional(&mut **tx)
  .await?
  .context("active mutation coordinator lease is required to publish an artifact")
}

fn ensure_binding_row(
  expected: &ArtifactBinding,
  row: &sqlx::postgres::PgRow,
) -> anyhow::Result<()> {
  ensure!(
    row.try_get::<String, _>("fingerprint")? == expected.fingerprint
      && row.try_get::<String, _>("resource")? == expected.resource
      && row.try_get::<String, _>("cluster_id")? == expected.cluster_id
      && row.try_get::<String, _>("membership_revision")? == expected.membership_revision
      && row.try_get::<String, _>("new_revision")? == expected.new_revision
      && row.try_get::<String, _>("content_digest")? == expected.content_digest,
    "mutation artifact binding conflicts with the durable mutation"
  );
  Ok(())
}
