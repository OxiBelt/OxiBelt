//! PostgreSQL authority for staged Admin membership.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use anyhow::{Context, bail, ensure};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use zeroize::Zeroize as _;

use super::artifact::{
  ARTIFACT_ALGORITHM, ArtifactBinding, MutationArtifactCipher, MutationArtifactPlaintext,
  StoredArtifact, artifact_key_fingerprint,
};
use super::membership::{
  MEMBERSHIP_CAPABILITY_VERSION, MEMBERSHIP_DOCUMENT_VERSION, MembershipActivationRequest,
  MembershipCancelRequest, MembershipEpoch, MembershipKeyProof, MembershipMember,
  MembershipReadinessReceipt, MembershipTransitionKind, MembershipTransitionRequest,
  MembershipTransitionState,
};
use super::membership_crypto::{
  CATCHUP_ALGORITHM, CatchupBinding, EPOCH_KEY_WRAP_ALGORITHM, EpochKeyBinding, StoredCatchupChunk,
  StoredEpochKeyWrap, open_catchup_chunk, seal_catchup_chunk, unwrap_epoch_artifact_key,
  wrap_epoch_artifact_key,
};
use super::store::MutationStore;

const MAX_CATCHUP_RECORDS: usize = 1_024;
const MAX_CATCHUP_ARTIFACTS: usize = 64;
const MAX_MEMBERSHIP_EPOCH_KEYS: usize = 64;
const MEMBERSHIP_EVIDENCE_FRESHNESS_SECONDS: u64 = 300;

pub(crate) type MembershipArtifactCiphers = HashMap<String, Arc<MutationArtifactCipher>>;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MembershipHead {
  pub(crate) cluster_id: String,
  pub(crate) active_epoch_digest: Option<String>,
  pub(crate) active_epoch_sequence: Option<i64>,
  pub(crate) state_version: i64,
  pub(crate) updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MembershipTransition {
  pub(crate) transition_id: String,
  pub(crate) kind: String,
  pub(crate) state: String,
  pub(crate) state_version: i64,
  pub(crate) source_epoch_digest: Option<String>,
  pub(crate) target_epoch_digest: String,
  pub(crate) member_id: Option<String>,
  pub(crate) proposal_request_id: String,
  pub(crate) activation_request_id: Option<String>,
  pub(crate) blocking_reason: Option<String>,
  pub(crate) catchup_cursor: i64,
  pub(crate) catchup_digest: Option<String>,
  pub(crate) checkpoint_digest: Option<String>,
  pub(crate) journal_tail_digest: Option<String>,
  pub(crate) verified_position: Option<i64>,
  pub(crate) capability_result: String,
  pub(crate) key_proof_count: i32,
  pub(crate) key_proof_required: i32,
  pub(crate) receipt_count: i32,
  pub(crate) fence_cutoff: Option<i64>,
  pub(crate) created_at: String,
  pub(crate) updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MembershipStatus {
  pub(crate) mode: &'static str,
  pub(crate) head: Option<MembershipHead>,
  pub(crate) active_epoch: Option<MembershipEpoch>,
  pub(crate) required_members: Vec<String>,
  pub(crate) pending_transition: Option<MembershipTransition>,
  pub(crate) recent_transitions: Vec<MembershipTransition>,
  pub(crate) fenced_members: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MembershipCatchupChunk {
  pub(crate) chunk_index: i32,
  pub(crate) algorithm: String,
  pub(crate) ephemeral_public_key: String,
  pub(crate) nonce: String,
  pub(crate) ciphertext: String,
  pub(crate) ciphertext_digest: String,
  pub(crate) plaintext_len: i32,
}

#[derive(Debug, Clone)]
pub(crate) struct ActiveMembershipAuthority {
  pub(crate) epoch_digest: String,
  pub(crate) members: Vec<String>,
  pub(crate) epoch_version: u32,
  pub(crate) artifact_key_fingerprint: Option<String>,
  pub(crate) epoch: MembershipEpoch,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingMembershipReconciliation {
  pub(crate) transition: MembershipTransition,
  pub(crate) epoch: MembershipEpoch,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipCatchupLogicalHead {
  pub(crate) resource: String,
  pub(crate) committed_revision: String,
  pub(crate) content_digest: String,
  pub(crate) membership_revision: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipCatchupJournalEntry {
  pub(crate) position: u64,
  pub(crate) previous_entry_digest: String,
  pub(crate) entry_digest: String,
  pub(crate) request_id: String,
  pub(crate) resource: String,
  pub(crate) state: String,
  pub(crate) expected_previous_revision: String,
  pub(crate) new_revision: String,
  pub(crate) content_digest: String,
  pub(crate) membership_revision: Option<String>,
  pub(crate) artifact_digest: Option<String>,
  pub(crate) artifact_plaintext_len: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipCatchupArtifact {
  pub(crate) namespace: String,
  pub(crate) request_id: String,
  pub(crate) fingerprint: String,
  pub(crate) principal: String,
  pub(crate) signer_id: String,
  pub(crate) action: String,
  pub(crate) resource: String,
  pub(crate) cluster_id: String,
  pub(crate) membership_revision: String,
  pub(crate) new_revision: String,
  pub(crate) expected_previous_revision: String,
  pub(crate) content_digest: String,
  pub(crate) encoded_plaintext: String,
}

impl Drop for MembershipCatchupArtifact {
  fn drop(&mut self) {
    self.encoded_plaintext.zeroize();
  }
}

impl MembershipCatchupArtifact {
  pub(crate) fn binding(&self) -> anyhow::Result<ArtifactBinding> {
    let binding = ArtifactBinding {
      namespace: self.namespace.clone(),
      request_id: self.request_id.clone(),
      fingerprint: self.fingerprint.clone(),
      principal: self.principal.clone(),
      signer_id: self.signer_id.clone(),
      action: self.action.clone(),
      resource: self.resource.clone(),
      cluster_id: self.cluster_id.clone(),
      membership_revision: self.membership_revision.clone(),
      new_revision: self.new_revision.clone(),
      expected_previous_revision: self.expected_previous_revision.clone(),
      content_digest: self.content_digest.clone(),
    };
    binding.validate()?;
    Ok(binding)
  }

  pub(crate) fn plaintext(&self) -> anyhow::Result<MutationArtifactPlaintext> {
    let bytes = base64::engine::general_purpose::STANDARD
      .decode(&self.encoded_plaintext)
      .context("membership checkpoint artifact is not base64")?;
    ensure!(
      base64::engine::general_purpose::STANDARD.encode(&bytes) == self.encoded_plaintext,
      "membership checkpoint artifact is not canonical base64"
    );
    ensure!(
      bytes.len() <= super::store::MAX_STORED_ARTIFACT_BYTES,
      "membership checkpoint artifact exceeds its bound"
    );
    Ok(MutationArtifactPlaintext::with_signed_digest(
      bytes,
      self.content_digest.clone(),
    ))
  }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MembershipCatchupManifestV2 {
  pub(crate) format: String,
  pub(crate) cluster_id: String,
  pub(crate) transition_id: String,
  pub(crate) member_id: String,
  pub(crate) source_epoch: String,
  pub(crate) target_epoch: String,
  pub(crate) artifact_key_fingerprint: String,
  pub(crate) key_wrap_digest: String,
  pub(crate) build_version: String,
  pub(crate) capability_version: String,
  pub(crate) logical_heads: Vec<MembershipCatchupLogicalHead>,
  pub(crate) checkpoint_artifacts: Vec<MembershipCatchupArtifact>,
  pub(crate) journal_tail: Vec<MembershipCatchupJournalEntry>,
  pub(crate) checkpoint_digest: String,
  pub(crate) journal_tail_digest: String,
  pub(crate) verified_position: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum MembershipMutationCheckpoint {
  Proposal {
    cluster_id: String,
    transition_id: String,
    target_epoch_digest: String,
    created_head: bool,
  },
  ActivationAuthorization {
    cluster_id: String,
    transition_id: String,
    target_epoch_digest: String,
    activation_request_id: String,
    previous_state_version: i64,
  },
  Cancellation {
    cluster_id: String,
    transition_id: String,
    target_epoch_digest: String,
    cancellation_request_id: String,
    previous_state: String,
    previous_state_version: i64,
    previous_blocking_reason: Option<String>,
  },
}

impl MembershipMutationCheckpoint {
  pub(crate) fn encode_plaintext(&self) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(self)?)
  }

  pub(crate) fn decode_plaintext(value: &[u8]) -> anyhow::Result<Self> {
    Ok(serde_json::from_slice(value)?)
  }
}

pub(crate) async fn load_membership_status(
  store: &MutationStore,
  cluster_id: &str,
  bootstrap_members: &[MembershipMember],
) -> anyhow::Result<MembershipStatus> {
  super::ledger::validate_identifier("cluster_id", cluster_id, 253)?;
  let head = sqlx::query(
    "SELECT cluster_id,active_epoch_digest,active_epoch_sequence,state_version,
            updated_at::text AS updated_at
       FROM oxibelt_admin_membership_heads
      WHERE namespace=$1 AND cluster_id=$2",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_optional(store.pool())
  .await?
  .map(|row| {
    Ok::<_, sqlx::Error>(MembershipHead {
      cluster_id: row.try_get("cluster_id")?,
      active_epoch_digest: row.try_get("active_epoch_digest")?,
      active_epoch_sequence: row.try_get("active_epoch_sequence")?,
      state_version: row.try_get("state_version")?,
      updated_at: row.try_get("updated_at")?,
    })
  })
  .transpose()?;
  let pending_transition = sqlx::query(
    "SELECT transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
            member_id,proposal_request_id,activation_request_id,blocking_reason,
            catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
            verified_position,capability_result,key_proof_count,key_proof_required,
            receipt_count,fence_cutoff,
            created_at::text AS created_at,updated_at::text AS updated_at
       FROM oxibelt_admin_membership_transitions
      WHERE namespace=$1 AND cluster_id=$2
        AND state NOT IN ('active','cancelled','indeterminate')
      ORDER BY created_at ASC LIMIT 1",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_optional(store.pool())
  .await?
  .as_ref()
  .map(transition_from_row)
  .transpose()?;
  let active_epoch = if let Some(digest) = head
    .as_ref()
    .and_then(|value| value.active_epoch_digest.as_deref())
  {
    let row = sqlx::query(
      "SELECT document::text AS document,artifact_key_fingerprint
         FROM oxibelt_admin_membership_epochs
        WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='active'",
    )
    .bind(store.namespace())
    .bind(cluster_id)
    .bind(digest)
    .fetch_one(store.pool())
    .await?;
    let document: String = row.try_get("document")?;
    let stored_fingerprint: Option<String> = row.try_get("artifact_key_fingerprint")?;
    let epoch: MembershipEpoch = serde_json::from_str(&document)?;
    ensure!(
      epoch.digest()? == digest && epoch.artifact_key_fingerprint == stored_fingerprint,
      "active membership epoch digest is invalid"
    );
    ensure!(
      head
        .as_ref()
        .and_then(|value| value.active_epoch_sequence)
        .and_then(|value| u64::try_from(value).ok())
        == Some(epoch.sequence),
      "active membership head sequence is inconsistent with the epoch document"
    );
    let indexed_rows = sqlx::query(
      "SELECT instance_id,readiness_ed25519_public_key,catchup_x25519_public_key
         FROM oxibelt_admin_membership_epoch_members
        WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3
        ORDER BY instance_id ASC LIMIT 1025",
    )
    .bind(store.namespace())
    .bind(cluster_id)
    .bind(digest)
    .fetch_all(store.pool())
    .await?;
    verify_epoch_member_index(&epoch, &indexed_rows)?;
    Some(epoch)
  } else {
    None
  };
  let required_members = active_epoch
    .as_ref()
    .map(|epoch| {
      epoch
        .canonical_members()
        .into_iter()
        .map(|member| member.id.clone())
        .collect()
    })
    .unwrap_or_else(|| {
      let mut members = bootstrap_members
        .iter()
        .map(|member| member.id.clone())
        .collect::<Vec<_>>();
      members.sort();
      members
    });
  let recent_rows = sqlx::query(
    "SELECT transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
            member_id,proposal_request_id,activation_request_id,blocking_reason,
            catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
            verified_position,capability_result,key_proof_count,key_proof_required,
            receipt_count,fence_cutoff,
            created_at::text AS created_at,updated_at::text AS updated_at
       FROM oxibelt_admin_membership_transitions
      WHERE namespace=$1 AND cluster_id=$2 ORDER BY created_at DESC LIMIT 32",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_all(store.pool())
  .await?;
  let recent_transitions = recent_rows
    .iter()
    .map(transition_from_row)
    .collect::<anyhow::Result<Vec<_>>>()?;
  let fenced_members = sqlx::query_scalar(
    "SELECT member_id FROM (
       SELECT DISTINCT ON (member_id) member_id,kind,state,created_at
         FROM oxibelt_admin_membership_transitions
        WHERE namespace=$1 AND cluster_id=$2 AND member_id IS NOT NULL
          AND state='active'
          AND kind IN ('join','rejoin','maintenance','remove')
        ORDER BY member_id,created_at DESC,transition_id DESC
     ) latest
     WHERE kind IN ('maintenance','remove')
     ORDER BY member_id ASC LIMIT 1025",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_all(store.pool())
  .await?;
  ensure!(
    fenced_members.len() <= 1_024,
    "membership fenced-member status exceeds its bound"
  );
  Ok(MembershipStatus {
    mode: "staged",
    head,
    active_epoch,
    required_members,
    pending_transition,
    recent_transitions,
    fenced_members,
  })
}

pub(crate) async fn durable_membership_cluster_ids(
  store: &MutationStore,
) -> anyhow::Result<Vec<String>> {
  let cluster_ids: Vec<String> = sqlx::query_scalar(
    "SELECT cluster_id
       FROM (
         SELECT cluster_id FROM oxibelt_admin_membership_heads WHERE namespace=$1
         UNION
         SELECT cluster_id FROM oxibelt_admin_membership_epochs WHERE namespace=$1
         UNION
         SELECT cluster_id FROM oxibelt_admin_membership_transitions WHERE namespace=$1
       ) durable
      ORDER BY cluster_id ASC LIMIT 2",
  )
  .bind(store.namespace())
  .fetch_all(store.pool())
  .await?;
  for cluster_id in &cluster_ids {
    super::ledger::validate_identifier("durable membership cluster_id", cluster_id, 253)?;
  }
  Ok(cluster_ids)
}

pub(crate) async fn durable_membership_cluster_ids_if_present(
  pool: &sqlx::PgPool,
  namespace: &str,
) -> anyhow::Result<Vec<String>> {
  super::ledger::validate_identifier("membership namespace", namespace, 256)?;
  let (heads, epochs, transitions): (bool, bool, bool) = sqlx::query_as(
    "SELECT to_regclass('oxibelt_admin_membership_heads') IS NOT NULL,
            to_regclass('oxibelt_admin_membership_epochs') IS NOT NULL,
            to_regclass('oxibelt_admin_membership_transitions') IS NOT NULL",
  )
  .fetch_one(pool)
  .await?;
  let mut cluster_ids = BTreeSet::<String>::new();
  if heads {
    cluster_ids.extend(
      sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT cluster_id FROM oxibelt_admin_membership_heads
          WHERE namespace=$1 ORDER BY cluster_id ASC LIMIT 2",
      )
      .bind(namespace)
      .fetch_all(pool)
      .await?,
    );
  }
  if epochs && cluster_ids.len() < 2 {
    cluster_ids.extend(
      sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT cluster_id FROM oxibelt_admin_membership_epochs
          WHERE namespace=$1 ORDER BY cluster_id ASC LIMIT 2",
      )
      .bind(namespace)
      .fetch_all(pool)
      .await?,
    );
  }
  if transitions && cluster_ids.len() < 2 {
    cluster_ids.extend(
      sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT cluster_id FROM oxibelt_admin_membership_transitions
          WHERE namespace=$1 ORDER BY cluster_id ASC LIMIT 2",
      )
      .bind(namespace)
      .fetch_all(pool)
      .await?,
    );
  }
  let cluster_ids = cluster_ids.into_iter().take(2).collect::<Vec<_>>();
  for cluster_id in &cluster_ids {
    super::ledger::validate_identifier("durable membership cluster_id", cluster_id, 253)?;
  }
  Ok(cluster_ids)
}

pub(crate) async fn ensure_membership_head(
  store: &MutationStore,
  cluster_id: &str,
) -> anyhow::Result<()> {
  super::ledger::validate_identifier("cluster_id", cluster_id, 253)?;
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_heads(namespace,cluster_id)
     VALUES($1,$2) ON CONFLICT DO NOTHING",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .execute(store.pool())
  .await?;
  Ok(())
}

pub(crate) async fn load_membership_catchup(
  store: &MutationStore,
  cluster_id: &str,
  transition_id: &str,
) -> anyhow::Result<Vec<MembershipCatchupChunk>> {
  super::ledger::validate_identifier("cluster_id", cluster_id, 253)?;
  super::ledger::validate_identifier("transition_id", transition_id, 256)?;
  let rows = sqlx::query(
    "SELECT chunk_index,algorithm,ephemeral_public_key,nonce,ciphertext,
            ciphertext_digest,plaintext_len
       FROM oxibelt_admin_membership_catchup_chunks
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
      ORDER BY chunk_index ASC LIMIT 4097",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(transition_id)
  .fetch_all(store.pool())
  .await?;
  ensure!(
    rows.len() <= 4_096,
    "membership catch-up chunk count exceeds its bound"
  );
  rows
    .iter()
    .map(|row| {
      Ok(MembershipCatchupChunk {
        chunk_index: row.try_get("chunk_index")?,
        algorithm: row.try_get("algorithm")?,
        ephemeral_public_key: base64::engine::general_purpose::STANDARD
          .encode(row.try_get::<Vec<u8>, _>("ephemeral_public_key")?),
        nonce: base64::engine::general_purpose::STANDARD
          .encode(row.try_get::<Vec<u8>, _>("nonce")?),
        ciphertext: base64::engine::general_purpose::STANDARD
          .encode(row.try_get::<Vec<u8>, _>("ciphertext")?),
        ciphertext_digest: row.try_get("ciphertext_digest")?,
        plaintext_len: row.try_get("plaintext_len")?,
      })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()
    .map_err(Into::into)
}

pub(crate) async fn submit_membership_readiness(
  store: &MutationStore,
  cluster_id: &str,
  receipt: &MembershipReadinessReceipt,
) -> anyhow::Result<MembershipTransition> {
  receipt.validate()?;
  let mut tx = store.pool().begin().await?;
  let now_unix_seconds: i64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::bigint")
    .fetch_one(&mut *tx)
    .await?;
  let row = sqlx::query(
    "SELECT transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
            member_id,proposal_request_id,activation_request_id,blocking_reason,
            catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
            verified_position,capability_result,key_proof_count,key_proof_required,
            receipt_count,fence_cutoff,
            created_at::text AS created_at,updated_at::text AS updated_at
       FROM oxibelt_admin_membership_transitions
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3 FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&receipt.transition_id)
  .fetch_one(&mut *tx)
  .await?;
  let transition = transition_from_row(&row)?;
  ensure!(
    transition.state == "catching_up",
    "membership learner is not catching up"
  );
  ensure!(
    transition.target_epoch_digest == receipt.target_epoch
      && transition.member_id.as_deref() == Some(receipt.member_id.as_str())
      && transition.catchup_cursor == i64::from(receipt.catchup_cursor)
      && transition.catchup_digest.as_deref() == Some(receipt.catchup_digest.as_str()),
    "membership readiness receipt does not match durable catch-up evidence"
  );
  let member_row = sqlx::query(
    "SELECT member.readiness_ed25519_public_key,member.catchup_x25519_public_key,
            epoch.document::text AS epoch_document
       FROM oxibelt_admin_membership_epoch_members member
       JOIN oxibelt_admin_membership_epochs epoch
         ON epoch.namespace=member.namespace AND epoch.cluster_id=member.cluster_id
        AND epoch.epoch_digest=member.epoch_digest
      WHERE member.namespace=$1 AND member.cluster_id=$2
        AND member.epoch_digest=$3 AND member.instance_id=$4",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&receipt.target_epoch)
  .bind(&receipt.member_id)
  .fetch_one(&mut *tx)
  .await?;
  let public_key: String = member_row.try_get("readiness_ed25519_public_key")?;
  let catchup_public_key: String = member_row.try_get("catchup_x25519_public_key")?;
  let epoch_document: String = member_row.try_get("epoch_document")?;
  let epoch: MembershipEpoch = serde_json::from_str(&epoch_document)
    .context("readiness target membership epoch is malformed")?;
  ensure!(
    epoch.digest()? == transition.target_epoch_digest,
    "readiness target membership epoch digest is invalid"
  );
  ensure!(
    epoch.members.iter().any(|member| {
      member.id == receipt.member_id
        && member.readiness_ed25519_public_key == public_key
        && member.catchup_x25519_public_key == catchup_public_key
    }),
    "readiness member index is inconsistent with the digest-bound epoch document"
  );
  ensure!(
    (epoch.version == 1 && receipt.version == 1)
      || (epoch.version == MEMBERSHIP_DOCUMENT_VERSION && receipt.version == 2),
    "membership readiness receipt version does not match the target epoch"
  );
  let public_key = base64::engine::general_purpose::STANDARD.decode(public_key)?;
  let signature = base64::engine::general_purpose::STANDARD.decode(&receipt.signature)?;
  UnparsedPublicKey::new(&ED25519, public_key)
    .verify(&receipt.transcript(cluster_id)?, &signature)
    .map_err(|_| anyhow::anyhow!("membership readiness signature is invalid"))?;
  if now_unix_seconds.abs_diff(receipt.issued_at_unix_seconds) > 300 {
    persist_membership_blocking_reason_tx(
      &mut tx,
      store.namespace(),
      cluster_id,
      &receipt.transition_id,
      "clock_skew",
      "incompatible",
    )
    .await?;
    tx.commit().await?;
    bail!("membership readiness receipt is outside the clock-skew window");
  }
  let expected_capability = if receipt.version == 1 {
    "admin-mutation-rollout-v1"
  } else {
    MEMBERSHIP_CAPABILITY_VERSION
  };
  if receipt.build_version != oxibelt_build_identity::SHORT_VERSION {
    persist_membership_blocking_reason_tx(
      &mut tx,
      store.namespace(),
      cluster_id,
      &receipt.transition_id,
      "incompatible_build",
      "incompatible",
    )
    .await?;
    tx.commit().await?;
    bail!("membership learner build version is incompatible");
  }
  if receipt.capability_version != expected_capability {
    persist_membership_blocking_reason_tx(
      &mut tx,
      store.namespace(),
      cluster_id,
      &receipt.transition_id,
      "incompatible_capability",
      "incompatible",
    )
    .await?;
    tx.commit().await?;
    bail!("membership learner capability is incompatible");
  }
  if receipt.version == 2 {
    ensure!(
      receipt.source_epoch.as_deref() == transition.source_epoch_digest.as_deref()
        && receipt.artifact_key_fingerprint.as_deref() == epoch.artifact_key_fingerprint.as_deref()
        && receipt.checkpoint_digest.as_deref() == transition.checkpoint_digest.as_deref()
        && receipt.journal_tail_digest.as_deref() == transition.journal_tail_digest.as_deref()
        && receipt
          .verified_position
          .and_then(|position| i64::try_from(position).ok())
          == transition.verified_position,
      "membership readiness v2 verification evidence is stale"
    );
    let key_proof_exists: bool = sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_membership_key_proofs
        WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
          AND instance_id=$4 AND target_epoch_digest=$5
          AND artifact_key_fingerprint=$6)",
    )
    .bind(store.namespace())
    .bind(cluster_id)
    .bind(&receipt.transition_id)
    .bind(&receipt.member_id)
    .bind(&receipt.target_epoch)
    .bind(
      receipt
        .artifact_key_fingerprint
        .as_deref()
        .context("validated readiness key fingerprint is missing")?,
    )
    .fetch_one(&mut *tx)
    .await?;
    ensure!(
      key_proof_exists,
      "membership learner has not proved the target epoch artifact key"
    );
  }
  let ordinal = transition.receipt_count;
  ensure!(
    (0..4_096).contains(&ordinal),
    "membership receipt count is exhausted"
  );
  let payload = serde_json::to_value(receipt)?;
  let payload_bytes = serde_json::to_vec(&payload)?;
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_receipts
       (namespace,cluster_id,transition_id,ordinal,receipt_kind,instance_id,payload_digest,payload)
     VALUES($1,$2,$3,$4,'readiness',$5,$6,$7::jsonb)",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&receipt.transition_id)
  .bind(ordinal)
  .bind(&receipt.member_id)
  .bind(super::artifact::sha256_digest(&payload_bytes))
  .bind(serde_json::to_string(&payload)?)
  .execute(&mut *tx)
  .await?
  .rows_affected();
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='ready',state_version=state_version+1,receipt_count=receipt_count+1,
            capability_result='compatible',blocking_reason=NULL,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state='catching_up' AND state_version=$4
      RETURNING transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
        member_id,proposal_request_id,activation_request_id,blocking_reason,
        catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
        verified_position,capability_result,key_proof_count,key_proof_required,
        receipt_count,fence_cutoff,
        created_at::text AS created_at,updated_at::text AS updated_at",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&receipt.transition_id)
  .bind(transition.state_version)
  .fetch_one(&mut *tx)
  .await?;
  let updated = transition_from_row(&updated)?;
  tx.commit().await?;
  Ok(updated)
}

pub(crate) async fn submit_membership_key_proof(
  store: &MutationStore,
  cluster_id: &str,
  proof: &MembershipKeyProof,
) -> anyhow::Result<MembershipTransition> {
  proof.validate()?;
  let mut tx = store.pool().begin().await?;
  let now_unix_seconds: i64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::bigint")
    .fetch_one(&mut *tx)
    .await?;
  let row =
    membership_transition_for_update(&mut tx, store.namespace(), cluster_id, &proof.transition_id)
      .await?;
  let transition = transition_from_row(&row)?;
  ensure!(
    !matches!(
      transition.state.as_str(),
      "active" | "cancelled" | "indeterminate"
    ) && transition.target_epoch_digest == proof.target_epoch,
    "membership key proof does not target a pending epoch"
  );
  let row = sqlx::query(
    "SELECT member.readiness_ed25519_public_key,member.catchup_x25519_public_key,
            epoch.document::text AS epoch_document
       FROM oxibelt_admin_membership_epoch_members member
       JOIN oxibelt_admin_membership_epochs epoch
         ON epoch.namespace=member.namespace AND epoch.cluster_id=member.cluster_id
        AND epoch.epoch_digest=member.epoch_digest AND epoch.state='staged'
      WHERE member.namespace=$1 AND member.cluster_id=$2
        AND member.epoch_digest=$3 AND member.instance_id=$4",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&proof.target_epoch)
  .bind(&proof.member_id)
  .fetch_one(&mut *tx)
  .await?;
  let epoch_document: String = row.try_get("epoch_document")?;
  let epoch: MembershipEpoch =
    serde_json::from_str(&epoch_document).context("key-proof target epoch is malformed")?;
  ensure!(
    epoch.version == MEMBERSHIP_DOCUMENT_VERSION
      && epoch.digest()? == proof.target_epoch
      && epoch.artifact_key_fingerprint.as_deref() == Some(proof.artifact_key_fingerprint.as_str()),
    "membership key proof does not match the target epoch"
  );
  let public_key: String = row.try_get("readiness_ed25519_public_key")?;
  let catchup_public_key: String = row.try_get("catchup_x25519_public_key")?;
  ensure!(
    epoch.members.iter().any(|member| {
      member.id == proof.member_id
        && member.readiness_ed25519_public_key == public_key
        && member.catchup_x25519_public_key == catchup_public_key
    }),
    "key-proof member index is inconsistent with the digest-bound epoch document"
  );
  let public_key = base64::engine::general_purpose::STANDARD.decode(public_key)?;
  let signature = base64::engine::general_purpose::STANDARD.decode(&proof.signature)?;
  UnparsedPublicKey::new(&ED25519, public_key)
    .verify(&proof.transcript(cluster_id)?, &signature)
    .map_err(|_| anyhow::anyhow!("membership key-proof signature is invalid"))?;
  let incompatibility = if now_unix_seconds.abs_diff(proof.issued_at_unix_seconds) > 300 {
    Some("clock_skew")
  } else if proof.build_version != oxibelt_build_identity::SHORT_VERSION {
    Some("incompatible_build")
  } else if proof.capability_version != MEMBERSHIP_CAPABILITY_VERSION {
    Some("incompatible_capability")
  } else {
    None
  };
  if let Some(reason) = incompatibility {
    persist_membership_blocking_reason_tx(
      &mut tx,
      store.namespace(),
      cluster_id,
      &proof.transition_id,
      reason,
      "incompatible",
    )
    .await?;
    tx.commit().await?;
    bail!("membership key proof is incompatible");
  }
  let payload = serde_json::to_value(proof)?;
  let payload_digest = super::artifact::sha256_digest(&serde_json::to_vec(&payload)?);
  let inserted = sqlx::query(
    "INSERT INTO oxibelt_admin_membership_key_proofs
       (namespace,cluster_id,transition_id,instance_id,target_epoch_digest,
        artifact_key_fingerprint,payload_digest,payload)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
     ON CONFLICT(namespace,cluster_id,transition_id,instance_id) DO NOTHING",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&proof.transition_id)
  .bind(&proof.member_id)
  .bind(&proof.target_epoch)
  .bind(&proof.artifact_key_fingerprint)
  .bind(&payload_digest)
  .bind(serde_json::to_string(&payload)?)
  .execute(&mut *tx)
  .await?
  .rows_affected();
  let stored_digest: String = sqlx::query_scalar(
    "SELECT payload_digest FROM oxibelt_admin_membership_key_proofs
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3 AND instance_id=$4",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&proof.transition_id)
  .bind(&proof.member_id)
  .fetch_one(&mut *tx)
  .await?;
  ensure!(
    stored_digest == payload_digest,
    "membership key-proof replay differs from the durable proof"
  );
  if inserted == 0 {
    tx.commit().await?;
    return Ok(transition);
  }
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions transition
        SET key_proof_count=(
              SELECT count(*)::integer FROM oxibelt_admin_membership_key_proofs proof
               WHERE proof.namespace=transition.namespace
                 AND proof.cluster_id=transition.cluster_id
                 AND proof.transition_id=transition.transition_id),
            state_version=state_version+1,
            blocking_reason=CASE WHEN capability_result='incompatible'
              THEN blocking_reason ELSE NULL END,
            updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state_version=$4
      RETURNING transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
        member_id,proposal_request_id,activation_request_id,blocking_reason,
        catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
        verified_position,capability_result,key_proof_count,key_proof_required,
        receipt_count,fence_cutoff,
        created_at::text AS created_at,updated_at::text AS updated_at",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&proof.transition_id)
  .bind(transition.state_version)
  .fetch_one(&mut *tx)
  .await?;
  let updated = transition_from_row(&updated)?;
  tx.commit().await?;
  Ok(updated)
}

pub(crate) async fn has_membership_key_proof(
  store: &MutationStore,
  cluster_id: &str,
  transition_id: &str,
  member_id: &str,
  target_epoch: &str,
  artifact_key_fingerprint: &str,
) -> anyhow::Result<bool> {
  for (name, value, maximum) in [
    ("cluster_id", cluster_id, 253_usize),
    ("transition_id", transition_id, 256),
    ("membership member ID", member_id, 253),
  ] {
    super::ledger::validate_identifier(name, value, maximum)?;
  }
  ensure!(
    super::artifact::is_sha256_digest(target_epoch)
      && super::artifact::is_sha256_digest(artifact_key_fingerprint),
    "membership key-proof lookup binding is invalid"
  );
  Ok(
    sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_membership_key_proofs
        WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
          AND instance_id=$4 AND target_epoch_digest=$5
          AND artifact_key_fingerprint=$6)",
    )
    .bind(store.namespace())
    .bind(cluster_id)
    .bind(transition_id)
    .bind(member_id)
    .bind(target_epoch)
    .bind(artifact_key_fingerprint)
    .fetch_one(store.pool())
    .await?,
  )
}

pub(crate) async fn set_membership_blocking_reason(
  store: &MutationStore,
  cluster_id: &str,
  transition_id: &str,
  reason: &'static str,
) -> anyhow::Result<()> {
  ensure!(
    matches!(
      reason,
      "clock_skew"
        | "incompatible_build"
        | "incompatible_capability"
        | "key_proof_failed"
        | "checkpoint_mismatch"
        | "journal_mismatch"
        | "local_state_mismatch"
        | "activation_indeterminate"
    ),
    "unsupported membership blocking reason"
  );
  let capability = if matches!(reason, "incompatible_build" | "incompatible_capability") {
    "incompatible"
  } else {
    "pending"
  };
  let mut tx = store.pool().begin().await?;
  persist_membership_blocking_reason_tx(
    &mut tx,
    store.namespace(),
    cluster_id,
    transition_id,
    reason,
    capability,
  )
  .await?;
  tx.commit().await?;
  Ok(())
}

async fn persist_membership_blocking_reason_tx(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  transition_id: &str,
  reason: &str,
  capability_result: &str,
) -> anyhow::Result<()> {
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET blocking_reason=$4,capability_result=$5,state_version=state_version+1,
            updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state NOT IN ('active','cancelled','indeterminate')",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(transition_id)
  .bind(reason)
  .bind(capability_result)
  .execute(&mut *connection)
  .await?
  .rows_affected();
  ensure!(updated == 1, "membership transition is no longer pending");
  Ok(())
}

fn verify_epoch_member_index(
  epoch: &MembershipEpoch,
  rows: &[sqlx::postgres::PgRow],
) -> anyhow::Result<Vec<String>> {
  ensure!(
    (2..=1_024).contains(&rows.len()),
    "membership epoch member index size is invalid"
  );
  let indexed = rows
    .iter()
    .map(|row| {
      Ok(MembershipMember {
        id: row.try_get("instance_id")?,
        readiness_ed25519_public_key: row.try_get("readiness_ed25519_public_key")?,
        catchup_x25519_public_key: row.try_get("catchup_x25519_public_key")?,
      })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;
  verify_epoch_members(epoch, indexed)
}

fn verify_epoch_members(
  epoch: &MembershipEpoch,
  indexed: Vec<MembershipMember>,
) -> anyhow::Result<Vec<String>> {
  let canonical = epoch
    .canonical_members()
    .into_iter()
    .cloned()
    .collect::<Vec<_>>();
  ensure!(
    indexed == canonical,
    "membership epoch member index is inconsistent with the digest-bound document"
  );
  Ok(indexed.into_iter().map(|member| member.id).collect())
}

fn verify_activation_key_proof(
  cluster_id: &str,
  transition: &MembershipTransition,
  epoch: &MembershipEpoch,
  member: &MembershipMember,
  proof: &MembershipKeyProof,
  now_unix_seconds: i64,
) -> anyhow::Result<()> {
  proof.validate()?;
  ensure!(
    proof.transition_id == transition.transition_id
      && proof.target_epoch == transition.target_epoch_digest
      && proof.member_id == member.id
      && proof.artifact_key_fingerprint.as_str()
        == epoch
          .artifact_key_fingerprint
          .as_deref()
          .context("activation target epoch key fingerprint is missing")?
      && proof.build_version == oxibelt_build_identity::SHORT_VERSION
      && proof.capability_version == MEMBERSHIP_CAPABILITY_VERSION,
    "membership activation key proof is stale or incompatible"
  );
  ensure!(
    now_unix_seconds.abs_diff(proof.issued_at_unix_seconds)
      <= MEMBERSHIP_EVIDENCE_FRESHNESS_SECONDS,
    "membership activation key proof is outside its freshness window; cancel and repropose the transition"
  );
  let public_key =
    base64::engine::general_purpose::STANDARD.decode(&member.readiness_ed25519_public_key)?;
  let signature = base64::engine::general_purpose::STANDARD.decode(&proof.signature)?;
  UnparsedPublicKey::new(&ED25519, public_key)
    .verify(&proof.transcript(cluster_id)?, &signature)
    .map_err(|_| anyhow::anyhow!("membership activation key-proof signature is invalid"))
}

fn verify_activation_readiness(
  cluster_id: &str,
  transition: &MembershipTransition,
  epoch: &MembershipEpoch,
  member: &MembershipMember,
  receipt: &MembershipReadinessReceipt,
  now_unix_seconds: i64,
) -> anyhow::Result<()> {
  receipt.validate()?;
  let expected_capability = if epoch.version == 1 {
    "admin-mutation-rollout-v1"
  } else {
    MEMBERSHIP_CAPABILITY_VERSION
  };
  ensure!(
    receipt.version == epoch.version
      && receipt.transition_id == transition.transition_id
      && receipt.target_epoch == transition.target_epoch_digest
      && receipt.member_id == member.id
      && i64::from(receipt.catchup_cursor) == transition.catchup_cursor
      && Some(receipt.catchup_digest.as_str()) == transition.catchup_digest.as_deref()
      && receipt.build_version == oxibelt_build_identity::SHORT_VERSION
      && receipt.capability_version == expected_capability,
    "membership activation readiness evidence is stale or incompatible"
  );
  if epoch.version == MEMBERSHIP_DOCUMENT_VERSION {
    ensure!(
      receipt.source_epoch == transition.source_epoch_digest
        && receipt.artifact_key_fingerprint == epoch.artifact_key_fingerprint
        && receipt.checkpoint_digest == transition.checkpoint_digest
        && receipt.journal_tail_digest == transition.journal_tail_digest
        && receipt
          .verified_position
          .and_then(|value| i64::try_from(value).ok())
          == transition.verified_position,
      "membership activation readiness evidence does not match the durable checkpoint"
    );
  }
  ensure!(
    now_unix_seconds.abs_diff(receipt.issued_at_unix_seconds)
      <= MEMBERSHIP_EVIDENCE_FRESHNESS_SECONDS,
    "membership activation readiness is outside its freshness window; cancel and repropose the transition"
  );
  let public_key =
    base64::engine::general_purpose::STANDARD.decode(&member.readiness_ed25519_public_key)?;
  let signature = base64::engine::general_purpose::STANDARD.decode(&receipt.signature)?;
  UnparsedPublicKey::new(&ED25519, public_key)
    .verify(&receipt.transcript(cluster_id)?, &signature)
    .map_err(|_| anyhow::anyhow!("membership activation readiness signature is invalid"))
}

async fn validate_activation_evidence(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  transition: &MembershipTransition,
  epoch: &MembershipEpoch,
) -> anyhow::Result<Vec<String>> {
  let indexed_rows = sqlx::query(
    "SELECT instance_id,readiness_ed25519_public_key,catchup_x25519_public_key
       FROM oxibelt_admin_membership_epoch_members
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3
      ORDER BY instance_id ASC LIMIT 1025",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&transition.target_epoch_digest)
  .fetch_all(&mut *connection)
  .await?;
  let target_members = verify_epoch_member_index(epoch, &indexed_rows)?;
  let now_unix_seconds: i64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::bigint")
    .fetch_one(&mut *connection)
    .await?;
  if epoch.version == MEMBERSHIP_DOCUMENT_VERSION {
    let proof_rows = sqlx::query(
      "SELECT instance_id,
              CASE WHEN octet_length(payload::text)<=16384 THEN payload::text END AS payload
         FROM oxibelt_admin_membership_key_proofs
        WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        ORDER BY instance_id ASC LIMIT 1025",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(&transition.transition_id)
    .fetch_all(&mut *connection)
    .await?;
    ensure!(
      proof_rows.len() == target_members.len(),
      "membership activation is missing an exact target-member key proof"
    );
    for (row, member) in proof_rows.iter().zip(epoch.canonical_members()) {
      ensure!(
        row.try_get::<String, _>("instance_id")? == member.id,
        "membership activation key-proof member set is inconsistent"
      );
      let payload: String = row
        .try_get::<Option<String>, _>("payload")?
        .context("membership activation key-proof payload exceeds its bound")?;
      let proof: MembershipKeyProof =
        serde_json::from_str(&payload).context("membership activation key-proof is malformed")?;
      verify_activation_key_proof(
        cluster_id,
        transition,
        epoch,
        member,
        &proof,
        now_unix_seconds,
      )?;
    }
  }
  if matches!(transition.kind.as_str(), "join" | "rejoin") {
    let learner_id = transition
      .member_id
      .as_deref()
      .context("membership learner identity is missing")?;
    let readiness_rows = sqlx::query(
      "SELECT CASE WHEN octet_length(payload::text)<=16384 THEN payload::text END AS payload
         FROM oxibelt_admin_membership_receipts
        WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
          AND receipt_kind='readiness' AND instance_id=$4
        ORDER BY ordinal ASC LIMIT 2",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(&transition.transition_id)
    .bind(learner_id)
    .fetch_all(&mut *connection)
    .await?;
    ensure!(
      readiness_rows.len() == 1,
      "membership activation requires exactly one learner readiness receipt"
    );
    let payload: String = readiness_rows[0]
      .try_get::<Option<String>, _>("payload")?
      .context("membership activation readiness payload exceeds its bound")?;
    let receipt: MembershipReadinessReceipt =
      serde_json::from_str(&payload).context("membership activation readiness is malformed")?;
    let member = epoch
      .members
      .iter()
      .find(|member| member.id == learner_id)
      .context("membership learner is absent from the target epoch")?;
    verify_activation_readiness(
      cluster_id,
      transition,
      epoch,
      member,
      &receipt,
      now_unix_seconds,
    )?;
  }
  Ok(target_members)
}

pub(crate) async fn load_active_membership_authority(
  store: &MutationStore,
  cluster_id: &str,
) -> anyhow::Result<Option<ActiveMembershipAuthority>> {
  let head = sqlx::query(
    "SELECT head.active_epoch_digest,head.active_epoch_sequence,epoch.document::text AS document,
            epoch.artifact_key_fingerprint
       FROM oxibelt_admin_membership_heads head
       LEFT JOIN oxibelt_admin_membership_epochs epoch
         ON epoch.namespace=head.namespace AND epoch.cluster_id=head.cluster_id
        AND epoch.epoch_digest=head.active_epoch_digest AND epoch.state='active'
      WHERE head.namespace=$1 AND head.cluster_id=$2",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_optional(store.pool())
  .await?;
  let Some(head) = head else {
    return Ok(None);
  };
  let Some(epoch_digest) = head.try_get::<Option<String>, _>("active_epoch_digest")? else {
    return Ok(None);
  };
  let document: String = head
    .try_get::<Option<String>, _>("document")?
    .context("active membership epoch document is missing")?;
  let epoch: MembershipEpoch =
    serde_json::from_str(&document).context("active membership epoch document is malformed")?;
  let stored_fingerprint: Option<String> = head.try_get("artifact_key_fingerprint")?;
  ensure!(
    epoch.digest()? == epoch_digest
      && epoch.artifact_key_fingerprint == stored_fingerprint
      && head
        .try_get::<Option<i64>, _>("active_epoch_sequence")?
        .and_then(|value| u64::try_from(value).ok())
        == Some(epoch.sequence),
    "active membership epoch evidence is inconsistent"
  );
  let indexed_rows = sqlx::query(
    "SELECT instance_id,readiness_ed25519_public_key,catchup_x25519_public_key
       FROM oxibelt_admin_membership_epoch_members
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 ORDER BY instance_id ASC LIMIT 1025",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&epoch_digest)
  .fetch_all(store.pool())
  .await?;
  let members = verify_epoch_member_index(&epoch, &indexed_rows)?;
  Ok(Some(ActiveMembershipAuthority {
    epoch_digest,
    members,
    epoch_version: epoch.version,
    artifact_key_fingerprint: epoch.artifact_key_fingerprint.clone(),
    epoch,
  }))
}

pub(crate) async fn load_pending_membership_reconciliation(
  store: &MutationStore,
  cluster_id: &str,
  member_id: &str,
) -> anyhow::Result<Option<PendingMembershipReconciliation>> {
  super::ledger::validate_identifier("cluster_id", cluster_id, 253)?;
  super::ledger::validate_identifier("membership member ID", member_id, 253)?;
  let row = sqlx::query(
    "SELECT transition.transition_id,transition.kind,transition.state,
            transition.state_version,transition.source_epoch_digest,
            transition.target_epoch_digest,transition.member_id,
            transition.proposal_request_id,transition.activation_request_id,
            transition.blocking_reason,transition.catchup_cursor,transition.catchup_digest,
            transition.checkpoint_digest,transition.journal_tail_digest,
            transition.verified_position,transition.capability_result,
            transition.key_proof_count,transition.key_proof_required,
            transition.receipt_count,transition.fence_cutoff,
            transition.created_at::text AS created_at,
            transition.updated_at::text AS updated_at,
            epoch.document::text AS epoch_document
       FROM oxibelt_admin_membership_transitions transition
       JOIN oxibelt_admin_membership_epoch_members member
         ON member.namespace=transition.namespace AND member.cluster_id=transition.cluster_id
        AND member.epoch_digest=transition.target_epoch_digest AND member.instance_id=$3
       JOIN oxibelt_admin_membership_epochs epoch
         ON epoch.namespace=transition.namespace AND epoch.cluster_id=transition.cluster_id
        AND epoch.epoch_digest=transition.target_epoch_digest AND epoch.state='staged'
      WHERE transition.namespace=$1 AND transition.cluster_id=$2
        AND transition.state NOT IN ('active','cancelled','indeterminate')
      ORDER BY transition.created_at ASC LIMIT 1",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(member_id)
  .fetch_optional(store.pool())
  .await?;
  let Some(row) = row else {
    return Ok(None);
  };
  let transition = transition_from_row(&row)?;
  let document: String = row.try_get("epoch_document")?;
  let epoch: MembershipEpoch =
    serde_json::from_str(&document).context("pending membership epoch document is malformed")?;
  ensure!(
    epoch.digest()? == transition.target_epoch_digest,
    "pending membership epoch digest is invalid"
  );
  Ok(Some(PendingMembershipReconciliation { transition, epoch }))
}

pub(crate) async fn load_epoch_artifact_cipher_for_member(
  store: &MutationStore,
  cluster_id: &str,
  epoch_digest: &str,
  member_id: &str,
  recipient_private_key: &[u8],
  maximum_plaintext_bytes: usize,
) -> anyhow::Result<Arc<MutationArtifactCipher>> {
  let row = sqlx::query(
    "SELECT wrap.transition_id,wrap.artifact_key_fingerprint,wrap.algorithm,
            wrap.ephemeral_public_key,wrap.nonce,wrap.ciphertext,wrap.ciphertext_digest,
            epoch.document::text AS epoch_document
       FROM oxibelt_admin_membership_epoch_key_wraps wrap
       JOIN oxibelt_admin_membership_epochs epoch
         ON epoch.namespace=wrap.namespace AND epoch.cluster_id=wrap.cluster_id
        AND epoch.epoch_digest=wrap.epoch_digest
      WHERE wrap.namespace=$1 AND wrap.cluster_id=$2
        AND wrap.epoch_digest=$3 AND wrap.instance_id=$4",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(epoch_digest)
  .bind(member_id)
  .fetch_one(store.pool())
  .await?;
  let algorithm: String = row.try_get("algorithm")?;
  ensure!(
    algorithm == EPOCH_KEY_WRAP_ALGORITHM,
    "membership epoch key-wrap algorithm is incompatible"
  );
  let document: String = row.try_get("epoch_document")?;
  let epoch: MembershipEpoch =
    serde_json::from_str(&document).context("membership epoch document is malformed")?;
  ensure!(
    epoch.version == MEMBERSHIP_DOCUMENT_VERSION && epoch.digest()? == epoch_digest,
    "membership epoch key wrap does not reference a valid v2 epoch"
  );
  let fingerprint: String = row.try_get("artifact_key_fingerprint")?;
  ensure!(
    epoch.artifact_key_fingerprint.as_deref() == Some(fingerprint.as_str()),
    "membership epoch key fingerprint is inconsistent"
  );
  let transition_id: String = row.try_get("transition_id")?;
  let key = unwrap_epoch_artifact_key(
    &EpochKeyBinding {
      cluster_id,
      transition_id: &transition_id,
      target_epoch: epoch_digest,
      member_id,
      artifact_key_fingerprint: &fingerprint,
    },
    recipient_private_key,
    StoredEpochKeyWrap {
      ephemeral_public_key: row.try_get("ephemeral_public_key")?,
      nonce: row.try_get("nonce")?,
      ciphertext: row.try_get("ciphertext")?,
      ciphertext_digest: row.try_get("ciphertext_digest")?,
    },
  )?;
  let cipher = MutationArtifactCipher::new(key.as_ref(), maximum_plaintext_bytes)?;
  ensure!(
    cipher.key_fingerprint() == fingerprint,
    "unwrapped membership epoch artifact-key fingerprint mismatch"
  );
  Ok(Arc::new(cipher))
}

pub(crate) async fn load_member_legacy_epoch_digests(
  store: &MutationStore,
  cluster_id: &str,
  member_id: &str,
) -> anyhow::Result<Vec<String>> {
  super::ledger::validate_identifier("cluster_id", cluster_id, 253)?;
  super::ledger::validate_identifier("membership member ID", member_id, 253)?;
  let rows = sqlx::query(
    "SELECT epoch.epoch_digest,epoch.document::text AS document
       FROM oxibelt_admin_membership_epochs epoch
       JOIN oxibelt_admin_membership_epoch_members member
         ON member.namespace=epoch.namespace AND member.cluster_id=epoch.cluster_id
        AND member.epoch_digest=epoch.epoch_digest
      WHERE epoch.namespace=$1 AND epoch.cluster_id=$2 AND member.instance_id=$3
        AND epoch.state IN ('active','superseded')
        AND (epoch.document->>'version')::integer=1
      ORDER BY epoch.epoch_sequence DESC LIMIT 65",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(member_id)
  .fetch_all(store.pool())
  .await?;
  ensure!(
    rows.len() <= MAX_MEMBERSHIP_EPOCH_KEYS,
    "member legacy epoch artifact-key history exceeds its bound"
  );
  rows
    .iter()
    .map(|row| {
      let epoch_digest: String = row.try_get("epoch_digest")?;
      let document: String = row.try_get("document")?;
      let epoch: MembershipEpoch =
        serde_json::from_str(&document).context("legacy membership epoch document is malformed")?;
      ensure!(
        epoch.version == 1 && epoch.digest()? == epoch_digest,
        "legacy membership epoch evidence is inconsistent"
      );
      Ok(epoch_digest)
    })
    .collect()
}

pub(crate) async fn load_and_open_membership_catchup(
  store: &MutationStore,
  cluster_id: &str,
  member_id: &str,
  recipient_private_key: &[u8],
) -> anyhow::Result<Option<(MembershipTransition, MembershipCatchupManifestV2)>> {
  let Some(pending) = load_pending_membership_reconciliation(store, cluster_id, member_id).await?
  else {
    return Ok(None);
  };
  if pending.transition.member_id.as_deref() != Some(member_id)
    || pending.transition.state != "catching_up"
  {
    return Ok(None);
  }
  ensure!(
    pending.epoch.version == MEMBERSHIP_DOCUMENT_VERSION,
    "legacy membership catch-up requires the legacy operator flow"
  );
  let rows = sqlx::query(
    "SELECT chunk_index,algorithm,ephemeral_public_key,nonce,ciphertext,
            ciphertext_digest,plaintext_len
       FROM oxibelt_admin_membership_catchup_chunks
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
      ORDER BY chunk_index ASC LIMIT 2",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&pending.transition.transition_id)
  .fetch_all(store.pool())
  .await?;
  ensure!(
    rows.len() == 1 && rows[0].try_get::<i32, _>("chunk_index")? == 0,
    "membership catch-up v2 requires exactly one canonical chunk"
  );
  let row = &rows[0];
  ensure!(
    row.try_get::<String, _>("algorithm")? == CATCHUP_ALGORITHM,
    "membership catch-up algorithm is incompatible"
  );
  let plaintext_len = usize::try_from(row.try_get::<i32, _>("plaintext_len")?)
    .context("membership catch-up plaintext length is negative")?;
  let plaintext = open_catchup_chunk(
    &CatchupBinding {
      cluster_id,
      transition_id: &pending.transition.transition_id,
      member_id,
      source_epoch: pending
        .transition
        .source_epoch_digest
        .as_deref()
        .context("membership catch-up source epoch is missing")?,
      target_epoch: &pending.transition.target_epoch_digest,
      chunk_index: 0,
    },
    recipient_private_key,
    StoredCatchupChunk {
      ephemeral_public_key: row.try_get("ephemeral_public_key")?,
      nonce: row.try_get("nonce")?,
      ciphertext: row.try_get("ciphertext")?,
      ciphertext_digest: row.try_get("ciphertext_digest")?,
      plaintext_len,
    },
  )?;
  ensure!(
    pending.transition.catchup_digest.as_deref()
      == Some(super::artifact::sha256_digest(&plaintext).as_str()),
    "membership catch-up plaintext digest mismatch"
  );
  let manifest: MembershipCatchupManifestV2 =
    serde_json::from_slice(&plaintext).context("membership catch-up manifest is malformed")?;
  validate_catchup_manifest(&manifest)?;
  ensure!(
    manifest.cluster_id == cluster_id
      && manifest.transition_id == pending.transition.transition_id
      && manifest.member_id == member_id
      && Some(manifest.source_epoch.as_str()) == pending.transition.source_epoch_digest.as_deref()
      && manifest.target_epoch == pending.transition.target_epoch_digest
      && Some(manifest.artifact_key_fingerprint.as_str())
        == pending.epoch.artifact_key_fingerprint.as_deref()
      && Some(manifest.checkpoint_digest.as_str())
        == pending.transition.checkpoint_digest.as_deref()
      && Some(manifest.journal_tail_digest.as_str())
        == pending.transition.journal_tail_digest.as_deref()
      && Some(
        i64::try_from(manifest.verified_position)
          .context("membership catch-up verified position exceeds PostgreSQL bigint")?
      ) == pending.transition.verified_position,
    "membership catch-up manifest does not match durable transition evidence"
  );
  verify_manifest_store_snapshot(store, &manifest).await?;
  Ok(Some((pending.transition, manifest)))
}

async fn verify_manifest_store_snapshot(
  store: &MutationStore,
  manifest: &MembershipCatchupManifestV2,
) -> anyhow::Result<()> {
  let rows = sqlx::query(
    "SELECT resource,committed_revision,content_digest,membership_revision
       FROM oxibelt_admin_mutation_revisions
      WHERE namespace=$1 AND cluster_id=$2 AND resource <> 'membership'
      ORDER BY resource ASC LIMIT 1025",
  )
  .bind(store.namespace())
  .bind(&manifest.cluster_id)
  .fetch_all(store.pool())
  .await?;
  ensure!(
    rows.len() <= MAX_CATCHUP_RECORDS,
    "membership catch-up logical heads exceed their verification bound"
  );
  let logical_heads = rows
    .iter()
    .map(|row| {
      Ok(MembershipCatchupLogicalHead {
        resource: row.try_get("resource")?,
        committed_revision: row.try_get("committed_revision")?,
        content_digest: row.try_get("content_digest")?,
        membership_revision: row.try_get("membership_revision")?,
      })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;
  ensure!(
    logical_heads == manifest.logical_heads,
    "membership learner logical checkpoint diverged"
  );
  let mut rows = sqlx::query(
    "SELECT mutation.audit_record_id,mutation.request_id,mutation.resource,mutation.state,
            mutation.expected_previous_revision,mutation.new_revision,mutation.content_digest,
            mutation.membership_revision,artifact.ciphertext_digest AS artifact_digest,
            artifact.plaintext_len
       FROM oxibelt_admin_mutations mutation
       LEFT JOIN oxibelt_admin_mutation_artifacts artifact
         ON artifact.namespace=mutation.namespace AND artifact.request_id=mutation.request_id
      WHERE mutation.namespace=$1 AND mutation.cluster_id=$2
        AND mutation.membership_revision=$3 AND mutation.resource <> 'membership'
        AND mutation.state IN
          ('committed','failed','rolled_back','rollback_failed','indeterminate')
      ORDER BY mutation.audit_record_id DESC,mutation.request_id DESC LIMIT 1025",
  )
  .bind(store.namespace())
  .bind(&manifest.cluster_id)
  .bind(&manifest.source_epoch)
  .fetch_all(store.pool())
  .await?;
  ensure!(
    rows.len() <= MAX_CATCHUP_RECORDS,
    "membership catch-up journal exceeds its verification bound"
  );
  rows.reverse();
  let journal_tail = journal_tail_from_rows(&rows, &manifest.source_epoch)?;
  ensure!(
    journal_tail == manifest.journal_tail,
    "membership learner journal tail diverged"
  );
  Ok(())
}

async fn ensure_no_concurrent_protected_mutation(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  allowed_request_id: &str,
) -> anyhow::Result<()> {
  let blocking: Option<String> = sqlx::query_scalar(
    "SELECT request_id FROM oxibelt_admin_mutations
      WHERE namespace=$1 AND cluster_id=$2 AND request_id <> $3
        AND state NOT IN ('committed','failed','rolled_back','rollback_failed','indeterminate')
      ORDER BY created_at ASC LIMIT 1",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(allowed_request_id)
  .fetch_optional(&mut *connection)
  .await?;
  ensure!(
    blocking.is_none(),
    "membership transition is blocked by another protected mutation"
  );
  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_membership_proposal_tx(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  transition_id: &str,
  proposal_request_id: &str,
  request: &MembershipTransitionRequest,
  bootstrap_members: &[MembershipMember],
  approving_members: &[String],
  source_membership_revision: &str,
  artifact_ciphers: &MembershipArtifactCiphers,
) -> anyhow::Result<(MembershipTransition, MembershipMutationCheckpoint)> {
  super::ledger::validate_identifier("cluster_id", cluster_id, 253)?;
  super::ledger::validate_identifier("transition_id", transition_id, 256)?;
  super::ledger::validate_identifier("proposal_request_id", proposal_request_id, 256)?;
  request.validate()?;
  ensure!(
    !approving_members.is_empty() && approving_members.len() <= 1_024,
    "membership proposal requires bounded current-member approval evidence"
  );
  super::ledger::validate_identifier(
    "membership proposal source revision",
    source_membership_revision,
    256,
  )?;
  ensure!(
    artifact_ciphers.contains_key(source_membership_revision),
    "membership proposal source artifact key is unavailable"
  );
  ensure_no_concurrent_protected_mutation(connection, namespace, cluster_id, proposal_request_id)
    .await?;
  let retained_epoch_count: i64 = sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_admin_membership_epochs
      WHERE namespace=$1 AND cluster_id=$2",
  )
  .bind(namespace)
  .bind(cluster_id)
  .fetch_one(&mut *connection)
  .await?;
  ensure_membership_epoch_capacity(retained_epoch_count)?;
  let created_head = sqlx::query(
    "INSERT INTO oxibelt_admin_membership_heads(namespace,cluster_id)
     VALUES($1,$2) ON CONFLICT DO NOTHING",
  )
  .bind(namespace)
  .bind(cluster_id)
  .execute(&mut *connection)
  .await?
  .rows_affected()
    == 1;
  let head = sqlx::query(
    "SELECT active_epoch_digest,active_epoch_sequence
       FROM oxibelt_admin_membership_heads
      WHERE namespace=$1 AND cluster_id=$2 FOR UPDATE",
  )
  .bind(namespace)
  .bind(cluster_id)
  .fetch_one(&mut *connection)
  .await?;
  let active_digest: Option<String> = head.try_get("active_epoch_digest")?;
  let active_sequence: Option<i64> = head.try_get("active_epoch_sequence")?;
  ensure!(
    active_digest.as_deref() == request.expected_active_epoch.as_deref(),
    "membership proposal active epoch precondition is stale"
  );
  let current = match active_digest.as_deref() {
    Some(digest) => {
      let document: String = sqlx::query_scalar(
        "SELECT document::text FROM oxibelt_admin_membership_epochs
          WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='active'",
      )
      .bind(namespace)
      .bind(cluster_id)
      .bind(digest)
      .fetch_one(&mut *connection)
      .await?;
      let epoch: MembershipEpoch =
        serde_json::from_str(&document).context("active membership epoch document is malformed")?;
      ensure!(
        epoch.digest()? == digest,
        "active membership epoch digest is invalid"
      );
      Some(epoch)
    }
    None => None,
  };
  if let Some(active_digest) = active_digest.as_deref() {
    ensure!(
      source_membership_revision == active_digest,
      "membership proposal source revision does not match the active epoch"
    );
  }
  let mut members = current
    .as_ref()
    .map(|epoch| epoch.members.clone())
    .unwrap_or_default();
  let member_id = request.member.as_ref().map(|member| member.id.clone());
  match request.kind {
    MembershipTransitionKind::Initialize => {
      ensure!(current.is_none(), "membership is already initialized");
      members = bootstrap_members.to_vec();
    }
    MembershipTransitionKind::Join | MembershipTransitionKind::Rejoin => {
      let member = request.member.as_ref().context("join member is missing")?;
      ensure!(
        !members.iter().any(|existing| existing.id == member.id),
        "membership join identity is already active"
      );
      members.push(member.clone());
    }
    MembershipTransitionKind::Maintenance | MembershipTransitionKind::Remove => {
      let member = request
        .member
        .as_ref()
        .context("removal member is missing")?;
      let position = members
        .iter()
        .position(|existing| existing == member)
        .context("membership removal identity or trust material is not active")?;
      members.remove(position);
    }
  }
  let sequence = active_sequence.map_or(0, |value| value + 1);
  let mut epoch_artifact_key = zeroize::Zeroizing::new([0_u8; 32]);
  crate::crypto::random_fill(epoch_artifact_key.as_mut())
    .context("failed to generate membership epoch artifact key")?;
  let epoch_artifact_key_fingerprint = artifact_key_fingerprint(epoch_artifact_key.as_ref());
  let epoch = MembershipEpoch::new_v2(
    cluster_id.to_string(),
    u64::try_from(sequence).context("membership sequence is negative")?,
    active_digest.clone(),
    epoch_artifact_key_fingerprint.clone(),
    members,
    proposal_request_id.to_string(),
  )?;
  let epoch_digest = epoch.digest()?;
  let document = serde_json::to_string(&epoch)?;
  let pending: bool = sqlx::query_scalar(
    "SELECT EXISTS(SELECT 1 FROM oxibelt_admin_membership_transitions
      WHERE namespace=$1 AND cluster_id=$2
        AND state NOT IN ('active','cancelled','indeterminate'))",
  )
  .bind(namespace)
  .bind(cluster_id)
  .fetch_one(&mut *connection)
  .await?;
  ensure!(!pending, "another membership transition is unresolved");
  let initial_state = match request.kind {
    MembershipTransitionKind::Initialize => MembershipTransitionState::Ready,
    MembershipTransitionKind::Join | MembershipTransitionKind::Rejoin => {
      MembershipTransitionState::Learner
    }
    MembershipTransitionKind::Maintenance | MembershipTransitionKind::Remove => {
      MembershipTransitionState::Ready
    }
  };
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_epochs
       (namespace,cluster_id,epoch_digest,epoch_sequence,predecessor_digest,
        artifact_key_fingerprint,document,authorized_request_id,state)
     VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,'staged')",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&epoch_digest)
  .bind(i64::try_from(epoch.sequence).context("membership sequence exceeds PostgreSQL bigint")?)
  .bind(epoch.predecessor.as_deref())
  .bind(&epoch_artifact_key_fingerprint)
  .bind(document)
  .bind(proposal_request_id)
  .execute(&mut *connection)
  .await?;
  for member in epoch.canonical_members() {
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_epoch_members
         (namespace,cluster_id,epoch_digest,instance_id,
          readiness_ed25519_public_key,catchup_x25519_public_key)
       VALUES($1,$2,$3,$4,$5,$6)",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(&epoch_digest)
    .bind(&member.id)
    .bind(&member.readiness_ed25519_public_key)
    .bind(&member.catchup_x25519_public_key)
    .execute(&mut *connection)
    .await?;
    let wrapped = wrap_epoch_artifact_key(
      &EpochKeyBinding {
        cluster_id,
        transition_id,
        target_epoch: &epoch_digest,
        member_id: &member.id,
        artifact_key_fingerprint: &epoch_artifact_key_fingerprint,
      },
      &member.catchup_x25519_public_key,
      epoch_artifact_key.as_ref(),
    )?;
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_epoch_key_wraps
         (namespace,cluster_id,epoch_digest,transition_id,instance_id,
          artifact_key_fingerprint,algorithm,ephemeral_public_key,nonce,
          ciphertext,ciphertext_digest)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(&epoch_digest)
    .bind(transition_id)
    .bind(&member.id)
    .bind(&epoch_artifact_key_fingerprint)
    .bind(EPOCH_KEY_WRAP_ALGORITHM)
    .bind(wrapped.ephemeral_public_key.as_slice())
    .bind(wrapped.nonce.as_slice())
    .bind(wrapped.ciphertext.as_slice())
    .bind(&wrapped.ciphertext_digest)
    .execute(&mut *connection)
    .await?;
  }
  let target_cipher = MutationArtifactCipher::new(
    epoch_artifact_key.as_ref(),
    super::store::MAX_STORED_ARTIFACT_BYTES,
  )?;
  let checkpoint_artifacts = rekey_current_checkpoint_artifacts(
    connection,
    namespace,
    cluster_id,
    source_membership_revision,
    &epoch_digest,
    &target_cipher,
    artifact_ciphers,
  )
  .await?;
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_transitions
       (namespace,cluster_id,transition_id,kind,state,source_epoch_digest,
        target_epoch_digest,member_id,proposal_request_id,capability_result,
        key_proof_required,receipt_count)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1)",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(transition_id)
  .bind(request.kind.as_str())
  .bind(initial_state.as_str())
  .bind(epoch.predecessor.as_deref())
  .bind(&epoch_digest)
  .bind(member_id.as_deref())
  .bind(proposal_request_id)
  .bind(
    if matches!(
      request.kind,
      MembershipTransitionKind::Join | MembershipTransitionKind::Rejoin
    ) {
      "pending"
    } else {
      "not_required"
    },
  )
  .bind(i32::try_from(epoch.members.len()).context("target membership is too large")?)
  .execute(&mut *connection)
  .await?;
  if matches!(
    request.kind,
    MembershipTransitionKind::Join | MembershipTransitionKind::Rejoin
  ) {
    let member = request.member.as_ref().context("join member is missing")?;
    let learner_wrap_digest: String = sqlx::query_scalar(
      "SELECT ciphertext_digest FROM oxibelt_admin_membership_epoch_key_wraps
        WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND instance_id=$4",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(&epoch_digest)
    .bind(&member.id)
    .fetch_one(&mut *connection)
    .await?;
    let manifest = membership_catchup_manifest(
      connection,
      namespace,
      cluster_id,
      transition_id,
      member_id.as_deref().context("join member ID is missing")?,
      epoch
        .predecessor
        .as_deref()
        .context("join source epoch is missing")?,
      &epoch_digest,
      &epoch_artifact_key_fingerprint,
      &learner_wrap_digest,
      source_membership_revision,
      checkpoint_artifacts,
    )
    .await?;
    let checkpoint_digest = manifest.checkpoint_digest.clone();
    let journal_tail_digest = manifest.journal_tail_digest.clone();
    let verified_position = manifest.verified_position;
    let plaintext = serde_json::to_vec(&manifest)?;
    let sealed = seal_catchup_chunk(
      &CatchupBinding {
        cluster_id,
        transition_id,
        member_id: &member.id,
        source_epoch: epoch
          .predecessor
          .as_deref()
          .context("join source epoch is missing")?,
        target_epoch: &epoch_digest,
        chunk_index: 0,
      },
      &member.catchup_x25519_public_key,
      zeroize::Zeroizing::new(plaintext),
    )?;
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_catchup_chunks
         (namespace,cluster_id,transition_id,chunk_index,algorithm,
          ephemeral_public_key,nonce,ciphertext,ciphertext_digest,plaintext_len)
       VALUES($1,$2,$3,0,$4,$5,$6,$7,$8,$9)",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(transition_id)
    .bind(CATCHUP_ALGORITHM)
    .bind(sealed.ephemeral_public_key.as_slice())
    .bind(sealed.nonce.as_slice())
    .bind(sealed.ciphertext.as_slice())
    .bind(&sealed.ciphertext_digest)
    .bind(i32::try_from(sealed.plaintext_len).context("catch-up chunk is too large")?)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
      "UPDATE oxibelt_admin_membership_transitions
          SET state='catching_up',state_version=state_version+1,
              catchup_cursor=1,catchup_digest=$4,checkpoint_digest=$5,
              journal_tail_digest=$6,verified_position=$7,updated_at=now()
        WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3 AND state='learner'",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(transition_id)
    .bind(&sealed.plaintext_digest)
    .bind(&checkpoint_digest)
    .bind(&journal_tail_digest)
    .bind(i64::try_from(verified_position).context("verified journal position is too large")?)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
      "UPDATE oxibelt_admin_membership_epochs SET checkpoint_digest=$4
        WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='staged'",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(&epoch_digest)
    .bind(&checkpoint_digest)
    .execute(&mut *connection)
    .await?;
  }
  let receipt = serde_json::json!({
    "version": 2,
    "kind": "proposal",
    "transition_id": transition_id,
    "proposal_request_id": proposal_request_id,
    "source_epoch": epoch.predecessor,
    "target_epoch": epoch_digest,
    "artifact_key_fingerprint": epoch_artifact_key_fingerprint,
    "required_key_proofs": epoch.members.len(),
    "approving_members": approving_members,
  });
  let receipt_bytes = serde_json::to_vec(&receipt)?;
  let receipt_digest = super::artifact::sha256_digest(&receipt_bytes);
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_receipts
       (namespace,cluster_id,transition_id,ordinal,receipt_kind,payload_digest,payload)
     VALUES($1,$2,$3,0,'proposal',$4,$5::jsonb)",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(transition_id)
  .bind(receipt_digest)
  .bind(serde_json::to_string(&receipt)?)
  .execute(&mut *connection)
  .await?;
  let row = sqlx::query(
    "SELECT transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
            member_id,proposal_request_id,activation_request_id,blocking_reason,
            catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
            verified_position,capability_result,key_proof_count,key_proof_required,
            receipt_count,fence_cutoff,
            created_at::text AS created_at,updated_at::text AS updated_at
       FROM oxibelt_admin_membership_transitions
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(transition_id)
  .fetch_one(&mut *connection)
  .await?;
  let transition = transition_from_row(&row)?;
  Ok((
    transition,
    MembershipMutationCheckpoint::Proposal {
      cluster_id: cluster_id.to_string(),
      transition_id: transition_id.to_string(),
      target_epoch_digest: epoch_digest,
      created_head,
    },
  ))
}

#[allow(clippy::too_many_arguments)]
async fn rekey_current_checkpoint_artifacts(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  source_membership_revision: &str,
  target_epoch: &str,
  target_cipher: &MutationArtifactCipher,
  artifact_ciphers: &MembershipArtifactCiphers,
) -> anyhow::Result<Vec<MembershipCatchupArtifact>> {
  ensure!(
    target_cipher.maximum_plaintext_bytes() <= super::store::MAX_STORED_ARTIFACT_BYTES,
    "target membership artifact bound is invalid"
  );
  let rows = sqlx::query(
    "SELECT mutation.request_id,mutation.fingerprint,mutation.principal,mutation.signer_id,
            mutation.action,mutation.resource,mutation.cluster_id,
            mutation.membership_revision,mutation.new_revision,
            mutation.expected_previous_revision,mutation.content_digest,
            artifact.nonce,artifact.ciphertext,artifact.ciphertext_digest,artifact.plaintext_len,
            replica.algorithm AS replica_algorithm,replica.nonce AS replica_nonce,
            replica.ciphertext AS replica_ciphertext,
            replica.ciphertext_digest AS replica_ciphertext_digest,
            replica.plaintext_len AS replica_plaintext_len
       FROM oxibelt_admin_mutation_revisions revision
       JOIN oxibelt_admin_mutations mutation
         ON mutation.namespace=revision.namespace AND mutation.resource=revision.resource
        AND mutation.new_revision=revision.committed_revision
        AND mutation.content_digest=revision.content_digest AND mutation.state='committed'
       JOIN oxibelt_admin_mutation_artifacts artifact
         ON artifact.namespace=mutation.namespace AND artifact.request_id=mutation.request_id
       LEFT JOIN oxibelt_admin_membership_epoch_artifacts replica
         ON replica.namespace=revision.namespace AND replica.cluster_id=revision.cluster_id
        AND replica.epoch_digest=$3 AND replica.resource=revision.resource
        AND replica.request_id=mutation.request_id
      WHERE revision.namespace=$1 AND revision.cluster_id=$2
        AND revision.resource <> 'membership'
      ORDER BY revision.resource ASC LIMIT 65",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(source_membership_revision)
  .fetch_all(&mut *connection)
  .await?;
  ensure!(
    rows.len() <= MAX_CATCHUP_ARTIFACTS,
    "membership checkpoint artifact set exceeds its bound"
  );
  let mut checkpoint_artifacts = Vec::with_capacity(rows.len());
  for row in rows {
    let binding = ArtifactBinding {
      namespace: namespace.to_string(),
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
    let replica_nonce: Option<Vec<u8>> = row.try_get("replica_nonce")?;
    let (cipher, nonce, ciphertext, ciphertext_digest, plaintext_len) =
      if let Some(nonce) = replica_nonce {
        ensure!(
          row
            .try_get::<Option<String>, _>("replica_algorithm")?
            .as_deref()
            == Some(ARTIFACT_ALGORITHM),
          "source membership artifact replica algorithm is incompatible"
        );
        (
          artifact_ciphers
            .get(source_membership_revision)
            .context("source membership artifact key is unavailable")?,
          nonce,
          row
            .try_get::<Option<Vec<u8>>, _>("replica_ciphertext")?
            .context("source membership artifact replica ciphertext is missing")?,
          row
            .try_get::<Option<String>, _>("replica_ciphertext_digest")?
            .context("source membership artifact replica digest is missing")?,
          usize::try_from(
            row
              .try_get::<Option<i32>, _>("replica_plaintext_len")?
              .context("source membership artifact replica length is missing")?,
          )
          .context("source membership artifact replica length is negative")?,
        )
      } else {
        (
          artifact_ciphers
            .get(&binding.membership_revision)
            .with_context(|| {
              format!(
                "artifact key for checkpoint membership {} is unavailable",
                binding.membership_revision
              )
            })?,
          row.try_get("nonce")?,
          row.try_get("ciphertext")?,
          row.try_get("ciphertext_digest")?,
          usize::try_from(row.try_get::<i32, _>("plaintext_len")?)
            .context("membership checkpoint artifact length is negative")?,
        )
      };
    let plaintext = cipher.open(
      &binding,
      StoredArtifact {
        binding: binding.clone(),
        nonce,
        ciphertext,
        ciphertext_digest,
        plaintext_len,
      },
    )?;
    let encoded_plaintext = base64::engine::general_purpose::STANDARD.encode(plaintext.as_bytes());
    let sealed = target_cipher.seal(&binding, plaintext)?;
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_epoch_artifacts
         (namespace,cluster_id,epoch_digest,resource,request_id,algorithm,nonce,
          ciphertext,ciphertext_digest,plaintext_len)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(target_epoch)
    .bind(&binding.resource)
    .bind(&binding.request_id)
    .bind(ARTIFACT_ALGORITHM)
    .bind(sealed.nonce.as_slice())
    .bind(sealed.ciphertext.as_slice())
    .bind(&sealed.ciphertext_digest)
    .bind(i32::try_from(sealed.plaintext_len).context("epoch artifact replica is too large")?)
    .execute(&mut *connection)
    .await?;
    checkpoint_artifacts.push(MembershipCatchupArtifact {
      namespace: binding.namespace,
      request_id: binding.request_id,
      fingerprint: binding.fingerprint,
      principal: binding.principal,
      signer_id: binding.signer_id,
      action: binding.action,
      resource: binding.resource,
      cluster_id: binding.cluster_id,
      membership_revision: binding.membership_revision,
      new_revision: binding.new_revision,
      expected_previous_revision: binding.expected_previous_revision,
      content_digest: binding.content_digest,
      encoded_plaintext,
    });
  }
  Ok(checkpoint_artifacts)
}

#[allow(clippy::too_many_arguments)]
async fn membership_catchup_manifest(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  transition_id: &str,
  member_id: &str,
  source_epoch: &str,
  target_epoch: &str,
  artifact_key_fingerprint: &str,
  key_wrap_digest: &str,
  source_membership_revision: &str,
  checkpoint_artifacts: Vec<MembershipCatchupArtifact>,
) -> anyhow::Result<MembershipCatchupManifestV2> {
  let mut mutations = sqlx::query(
    "SELECT mutation.audit_record_id,mutation.request_id,mutation.resource,mutation.state,
            mutation.expected_previous_revision,mutation.new_revision,mutation.content_digest,
            mutation.membership_revision,artifact.ciphertext_digest AS artifact_digest,
            artifact.plaintext_len
       FROM oxibelt_admin_mutations mutation
       LEFT JOIN oxibelt_admin_mutation_artifacts artifact
         ON artifact.namespace=mutation.namespace AND artifact.request_id=mutation.request_id
      WHERE mutation.namespace=$1 AND mutation.cluster_id=$2
        AND mutation.membership_revision=$3 AND mutation.resource <> 'membership'
        AND mutation.state IN
          ('committed','failed','rolled_back','rollback_failed','indeterminate')
      ORDER BY mutation.audit_record_id DESC,mutation.request_id DESC LIMIT 1025",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(source_membership_revision)
  .fetch_all(&mut *connection)
  .await?;
  ensure!(
    mutations.len() <= MAX_CATCHUP_RECORDS,
    "membership catch-up mutation history exceeds its bounded snapshot"
  );
  mutations.reverse();
  let journal_tail = journal_tail_from_rows(&mutations, source_epoch)?;
  let heads = sqlx::query(
    "SELECT resource,committed_revision,content_digest,membership_revision
       FROM oxibelt_admin_mutation_revisions
      WHERE namespace=$1 AND cluster_id=$2 AND resource <> 'membership'
      ORDER BY resource ASC LIMIT 1025",
  )
  .bind(namespace)
  .bind(cluster_id)
  .fetch_all(&mut *connection)
  .await?;
  ensure!(
    heads.len() <= MAX_CATCHUP_RECORDS,
    "membership catch-up logical heads exceed their bound"
  );
  let logical_heads = heads
    .iter()
    .map(|row| {
      Ok(MembershipCatchupLogicalHead {
        resource: row.try_get("resource")?,
        committed_revision: row.try_get("committed_revision")?,
        content_digest: row.try_get("content_digest")?,
        membership_revision: row.try_get("membership_revision")?,
      })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;
  let checkpoint_digest = membership_evidence_digest(
    b"OXIBELT-ADMIN-MEMBERSHIP-CHECKPOINT-V2\0",
    &(logical_heads.as_slice(), checkpoint_artifacts.as_slice()),
  )?;
  let journal_tail_digest =
    membership_evidence_digest(b"OXIBELT-ADMIN-MEMBERSHIP-JOURNAL-TAIL-V2\0", &journal_tail)?;
  let verified_position = journal_tail.last().map_or(0, |entry| entry.position);
  let manifest = MembershipCatchupManifestV2 {
    format: "oxibelt-admin-membership-catchup-v2".to_string(),
    cluster_id: cluster_id.to_string(),
    transition_id: transition_id.to_string(),
    member_id: member_id.to_string(),
    source_epoch: source_epoch.to_string(),
    target_epoch: target_epoch.to_string(),
    artifact_key_fingerprint: artifact_key_fingerprint.to_string(),
    key_wrap_digest: key_wrap_digest.to_string(),
    build_version: oxibelt_build_identity::SHORT_VERSION.to_string(),
    capability_version: MEMBERSHIP_CAPABILITY_VERSION.to_string(),
    logical_heads,
    checkpoint_artifacts,
    journal_tail,
    checkpoint_digest,
    journal_tail_digest,
    verified_position,
  };
  validate_catchup_manifest(&manifest)?;
  Ok(manifest)
}

fn membership_evidence_digest(domain: &[u8], value: &impl Serialize) -> anyhow::Result<String> {
  let encoded = serde_json::to_vec(value)?;
  let mut transcript = Vec::with_capacity(domain.len() + encoded.len());
  transcript.extend_from_slice(domain);
  transcript.extend_from_slice(&encoded);
  Ok(super::artifact::sha256_digest(&transcript))
}

fn journal_chain_root(source_epoch: &str) -> anyhow::Result<String> {
  ensure!(
    super::artifact::is_sha256_digest(source_epoch),
    "membership journal source epoch is invalid"
  );
  membership_evidence_digest(b"OXIBELT-ADMIN-MEMBERSHIP-JOURNAL-ROOT-V2\0", &source_epoch)
}

fn journal_entry_digest(entry: &MembershipCatchupJournalEntry) -> anyhow::Result<String> {
  membership_evidence_digest(
    b"OXIBELT-ADMIN-MEMBERSHIP-JOURNAL-ENTRY-V2\0",
    &(
      entry.position,
      entry.previous_entry_digest.as_str(),
      entry.request_id.as_str(),
      entry.resource.as_str(),
      entry.state.as_str(),
      entry.expected_previous_revision.as_str(),
      entry.new_revision.as_str(),
      entry.content_digest.as_str(),
      entry.membership_revision.as_deref(),
      entry.artifact_digest.as_deref(),
      entry.artifact_plaintext_len,
    ),
  )
}

fn journal_tail_from_rows(
  rows: &[sqlx::postgres::PgRow],
  source_epoch: &str,
) -> anyhow::Result<Vec<MembershipCatchupJournalEntry>> {
  let mut previous_entry_digest = journal_chain_root(source_epoch)?;
  let mut journal = Vec::with_capacity(rows.len());
  for row in rows {
    let position: i64 = row.try_get("audit_record_id")?;
    let mut entry = MembershipCatchupJournalEntry {
      position: u64::try_from(position).context("membership journal position is negative")?,
      previous_entry_digest: previous_entry_digest.clone(),
      entry_digest: String::new(),
      request_id: row.try_get("request_id")?,
      resource: row.try_get("resource")?,
      state: row.try_get("state")?,
      expected_previous_revision: row.try_get("expected_previous_revision")?,
      new_revision: row.try_get("new_revision")?,
      content_digest: row.try_get("content_digest")?,
      membership_revision: row.try_get("membership_revision")?,
      artifact_digest: row.try_get("artifact_digest")?,
      artifact_plaintext_len: row.try_get("plaintext_len")?,
    };
    entry.entry_digest = journal_entry_digest(&entry)?;
    previous_entry_digest = entry.entry_digest.clone();
    journal.push(entry);
  }
  Ok(journal)
}

fn validate_catchup_manifest(manifest: &MembershipCatchupManifestV2) -> anyhow::Result<()> {
  ensure!(
    manifest.format == "oxibelt-admin-membership-catchup-v2",
    "membership catch-up format is incompatible"
  );
  for (name, value, maximum) in [
    ("cluster ID", manifest.cluster_id.as_str(), 253_usize),
    ("transition ID", manifest.transition_id.as_str(), 256),
    ("member ID", manifest.member_id.as_str(), 253),
  ] {
    super::ledger::validate_identifier(name, value, maximum)?;
  }
  ensure!(
    manifest.build_version == oxibelt_build_identity::SHORT_VERSION,
    "membership catch-up build is incompatible"
  );
  ensure!(
    manifest.capability_version == MEMBERSHIP_CAPABILITY_VERSION,
    "membership catch-up capability is incompatible"
  );
  for (name, digest) in [
    ("source epoch", manifest.source_epoch.as_str()),
    ("target epoch", manifest.target_epoch.as_str()),
    (
      "artifact-key fingerprint",
      manifest.artifact_key_fingerprint.as_str(),
    ),
    ("key-wrap digest", manifest.key_wrap_digest.as_str()),
    ("checkpoint digest", manifest.checkpoint_digest.as_str()),
    ("journal-tail digest", manifest.journal_tail_digest.as_str()),
  ] {
    ensure!(
      super::artifact::is_sha256_digest(digest),
      "membership catch-up {name} is invalid"
    );
  }
  ensure!(
    manifest.logical_heads.len() <= MAX_CATCHUP_RECORDS
      && manifest.journal_tail.len() <= MAX_CATCHUP_RECORDS
      && manifest.checkpoint_artifacts.len() <= MAX_CATCHUP_ARTIFACTS,
    "membership catch-up evidence exceeds its bound"
  );
  ensure!(
    membership_evidence_digest(
      b"OXIBELT-ADMIN-MEMBERSHIP-CHECKPOINT-V2\0",
      &(
        manifest.logical_heads.as_slice(),
        manifest.checkpoint_artifacts.as_slice(),
      ),
    )? == manifest.checkpoint_digest,
    "membership catch-up checkpoint digest mismatch"
  );
  ensure!(
    membership_evidence_digest(
      b"OXIBELT-ADMIN-MEMBERSHIP-JOURNAL-TAIL-V2\0",
      &manifest.journal_tail,
    )? == manifest.journal_tail_digest,
    "membership catch-up journal-tail digest mismatch"
  );
  ensure!(
    manifest.journal_tail.windows(2).all(|entries| {
      entries[0].position < entries[1].position
        || (entries[0].position == entries[1].position
          && entries[0].request_id < entries[1].request_id)
    }),
    "membership catch-up journal tail is not canonically ordered"
  );
  let mut previous_entry_digest = journal_chain_root(&manifest.source_epoch)?;
  for entry in &manifest.journal_tail {
    ensure!(
      entry.previous_entry_digest == previous_entry_digest
        && entry.entry_digest == journal_entry_digest(entry)?,
      "membership catch-up journal predecessor chain is invalid"
    );
    ensure!(
      entry.membership_revision.as_deref() == Some(manifest.source_epoch.as_str())
        && super::artifact::is_sha256_digest(&entry.content_digest)
        && entry
          .artifact_digest
          .as_deref()
          .is_none_or(super::artifact::is_sha256_digest),
      "membership catch-up journal binding is invalid"
    );
    previous_entry_digest.clone_from(&entry.entry_digest);
  }
  ensure!(
    manifest.verified_position
      == manifest
        .journal_tail
        .last()
        .map_or(0, |entry| entry.position),
    "membership catch-up verified position is inconsistent"
  );
  let mut resources = BTreeSet::new();
  for head in &manifest.logical_heads {
    ensure!(
      resources.insert(head.resource.as_str()),
      "membership catch-up contains duplicate logical heads"
    );
    ensure!(
      super::artifact::is_sha256_digest(&head.content_digest),
      "membership catch-up logical-head digest is invalid"
    );
  }
  for artifact in &manifest.checkpoint_artifacts {
    artifact.binding()?;
    let _ = artifact.plaintext()?;
    ensure!(
      manifest.logical_heads.iter().any(|head| {
        head.resource == artifact.resource
          && head.committed_revision == artifact.new_revision
          && head.content_digest == artifact.content_digest
      }),
      "membership checkpoint artifact is not bound to a logical head"
    );
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_membership_activation_tx(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  activation_request_id: &str,
  request: &MembershipActivationRequest,
  authorization_coordinator_epoch: i64,
  approving_members: &[String],
) -> anyhow::Result<(MembershipTransition, MembershipMutationCheckpoint)> {
  request.validate()?;
  ensure_no_concurrent_protected_mutation(connection, namespace, cluster_id, activation_request_id)
    .await?;
  ensure!(
    authorization_coordinator_epoch > 0,
    "membership activation coordinator epoch is invalid"
  );
  let row =
    membership_transition_for_update(connection, namespace, cluster_id, &request.transition_id)
      .await?;
  let transition = transition_from_row(&row)?;
  let state = MembershipTransitionState::parse(&transition.state)?;
  ensure!(
    state.may_transition_to(MembershipTransitionState::ActivationAuthorized),
    "membership transition is not ready for activation"
  );
  ensure!(
    transition.target_epoch_digest == request.expected_target_epoch,
    "membership activation target epoch is stale"
  );
  ensure!(
    !approving_members.is_empty() && approving_members.len() <= 1_024,
    "membership activation requires bounded current-member approval evidence"
  );
  let epoch_document: String = sqlx::query_scalar(
    "SELECT document::text FROM oxibelt_admin_membership_epochs
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='staged'",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&request.expected_target_epoch)
  .fetch_one(&mut *connection)
  .await?;
  let epoch: MembershipEpoch = serde_json::from_str(&epoch_document)
    .context("membership activation target epoch is malformed")?;
  ensure!(
    epoch.digest()? == request.expected_target_epoch,
    "membership activation target epoch digest is invalid"
  );
  ensure!(
    matches!(epoch.version, 1 | MEMBERSHIP_DOCUMENT_VERSION),
    "membership activation epoch version is unsupported"
  );
  if matches!(transition.kind.as_str(), "join" | "rejoin") {
    ensure!(
      transition.capability_result == "compatible"
        && transition.checkpoint_digest.is_some()
        && transition.journal_tail_digest.is_some()
        && transition.verified_position.is_some(),
      "membership learner verification is incomplete"
    );
  }
  let target_members =
    validate_activation_evidence(connection, namespace, cluster_id, &transition, &epoch).await?;
  let proof_members = if epoch.version == MEMBERSHIP_DOCUMENT_VERSION {
    target_members
  } else {
    Vec::new()
  };
  let receipt_version = epoch.version;
  let artifact_key_fingerprint = epoch.artifact_key_fingerprint.clone();
  let ordinal = transition.receipt_count;
  ensure!(
    (0..4_096).contains(&ordinal),
    "membership receipt count is exhausted"
  );
  let payload = serde_json::json!({
    "version": receipt_version,
    "kind": "activation_authorization",
    "activation_request_id": activation_request_id,
    "transition_id": request.transition_id,
    "target_epoch": request.expected_target_epoch,
    "authorization_coordinator_epoch": authorization_coordinator_epoch,
    "artifact_key_fingerprint": artifact_key_fingerprint,
    "key_proof_members": proof_members,
    "approving_members": approving_members,
  });
  insert_membership_receipt(
    connection,
    namespace,
    cluster_id,
    &request.transition_id,
    ordinal,
    "activation_authorization",
    None,
    &payload,
  )
  .await?;
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='activation_authorized',state_version=state_version+1,
            activation_request_id=$5,receipt_count=receipt_count+1,fence_cutoff=NULL,
            blocking_reason=NULL,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state='ready' AND state_version=$4
      RETURNING transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
        member_id,proposal_request_id,activation_request_id,blocking_reason,
        catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
        verified_position,capability_result,key_proof_count,key_proof_required,
        receipt_count,fence_cutoff,
        created_at::text AS created_at,updated_at::text AS updated_at",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&request.transition_id)
  .bind(transition.state_version)
  .bind(activation_request_id)
  .fetch_one(&mut *connection)
  .await?;
  Ok((
    transition_from_row(&updated)?,
    MembershipMutationCheckpoint::ActivationAuthorization {
      cluster_id: cluster_id.to_string(),
      transition_id: request.transition_id.clone(),
      target_epoch_digest: request.expected_target_epoch.clone(),
      activation_request_id: activation_request_id.to_string(),
      previous_state_version: transition.state_version,
    },
  ))
}

pub(crate) async fn cancel_membership_transition_tx(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  cancellation_request_id: &str,
  request: &MembershipCancelRequest,
) -> anyhow::Result<(MembershipTransition, MembershipMutationCheckpoint)> {
  request.validate()?;
  let row =
    membership_transition_for_update(connection, namespace, cluster_id, &request.transition_id)
      .await?;
  let transition = transition_from_row(&row)?;
  let previous = MembershipTransitionState::parse(&transition.state)?;
  ensure!(
    transition.state != "activation_authorized"
      && previous.may_transition_to(MembershipTransitionState::Cancelled),
    "membership transition can be cancelled only before activation authorization"
  );
  ensure!(
    transition.target_epoch_digest == request.expected_target_epoch,
    "membership cancellation target epoch is stale"
  );
  let ordinal = transition.receipt_count;
  ensure!(
    (0..4_096).contains(&ordinal),
    "membership receipt count is exhausted"
  );
  let payload = serde_json::json!({
    "version": 1,
    "kind": "cancellation",
    "cancellation_request_id": cancellation_request_id,
    "transition_id": request.transition_id,
    "target_epoch": request.expected_target_epoch,
  });
  insert_membership_receipt(
    connection,
    namespace,
    cluster_id,
    &request.transition_id,
    ordinal,
    "cancellation",
    None,
    &payload,
  )
  .await?;
  let epoch_cancelled = sqlx::query(
    "UPDATE oxibelt_admin_membership_epochs SET state='cancelled'
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='staged'",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&request.expected_target_epoch)
  .execute(&mut *connection)
  .await?
  .rows_affected();
  ensure!(
    epoch_cancelled == 1,
    "membership cancellation target epoch is not staged"
  );
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='cancelled',state_version=state_version+1,
            receipt_count=receipt_count+1,blocking_reason=NULL,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state=$4 AND state_version=$5
      RETURNING transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
        member_id,proposal_request_id,activation_request_id,blocking_reason,
        catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
        verified_position,capability_result,key_proof_count,key_proof_required,
        receipt_count,fence_cutoff,
        created_at::text AS created_at,updated_at::text AS updated_at",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&request.transition_id)
  .bind(&transition.state)
  .bind(transition.state_version)
  .fetch_one(&mut *connection)
  .await?;
  Ok((
    transition_from_row(&updated)?,
    MembershipMutationCheckpoint::Cancellation {
      cluster_id: cluster_id.to_string(),
      transition_id: request.transition_id.clone(),
      target_epoch_digest: request.expected_target_epoch.clone(),
      cancellation_request_id: cancellation_request_id.to_string(),
      previous_state: transition.state,
      previous_state_version: transition.state_version,
      previous_blocking_reason: transition.blocking_reason,
    },
  ))
}

async fn membership_transition_for_update(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  transition_id: &str,
) -> anyhow::Result<sqlx::postgres::PgRow> {
  Ok(
    sqlx::query(
      "SELECT transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
            member_id,proposal_request_id,activation_request_id,blocking_reason,
            catchup_cursor,catchup_digest,checkpoint_digest,journal_tail_digest,
            verified_position,capability_result,key_proof_count,key_proof_required,
            receipt_count,fence_cutoff,
            created_at::text AS created_at,updated_at::text AS updated_at
       FROM oxibelt_admin_membership_transitions
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3 FOR UPDATE",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(transition_id)
    .fetch_one(&mut *connection)
    .await?,
  )
}

#[allow(clippy::too_many_arguments)]
async fn insert_membership_receipt(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  transition_id: &str,
  ordinal: i32,
  receipt_kind: &str,
  instance_id: Option<&str>,
  payload: &serde_json::Value,
) -> anyhow::Result<()> {
  let encoded = serde_json::to_vec(payload)?;
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_receipts
       (namespace,cluster_id,transition_id,ordinal,receipt_kind,instance_id,payload_digest,payload)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(transition_id)
  .bind(ordinal)
  .bind(receipt_kind)
  .bind(instance_id)
  .bind(super::artifact::sha256_digest(&encoded))
  .bind(serde_json::to_string(payload)?)
  .execute(&mut *connection)
  .await?;
  Ok(())
}

pub(crate) async fn restore_membership_mutation_tx(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  checkpoint: &MembershipMutationCheckpoint,
) -> anyhow::Result<()> {
  match checkpoint {
    MembershipMutationCheckpoint::Proposal { .. } => {
      restore_membership_proposal_checkpoint_tx(connection, namespace, checkpoint).await
    }
    MembershipMutationCheckpoint::ActivationAuthorization {
      cluster_id,
      transition_id,
      target_epoch_digest,
      activation_request_id,
      previous_state_version,
    } => {
      let transition = transition_from_row(
        &membership_transition_for_update(connection, namespace, cluster_id, transition_id).await?,
      )?;
      ensure!(
        transition.target_epoch_digest == *target_epoch_digest
          && transition.activation_request_id.as_deref() == Some(activation_request_id.as_str())
          && transition.state == "activation_authorized"
          && transition.state_version == previous_state_version + 1,
        "membership activation authorization is not restorable"
      );
      ensure!(
        (0..4_096).contains(&transition.receipt_count),
        "membership activation rollback receipt count is exhausted"
      );
      let payload = serde_json::json!({
        "version": 2,
        "kind": "activation_authorization_rollback",
        "transition_id": transition_id,
        "target_epoch": target_epoch_digest,
        "activation_request_id": activation_request_id,
        "restored_state": "ready",
      });
      insert_membership_receipt(
        connection,
        namespace,
        cluster_id,
        transition_id,
        transition.receipt_count,
        "activation_authorization_rollback",
        None,
        &payload,
      )
      .await?;
      let restored = sqlx::query(
        "UPDATE oxibelt_admin_membership_transitions
            SET state='ready',state_version=state_version+1,activation_request_id=NULL,
                receipt_count=receipt_count+1,fence_cutoff=NULL,updated_at=now()
          WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
            AND target_epoch_digest=$4 AND activation_request_id=$5
            AND state='activation_authorized' AND state_version=$6",
      )
      .bind(namespace)
      .bind(cluster_id)
      .bind(transition_id)
      .bind(target_epoch_digest)
      .bind(activation_request_id)
      .bind(previous_state_version + 1)
      .execute(&mut *connection)
      .await?
      .rows_affected();
      ensure!(
        restored == 1,
        "membership activation authorization is not restorable"
      );
      Ok(())
    }
    MembershipMutationCheckpoint::Cancellation {
      cluster_id,
      transition_id,
      target_epoch_digest,
      cancellation_request_id,
      previous_state,
      previous_state_version,
      previous_blocking_reason,
    } => {
      MembershipTransitionState::parse(previous_state)?;
      let transition = transition_from_row(
        &membership_transition_for_update(connection, namespace, cluster_id, transition_id).await?,
      )?;
      ensure!(
        transition.target_epoch_digest == *target_epoch_digest
          && transition.state == "cancelled"
          && transition.state_version == previous_state_version + 1,
        "membership cancellation is not restorable"
      );
      ensure!(
        (0..4_096).contains(&transition.receipt_count),
        "membership cancellation rollback receipt count is exhausted"
      );
      let payload = serde_json::json!({
        "version": 2,
        "kind": "cancellation_rollback",
        "transition_id": transition_id,
        "target_epoch": target_epoch_digest,
        "cancellation_request_id": cancellation_request_id,
        "restored_state": previous_state,
        "restored_blocking_reason": previous_blocking_reason,
      });
      insert_membership_receipt(
        connection,
        namespace,
        cluster_id,
        transition_id,
        transition.receipt_count,
        "cancellation_rollback",
        None,
        &payload,
      )
      .await?;
      let epoch_restored = sqlx::query(
        "UPDATE oxibelt_admin_membership_epochs SET state='staged'
          WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='cancelled'",
      )
      .bind(namespace)
      .bind(cluster_id)
      .bind(target_epoch_digest)
      .execute(&mut *connection)
      .await?
      .rows_affected();
      ensure!(
        epoch_restored == 1,
        "membership cancellation target epoch is not restorable"
      );
      let restored = sqlx::query(
        "UPDATE oxibelt_admin_membership_transitions
            SET state=$5,state_version=state_version+1,receipt_count=receipt_count+1,
                blocking_reason=$7,updated_at=now()
          WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
            AND target_epoch_digest=$4 AND state='cancelled' AND state_version=$6",
      )
      .bind(namespace)
      .bind(cluster_id)
      .bind(transition_id)
      .bind(target_epoch_digest)
      .bind(previous_state)
      .bind(previous_state_version + 1)
      .bind(previous_blocking_reason)
      .execute(&mut *connection)
      .await?
      .rows_affected();
      ensure!(restored == 1, "membership cancellation is not restorable");
      Ok(())
    }
  }
}

async fn restore_membership_proposal_checkpoint_tx(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  checkpoint: &MembershipMutationCheckpoint,
) -> anyhow::Result<()> {
  let MembershipMutationCheckpoint::Proposal {
    cluster_id,
    transition_id,
    target_epoch_digest,
    created_head,
  } = checkpoint
  else {
    anyhow::bail!("membership checkpoint is not a proposal")
  };
  let row = sqlx::query(
    "SELECT receipt_count,state_version,state FROM oxibelt_admin_membership_transitions
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND target_epoch_digest=$4 AND state IN ('learner','catching_up','ready')
      FOR UPDATE",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(transition_id)
  .bind(target_epoch_digest)
  .fetch_one(&mut *connection)
  .await?;
  let receipt_count: i32 = row.try_get("receipt_count")?;
  let state_version: i64 = row.try_get("state_version")?;
  let previous_state: String = row.try_get("state")?;
  ensure!(
    (0..4_096).contains(&receipt_count),
    "membership proposal rollback receipt count is exhausted"
  );
  let payload = serde_json::json!({
    "version": 2,
    "kind": "proposal_rollback",
    "transition_id": transition_id,
    "target_epoch": target_epoch_digest,
    "previous_state": previous_state,
    "created_head": created_head,
  });
  insert_membership_receipt(
    connection,
    namespace,
    cluster_id,
    transition_id,
    receipt_count,
    "proposal_rollback",
    None,
    &payload,
  )
  .await?;
  let restored = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='cancelled',state_version=state_version+1,
            receipt_count=receipt_count+1,blocking_reason='proposal_rolled_back',
            updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND target_epoch_digest=$4 AND state_version=$5",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(transition_id)
  .bind(target_epoch_digest)
  .bind(state_version)
  .execute(&mut *connection)
  .await?
  .rows_affected();
  ensure!(
    restored == 1,
    "membership proposal is no longer exactly restorable"
  );
  let epoch_retained = sqlx::query(
    "UPDATE oxibelt_admin_membership_epochs SET state='indeterminate'
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='staged'",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(target_epoch_digest)
  .execute(&mut *connection)
  .await?
  .rows_affected();
  ensure!(
    epoch_retained == 1,
    "staged membership epoch is no longer exactly restorable"
  );
  Ok(())
}

pub(crate) async fn finalize_committed_membership_activation(
  store: &MutationStore,
  cluster_id: &str,
) -> anyhow::Result<Option<ActiveMembershipAuthority>> {
  let mut tx = store.pool().begin().await?;
  if reconcile_indeterminate_membership_activation_tx(&mut tx, store.namespace(), cluster_id)
    .await?
  {
    tx.commit().await?;
    return Ok(None);
  }
  let row = sqlx::query(
    "SELECT transition.transition_id,transition.kind,transition.state,
            transition.state_version,transition.source_epoch_digest,
            transition.target_epoch_digest,transition.member_id,
            transition.proposal_request_id,transition.activation_request_id,
            transition.blocking_reason,transition.catchup_cursor,transition.catchup_digest,
            transition.checkpoint_digest,transition.journal_tail_digest,
            transition.verified_position,transition.capability_result,
            transition.key_proof_count,transition.key_proof_required,
            transition.receipt_count,transition.fence_cutoff,
            transition.created_at::text AS created_at,transition.updated_at::text AS updated_at
       FROM oxibelt_admin_membership_transitions transition
       JOIN oxibelt_admin_mutations mutation
         ON mutation.namespace=transition.namespace
        AND mutation.request_id=transition.activation_request_id
      WHERE transition.namespace=$1 AND transition.cluster_id=$2
        AND transition.state='activation_authorized' AND mutation.state='committed'
      ORDER BY transition.created_at ASC FOR UPDATE OF transition SKIP LOCKED LIMIT 1",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_optional(&mut *tx)
  .await?;
  let Some(row) = row else {
    tx.rollback().await?;
    return Ok(None);
  };
  let transition = transition_from_row(&row)?;
  ensure!(
    MembershipTransitionState::ActivationAuthorized
      .may_transition_to(MembershipTransitionState::Fencing),
    "membership activation state transition is invalid"
  );
  ensure!(
    transition.receipt_count <= 4_094,
    "membership activation receipts exceed their bound"
  );
  let epoch_document: String = sqlx::query_scalar(
    "SELECT document::text FROM oxibelt_admin_membership_epochs
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='staged'",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.target_epoch_digest)
  .fetch_one(&mut *tx)
  .await?;
  let epoch: MembershipEpoch = serde_json::from_str(&epoch_document)
    .context("committed membership activation target epoch is malformed")?;
  ensure!(
    epoch.digest()? == transition.target_epoch_digest,
    "committed membership activation target epoch digest is invalid"
  );
  let members =
    validate_activation_evidence(&mut tx, store.namespace(), cluster_id, &transition, &epoch)
      .await?;
  let head = sqlx::query(
    "SELECT active_epoch_digest,active_epoch_sequence,state_version
       FROM oxibelt_admin_membership_heads
      WHERE namespace=$1 AND cluster_id=$2 FOR UPDATE",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_one(&mut *tx)
  .await?;
  let active_digest: Option<String> = head.try_get("active_epoch_digest")?;
  let prior_head_state_version: i64 = head.try_get("state_version")?;
  let fence_cutoff = prior_head_state_version
    .checked_add(1)
    .context("membership head state version overflow")?;
  ensure!(
    active_digest == transition.source_epoch_digest,
    "membership activation source epoch is stale"
  );
  let invalidated_heartbeats = sqlx::query(
    "UPDATE oxibelt_admin_instance_heartbeats
        SET ready=false,lease_expires_at=now(),updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND membership_revision<>$3",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.target_epoch_digest)
  .execute(&mut *tx)
  .await?
  .rows_affected();
  let fence_payload = serde_json::json!({
    "version": epoch.version,
    "kind": "fence_activation",
    "transition_id": transition.transition_id,
    "source_epoch": transition.source_epoch_digest,
    "target_epoch": transition.target_epoch_digest,
    "fence_cutoff": fence_cutoff,
    "invalidated_heartbeats": invalidated_heartbeats,
    "artifact_key_fingerprint": epoch.artifact_key_fingerprint,
  });
  insert_membership_receipt(
    &mut tx,
    store.namespace(),
    cluster_id,
    &transition.transition_id,
    transition.receipt_count,
    "fence_activation",
    transition.member_id.as_deref(),
    &fence_payload,
  )
  .await?;
  let fencing = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='fencing',state_version=state_version+1,
            receipt_count=receipt_count+1,fence_cutoff=$5,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state='activation_authorized' AND state_version=$4",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.transition_id)
  .bind(transition.state_version)
  .bind(fence_cutoff)
  .execute(&mut *tx)
  .await?
  .rows_affected();
  ensure!(fencing == 1, "membership activation fencing was superseded");
  if let Some(source) = transition.source_epoch_digest.as_deref() {
    let superseded = sqlx::query(
      "UPDATE oxibelt_admin_membership_epochs SET state='superseded'
        WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='active'",
    )
    .bind(store.namespace())
    .bind(cluster_id)
    .bind(source)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    ensure!(superseded == 1, "membership source epoch is not active");
  }
  let target_sequence: i64 = sqlx::query_scalar(
    "UPDATE oxibelt_admin_membership_epochs
        SET state='active',activated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='staged'
      RETURNING epoch_sequence",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.target_epoch_digest)
  .fetch_one(&mut *tx)
  .await?;
  let head_updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_heads
        SET active_epoch_digest=$3,active_epoch_sequence=$4,
            state_version=state_version+1,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND state_version=$5",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.target_epoch_digest)
  .bind(target_sequence)
  .bind(prior_head_state_version)
  .execute(&mut *tx)
  .await?
  .rows_affected();
  ensure!(head_updated == 1, "membership head cutover was superseded");
  sqlx::query(
    "UPDATE oxibelt_admin_mutation_revisions
        SET membership_revision=$3,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.target_epoch_digest)
  .execute(&mut *tx)
  .await?;
  let activation_id = transition
    .activation_request_id
    .as_deref()
    .context("membership activation request ID is missing")?;
  let payload = serde_json::json!({
    "version": epoch.version,
    "kind": "activation",
    "activation_request_id": activation_id,
    "transition_id": transition.transition_id,
    "source_epoch": transition.source_epoch_digest,
    "target_epoch": transition.target_epoch_digest,
    "fence_cutoff": fence_cutoff,
    "artifact_key_fingerprint": epoch.artifact_key_fingerprint,
  });
  insert_membership_receipt(
    &mut tx,
    store.namespace(),
    cluster_id,
    &transition.transition_id,
    transition.receipt_count + 1,
    "activation",
    transition.member_id.as_deref(),
    &payload,
  )
  .await?;
  sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='active',state_version=state_version+1,
            receipt_count=receipt_count+1,blocking_reason=NULL,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state='fencing' AND state_version=$4",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.transition_id)
  .bind(transition.state_version + 1)
  .execute(&mut *tx)
  .await?;
  tx.commit().await?;
  Ok(Some(ActiveMembershipAuthority {
    epoch_digest: transition.target_epoch_digest,
    members,
    epoch_version: epoch.version,
    artifact_key_fingerprint: epoch.artifact_key_fingerprint.clone(),
    epoch,
  }))
}

async fn reconcile_indeterminate_membership_activation_tx(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
) -> anyhow::Result<bool> {
  let row = sqlx::query(
    "SELECT transition.transition_id,transition.target_epoch_digest,
            transition.activation_request_id,transition.receipt_count,
            transition.state_version
       FROM oxibelt_admin_membership_transitions transition
       JOIN oxibelt_admin_mutations mutation
         ON mutation.namespace=transition.namespace
        AND mutation.request_id=transition.activation_request_id
      WHERE transition.namespace=$1 AND transition.cluster_id=$2
        AND transition.state IN ('activation_authorized','fencing')
        AND mutation.state='indeterminate'
      ORDER BY transition.created_at ASC FOR UPDATE OF transition LIMIT 1",
  )
  .bind(namespace)
  .bind(cluster_id)
  .fetch_optional(&mut *connection)
  .await?;
  let Some(row) = row else {
    return Ok(false);
  };
  let transition_id: String = row.try_get("transition_id")?;
  let target_epoch_digest: String = row.try_get("target_epoch_digest")?;
  let activation_request_id: Option<String> = row.try_get("activation_request_id")?;
  let receipt_count: i32 = row.try_get("receipt_count")?;
  let state_version: i64 = row.try_get("state_version")?;
  ensure!(
    (0..4_096).contains(&receipt_count),
    "membership indeterminate receipt count is exhausted"
  );
  let payload = serde_json::json!({
    "version": 2,
    "kind": "activation_indeterminate",
    "transition_id": transition_id,
    "activation_request_id": activation_request_id,
    "target_epoch": target_epoch_digest,
  });
  insert_membership_receipt(
    connection,
    namespace,
    cluster_id,
    &transition_id,
    receipt_count,
    "activation_indeterminate",
    None,
    &payload,
  )
  .await?;
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='indeterminate',state_version=state_version+1,
            receipt_count=receipt_count+1,blocking_reason='activation_indeterminate',
            updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3 AND state_version=$4",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&transition_id)
  .bind(state_version)
  .execute(&mut *connection)
  .await?
  .rows_affected();
  ensure!(updated == 1, "membership indeterminate transition changed");
  sqlx::query(
    "UPDATE oxibelt_admin_membership_epochs SET state='indeterminate'
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='staged'",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&target_epoch_digest)
  .execute(&mut *connection)
  .await?;
  Ok(true)
}

fn transition_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<MembershipTransition> {
  Ok(MembershipTransition {
    transition_id: row.try_get("transition_id")?,
    kind: row.try_get("kind")?,
    state: row.try_get("state")?,
    state_version: row.try_get("state_version")?,
    source_epoch_digest: row.try_get("source_epoch_digest")?,
    target_epoch_digest: row.try_get("target_epoch_digest")?,
    member_id: row.try_get("member_id")?,
    proposal_request_id: row.try_get("proposal_request_id")?,
    activation_request_id: row.try_get("activation_request_id")?,
    blocking_reason: row.try_get("blocking_reason")?,
    catchup_cursor: row.try_get("catchup_cursor")?,
    catchup_digest: row.try_get("catchup_digest")?,
    checkpoint_digest: row.try_get("checkpoint_digest")?,
    journal_tail_digest: row.try_get("journal_tail_digest")?,
    verified_position: row.try_get("verified_position")?,
    capability_result: row.try_get("capability_result")?,
    key_proof_count: row.try_get("key_proof_count")?,
    key_proof_required: row.try_get("key_proof_required")?,
    receipt_count: row.try_get("receipt_count")?,
    fence_cutoff: row.try_get("fence_cutoff")?,
    created_at: row.try_get("created_at")?,
    updated_at: row.try_get("updated_at")?,
  })
}

fn ensure_membership_epoch_capacity(retained_epoch_count: i64) -> anyhow::Result<()> {
  ensure!(
    (0..i64::try_from(MAX_MEMBERSHIP_EPOCH_KEYS)?).contains(&retained_epoch_count),
    "membership epoch retention limit reached; new proposals remain disabled until a reviewed supported retention migration is available"
  );
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};

  fn evidence_transition(
    target_epoch_digest: String,
    kind: &str,
    member_id: Option<String>,
    source_epoch_digest: Option<String>,
  ) -> MembershipTransition {
    MembershipTransition {
      transition_id: "transition-1".to_string(),
      kind: kind.to_string(),
      state: "ready".to_string(),
      state_version: 1,
      source_epoch_digest,
      target_epoch_digest,
      member_id,
      proposal_request_id: "proposal-1".to_string(),
      activation_request_id: None,
      blocking_reason: None,
      catchup_cursor: 1,
      catchup_digest: Some(
        "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string(),
      ),
      checkpoint_digest: Some(
        "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_string(),
      ),
      journal_tail_digest: Some(
        "sha256:4444444444444444444444444444444444444444444444444444444444444444".to_string(),
      ),
      verified_position: Some(7),
      capability_result: "compatible".to_string(),
      key_proof_count: 2,
      key_proof_required: 2,
      receipt_count: 2,
      fence_cutoff: None,
      created_at: "now".to_string(),
      updated_at: "now".to_string(),
    }
  }

  #[test]
  fn activation_rejects_stale_or_mixed_build_key_proof_and_readiness() {
    let pair = Ed25519KeyPair::generate().expect("readiness key");
    let learner = MembershipMember {
      id: "edge-a".to_string(),
      readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD
        .encode(pair.public_key().as_ref()),
      catchup_x25519_public_key: base64::engine::general_purpose::STANDARD.encode([9_u8; 32]),
    };
    let peer = MembershipMember {
      id: "edge-b".to_string(),
      readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD.encode([10_u8; 32]),
      catchup_x25519_public_key: base64::engine::general_purpose::STANDARD.encode([11_u8; 32]),
    };
    let source =
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let epoch = MembershipEpoch::new_v2(
      "cluster-a".to_string(),
      1,
      Some(source.clone()),
      "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
      vec![learner.clone(), peer],
      "proposal-1".to_string(),
    )
    .expect("epoch");
    let target = epoch.digest().expect("epoch digest");
    let transition = evidence_transition(
      target.clone(),
      "join",
      Some(learner.id.clone()),
      Some(source.clone()),
    );
    let signed_proof =
      |issued_at_unix_seconds: i64, build_version: &str, capability_version: &str| {
        let mut proof = MembershipKeyProof {
          version: 2,
          transition_id: transition.transition_id.clone(),
          target_epoch: target.clone(),
          member_id: learner.id.clone(),
          artifact_key_fingerprint: epoch.artifact_key_fingerprint.clone().expect("fingerprint"),
          build_version: build_version.to_string(),
          capability_version: capability_version.to_string(),
          issued_at_unix_seconds,
          signature: base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
        };
        if capability_version == MEMBERSHIP_CAPABILITY_VERSION {
          proof.signature = base64::engine::general_purpose::STANDARD.encode(
            pair
              .sign(&proof.transcript("cluster-a").expect("proof transcript"))
              .as_ref(),
          );
        }
        proof
      };
    verify_activation_key_proof(
      "cluster-a",
      &transition,
      &epoch,
      &learner,
      &signed_proof(
        1_000,
        oxibelt_build_identity::SHORT_VERSION,
        MEMBERSHIP_CAPABILITY_VERSION,
      ),
      1_000,
    )
    .expect("fresh proof");
    assert!(
      verify_activation_key_proof(
        "cluster-a",
        &transition,
        &epoch,
        &learner,
        &signed_proof(
          699,
          oxibelt_build_identity::SHORT_VERSION,
          MEMBERSHIP_CAPABILITY_VERSION,
        ),
        1_000,
      )
      .is_err()
    );
    assert!(
      verify_activation_key_proof(
        "cluster-a",
        &transition,
        &epoch,
        &learner,
        &signed_proof(1_000, "older-build", MEMBERSHIP_CAPABILITY_VERSION),
        1_000,
      )
      .is_err()
    );
    assert!(
      verify_activation_key_proof(
        "cluster-a",
        &transition,
        &epoch,
        &learner,
        &signed_proof(
          1_000,
          oxibelt_build_identity::SHORT_VERSION,
          "membership-v1",
        ),
        1_000,
      )
      .is_err()
    );

    let signed_readiness =
      |issued_at_unix_seconds: i64, build_version: &str, capability_version: &str| {
        let mut receipt = MembershipReadinessReceipt {
          version: 2,
          transition_id: transition.transition_id.clone(),
          target_epoch: target.clone(),
          member_id: learner.id.clone(),
          catchup_cursor: 1,
          catchup_digest: transition.catchup_digest.clone().expect("catchup digest"),
          source_epoch: Some(source.clone()),
          artifact_key_fingerprint: epoch.artifact_key_fingerprint.clone(),
          checkpoint_digest: transition.checkpoint_digest.clone(),
          journal_tail_digest: transition.journal_tail_digest.clone(),
          verified_position: Some(7),
          build_version: build_version.to_string(),
          capability_version: capability_version.to_string(),
          issued_at_unix_seconds,
          signature: base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
        };
        if capability_version == MEMBERSHIP_CAPABILITY_VERSION {
          receipt.signature = base64::engine::general_purpose::STANDARD.encode(
            pair
              .sign(
                &receipt
                  .transcript("cluster-a")
                  .expect("readiness transcript"),
              )
              .as_ref(),
          );
        }
        receipt
      };
    verify_activation_readiness(
      "cluster-a",
      &transition,
      &epoch,
      &learner,
      &signed_readiness(
        1_000,
        oxibelt_build_identity::SHORT_VERSION,
        MEMBERSHIP_CAPABILITY_VERSION,
      ),
      1_000,
    )
    .expect("fresh readiness");
    assert!(
      verify_activation_readiness(
        "cluster-a",
        &transition,
        &epoch,
        &learner,
        &signed_readiness(
          699,
          oxibelt_build_identity::SHORT_VERSION,
          MEMBERSHIP_CAPABILITY_VERSION,
        ),
        1_000,
      )
      .is_err()
    );
    assert!(
      verify_activation_readiness(
        "cluster-a",
        &transition,
        &epoch,
        &learner,
        &signed_readiness(1_000, "older-build", MEMBERSHIP_CAPABILITY_VERSION),
        1_000,
      )
      .is_err()
    );
    assert!(
      verify_activation_readiness(
        "cluster-a",
        &transition,
        &epoch,
        &learner,
        &signed_readiness(
          1_000,
          oxibelt_build_identity::SHORT_VERSION,
          "membership-v1",
        ),
        1_000,
      )
      .is_err()
    );
  }

  #[test]
  fn epoch_member_index_rejects_public_key_drift() {
    let members = vec![
      MembershipMember {
        id: "edge-a".to_string(),
        readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD.encode([1_u8; 32]),
        catchup_x25519_public_key: base64::engine::general_purpose::STANDARD.encode([2_u8; 32]),
      },
      MembershipMember {
        id: "edge-b".to_string(),
        readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD.encode([3_u8; 32]),
        catchup_x25519_public_key: base64::engine::general_purpose::STANDARD.encode([4_u8; 32]),
      },
    ];
    let epoch = MembershipEpoch::new_v2(
      "cluster-a".to_string(),
      0,
      None,
      "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
      members.clone(),
      "proposal-1".to_string(),
    )
    .expect("epoch");
    verify_epoch_members(&epoch, members.clone()).expect("exact index");
    let mut drifted = members;
    drifted[0].catchup_x25519_public_key =
      base64::engine::general_purpose::STANDARD.encode([5_u8; 32]);
    assert!(verify_epoch_members(&epoch, drifted).is_err());
  }

  #[test]
  fn epoch_retention_limit_fails_closed_without_automatic_pruning() {
    ensure_membership_epoch_capacity(63).expect("last supported retained epoch slot");
    let error = ensure_membership_epoch_capacity(64).expect_err("retention hard stop");
    assert!(
      error
        .to_string()
        .contains("new proposals remain disabled until a reviewed supported retention migration")
    );
    assert!(ensure_membership_epoch_capacity(65).is_err());
  }

  #[tokio::test]
  async fn postgres_membership_proposal_is_serialized_and_recoverable() {
    let Some(pool) = super::super::postgres_test_support::connect("membership proposal").await
    else {
      return;
    };
    super::super::store::init_postgres(&pool)
      .await
      .expect("membership schema");
    let namespace = format!(
      "membership-{}",
      std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
    );
    let store = MutationStore::new_cluster(pool.clone(), namespace.clone()).expect("store");
    let member = |id: &str, key: u8| MembershipMember {
      id: id.to_string(),
      readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD.encode([key; 32]),
      catchup_x25519_public_key: base64::engine::general_purpose::STANDARD
        .encode([key.wrapping_add(1); 32]),
    };
    let bootstrap = vec![member("edge-a", 1), member("edge-b", 3)];
    let request = MembershipTransitionRequest {
      version: 1,
      kind: MembershipTransitionKind::Initialize,
      expected_active_epoch: None,
      member: None,
    };
    let source_revision = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let mut artifact_ciphers = MembershipArtifactCiphers::new();
    artifact_ciphers.insert(
      source_revision.to_string(),
      Arc::new(
        MutationArtifactCipher::new(&[42_u8; 32], super::super::store::MAX_STORED_ARTIFACT_BYTES)
          .expect("artifact cipher"),
      ),
    );
    let mut tx = pool.begin().await.expect("transaction");
    let (transition, _checkpoint) = apply_membership_proposal_tx(
      &mut tx,
      &namespace,
      "cluster-a",
      "initialize-1",
      "initialize-1",
      &request,
      &bootstrap,
      &["edge-a".to_string(), "edge-b".to_string()],
      source_revision,
      &artifact_ciphers,
    )
    .await
    .expect("proposal");
    assert_eq!(transition.state, "ready");
    tx.commit().await.expect("commit");
    let durable_cluster_ids = durable_membership_cluster_ids_if_present(&pool, &namespace)
      .await
      .expect("disabled-mode durable membership lookup");
    assert_eq!(durable_cluster_ids, vec!["cluster-a".to_string()]);
    let status = load_membership_status(&store, "cluster-a", &bootstrap)
      .await
      .expect("status");
    assert_eq!(
      status.pending_transition.expect("pending").transition_id,
      "initialize-1"
    );
    sqlx::query(
      "UPDATE oxibelt_admin_membership_transitions
          SET blocking_reason='waiting_for_operator'
        WHERE namespace=$1 AND cluster_id='cluster-a' AND transition_id='initialize-1'",
    )
    .bind(&namespace)
    .execute(&pool)
    .await
    .expect("set cancellation rollback fixture");
    let cancellation = MembershipCancelRequest {
      version: 1,
      transition_id: transition.transition_id.clone(),
      expected_target_epoch: transition.target_epoch_digest.clone(),
    };
    let mut cancel = pool.begin().await.expect("cancel transaction");
    let (cancelled, cancellation_checkpoint) = cancel_membership_transition_tx(
      &mut cancel,
      &namespace,
      "cluster-a",
      "cancel-1",
      &cancellation,
    )
    .await
    .expect("cancel proposal");
    assert_eq!(cancelled.state, "cancelled");
    cancel.commit().await.expect("cancel commit");
    let cancelled_epoch_state: String = sqlx::query_scalar(
      "SELECT state FROM oxibelt_admin_membership_epochs
        WHERE namespace=$1 AND cluster_id='cluster-a' AND epoch_digest=$2",
    )
    .bind(&namespace)
    .bind(&transition.target_epoch_digest)
    .fetch_one(&pool)
    .await
    .expect("cancelled epoch");
    assert_eq!(cancelled_epoch_state, "cancelled");

    let mut restore = pool
      .begin()
      .await
      .expect("restore cancellation transaction");
    restore_membership_mutation_tx(&mut restore, &namespace, &cancellation_checkpoint)
      .await
      .expect("restore cancellation");
    restore.commit().await.expect("restore cancellation commit");
    let (restored_state, restored_reason, restored_epoch_state): (String, Option<String>, String) =
      sqlx::query_as(
        "SELECT transition.state,transition.blocking_reason,epoch.state
           FROM oxibelt_admin_membership_transitions transition
           JOIN oxibelt_admin_membership_epochs epoch
             ON epoch.namespace=transition.namespace AND epoch.cluster_id=transition.cluster_id
            AND epoch.epoch_digest=transition.target_epoch_digest
          WHERE transition.namespace=$1 AND transition.cluster_id='cluster-a'
            AND transition.transition_id='initialize-1'",
      )
      .bind(&namespace)
      .fetch_one(&pool)
      .await
      .expect("restored cancellation state");
    assert_eq!(restored_state, "ready");
    assert_eq!(restored_reason.as_deref(), Some("waiting_for_operator"));
    assert_eq!(restored_epoch_state, "staged");

    let mut cancel = pool.begin().await.expect("second cancel transaction");
    cancel_membership_transition_tx(
      &mut cancel,
      &namespace,
      "cluster-a",
      "cancel-2",
      &cancellation,
    )
    .await
    .expect("cancel restored proposal");
    cancel.commit().await.expect("second cancel commit");

    let mut repropose = pool.begin().await.expect("reproposal transaction");
    let (replacement, replacement_checkpoint) = apply_membership_proposal_tx(
      &mut repropose,
      &namespace,
      "cluster-a",
      "initialize-2",
      "initialize-2",
      &request,
      &bootstrap,
      &["edge-a".to_string(), "edge-b".to_string()],
      source_revision,
      &artifact_ciphers,
    )
    .await
    .expect("proposal after cancellation");
    assert_eq!(replacement.state, "ready");
    repropose.commit().await.expect("reproposal commit");

    let mut restore = pool.begin().await.expect("restore replacement transaction");
    restore_membership_mutation_tx(&mut restore, &namespace, &replacement_checkpoint)
      .await
      .expect("restore replacement proposal");
    restore.commit().await.expect("restore replacement commit");
    assert!(
      load_membership_status(&store, "cluster-a", &bootstrap)
        .await
        .expect("restored status")
        .pending_transition
        .is_none()
    );

    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_transitions
         (namespace,cluster_id,transition_id,kind,state,source_epoch_digest,
          target_epoch_digest,member_id,proposal_request_id,created_at)
       VALUES
         ($1,'cluster-a','maintenance-active','maintenance','active',NULL,
          'sha256:1111111111111111111111111111111111111111111111111111111111111111',
          'edge-b','maintenance-active',now()),
         ($1,'cluster-a','rejoin-cancelled','rejoin','cancelled',NULL,
          'sha256:2222222222222222222222222222222222222222222222222222222222222222',
          'edge-b','rejoin-cancelled',now() + interval '1 second')",
    )
    .bind(&namespace)
    .execute(&pool)
    .await
    .expect("fenced-member fixture");
    assert_eq!(
      load_membership_status(&store, "cluster-a", &bootstrap)
        .await
        .expect("fenced status after cancelled rejoin")
        .fenced_members,
      vec!["edge-b".to_string()]
    );
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_transitions
         (namespace,cluster_id,transition_id,kind,state,source_epoch_digest,
          target_epoch_digest,member_id,proposal_request_id,created_at)
       VALUES
         ($1,'cluster-a','rejoin-active','rejoin','active',NULL,
          'sha256:3333333333333333333333333333333333333333333333333333333333333333',
          'edge-b','rejoin-active',now() + interval '2 seconds')",
    )
    .bind(&namespace)
    .execute(&pool)
    .await
    .expect("active rejoin fixture");
    assert!(
      load_membership_status(&store, "cluster-a", &bootstrap)
        .await
        .expect("status after active rejoin")
        .fenced_members
        .is_empty()
    );
  }

  #[tokio::test]
  async fn postgres_proposal_rekeys_current_artifact_from_source_epoch_replica() {
    let Some(pool) = super::super::postgres_test_support::connect("membership epoch rekey").await
    else {
      return;
    };
    super::super::store::init_postgres(&pool)
      .await
      .expect("membership schema");
    let namespace = format!(
      "membership-rekey-{}",
      std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
    );
    let member = |id: &str, key: u8| MembershipMember {
      id: id.to_string(),
      readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD.encode([key; 32]),
      catchup_x25519_public_key: base64::engine::general_purpose::STANDARD
        .encode([key.wrapping_add(1); 32]),
    };
    let members = vec![
      member("edge-a", 1),
      member("edge-b", 3),
      member("edge-c", 5),
    ];
    let epoch_a =
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let cipher_a =
      MutationArtifactCipher::new(&[41_u8; 32], super::super::store::MAX_STORED_ARTIFACT_BYTES)
        .expect("epoch A cipher");
    let cipher_b = Arc::new(
      MutationArtifactCipher::new(&[42_u8; 32], super::super::store::MAX_STORED_ARTIFACT_BYTES)
        .expect("epoch B cipher"),
    );
    let epoch_b = MembershipEpoch::new_v2(
      "cluster-a".to_string(),
      1,
      Some(epoch_a.clone()),
      cipher_b.key_fingerprint().to_string(),
      members.clone(),
      "activate-b".to_string(),
    )
    .expect("epoch B");
    let epoch_b_digest = epoch_b.digest().expect("epoch B digest");
    let plaintext_bytes = b"artifact survives A to B to C".to_vec();
    let content_digest = super::super::artifact::sha256_digest(&plaintext_bytes);
    let binding = ArtifactBinding {
      namespace: namespace.clone(),
      request_id: "artifact-a".to_string(),
      fingerprint: "fingerprint-a".to_string(),
      principal: "operator-a".to_string(),
      signer_id: "signer-a".to_string(),
      action: "replace".to_string(),
      resource: "config-a".to_string(),
      cluster_id: "cluster-a".to_string(),
      membership_revision: epoch_a.clone(),
      new_revision: "revision-1".to_string(),
      expected_previous_revision: "revision-0".to_string(),
      content_digest: content_digest.clone(),
    };
    let artifact_a = cipher_a
      .seal(
        &binding,
        MutationArtifactPlaintext::new(plaintext_bytes.clone()),
      )
      .expect("epoch A artifact");
    let artifact_b = cipher_b
      .seal(&binding, MutationArtifactPlaintext::new(plaintext_bytes))
      .expect("epoch B replica");
    let mut tx = pool.begin().await.expect("rekey fixture transaction");
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_heads
         (namespace,cluster_id,active_epoch_digest,active_epoch_sequence)
       VALUES($1,'cluster-a',$2,1)",
    )
    .bind(&namespace)
    .bind(&epoch_b_digest)
    .execute(&mut *tx)
    .await
    .expect("epoch B head");
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_epochs
         (namespace,cluster_id,epoch_digest,epoch_sequence,predecessor_digest,
          artifact_key_fingerprint,document,authorized_request_id,state,activated_at)
       VALUES($1,'cluster-a',$2,1,$3,$4,$5::jsonb,'activate-b','active',now())",
    )
    .bind(&namespace)
    .bind(&epoch_b_digest)
    .bind(&epoch_a)
    .bind(cipher_b.key_fingerprint())
    .bind(serde_json::to_string(&epoch_b).expect("epoch B document"))
    .execute(&mut *tx)
    .await
    .expect("epoch B row");
    for member in &members {
      sqlx::query(
        "INSERT INTO oxibelt_admin_membership_epoch_members
           (namespace,cluster_id,epoch_digest,instance_id,
            readiness_ed25519_public_key,catchup_x25519_public_key)
         VALUES($1,'cluster-a',$2,$3,$4,$5)",
      )
      .bind(&namespace)
      .bind(&epoch_b_digest)
      .bind(&member.id)
      .bind(&member.readiness_ed25519_public_key)
      .bind(&member.catchup_x25519_public_key)
      .execute(&mut *tx)
      .await
      .expect("epoch B member");
    }
    sqlx::query(
      "INSERT INTO oxibelt_admin_mutations
         (namespace,request_id,fingerprint,principal,signer_id,action,resource,
          expected_previous_revision,new_revision,content_digest,cluster_id,
          membership_revision,state,audit_record_id,issued_at,expires_at,retention_until)
       VALUES($1,'artifact-a','fingerprint-a','operator-a','signer-a','replace','config-a',
          'revision-0','revision-1',$2,'cluster-a',$3,'committed',1,
          now(),now() + interval '1 hour',now() + interval '2 hours')",
    )
    .bind(&namespace)
    .bind(&content_digest)
    .bind(&epoch_a)
    .execute(&mut *tx)
    .await
    .expect("epoch A mutation");
    sqlx::query(
      "INSERT INTO oxibelt_admin_mutation_artifacts
         (namespace,request_id,fingerprint,resource,cluster_id,membership_revision,
          new_revision,content_digest,algorithm,nonce,ciphertext,ciphertext_digest,plaintext_len)
       VALUES($1,'artifact-a','fingerprint-a','config-a','cluster-a',$2,
          'revision-1',$3,$4,$5,$6,$7,$8)",
    )
    .bind(&namespace)
    .bind(&epoch_a)
    .bind(&content_digest)
    .bind(ARTIFACT_ALGORITHM)
    .bind(artifact_a.nonce.as_slice())
    .bind(artifact_a.ciphertext.as_slice())
    .bind(&artifact_a.ciphertext_digest)
    .bind(i32::try_from(artifact_a.plaintext_len).expect("artifact A length"))
    .execute(&mut *tx)
    .await
    .expect("epoch A artifact row");
    sqlx::query(
      "INSERT INTO oxibelt_admin_mutation_revisions
         (namespace,resource,committed_revision,content_digest,cluster_id,membership_revision)
       VALUES($1,'config-a','revision-1',$2,'cluster-a',$3)",
    )
    .bind(&namespace)
    .bind(&content_digest)
    .bind(&epoch_b_digest)
    .execute(&mut *tx)
    .await
    .expect("epoch B logical head");
    sqlx::query(
      "INSERT INTO oxibelt_admin_membership_epoch_artifacts
         (namespace,cluster_id,epoch_digest,resource,request_id,algorithm,nonce,
          ciphertext,ciphertext_digest,plaintext_len)
       VALUES($1,'cluster-a',$2,'config-a','artifact-a',$3,$4,$5,$6,$7)",
    )
    .bind(&namespace)
    .bind(&epoch_b_digest)
    .bind(ARTIFACT_ALGORITHM)
    .bind(artifact_b.nonce.as_slice())
    .bind(artifact_b.ciphertext.as_slice())
    .bind(&artifact_b.ciphertext_digest)
    .bind(i32::try_from(artifact_b.plaintext_len).expect("artifact B length"))
    .execute(&mut *tx)
    .await
    .expect("epoch B artifact replica");
    tx.commit().await.expect("commit epoch B fixture");

    let store = MutationStore::new_cluster(pool.clone(), namespace.clone()).expect("store");
    load_membership_status(&store, "cluster-a", &[])
      .await
      .expect("consistent epoch B status");
    sqlx::query(
      "UPDATE oxibelt_admin_membership_heads SET active_epoch_sequence=2
        WHERE namespace=$1 AND cluster_id='cluster-a'",
    )
    .bind(&namespace)
    .execute(&pool)
    .await
    .expect("drift head sequence");
    assert!(
      load_membership_status(&store, "cluster-a", &[])
        .await
        .is_err()
    );
    sqlx::query(
      "UPDATE oxibelt_admin_membership_heads SET active_epoch_sequence=1
        WHERE namespace=$1 AND cluster_id='cluster-a'",
    )
    .bind(&namespace)
    .execute(&pool)
    .await
    .expect("restore head sequence");
    sqlx::query(
      "UPDATE oxibelt_admin_membership_epoch_members
          SET catchup_x25519_public_key=$3
        WHERE namespace=$1 AND cluster_id='cluster-a' AND epoch_digest=$2
          AND instance_id='edge-a'",
    )
    .bind(&namespace)
    .bind(&epoch_b_digest)
    .bind(base64::engine::general_purpose::STANDARD.encode([77_u8; 32]))
    .execute(&pool)
    .await
    .expect("drift epoch member key");
    assert!(
      load_membership_status(&store, "cluster-a", &[])
        .await
        .is_err()
    );
    sqlx::query(
      "UPDATE oxibelt_admin_membership_epoch_members
          SET catchup_x25519_public_key=$3
        WHERE namespace=$1 AND cluster_id='cluster-a' AND epoch_digest=$2
          AND instance_id='edge-a'",
    )
    .bind(&namespace)
    .bind(&epoch_b_digest)
    .bind(&members[0].catchup_x25519_public_key)
    .execute(&pool)
    .await
    .expect("restore epoch member key");

    let mut artifact_ciphers = MembershipArtifactCiphers::new();
    artifact_ciphers.insert(epoch_b_digest.clone(), cipher_b);
    let request = MembershipTransitionRequest {
      version: 1,
      kind: MembershipTransitionKind::Remove,
      expected_active_epoch: Some(epoch_b_digest.clone()),
      member: Some(members[2].clone()),
    };
    let approvers = members
      .iter()
      .map(|member| member.id.clone())
      .collect::<Vec<_>>();
    let mut tx = pool.begin().await.expect("epoch C proposal transaction");
    let (transition, _) = apply_membership_proposal_tx(
      &mut tx,
      &namespace,
      "cluster-a",
      "remove-c",
      "remove-c",
      &request,
      &[],
      &approvers,
      &epoch_b_digest,
      &artifact_ciphers,
    )
    .await
    .expect("epoch C proposal from epoch B replica without epoch A key");
    let replica_digest: String = sqlx::query_scalar(
      "SELECT ciphertext_digest FROM oxibelt_admin_membership_epoch_artifacts
        WHERE namespace=$1 AND cluster_id='cluster-a' AND epoch_digest=$2
          AND resource='config-a' AND request_id='artifact-a'",
    )
    .bind(&namespace)
    .bind(&transition.target_epoch_digest)
    .fetch_one(&mut *tx)
    .await
    .expect("epoch C artifact replica");
    assert_ne!(replica_digest, artifact_b.ciphertext_digest);
    tx.rollback().await.expect("rollback rekey fixture");
  }
}
