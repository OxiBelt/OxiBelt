//! PostgreSQL authority for staged Admin membership.

use anyhow::{Context, ensure};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::membership::{
  MembershipActivationRequest, MembershipCancelRequest, MembershipEpoch, MembershipMember,
  MembershipReadinessReceipt, MembershipTransitionKind, MembershipTransitionRequest,
  MembershipTransitionState,
};
use super::membership_crypto::{CATCHUP_ALGORITHM, CatchupBinding, seal_catchup_chunk};
use super::store::MutationStore;

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
            catchup_cursor,catchup_digest,receipt_count,fence_cutoff,
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
    let document: String = sqlx::query_scalar(
      "SELECT document::text FROM oxibelt_admin_membership_epochs
        WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='active'",
    )
    .bind(store.namespace())
    .bind(cluster_id)
    .bind(digest)
    .fetch_one(store.pool())
    .await?;
    let epoch: MembershipEpoch = serde_json::from_str(&document)?;
    ensure!(
      epoch.digest()? == digest,
      "active membership epoch digest is invalid"
    );
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
    .unwrap_or_default();
  let recent_rows = sqlx::query(
    "SELECT transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
            member_id,proposal_request_id,activation_request_id,blocking_reason,
            catchup_cursor,catchup_digest,receipt_count,fence_cutoff,
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
  let fenced_members = recent_transitions
    .iter()
    .filter(|transition| {
      transition.state == "active" && matches!(transition.kind.as_str(), "maintenance" | "remove")
    })
    .filter_map(|transition| transition.member_id.clone())
    .collect();
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
  now_unix_seconds: i64,
) -> anyhow::Result<MembershipTransition> {
  receipt.validate()?;
  ensure!(
    now_unix_seconds.abs_diff(receipt.issued_at_unix_seconds) <= 300,
    "membership readiness receipt is outside the clock-skew window"
  );
  ensure!(
    receipt.build_version == oxibelt_build_identity::SHORT_VERSION,
    "membership learner build version is incompatible"
  );
  ensure!(
    receipt.capability_version == "admin-mutation-rollout-v1",
    "membership learner capability is incompatible"
  );
  let mut tx = store.pool().begin().await?;
  let row = sqlx::query(
    "SELECT transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
            member_id,proposal_request_id,activation_request_id,blocking_reason,
            catchup_cursor,catchup_digest,receipt_count,fence_cutoff,
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
  let public_key: String = sqlx::query_scalar(
    "SELECT readiness_ed25519_public_key
       FROM oxibelt_admin_membership_epoch_members
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND instance_id=$4",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&receipt.target_epoch)
  .bind(&receipt.member_id)
  .fetch_one(&mut *tx)
  .await?;
  let public_key = base64::engine::general_purpose::STANDARD.decode(public_key)?;
  let signature = base64::engine::general_purpose::STANDARD.decode(&receipt.signature)?;
  UnparsedPublicKey::new(&ED25519, public_key)
    .verify(&receipt.transcript(cluster_id)?, &signature)
    .map_err(|_| anyhow::anyhow!("membership readiness signature is invalid"))?;
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
  .await?;
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='ready',state_version=state_version+1,receipt_count=receipt_count+1,
            blocking_reason=NULL,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state='catching_up' AND state_version=$4
      RETURNING transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
        member_id,proposal_request_id,activation_request_id,blocking_reason,
        catchup_cursor,catchup_digest,receipt_count,fence_cutoff,
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

pub(crate) async fn load_active_membership_authority(
  store: &MutationStore,
  cluster_id: &str,
) -> anyhow::Result<Option<ActiveMembershipAuthority>> {
  let digest: Option<String> = sqlx::query_scalar(
    "SELECT active_epoch_digest FROM oxibelt_admin_membership_heads
      WHERE namespace=$1 AND cluster_id=$2",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .fetch_optional(store.pool())
  .await?
  .flatten();
  let Some(epoch_digest) = digest else {
    return Ok(None);
  };
  let members = sqlx::query_scalar(
    "SELECT instance_id FROM oxibelt_admin_membership_epoch_members
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 ORDER BY instance_id ASC",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&epoch_digest)
  .fetch_all(store.pool())
  .await?;
  ensure!(
    (2..=1_024).contains(&members.len()),
    "active membership size is invalid"
  );
  Ok(Some(ActiveMembershipAuthority {
    epoch_digest,
    members,
  }))
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
) -> anyhow::Result<(MembershipTransition, MembershipMutationCheckpoint)> {
  super::ledger::validate_identifier("cluster_id", cluster_id, 253)?;
  super::ledger::validate_identifier("transition_id", transition_id, 256)?;
  super::ledger::validate_identifier("proposal_request_id", proposal_request_id, 256)?;
  request.validate()?;
  ensure!(
    !approving_members.is_empty() && approving_members.len() <= 1_024,
    "membership proposal requires bounded current-member approval evidence"
  );
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
  let epoch = MembershipEpoch::new(
    cluster_id.to_string(),
    u64::try_from(sequence).context("membership sequence is negative")?,
    active_digest.clone(),
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
       (namespace,cluster_id,epoch_digest,epoch_sequence,predecessor_digest,document,
        authorized_request_id,state)
     VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,'staged')",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&epoch_digest)
  .bind(i64::try_from(epoch.sequence).context("membership sequence exceeds PostgreSQL bigint")?)
  .bind(epoch.predecessor.as_deref())
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
  }
  sqlx::query(
    "INSERT INTO oxibelt_admin_membership_transitions
       (namespace,cluster_id,transition_id,kind,state,source_epoch_digest,
        target_epoch_digest,member_id,proposal_request_id,receipt_count)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1)",
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
  .execute(&mut *connection)
  .await?;
  if matches!(
    request.kind,
    MembershipTransitionKind::Join | MembershipTransitionKind::Rejoin
  ) {
    let member = request.member.as_ref().context("join member is missing")?;
    let plaintext = membership_catchup_manifest(
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
    )
    .await?;
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
              catchup_cursor=1,catchup_digest=$4,updated_at=now()
        WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3 AND state='learner'",
    )
    .bind(namespace)
    .bind(cluster_id)
    .bind(transition_id)
    .bind(&sealed.plaintext_digest)
    .execute(&mut *connection)
    .await?;
  }
  let receipt = serde_json::json!({
    "version": 1,
    "kind": "proposal",
    "transition_id": transition_id,
    "proposal_request_id": proposal_request_id,
    "source_epoch": epoch.predecessor,
    "target_epoch": epoch_digest,
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
            catchup_cursor,catchup_digest,receipt_count,fence_cutoff,
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
async fn membership_catchup_manifest(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  transition_id: &str,
  member_id: &str,
  source_epoch: &str,
  target_epoch: &str,
) -> anyhow::Result<Vec<u8>> {
  let mut mutations = sqlx::query(
    "SELECT mutation.request_id,mutation.resource,mutation.state,
            mutation.expected_previous_revision,mutation.new_revision,mutation.content_digest,
            mutation.membership_revision,artifact.ciphertext_digest AS artifact_digest,
            artifact.plaintext_len
       FROM oxibelt_admin_mutations mutation
       LEFT JOIN oxibelt_admin_mutation_artifacts artifact
         ON artifact.namespace=mutation.namespace AND artifact.request_id=mutation.request_id
      WHERE mutation.namespace=$1 AND mutation.cluster_id=$2
      ORDER BY mutation.created_at DESC,mutation.request_id DESC LIMIT 1025",
  )
  .bind(namespace)
  .bind(cluster_id)
  .fetch_all(&mut *connection)
  .await?;
  ensure!(
    mutations.len() <= 1_024,
    "membership catch-up mutation history exceeds its bounded snapshot"
  );
  mutations.reverse();
  let mutation_chain = mutations
    .iter()
    .map(|row| {
      Ok(serde_json::json!({
        "request_id": row.try_get::<String, _>("request_id")?,
        "resource": row.try_get::<String, _>("resource")?,
        "state": row.try_get::<String, _>("state")?,
        "expected_previous_revision": row.try_get::<String, _>("expected_previous_revision")?,
        "new_revision": row.try_get::<String, _>("new_revision")?,
        "content_digest": row.try_get::<String, _>("content_digest")?,
        "membership_revision": row.try_get::<Option<String>, _>("membership_revision")?,
        "artifact_digest": row.try_get::<Option<String>, _>("artifact_digest")?,
        "artifact_plaintext_len": row.try_get::<Option<i32>, _>("plaintext_len")?,
      }))
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;
  let heads = sqlx::query(
    "SELECT resource,committed_revision,content_digest,membership_revision
       FROM oxibelt_admin_mutation_revisions
      WHERE namespace=$1 ORDER BY resource ASC LIMIT 1025",
  )
  .bind(namespace)
  .fetch_all(&mut *connection)
  .await?;
  ensure!(
    heads.len() <= 1_024,
    "membership catch-up logical heads exceed their bound"
  );
  let logical_heads = heads
    .iter()
    .map(|row| {
      Ok(serde_json::json!({
        "resource": row.try_get::<String, _>("resource")?,
        "committed_revision": row.try_get::<String, _>("committed_revision")?,
        "content_digest": row.try_get::<String, _>("content_digest")?,
        "membership_revision": row.try_get::<Option<String>, _>("membership_revision")?,
      }))
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()?;
  Ok(serde_json::to_vec(&serde_json::json!({
    "format": "oxibelt-admin-membership-catchup-v1",
    "cluster_id": cluster_id,
    "transition_id": transition_id,
    "member_id": member_id,
    "source_epoch": source_epoch,
    "target_epoch": target_epoch,
    "build_version": oxibelt_build_identity::SHORT_VERSION,
    "capability_version": "admin-mutation-rollout-v1",
    "logical_heads": logical_heads,
    "mutation_chain": mutation_chain,
  }))?)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_membership_activation_tx(
  connection: &mut sqlx::PgConnection,
  namespace: &str,
  cluster_id: &str,
  activation_request_id: &str,
  request: &MembershipActivationRequest,
  fence_cutoff: i64,
  approving_members: &[String],
) -> anyhow::Result<(MembershipTransition, MembershipMutationCheckpoint)> {
  request.validate()?;
  ensure!(
    fence_cutoff > 0,
    "membership activation fence cutoff is invalid"
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
  let ordinal = transition.receipt_count;
  ensure!(
    (0..4_096).contains(&ordinal),
    "membership receipt count is exhausted"
  );
  let payload = serde_json::json!({
    "version": 1,
    "kind": "activation_authorization",
    "activation_request_id": activation_request_id,
    "transition_id": request.transition_id,
    "target_epoch": request.expected_target_epoch,
    "fence_cutoff": fence_cutoff,
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
            activation_request_id=$5,receipt_count=receipt_count+1,fence_cutoff=$6,
            blocking_reason=NULL,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state='ready' AND state_version=$4
      RETURNING transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
        member_id,proposal_request_id,activation_request_id,blocking_reason,
        catchup_cursor,catchup_digest,receipt_count,fence_cutoff,
        created_at::text AS created_at,updated_at::text AS updated_at",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(&request.transition_id)
  .bind(transition.state_version)
  .bind(activation_request_id)
  .bind(fence_cutoff)
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
    previous.may_transition_to(MembershipTransitionState::Cancelled),
    "membership transition cannot be cancelled in its current state"
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
  let updated = sqlx::query(
    "UPDATE oxibelt_admin_membership_transitions
        SET state='cancelled',state_version=state_version+1,
            receipt_count=receipt_count+1,blocking_reason=NULL,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND state=$4 AND state_version=$5
      RETURNING transition_id,kind,state,state_version,source_epoch_digest,target_epoch_digest,
        member_id,proposal_request_id,activation_request_id,blocking_reason,
        catchup_cursor,catchup_digest,receipt_count,fence_cutoff,
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
            catchup_cursor,catchup_digest,receipt_count,fence_cutoff,
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
      let restored = sqlx::query(
        "UPDATE oxibelt_admin_membership_transitions
            SET state='ready',state_version=state_version+1,activation_request_id=NULL,
                receipt_count=receipt_count-1,fence_cutoff=NULL,updated_at=now()
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
      let deleted = sqlx::query(
        "DELETE FROM oxibelt_admin_membership_receipts
          WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
            AND receipt_kind='activation_authorization'
            AND payload->>'activation_request_id'=$4",
      )
      .bind(namespace)
      .bind(cluster_id)
      .bind(transition_id)
      .bind(activation_request_id)
      .execute(&mut *connection)
      .await?
      .rows_affected();
      ensure!(
        deleted == 1,
        "membership activation receipt is not restorable"
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
    } => {
      MembershipTransitionState::parse(previous_state)?;
      let restored = sqlx::query(
        "UPDATE oxibelt_admin_membership_transitions
            SET state=$5,state_version=state_version+1,receipt_count=receipt_count-1,updated_at=now()
          WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
            AND target_epoch_digest=$4 AND state='cancelled' AND state_version=$6",
      )
      .bind(namespace)
      .bind(cluster_id)
      .bind(transition_id)
      .bind(target_epoch_digest)
      .bind(previous_state)
      .bind(previous_state_version + 1)
      .execute(&mut *connection)
      .await?
      .rows_affected();
      ensure!(restored == 1, "membership cancellation is not restorable");
      let deleted = sqlx::query(
        "DELETE FROM oxibelt_admin_membership_receipts
          WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
            AND receipt_kind='cancellation'
            AND payload->>'cancellation_request_id'=$4",
      )
      .bind(namespace)
      .bind(cluster_id)
      .bind(transition_id)
      .bind(cancellation_request_id)
      .execute(&mut *connection)
      .await?
      .rows_affected();
      ensure!(
        deleted == 1,
        "membership cancellation receipt is not restorable"
      );
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
  let deleted = sqlx::query(
    "DELETE FROM oxibelt_admin_membership_transitions
      WHERE namespace=$1 AND cluster_id=$2 AND transition_id=$3
        AND target_epoch_digest=$4
        AND state IN ('learner','catching_up','ready')",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(transition_id)
  .bind(target_epoch_digest)
  .execute(&mut *connection)
  .await?
  .rows_affected();
  ensure!(
    deleted == 1,
    "membership proposal is no longer exactly restorable"
  );
  let epoch_deleted = sqlx::query(
    "DELETE FROM oxibelt_admin_membership_epochs
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 AND state='staged'",
  )
  .bind(namespace)
  .bind(cluster_id)
  .bind(target_epoch_digest)
  .execute(&mut *connection)
  .await?
  .rows_affected();
  ensure!(
    epoch_deleted == 1,
    "staged membership epoch is no longer exactly restorable"
  );
  if *created_head {
    let head_deleted = sqlx::query(
      "DELETE FROM oxibelt_admin_membership_heads
        WHERE namespace=$1 AND cluster_id=$2
          AND active_epoch_digest IS NULL AND state_version=0",
    )
    .bind(namespace)
    .bind(cluster_id)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    ensure!(
      head_deleted == 1,
      "empty membership head is no longer exactly restorable"
    );
  }
  Ok(())
}

pub(crate) async fn finalize_committed_membership_activation(
  store: &MutationStore,
  cluster_id: &str,
) -> anyhow::Result<Option<ActiveMembershipAuthority>> {
  let mut tx = store.pool().begin().await?;
  let row = sqlx::query(
    "SELECT transition.transition_id,transition.kind,transition.state,
            transition.state_version,transition.source_epoch_digest,
            transition.target_epoch_digest,transition.member_id,
            transition.proposal_request_id,transition.activation_request_id,
            transition.blocking_reason,transition.catchup_cursor,transition.catchup_digest,
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
      .may_transition_to(MembershipTransitionState::Active),
    "membership activation state transition is invalid"
  );
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
  ensure!(
    active_digest == transition.source_epoch_digest,
    "membership activation source epoch is stale"
  );
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
  sqlx::query(
    "UPDATE oxibelt_admin_membership_heads
        SET active_epoch_digest=$3,active_epoch_sequence=$4,
            state_version=state_version+1,updated_at=now()
      WHERE namespace=$1 AND cluster_id=$2",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.target_epoch_digest)
  .bind(target_sequence)
  .execute(&mut *tx)
  .await?;
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
    "version": 1,
    "kind": "activation",
    "activation_request_id": activation_id,
    "transition_id": transition.transition_id,
    "source_epoch": transition.source_epoch_digest,
    "target_epoch": transition.target_epoch_digest,
    "fence_cutoff": transition.fence_cutoff,
  });
  insert_membership_receipt(
    &mut tx,
    store.namespace(),
    cluster_id,
    &transition.transition_id,
    transition.receipt_count,
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
        AND state='activation_authorized' AND state_version=$4",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.transition_id)
  .bind(transition.state_version)
  .execute(&mut *tx)
  .await?;
  let members = sqlx::query_scalar(
    "SELECT instance_id FROM oxibelt_admin_membership_epoch_members
      WHERE namespace=$1 AND cluster_id=$2 AND epoch_digest=$3 ORDER BY instance_id ASC",
  )
  .bind(store.namespace())
  .bind(cluster_id)
  .bind(&transition.target_epoch_digest)
  .fetch_all(&mut *tx)
  .await?;
  ensure!(
    (2..=1_024).contains(&members.len()),
    "activated membership size is invalid"
  );
  tx.commit().await?;
  Ok(Some(ActiveMembershipAuthority {
    epoch_digest: transition.target_epoch_digest,
    members,
  }))
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
    receipt_count: row.try_get("receipt_count")?,
    fence_cutoff: row.try_get("fence_cutoff")?,
    created_at: row.try_get("created_at")?,
    updated_at: row.try_get("updated_at")?,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

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
    let mut tx = pool.begin().await.expect("transaction");
    let (transition, checkpoint) = apply_membership_proposal_tx(
      &mut tx,
      &namespace,
      "cluster-a",
      "initialize-1",
      "initialize-1",
      &request,
      &bootstrap,
      &["edge-a".to_string(), "edge-b".to_string()],
    )
    .await
    .expect("proposal");
    assert_eq!(transition.state, "ready");
    tx.commit().await.expect("commit");
    let status = load_membership_status(&store, "cluster-a")
      .await
      .expect("status");
    assert_eq!(
      status.pending_transition.expect("pending").transition_id,
      "initialize-1"
    );
    let mut restore = pool.begin().await.expect("restore transaction");
    restore_membership_mutation_tx(&mut restore, &namespace, &checkpoint)
      .await
      .expect("restore proposal");
    restore.commit().await.expect("restore commit");
    assert!(
      load_membership_status(&store, "cluster-a")
        .await
        .expect("restored status")
        .pending_transition
        .is_none()
    );
  }
}
