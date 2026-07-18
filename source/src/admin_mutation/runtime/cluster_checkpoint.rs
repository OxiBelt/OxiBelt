//! Member-fenced encrypted rollback checkpoint persistence.

use std::time::Duration;

use anyhow::Context;
use zeroize::Zeroizing;

use crate::admin_mutation::artifact::{ArtifactBinding, CheckpointArtifactBinding, sha256_digest};
use crate::admin_mutation::ledger::MutationRecord;
use crate::admin_mutation::rollout_store::{
  MemberFence, SealedCheckpoint, fetch_checkpoint, publish_checkpoint,
};

use super::AdminMutationRuntime;

const WINNER_RESPONSE_FORWARD_PHASES: u64 = 4;

pub(super) fn winner_response_wait(
  phase_timeout_seconds: u64,
  rollback_timeout_seconds: u64,
  stale_after_seconds: u64,
) -> anyhow::Result<Duration> {
  let seconds = phase_timeout_seconds
    .checked_mul(WINNER_RESPONSE_FORWARD_PHASES)
    .and_then(|value| value.checked_add(rollback_timeout_seconds))
    .and_then(|value| value.checked_add(stale_after_seconds))
    .context("Admin winner-response wait bound overflow")?
    .max(super::ORDINARY_TERMINAL_WAIT.as_secs());
  Ok(Duration::from_secs(seconds))
}

pub(crate) struct SharedWinnerResponseGuard {
  runtime: AdminMutationRuntime,
  request_id: String,
  active: bool,
}

impl std::fmt::Debug for SharedWinnerResponseGuard {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("SharedWinnerResponseGuard")
      .field("request_id", &self.request_id)
      .field("active", &self.active)
      .finish_non_exhaustive()
  }
}

impl SharedWinnerResponseGuard {
  pub(super) fn take(&mut self) -> Option<Zeroizing<Vec<u8>>> {
    if !self.active {
      return None;
    }
    self.active = false;
    self.runtime.take_shared_winner_response(&self.request_id)
  }
}

impl Drop for SharedWinnerResponseGuard {
  fn drop(&mut self) {
    if self.active {
      self.active = false;
      drop(self.runtime.take_shared_winner_response(&self.request_id));
    }
  }
}

pub(crate) struct DecryptedClusterCheckpoint {
  pub(crate) plaintext: Zeroizing<Vec<u8>>,
  pub(crate) integrity_digest: String,
  pub(crate) prior_revision: String,
  pub(crate) prior_digest: String,
  pub(crate) candidate_revision: String,
  pub(crate) candidate_digest: String,
}

impl AdminMutationRuntime {
  pub(crate) fn register_shared_winner_response(
    &self,
    request_id: &str,
  ) -> SharedWinnerResponseGuard {
    self
      .inner
      .winner_responses
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .entry(request_id.to_string())
      .or_insert(None);
    SharedWinnerResponseGuard {
      runtime: self.clone(),
      request_id: request_id.to_string(),
      active: true,
    }
  }

  pub(crate) fn deliver_shared_winner_response(
    &self,
    request_id: &str,
    response: Zeroizing<Vec<u8>>,
  ) {
    let mut responses = self
      .inner
      .winner_responses
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(slot) = responses.get_mut(request_id)
      && slot.is_none()
    {
      *slot = Some(response);
    }
  }

  pub(crate) fn shared_winner_response_registered(&self, request_id: &str) -> bool {
    self
      .inner
      .winner_responses
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .contains_key(request_id)
  }

  fn take_shared_winner_response(&self, request_id: &str) -> Option<Zeroizing<Vec<u8>>> {
    self
      .inner
      .winner_responses
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .remove(request_id)
      .flatten()
  }

  pub(crate) fn seal_shared_cluster_checkpoint(
    &self,
    record: &MutationRecord,
    owner: &MemberFence,
    assignment_epoch: i64,
    prior_revision: &str,
    prior_digest: &str,
    plaintext: &[u8],
  ) -> anyhow::Result<SealedCheckpoint> {
    let binding = CheckpointArtifactBinding {
      artifact: ArtifactBinding::from_record(self.store()?.namespace(), record)?,
      instance_id: owner.instance_id.clone(),
      assignment_epoch,
      prior_revision: prior_revision.to_string(),
      prior_digest: prior_digest.to_string(),
    };
    let sealed = self
      .artifact_cipher()?
      .seal_checkpoint(&binding, plaintext)?;
    Ok(SealedCheckpoint {
      assignment_epoch,
      candidate_revision: record.new_revision.clone(),
      candidate_digest: record.content_digest.clone(),
      prior_revision: prior_revision.to_string(),
      prior_digest: prior_digest.to_string(),
      nonce: sealed.nonce.to_vec(),
      ciphertext: sealed.ciphertext.to_vec(),
      ciphertext_digest: sealed.ciphertext_digest,
      plaintext_len: sealed.plaintext_len,
    })
  }

  pub(crate) async fn fetch_shared_cluster_checkpoint(
    &self,
    record: &MutationRecord,
    owner: &MemberFence,
    assignment_epoch: i64,
  ) -> anyhow::Result<DecryptedClusterCheckpoint> {
    let stored =
      fetch_checkpoint(self.store()?, owner, &record.request_id, assignment_epoch).await?;
    let binding = CheckpointArtifactBinding {
      artifact: ArtifactBinding::from_record(self.store()?.namespace(), record)?,
      instance_id: owner.instance_id.clone(),
      assignment_epoch,
      prior_revision: stored.prior_revision.clone(),
      prior_digest: stored.prior_digest.clone(),
    };
    let plaintext = self.artifact_cipher()?.open_checkpoint(
      &binding,
      stored.nonce,
      stored.ciphertext,
      &stored.ciphertext_digest,
      stored.plaintext_len,
    )?;
    Ok(DecryptedClusterCheckpoint {
      integrity_digest: sha256_digest(&plaintext),
      plaintext,
      prior_revision: stored.prior_revision,
      prior_digest: stored.prior_digest,
      candidate_revision: stored.candidate_revision,
      candidate_digest: stored.candidate_digest,
    })
  }

  #[allow(clippy::too_many_arguments)]
  pub(crate) async fn publish_cluster_checkpoint(
    &self,
    record: &MutationRecord,
    assignment_epoch: i64,
    prior_revision: &str,
    prior_digest: &str,
    plaintext: &[u8],
  ) -> anyhow::Result<bool> {
    let controller = self.cluster_controller_ref()?;
    let member = controller.member_fence().await?;
    let binding = CheckpointArtifactBinding {
      artifact: ArtifactBinding::from_record(self.store()?.namespace(), record)?,
      instance_id: member.instance_id.clone(),
      assignment_epoch,
      prior_revision: prior_revision.to_string(),
      prior_digest: prior_digest.to_string(),
    };
    let sealed = self
      .artifact_cipher()?
      .seal_checkpoint(&binding, plaintext)?;
    publish_checkpoint(
      self.store()?,
      &member,
      &record.request_id,
      &SealedCheckpoint {
        assignment_epoch,
        candidate_revision: record.new_revision.clone(),
        candidate_digest: record.content_digest.clone(),
        prior_revision: prior_revision.to_string(),
        prior_digest: prior_digest.to_string(),
        nonce: sealed.nonce.to_vec(),
        ciphertext: sealed.ciphertext.to_vec(),
        ciphertext_digest: sealed.ciphertext_digest,
        plaintext_len: sealed.plaintext_len,
      },
    )
    .await
  }

  pub(crate) async fn fetch_cluster_checkpoint(
    &self,
    record: &MutationRecord,
    assignment_epoch: i64,
  ) -> anyhow::Result<DecryptedClusterCheckpoint> {
    let controller = self.cluster_controller_ref()?;
    let member = controller.member_fence().await?;
    let stored =
      fetch_checkpoint(self.store()?, &member, &record.request_id, assignment_epoch).await?;
    let binding = CheckpointArtifactBinding {
      artifact: ArtifactBinding::from_record(self.store()?.namespace(), record)?,
      instance_id: member.instance_id.clone(),
      assignment_epoch,
      prior_revision: stored.prior_revision.clone(),
      prior_digest: stored.prior_digest.clone(),
    };
    let plaintext = self.artifact_cipher()?.open_checkpoint(
      &binding,
      stored.nonce,
      stored.ciphertext,
      &stored.ciphertext_digest,
      stored.plaintext_len,
    )?;
    let integrity_digest = sha256_digest(&plaintext);
    Ok(DecryptedClusterCheckpoint {
      plaintext,
      integrity_digest,
      prior_revision: stored.prior_revision,
      prior_digest: stored.prior_digest,
      candidate_revision: stored.candidate_revision,
      candidate_digest: stored.candidate_digest,
    })
  }
}
