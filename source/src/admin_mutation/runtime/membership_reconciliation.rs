//! Local staged-membership proof, checkpoint verification, and readiness.

use anyhow::{Context, ensure};
use aws_lc_rs::agreement::{PrivateKey, X25519};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use base64::Engine as _;

use crate::admin_mutation::membership::{
  MEMBERSHIP_CAPABILITY_VERSION, MEMBERSHIP_DOCUMENT_VERSION, MembershipEpoch, MembershipKeyProof,
  MembershipReadinessReceipt,
};
use crate::admin_mutation::rollout::AdminClusterRolloutController;
use crate::admin_mutation::store::MAX_STORED_ARTIFACT_BYTES;

use super::AdminMutationRuntime;

impl AdminMutationRuntime {
  pub(super) async fn reconcile_local_staged_membership(
    &self,
    controller: &AdminClusterRolloutController,
  ) -> anyhow::Result<()> {
    if !self.staged_membership() {
      return Ok(());
    }
    let store = self.store()?;
    let member_id = self
      .inner
      .local_instance_id
      .as_deref()
      .context("staged membership local instance ID is missing")?;
    let Some(pending) = super::super::membership_store::load_pending_membership_reconciliation(
      store,
      &self.inner.cluster_id,
      member_id,
    )
    .await?
    else {
      return Ok(());
    };
    if pending.epoch.version != MEMBERSHIP_DOCUMENT_VERSION {
      // Persisted v1 transitions remain readable and use the documented
      // legacy/manual readiness flow. A v2 binary must not make its heartbeat
      // unavailable merely because an older transition is still pending.
      return Ok(());
    }
    let private = self
      .inner
      .membership_private_keys
      .as_ref()
      .context("staged membership private keys are missing")?;
    let readiness_pair = match validate_local_epoch_identity(
      &pending.epoch,
      member_id,
      &private.readiness_pkcs8,
      private.catchup_x25519.as_ref(),
    ) {
      Ok(pair) => pair,
      Err(error) => {
        let _ = super::super::membership_store::set_membership_blocking_reason(
          store,
          &self.inner.cluster_id,
          &pending.transition.transition_id,
          "key_proof_failed",
        )
        .await;
        return Err(error);
      }
    };
    let cipher = match super::super::membership_store::load_epoch_artifact_cipher_for_member(
      store,
      &self.inner.cluster_id,
      &pending.transition.target_epoch_digest,
      member_id,
      private.catchup_x25519.as_ref(),
      MAX_STORED_ARTIFACT_BYTES,
    )
    .await
    {
      Ok(cipher) => cipher,
      Err(error) => {
        let _ = super::super::membership_store::set_membership_blocking_reason(
          store,
          &self.inner.cluster_id,
          &pending.transition.transition_id,
          "key_proof_failed",
        )
        .await;
        return Err(error.context("failed to open target membership artifact key"));
      }
    };
    let artifact_key_fingerprint = pending
      .epoch
      .artifact_key_fingerprint
      .as_deref()
      .context("target membership epoch key fingerprint is missing")?;
    ensure!(
      cipher.key_fingerprint() == artifact_key_fingerprint,
      "target membership artifact key fingerprint is inconsistent"
    );
    self
      .inner
      .artifact_ciphers
      .write()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .insert(pending.transition.target_epoch_digest.clone(), cipher);

    let now_unix_seconds: i64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::bigint")
      .fetch_one(store.pool())
      .await?;
    let proof = sign_key_proof(
      &readiness_pair,
      &self.inner.cluster_id,
      &pending.transition.transition_id,
      &pending.transition.target_epoch_digest,
      member_id,
      artifact_key_fingerprint,
      now_unix_seconds,
    )?;
    if !super::super::membership_store::has_membership_key_proof(
      store,
      &self.inner.cluster_id,
      &proof.transition_id,
      member_id,
      &proof.target_epoch,
      artifact_key_fingerprint,
    )
    .await?
    {
      super::super::membership_store::submit_membership_key_proof(
        store,
        &self.inner.cluster_id,
        &proof,
      )
      .await?;
    }

    if pending.transition.member_id.as_deref() != Some(member_id)
      || pending.transition.state != "catching_up"
    {
      return Ok(());
    }
    ensure!(
      !controller.participating(),
      "membership learner must remain outside active rollout participation"
    );
    let (transition, manifest) =
      match super::super::membership_store::load_and_open_membership_catchup(
        store,
        &self.inner.cluster_id,
        member_id,
        private.catchup_x25519.as_ref(),
      )
      .await
      {
        Ok(Some(value)) => value,
        Ok(None) => return Ok(()),
        Err(error) => {
          let _ = super::super::membership_store::set_membership_blocking_reason(
            store,
            &self.inner.cluster_id,
            &pending.transition.transition_id,
            "checkpoint_mismatch",
          )
          .await;
          return Err(error.context("membership learner checkpoint verification failed"));
        }
      };
    if let Err(error) = self
      .verify_local_membership_checkpoint(controller, &manifest)
      .await
    {
      let _ = super::super::membership_store::set_membership_blocking_reason(
        store,
        &self.inner.cluster_id,
        &transition.transition_id,
        "local_state_mismatch",
      )
      .await;
      return Err(error);
    }
    let receipt = sign_readiness_receipt(
      &readiness_pair,
      &self.inner.cluster_id,
      &transition,
      member_id,
      artifact_key_fingerprint,
      now_unix_seconds,
    )?;
    super::super::membership_store::submit_membership_readiness(
      store,
      &self.inner.cluster_id,
      &receipt,
    )
    .await?;
    Ok(())
  }

  async fn verify_local_membership_checkpoint(
    &self,
    controller: &AdminClusterRolloutController,
    manifest: &super::super::membership_store::MembershipCatchupManifestV2,
  ) -> anyhow::Result<()> {
    for artifact in &manifest.checkpoint_artifacts {
      let binding = artifact.binding()?;
      let plaintext = artifact.plaintext()?;
      let command = super::super::cluster_command::ClusterMutationCommand::from_plaintext(
        &plaintext, &binding,
      )?;
      command.reverify(
        &self.inner.signers,
        &self.inner.namespace,
        &binding,
        self.inner.maximum_validity_seconds,
        self.inner.maximum_clock_skew_seconds,
      )?;
    }
    let config_head = manifest
      .logical_heads
      .iter()
      .find(|head| head.resource == "config")
      .context("membership checkpoint has no durable configuration head")?;
    let local = controller.local_status().await;
    ensure!(
      local.assigned_revision.is_none()
        && local.applied_revision == config_head.committed_revision
        && local.applied_digest == config_head.content_digest,
      "learner provisioned configuration does not exactly match the checkpoint"
    );
    let local_heads = self.local_membership_heads();
    for head in &manifest.logical_heads {
      ensure!(
        local_heads.get(&head.resource).is_some_and(|local| {
          local.revision == head.committed_revision && local.digest == head.content_digest
        }),
        "learner provisioned resource {} does not exactly match the checkpoint",
        head.resource
      );
    }
    Ok(())
  }
}

pub(super) fn validate_local_epoch_identity(
  epoch: &MembershipEpoch,
  member_id: &str,
  readiness_pkcs8: &[u8],
  catchup_x25519: &[u8],
) -> anyhow::Result<Ed25519KeyPair> {
  let member = epoch
    .members
    .iter()
    .find(|member| member.id == member_id)
    .context("local instance is not a member of the target epoch")?;
  let readiness = Ed25519KeyPair::from_pkcs8(readiness_pkcs8)
    .map_err(|_| anyhow::anyhow!("membership readiness private key is not Ed25519 PKCS#8"))?;
  ensure!(
    base64::engine::general_purpose::STANDARD.encode(readiness.public_key().as_ref())
      == member.readiness_ed25519_public_key,
    "membership readiness private key does not match the target epoch identity"
  );
  let catchup = PrivateKey::from_private_key(&X25519, catchup_x25519)
    .map_err(|_| anyhow::anyhow!("membership catch-up X25519 private key is invalid"))?;
  let catchup_public = catchup
    .compute_public_key()
    .map_err(|_| anyhow::anyhow!("failed to derive membership catch-up public key"))?;
  ensure!(
    base64::engine::general_purpose::STANDARD.encode(catchup_public.as_ref())
      == member.catchup_x25519_public_key,
    "membership catch-up private key does not match the target epoch identity"
  );
  Ok(readiness)
}

fn sign_key_proof(
  pair: &Ed25519KeyPair,
  cluster_id: &str,
  transition_id: &str,
  target_epoch: &str,
  member_id: &str,
  artifact_key_fingerprint: &str,
  issued_at_unix_seconds: i64,
) -> anyhow::Result<MembershipKeyProof> {
  let mut proof = MembershipKeyProof {
    version: 2,
    transition_id: transition_id.to_string(),
    target_epoch: target_epoch.to_string(),
    member_id: member_id.to_string(),
    artifact_key_fingerprint: artifact_key_fingerprint.to_string(),
    build_version: oxibelt_build_identity::SHORT_VERSION.to_string(),
    capability_version: MEMBERSHIP_CAPABILITY_VERSION.to_string(),
    issued_at_unix_seconds,
    signature: base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
  };
  proof.signature = base64::engine::general_purpose::STANDARD
    .encode(pair.sign(&proof.transcript(cluster_id)?).as_ref());
  proof.validate()?;
  Ok(proof)
}

fn sign_readiness_receipt(
  pair: &Ed25519KeyPair,
  cluster_id: &str,
  transition: &super::super::membership_store::MembershipTransition,
  member_id: &str,
  artifact_key_fingerprint: &str,
  issued_at_unix_seconds: i64,
) -> anyhow::Result<MembershipReadinessReceipt> {
  let mut receipt = MembershipReadinessReceipt {
    version: 2,
    transition_id: transition.transition_id.clone(),
    target_epoch: transition.target_epoch_digest.clone(),
    member_id: member_id.to_string(),
    catchup_cursor: u32::try_from(transition.catchup_cursor)
      .context("membership catch-up cursor exceeds u32")?,
    catchup_digest: transition
      .catchup_digest
      .clone()
      .context("membership catch-up digest is missing")?,
    source_epoch: transition.source_epoch_digest.clone(),
    artifact_key_fingerprint: Some(artifact_key_fingerprint.to_string()),
    checkpoint_digest: transition.checkpoint_digest.clone(),
    journal_tail_digest: transition.journal_tail_digest.clone(),
    verified_position: transition
      .verified_position
      .map(u64::try_from)
      .transpose()
      .context("membership verified position is negative")?,
    build_version: oxibelt_build_identity::SHORT_VERSION.to_string(),
    capability_version: MEMBERSHIP_CAPABILITY_VERSION.to_string(),
    issued_at_unix_seconds,
    signature: base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
  };
  receipt.signature = base64::engine::general_purpose::STANDARD
    .encode(pair.sign(&receipt.transcript(cluster_id)?).as_ref());
  receipt.validate()?;
  Ok(receipt)
}

#[cfg(test)]
mod tests {
  use super::*;
  use aws_lc_rs::rand::SystemRandom;

  fn x25519_public(private: &[u8; 32]) -> String {
    let key = PrivateKey::from_private_key(&X25519, private).expect("test X25519 private key");
    let public = key.compute_public_key().expect("test X25519 public key");
    base64::engine::general_purpose::STANDARD.encode(public.as_ref())
  }

  #[test]
  fn active_epoch_identity_requires_both_local_private_keys() {
    let random = SystemRandom::new();
    let local_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("local Ed25519 key");
    let local_pair = Ed25519KeyPair::from_pkcs8(local_pkcs8.as_ref()).expect("local key pair");
    let other_pkcs8 = Ed25519KeyPair::generate_pkcs8(&random).expect("other Ed25519 key");
    let other_pair = Ed25519KeyPair::from_pkcs8(other_pkcs8.as_ref()).expect("other key pair");
    let local_x25519 = [7_u8; 32];
    let other_x25519 = [8_u8; 32];
    let epoch = MembershipEpoch::new_v2(
      "cluster-a".to_string(),
      0,
      None,
      "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
      vec![
        crate::admin_mutation::membership::MembershipMember {
          id: "edge-a".to_string(),
          readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD
            .encode(local_pair.public_key().as_ref()),
          catchup_x25519_public_key: x25519_public(&local_x25519),
        },
        crate::admin_mutation::membership::MembershipMember {
          id: "edge-b".to_string(),
          readiness_ed25519_public_key: base64::engine::general_purpose::STANDARD
            .encode(other_pair.public_key().as_ref()),
          catchup_x25519_public_key: x25519_public(&other_x25519),
        },
      ],
      "018f47a2-7b2c-7b25-8f31-d13db7b4c127".to_string(),
    )
    .expect("valid membership epoch");

    validate_local_epoch_identity(&epoch, "edge-a", local_pkcs8.as_ref(), &local_x25519)
      .expect("matching local identity");
    assert!(
      validate_local_epoch_identity(&epoch, "edge-a", other_pkcs8.as_ref(), &local_x25519,)
        .expect_err("wrong readiness key")
        .to_string()
        .contains("readiness private key does not match")
    );
    assert!(
      validate_local_epoch_identity(&epoch, "edge-a", local_pkcs8.as_ref(), &other_x25519,)
        .expect_err("wrong catch-up key")
        .to_string()
        .contains("catch-up private key does not match")
    );
  }
}
