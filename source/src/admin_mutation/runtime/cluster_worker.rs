//! Fenced durable worker accessors for the server-owned typed executor.

use anyhow::Context;

use crate::admin_mutation::cluster_command::ClusterMutationCommand;
use crate::admin_mutation::ledger::MutationRecord;
use crate::admin_mutation::rollout::LocalRolloutStatus;
use crate::admin_mutation::rollout_store::{
  CoordinatorFence, FencedTargetTransition, MemberWork, RecoveryMutation, ResourceHeadUpdate,
  RolloutTransitionPlan, acquire_coordinator_fence, apply_transition_plan,
  fetch_committed_artifact, is_admission_origin, load_member_work, load_recoverable_mutations,
  load_targets, prove_exact_live_membership, publish_resource_head, transition_target_fenced,
};
use crate::admin_mutation::store::LogicalRevision;

use super::AdminMutationRuntime;

impl AdminMutationRuntime {
  pub(crate) async fn cluster_set_worker_ready(
    &self,
    applied_revision: String,
    applied_digest: String,
  ) -> anyhow::Result<()> {
    let controller = self.cluster_controller_ref()?;
    controller
      .update_local_status(LocalRolloutStatus {
        assigned_revision: None,
        applied_revision,
        applied_digest,
        ready: true,
      })
      .await?;
    controller.heartbeat_once().await
  }

  pub(crate) async fn cluster_publish_resource_head(
    &self,
    update: ResourceHeadUpdate,
  ) -> anyhow::Result<()> {
    let member = self.cluster_controller_ref()?.member_fence().await?;
    publish_resource_head(self.store()?, &member, &update).await
  }

  pub(crate) async fn cluster_logical_revision(
    &self,
    resource: &str,
  ) -> anyhow::Result<Option<LogicalRevision>> {
    self.store()?.load_revision(resource).await
  }

  pub(crate) async fn cluster_initialize_revision(
    &self,
    resource: &str,
    revision: &str,
    digest: &str,
  ) -> anyhow::Result<()> {
    self
      .store()?
      .initialize_revision(
        resource,
        revision,
        digest,
        Some(&self.inner.target.cluster_id),
        Some(&self.inner.target.membership_revision),
      )
      .await
  }

  pub(crate) async fn cluster_member_work(&self) -> anyhow::Result<Vec<MemberWork>> {
    let member = self.cluster_controller_ref()?.member_fence().await?;
    load_member_work(self.store()?, &member, 64).await
  }

  pub(crate) async fn cluster_transition_target(
    &self,
    request_id: &str,
    transition: &FencedTargetTransition,
  ) -> anyhow::Result<()> {
    let member = self.cluster_controller_ref()?.member_fence().await?;
    transition_target_fenced(self.store()?, &member, request_id, transition).await?;
    Ok(())
  }

  pub(crate) async fn cluster_recoverable_mutations(
    &self,
  ) -> anyhow::Result<Vec<RecoveryMutation>> {
    load_recoverable_mutations(self.store()?, 64).await
  }

  pub(crate) async fn cluster_targets(
    &self,
    request_id: &str,
  ) -> anyhow::Result<Vec<crate::admin_mutation::RolloutTarget>> {
    load_targets(self.store()?, request_id).await
  }

  pub(crate) async fn cluster_rollout_directive(
    &self,
    record: &MutationRecord,
    targets: &[crate::admin_mutation::RolloutTarget],
  ) -> anyhow::Result<crate::admin_mutation::RolloutDirective> {
    self
      .cluster_controller_ref()?
      .classify_durable(record, targets)
      .await
  }

  pub(crate) async fn cluster_acquire_coordinator(
    &self,
    record: &MutationRecord,
    require_admission_origin: bool,
  ) -> anyhow::Result<Option<CoordinatorFence>> {
    let controller = self.cluster_controller_ref()?;
    let member = controller.member_fence().await?;
    if require_admission_origin
      && !is_admission_origin(self.store()?, &record.request_id, &member).await?
    {
      return Ok(None);
    }
    let logical = self
      .store()?
      .load_revision(&record.resource)
      .await?
      .context("cluster resource logical head is unavailable")?;
    let mut exact = prove_exact_live_membership(
      self.store()?,
      &self.inner.cluster_id,
      &self.inner.target.membership_revision,
      &self.inner.members,
      env!("CARGO_PKG_VERSION"),
      "admin-mutation-rollout-v1",
      self.artifact_key_fingerprint()?,
    )
    .await?;
    exact.resource = record.resource.clone();
    exact.baseline_revision = record.expected_previous_revision.clone();
    exact.baseline_digest = logical.content_digest;
    acquire_coordinator_fence(
      self.store()?,
      &record.request_id,
      &member,
      &exact,
      controller.coordinator_lease_seconds()?,
    )
    .await
  }

  pub(crate) async fn cluster_apply_transition_plan(
    &self,
    fence: &CoordinatorFence,
    plan: &RolloutTransitionPlan,
  ) -> anyhow::Result<CoordinatorFence> {
    apply_transition_plan(self.store()?, fence, plan).await
  }

  pub(crate) async fn fetch_committed_cluster_command(
    &self,
    resource: &str,
  ) -> anyhow::Result<Option<(String, ClusterMutationCommand)>> {
    let member = self.cluster_controller_ref()?.member_fence().await?;
    let cipher = self.artifact_cipher()?;
    let Some(stored) = fetch_committed_artifact(
      self.store()?,
      &member,
      resource,
      cipher.maximum_plaintext_bytes(),
    )
    .await?
    else {
      return Ok(None);
    };
    let binding = stored.binding.clone();
    let request_id = binding.request_id.clone();
    let plaintext = cipher.open(&binding, stored)?;
    let command = ClusterMutationCommand::from_plaintext(&plaintext, &binding)?;
    command.reverify(
      &self.inner.signers,
      &self.inner.namespace,
      &binding,
      self.inner.maximum_validity_seconds,
      self.inner.maximum_clock_skew_seconds,
    )?;
    Ok(Some((request_id, command)))
  }
}
