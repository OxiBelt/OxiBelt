//! Fresh workload, owner-chain, source, and leadership proof for status commit.

use anyhow::{Context, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::cli::RunArgs;
use super::rollout::{
  RolloutPhase, RolloutState, RolloutTarget, WorkloadKind, WorkloadPodOwnership,
  evaluate_convergence, pod_is_selected,
};
use super::rollout_status::{CommitProof, RolloutStatus};
use super::watch::KubernetesPoller;

impl KubernetesPoller {
  pub async fn prove_committed_rollout(
    &self,
    args: &RunArgs,
    status: &RolloutStatus,
    source_snapshot_digest: String,
  ) -> anyhow::Result<CommitProof> {
    if status.phase != RolloutPhase::Committed {
      bail!("only a committed rollout can produce a status commitment proof");
    }
    let revision = status
      .desired_revision
      .as_deref()
      .context("committed rollout has no desired revision")?;
    let content_digest = status
      .desired_content_digest
      .as_deref()
      .context("committed rollout has no desired content digest")?;
    let target = RolloutTarget::from_args(args)?;
    let workload = self.get_required_json(&target.workload_path()).await?;
    let state = RolloutState::from_workload(&workload);
    if state.phase != RolloutPhase::Committed
      || state.committed_revision.as_deref() != Some(revision)
      || state.committed_content_digest.as_deref() != Some(content_digest)
      || state.desired_revision.as_deref() != Some(revision)
      || state.desired_content_digest.as_deref() != Some(content_digest)
    {
      bail!("fresh workload state does not prove the committed revision and content digest");
    }
    let replica_sets = if target.kind == WorkloadKind::Deployment {
      self.list_replica_sets(&target.namespace).await?
    } else {
      Vec::new()
    };
    let ownership = WorkloadPodOwnership::from_workload(&target, &workload, &replica_sets)?;
    let pods = self.list_pods(&target.namespace).await?;
    let convergence = evaluate_convergence(
      &target,
      &workload,
      &ownership,
      &pods,
      revision,
      content_digest,
    );
    if !convergence.all_replicas_converged() {
      bail!("fresh workload and Pod owner-chain observation no longer proves convergence");
    }
    let permit = self.authorize_write().await?;
    let expected_epoch = permit.term().leader_epoch.to_string();
    if super::rollout::annotation(&workload, super::rollout::LEASE_UID_ANNOTATION)
      != Some(permit.term().lease_uid.as_str())
      || super::rollout::annotation(&workload, super::rollout::LEADER_EPOCH_ANNOTATION)
        != Some(expected_epoch.as_str())
      || super::rollout::annotation(&workload, super::rollout::HOLDER_IDENTITY_ANNOTATION)
        != Some(permit.term().holder_identity.as_str())
    {
      bail!("workload state has not been adopted by the current leadership term");
    }
    Ok(CommitProof {
      revision: revision.to_string(),
      content_digest: content_digest.to_string(),
      workload_uid: required_metadata_string(&workload, "uid")?.to_string(),
      workload_generation: workload
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
        .context("target workload metadata.generation is required for commitment proof")?,
      workload_resource_version: required_metadata_string(&workload, "resourceVersion")?
        .to_string(),
      owner_chain_digest: owner_chain_digest(&workload, &ownership, &pods)?,
      source_snapshot_digest,
      leadership: permit.term().clone(),
    })
  }
}

fn required_metadata_string<'a>(value: &'a Value, field: &str) -> anyhow::Result<&'a str> {
  value
    .pointer(&format!("/metadata/{field}"))
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
    .with_context(|| format!("target workload metadata.{field} is required"))
}

fn owner_chain_digest(
  workload: &Value,
  ownership: &WorkloadPodOwnership,
  pods: &[Value],
) -> anyhow::Result<String> {
  let mut chain = ownership
    .proof_owner_uids()
    .into_iter()
    .map(|uid| format!("owner/{uid}"))
    .collect::<Vec<_>>();
  for pod in pods
    .iter()
    .filter(|pod| pod_is_selected(workload, ownership, pod))
  {
    let pod_uid = pod
      .pointer("/metadata/uid")
      .and_then(Value::as_str)
      .filter(|uid| !uid.is_empty())
      .context("selected Pod metadata.uid is required for commitment proof")?;
    let owner_uid = pod
      .pointer("/metadata/ownerReferences")
      .and_then(Value::as_array)
      .context("selected Pod controller ownerReference is required for commitment proof")?
      .iter()
      .find(|owner| owner.get("controller").and_then(Value::as_bool) == Some(true))
      .and_then(|owner| owner.get("uid"))
      .and_then(Value::as_str)
      .filter(|uid| !uid.is_empty())
      .context("selected Pod controller owner UID is required for commitment proof")?;
    chain.push(format!("pod/{owner_uid}/{pod_uid}"));
  }
  chain.sort();
  let digest = Sha256::digest(chain.join("\n").as_bytes());
  Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
