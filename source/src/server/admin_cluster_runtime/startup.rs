//! Restart convergence for committed per-resource heads.

use anyhow::{Context, ensure};

use crate::admin_mutation::AdminMutationRuntime;
use crate::server::admin_cluster_executor::{
  AdminClusterExecutor, PreviousEvidence, RuntimeSharedPublisher,
};

use super::ObservedResourceHead;
use super::support::publish_head;

pub(super) async fn activate_resource_heads(
  runtime: &AdminMutationRuntime,
  executor: &AdminClusterExecutor,
  publisher: &RuntimeSharedPublisher,
  observed: &[ObservedResourceHead],
) -> anyhow::Result<()> {
  let config = observed
    .iter()
    .find(|head| head.resource == "config")
    .context("observed configuration head is missing")?;
  for head in observed {
    if runtime
      .cluster_logical_revision(head.resource)
      .await?
      .is_none()
    {
      runtime
        .cluster_initialize_revision(head.resource, &head.revision, &head.digest)
        .await?;
    }
    publish_head(
      runtime,
      head.resource,
      None,
      &head.revision,
      &head.digest,
      false,
    )
    .await?;
  }
  runtime
    .cluster_set_worker_ready(config.revision.clone(), config.digest.clone())
    .await?;
  for head in observed {
    let logical = runtime
      .cluster_logical_revision(head.resource)
      .await?
      .context("cluster logical resource head disappeared")?;
    if logical.committed_revision == head.revision {
      publish_head(
        runtime,
        head.resource,
        None,
        &logical.committed_revision,
        &logical.content_digest,
        true,
      )
      .await?;
      continue;
    }
    if let Some((request_id, command)) = runtime
      .fetch_committed_cluster_command(head.resource)
      .await?
    {
      let operation = executor
        .validate(&command)
        .await
        .map_err(anyhow::Error::new)?;
      if operation.is_shared_staged() {
        if executor
          .observe_shared(&request_id, &operation, publisher)
          .await
          .is_ok()
        {
          let evidence = operation.candidate_evidence();
          ensure!(
            evidence.revision == logical.committed_revision
              && evidence.digest == logical.content_digest,
            "retained shared command conflicts with its committed logical head"
          );
          publish_head(
            runtime,
            head.resource,
            None,
            &evidence.revision,
            &evidence.digest,
            true,
          )
          .await?;
          continue;
        }
        publish_head(
          runtime,
          head.resource,
          None,
          &head.revision,
          &head.digest,
          false,
        )
        .await?;
        continue;
      }
      ensure!(
        head.resource == "config",
        "per-member committed command has invalid resource"
      );
      if let Ok(evidence) = executor
        .observe(&operation, &operation.candidate_evidence())
        .await
      {
        publish_head(
          runtime,
          "config",
          None,
          &evidence.revision,
          &evidence.digest,
          true,
        )
        .await?;
        continue;
      }
      let checkpoint = executor
        .checkpoint(
          &operation,
          &PreviousEvidence {
            revision: head.revision.clone(),
            digest: head.digest.clone(),
          },
        )
        .await
        .map_err(anyhow::Error::new)?;
      let evidence = executor
        .apply(&operation, &checkpoint)
        .await
        .map_err(anyhow::Error::new)?;
      publish_head(
        runtime,
        "config",
        None,
        &evidence.revision,
        &evidence.digest,
        true,
      )
      .await?;
      continue;
    }
    publish_head(
      runtime,
      head.resource,
      None,
      &head.revision,
      &head.digest,
      false,
    )
    .await?;
  }
  Ok(())
}
