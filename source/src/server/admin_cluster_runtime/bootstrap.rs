use anyhow::Context;
use tokio::sync::mpsc;

use crate::admin_mutation::{
  AdminMutationRuntime, ClusterHeartbeatBootstrap, ClusterHeartbeatTask, LocalMembershipHead,
};
use crate::state::AppHandle;

use super::{AdminClusterRuntimeTasks, AdminControlHandle, ObservedResourceHead};

pub(crate) struct PreparedAdminClusterRuntime {
  heartbeat: Option<ClusterHeartbeatTask>,
  observed: Option<Vec<ObservedResourceHead>>,
}

impl PreparedAdminClusterRuntime {
  pub(crate) async fn prepare(
    state: &AppHandle,
    control: &AdminControlHandle,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> anyhow::Result<Self> {
    let snapshot = state.snapshot();
    if !snapshot.admin_mutations.cluster_mode() {
      return Ok(Self {
        heartbeat: None,
        observed: None,
      });
    }
    let status = control.status().await;
    let config_revision = status
      .get("etag")
      .and_then(serde_json::Value::as_str)
      .context("Admin cluster baseline revision is unavailable")?
      .trim_matches('"')
      .to_string();
    anyhow::ensure!(
      !config_revision.is_empty() && !config_revision.chars().any(char::is_control),
      "Admin cluster baseline revision is invalid"
    );
    let config_digest = AdminMutationRuntime::baseline_digest(&snapshot.config)?;
    let ipm_revision = snapshot
      .ipm
      .admin_status()
      .etag
      .trim_matches('"')
      .to_string();
    let observed = vec![
      ObservedResourceHead {
        resource: "config",
        revision: config_revision.clone(),
        digest: config_digest.clone(),
      },
      ObservedResourceHead {
        resource: "ipm",
        revision: ipm_revision.clone(),
        digest: AdminMutationRuntime::observed_resource_digest("ipm", &ipm_revision),
      },
      ObservedResourceHead {
        resource: "break-glass",
        revision: ipm_revision.clone(),
        digest: AdminMutationRuntime::observed_resource_digest("break-glass", &ipm_revision),
      },
    ];
    let heartbeat = snapshot
      .admin_mutations
      .start_cluster_heartbeat(
        &snapshot.config,
        ClusterHeartbeatBootstrap {
          applied_revision: config_revision,
          applied_digest: config_digest,
          local_heads: observed
            .iter()
            .map(|head| LocalMembershipHead {
              resource: head.resource.to_string(),
              revision: head.revision.clone(),
              digest: head.digest.clone(),
            })
            .collect(),
        },
        snapshot.metrics.clone(),
        snapshot.runtime_health.clone(),
        snapshot.runtime_generation,
        fatal_tx,
      )
      .await?;
    Ok(Self {
      heartbeat,
      observed: Some(observed),
    })
  }

  pub(crate) fn start_workers(
    self,
    state: AppHandle,
    control: AdminControlHandle,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> (
    Option<ClusterHeartbeatTask>,
    Option<AdminClusterRuntimeTasks>,
  ) {
    let tasks = self
      .observed
      .map(|observed| AdminClusterRuntimeTasks::start(state, control, observed, fatal_tx));
    (self.heartbeat, tasks)
  }
}
