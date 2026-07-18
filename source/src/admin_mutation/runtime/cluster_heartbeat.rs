//! Process-lifetime fixed-member heartbeat activation and shutdown.

use std::fmt::Write as _;

use anyhow::Context;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::crypto::random_fill;
use crate::runtime_health::{
  RuntimeHealth, RuntimeTaskKind, RuntimeTaskPolicy, spawn_supervised_task,
};

use super::AdminMutationRuntime;

pub(crate) struct ClusterHeartbeatTask {
  runtime: AdminMutationRuntime,
  shutdown: watch::Sender<bool>,
  task: Option<JoinHandle<()>>,
}

impl ClusterHeartbeatTask {
  pub(crate) async fn shutdown(mut self) -> anyhow::Result<()> {
    let _ = self.shutdown.send(true);
    if let Some(task) = self.task.take() {
      let _ = task.await;
    }
    if let Some(controller) = self.runtime.installed_cluster_controller() {
      controller.release().await?;
    }
    Ok(())
  }
}

impl Drop for ClusterHeartbeatTask {
  fn drop(&mut self) {
    let _ = self.shutdown.send(true);
    if let Some(task) = self.task.take() {
      task.abort();
    }
  }
}

impl AdminMutationRuntime {
  pub(crate) fn observed_resource_digest(resource: &str, revision: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"OXIBELT-ADMIN-CLUSTER-OBSERVED-RESOURCE-V1\0");
    hasher.update((resource.len() as u64).to_be_bytes());
    hasher.update(resource.as_bytes());
    hasher.update((revision.len() as u64).to_be_bytes());
    hasher.update(revision.as_bytes());
    let mut digest = String::with_capacity(71);
    digest.push_str("sha256:");
    for byte in hasher.finalize() {
      let _ = write!(digest, "{byte:02x}");
    }
    digest
  }

  pub(crate) fn baseline_digest(config: &Config) -> anyhow::Result<String> {
    let mut files = config.source_paths.config_files.clone();
    files.sort();
    anyhow::ensure!(
      !files.is_empty(),
      "admin_cluster rollout requires file-backed active configuration"
    );
    let config_dir = config
      .source_paths
      .config_dir
      .as_deref()
      .context("admin_cluster rollout requires a configuration root")?;
    let mut hasher = Sha256::new();
    hasher.update(b"OXIBELT-ADMIN-CLUSTER-BASELINE-V1\0");
    for path in files {
      let path_label = path
        .strip_prefix(config_dir)
        .context("cluster baseline file escaped the configuration root")?
        .to_string_lossy();
      let bytes = std::fs::read(&path)
        .with_context(|| format!("failed to read cluster baseline {}", path.display()))?;
      hasher.update((path_label.len() as u64).to_be_bytes());
      hasher.update(path_label.as_bytes());
      hasher.update((bytes.len() as u64).to_be_bytes());
      hasher.update(&bytes);
    }
    let mut digest = String::with_capacity(71);
    digest.push_str("sha256:");
    for byte in hasher.finalize() {
      let _ = write!(digest, "{byte:02x}");
    }
    Ok(digest)
  }

  pub(crate) async fn start_cluster_heartbeat(
    &self,
    config: &Config,
    applied_revision: String,
    applied_digest: String,
    health: std::sync::Arc<RuntimeHealth>,
    generation: u64,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> anyhow::Result<Option<ClusterHeartbeatTask>> {
    if !self.cluster_mode() {
      return Ok(None);
    }
    let mut random = [0_u8; 16];
    random_fill(&mut random).context("failed to generate Admin cluster boot identity")?;
    let mut boot_id = String::with_capacity(37);
    boot_id.push_str("boot-");
    for byte in random {
      let _ = write!(boot_id, "{byte:02x}");
    }
    if self.store()?.load_revision("config").await?.is_none() {
      self
        .store()?
        .initialize_revision(
          "config",
          &applied_revision,
          &applied_digest,
          Some(&self.inner.target.cluster_id),
          Some(&self.inner.target.membership_revision),
        )
        .await
        .context("failed to initialize Admin cluster configuration baseline")?;
    }
    self.initialize_cluster_controller(config, boot_id, applied_revision, applied_digest)?;
    let controller = self
      .installed_cluster_controller()
      .context("Admin cluster controller failed to initialize")?;
    controller.heartbeat_once().await?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task_controller = controller.clone();
    Ok(Some(ClusterHeartbeatTask {
      runtime: self.clone(),
      shutdown,
      task: Some(spawn_supervised_task(
        health,
        generation,
        RuntimeTaskKind::AdminMutationHeartbeat,
        RuntimeTaskPolicy::RestartableCritical,
        shutdown_rx,
        fatal_tx,
        move |shutdown| {
          let controller = task_controller.clone();
          async move { controller.heartbeat_until_shutdown(shutdown).await }
        },
      )),
    }))
  }
}
