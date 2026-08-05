//! Process-lifetime fixed-member heartbeat activation and shutdown.

use std::fmt::Write as _;

use anyhow::Context;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};

use crate::config::Config;
use crate::crypto::random_fill;
use crate::metrics::Metrics;
use crate::runtime_health::{
  RuntimeHealth, RuntimeTaskKind, RuntimeTaskPolicy, spawn_supervised_task,
};

use super::{AdminMutationRuntime, LocalMembershipHead};

pub(crate) struct ClusterHeartbeatBootstrap {
  pub(crate) applied_revision: String,
  pub(crate) applied_digest: String,
  pub(crate) local_heads: Vec<LocalMembershipHead>,
}

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
  async fn refresh_staged_membership_authority(
    &self,
    controller: &crate::admin_mutation::rollout::AdminClusterRolloutController,
  ) -> anyhow::Result<()> {
    if !self.staged_membership() {
      return Ok(());
    }
    let store = self.store()?;
    self.reconcile_local_staged_membership(controller).await?;
    let _ = super::super::membership_store::finalize_committed_membership_activation(
      store,
      &self.inner.cluster_id,
    )
    .await?;
    let Some(active) = super::super::membership_store::load_active_membership_authority(
      store,
      &self.inner.cluster_id,
    )
    .await?
    else {
      return Ok(());
    };
    let current = self.membership_authority();
    let local_member = self
      .inner
      .local_instance_id
      .as_deref()
      .context("staged membership local instance ID is missing")?;
    let local_is_active_member = active
      .members
      .binary_search_by(|member| member.as_str().cmp(local_member))
      .is_ok();
    let artifact_key_fingerprint = if active.epoch_version == 1 {
      if local_is_active_member {
        self
          .artifact_cipher_for_membership(&active.epoch_digest)?
          .key_fingerprint()
          .to_string()
      } else {
        current.artifact_key_fingerprint.clone()
      }
    } else {
      active
        .artifact_key_fingerprint
        .clone()
        .context("active membership epoch v2 is missing its artifact-key fingerprint")?
    };
    if current.target.membership_revision == active.epoch_digest
      && current.members == active.members
      && current.artifact_key_fingerprint == artifact_key_fingerprint
    {
      return Ok(());
    }
    if active.epoch_version == crate::admin_mutation::membership::MEMBERSHIP_DOCUMENT_VERSION
      && local_is_active_member
    {
      let private = self
        .inner
        .membership_private_keys
        .as_ref()
        .context("staged membership private keys are missing")?;
      super::membership_reconciliation::validate_local_epoch_identity(
        &active.epoch,
        local_member,
        &private.readiness_pkcs8,
        private.catchup_x25519.as_ref(),
      )
      .context("active membership epoch local identity is invalid")?;
    }
    if local_is_active_member
      && self
        .artifact_cipher_for_membership(&active.epoch_digest)
        .is_err()
    {
      let private = self
        .inner
        .membership_private_keys
        .as_ref()
        .context("staged membership private keys are missing")?;
      let cipher = super::super::membership_store::load_epoch_artifact_cipher_for_member(
        store,
        &self.inner.cluster_id,
        &active.epoch_digest,
        local_member,
        private.catchup_x25519.as_ref(),
        crate::admin_mutation::store::MAX_STORED_ARTIFACT_BYTES,
      )
      .await?;
      self
        .inner
        .artifact_ciphers
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(active.epoch_digest.clone(), cipher);
    }
    controller
      .activate_membership(
        active.epoch_digest.clone(),
        active.members.clone(),
        artifact_key_fingerprint.clone(),
      )
      .await?;
    if active.epoch_version == crate::admin_mutation::membership::MEMBERSHIP_DOCUMENT_VERSION {
      self
        .inner
        .artifact_ciphers
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .retain(|revision, _| revision == &active.epoch_digest);
    }
    *self
      .inner
      .membership_authority
      .write()
      .unwrap_or_else(std::sync::PoisonError::into_inner) = super::MembershipAuthority {
      target: crate::admin_mutation::MutationTarget {
        cluster_id: self.inner.cluster_id.clone(),
        membership_revision: active.epoch_digest,
      },
      members: active.members,
      artifact_key_fingerprint,
    };
    Ok(())
  }

  async fn update_membership_metrics(&self, metrics: &Metrics) -> anyhow::Result<()> {
    if !self.staged_membership() {
      metrics.set_admin_membership_status(self.configured_members().len() as u64, 0, None);
      return Ok(());
    }
    let status = super::super::membership_store::load_membership_status(
      self.store()?,
      &self.inner.cluster_id,
      &self.inner.membership_bootstrap_members,
    )
    .await?;
    metrics.set_admin_membership_status(
      status.required_members.len() as u64,
      status.fenced_members.len() as u64,
      status
        .pending_transition
        .as_ref()
        .map(|transition| transition.state.as_str()),
    );
    Ok(())
  }

  async fn heartbeat_with_membership_until_shutdown(
    &self,
    controller: crate::admin_mutation::rollout::AdminClusterRolloutController,
    metrics: std::sync::Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
  ) -> anyhow::Result<()> {
    let mut ticker = interval(controller.heartbeat_interval());
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
      tokio::select! {
        biased;
        changed = shutdown.changed() => {
          if changed.is_err() || *shutdown.borrow() {
            return Ok(());
          }
        }
        _ = ticker.tick() => {
          self.refresh_staged_membership_authority(&controller).await?;
          controller.heartbeat_and_refresh_readiness().await?;
          self.update_membership_metrics(&metrics).await?;
        }
      }
    }
  }

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
    bootstrap: ClusterHeartbeatBootstrap,
    metrics: std::sync::Arc<Metrics>,
    health: std::sync::Arc<RuntimeHealth>,
    generation: u64,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
  ) -> anyhow::Result<Option<ClusterHeartbeatTask>> {
    if !self.cluster_mode() {
      return Ok(None);
    }
    let ClusterHeartbeatBootstrap {
      applied_revision,
      applied_digest,
      local_heads,
    } = bootstrap;
    self.install_local_membership_heads(local_heads)?;
    let mut random = [0_u8; 16];
    random_fill(&mut random).context("failed to generate Admin cluster boot identity")?;
    let mut boot_id = String::with_capacity(37);
    boot_id.push_str("boot-");
    for byte in random {
      let _ = write!(boot_id, "{byte:02x}");
    }
    let authority = self.membership_authority();
    if self.store()?.load_revision("config").await?.is_none() {
      self
        .store()?
        .initialize_revision(
          "config",
          &applied_revision,
          &applied_digest,
          Some(&authority.target.cluster_id),
          Some(&authority.target.membership_revision),
        )
        .await
        .context("failed to initialize Admin cluster configuration baseline")?;
    }
    if self.staged_membership() && self.store()?.load_revision("membership").await?.is_none() {
      self
        .store()?
        .initialize_revision(
          "membership",
          "membership-uninitialized",
          &super::digest_parts(["membership-uninitialized"]),
          Some(&authority.target.cluster_id),
          Some(&authority.target.membership_revision),
        )
        .await
        .context("failed to initialize Admin membership logical baseline")?;
    }
    self.initialize_cluster_controller(config, boot_id, applied_revision, applied_digest)?;
    let controller = self
      .installed_cluster_controller()
      .context("Admin cluster controller failed to initialize")?;
    self
      .refresh_staged_membership_authority(&controller)
      .await?;
    controller.heartbeat_once().await?;
    self.update_membership_metrics(&metrics).await?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task_controller = controller.clone();
    let task_runtime = self.clone();
    let task_metrics = metrics.clone();
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
          let runtime = task_runtime.clone();
          let metrics = task_metrics.clone();
          async move {
            runtime
              .heartbeat_with_membership_until_shutdown(controller, metrics, shutdown)
              .await
          }
        },
      )),
    }))
  }
}

#[cfg(test)]
#[path = "cluster_heartbeat_tests.rs"]
mod tests;
