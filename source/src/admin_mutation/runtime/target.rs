//! Canonical mutation targets shared by admission and cluster fencing.

use std::fmt::Write as _;

use anyhow::ensure;
use sha2::{Digest, Sha256};

use crate::admin_audit::AdminAuditRuntime;
use crate::config::Config;

use super::AdminMutationRuntime;
use crate::admin_mutation::envelope::MutationTarget;

impl AdminMutationRuntime {
  pub(crate) async fn new_or_reuse(
    config: &Config,
    audit: &AdminAuditRuntime,
    previous: Option<(&Config, &Self)>,
  ) -> anyhow::Result<Self> {
    if let Some((previous_config, runtime)) = previous
      && config.admin.mutations.rollout.mode.is_cluster()
      && config.admin.enabled == previous_config.admin.enabled
      && config.admin.audit == previous_config.admin.audit
      && config.admin.mutations == previous_config.admin.mutations
      && config.rollout == previous_config.rollout
      && config.shared_state.namespace == previous_config.shared_state.namespace
      && config.shared_state.backends == previous_config.shared_state.backends
    {
      return Ok(runtime.clone());
    }
    Self::new(config, audit).await
  }
}

pub(crate) fn configured_target(config: &Config) -> MutationTarget {
  let rollout = &config.admin.mutations.rollout;
  if rollout.mode.is_cluster() {
    return MutationTarget {
      cluster_id: rollout.cluster_id.clone(),
      membership_revision: cluster_membership_revision(&rollout.cluster_id, &rollout.members),
    };
  }
  let cluster_id = if rollout.cluster_id.is_empty() {
    "single".to_string()
  } else {
    rollout.cluster_id.clone()
  };
  let mut digest_fields = vec![cluster_id.as_str(), rollout.instance_id_env.as_str()];
  digest_fields.extend(rollout.members.iter().map(String::as_str));
  MutationTarget {
    membership_revision: digest_parts(digest_fields),
    cluster_id,
  }
}

fn cluster_membership_revision(cluster_id: &str, members: &[String]) -> String {
  let mut members = members.iter().map(String::as_str).collect::<Vec<_>>();
  members.sort_unstable();
  let mut digest_fields = vec!["v1", cluster_id];
  digest_fields.extend(members);
  digest_parts(digest_fields)
}

pub(super) fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
  let mut hasher = Sha256::new();
  hasher.update(b"OXIBELT-ADMIN-MUTATION-MEMBERSHIP\0");
  for part in parts {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part.as_bytes());
  }
  let mut output = String::with_capacity(71);
  output.push_str("sha256:");
  for byte in hasher.finalize() {
    let _ = write!(output, "{byte:02x}");
  }
  output
}

pub(super) fn ensure_cluster_member(
  runtime: &AdminMutationRuntime,
  instance_id: &str,
) -> anyhow::Result<()> {
  ensure!(
    runtime.cluster_mode(),
    "Admin mutation runtime is not in admin_cluster mode"
  );
  ensure!(
    runtime
      .inner
      .members
      .binary_search(&instance_id.to_string())
      .is_ok(),
    "instance is not in the configured Admin cluster membership"
  );
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cluster_membership_revision_is_canonical_but_cluster_bound() {
    let left = vec![
      "edge-c".to_string(),
      "edge-a".to_string(),
      "edge-b".to_string(),
    ];
    let right = vec![
      "edge-a".to_string(),
      "edge-b".to_string(),
      "edge-c".to_string(),
    ];
    assert_eq!(
      cluster_membership_revision("primary", &left),
      cluster_membership_revision("primary", &right)
    );
    assert_ne!(
      cluster_membership_revision("primary", &left),
      cluster_membership_revision("recovery", &left)
    );
  }
}
