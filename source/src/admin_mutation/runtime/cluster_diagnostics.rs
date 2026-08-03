use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use crate::config::AdminMutationRolloutMode;

use super::AdminMutationRuntime;
use crate::admin_mutation::rollout_store;

const CAPABILITY_VERSION: &str = "admin-mutation-rollout-v1";
const ACTIVE_ROLLOUT_LIMIT: i64 = 32;
const LIVE_MEMBER_LIMIT: i64 = 1024;

impl AdminMutationRuntime {
  /// Returns a bounded diagnostic view. Guarded terminal transitions remain
  /// the convergence authority; this snapshot never authorizes a mutation.
  pub(crate) async fn cluster_diagnostics(&self) -> anyhow::Result<Value> {
    let authority = self.membership_authority();
    if self.inner.rollout_mode != AdminMutationRolloutMode::AdminCluster {
      return Ok(json!({
        "membership_revision": authority.target.membership_revision,
        "membership": self.membership_status().await?,
        "authority": { "ready": true, "blocking_reason": null },
        "active_rollouts": [],
        "logical_revisions": {},
        "live_members_truncated": false,
        "instances": [],
      }));
    }
    let store = self.store()?;
    let (live, live_members_truncated) =
      rollout_store::load_live_members_bounded(store, &self.inner.cluster_id, LIVE_MEMBER_LIMIT)
        .await?;
    let mut heads = BTreeMap::<(String, String), _>::new();
    for resource in ["config", "ipm", "break-glass"] {
      for head in
        rollout_store::load_resource_heads(store, &self.inner.cluster_id, resource).await?
      {
        heads.insert((head.instance_id.clone(), resource.to_string()), head);
      }
    }
    let expected_key = self.artifact_key_fingerprint()?;
    let mut instance_ids = authority.members.clone();
    instance_ids.extend(live.iter().map(|value| value.instance_id.clone()));
    instance_ids.sort();
    instance_ids.dedup();
    let instances = instance_ids
      .iter()
      .map(|instance_id| {
        let heartbeat = live.iter().find(|value| &value.instance_id == instance_id);
        let compatible = heartbeat.is_some_and(|value| {
          value.membership_revision == authority.target.membership_revision
            && value.build_version == oxibelt_build_identity::SHORT_VERSION
            && value.capability_version == CAPABILITY_VERSION
            && value.artifact_key_fingerprint == expected_key
        });
        let resource_heads = ["config", "ipm", "break-glass"]
          .into_iter()
          .map(|resource| {
            let current = heads
              .get(&(instance_id.clone(), resource.to_string()))
              .filter(|head| {
                heartbeat.is_some_and(|value| {
                  head.boot_id == value.boot_id && head.instance_epoch == value.instance_epoch
                })
              });
            (
              resource.to_string(),
              current.map(|head| json!(head)).unwrap_or(Value::Null),
            )
          })
          .collect::<serde_json::Map<_, _>>();
        let ready = heartbeat.is_some_and(|value| value.ready)
          && compatible
          && resource_heads.values().all(|head| head["ready"] == true);
        let safe_heartbeat = heartbeat.map(|value| {
          json!({
            "cluster_id": value.cluster_id,
            "instance_id": value.instance_id,
            "boot_id": value.boot_id,
            "instance_epoch": value.instance_epoch,
            "build_version": value.build_version,
            "capability_version": value.capability_version,
            "membership_revision": value.membership_revision,
            "assigned_revision": value.assigned_revision,
            "applied_revision": value.applied_revision,
            "applied_digest": value.applied_digest,
            "ready": value.ready,
            "lease_expires_at": value.lease_expires_at,
            "updated_at": value.updated_at,
          })
        });
        json!({
          "instance_id": instance_id,
          "configured": authority.members.contains(instance_id),
          "live": heartbeat.is_some(),
          "ready": ready,
          "compatible": compatible,
          "heartbeat": safe_heartbeat,
          "resources": resource_heads,
        })
      })
      .collect::<Vec<_>>();
    let workers = self.inner.cluster_worker_state.load(Ordering::Acquire) == 0b11;
    let authority_ready = self.cluster_rollout_ready();
    let blocking_reason = if live_members_truncated {
      Some("live_members_truncated")
    } else if !workers {
      Some("cluster_workers_unavailable")
    } else if !authority_ready {
      Some("durable_authority_unavailable")
    } else if instances.iter().any(|instance| instance["ready"] != true) {
      Some("exact_membership_not_ready")
    } else {
      None
    };
    let mut logical_revisions = serde_json::Map::new();
    for resource in ["config", "ipm", "break-glass"] {
      logical_revisions.insert(
        resource.to_string(),
        store
          .load_revision(resource)
          .await?
          .map(serde_json::to_value)
          .transpose()?
          .unwrap_or(Value::Null),
      );
    }
    Ok(json!({
      "membership_revision": authority.target.membership_revision,
      "membership": self.membership_status().await?,
      "authority": {
        "ready": authority_ready && blocking_reason.is_none(),
        "blocking_reason": blocking_reason,
      },
      "live_members_truncated": live_members_truncated,
      "active_rollouts": rollout_store::load_recoverable_mutations(store, ACTIVE_ROLLOUT_LIMIT).await?,
      "logical_revisions": logical_revisions,
      "instances": instances,
    }))
  }
}
