//! Kubernetes controller-owner chain verification for immutable rollout Pods.

use std::collections::HashSet;

use anyhow::Context;
use serde_json::{Map, Value};

use super::{RolloutTarget, WorkloadKind};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct WorkloadPodOwnership {
  pod_owner_kind: &'static str,
  pod_owner_uids: HashSet<String>,
}

impl WorkloadPodOwnership {
  pub(crate) fn from_workload(
    target: &RolloutTarget,
    workload: &Value,
    replica_sets: &[Value],
  ) -> anyhow::Result<Self> {
    let workload_uid = object_uid(workload)
      .context("target workload metadata.uid is required for Pod ownership verification")?;
    let (pod_owner_kind, pod_owner_uids) = match target.kind {
      WorkloadKind::DaemonSet => ("DaemonSet", HashSet::from([workload_uid.to_string()])),
      WorkloadKind::Deployment => (
        "ReplicaSet",
        replica_sets
          .iter()
          .filter(|replica_set| controller_owned_by(replica_set, "Deployment", workload_uid))
          .filter_map(object_uid)
          .map(str::to_string)
          .collect(),
      ),
    };
    Ok(Self {
      pod_owner_kind,
      pod_owner_uids,
    })
  }

  fn owns_pod(&self, pod: &Value) -> bool {
    self
      .pod_owner_uids
      .iter()
      .any(|owner_uid| controller_owned_by(pod, self.pod_owner_kind, owner_uid))
  }

  pub(crate) fn proof_owner_uids(&self) -> Vec<&str> {
    let mut uids = self
      .pod_owner_uids
      .iter()
      .map(String::as_str)
      .collect::<Vec<_>>();
    uids.sort();
    uids
  }
}

pub(crate) fn pod_is_selected(
  workload: &Value,
  ownership: &WorkloadPodOwnership,
  pod: &Value,
) -> bool {
  let Some(selector) = workload
    .pointer("/spec/selector")
    .and_then(Value::as_object)
  else {
    return false;
  };
  let labels = pod
    .pointer("/metadata/labels")
    .and_then(Value::as_object)
    .cloned()
    .unwrap_or_default();
  let labels_match = selector
    .get("matchLabels")
    .and_then(Value::as_object)
    .is_none_or(|required| {
      required
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
    });
  ownership.owns_pod(pod)
    && labels_match
    && selector
      .get("matchExpressions")
      .and_then(Value::as_array)
      .is_none_or(|expressions| {
        expressions
          .iter()
          .all(|expression| expression_matches(expression, &labels))
      })
}

fn object_uid(value: &Value) -> Option<&str> {
  value
    .pointer("/metadata/uid")
    .and_then(Value::as_str)
    .filter(|uid| !uid.is_empty())
}

fn controller_owned_by(object: &Value, owner_kind: &str, owner_uid: &str) -> bool {
  object
    .pointer("/metadata/ownerReferences")
    .and_then(Value::as_array)
    .is_some_and(|references| {
      references.iter().any(|reference| {
        reference.get("apiVersion").and_then(Value::as_str) == Some("apps/v1")
          && reference.get("kind").and_then(Value::as_str) == Some(owner_kind)
          && reference.get("uid").and_then(Value::as_str) == Some(owner_uid)
          && reference.get("controller").and_then(Value::as_bool) == Some(true)
      })
    })
}

fn expression_matches(expression: &Value, labels: &Map<String, Value>) -> bool {
  let Some(key) = expression.get("key").and_then(Value::as_str) else {
    return false;
  };
  let operator = expression
    .get("operator")
    .and_then(Value::as_str)
    .unwrap_or_default();
  let values = expression
    .get("values")
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .collect::<Vec<_>>();
  match operator {
    "In" => labels
      .get(key)
      .and_then(Value::as_str)
      .is_some_and(|value| values.contains(&value)),
    "NotIn" => labels
      .get(key)
      .and_then(Value::as_str)
      .is_some_and(|value| !values.contains(&value)),
    "Exists" => labels.contains_key(key),
    "DoesNotExist" => !labels.contains_key(key),
    _ => false,
  }
}
