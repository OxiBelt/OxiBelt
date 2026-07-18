use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use oxibelt_control_http::{full_body, uri_from_url};
use serde_json::Value;
use tracing::{info, warn};

use super::cli::{RunArgs, SharedArgs};
use super::rollout::{
  CONFIG_DIGEST_ANNOTATION, CONFIG_REVISION_ANNOTATION, ConfigArtifact, HOLDER_IDENTITY_ANNOTATION,
  LEADER_EPOCH_ANNOTATION, LEASE_UID_ANNOTATION, RolloutPhase, RolloutState, RolloutTarget,
  WorkloadKind, WorkloadPodOwnership, annotation, build_workload_patch, evaluate_convergence,
  now_unix_seconds, pod_is_selected,
};
use super::rollout_decision::{
  ObservationDecision, decide_observation, mark_failed_attempt, prepare_rollback_state,
  requires_rollback,
};
use super::rollout_patch::{
  add_leadership_fence, base_config_reference, validate_immutable_base_config,
  validate_rollout_opt_in,
};
use super::rollout_status::RolloutStatus;
use super::watch::{KUBERNETES_MAX_BODY_BYTES, KubernetesPoller};

const ROLLOUT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

impl KubernetesPoller {
  pub async fn reconcile_immutable_rollout(
    &self,
    shared: &SharedArgs,
    args: &RunArgs,
    generated_toml: &str,
  ) -> anyhow::Result<RolloutStatus> {
    let target = RolloutTarget::from_args(args)?;
    let candidate = ConfigArtifact::new(
      &target,
      &shared.managed_config_path,
      generated_toml.to_string(),
    )?;
    let workload = self.get_required_json(&target.workload_path()).await?;
    validate_rollout_opt_in(&workload)?;
    self
      .preflight_base_config(&target, &workload, &candidate.managed_path)
      .await?;
    self.ensure_config_map(&target, &candidate).await?;
    let state = RolloutState::from_workload(&workload);

    if state.desired_revision.is_some() {
      let permit = self.authorize_write().await?;
      if !workload_term_matches(&workload, permit.term()) {
        let desired = self.load_desired_artifact(&target, &state).await?;
        self
          .apply_state(&target, &workload, &desired, &state)
          .await?;
        info!(
          lease_uid = %permit.term().lease_uid,
          leader_epoch = permit.term().leader_epoch,
          "adopted persisted immutable rollout state under the current leadership term"
        );
        return Ok(RolloutStatus::from(&state));
      }
    }

    if state.phase == RolloutPhase::RolledBack
      && state.failed_revision.as_deref() == Some(candidate.name.as_str())
    {
      let rollback = self.load_desired_artifact(&target, &state).await?;
      let mut failed = state;
      failed.phase = RolloutPhase::Failed;
      self
        .apply_state(&target, &workload, &rollback, &failed)
        .await?;
      return Ok(RolloutStatus::from(&failed));
    }

    if candidate_is_blocked_after_failure(&state, &candidate.name) {
      return Ok(RolloutStatus::from(&state));
    }

    if state.desired_revision.as_deref() == Some(candidate.name.as_str()) {
      return self
        .reconcile_active_revision(&target, &workload, state, candidate, false)
        .await;
    }

    if state.phase == RolloutPhase::RollbackRequested {
      let rollback = self.load_desired_artifact(&target, &state).await?;
      return self
        .reconcile_active_revision(&target, &workload, state, rollback, true)
        .await;
    }

    if state.phase != RolloutPhase::Committed
      && state.desired_revision.is_some()
      && state.committed_revision.is_some()
      && state.desired_revision != state.committed_revision
    {
      return self
        .request_rollback(&target, &workload, state, "SupersededByNewRevision")
        .await;
    }

    let next = RolloutState::new_attempt(&candidate, &state, now_unix_seconds());
    self
      .apply_state(&target, &workload, &candidate, &next)
      .await?;
    info!(
      revision = %candidate.name,
      digest = %candidate.content_digest,
      "started immutable Gateway API configuration rollout"
    );
    Ok(RolloutStatus::from(&next))
  }

  async fn reconcile_active_revision(
    &self,
    target: &RolloutTarget,
    workload: &Value,
    state: RolloutState,
    active: ConfigArtifact,
    rolling_back: bool,
  ) -> anyhow::Result<RolloutStatus> {
    let replica_sets = if target.kind == WorkloadKind::Deployment {
      self.list_replica_sets(&target.namespace).await?
    } else {
      Vec::new()
    };
    let ownership = WorkloadPodOwnership::from_workload(target, workload, &replica_sets)?;
    let pods = self.list_pods(&target.namespace).await?;
    let convergence = evaluate_convergence(
      target,
      workload,
      &ownership,
      &pods,
      &active.name,
      &active.content_digest,
    );
    let rejected_reason = rejected_pod_reason(
      workload,
      &ownership,
      &pods,
      &active.name,
      &active.content_digest,
    );
    match decide_observation(
      &state,
      &convergence,
      rejected_reason,
      rollout_timed_out(&state, target),
    ) {
      ObservationDecision::Reject(reason) => {
        self
          .fail_or_rollback(target, workload, state, &active, reason)
          .await
      }
      ObservationDecision::Converged => {
        self
          .advance_converged_state(target, workload, state, &active, rolling_back)
          .await
      }
      ObservationDecision::ConvergenceLost => Ok(convergence_lost_status(&state)),
      ObservationDecision::Advance(phase) => {
        let mut next = state;
        next.phase = phase;
        self.apply_state(target, workload, &active, &next).await?;
        Ok(RolloutStatus::from(&next))
      }
      ObservationDecision::Wait => Ok(RolloutStatus::from(&state)),
    }
  }

  async fn advance_converged_state(
    &self,
    target: &RolloutTarget,
    workload: &Value,
    state: RolloutState,
    active: &ConfigArtifact,
    rolling_back: bool,
  ) -> anyhow::Result<RolloutStatus> {
    let mut next = state;
    let next_phase = convergence_transition(next.phase, rolling_back);
    if next_phase == next.phase {
      return Ok(RolloutStatus::from(&next));
    }
    next.phase = next_phase;
    if next.phase == RolloutPhase::RolledBack {
      self.apply_state(target, workload, active, &next).await?;
      return Ok(RolloutStatus::from(&next));
    }
    if next.phase == RolloutPhase::FullyApplied {
      self.apply_state(target, workload, active, &next).await?;
      return Ok(RolloutStatus::from(&next));
    }
    next.phase = RolloutPhase::Committed;
    next.committed_revision = Some(active.name.clone());
    next.committed_content_digest = Some(active.content_digest.clone());
    next.failure = None;
    self.apply_state(target, workload, active, &next).await?;
    info!(revision = %active.name, digest = %active.content_digest, "committed immutable Gateway API configuration rollout");
    Ok(RolloutStatus::from(&next))
  }

  async fn fail_or_rollback(
    &self,
    target: &RolloutTarget,
    workload: &Value,
    state: RolloutState,
    active: &ConfigArtifact,
    reason: &str,
  ) -> anyhow::Result<RolloutStatus> {
    let mut failed = mark_failed_attempt(state, &active.name);
    if requires_rollback(&failed, &active.name) {
      return self
        .request_rollback(target, workload, failed, reason)
        .await;
    }
    failed.phase = RolloutPhase::Failed;
    failed.failure = Some(reason.to_string());
    self.apply_state(target, workload, active, &failed).await?;
    Ok(RolloutStatus::from(&failed))
  }

  async fn request_rollback(
    &self,
    target: &RolloutTarget,
    workload: &Value,
    state: RolloutState,
    reason: &str,
  ) -> anyhow::Result<RolloutStatus> {
    let rollback = self.load_committed_artifact(target, &state).await?;
    let next = prepare_rollback_state(state, &rollback, reason);
    self.apply_state(target, workload, &rollback, &next).await?;
    warn!(revision = %rollback.name, reason, "requested immutable Gateway configuration rollback");
    Ok(RolloutStatus::from(&next))
  }

  async fn apply_state(
    &self,
    target: &RolloutTarget,
    workload: &Value,
    artifact: &ConfigArtifact,
    state: &RolloutState,
  ) -> anyhow::Result<()> {
    let permit = self.authorize_write().await?;
    let mut patch = build_workload_patch(workload, target, artifact, state)?;
    add_leadership_fence(&mut patch, workload, permit.term())?;
    let body =
      serde_json::to_vec(&patch.json()).context("failed to serialize workload JSON Patch")?;
    let (status, response) = self
      .request(
        Method::PATCH,
        &target.workload_path(),
        None,
        Some("application/json-patch+json"),
        Some(body),
      )
      .await?;
    if status == StatusCode::CONFLICT {
      bail!(
        "target workload changed during immutable rollout; retrying with a fresh resourceVersion is required"
      );
    }
    if !status.is_success() {
      bail!(
        "Kubernetes workload JSON Patch returned {status}: {}",
        response_message(&response)
      );
    }
    Ok(())
  }

  async fn ensure_config_map(
    &self,
    target: &RolloutTarget,
    artifact: &ConfigArtifact,
  ) -> anyhow::Result<()> {
    let path = format!(
      "/api/v1/namespaces/{}/configmaps/{}",
      target.namespace, artifact.name
    );
    if let Some(existing) = self.get_optional_json(&path).await? {
      if artifact.matches_existing(target, &existing) {
        return Ok(());
      }
      bail!("immutable ConfigMap name collision has different content or metadata");
    }
    let collection = format!("/api/v1/namespaces/{}/configmaps", target.namespace);
    let _permit = self.authorize_write().await?;
    let body = serde_json::to_vec(&artifact.manifest(target))
      .context("failed to serialize immutable ConfigMap")?;
    let (status, response) = self
      .request(
        Method::POST,
        &collection,
        None,
        Some("application/json"),
        Some(body),
      )
      .await?;
    if status.is_success() {
      return Ok(());
    }
    if status == StatusCode::CONFLICT {
      let existing = self
        .get_optional_json(&path)
        .await?
        .context("ConfigMap creation conflicted but no existing ConfigMap was readable")?;
      if artifact.matches_existing(target, &existing) {
        return Ok(());
      }
      bail!("immutable ConfigMap name collision has different content or metadata");
    }
    bail!(
      "Kubernetes ConfigMap create returned {status}: {}",
      response_message(&response)
    );
  }

  async fn preflight_base_config(
    &self,
    target: &RolloutTarget,
    workload: &Value,
    managed_path: &str,
  ) -> anyhow::Result<()> {
    let base = base_config_reference(workload, target, managed_path)?;
    let path = format!(
      "/api/v1/namespaces/{}/configmaps/{}",
      target.namespace, base.config_map_name
    );
    let config_map = self.get_optional_json(&path).await?.with_context(|| {
      format!(
        "target base ConfigMap `{}` was not found",
        base.config_map_name
      )
    })?;
    validate_immutable_base_config(&config_map, &base, managed_path)
  }

  async fn load_desired_artifact(
    &self,
    target: &RolloutTarget,
    state: &RolloutState,
  ) -> anyhow::Result<ConfigArtifact> {
    let revision = state
      .desired_revision
      .as_deref()
      .context("rollback state has no desired immutable revision")?;
    self.load_artifact(target, revision).await
  }

  async fn load_committed_artifact(
    &self,
    target: &RolloutTarget,
    state: &RolloutState,
  ) -> anyhow::Result<ConfigArtifact> {
    let revision = state
      .committed_revision
      .as_deref()
      .context("rollout cannot roll back because no committed immutable revision exists")?;
    self.load_artifact(target, revision).await
  }

  async fn load_artifact(
    &self,
    target: &RolloutTarget,
    revision: &str,
  ) -> anyhow::Result<ConfigArtifact> {
    let path = format!(
      "/api/v1/namespaces/{}/configmaps/{revision}",
      target.namespace
    );
    let value = self
      .get_optional_json(&path)
      .await?
      .with_context(|| format!("immutable ConfigMap `{revision}` no longer exists"))?;
    ConfigArtifact::from_existing(target, &value)
  }

  pub(super) async fn get_required_json(&self, path: &str) -> anyhow::Result<Value> {
    self
      .get_optional_json(path)
      .await?
      .with_context(|| format!("Kubernetes resource {path} was not found"))
  }

  async fn get_optional_json(&self, path: &str) -> anyhow::Result<Option<Value>> {
    let (status, body) = self.request(Method::GET, path, None, None, None).await?;
    if status == StatusCode::NOT_FOUND {
      return Ok(None);
    }
    if !status.is_success() {
      bail!(
        "Kubernetes API GET {path} returned {status}: {}",
        response_message(&body)
      );
    }
    let value = serde_json::from_slice(&body)
      .with_context(|| format!("failed to parse Kubernetes API JSON from {path}"))?;
    Ok(Some(value))
  }

  pub(super) async fn list_pods(&self, namespace: &str) -> anyhow::Result<Vec<Value>> {
    let path = format!("/api/v1/namespaces/{namespace}/pods");
    let value = self
      .get_required_json(&path)
      .await
      .context("failed to list Pods for immutable rollout convergence")?;
    Ok(
      value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default(),
    )
  }

  pub(super) async fn list_replica_sets(&self, namespace: &str) -> anyhow::Result<Vec<Value>> {
    let path = format!("/apis/apps/v1/namespaces/{namespace}/replicasets");
    let value = self
      .get_required_json(&path)
      .await
      .context("failed to list ReplicaSets for immutable rollout Pod ownership verification")?;
    Ok(
      value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default(),
    )
  }

  async fn request(
    &self,
    method: Method,
    path: &str,
    query: Option<&str>,
    content_type: Option<&str>,
    body: Option<Vec<u8>>,
  ) -> anyhow::Result<(StatusCode, Bytes)> {
    let mut url = self.base_url.clone();
    url.set_path(path);
    url.set_query(query);
    let bearer = self.bearer()?;
    let mut builder = Request::builder()
      .method(method)
      .uri(uri_from_url(&url)?)
      .header(http::header::ACCEPT, "application/json")
      .header(http::header::AUTHORIZATION, bearer);
    if let Some(content_type) = content_type {
      builder = builder.header(http::header::CONTENT_TYPE, content_type);
    }
    let request = builder.body(full_body(Bytes::from(body.unwrap_or_default())))?;
    let response = self
      .client
      .request(request, ROLLOUT_REQUEST_TIMEOUT, KUBERNETES_MAX_BODY_BYTES)
      .await?;
    Ok((response.status, response.body))
  }
}

fn workload_term_matches(workload: &Value, term: &super::leader_election::LeadershipTerm) -> bool {
  annotation(workload, LEASE_UID_ANNOTATION) == Some(term.lease_uid.as_str())
    && annotation(workload, LEADER_EPOCH_ANNOTATION).and_then(|epoch| epoch.parse::<u64>().ok())
      == Some(term.leader_epoch)
    && annotation(workload, HOLDER_IDENTITY_ANNOTATION) == Some(term.holder_identity.as_str())
}

fn rollout_timed_out(state: &RolloutState, target: &RolloutTarget) -> bool {
  state
    .started_at_unix
    .is_some_and(|started| now_unix_seconds().saturating_sub(started) >= target.timeout.as_secs())
}

pub(super) fn convergence_transition(phase: RolloutPhase, rolling_back: bool) -> RolloutPhase {
  if rolling_back {
    RolloutPhase::RolledBack
  } else {
    match phase {
      RolloutPhase::Committed => RolloutPhase::Committed,
      RolloutPhase::FullyApplied => RolloutPhase::Committed,
      _ => RolloutPhase::FullyApplied,
    }
  }
}

pub(super) fn candidate_is_blocked_after_failure(
  state: &RolloutState,
  candidate_revision: &str,
) -> bool {
  state.phase == RolloutPhase::Failed
    && state.failed_revision.as_deref() == Some(candidate_revision)
}

fn convergence_lost_status(state: &RolloutState) -> RolloutStatus {
  RolloutStatus {
    phase: RolloutPhase::Generated,
    desired_revision: state.desired_revision.clone(),
    desired_content_digest: state.desired_content_digest.clone(),
    reason: Some("ConvergenceLost".to_string()),
    proof: None,
  }
}

fn rejected_pod_reason(
  workload: &Value,
  ownership: &WorkloadPodOwnership,
  pods: &[Value],
  revision: &str,
  content_digest: &str,
) -> Option<&'static str> {
  for pod in pods.iter().filter(|pod| {
    pod_is_selected(workload, ownership, pod)
      && pod
        .pointer("/metadata/deletionTimestamp")
        .is_none_or(|value| value.is_null())
      && annotation(pod, CONFIG_REVISION_ANNOTATION) == Some(revision)
      && annotation(pod, CONFIG_DIGEST_ANNOTATION) == Some(content_digest)
  }) {
    let Some(statuses) = pod
      .pointer("/status/containerStatuses")
      .and_then(Value::as_array)
    else {
      continue;
    };
    for status in statuses {
      if status
        .pointer("/state/terminated/exitCode")
        .and_then(Value::as_i64)
        .is_some_and(|exit_code| exit_code != 0)
      {
        return Some("PodRejected");
      }
      if status
        .pointer("/state/waiting/reason")
        .and_then(Value::as_str)
        .is_some_and(|reason| {
          matches!(
            reason,
            "CrashLoopBackOff" | "CreateContainerConfigError" | "Error"
          )
        })
      {
        return Some("PodRejected");
      }
    }
  }
  None
}

fn response_message(body: &[u8]) -> String {
  String::from_utf8_lossy(body).chars().take(1_024).collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::leader_election::LeadershipTerm;
  use serde_json::json;

  #[test]
  fn persisted_rollout_requires_current_term_adoption() {
    let term = LeadershipTerm {
      lease_uid: "lease-a".to_string(),
      leader_epoch: 3,
      holder_identity: "pod-a".to_string(),
    };
    let mut workload = json!({"metadata":{"annotations":{}}});
    assert!(!workload_term_matches(&workload, &term));
    workload["metadata"]["annotations"][LEASE_UID_ANNOTATION] = json!("lease-a");
    workload["metadata"]["annotations"][LEADER_EPOCH_ANNOTATION] = json!("3");
    workload["metadata"]["annotations"][HOLDER_IDENTITY_ANNOTATION] = json!("pod-a");
    assert!(workload_term_matches(&workload, &term));
  }

  #[test]
  fn rejection_detection_ignores_selector_colliding_pods_outside_the_owner_chain() {
    let target = RolloutTarget {
      namespace: "default".to_string(),
      kind: WorkloadKind::Deployment,
      name: "edge".to_string(),
      container_name: "oxibelt".to_string(),
      volume_name: "gateway-config".to_string(),
      timeout: Duration::from_secs(300),
      config_map_prefix: "oxibelt-gateway-config".to_string(),
    };
    let workload = json!({
      "metadata": { "uid": "target-deployment-uid" },
      "spec": { "selector": { "matchLabels": { "app": "edge" }}}
    });
    let replica_sets = [json!({
      "metadata": {
        "uid": "target-replica-set-uid",
        "ownerReferences": [{
          "apiVersion": "apps/v1",
          "kind": "Deployment",
          "uid": "target-deployment-uid",
          "controller": true,
        }],
      },
    })];
    let ownership = WorkloadPodOwnership::from_workload(&target, &workload, &replica_sets)
      .expect("target ownership");
    let stale = json!({
      "metadata": {
        "labels": { "app": "edge" },
        "annotations": {
          CONFIG_REVISION_ANNOTATION: "candidate", CONFIG_DIGEST_ANNOTATION: "digest"
        },
        "ownerReferences": [{
          "apiVersion": "apps/v1",
          "kind": "ReplicaSet",
          "uid": "tenant-replica-set-uid",
          "controller": true,
        }],
      },
      "status": { "containerStatuses": [{
        "state": { "waiting": { "reason": "CrashLoopBackOff" } }
      }]}
    });
    assert_eq!(
      rejected_pod_reason(&workload, &ownership, &[stale], "candidate", "digest"),
      None
    );
    let candidate = json!({
      "metadata": {
        "labels": { "app": "edge" },
        "annotations": {
          CONFIG_REVISION_ANNOTATION: "candidate", CONFIG_DIGEST_ANNOTATION: "digest"
        },
        "ownerReferences": [{
          "apiVersion": "apps/v1",
          "kind": "ReplicaSet",
          "uid": "target-replica-set-uid",
          "controller": true,
        }],
      },
      "status": { "containerStatuses": [{
        "state": { "waiting": { "reason": "CrashLoopBackOff" } }
      }]}
    });
    assert_eq!(
      rejected_pod_reason(&workload, &ownership, &[candidate], "candidate", "digest"),
      Some("PodRejected")
    );
  }

  #[test]
  fn failed_candidate_is_not_retried_until_its_revision_changes() {
    let state = RolloutState {
      phase: RolloutPhase::Failed,
      desired_revision: Some("known-good".to_string()),
      desired_artifact_digest: None,
      desired_content_digest: None,
      committed_revision: Some("known-good".to_string()),
      committed_content_digest: None,
      failed_revision: Some("rejected".to_string()),
      started_at_unix: None,
      failure: Some("PodRejected".to_string()),
    };
    assert!(candidate_is_blocked_after_failure(&state, "rejected"));
    assert!(!candidate_is_blocked_after_failure(&state, "changed"));
  }

  #[test]
  fn committed_convergence_is_a_noop() {
    assert_eq!(
      convergence_transition(RolloutPhase::Committed, false),
      RolloutPhase::Committed
    );
    assert_eq!(
      convergence_transition(RolloutPhase::FullyApplied, false),
      RolloutPhase::Committed
    );
  }

  #[test]
  fn committed_state_losing_convergence_is_not_reported_as_programmed() {
    let state = RolloutState {
      phase: RolloutPhase::Committed,
      desired_revision: Some("revision".to_string()),
      desired_artifact_digest: Some("artifact".to_string()),
      desired_content_digest: Some("digest".to_string()),
      committed_revision: Some("revision".to_string()),
      committed_content_digest: Some("digest".to_string()),
      failed_revision: None,
      started_at_unix: Some(1),
      failure: None,
    };

    let status = convergence_lost_status(&state);
    assert!(!status.is_committed());
    assert_eq!(status.reason.as_deref(), Some("ConvergenceLost"));
    assert_eq!(status.desired_revision.as_deref(), Some("revision"));
  }
}
