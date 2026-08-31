use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use oxibelt_control_http::{full_body, uri_from_url};
use serde_json::Value;
use tracing::{info, warn};

use super::cli::SharedArgs;
use super::compatibility::CompatibilityPolicy;
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
  pub async fn preflight_target_compatibility_for(
    &self,
    target: &RolloutTarget,
    compatibility: &CompatibilityPolicy,
  ) -> anyhow::Result<()> {
    let workload = self.get_required_json(&target.workload_path()).await?;
    compatibility
      .validate_target_workload(&workload)
      .context("target workload compatibility preflight failed")
  }

  pub async fn reconcile_immutable_rollout_for(
    &self,
    shared: &SharedArgs,
    target: &RolloutTarget,
    compatibility: &CompatibilityPolicy,
    generated_toml: &str,
    generated_assets: &[super::translate::RenderedAsset],
    client_identities: &[super::upstream_client_tls::ClientIdentityMaterial],
  ) -> anyhow::Result<RolloutStatus> {
    let candidate = ConfigArtifact::new_with_assets_and_client_identities(
      target,
      &shared.managed_config_path,
      generated_toml.to_string(),
      generated_assets
        .iter()
        .map(|asset| super::rollout::ConfigArtifactAsset {
          data_key: asset.data_key.clone(),
          managed_path: asset.managed_path.clone(),
          content: asset.content.clone(),
        })
        .collect(),
      client_identities
        .iter()
        .map(|identity| identity.derived_secret_name.clone())
        .collect(),
    )?;
    let workload = self.get_required_json(&target.workload_path()).await?;
    compatibility
      .validate_target_workload(&workload)
      .context("target workload compatibility preflight failed")?;
    validate_rollout_opt_in(&workload)?;
    self
      .preflight_base_config(target, &workload, &candidate.managed_path)
      .await?;
    for identity in client_identities {
      self.ensure_client_identity_secret(target, identity).await?;
    }
    self.ensure_config_map(target, &candidate).await?;
    let state = RolloutState::from_workload(&workload);

    if state.desired_revision.is_some() {
      let permit = self.authorize_write().await?;
      if !workload_term_matches(&workload, permit.term()) {
        let desired = self.load_desired_artifact(target, &state).await?;
        self
          .apply_state(target, &workload, &desired, &state)
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
      let rollback = self.load_desired_artifact(target, &state).await?;
      let mut failed = state;
      failed.phase = RolloutPhase::Failed;
      self
        .apply_state(target, &workload, &rollback, &failed)
        .await?;
      return Ok(RolloutStatus::from(&failed));
    }

    if candidate_is_blocked_after_failure(&state, &candidate.name) {
      return Ok(RolloutStatus::from(&state));
    }

    if state.desired_revision.as_deref() == Some(candidate.name.as_str()) {
      return self
        .reconcile_active_revision(target, &workload, state, candidate, false)
        .await;
    }

    if state.phase == RolloutPhase::RollbackRequested {
      let rollback = self.load_desired_artifact(target, &state).await?;
      return self
        .reconcile_active_revision(target, &workload, state, rollback, true)
        .await;
    }

    if state.phase != RolloutPhase::Committed
      && state.desired_revision.is_some()
      && state.committed_revision.is_some()
      && state.desired_revision != state.committed_revision
    {
      return self
        .request_rollback(target, &workload, state, "SupersededByNewRevision")
        .await;
    }

    let next = RolloutState::new_attempt(&candidate, &state, now_unix_seconds());
    self
      .apply_state(target, &workload, &candidate, &next)
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
          .advance_converged_state(target, workload, &pods, state, &active, rolling_back)
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
    pods: &[Value],
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
      if let Some(failed_revision) = next.failed_revision.as_deref()
        && let Ok(failed_artifact) = self.load_artifact(target, failed_revision).await
      {
        next.previous_client_identity_secrets = failed_artifact.client_identity_secret_names;
      }
      self.apply_state(target, workload, active, &next).await?;
      return Ok(RolloutStatus::from(&next));
    }
    if next.phase == RolloutPhase::FullyApplied {
      self.apply_state(target, workload, active, &next).await?;
      return Ok(RolloutStatus::from(&next));
    }
    next.phase = RolloutPhase::Committed;
    let retired_client_identity_secrets = next.previous_client_identity_secrets.clone();
    next.previous_client_identity_secrets = next.committed_client_identity_secrets.clone();
    next.committed_client_identity_secrets = active.client_identity_secret_names.clone();
    next.desired_client_identity_secrets = active.client_identity_secret_names.clone();
    next.committed_revision = Some(active.name.clone());
    next.committed_content_digest = Some(active.content_digest.clone());
    next.failure = None;
    self.apply_state(target, workload, active, &next).await?;
    self
      .cleanup_retired_client_identity_secrets(
        target,
        &retired_client_identity_secrets,
        &next,
        workload,
        pods,
      )
      .await;
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

  async fn ensure_client_identity_secret(
    &self,
    target: &RolloutTarget,
    identity: &super::upstream_client_tls::ClientIdentityMaterial,
  ) -> anyhow::Result<()> {
    let path = format!(
      "/api/v1/namespaces/{}/secrets/{}",
      target.namespace, identity.derived_secret_name
    );
    if let Some(existing) = self.get_optional_json(&path).await? {
      if identity.matches_existing(target, &existing) {
        return Ok(());
      }
      bail!("immutable upstream client Secret name collision has different content or ownership");
    }
    let collection = format!("/api/v1/namespaces/{}/secrets", target.namespace);
    let _permit = self.authorize_write().await?;
    let body = serde_json::to_vec(&identity.manifest(target))
      .context("failed to serialize immutable upstream client Secret")?;
    let (status, _) = self
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
        .context("Secret creation conflicted but no existing Secret was readable")?;
      if identity.matches_existing(target, &existing) {
        return Ok(());
      }
      bail!("immutable upstream client Secret name collision has different content or ownership");
    }
    bail!("Kubernetes immutable upstream client Secret create returned {status}");
  }

  async fn cleanup_retired_client_identity_secrets(
    &self,
    target: &RolloutTarget,
    candidates: &[String],
    state: &RolloutState,
    workload: &Value,
    pods: &[Value],
  ) {
    let retained = state
      .desired_client_identity_secrets
      .iter()
      .chain(state.committed_client_identity_secrets.iter())
      .chain(state.previous_client_identity_secrets.iter())
      .collect::<HashSet<_>>();
    let referenced = referenced_client_identity_secrets(workload, pods);
    for name in candidates {
      if retained.contains(name) || referenced.contains(name) {
        continue;
      }
      if let Err(error) = self
        .delete_retired_client_identity_secret(target, name)
        .await
      {
        warn!(
          secret = name,
          error = %error,
          "retained an older derived upstream client Secret after safe cleanup failed"
        );
      }
    }
  }

  async fn delete_retired_client_identity_secret(
    &self,
    target: &RolloutTarget,
    name: &str,
  ) -> anyhow::Result<()> {
    let path = format!("/api/v1/namespaces/{}/secrets/{name}", target.namespace);
    let Some(existing) = self.get_optional_json(&path).await? else {
      return Ok(());
    };
    let uid = retired_client_identity_secret_uid(target, name, &existing)?;
    let _permit = self.authorize_write().await?;
    let body = serde_json::to_vec(&delete_options_with_uid(&uid))?;
    let (status, _) = self
      .request(
        Method::DELETE,
        &path,
        None,
        Some("application/json"),
        Some(body),
      )
      .await?;
    if status.is_success() || status == StatusCode::NOT_FOUND {
      return Ok(());
    }
    bail!("Kubernetes retired upstream client Secret delete returned {status}")
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

fn referenced_client_identity_secrets(workload: &Value, pods: &[Value]) -> HashSet<String> {
  let mut referenced = HashSet::new();
  collect_secret_volume_references(
    workload.pointer("/spec/template/spec/volumes"),
    &mut referenced,
  );
  for pod in pods {
    collect_secret_volume_references(pod.pointer("/spec/volumes"), &mut referenced);
  }
  referenced
}

fn collect_secret_volume_references(volumes: Option<&Value>, referenced: &mut HashSet<String>) {
  for volume in volumes.and_then(Value::as_array).into_iter().flatten() {
    if let Some(name) = volume
      .pointer("/secret/secretName")
      .and_then(Value::as_str)
      .filter(|name| name.starts_with(super::upstream_client_tls::DERIVED_SECRET_PREFIX))
    {
      referenced.insert(name.to_string());
    }
  }
}

fn retired_client_identity_secret_uid(
  target: &RolloutTarget,
  name: &str,
  existing: &Value,
) -> anyhow::Result<String> {
  if !name.starts_with(super::upstream_client_tls::DERIVED_SECRET_PREFIX) {
    bail!("refusing to delete a Secret outside the controller-derived name prefix");
  }
  let metadata = existing
    .get("metadata")
    .context("retired upstream client Secret metadata is required")?;
  if metadata.get("name").and_then(Value::as_str) != Some(name)
    || metadata.get("namespace").and_then(Value::as_str) != Some(target.namespace.as_str())
    || existing.get("immutable").and_then(Value::as_bool) != Some(true)
    || existing.get("type").and_then(Value::as_str) != Some("kubernetes.io/tls")
  {
    bail!("refusing to delete a retired Secret without exact immutable identity");
  }
  let labels = metadata
    .get("labels")
    .context("retired upstream client Secret ownership labels are required")?;
  if labels
    .get(super::rollout::MANAGED_BY_LABEL)
    .and_then(Value::as_str)
    != Some("oxibelt-gateway-controller")
    || labels
      .get(super::rollout::ROLLOUT_TARGET_LABEL)
      .and_then(Value::as_str)
      != Some(target.name.as_str())
    || labels
      .get(super::rollout::ROLLOUT_TARGET_KIND_LABEL)
      .and_then(Value::as_str)
      != Some(target.kind.label_value())
  {
    bail!("refusing to delete a retired Secret without exact controller ownership");
  }
  let annotations = metadata
    .get("annotations")
    .context("retired upstream client Secret source annotations are required")?;
  let source = annotations
    .get(super::upstream_client_tls::DERIVED_SECRET_SOURCE_ANNOTATION)
    .and_then(Value::as_str)
    .context("retired upstream client Secret source identity is required")?;
  let (source_namespace, source_name) = source
    .split_once('/')
    .filter(|(_, name)| !name.contains('/'))
    .context("retired upstream client Secret source identity is invalid")?;
  super::rollout::validate_kubernetes_dns_label("source Secret namespace", source_namespace)?;
  super::rollout::validate_kubernetes_dns_subdomain("source Secret name", source_name)?;
  let source_uid = annotations
    .get(super::upstream_client_tls::DERIVED_SECRET_SOURCE_UID_ANNOTATION)
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
    .context("retired upstream client Secret source UID is required")?;
  let source_resource_version = annotations
    .get(super::upstream_client_tls::DERIVED_SECRET_SOURCE_VERSION_ANNOTATION)
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty())
    .context("retired upstream client Secret source resourceVersion is required")?;
  let data = existing
    .get("data")
    .and_then(Value::as_object)
    .context("retired upstream client Secret data is required")?;
  if data.len() != 2
    || !data.contains_key(super::upstream_client_tls::CERTIFICATE_DATA_KEY)
    || !data.contains_key(super::upstream_client_tls::PRIVATE_KEY_DATA_KEY)
  {
    bail!("refusing to delete a retired Secret with noncanonical data keys");
  }
  let certificate_data = data
    .get(super::upstream_client_tls::CERTIFICATE_DATA_KEY)
    .and_then(Value::as_str)
    .context("retired upstream client Secret certificate data is required")?;
  let certificate_bytes = super::upstream_client_tls::decode_base64_bounded(
    certificate_data,
    super::upstream_client_tls::MAX_CERTIFICATE_BYTES,
  )
  .context("retired upstream client Secret certificate data is invalid")?;
  let expected_name = super::upstream_client_tls::derived_secret_name_for_source(
    source_namespace,
    source_name,
    source_uid,
    source_resource_version,
    &certificate_bytes,
  );
  if expected_name != name {
    bail!("refusing to delete a retired Secret outside its exact source lineage");
  }
  metadata
    .get("uid")
    .and_then(Value::as_str)
    .filter(|uid| !uid.is_empty())
    .map(str::to_string)
    .context("retired upstream client Secret UID is required")
}

fn delete_options_with_uid(uid: &str) -> Value {
  serde_json::json!({
    "apiVersion": "v1",
    "kind": "DeleteOptions",
    "preconditions": { "uid": uid },
  })
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
    target_summary: None,
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
      artifact_context: None,
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
      desired_client_identity_secrets: Vec::new(),
      committed_client_identity_secrets: Vec::new(),
      previous_client_identity_secrets: Vec::new(),
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
      desired_client_identity_secrets: Vec::new(),
      committed_client_identity_secrets: Vec::new(),
      previous_client_identity_secrets: Vec::new(),
    };

    let status = convergence_lost_status(&state);
    assert!(!status.is_committed());
    assert_eq!(status.reason.as_deref(), Some("ConvergenceLost"));
    assert_eq!(status.desired_revision.as_deref(), Some("revision"));
  }

  #[test]
  fn retired_secret_cleanup_requires_exact_lineage_uid_and_no_live_references() {
    let target = RolloutTarget {
      namespace: "default".to_string(),
      kind: WorkloadKind::Deployment,
      name: "edge".to_string(),
      container_name: "oxibelt".to_string(),
      volume_name: "gateway-config".to_string(),
      timeout: Duration::from_secs(300),
      config_map_prefix: "oxibelt-gateway-config".to_string(),
      artifact_context: None,
    };
    let certificate = "c2FtZS1wdWJsaWMtY2VydGlmaWNhdGU=";
    let name = crate::upstream_client_tls::derived_secret_name_for_source(
      "credentials",
      "client.identity",
      "source-uid",
      "17",
      b"same-public-certificate",
    );
    let secret = json!({
      "apiVersion": "v1",
      "kind": "Secret",
      "metadata": {
        "name": name,
        "namespace": "default",
        "uid": "derived-uid",
        "labels": {
          (crate::rollout::MANAGED_BY_LABEL): "oxibelt-gateway-controller",
          (crate::rollout::ROLLOUT_TARGET_LABEL): "edge",
          (crate::rollout::ROLLOUT_TARGET_KIND_LABEL): "deployment",
        },
        "annotations": {
          (crate::upstream_client_tls::DERIVED_SECRET_SOURCE_ANNOTATION): "credentials/client.identity",
          (crate::upstream_client_tls::DERIVED_SECRET_SOURCE_UID_ANNOTATION): "source-uid",
          (crate::upstream_client_tls::DERIVED_SECRET_SOURCE_VERSION_ANNOTATION): "17",
        },
      },
      "immutable": true,
      "type": "kubernetes.io/tls",
      "data": {"tls.crt": certificate, "tls.key": "a2V5"},
    });
    assert_eq!(
      retired_client_identity_secret_uid(&target, &name, &secret).unwrap(),
      "derived-uid"
    );
    assert_eq!(
      delete_options_with_uid("derived-uid")["preconditions"]["uid"],
      "derived-uid"
    );

    let mut wrong_owner = secret.clone();
    wrong_owner["metadata"]["labels"][crate::rollout::ROLLOUT_TARGET_LABEL] = json!("other");
    assert!(retired_client_identity_secret_uid(&target, &name, &wrong_owner).is_err());
    let mut missing_uid = secret.clone();
    missing_uid["metadata"]
      .as_object_mut()
      .unwrap()
      .remove("uid");
    assert!(retired_client_identity_secret_uid(&target, &name, &missing_uid).is_err());

    let workload = json!({
      "spec": {"template": {"spec": {"volumes": [
        {"name": "current", "secret": {"secretName": "oxibelt-upstream-client-current"}}
      ]}}}
    });
    let pods = [json!({
      "metadata": {"deletionTimestamp": "2026-08-31T00:00:00Z"},
      "spec": {"volumes": [
        {"name": "retiring", "secret": {"secretName": name}}
      ]}
    })];
    let referenced = referenced_client_identity_secrets(&workload, &pods);
    assert!(referenced.contains("oxibelt-upstream-client-current"));
    assert!(referenced.contains(&name));
    assert_eq!(
      convergence_transition(RolloutPhase::RollbackRequested, true),
      RolloutPhase::RolledBack,
      "rollback completion retains failed identities for a later proven cleanup"
    );
  }
}
