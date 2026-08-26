//! Candidate construction, atomic installation, and rollback for Admin snapshots.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_secret_reference_activation(
  actor: &str,
  if_match: Option<String>,
  mutation_request_id: String,
  logical_revision: Option<String>,
  expected_reference_set_digest: Option<String>,
  request: SecretReferenceUpdateRequest,
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  rollback: &mut Option<RollbackSnapshot>,
) -> AdminControlResponse {
  if let Err(response) = check_if_match(control, if_match).await {
    return response;
  }
  let active = state.snapshot();
  if active.config.rollout.blocks_per_pod_mutation() {
    return AdminControlResponse {
      status: StatusCode::CONFLICT,
      body: json!({
        "error": "secret reference activation is controlled by immutable rollout",
        "code": "immutable_rollout_conflict",
      }),
    };
  }
  let next_revision = current_revision(control).await.saturating_add(1);
  let logical_revision = logical_revision.unwrap_or_else(|| format!("config-{next_revision}"));
  let target_revision = if active.config.rollout.is_admin_cluster() {
    format!(
      "cluster:{}:{}",
      active.config.admin.mutations.rollout.cluster_id, logical_revision
    )
  } else {
    format!(
      "instance:{}:{}",
      active
        .config
        .rollout
        .instance_id()
        .unwrap_or("single_instance"),
      next_revision
    )
  };
  let assigned_runtime_revision = active
    .config
    .rollout
    .is_admin_cluster()
    .then(|| logical_revision.clone());
  let snapshot = match build_candidate_snapshot(
    active.as_ref(),
    &request,
    mutation_request_id.clone(),
    logical_revision.clone(),
    target_revision.clone(),
    assigned_runtime_revision,
  )
  .await
  {
    Ok(snapshot) => snapshot,
    Err(safe) => {
      active
        .metrics
        .record_secret_reference_activation("rejected");
      warn!(
        event = "oxibelt.admin.audit",
        operation = "secret_reference_activation",
        outcome = "rejected",
        code = safe.code(),
        "secret-reference candidate runtime preflight failed"
      );
      return AdminControlResponse::secret_error(secret_error_status(safe), safe);
    }
  };
  let Some(binding) = snapshot.secret_references.binding().cloned() else {
    return AdminControlResponse::secret_error(
      StatusCode::INTERNAL_SERVER_ERROR,
      SecretActivationError::CandidateInvalid,
    );
  };
  if expected_reference_set_digest
    .as_deref()
    .is_some_and(|expected| expected != binding.reference_set_digest)
  {
    active
      .metrics
      .record_secret_reference_activation("rejected");
    return AdminControlResponse::secret_error(
      StatusCode::CONFLICT,
      SecretActivationError::ValidationEvidenceMismatch,
    );
  }
  if let Err(error) =
    install_snapshot(snapshot, state, listeners, Some(rollback), control, None).await
  {
    active
      .metrics
      .record_secret_reference_activation("rejected");
    let safe = if error.to_string().contains("active snapshot changed") {
      SecretActivationError::ActivationConflict
    } else {
      SecretActivationError::CandidateInvalid
    };
    return AdminControlResponse::secret_error(StatusCode::CONFLICT, safe);
  }
  info!(
    actor,
    mutation_request_id,
    config_logical_revision = logical_revision,
    reference_set_digest = binding.reference_set_digest,
    runtime_snapshot_revision = binding.runtime_snapshot_revision,
    target_revision,
    "secret reference activation applied"
  );
  state
    .snapshot()
    .metrics
    .record_secret_reference_activation("applied");
  record_operation(control, "secret_reference_activation", "applied", None).await;
  AdminControlResponse::ok(json!({
    "ok": true,
    "request_id": binding.mutation_request_id,
    "config_logical_revision": binding.config_logical_revision,
    "reference_set_digest": binding.reference_set_digest,
    "runtime_snapshot_revision": binding.runtime_snapshot_revision,
    "target_revision": binding.target_revision,
  }))
}

const fn secret_error_status(error: SecretActivationError) -> StatusCode {
  match error {
    SecretActivationError::UnsupportedVersion
    | SecretActivationError::FieldNotAllowlisted
    | SecretActivationError::InvalidReference => StatusCode::BAD_REQUEST,
    SecretActivationError::ReferenceUnauthorized => StatusCode::FORBIDDEN,
    SecretActivationError::ProviderUnavailable | SecretActivationError::EntropyUnavailable => {
      StatusCode::SERVICE_UNAVAILABLE
    }
    _ => StatusCode::CONFLICT,
  }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_config_load(
  actor: &str,
  control_plane_permissions: ControlPlaneConfigPermissions,
  if_match: Option<String>,
  raw: String,
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  runtime_overrides: &RuntimeOverrides,
  rollback: &mut Option<RollbackSnapshot>,
) -> AdminControlResponse {
  if let Err(response) = check_if_match(control, if_match).await {
    return response;
  }
  let active = state.snapshot();
  let mut config = match Config::load_admin_inline_toml(&raw, &active.config) {
    Ok(config) => config,
    Err(error) => {
      record_operation(control, "config_load", "rejected", Some(error.to_string())).await;
      return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
    }
  };
  if let Err(response) =
    validate_control_plane_config_scope(control_plane_permissions, &active.config, &config)
  {
    record_operation(
      control,
      "config_load",
      "rejected",
      Some(
        response
          .body
          .get("error")
          .and_then(|value| value.as_str())
          .unwrap_or("admin or IPM configuration changes require additional permissions")
          .to_string(),
      ),
    )
    .await;
    return response;
  }
  for warning in config.apply_runtime_overrides(runtime_overrides) {
    warn!("{warning}");
  }
  if let Err(error) = config.validate() {
    record_operation(control, "config_load", "rejected", Some(error.to_string())).await;
    return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
  }
  if let Err(error) = validate_full_reload_runtime_compatibility(&active.config, &config) {
    record_operation(control, "config_load", "rejected", Some(error.to_string())).await;
    return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
  }
  let activation_config =
    match Config::load_admin_inline_effective_toml_for_activation(&raw, &active.config) {
      Ok(value) => value,
      Err(error) => {
        record_operation(control, "config_load", "rejected", Some(error.to_string())).await;
        return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
      }
    };
  let effective = match Config::load_admin_inline_effective_toml_redacted(&raw, &active.config)
    .and_then(|value| toml::to_string_pretty(&value).map_err(Into::into))
  {
    Ok(value) => Some(
      control
        .effective_config_update(value, &activation_config)
        .await,
    ),
    Err(error) => {
      record_operation(control, "config_load", "rejected", Some(error.to_string())).await;
      return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
    }
  };
  let snapshot = match AppSnapshot::new_with_previous(config, Some(active.as_ref())).await {
    Ok(snapshot) => snapshot,
    Err(error) => {
      record_operation(control, "config_load", "rejected", Some(error.to_string())).await;
      return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
    }
  };
  if let Err(error) = install_snapshot(
    snapshot,
    state,
    listeners,
    Some(rollback),
    control,
    effective,
  )
  .await
  {
    record_operation(control, "config_load", "rejected", Some(error.to_string())).await;
    return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
  }
  info!(actor, "admin config load applied");
  record_operation(control, "config_load", "applied", None).await;
  AdminControlResponse::ok(json!({ "ok": true, "revision": current_revision(control).await }))
}

pub(super) async fn apply_config_rollback(
  actor: &str,
  control_plane_permissions: ControlPlaneConfigPermissions,
  if_match: Option<String>,
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  rollback: &mut Option<RollbackSnapshot>,
) -> AdminControlResponse {
  if let Err(response) = check_if_match(control, if_match).await {
    return response;
  }
  if rollback
    .as_ref()
    .and_then(|snapshot| snapshot.expires_at)
    .is_some_and(|deadline| Instant::now() >= deadline)
  {
    *rollback = None;
    control.state.lock().await.rollback_available = false;
  }
  let Some(previous) = rollback.as_ref() else {
    return AdminControlResponse::error(StatusCode::CONFLICT, "no rollback snapshot is available");
  };
  let current = state.snapshot();
  if let Err(response) = validate_control_plane_config_scope(
    control_plane_permissions,
    &current.config,
    &previous.snapshot.config,
  ) {
    record_operation(
      control,
      "config_rollback",
      "rejected",
      Some(
        response
          .body
          .get("error")
          .and_then(|value| value.as_str())
          .unwrap_or("admin or IPM configuration changes require additional permissions")
          .to_string(),
      ),
    )
    .await;
    return response;
  }
  let Some(previous) = rollback.take() else {
    return AdminControlResponse::error(
      StatusCode::CONFLICT,
      "rollback snapshot became unavailable",
    );
  };
  let current_effective = control.state.lock().await.effective_config.clone();
  let secret_rollback = previous.secret_runtime_revision.is_some();
  let pending = match listeners.prepare(&previous.snapshot).await {
    Ok(pending) => pending,
    Err(error) => {
      *rollback = Some(previous);
      if secret_rollback {
        record_operation(
          control,
          "config_rollback",
          "rejected",
          Some(SecretActivationError::RollbackFailed.code().to_string()),
        )
        .await;
        return AdminControlResponse::secret_error(
          StatusCode::CONFLICT,
          SecretActivationError::RollbackFailed,
        );
      }
      record_operation(
        control,
        "config_rollback",
        "rejected",
        Some(error.to_string()),
      )
      .await;
      return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
    }
  };
  let restored_secret_digest = previous
    .snapshot
    .secret_references
    .reference_set_digest()
    .to_string();
  if !state.replace_if_current(&current, previous.snapshot.clone()) {
    *rollback = Some(previous);
    return AdminControlResponse::secret_error(
      StatusCode::CONFLICT,
      SecretActivationError::ActivationConflict,
    );
  }
  let active = state.snapshot();
  listeners.commit(pending, active.as_ref(), state.clone());
  let secret_changed = current.secret_references.reference_set_digest() != restored_secret_digest;
  if secret_changed {
    active
      .metrics
      .record_secret_reference_activation("rollback");
  }
  let (secret_runtime_revision, expires_at) =
    rollback_retirement_metadata(active.as_ref(), secret_changed);
  *rollback = Some(RollbackSnapshot {
    snapshot: current.as_ref().clone(),
    effective_config: current_effective,
    secret_runtime_revision: secret_runtime_revision.clone(),
    expires_at,
  });
  if let Some(runtime_revision) = secret_runtime_revision {
    control
      .schedule_secret_rollback_expiry(runtime_revision, secret_retirement_grace(active.as_ref()));
  }
  control.state.lock().await.rollback_available = true;
  advance_revision(control, previous.effective_config).await;
  info!(actor, "admin config rollback applied");
  record_operation(control, "config_rollback", "applied", None).await;
  AdminControlResponse::ok(json!({ "ok": true, "revision": current_revision(control).await }))
}

pub(super) async fn apply_downstream_tls_reload(
  actor: &str,
  if_match: Option<String>,
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  rollback: &mut Option<RollbackSnapshot>,
) -> AdminControlResponse {
  if let Err(response) = check_if_match(control, if_match).await {
    return response;
  }
  let active = state.snapshot();
  let mut config = active.config.clone();
  if let Err(error) = reload_downstream_tls_paths(&mut config) {
    record_operation(
      control,
      "tls_downstream_reload",
      "rejected",
      Some(error.to_string()),
    )
    .await;
    return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
  }
  let hardening = match active.admitted_reload_hardening(&config) {
    Ok(hardening) => hardening,
    Err(error) => {
      record_operation(
        control,
        "tls_downstream_reload",
        "rejected",
        Some(error.to_string()),
      )
      .await;
      return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
    }
  };
  let (crlite, downstream_ct, ocsp_staple, tls_server_config, quic_server_config) =
    match tls_reload::build_downstream_tls_reload_configs(&config, active.as_ref()).await {
      Ok(configs) => configs,
      Err(error) => {
        record_operation(
          control,
          "tls_downstream_reload",
          "rejected",
          Some(error.to_string()),
        )
        .await;
        return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
      }
    };
  let mut snapshot = active.as_ref().clone();
  snapshot.config = config;
  snapshot.hardening = hardening;
  snapshot.crlite = crlite;
  snapshot.downstream_ct = downstream_ct;
  snapshot.ocsp_staple = ocsp_staple;
  snapshot.tls_server_config = tls_server_config;
  snapshot.quic_server_config = quic_server_config;
  if let Err(error) =
    install_snapshot(snapshot, state, listeners, Some(rollback), control, None).await
  {
    record_operation(
      control,
      "tls_downstream_reload",
      "rejected",
      Some(error.to_string()),
    )
    .await;
    return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
  }
  info!(actor, "admin downstream TLS reload applied");
  record_operation(control, "tls_downstream_reload", "applied", None).await;
  AdminControlResponse::ok(json!({ "ok": true, "revision": current_revision(control).await }))
}

pub(super) async fn install_snapshot(
  snapshot: AppSnapshot,
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  rollback: Option<&mut Option<RollbackSnapshot>>,
  control: &AdminControlHandle,
  effective_config: Option<AdminEffectiveConfig>,
) -> anyhow::Result<()> {
  let active = state.snapshot();
  let pending = listeners.prepare(&snapshot).await?;
  let previous_effective = control.state.lock().await.effective_config.clone();
  let secret_changed = active.secret_references.reference_set_digest()
    != snapshot.secret_references.reference_set_digest();
  if !state.replace_if_current(&active, snapshot) {
    bail!("active snapshot changed during candidate installation");
  }
  let installed = state.snapshot();
  listeners.commit(pending, installed.as_ref(), state.clone());
  if let Some(rollback) = rollback {
    let (secret_runtime_revision, expires_at) =
      rollback_retirement_metadata(installed.as_ref(), secret_changed);
    *rollback = Some(RollbackSnapshot {
      snapshot: active.as_ref().clone(),
      effective_config: previous_effective,
      secret_runtime_revision: secret_runtime_revision.clone(),
      expires_at,
    });
    control.state.lock().await.rollback_available = true;
    if let Some(runtime_revision) = secret_runtime_revision {
      control.schedule_secret_rollback_expiry(
        runtime_revision,
        secret_retirement_grace(installed.as_ref()),
      );
    }
  }
  advance_revision(control, effective_config).await;
  Ok(())
}

pub(super) fn rollback_retirement_metadata(
  installed: &AppSnapshot,
  secret_changed: bool,
) -> (Option<String>, Option<Instant>) {
  if !secret_changed {
    return (None, None);
  }
  let runtime_revision = installed
    .secret_references
    .binding()
    .map(|binding| binding.runtime_snapshot_revision.clone())
    .unwrap_or_else(|| {
      format!(
        "unbound:{}",
        installed.secret_references.reference_set_digest()
      )
    });
  let grace = secret_retirement_grace(installed);
  (Some(runtime_revision), Instant::now().checked_add(grace))
}

pub(super) fn secret_retirement_grace(snapshot: &AppSnapshot) -> Duration {
  let drain_ms = snapshot
    .config
    .runtime
    .drain
    .graceful_timeout_ms
    .max(snapshot.config.runtime.drain.long_connection_close_delay_ms);
  let mut grace = Duration::from_millis(drain_ms);
  if snapshot.config.admin.mutations.rollout.mode.is_cluster() {
    let rollout = &snapshot.config.admin.mutations.rollout;
    let rollout_seconds = rollout
      .phase_timeout_seconds
      .saturating_mul(4)
      .saturating_add(rollout.rollback_timeout_seconds)
      .saturating_add(rollout.stale_after_seconds);
    grace = grace.max(Duration::from_secs(rollout_seconds));
  }
  grace
}
