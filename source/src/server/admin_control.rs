use std::sync::Arc;
use std::time::{Duration, Instant};

use ::http::StatusCode;
use anyhow::{anyhow, bail};
use serde::Serialize;
use serde_json::json;
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{info, warn};

use crate::activation_plan::{
  ConfigActivationReport, ConfigComparisonKey, ConfigComparisonProjection, PlanningBasis,
  plan_config_projections,
};
use crate::config::{Config, RuntimeOverrides};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::fast_path::build_compiled_fast_path_actions;
use crate::proxy::http::response::text_response;
use crate::reload::{reload_downstream_tls_paths, validate_full_reload_runtime_compatibility};
use crate::routes::RouteTable;
use crate::secret_activation::{
  SecretActivationError, SecretReferenceUpdateRequest, build_candidate_snapshot,
};
use crate::state::{AppHandle, AppSnapshot, RequestPathFeaturePlan};
use crate::waf::WafEngine;

use super::{ListenerSupervisor, admin::json_response, admin_auth::AdminAuthorization};

pub(crate) mod checkpoint;
pub(super) mod file_sync;
mod load_scope;
mod request;
mod snapshot_mutation;
#[cfg(test)]
mod tests;
mod tls_reload;

pub(super) use load_scope::{ControlPlaneConfigPermissions, validate_control_plane_config_scope};
pub(super) use request::{
  AdminApplyMode, AdminConfigPayload, AdminControlCommand, AdminFileOperation,
  AdminFileOperationKind, AdminFileRoot, AdminFilesSyncRequest,
};
use snapshot_mutation::{
  apply_config_load, apply_config_rollback, apply_downstream_tls_reload,
  apply_secret_reference_activation, install_snapshot,
};

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_decode_mutation_body(selector: u8, data: &[u8]) {
  request::fuzz_decode_mutation_body(selector, data);
}

pub(super) const ADMIN_CONFIG_BODY_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
pub(super) struct AdminControlHandle {
  sender: mpsc::UnboundedSender<AdminControlCommand>,
  state: Arc<Mutex<AdminControlState>>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct AdminOperationStatus {
  operation: String,
  outcome: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  message: Option<String>,
}

struct AdminControlState {
  revision: u64,
  effective_config: Option<AdminEffectiveConfig>,
  comparison_key: ConfigComparisonKey,
  last_operation: Option<AdminOperationStatus>,
  rollback_available: bool,
}

#[derive(Clone)]
pub(super) struct AdminEffectiveConfig {
  rendered: String,
  comparison: ConfigComparisonProjection,
}

#[derive(Clone)]
pub(super) struct RollbackSnapshot {
  snapshot: AppSnapshot,
  effective_config: Option<AdminEffectiveConfig>,
  secret_runtime_revision: Option<String>,
  expires_at: Option<Instant>,
}

#[derive(Debug)]
pub(super) struct AdminControlResponse {
  pub(super) status: StatusCode,
  pub(super) body: serde_json::Value,
}

impl AdminControlHandle {
  pub(super) fn new(
    effective_config: Option<String>,
    activation_config: Option<&toml::Value>,
  ) -> anyhow::Result<(Self, mpsc::UnboundedReceiver<AdminControlCommand>)> {
    let (sender, receiver) = mpsc::unbounded_channel();
    let comparison_key = ConfigComparisonKey::generate()?;
    let effective_config = effective_config
      .zip(activation_config)
      .map(|(rendered, value)| AdminEffectiveConfig {
        rendered,
        comparison: ConfigComparisonProjection::from_value(value, &comparison_key),
      });
    let state = Arc::new(Mutex::new(AdminControlState {
      revision: 1,
      effective_config,
      comparison_key,
      last_operation: None,
      rollback_available: false,
    }));
    Ok((Self { sender, state }, receiver))
  }

  pub(super) async fn status(&self) -> serde_json::Value {
    let state = self.state.lock().await;
    json!({
      "revision": state.revision,
      "etag": etag_for_revision(state.revision),
      "runtime_only": true,
      "rollback_available": state.rollback_available,
      "last_operation": state.last_operation,
    })
  }

  pub(super) async fn effective_config(&self) -> Option<(u64, String, String)> {
    let state = self.state.lock().await;
    state.effective_config.as_ref().map(|config| {
      (
        state.revision,
        etag_for_revision(state.revision),
        config.rendered.clone(),
      )
    })
  }

  pub(super) async fn activation_plan(
    &self,
    candidate: &toml::Value,
  ) -> Option<ConfigActivationReport> {
    let state = self.state.lock().await;
    let current = &state.effective_config.as_ref()?.comparison;
    let candidate = ConfigComparisonProjection::from_value(candidate, &state.comparison_key);
    Some(plan_config_projections(
      current,
      &candidate,
      PlanningBasis::OnlineActive,
    ))
  }

  pub(super) async fn effective_config_update(
    &self,
    rendered: String,
    activation_config: &toml::Value,
  ) -> AdminEffectiveConfig {
    let state = self.state.lock().await;
    AdminEffectiveConfig {
      rendered,
      comparison: ConfigComparisonProjection::from_value(activation_config, &state.comparison_key),
    }
  }

  pub(super) async fn load_config(
    &self,
    actor: String,
    control_plane_permissions: ControlPlaneConfigPermissions,
    if_match: Option<String>,
    raw: String,
  ) -> AdminControlResponse {
    self
      .request(|respond| AdminControlCommand::LoadConfig {
        actor,
        control_plane_permissions,
        if_match,
        raw,
        respond,
      })
      .await
  }

  pub(super) async fn rollback_config(
    &self,
    actor: String,
    control_plane_permissions: ControlPlaneConfigPermissions,
    if_match: Option<String>,
  ) -> AdminControlResponse {
    self
      .request(|respond| AdminControlCommand::RollbackConfig {
        actor,
        control_plane_permissions,
        if_match,
        respond,
      })
      .await
  }

  pub(super) async fn reload_downstream_tls(
    &self,
    actor: String,
    if_match: Option<String>,
  ) -> AdminControlResponse {
    self
      .request(|respond| AdminControlCommand::ReloadDownstreamTls {
        actor,
        if_match,
        respond,
      })
      .await
  }

  pub(super) async fn activate_secret_reference(
    &self,
    actor: String,
    if_match: Option<String>,
    mutation_request_id: String,
    logical_revision: Option<String>,
    expected_reference_set_digest: Option<String>,
    request: SecretReferenceUpdateRequest,
  ) -> AdminControlResponse {
    self
      .request(|respond| AdminControlCommand::ActivateSecretReference {
        actor,
        if_match,
        mutation_request_id,
        logical_revision,
        expected_reference_set_digest,
        request,
        respond,
      })
      .await
  }

  pub(super) async fn sync_files(
    &self,
    actor: String,
    control_plane_permissions: ControlPlaneConfigPermissions,
    if_match: Option<String>,
    request: AdminFilesSyncRequest,
  ) -> AdminControlResponse {
    self
      .request(|respond| AdminControlCommand::SyncFiles {
        actor,
        control_plane_permissions,
        if_match,
        request,
        respond,
      })
      .await
  }

  async fn request(
    &self,
    build: impl FnOnce(oneshot::Sender<AdminControlResponse>) -> AdminControlCommand,
  ) -> AdminControlResponse {
    let (respond, receiver) = oneshot::channel();
    if self.sender.send(build(respond)).is_err() {
      return AdminControlResponse::error(
        StatusCode::SERVICE_UNAVAILABLE,
        "admin control channel is unavailable",
      );
    }
    receiver.await.unwrap_or_else(|_| {
      AdminControlResponse::error(
        StatusCode::SERVICE_UNAVAILABLE,
        "admin control operation was cancelled",
      )
    })
  }

  fn schedule_secret_rollback_expiry(&self, runtime_snapshot_revision: String, grace: Duration) {
    let sender = self.sender.clone();
    tokio::spawn(async move {
      tokio::time::sleep(grace).await;
      let _ = sender.send(AdminControlCommand::ExpireSecretRollback {
        runtime_snapshot_revision,
      });
    });
  }
}

impl AdminControlResponse {
  fn ok(body: serde_json::Value) -> Self {
    Self {
      status: StatusCode::OK,
      body,
    }
  }

  fn error(status: StatusCode, message: impl Into<String>) -> Self {
    Self {
      status,
      body: json!({ "error": message.into() }),
    }
  }

  fn error_with_details(
    status: StatusCode,
    message: impl Into<String>,
    details: serde_json::Value,
  ) -> Self {
    Self {
      status,
      body: json!({ "error": message.into(), "details": details }),
    }
  }

  fn secret_error(status: StatusCode, error: SecretActivationError) -> Self {
    Self {
      status,
      body: json!({
        "error": "secret reference activation failed",
        "code": error.code(),
      }),
    }
  }

  pub(super) fn into_http(self) -> ::http::Response<ProxyBody> {
    json_response(self.status, &self.body)
  }
}

pub(super) fn control_plane_config_permissions(
  authorization: &AdminAuthorization<'_>,
) -> ControlPlaneConfigPermissions {
  ControlPlaneConfigPermissions {
    admin_update_config: authorization.is_allowed("admin:UpdateConfig", "config"),
    ipm_update_config: authorization.is_allowed("ipm:UpdateConfig", "config"),
  }
}

pub(super) async fn handle_admin_control_command(
  command: AdminControlCommand,
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  runtime_overrides: &RuntimeOverrides,
  rollback: &mut Option<RollbackSnapshot>,
) {
  match command {
    AdminControlCommand::LoadConfig {
      actor,
      control_plane_permissions,
      if_match,
      raw,
      respond,
    } => {
      let response = apply_config_load(
        &actor,
        control_plane_permissions,
        if_match,
        raw,
        state,
        listeners,
        control,
        runtime_overrides,
        rollback,
      )
      .await;
      let _ = respond.send(response);
    }
    AdminControlCommand::RollbackConfig {
      actor,
      control_plane_permissions,
      if_match,
      respond,
    } => {
      let response = apply_config_rollback(
        &actor,
        control_plane_permissions,
        if_match,
        state,
        listeners,
        control,
        rollback,
      )
      .await;
      let _ = respond.send(response);
    }
    AdminControlCommand::ReloadDownstreamTls {
      actor,
      if_match,
      respond,
    } => {
      let response =
        apply_downstream_tls_reload(&actor, if_match, state, listeners, control, rollback).await;
      let _ = respond.send(response);
    }
    AdminControlCommand::ActivateSecretReference {
      actor,
      if_match,
      mutation_request_id,
      logical_revision,
      expected_reference_set_digest,
      request,
      respond,
    } => {
      let response = apply_secret_reference_activation(
        &actor,
        if_match,
        mutation_request_id,
        logical_revision,
        expected_reference_set_digest,
        request,
        state,
        listeners,
        control,
        rollback,
      )
      .await;
      let _ = respond.send(response);
    }
    AdminControlCommand::ExpireSecretRollback {
      runtime_snapshot_revision,
    } => {
      if expire_secret_rollback_if_due(rollback, &runtime_snapshot_revision, Instant::now()) {
        control.state.lock().await.rollback_available = false;
        info!(
          runtime_snapshot_revision,
          "retired secret-reference rollback snapshot"
        );
      }
    }
    AdminControlCommand::SyncFiles {
      actor,
      control_plane_permissions,
      if_match,
      request,
      respond,
    } => {
      let response = file_sync::apply_file_sync(
        &actor,
        control_plane_permissions,
        if_match,
        request,
        state,
        listeners,
        control,
        runtime_overrides,
        rollback,
      )
      .await;
      let _ = respond.send(response);
    }
  }
}

fn expire_secret_rollback_if_due(
  rollback: &mut Option<RollbackSnapshot>,
  runtime_snapshot_revision: &str,
  now: Instant,
) -> bool {
  let due = rollback.as_ref().is_some_and(|snapshot| {
    snapshot.secret_runtime_revision.as_deref() == Some(runtime_snapshot_revision)
      && snapshot.expires_at.is_some_and(|deadline| now >= deadline)
  });
  if due {
    *rollback = None;
  }
  due
}

async fn apply_full_from_files(
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  runtime_overrides: &RuntimeOverrides,
  rollback: &mut Option<RollbackSnapshot>,
) -> anyhow::Result<()> {
  let active = state.snapshot();
  let config_entry = active
    .config
    .source_paths
    .config_entry
    .as_ref()
    .ok_or_else(|| anyhow!("active configuration does not have a config entry"))?;
  let mut config = Config::load(config_entry)?;
  for warning in config.apply_runtime_overrides(runtime_overrides) {
    warn!("{warning}");
  }
  config.validate()?;
  validate_full_reload_runtime_compatibility(&active.config, &config)?;
  let effective = Some(load_effective_config_update(control, config_entry).await?);
  let snapshot = AppSnapshot::new_with_previous(config, Some(active.as_ref())).await?;
  install_snapshot(
    snapshot,
    state,
    listeners,
    Some(rollback),
    control,
    effective,
  )
  .await
}

async fn apply_oxirule_from_files(
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  runtime_overrides: &RuntimeOverrides,
  rollback: &mut Option<RollbackSnapshot>,
) -> anyhow::Result<()> {
  let active = state.snapshot();
  let config_entry = active
    .config
    .source_paths
    .config_entry
    .as_ref()
    .ok_or_else(|| anyhow!("active configuration does not have a config entry"))?;
  let mut config = Config::load(config_entry)?;
  for warning in config.apply_runtime_overrides(runtime_overrides) {
    warn!("{warning}");
  }
  config.validate()?;
  if !active.config.non_waf_equivalent(&config) {
    bail!("OxiRule reload rejected because non-WAF OxiBelt configuration changed");
  }
  if active.config.waf_equivalent(&config) {
    return Ok(());
  }
  let hardening = active.admitted_reload_hardening(&config)?;
  let waf = WafEngine::new_with_previous_limits_and_mitigation(
    &config,
    Some(&active.waf),
    active.shared_state.clone(),
    Some(active.limits.clone()),
    active.mitigation.clone(),
  )?;
  let snapshot = build_oxirule_reload_snapshot(active.as_ref(), config, waf);
  let mut snapshot = snapshot;
  snapshot.hardening = hardening;
  let effective = Some(load_effective_config_update(control, config_entry).await?);
  install_snapshot(
    snapshot,
    state,
    listeners,
    Some(rollback),
    control,
    effective,
  )
  .await
}

async fn load_effective_config_update(
  control: &AdminControlHandle,
  config_entry: &std::path::Path,
) -> anyhow::Result<AdminEffectiveConfig> {
  let activation = Config::load_effective_toml_for_activation(config_entry)?;
  let rendered = toml::to_string_pretty(&Config::redact_effective_toml_value(&activation))?;
  Ok(control.effective_config_update(rendered, &activation).await)
}

fn build_oxirule_reload_snapshot(
  active: &AppSnapshot,
  config: Config,
  waf: WafEngine,
) -> AppSnapshot {
  let route_table = RouteTable::new_with_waf(&config, &waf);
  let request_path_features = RequestPathFeaturePlan::new(
    &config,
    active.cache.enabled(),
    active.dynamic_policy.enabled(),
    active.telemetry.enabled(),
    active.system_access_log.enabled(),
    waf.has_person_proof_api_paths(),
  );
  let mut snapshot = active.clone();
  snapshot.config = config;
  snapshot.compiled_fast_path_actions = build_compiled_fast_path_actions(
    &snapshot.config,
    &route_table,
    &snapshot.upstreams,
    &snapshot.upstream_uri_parts_by_index,
  );
  snapshot.route_table = route_table;
  snapshot.waf = waf;
  snapshot.request_path_features = request_path_features;
  snapshot
}

async fn check_if_match(
  control: &AdminControlHandle,
  if_match: Option<String>,
) -> Result<(), AdminControlResponse> {
  let state = control.state.lock().await;
  let expected = etag_for_revision(state.revision);
  match if_match {
    Some(value) if value == expected => Ok(()),
    Some(_) => Err(AdminControlResponse::error_with_details(
      StatusCode::PRECONDITION_FAILED,
      "If-Match does not match the active config revision",
      json!({ "header": "If-Match", "expected": expected }),
    )),
    None => Err(AdminControlResponse::error_with_details(
      StatusCode::PRECONDITION_REQUIRED,
      "If-Match is required",
      json!({ "header": "If-Match", "expected": expected }),
    )),
  }
}

async fn advance_revision(
  control: &AdminControlHandle,
  effective_config: Option<AdminEffectiveConfig>,
) {
  let mut state = control.state.lock().await;
  state.revision += 1;
  if effective_config.is_some() {
    state.effective_config = effective_config;
  }
}

async fn current_revision(control: &AdminControlHandle) -> u64 {
  control.state.lock().await.revision
}

async fn record_operation(
  control: &AdminControlHandle,
  operation: &str,
  outcome: &str,
  message: Option<String>,
) {
  if let Some(error) = message.as_deref() {
    warn!(
      event = "oxibelt.admin.audit",
      operation, outcome, error, "admin operation audit"
    );
  } else {
    info!(
      event = "oxibelt.admin.audit",
      operation, outcome, "admin operation audit"
    );
  }
  let mut state = control.state.lock().await;
  state.last_operation = Some(AdminOperationStatus {
    operation: operation.to_string(),
    outcome: outcome.to_string(),
    message,
  });
}

pub(super) fn etag_for_revision(revision: u64) -> String {
  format!("\"oxibelt-config-{revision}\"")
}

pub(super) fn validate_config_payload(
  payload: &AdminConfigPayload,
) -> Option<::http::Response<ProxyBody>> {
  if payload.format != "toml" {
    return Some(text_response(
      StatusCode::BAD_REQUEST,
      "format must be toml",
    ));
  }
  if payload.config.len() > ADMIN_CONFIG_BODY_LIMIT {
    return Some(text_response(
      StatusCode::PAYLOAD_TOO_LARGE,
      "config payload is too large",
    ));
  }
  None
}

pub(super) fn validate_file_sync_payload(
  payload: &AdminFilesSyncRequest,
) -> Option<::http::Response<ProxyBody>> {
  file_sync::validate_file_sync_payload(payload)
}
