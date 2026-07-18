use std::sync::Arc;

use ::http::StatusCode;
use anyhow::{anyhow, bail};
use serde::Serialize;
use serde_json::json;
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{info, warn};

use crate::config::{Config, RuntimeOverrides};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::fast_path::build_compiled_fast_path_actions;
use crate::proxy::http::response::text_response;
use crate::reload::{reload_downstream_tls_paths, validate_full_reload_runtime_compatibility};
use crate::routes::RouteTable;
use crate::state::{AppHandle, AppSnapshot, RequestPathFeaturePlan};
use crate::waf::WafEngine;

use super::{ListenerSupervisor, admin::json_response, admin_auth::AdminAuthorization};

pub(crate) mod checkpoint;
pub(super) mod file_sync;
mod load_scope;
mod request;
#[cfg(test)]
mod tests;
mod tls_reload;

pub(super) use load_scope::{ControlPlaneConfigPermissions, validate_control_plane_config_scope};
pub(super) use request::{
  AdminApplyMode, AdminConfigPayload, AdminControlCommand, AdminFileOperation,
  AdminFileOperationKind, AdminFileRoot, AdminFilesSyncRequest,
};

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

#[derive(Debug)]
struct AdminControlState {
  revision: u64,
  effective_config: Option<String>,
  last_operation: Option<AdminOperationStatus>,
  rollback_available: bool,
}

#[derive(Clone)]
pub(super) struct RollbackSnapshot {
  snapshot: AppSnapshot,
  effective_config: Option<String>,
}

#[derive(Debug)]
pub(super) struct AdminControlResponse {
  pub(super) status: StatusCode,
  pub(super) body: serde_json::Value,
}

impl AdminControlHandle {
  pub(super) fn new(
    effective_config: Option<String>,
  ) -> (Self, mpsc::UnboundedReceiver<AdminControlCommand>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let state = Arc::new(Mutex::new(AdminControlState {
      revision: 1,
      effective_config,
      last_operation: None,
      rollback_available: false,
    }));
    (Self { sender, state }, receiver)
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
    state
      .effective_config
      .clone()
      .map(|config| (state.revision, etag_for_revision(state.revision), config))
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

#[allow(clippy::too_many_arguments)]
async fn apply_config_load(
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
  let effective = match Config::load_admin_inline_effective_toml_redacted(&raw, &active.config)
    .and_then(|value| toml::to_string_pretty(&value).map_err(Into::into))
  {
    Ok(value) => Some(value),
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

async fn apply_config_rollback(
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
  let Some(previous) = rollback.as_ref() else {
    return AdminControlResponse::error(StatusCode::CONFLICT, "no rollback snapshot is available");
  };
  let current = state.snapshot().as_ref().clone();
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
  let pending = match listeners.prepare(&previous.snapshot).await {
    Ok(pending) => pending,
    Err(error) => {
      *rollback = Some(previous);
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
  state.replace(previous.snapshot);
  let active = state.snapshot();
  listeners.commit(pending, active.as_ref(), state.clone());
  *rollback = Some(RollbackSnapshot {
    snapshot: current,
    effective_config: current_effective,
  });
  control.state.lock().await.rollback_available = true;
  advance_revision(control, previous.effective_config).await;
  info!(actor, "admin config rollback applied");
  record_operation(control, "config_rollback", "applied", None).await;
  AdminControlResponse::ok(json!({ "ok": true, "revision": current_revision(control).await }))
}

async fn apply_downstream_tls_reload(
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
  let (crlite, ocsp_staple, tls_server_config, quic_server_config) =
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
  snapshot.crlite = crlite;
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
  let effective = Config::load_effective_toml_redacted(config_entry)
    .and_then(|value| toml::to_string_pretty(&value).map_err(Into::into))
    .ok();
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
  let waf = WafEngine::new_with_previous_limits_and_mitigation(
    &config,
    Some(&active.waf),
    active.shared_state.clone(),
    Some(active.limits.clone()),
    active.mitigation.clone(),
  )?;
  let snapshot = build_oxirule_reload_snapshot(active.as_ref(), config, waf);
  install_snapshot(snapshot, state, listeners, Some(rollback), control, None).await
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

async fn install_snapshot(
  snapshot: AppSnapshot,
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  rollback: Option<&mut Option<RollbackSnapshot>>,
  control: &AdminControlHandle,
  effective_config: Option<String>,
) -> anyhow::Result<()> {
  let active = state.snapshot();
  let pending = listeners.prepare(&snapshot).await?;
  let previous_effective = control.state.lock().await.effective_config.clone();
  if let Some(rollback) = rollback {
    *rollback = Some(RollbackSnapshot {
      snapshot: active.as_ref().clone(),
      effective_config: previous_effective,
    });
    control.state.lock().await.rollback_available = true;
  }
  state.replace(snapshot);
  let active = state.snapshot();
  listeners.commit(pending, active.as_ref(), state.clone());
  advance_revision(control, effective_config).await;
  Ok(())
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

async fn advance_revision(control: &AdminControlHandle, effective_config: Option<String>) {
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
