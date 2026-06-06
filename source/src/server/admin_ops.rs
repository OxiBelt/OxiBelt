//! Admin operation endpoint dispatch.
//! Long-running operations are tracked separately from request/response lifetimes.

use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde_json::json;
use tracing::warn;

use crate::config::Config;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::{AppHandle, AppSnapshot};

use super::admin_auth::{AdminActor, AdminAuthorization};
use super::{admin, admin_body::collect_admin_json, admin_control, file_sync_path};

mod oxirule_devtools;
pub(in crate::server) use oxirule_devtools::{
  OXIRULE_REPLAY_BODY_LIMIT, admin_waf_devtools_response, enqueue_oxirule_replay_operation,
};
#[cfg(test)]
pub(super) use oxirule_devtools::{authorize_oxirule_active_context, authorize_oxirule_check};

#[cfg(test)]
mod tests;

pub(super) fn admin_waf_response(
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path != "/admin/v1/waf/rule-hits"
    && path != "/admin/v1/waf/rule-costs"
    && path != "/admin/v1/waf/crs/compatibility"
    && path != "/admin/v1/waf/rulepacks"
  {
    return None;
  }
  if *method != ::http::Method::GET {
    return Some(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "method not allowed",
    ));
  }
  let action = match path {
    "/admin/v1/waf/rule-hits" => "waf:GetRuleHits",
    "/admin/v1/waf/rule-costs" => "waf:GetRuleCosts",
    "/admin/v1/waf/crs/compatibility" => "waf:GetCrsCompatibility",
    "/admin/v1/waf/rulepacks" => "waf:ListOxiRulePacks",
    _ => return None,
  };
  if !authorization.is_allowed(action, "*") {
    return Some(permission_denied(authorization.actor, action));
  }
  match path {
    "/admin/v1/waf/rule-hits" => Some(admin::json_response(
      StatusCode::OK,
      &json!({ "rules": snapshot.waf.rule_hit_snapshots() }),
    )),
    "/admin/v1/waf/rule-costs" => Some(admin::json_response(
      StatusCode::OK,
      &json!({ "rules": snapshot.waf.rule_cost_snapshots() }),
    )),
    "/admin/v1/waf/crs/compatibility" => Some(admin::json_response(
      StatusCode::OK,
      &crate::waf::crs_compatibility_matrix(),
    )),
    "/admin/v1/waf/rulepacks" => Some(admin::json_response(
      StatusCode::OK,
      &json!({ "rulepacks": super::admin_rulepacks::active_rulepack_summaries(&snapshot.config) }),
    )),
    _ => None,
  }
}

pub(super) fn admin_lifecycle_response(
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  match path {
    "/admin/v1/lifecycle" => {
      if !authorization.is_allowed("lifecycle:Get", "*") {
        return Some(permission_denied(authorization.actor, "lifecycle:Get"));
      }
      if *method != ::http::Method::GET {
        return Some(text_response(
          StatusCode::METHOD_NOT_ALLOWED,
          "method not allowed",
        ));
      }
      Some(admin::json_response(
        StatusCode::OK,
        &json!({
          "draining": snapshot.lifecycle.is_draining(),
          "reason": snapshot.lifecycle.reason(),
        }),
      ))
    }
    "/admin/v1/lifecycle/drain" => {
      if !authorization.is_allowed("lifecycle:Drain", "*") {
        return Some(permission_denied(authorization.actor, "lifecycle:Drain"));
      }
      if *method != ::http::Method::POST {
        return Some(text_response(
          StatusCode::METHOD_NOT_ALLOWED,
          "method not allowed",
        ));
      }
      snapshot.lifecycle.set_admin_draining();
      Some(admin::json_response(StatusCode::OK, &json!({ "ok": true })))
    }
    "/admin/v1/lifecycle/undrain" => {
      if !authorization.is_allowed("lifecycle:Undrain", "*") {
        return Some(permission_denied(authorization.actor, "lifecycle:Undrain"));
      }
      if *method != ::http::Method::POST {
        return Some(text_response(
          StatusCode::METHOD_NOT_ALLOWED,
          "method not allowed",
        ));
      }
      snapshot.lifecycle.clear_admin_draining();
      Some(admin::json_response(StatusCode::OK, &json!({ "ok": true })))
    }
    _ => None,
  }
}

pub(super) async fn admin_config_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  admin_control: admin_control::AdminControlHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Response<ProxyBody> {
  match (method, path) {
    (&::http::Method::GET, "/admin/v1/config/status") => {
      if !authorization.is_allowed("config:GetStatus", "*") {
        return permission_denied(authorization.actor, "config:GetStatus");
      }
      admin::json_response(StatusCode::OK, &admin_control.status().await)
    }
    (&::http::Method::GET, "/admin/v1/config/effective") => {
      if !authorization.is_allowed("config:GetEffective", "*") {
        return permission_denied(authorization.actor, "config:GetEffective");
      }
      match admin_control.effective_config().await {
        Some((revision, etag, config)) => admin::json_response(
          StatusCode::OK,
          &json!({
            "format": "toml",
            "revision": revision,
            "etag": etag,
            "config": config,
          }),
        ),
        None => text_response(StatusCode::NOT_FOUND, "effective config is unavailable"),
      }
    }
    (&::http::Method::POST, "/admin/v1/config/validate") => {
      if !authorization.is_allowed("config:Validate", "*") {
        return permission_denied(authorization.actor, "config:Validate");
      }
      let payload = match collect_admin_json::<admin_control::AdminConfigPayload>(request).await {
        Ok(payload) => payload,
        Err(response) => return response,
      };
      if let Some(response) = admin_control::validate_config_payload(&payload) {
        return response;
      }
      let active = state.snapshot();
      match Config::load_admin_inline_toml(&payload.config, &active.config)
        .and_then(|config| config.validate().map(|()| config))
      {
        Ok(_) => admin::json_response(StatusCode::OK, &json!({ "ok": true })),
        Err(error) => {
          let error = error.to_string();
          validation_failed(authorization.actor, "config.validate", &error);
          admin::json_response(
            StatusCode::BAD_REQUEST,
            &json!({ "ok": false, "error": error }),
          )
        }
      }
    }
    (&::http::Method::POST, "/admin/v1/config/diff") => {
      if !authorization.is_allowed("config:Diff", "*") {
        return permission_denied(authorization.actor, "config:Diff");
      }
      let payload = match collect_admin_json::<admin_control::AdminConfigPayload>(request).await {
        Ok(payload) => payload,
        Err(response) => return response,
      };
      if let Some(response) = admin_control::validate_config_payload(&payload) {
        return response;
      }
      let active = state.snapshot();
      let candidate =
        match Config::load_admin_inline_effective_toml_redacted(&payload.config, &active.config) {
          Ok(value) => value,
          Err(error) => {
            let error = error.to_string();
            validation_failed(authorization.actor, "config.diff", &error);
            return admin::json_response(
              StatusCode::BAD_REQUEST,
              &json!({ "ok": false, "error": error }),
            );
          }
        };
      let Some((_, _, current_raw)) = admin_control.effective_config().await else {
        return text_response(StatusCode::NOT_FOUND, "effective config is unavailable");
      };
      let current = toml::from_str::<toml::Value>(&current_raw)
        .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
      let mut changes = Vec::new();
      super::admin_config_diff::diff_toml_values(
        "",
        Some(&current),
        Some(&candidate),
        &mut changes,
      );
      admin::json_response(StatusCode::OK, &json!({ "changes": changes }))
    }
    (&::http::Method::POST, "/admin/v1/config/load") => {
      if !authorization.is_allowed("config:Load", "*") {
        return permission_denied(authorization.actor, "config:Load");
      }
      let if_match = if_match_header(&request);
      let payload = match collect_admin_json::<admin_control::AdminConfigPayload>(request).await {
        Ok(payload) => payload,
        Err(response) => return response,
      };
      if let Some(response) = admin_control::validate_config_payload(&payload) {
        return response;
      }
      admin_control
        .load_config(
          authorization.actor.name.clone(),
          admin_control::control_plane_config_permissions(authorization),
          if_match,
          payload.config,
        )
        .await
        .into_http()
    }
    (&::http::Method::POST, "/admin/v1/config/rollback") => {
      if !authorization.is_allowed("config:Rollback", "*") {
        return permission_denied(authorization.actor, "config:Rollback");
      }
      admin_control
        .rollback_config(
          authorization.actor.name.clone(),
          admin_control::control_plane_config_permissions(authorization),
          if_match_header(&request),
        )
        .await
        .into_http()
    }
    (_, _) => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
  }
}

pub(super) async fn admin_tls_response(
  request: &hyper::Request<Incoming>,
  snapshot: &AppSnapshot,
  admin_control: admin_control::AdminControlHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  match (method, path) {
    (&::http::Method::GET, "/admin/v1/tls/downstream") => {
      if !authorization.is_allowed("config:ReadDownstreamTls", "*") {
        return Some(permission_denied(
          authorization.actor,
          "config:ReadDownstreamTls",
        ));
      }
      Some(admin::json_response(
        StatusCode::OK,
        &json!({
          "cert_chain": snapshot.config.source_paths.downstream_tls_cert_chain,
          "private_key_configured": snapshot.config.source_paths.downstream_tls_private_key.is_some(),
          "remote_signer_enabled": snapshot.config.tls.remote_signer.enabled,
          "crlite_mode": snapshot.config.tls.crlite.mode.as_str(),
          "crlite": snapshot.crlite.status(),
          "ocsp_mode": format!("{:?}", snapshot.config.tls.ocsp.mode),
          "ocsp_response_file": snapshot.config.source_paths.downstream_tls_ocsp_response_file,
          "ocsp": snapshot.ocsp_staple.status(),
          "etag": admin_control.status().await["etag"].clone(),
        }),
      ))
    }
    (&::http::Method::POST, "/admin/v1/tls/downstream/reload") => {
      if !authorization.is_allowed("config:ReloadDownstreamTls", "*") {
        return Some(permission_denied(
          authorization.actor,
          "config:ReloadDownstreamTls",
        ));
      }
      Some(
        admin_control
          .reload_downstream_tls(authorization.actor.name.clone(), if_match_header(request))
          .await
          .into_http(),
      )
    }
    (_, "/admin/v1/tls/downstream") | (_, "/admin/v1/tls/downstream/reload") => Some(
      text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    ),
    _ => None,
  }
}

pub(super) async fn admin_files_response(
  request: hyper::Request<Incoming>,
  admin_control: admin_control::AdminControlHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Response<ProxyBody> {
  if path != "/admin/v1/files/sync" {
    return text_response(StatusCode::NOT_FOUND, "not found");
  }
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  let if_match = if_match_header(&request);
  let payload = match collect_admin_json::<admin_control::AdminFilesSyncRequest>(request).await {
    Ok(payload) => payload,
    Err(response) => return response,
  };
  if let Some(response) = admin_control::validate_file_sync_payload(&payload) {
    return response;
  }
  if let Err(error) = check_file_sync_permissions(authorization, &payload) {
    return match error {
      FileSyncPermissionError::Denied(action) => permission_denied(authorization.actor, action),
      FileSyncPermissionError::InvalidPath(message) => {
        text_response(StatusCode::BAD_REQUEST, &message)
      }
    };
  }
  admin_control
    .sync_files(
      authorization.actor.name.clone(),
      admin_control::control_plane_config_permissions(authorization),
      if_match,
      payload,
    )
    .await
    .into_http()
}

struct RequiredIpmPermission {
  action: &'static str,
  resource_name: String,
}

#[derive(Debug, Eq, PartialEq)]
enum FileSyncPermissionError {
  Denied(&'static str),
  InvalidPath(String),
}

fn check_file_sync_permissions(
  authorization: &AdminAuthorization<'_>,
  payload: &admin_control::AdminFilesSyncRequest,
) -> Result<(), FileSyncPermissionError> {
  for operation in &payload.operations {
    for permission in file_sync_operation_permissions(operation)? {
      require_ipm_permission(authorization, permission)?;
    }
  }
  if let Some(permission) = file_sync_apply_permission(payload.apply) {
    require_ipm_permission(authorization, permission)?;
  }
  Ok(())
}

fn file_sync_operation_permissions(
  operation: &admin_control::AdminFileOperation,
) -> Result<Vec<RequiredIpmPermission>, FileSyncPermissionError> {
  match (operation.root, operation.op) {
    (admin_control::AdminFileRoot::Config, admin_control::AdminFileOperationKind::Put) => {
      Ok(vec![RequiredIpmPermission {
        action: "config:SyncFiles",
        resource_name: "*".to_string(),
      }])
    }
    (admin_control::AdminFileRoot::Config, admin_control::AdminFileOperationKind::Delete) => {
      Ok(vec![
        RequiredIpmPermission {
          action: "config:SyncFiles",
          resource_name: "*".to_string(),
        },
        RequiredIpmPermission {
          action: "config:SyncFiles",
          resource_name: "delete".to_string(),
        },
      ])
    }
    (admin_control::AdminFileRoot::OxiRule, admin_control::AdminFileOperationKind::Put) => {
      waf_file_permission(operation.root, "waf:PutOxiRule", "oxirule", &operation.path)
    }
    (admin_control::AdminFileRoot::OxiRule, admin_control::AdminFileOperationKind::Delete) => {
      waf_file_permission(
        operation.root,
        "waf:DeleteOxiRule",
        "oxirule",
        &operation.path,
      )
    }
    (admin_control::AdminFileRoot::OxiRuleGroup, admin_control::AdminFileOperationKind::Put) => {
      waf_file_permission(
        operation.root,
        "waf:PutOxiRuleGroup",
        "oxirule-group",
        &operation.path,
      )
    }
    (admin_control::AdminFileRoot::OxiRuleGroup, admin_control::AdminFileOperationKind::Delete) => {
      waf_file_permission(
        operation.root,
        "waf:DeleteOxiRuleGroup",
        "oxirule-group",
        &operation.path,
      )
    }
    (admin_control::AdminFileRoot::OxiRuleRulepack, admin_control::AdminFileOperationKind::Put) => {
      waf_file_permission(
        operation.root,
        "waf:PutOxiRulePack",
        "oxirule-rulepack",
        &operation.path,
      )
    }
    (
      admin_control::AdminFileRoot::OxiRuleRulepack,
      admin_control::AdminFileOperationKind::Delete,
    ) => waf_file_permission(
      operation.root,
      "waf:DeleteOxiRulePack",
      "oxirule-rulepack",
      &operation.path,
    ),
  }
}

fn waf_file_permission(
  root: admin_control::AdminFileRoot,
  action: &'static str,
  resource_prefix: &str,
  path: &str,
) -> Result<Vec<RequiredIpmPermission>, FileSyncPermissionError> {
  let path =
    file_sync_path::normalized_relative_path(path).map_err(FileSyncPermissionError::InvalidPath)?;
  file_sync_path::validate_root_path(root, &path).map_err(FileSyncPermissionError::InvalidPath)?;
  Ok(vec![RequiredIpmPermission {
    action,
    resource_name: format!("{resource_prefix}/{path}"),
  }])
}

fn file_sync_apply_permission(
  apply: admin_control::AdminApplyMode,
) -> Option<RequiredIpmPermission> {
  match apply {
    admin_control::AdminApplyMode::None => None,
    admin_control::AdminApplyMode::Full => Some(RequiredIpmPermission {
      action: "config:Load",
      resource_name: "*".to_string(),
    }),
    admin_control::AdminApplyMode::DownstreamTls => Some(RequiredIpmPermission {
      action: "config:ReloadDownstreamTls",
      resource_name: "*".to_string(),
    }),
    admin_control::AdminApplyMode::OxiRule => Some(RequiredIpmPermission {
      action: "waf:ReloadOxiRule",
      resource_name: "*".to_string(),
    }),
  }
}

fn require_ipm_permission(
  authorization: &AdminAuthorization<'_>,
  permission: RequiredIpmPermission,
) -> Result<(), FileSyncPermissionError> {
  if authorization.is_allowed(permission.action, &permission.resource_name) {
    Ok(())
  } else {
    Err(FileSyncPermissionError::Denied(permission.action))
  }
}

fn permission_denied(actor: &AdminActor, operation: &str) -> Response<ProxyBody> {
  warn!(
    event = "oxibelt.admin.audit",
    actor = %actor.name,
    operation,
    outcome = "rejected",
    error = "permission denied",
    "admin operation audit"
  );
  text_response(StatusCode::FORBIDDEN, "forbidden")
}

fn validation_failed(actor: &AdminActor, operation: &'static str, error: &str) {
  warn!(
    event = "oxibelt.admin.audit",
    actor = %actor.name,
    operation,
    outcome = "rejected",
    error,
    "admin operation audit"
  );
}

fn if_match_header(request: &hyper::Request<Incoming>) -> Option<String> {
  request
    .headers()
    .get(::http::header::IF_MATCH)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string)
}
