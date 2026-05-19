use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde_json::json;
use tracing::warn;

use crate::config::{AdminPermission, AdminRole, Config};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::{AppHandle, AppSnapshot};

use super::admin_auth::{AdminActor, admin_actor_has_permission, admin_actor_has_role};
use super::{admin, admin_control, collect_admin_json};

pub(super) fn admin_waf_response(
  snapshot: &AppSnapshot,
  actor: &AdminActor,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path != "/admin/v1/waf/rule-hits"
    && path != "/admin/v1/waf/rule-costs"
    && path != "/admin/v1/waf/crs/compatibility"
  {
    return None;
  }
  if !admin_actor_has_role(actor, AdminRole::Viewer) {
    return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }
  if *method != ::http::Method::GET {
    return Some(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "method not allowed",
    ));
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
    _ => None,
  }
}

pub(super) fn admin_lifecycle_response(
  snapshot: &AppSnapshot,
  actor: &AdminActor,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  match path {
    "/admin/v1/lifecycle" => {
      if !admin_actor_has_role(actor, AdminRole::Viewer) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
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
      if !admin_actor_has_role(actor, AdminRole::Admin) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
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
      if !admin_actor_has_role(actor, AdminRole::Admin) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
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
  actor: &AdminActor,
  method: &::http::Method,
  path: &str,
) -> Response<ProxyBody> {
  match (method, path) {
    (&::http::Method::GET, "/admin/v1/config/status") => {
      if !admin_actor_has_permission(actor, AdminPermission::ConfigRead) {
        return permission_denied(actor, "config.status", AdminPermission::ConfigRead);
      }
      admin::json_response(StatusCode::OK, &admin_control.status().await)
    }
    (&::http::Method::GET, "/admin/v1/config/effective") => {
      if !admin_actor_has_permission(actor, AdminPermission::ConfigRead) {
        return permission_denied(actor, "config.effective", AdminPermission::ConfigRead);
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
      if !admin_actor_has_permission(actor, AdminPermission::ConfigValidate) {
        return permission_denied(actor, "config.validate", AdminPermission::ConfigValidate);
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
          validation_failed(actor, "config.validate", &error);
          admin::json_response(
            StatusCode::BAD_REQUEST,
            &json!({ "ok": false, "error": error }),
          )
        }
      }
    }
    (&::http::Method::POST, "/admin/v1/config/diff") => {
      if !admin_actor_has_permission(actor, AdminPermission::ConfigDiff) {
        return permission_denied(actor, "config.diff", AdminPermission::ConfigDiff);
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
            validation_failed(actor, "config.diff", &error);
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
      diff_toml_values("", Some(&current), Some(&candidate), &mut changes);
      admin::json_response(StatusCode::OK, &json!({ "changes": changes }))
    }
    (&::http::Method::POST, "/admin/v1/config/load") => {
      if !admin_actor_has_permission(actor, AdminPermission::ConfigLoad) {
        return permission_denied(actor, "config.load", AdminPermission::ConfigLoad);
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
        .load_config(actor.name.clone(), if_match, payload.config)
        .await
        .into_http()
    }
    (&::http::Method::POST, "/admin/v1/config/rollback") => {
      if !admin_actor_has_permission(actor, AdminPermission::ConfigRollback) {
        return permission_denied(actor, "config.rollback", AdminPermission::ConfigRollback);
      }
      admin_control
        .rollback_config(actor.name.clone(), if_match_header(&request))
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
  actor: &AdminActor,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  match (method, path) {
    (&::http::Method::GET, "/admin/v1/tls/downstream") => {
      if !admin_actor_has_permission(actor, AdminPermission::TlsDownstreamRead) {
        return Some(permission_denied(
          actor,
          "tls.downstream",
          AdminPermission::TlsDownstreamRead,
        ));
      }
      Some(admin::json_response(
        StatusCode::OK,
        &json!({
          "cert_chain": snapshot.config.source_paths.downstream_tls_cert_chain,
          "private_key_configured": snapshot.config.source_paths.downstream_tls_private_key.is_some(),
          "remote_signer_enabled": snapshot.config.tls.remote_signer.enabled,
          "ocsp_mode": format!("{:?}", snapshot.config.tls.ocsp.mode),
          "ocsp_response_file": snapshot.config.source_paths.downstream_tls_ocsp_response_file,
          "etag": admin_control.status().await["etag"].clone(),
        }),
      ))
    }
    (&::http::Method::POST, "/admin/v1/tls/downstream/reload") => {
      if !admin_actor_has_permission(actor, AdminPermission::TlsDownstreamReload) {
        return Some(permission_denied(
          actor,
          "tls.downstream.reload",
          AdminPermission::TlsDownstreamReload,
        ));
      }
      Some(
        admin_control
          .reload_downstream_tls(actor.name.clone(), if_match_header(request))
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
  actor: &AdminActor,
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
  for operation in &payload.operations {
    let sync_permission = operation.root.sync_permission();
    if !admin_actor_has_permission(actor, sync_permission) {
      return permission_denied(actor, "files.sync", sync_permission);
    }
    if operation.op == admin_control::AdminFileOperationKind::Delete
      && !admin_actor_has_permission(actor, AdminPermission::FilesDelete)
    {
      return permission_denied(actor, "files.sync", AdminPermission::FilesDelete);
    }
  }
  admin_control
    .sync_files(actor.name.clone(), if_match, payload)
    .await
    .into_http()
}

fn permission_denied(
  actor: &AdminActor,
  operation: &'static str,
  permission: AdminPermission,
) -> Response<ProxyBody> {
  warn!(
    event = "oxibelt.admin.audit",
    actor = %actor.name,
    operation,
    permission = permission.as_str(),
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

fn diff_toml_values(
  path: &str,
  left: Option<&toml::Value>,
  right: Option<&toml::Value>,
  changes: &mut Vec<serde_json::Value>,
) {
  match (left, right) {
    (Some(toml::Value::Table(left)), Some(toml::Value::Table(right))) => {
      let keys = left
        .keys()
        .chain(right.keys())
        .collect::<std::collections::BTreeSet<_>>();
      for key in keys {
        let child = if path.is_empty() {
          key.to_string()
        } else {
          format!("{path}.{key}")
        };
        diff_toml_values(&child, left.get(key), right.get(key), changes);
      }
    }
    (Some(left), Some(right)) if left == right => {}
    (None, Some(_)) => changes.push(json!({ "path": path, "op": "add" })),
    (Some(_), None) => changes.push(json!({ "path": path, "op": "remove" })),
    (Some(_), Some(_)) => changes.push(json!({ "path": path, "op": "change" })),
    (None, None) => {}
  }
}
