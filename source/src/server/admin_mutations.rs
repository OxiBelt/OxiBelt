//! Replay-protected Admin mutation admission and retained receipt responses.

use ::http::{HeaderMap, Method, Response, StatusCode, header};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use serde_json::{Value, json};
use tracing::warn;

use crate::admin_audit::AdminAuditHandle;
use crate::admin_mutation::{
  AdminMutationRuntime, MutationAdmission, MutationAdmissionError, MutationConflict,
  MutationRecord, MutationResponseMetadata, attach_mutation_response_headers,
};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_request_bytes;
use super::admin_control::{self, AdminControlHandle};
use super::{admin_ipm, admin_mutation_resources, admin_ops};

pub(super) fn break_glass_activation_bootstrap_route(method: &Method, path: &str) -> bool {
  matches!(
    (method, path),
    (&Method::GET, "/admin/v1/break-glass/activations/self")
      | (&Method::POST, "/admin/v1/break-glass/activations")
  )
}

pub(super) fn handles(
  runtime: &AdminMutationRuntime,
  method: &Method,
  path: &str,
  headers: &HeaderMap,
) -> bool {
  if is_receipt_read(method, path) || is_instance_read(method, path) {
    return true;
  }
  if *method == Method::GET && admin_mutation_resources::handles(method, path) {
    return runtime.enabled();
  }
  is_protected_write(method, path)
    && runtime.enabled()
    && (runtime.required() || runtime.has_envelope(headers))
}

pub(super) async fn response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  authorization: &AdminAuthorization<'_>,
  authenticated_with_break_glass: bool,
  method: &Method,
  path: &str,
) -> Response<ProxyBody> {
  let snapshot = state.snapshot();
  let runtime = snapshot.admin_mutations.clone();
  if is_receipt_read(method, path) {
    return receipt_response(&runtime, authorization, path).await;
  }
  if is_instance_read(method, path) {
    return instances_response(&runtime, authorization).await;
  }
  if *method == Method::GET && admin_mutation_resources::handles(method, path) {
    return admin_mutation_resources::response(
      request,
      state,
      admin_control,
      authorization,
      method,
      path,
      None,
      authenticated_with_break_glass,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }
  if runtime.cluster_mode() {
    return text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "fixed-member Admin mutation rollout is not ready",
    );
  }
  let if_match = match normalized_if_match(request.headers()) {
    Ok(value) => value,
    Err(response) => return response,
  };

  let audit = AdminAuditHandle::from_request(&request)
    .expect("Admin mutation admission follows the Admin audit gate");
  let (parts, bytes) =
    match collect_admin_request_bytes(request, admin_control::ADMIN_CONFIG_BODY_LIMIT).await {
      Ok(collected) => collected,
      Err(response) => return response,
    };
  let (action, resource) = mutation_scope(method, path);
  let active_revision = current_revision(&state, &admin_control, path).await;
  let admission = runtime
    .admit(
      &parts.headers,
      method,
      &parts.uri,
      &authorization.actor.principal,
      &bytes,
      action,
      resource,
      &active_revision,
      &if_match,
      &audit,
      &snapshot.admin_audit,
    )
    .await;
  let execution = match admission {
    Ok(MutationAdmission::Claimed(execution)) => execution,
    Ok(MutationAdmission::Replay(record)) => return replay_response(record),
    Ok(MutationAdmission::InProgress(record)) => return in_progress_response(&record),
    Ok(MutationAdmission::PreconditionFailed { active_revision }) => {
      return precondition_failed_response(&active_revision);
    }
    Ok(MutationAdmission::Conflict(conflict)) => return conflict_response(&conflict),
    Ok(MutationAdmission::Bypass) => {
      return text_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "mutation admission bypassed",
      );
    }
    Err(error) => return admission_error_response(&error),
  };

  let replayable_request = hyper::Request::from_parts(parts, Full::new(bytes));
  let mut response = dispatch_protected(
    replayable_request,
    state,
    admin_control,
    authorization,
    authenticated_with_break_glass,
    method,
    path,
    &execution.request_id,
  )
  .await;
  let status = response.status();
  if let Err(error) = runtime
    .finish(
      &execution,
      status,
      safe_terminal_response(path, status, &execution.request_id),
      &audit,
      &snapshot.admin_audit,
    )
    .await
  {
    warn!(
      error = %error,
      mutation_request_id = %execution.request_id,
      "Admin mutation side effect completed without a durable terminal receipt"
    );
    return text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "mutation terminal state could not be persisted",
    );
  }
  attach_mutation_response_headers(
    &mut response,
    MutationResponseMetadata {
      request_id: &execution.request_id,
      revision: &execution.new_revision,
      replayed: false,
    },
  );
  response
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_protected(
  request: hyper::Request<Full<Bytes>>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  authorization: &AdminAuthorization<'_>,
  authenticated_with_break_glass: bool,
  method: &Method,
  path: &str,
  mutation_request_id: &str,
) -> Response<ProxyBody> {
  if admin_mutation_resources::handles(method, path) {
    return admin_mutation_resources::response(
      request,
      state,
      admin_control,
      authorization,
      method,
      path,
      Some(mutation_request_id),
      authenticated_with_break_glass,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }
  if matches!(path, "/admin/v1/config/load" | "/admin/v1/config/rollback") {
    return admin_ops::admin_config_response(
      request,
      state,
      admin_control,
      authorization,
      method,
      path,
    )
    .await;
  }
  if path == "/admin/v1/files/sync" {
    return admin_ops::admin_files_response(
      request,
      admin_control,
      false,
      authorization,
      method,
      path,
    )
    .await;
  }
  if path == "/admin/v1/tls/downstream/reload" {
    return admin_ops::admin_tls_response(
      &request,
      state.snapshot().as_ref(),
      admin_control,
      authorization,
      method,
      path,
    )
    .await
    .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }
  if path.starts_with("/admin/v1/ipm/") {
    return admin_ipm::ipm_response(request, state, authorization, method, path)
      .await
      .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"));
  }
  text_response(StatusCode::NOT_FOUND, "not found")
}

fn is_protected_write(method: &Method, path: &str) -> bool {
  if admin_mutation_resources::handles(method, path) && *method != Method::GET {
    return true;
  }
  if matches!(
    (method, path),
    (&Method::POST, "/admin/v1/config/load")
      | (&Method::POST, "/admin/v1/config/rollback")
      | (&Method::POST, "/admin/v1/files/sync")
      | (&Method::POST, "/admin/v1/tls/downstream/reload")
  ) {
    return true;
  }
  path.starts_with("/admin/v1/ipm/")
    && matches!(*method, Method::POST | Method::PATCH | Method::DELETE)
    && path != "/admin/v1/ipm/simulate"
}

#[allow(clippy::result_large_err)]
fn normalized_if_match(headers: &HeaderMap) -> Result<String, Response<ProxyBody>> {
  let values = headers.get_all(header::IF_MATCH).iter().collect::<Vec<_>>();
  if values.is_empty() {
    return Err(text_response(
      StatusCode::PRECONDITION_REQUIRED,
      "If-Match is required",
    ));
  }
  if values.len() != 1 {
    return Err(text_response(
      StatusCode::BAD_REQUEST,
      "If-Match must be supplied exactly once",
    ));
  }
  let value = values[0]
    .to_str()
    .map_err(|_| text_response(StatusCode::BAD_REQUEST, "If-Match is invalid"))?;
  if value.len() > 256 || value.chars().any(char::is_control) {
    return Err(text_response(
      StatusCode::BAD_REQUEST,
      "If-Match is invalid",
    ));
  }
  let Some(normalized) = value
    .strip_prefix('"')
    .and_then(|value| value.strip_suffix('"'))
    .filter(|value| !value.is_empty() && !value.contains('"'))
  else {
    return Err(text_response(
      StatusCode::BAD_REQUEST,
      "If-Match is invalid",
    ));
  };
  Ok(normalized.to_string())
}

fn is_receipt_read(method: &Method, path: &str) -> bool {
  *method == Method::GET
    && path
      .strip_prefix("/admin/v1/mutations/")
      .is_some_and(|request_id| !request_id.is_empty() && !request_id.contains('/'))
}

fn is_instance_read(method: &Method, path: &str) -> bool {
  *method == Method::GET && path == "/admin/v1/config/instances"
}

async fn current_revision(
  state: &AppHandle,
  admin_control: &AdminControlHandle,
  path: &str,
) -> String {
  let value = if path.starts_with("/admin/v1/ipm/") || path.starts_with("/admin/v1/break-glass/") {
    state.snapshot().ipm.admin_status().etag
  } else {
    admin_control
      .status()
      .await
      .get("etag")
      .and_then(Value::as_str)
      .unwrap_or("oxibelt-config-1")
      .to_string()
  };
  value.trim_matches('"').to_string()
}

fn mutation_scope(method: &Method, path: &str) -> (&'static str, &'static str) {
  if path.starts_with("/admin/v1/ipm/") {
    ("ipm.write", "ipm")
  } else if path.starts_with("/admin/v1/break-glass/") {
    match (method, path) {
      (&Method::POST, "/admin/v1/break-glass/activations") => {
        ("break_glass.activate", "break-glass")
      }
      (&Method::POST, _) => ("break_glass.revoke", "break-glass"),
      _ => ("break_glass.read", "break-glass"),
    }
  } else {
    match (method, path) {
      (&Method::POST, "/admin/v1/config/load") => ("config.load", "config"),
      (&Method::POST, "/admin/v1/config/rollback") => ("config.rollback", "config"),
      (&Method::POST, "/admin/v1/files/sync") => ("config.files_sync", "config"),
      (&Method::POST, "/admin/v1/tls/downstream/reload") => {
        ("config.downstream_tls_reload", "config")
      }
      (&Method::POST, "/admin/v1/keys/rotate") => ("config.key_rotate", "config"),
      (&Method::POST, "/admin/v1/config/secret-references/update") => {
        ("config.secret_reference_update", "config")
      }
      _ => ("admin.mutation", "admin"),
    }
  }
}

fn replay_response(record: MutationRecord) -> Response<ProxyBody> {
  let status = record
    .http_status
    .and_then(|value| u16::try_from(value).ok())
    .and_then(|value| StatusCode::from_u16(value).ok())
    .unwrap_or(StatusCode::OK);
  let body = record.safe_response.clone().unwrap_or_else(|| {
    json!({
      "ok": status.is_success(),
      "request_id": record.request_id,
      "revision": record.new_revision,
      "state": record.state,
      "token_recoverable": false,
    })
  });
  let mut response = json_response(status, &body);
  attach_mutation_response_headers(
    &mut response,
    MutationResponseMetadata {
      request_id: &record.request_id,
      revision: &record.new_revision,
      replayed: true,
    },
  );
  response
}

fn in_progress_response(record: &MutationRecord) -> Response<ProxyBody> {
  json_response(
    StatusCode::CONFLICT,
    &json!({
      "error": "mutation outcome is not terminal",
      "code": "mutation_in_progress",
      "request_id": record.request_id,
      "state": record.state,
    }),
  )
}

fn precondition_failed_response(active_revision: &str) -> Response<ProxyBody> {
  json_response(
    StatusCode::PRECONDITION_FAILED,
    &json!({
      "error": "If-Match does not match the active revision",
      "details": { "expected": active_revision },
    }),
  )
}

fn conflict_response(conflict: &MutationConflict) -> Response<ProxyBody> {
  json_response(
    conflict.status(),
    &json!({
      "error": "mutation claim conflicts with durable state",
      "code": conflict.code(),
      "details": conflict.details(),
    }),
  )
}

fn admission_error_response(error: &MutationAdmissionError) -> Response<ProxyBody> {
  if let MutationAdmissionError::Runtime(inner) = error {
    warn!(error = %inner, "Admin mutation admission failed closed");
  }
  json_response(
    error.status(),
    &json!({
      "error": if matches!(error, MutationAdmissionError::Runtime(_)) {
        "mutation persistence is unavailable"
      } else {
        "mutation envelope was rejected"
      },
      "code": error.code(),
    }),
  )
}

fn safe_terminal_response(path: &str, status: StatusCode, request_id: &str) -> Option<Value> {
  let mut response = json!({
    "ok": status.is_success(),
    "token_recoverable": false,
  });
  if path == "/admin/v1/break-glass/activations" && status.is_success() {
    response["activation_id"] = Value::String(request_id.to_string());
  }
  Some(response)
}

async fn receipt_response(
  runtime: &AdminMutationRuntime,
  authorization: &AdminAuthorization<'_>,
  path: &str,
) -> Response<ProxyBody> {
  let request_id = path.trim_start_matches("/admin/v1/mutations/");
  let record = match runtime.load_mutation(request_id).await {
    Ok(Some(record)) => record,
    Ok(None) => return text_response(StatusCode::NOT_FOUND, "not found"),
    Err(error) => {
      warn!(error = %error, "failed to load Admin mutation receipt");
      return text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "mutation store unavailable",
      );
    }
  };
  if record.principal != authorization.actor.principal
    && !authorization.is_allowed("admin:ReadMutations", &format!("mutation/{request_id}"))
  {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  json_response(
    StatusCode::OK,
    &json!({
      "request_id": record.request_id,
      "principal": record.principal,
      "signer_id": record.signer_id,
      "action": record.action,
      "resource": record.resource,
      "expected_previous_revision": record.expected_previous_revision,
      "new_revision": record.new_revision,
      "content_digest": record.content_digest,
      "target": {
        "cluster_id": record.cluster_id,
        "membership_revision": record.membership_revision,
      },
      "state": record.state,
      "http_status": record.http_status,
      "result": record.safe_response,
      "error_code": record.error_code,
      "issued_at": record.issued_at,
      "expires_at": record.expires_at,
      "created_at": record.created_at,
      "updated_at": record.updated_at,
    }),
  )
}

async fn instances_response(
  runtime: &AdminMutationRuntime,
  authorization: &AdminAuthorization<'_>,
) -> Response<ProxyBody> {
  if !authorization.is_allowed("config:GetInstances", "instances/current") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  match runtime.live_instances().await {
    Ok(instances) => json_response(
      StatusCode::OK,
      &json!({
        "configured_members": runtime.configured_members(),
        "instances": instances,
      }),
    ),
    Err(error) => {
      warn!(error = %error, "failed to load Admin mutation instance state");
      text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "mutation store unavailable",
      )
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use http_body_util::BodyExt;

  #[test]
  fn inactive_break_glass_credentials_are_limited_to_activation_bootstrap_routes() {
    assert!(break_glass_activation_bootstrap_route(
      &Method::GET,
      "/admin/v1/break-glass/activations/self",
    ));
    assert!(break_glass_activation_bootstrap_route(
      &Method::POST,
      "/admin/v1/break-glass/activations",
    ));
    assert!(!break_glass_activation_bootstrap_route(
      &Method::POST,
      "/admin/v1/config/load",
    ));
  }

  #[test]
  fn protected_route_set_covers_every_p1_13_operation_family() {
    for path in [
      "/admin/v1/config/load",
      "/admin/v1/config/rollback",
      "/admin/v1/files/sync",
      "/admin/v1/tls/downstream/reload",
      "/admin/v1/keys/rotate",
      "/admin/v1/config/secret-references/update",
      "/admin/v1/break-glass/activations",
      "/admin/v1/ipm/policies",
    ] {
      assert!(is_protected_write(&Method::POST, path), "missing {path}");
    }
    assert!(!is_protected_write(&Method::POST, "/admin/v1/ipm/simulate"));
    assert!(!is_protected_write(&Method::GET, "/admin/v1/config"));
  }

  #[test]
  fn if_match_requires_one_strong_quoted_revision() {
    let mut headers = HeaderMap::new();
    assert_eq!(
      normalized_if_match(&headers)
        .expect_err("missing If-Match")
        .status(),
      StatusCode::PRECONDITION_REQUIRED
    );

    headers.insert(header::IF_MATCH, "\"r-2041\"".parse().expect("header"));
    assert_eq!(
      normalized_if_match(&headers).expect("strong ETag"),
      "r-2041"
    );

    headers.insert(header::IF_MATCH, "W/\"r-2041\"".parse().expect("header"));
    assert_eq!(
      normalized_if_match(&headers)
        .expect_err("weak ETag")
        .status(),
      StatusCode::BAD_REQUEST
    );

    headers.insert(header::IF_MATCH, "\"r-2041\"".parse().expect("header"));
    headers.append(header::IF_MATCH, "\"r-2042\"".parse().expect("header"));
    assert_eq!(
      normalized_if_match(&headers)
        .expect_err("duplicate If-Match")
        .status(),
      StatusCode::BAD_REQUEST
    );
  }

  #[tokio::test]
  async fn operational_precondition_failure_preserves_legacy_response() {
    let response = precondition_failed_response("r-2042");
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
      !response
        .headers()
        .contains_key(crate::admin_mutation::IDEMPOTENT_REPLAY_HEADER)
    );
    assert!(
      !response
        .headers()
        .contains_key(crate::admin_mutation::MUTATION_REQUEST_ID_HEADER)
    );
    let body = response
      .into_body()
      .collect()
      .await
      .expect("collect precondition response")
      .to_bytes();
    let payload: serde_json::Value =
      serde_json::from_slice(&body).expect("precondition response JSON");
    assert_eq!(
      payload,
      json!({
        "error": "If-Match does not match the active revision",
        "details": { "expected": "r-2042" },
      })
    );
  }
}
