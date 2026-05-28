use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;

use crate::ipm::{
  IpmAuditQuery, IpmBindingCreate, IpmCredentialCreate, IpmCredentialPatch, IpmCredentialRevoke,
  IpmCredentialRotate, IpmDecision, IpmPolicyCreate, IpmPolicyPatch, IpmPreconditionError,
  IpmPrincipalCreate, IpmPrincipalPatch, IpmRequestContext,
};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_json;
use super::admin_error;

pub(super) async fn ipm_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if !path.starts_with("/admin/v1/ipm/") {
    return None;
  }

  match (method, path) {
    (&::http::Method::GET, "/admin/v1/ipm/status") => {
      if !authorization.is_allowed("ipm:GetStatus", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(json_response(
        StatusCode::OK,
        &state.snapshot().ipm.admin_status(),
      ));
    }
    (&::http::Method::GET, "/admin/v1/ipm/principals") => {
      if !authorization.is_allowed("ipm:ListPrincipals", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(json_response(
        StatusCode::OK,
        &json!({ "principals": state.snapshot().ipm.admin_list_principals() }),
      ));
    }
    (&::http::Method::POST, "/admin/v1/ipm/principals") => {
      let if_match = request_if_match(&request);
      let body = match collect_admin_json::<IpmPrincipalCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorization.is_allowed("ipm:CreatePrincipal", &body.id) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return Some(response);
      }
      return Some(
        match state
          .snapshot()
          .ipm
          .admin_create_principal(authorization.actor, body)
          .await
        {
          Ok(principal) => json_response(StatusCode::CREATED, &principal),
          Err(error) => ipm_error_response(error),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/ipm/credentials") => {
      if !authorization.is_allowed("ipm:ListCredentials", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(json_response(
        StatusCode::OK,
        &json!({ "credentials": state.snapshot().ipm.list_credentials() }),
      ));
    }
    (&::http::Method::POST, "/admin/v1/ipm/credentials") => {
      let if_match = request_if_match(&request);
      let body = match collect_admin_json::<IpmCredentialCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorization.is_allowed("ipm:CreateCredential", &body.id) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return Some(response);
      }
      return Some(
        match state
          .snapshot()
          .ipm
          .admin_create_credential(authorization.actor, body)
          .await
        {
          Ok(credential) => json_response(StatusCode::CREATED, &credential),
          Err(error) => ipm_error_response(error),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/ipm/policies") => {
      if !authorization.is_allowed("ipm:ListPolicies", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(json_response(
        StatusCode::OK,
        &json!({ "policies": state.snapshot().ipm.list_policies() }),
      ));
    }
    (&::http::Method::POST, "/admin/v1/ipm/policies") => {
      let if_match = request_if_match(&request);
      let body = match collect_admin_json::<IpmPolicyCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorization.is_allowed("ipm:CreatePolicy", &body.name) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return Some(response);
      }
      return Some(
        match state
          .snapshot()
          .ipm
          .admin_create_policy(authorization.actor, body)
          .await
        {
          Ok(policy) => json_response(StatusCode::CREATED, &policy),
          Err(error) => ipm_error_response(error),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/ipm/bindings") => {
      if !authorization.is_allowed("ipm:ListBindings", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(json_response(
        StatusCode::OK,
        &json!({ "bindings": state.snapshot().ipm.list_bindings() }),
      ));
    }
    (&::http::Method::POST, "/admin/v1/ipm/bindings") => {
      let if_match = request_if_match(&request);
      let body = match collect_admin_json::<IpmBindingCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      let resource = body.id.as_deref().unwrap_or("*");
      if !authorization.is_allowed("ipm:CreateBinding", resource) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return Some(response);
      }
      return Some(
        match state
          .snapshot()
          .ipm
          .admin_create_binding(authorization.actor, body)
          .await
        {
          Ok(binding) => json_response(StatusCode::CREATED, &binding),
          Err(error) => ipm_error_response(error),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/ipm/audit") => {
      if !authorization.is_allowed("ipm:ReadAudit", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let query = match audit_query(request.uri().query()) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      return Some(match state.snapshot().ipm.admin_audit(query).await {
        Ok(audit) => json_response(StatusCode::OK, &json!({ "audit": audit })),
        Err(error) => ipm_error_response(error),
      });
    }
    (&::http::Method::POST, "/admin/v1/ipm/simulate") => {
      if !authorization.is_allowed("ipm:Simulate", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let body = match collect_admin_json::<IpmSimulationRequest>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      let decision = authorization.ipm.authorize(
        authorization.actor,
        &body.action,
        &body.resource,
        &IpmRequestContext::default(),
      );
      return Some(json_response(
        StatusCode::OK,
        &json!({ "decision": if decision == IpmDecision::Allow { "allow" } else { "deny" } }),
      ));
    }
    _ => {}
  }

  let rest = path.strip_prefix("/admin/v1/ipm/")?;
  let segments = rest.split('/').collect::<Vec<_>>();
  match segments.as_slice() {
    ["principals", id] => {
      Some(principal_item_response(request, state, authorization, method, id).await)
    }
    ["credentials", id] => {
      Some(credential_item_response(request, state, authorization, method, id).await)
    }
    ["credentials", id, "rotate"] => {
      Some(credential_rotate_response(request, state, authorization, method, id).await)
    }
    ["credentials", id, "revoke"] => {
      Some(credential_revoke_response(request, state, authorization, method, id).await)
    }
    ["policies", id] => Some(policy_item_response(request, state, authorization, method, id).await),
    ["bindings", id] => {
      Some(binding_item_response(request, state, authorization, method, id).await)
    }
    _ => Some(text_response(StatusCode::NOT_FOUND, "not found")),
  }
}

async fn principal_item_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  id: &str,
) -> Response<ProxyBody> {
  match *method {
    ::http::Method::GET => {
      if !authorization.is_allowed("ipm:GetPrincipal", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      state
        .snapshot()
        .ipm
        .admin_get_principal(id)
        .map(|principal| json_response(StatusCode::OK, &principal))
        .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"))
    }
    ::http::Method::PATCH => {
      if !authorization.is_allowed("ipm:UpdatePrincipal", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let if_match = request_if_match(&request);
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return response;
      }
      let body = match collect_admin_json::<IpmPrincipalPatch>(request).await {
        Ok(body) => body,
        Err(response) => return response,
      };
      match state
        .snapshot()
        .ipm
        .admin_patch_principal(authorization.actor, id, body)
        .await
      {
        Ok(principal) => json_response(StatusCode::OK, &principal),
        Err(error) => ipm_error_response(error),
      }
    }
    ::http::Method::DELETE => {
      if !authorization.is_allowed("ipm:DeletePrincipal", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let if_match = request_if_match(&request);
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return response;
      }
      match state
        .snapshot()
        .ipm
        .admin_delete_principal(authorization.actor, id)
        .await
      {
        Ok(()) => json_response(StatusCode::OK, &json!({ "ok": true })),
        Err(error) => ipm_error_response(error),
      }
    }
    _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
  }
}

async fn credential_item_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  id: &str,
) -> Response<ProxyBody> {
  match *method {
    ::http::Method::GET => {
      if !authorization.is_allowed("ipm:GetCredential", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      state
        .snapshot()
        .ipm
        .admin_get_credential(id)
        .map(|credential| json_response(StatusCode::OK, &credential))
        .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"))
    }
    ::http::Method::PATCH => {
      if !authorization.is_allowed("ipm:UpdateCredential", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let if_match = request_if_match(&request);
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return response;
      }
      let body = match collect_admin_json::<IpmCredentialPatch>(request).await {
        Ok(body) => body,
        Err(response) => return response,
      };
      match state
        .snapshot()
        .ipm
        .admin_patch_credential(authorization.actor, id, body)
        .await
      {
        Ok(credential) => json_response(StatusCode::OK, &credential),
        Err(error) => ipm_error_response(error),
      }
    }
    ::http::Method::DELETE => {
      if !authorization.is_allowed("ipm:DeleteCredential", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let if_match = request_if_match(&request);
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return response;
      }
      match state
        .snapshot()
        .ipm
        .admin_delete_credential(authorization.actor, id)
        .await
      {
        Ok(()) => json_response(StatusCode::OK, &json!({ "ok": true })),
        Err(error) => ipm_error_response(error),
      }
    }
    _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
  }
}

async fn credential_rotate_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  id: &str,
) -> Response<ProxyBody> {
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  if !authorization.is_allowed("ipm:RotateCredential", id) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  let if_match = request_if_match(&request);
  if let Some(response) = check_if_match(&state, if_match.as_deref()) {
    return response;
  }
  let body = match collect_admin_json::<IpmCredentialRotate>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  match state
    .snapshot()
    .ipm
    .admin_rotate_credential(authorization.actor, id, body)
    .await
  {
    Ok(credential) => json_response(StatusCode::OK, &credential),
    Err(error) => ipm_error_response(error),
  }
}

async fn credential_revoke_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  id: &str,
) -> Response<ProxyBody> {
  if *method != ::http::Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  if !authorization.is_allowed("ipm:RevokeCredential", id) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  let if_match = request_if_match(&request);
  if let Some(response) = check_if_match(&state, if_match.as_deref()) {
    return response;
  }
  let body = match collect_admin_json::<IpmCredentialRevoke>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  match state
    .snapshot()
    .ipm
    .admin_revoke_credential(authorization.actor, id, body)
    .await
  {
    Ok(credential) => json_response(StatusCode::OK, &credential),
    Err(error) => ipm_error_response(error),
  }
}

async fn policy_item_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  id: &str,
) -> Response<ProxyBody> {
  match *method {
    ::http::Method::GET => {
      if !authorization.is_allowed("ipm:GetPolicy", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      state
        .snapshot()
        .ipm
        .admin_get_policy(id)
        .map(|policy| json_response(StatusCode::OK, &policy))
        .unwrap_or_else(|| text_response(StatusCode::NOT_FOUND, "not found"))
    }
    ::http::Method::PATCH => {
      if !authorization.is_allowed("ipm:UpdatePolicy", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let if_match = request_if_match(&request);
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return response;
      }
      let body = match collect_admin_json::<IpmPolicyPatch>(request).await {
        Ok(body) => body,
        Err(response) => return response,
      };
      match state
        .snapshot()
        .ipm
        .admin_patch_policy(authorization.actor, id, body)
        .await
      {
        Ok(policy) => json_response(StatusCode::OK, &policy),
        Err(error) => ipm_error_response(error),
      }
    }
    ::http::Method::DELETE => {
      if !authorization.is_allowed("ipm:DeletePolicy", id) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
      let if_match = request_if_match(&request);
      if let Some(response) = check_if_match(&state, if_match.as_deref()) {
        return response;
      }
      match state
        .snapshot()
        .ipm
        .admin_delete_policy(authorization.actor, id)
        .await
      {
        Ok(()) => json_response(StatusCode::OK, &json!({ "ok": true })),
        Err(error) => ipm_error_response(error),
      }
    }
    _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
  }
}

async fn binding_item_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  id: &str,
) -> Response<ProxyBody> {
  if *method != ::http::Method::DELETE {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  if !authorization.is_allowed("ipm:DeleteBinding", id) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  let if_match = request_if_match(&request);
  if let Some(response) = check_if_match(&state, if_match.as_deref()) {
    return response;
  }
  match state
    .snapshot()
    .ipm
    .admin_delete_binding(authorization.actor, id)
    .await
  {
    Ok(()) => json_response(StatusCode::OK, &json!({ "ok": true })),
    Err(error) => ipm_error_response(error),
  }
}

fn check_if_match(state: &AppHandle, if_match: Option<&str>) -> Option<Response<ProxyBody>> {
  let snapshot = state.snapshot();
  let expected = snapshot.ipm.admin_status().etag;
  match snapshot.ipm.check_if_match(if_match) {
    Ok(()) => None,
    Err(IpmPreconditionError::Missing) => Some(admin_error::error_response_with_details(
      StatusCode::PRECONDITION_REQUIRED,
      "If-Match is required",
      Some(json!({ "header": "If-Match", "expected": expected })),
    )),
    Err(IpmPreconditionError::Stale) => Some(admin_error::error_response_with_details(
      StatusCode::PRECONDITION_FAILED,
      "If-Match does not match the active IPM generation",
      Some(json!({ "header": "If-Match", "expected": expected })),
    )),
  }
}

fn request_if_match(request: &hyper::Request<Incoming>) -> Option<String> {
  request
    .headers()
    .get(::http::header::IF_MATCH)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string)
}

fn ipm_error_response(error: anyhow::Error) -> Response<ProxyBody> {
  let message = error.to_string();
  let status = if message.contains("IPM store is not configured") {
    StatusCode::CONFLICT
  } else {
    StatusCode::BAD_REQUEST
  };
  text_response(status, &message)
}

fn audit_query(query: Option<&str>) -> anyhow::Result<IpmAuditQuery> {
  let mut parsed = IpmAuditQuery {
    limit: 100,
    ..IpmAuditQuery::default()
  };
  if let Some(query) = query {
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
      match key.as_ref() {
        "target_kind" => parsed.target_kind = Some(value.into_owned()),
        "target_id" => parsed.target_id = Some(value.into_owned()),
        "outcome" => parsed.outcome = Some(value.into_owned()),
        "actor" => parsed.actor = Some(value.into_owned()),
        "limit" => {
          parsed.limit = value
            .parse::<i64>()
            .map_err(|_| anyhow::anyhow!("limit must be an integer"))?;
        }
        _ => {}
      }
    }
  }
  Ok(parsed)
}

#[derive(Debug, Deserialize)]
struct IpmSimulationRequest {
  action: String,
  resource: String,
}
