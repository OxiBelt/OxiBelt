use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde_json::json;

use crate::admin_list::AdminListQuery;
use crate::ipm::{
  IpmAuditQuery, IpmBindingCreate, IpmCredentialCreate, IpmCredentialPatch, IpmCredentialRevoke,
  IpmCredentialRotate, IpmPolicyCreate, IpmPolicyPatch, IpmPreconditionError, IpmPrincipalCreate,
  IpmPrincipalPatch,
};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_json;
use super::admin_error;
use super::admin_ipm_list::{
  IPM_BINDINGS_LIST, IPM_CREDENTIALS_LIST, IPM_POLICIES_LIST, IPM_PRINCIPALS_LIST,
  ipm_binding_page, ipm_credential_page, ipm_policy_page, ipm_principal_page,
};
use super::admin_resource;
fn allowed(authorization: &AdminAuthorization<'_>, action: &str, resource_name: &str) -> bool {
  authorization.is_allowed(action, resource_name)
}

fn generated_binding_id(body: &IpmBindingCreate) -> String {
  body
    .id
    .clone()
    .unwrap_or_else(|| match (&body.principal, &body.group) {
      (Some(principal), None) => format!("principal.{principal}.{}", body.policy),
      (None, Some(group)) => format!("group.{group}.{}", body.policy),
      _ => format!("binding.{}", body.policy),
    })
}

fn authorize_ipm_credential_target(
  authorization: &AdminAuthorization<'_>,
  action: &str,
  credential_id: &str,
  principal: Option<&str>,
) -> bool {
  let credential_resource = admin_resource::ipm_credential(credential_id);
  if !allowed(authorization, action, &credential_resource) {
    return false;
  }
  if let Some(principal) = principal {
    let principal_resource = admin_resource::ipm_principal(principal);
    if !allowed(authorization, action, &principal_resource) {
      return false;
    }
  }
  true
}

fn authorize_ipm_binding_target(
  authorization: &AdminAuthorization<'_>,
  action: &str,
  body: &IpmBindingCreate,
) -> bool {
  let binding_id = generated_binding_id(body);
  let binding_resource = admin_resource::ipm_binding(&binding_id);
  if !allowed(authorization, action, &binding_resource) {
    return false;
  }
  if let Some(principal) = &body.principal {
    let principal_resource = admin_resource::ipm_principal(principal);
    if !allowed(authorization, action, &principal_resource) {
      return false;
    }
  }
  if let Some(group) = &body.group {
    let group_resource = admin_resource::ipm_group(group);
    if !allowed(authorization, action, &group_resource) {
      return false;
    }
  }
  let policy_resource = admin_resource::ipm_policy(&body.policy);
  allowed(authorization, action, &policy_resource)
}

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
      if !allowed(authorization, "ipm:GetStatus", admin_resource::ipm_status()) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(json_response(
        StatusCode::OK,
        &state.snapshot().ipm.admin_status(),
      ));
    }
    (&::http::Method::GET, "/admin/v1/ipm/principals") => {
      if !allowed(authorization, "ipm:ListPrincipals", "principal/*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let query = match AdminListQuery::parse(request.uri().query(), &IPM_PRINCIPALS_LIST) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      if let Some(query) = query {
        return Some(
          match ipm_principal_page(state.snapshot().ipm.admin_list_principals(), &query) {
            Ok(page) => json_response(
              StatusCode::OK,
              &json!({ "principals": page.items, "pagination": page.pagination }),
            ),
            Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
          },
        );
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
      let resource = admin_resource::ipm_principal(&body.id);
      if !allowed(authorization, "ipm:CreatePrincipal", &resource) {
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
      if !allowed(authorization, "ipm:ListCredentials", "credential/*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let query = match AdminListQuery::parse(request.uri().query(), &IPM_CREDENTIALS_LIST) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      if let Some(query) = query {
        return Some(
          match ipm_credential_page(state.snapshot().ipm.list_credentials(), &query) {
            Ok(page) => json_response(
              StatusCode::OK,
              &json!({ "credentials": page.items, "pagination": page.pagination }),
            ),
            Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
          },
        );
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
      if !authorize_ipm_credential_target(
        authorization,
        "ipm:CreateCredential",
        &body.id,
        Some(&body.principal),
      ) {
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
      if !allowed(authorization, "ipm:ListPolicies", "policy/*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let query = match AdminListQuery::parse(request.uri().query(), &IPM_POLICIES_LIST) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      if let Some(query) = query {
        return Some(
          match ipm_policy_page(state.snapshot().ipm.list_policies(), &query) {
            Ok(page) => json_response(
              StatusCode::OK,
              &json!({ "policies": page.items, "pagination": page.pagination }),
            ),
            Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
          },
        );
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
      let resource = admin_resource::ipm_policy(&body.name);
      if !allowed(authorization, "ipm:CreatePolicy", &resource) {
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
      if !allowed(authorization, "ipm:ListBindings", "binding/*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let query = match AdminListQuery::parse(request.uri().query(), &IPM_BINDINGS_LIST) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      if let Some(query) = query {
        return Some(
          match ipm_binding_page(state.snapshot().ipm.list_bindings(), &query) {
            Ok(page) => json_response(
              StatusCode::OK,
              &json!({ "bindings": page.items, "pagination": page.pagination }),
            ),
            Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
          },
        );
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
      if !authorize_ipm_binding_target(authorization, "ipm:CreateBinding", &body) {
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
      if !allowed(authorization, "ipm:ReadAudit", admin_resource::ipm_audit()) {
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
      return Some(super::admin_ipm_simulation::simulation_response(request, authorization).await);
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
      let resource = admin_resource::ipm_principal(id);
      if !allowed(authorization, "ipm:GetPrincipal", &resource) {
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
      let resource = admin_resource::ipm_principal(id);
      if !allowed(authorization, "ipm:UpdatePrincipal", &resource) {
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
      let resource = admin_resource::ipm_principal(id);
      if !allowed(authorization, "ipm:DeletePrincipal", &resource) {
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
      let resource = admin_resource::ipm_credential(id);
      if !allowed(authorization, "ipm:GetCredential", &resource) {
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
      let credential_resource = admin_resource::ipm_credential(id);
      if !allowed(authorization, "ipm:UpdateCredential", &credential_resource) {
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
      if !authorize_ipm_credential_target(
        authorization,
        "ipm:UpdateCredential",
        id,
        body.principal.as_deref(),
      ) {
        return text_response(StatusCode::FORBIDDEN, "forbidden");
      }
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
      let resource = admin_resource::ipm_credential(id);
      if !allowed(authorization, "ipm:DeleteCredential", &resource) {
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
  let resource = admin_resource::ipm_credential(id);
  if !allowed(authorization, "ipm:RotateCredential", &resource) {
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
  let resource = admin_resource::ipm_credential(id);
  if !allowed(authorization, "ipm:RevokeCredential", &resource) {
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
      let resource = admin_resource::ipm_policy(id);
      if !allowed(authorization, "ipm:GetPolicy", &resource) {
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
      let resource = admin_resource::ipm_policy(id);
      if !allowed(authorization, "ipm:UpdatePolicy", &resource) {
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
      let resource = admin_resource::ipm_policy(id);
      if !allowed(authorization, "ipm:DeletePolicy", &resource) {
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
  let resource = admin_resource::ipm_binding(id);
  if !allowed(authorization, "ipm:DeleteBinding", &resource) {
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

pub(super) fn ipm_error_response(error: anyhow::Error) -> Response<ProxyBody> {
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
