//! Admin HTTP route dispatch.
//! Handlers share authorization and response helpers so admin endpoints fail consistently.

use ::http::{Response, StatusCode};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::Incoming;
use serde::Serialize;
use serde_json::json;

use crate::admin_audit::AdminAuditHandle;
use crate::admin_list::{AdminListQuery, AdminListSpec};
use crate::dynamic_policy::{
  DynamicPolicyAdminCreate, DynamicPolicyAdminImport, DynamicPolicyAdminPatch,
  DynamicPolicyAdminRecord, DynamicPolicyPreconditionError, DynamicPolicyPreconditionErrorKind,
};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::{AdminAuthorization, admin_error, admin_operations, admin_resource};

mod cache;
mod dynamic_policy_query;
pub(super) use cache::{
  cache_key_explain_response, cache_purge_json_response, cache_purge_response, cache_warm_response,
  enqueue_cache_warm_operation, signed_cache_purge_actor,
};

pub(super) const ADMIN_JSON_BODY_LIMIT: usize = 64 * 1024;

const DYNAMIC_POLICY_LIST: AdminListSpec = AdminListSpec {
  endpoint: "/admin/v1/dynamic-policies",
  default_sort: "source",
  allowed_sorts: &[
    "source",
    "name",
    "enabled",
    "priority",
    "created_at",
    "updated_at",
    "id",
  ],
  allowed_filters: &["source", "name", "enabled"],
};

fn allowed(authorization: &AdminAuthorization<'_>, action: &str, resource_name: &str) -> bool {
  authorization.is_allowed(action, resource_name)
}

fn authorize_dynamic_policy_record(
  authorization: &AdminAuthorization<'_>,
  action: &str,
  source: &str,
  name: &str,
  route_name: Option<&str>,
) -> bool {
  let policy_resource = admin_resource::dynamic_policy_source_name(source, name);
  if !allowed(authorization, action, &policy_resource) {
    return false;
  }
  if let Some(route_name) = route_name {
    let route_resource = admin_resource::dynamic_policy_route(route_name);
    if !allowed(authorization, action, &route_resource) {
      return false;
    }
  }
  true
}

fn authorize_dynamic_policy_transition(
  authorization: &AdminAuthorization<'_>,
  action: &str,
  existing: &DynamicPolicyAdminRecord,
  patch: &DynamicPolicyAdminPatch,
) -> bool {
  if !authorize_dynamic_policy_record(
    authorization,
    action,
    &existing.source,
    &existing.name,
    existing.route_name.as_deref(),
  ) {
    return false;
  }
  let next_source = patch.source.as_deref().unwrap_or(&existing.source);
  let next_name = patch.name.as_deref().unwrap_or(&existing.name);
  let next_route = patch
    .route_name
    .as_deref()
    .or(existing.route_name.as_deref());
  if next_source == existing.source
    && next_name == existing.name
    && next_route == existing.route_name.as_deref()
  {
    return true;
  }
  authorize_dynamic_policy_record(authorization, action, next_source, next_name, next_route)
}

pub(super) async fn dynamic_policy_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path != "/admin/v1/dynamic-policies"
    && path != "/admin/v1/dynamic-policies/apply"
    && path != "/admin/v1/dynamic-policies/audit"
    && path != "/admin/v1/dynamic-policies/export"
    && path != "/admin/v1/dynamic-policies/import"
    && !path.starts_with("/admin/v1/dynamic-policies/")
  {
    return None;
  }
  let query = request.uri().query().map(str::to_string);
  match (method, path) {
    (&::http::Method::GET, "/admin/v1/dynamic-policies/status") => {
      if !allowed(
        authorization,
        "dynamic-policy:GetStatus",
        admin_resource::dynamic_policy_status(),
      ) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(match state.snapshot().dynamic_policy.admin_status().await {
        Ok(status) => json_response(StatusCode::OK, &status),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      });
    }
    (&::http::Method::GET, "/admin/v1/dynamic-policies") => {
      if !allowed(authorization, "dynamic-policy:List", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let list_query = match AdminListQuery::parse(query.as_deref(), &DYNAMIC_POLICY_LIST) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      if let Some(list_query) = list_query {
        return Some(
          match state
            .snapshot()
            .dynamic_policy
            .admin_list_page(&list_query)
            .await
          {
            Ok(page) => json_response(
              StatusCode::OK,
              &json!({ "policies": page.items, "pagination": page.pagination }),
            ),
            Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
          },
        );
      }
      return Some(match state.snapshot().dynamic_policy.admin_list().await {
        Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      });
    }
    (&::http::Method::POST, "/admin/v1/dynamic-policies") => {
      let if_match = request_if_match(&request);
      let body = match collect_admin_json::<DynamicPolicyAdminCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorize_dynamic_policy_record(
        authorization,
        "dynamic-policy:Create",
        &body.source,
        &body.name,
        body.route_name.as_deref(),
      ) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_create(&authorization.actor.name, body, if_match.as_deref())
          .await
        {
          Ok(policy) => json_response(StatusCode::CREATED, &policy),
          Err(error) => dynamic_policy_error_response(error),
        },
      );
    }
    (&::http::Method::POST, "/admin/v1/dynamic-policies/apply") => {
      let if_match = request_if_match(&request);
      let body = match collect_admin_json::<DynamicPolicyAdminCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorize_dynamic_policy_record(
        authorization,
        "dynamic-policy:Apply",
        &body.source,
        &body.name,
        body.route_name.as_deref(),
      ) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_apply(&authorization.actor.name, body, if_match.as_deref())
          .await
        {
          Ok(policy) => json_response(StatusCode::OK, &policy),
          Err(error) => dynamic_policy_error_response(error),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/dynamic-policies/audit") => {
      if !allowed(authorization, "dynamic-policy:ReadAudit", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let (policy_id, limit) = match dynamic_policy_query::audit_query(query.as_deref()) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_audit(policy_id, limit)
          .await
        {
          Ok(audit) => json_response(StatusCode::OK, &json!({ "audit": audit })),
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/dynamic-policies/export") => {
      if !allowed(authorization, "dynamic-policy:Export", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      return Some(match state.snapshot().dynamic_policy.admin_export().await {
        Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      });
    }
    (&::http::Method::POST, "/admin/v1/dynamic-policies/import") => {
      let respond_async = admin_operations::prefer_respond_async(&request);
      let request_id = AdminAuditHandle::from_request(&request)
        .map(|audit| audit.request_id())
        .unwrap_or_else(|| "unknown".to_string());
      let if_match = request_if_match(&request);
      let body = match collect_admin_json::<DynamicPolicyAdminImport>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      for policy in &body.policies {
        if !authorize_dynamic_policy_record(
          authorization,
          "dynamic-policy:Import",
          &policy.source,
          &policy.name,
          policy.route_name.as_deref(),
        ) {
          return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
        }
      }
      if respond_async {
        let actor_name = authorization.actor.name.clone();
        return Some(
          match operations
            .enqueue(
              admin_operations::AdminOperationKind::DynamicPolicyImport,
              authorization.actor,
              request_id,
              move |context| async move {
                context.ensure_not_cancelled()?;
                context
                  .progress("importing", Some(0), Some(body.policies.len() as u64))
                  .await;
                let policies = state
                  .snapshot()
                  .dynamic_policy
                  .admin_import(&actor_name, body, if_match.as_deref())
                  .await
                  .map_err(|error| error.to_string())?;
                context.ensure_not_cancelled()?;
                context
                  .progress(
                    "importing",
                    Some(policies.len() as u64),
                    Some(policies.len() as u64),
                  )
                  .await;
                admin_operations::value_result(json!({ "policies": policies }))
              },
            )
            .await
          {
            Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
            Err(error) => admin_operations::enqueue_error_response(error),
          },
        );
      }
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_import(&authorization.actor.name, body, if_match.as_deref())
          .await
        {
          Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
          Err(error) => dynamic_policy_error_response(error),
        },
      );
    }
    _ => {}
  }

  let Some(id) = dynamic_policy_query::policy_id_from_path(path) else {
    return Some(text_response(StatusCode::NOT_FOUND, "not found"));
  };
  Some(match *method {
    ::http::Method::GET => match state.snapshot().dynamic_policy.admin_get(id).await {
      Ok(Some(policy)) => {
        if !authorize_dynamic_policy_record(
          authorization,
          "dynamic-policy:Get",
          &policy.source,
          &policy.name,
          policy.route_name.as_deref(),
        ) {
          return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
        }
        json_response(StatusCode::OK, &policy)
      }
      Ok(None) => text_response(StatusCode::NOT_FOUND, "not found"),
      Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
    },
    ::http::Method::PATCH => {
      let if_match = request_if_match(&request);
      let existing = match state.snapshot().dynamic_policy.admin_get(id).await {
        Ok(Some(policy)) => policy,
        Ok(None) => return Some(text_response(StatusCode::NOT_FOUND, "not found")),
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      let body = match collect_admin_json::<DynamicPolicyAdminPatch>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorize_dynamic_policy_transition(
        authorization,
        "dynamic-policy:Update",
        &existing,
        &body,
      ) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      match state
        .snapshot()
        .dynamic_policy
        .admin_patch(&authorization.actor.name, id, body, if_match.as_deref())
        .await
      {
        Ok(Some(policy)) => json_response(StatusCode::OK, &policy),
        Ok(None) => text_response(StatusCode::NOT_FOUND, "not found"),
        Err(error) => dynamic_policy_error_response(error),
      }
    }
    ::http::Method::DELETE => {
      let if_match = request_if_match(&request);
      let existing = match state.snapshot().dynamic_policy.admin_get(id).await {
        Ok(Some(policy)) => policy,
        Ok(None) => return Some(text_response(StatusCode::NOT_FOUND, "not found")),
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      if !authorize_dynamic_policy_record(
        authorization,
        "dynamic-policy:Delete",
        &existing.source,
        &existing.name,
        existing.route_name.as_deref(),
      ) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      match state
        .snapshot()
        .dynamic_policy
        .admin_delete(&authorization.actor.name, id, if_match.as_deref())
        .await
      {
        Ok(true) => json_response(StatusCode::OK, &json!({ "ok": true })),
        Ok(false) => text_response(StatusCode::NOT_FOUND, "not found"),
        Err(error) => dynamic_policy_error_response(error),
      }
    }
    _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
  })
}

pub(in crate::server) async fn enqueue_dynamic_policy_import_operation(
  request: serde_json::Value,
  state: AppHandle,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
  if_match: Option<String>,
) -> Response<ProxyBody> {
  let body = match serde_json::from_value::<DynamicPolicyAdminImport>(request) {
    Ok(body) => body,
    Err(_) => {
      return text_response(
        StatusCode::BAD_REQUEST,
        "invalid dynamic_policy_import request",
      );
    }
  };
  for policy in &body.policies {
    if !authorize_dynamic_policy_record(
      authorization,
      "dynamic-policy:Import",
      &policy.source,
      &policy.name,
      policy.route_name.as_deref(),
    ) {
      return text_response(StatusCode::FORBIDDEN, "forbidden");
    }
  }
  let actor_name = authorization.actor.name.clone();
  match operations
    .enqueue(
      admin_operations::AdminOperationKind::DynamicPolicyImport,
      authorization.actor,
      request_id,
      move |context| async move {
        context.ensure_not_cancelled()?;
        context
          .progress("importing", Some(0), Some(body.policies.len() as u64))
          .await;
        let policies = state
          .snapshot()
          .dynamic_policy
          .admin_import(&actor_name, body, if_match.as_deref())
          .await
          .map_err(|error| error.to_string())?;
        context.ensure_not_cancelled()?;
        context
          .progress(
            "importing",
            Some(policies.len() as u64),
            Some(policies.len() as u64),
          )
          .await;
        admin_operations::value_result(json!({ "policies": policies }))
      },
    )
    .await
  {
    Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
    Err(error) => admin_operations::enqueue_error_response(error),
  }
}

fn request_if_match(request: &hyper::Request<Incoming>) -> Option<String> {
  request
    .headers()
    .get(::http::header::IF_MATCH)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string)
}

fn dynamic_policy_error_response(error: anyhow::Error) -> Response<ProxyBody> {
  if let Some(precondition) = error.downcast_ref::<DynamicPolicyPreconditionError>() {
    let status = match precondition.kind() {
      DynamicPolicyPreconditionErrorKind::Missing => StatusCode::PRECONDITION_REQUIRED,
      DynamicPolicyPreconditionErrorKind::Stale => StatusCode::PRECONDITION_FAILED,
    };
    return admin_error::error_response_with_details(
      status,
      &error.to_string(),
      Some(json!({ "header": "If-Match", "expected": precondition.expected() })),
    );
  }
  text_response(StatusCode::BAD_REQUEST, &error.to_string())
}

async fn collect_admin_json<T>(request: hyper::Request<Incoming>) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> serde::Deserialize<'de>,
{
  let bytes = Limited::new(request.into_body(), ADMIN_JSON_BODY_LIMIT)
    .collect()
    .await
    .map_err(|error| {
      if error.downcast_ref::<LengthLimitError>().is_some() {
        super::admin_error::error_response(
          StatusCode::PAYLOAD_TOO_LARGE,
          "request body is too large",
        )
      } else {
        super::admin_error::error_response(StatusCode::BAD_REQUEST, "failed to read request body")
      }
    })?
    .to_bytes();
  serde_json::from_slice(&bytes).map_err(|_| {
    super::admin_error::error_response(StatusCode::BAD_REQUEST, "invalid JSON request body")
  })
}

pub(super) fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<ProxyBody> {
  match serde_json::to_vec(value) {
    Ok(bytes) => {
      let body = http_body_util::Full::new(bytes::Bytes::from(bytes))
        .map_err(|never| -> crate::proxy::http::body::BoxError { match never {} })
        .boxed();
      let mut response = Response::new(body);
      *response.status_mut() = status;
      response.headers_mut().insert(
        ::http::header::CONTENT_TYPE,
        ::http::HeaderValue::from_static("application/json"),
      );
      response
    }
    Err(error) => text_response(
      StatusCode::INTERNAL_SERVER_ERROR,
      &format!("failed to encode JSON response: {error}"),
    ),
  }
}
