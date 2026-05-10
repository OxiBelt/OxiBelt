use ::http::{Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use serde::Serialize;
use serde_json::json;

use crate::config::AdminRole;
use crate::dynamic_policy::{
  DynamicPolicyAdminCreate, DynamicPolicyAdminImport, DynamicPolicyAdminPatch,
};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

pub(super) async fn dynamic_policy_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  actor: &super::AdminActor,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path != "/admin/v1/dynamic-policies"
    && path != "/admin/v1/dynamic-policies/export"
    && path != "/admin/v1/dynamic-policies/import"
    && !path.starts_with("/admin/v1/dynamic-policies/")
  {
    return None;
  }
  if !super::admin_actor_has_role(actor, AdminRole::SecurityOperator) {
    return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }

  match (method, path) {
    (&::http::Method::GET, "/admin/v1/dynamic-policies") => {
      return Some(match state.snapshot().dynamic_policy.admin_list().await {
        Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      });
    }
    (&::http::Method::POST, "/admin/v1/dynamic-policies") => {
      let body = match collect_admin_json::<DynamicPolicyAdminCreate>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_create(&actor.name, body)
          .await
        {
          Ok(policy) => json_response(StatusCode::CREATED, &policy),
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
      );
    }
    (&::http::Method::GET, "/admin/v1/dynamic-policies/export") => {
      return Some(match state.snapshot().dynamic_policy.admin_export().await {
        Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      });
    }
    (&::http::Method::POST, "/admin/v1/dynamic-policies/import") => {
      let body = match collect_admin_json::<DynamicPolicyAdminImport>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      return Some(
        match state
          .snapshot()
          .dynamic_policy
          .admin_import(&actor.name, body)
          .await
        {
          Ok(policies) => json_response(StatusCode::OK, &json!({ "policies": policies })),
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
      );
    }
    _ => {}
  }

  let Some(id) = policy_id_from_path(path) else {
    return Some(text_response(StatusCode::NOT_FOUND, "not found"));
  };
  Some(match *method {
    ::http::Method::GET => match state.snapshot().dynamic_policy.admin_get(id).await {
      Ok(Some(policy)) => json_response(StatusCode::OK, &policy),
      Ok(None) => text_response(StatusCode::NOT_FOUND, "not found"),
      Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
    },
    ::http::Method::PATCH => {
      let body = match collect_admin_json::<DynamicPolicyAdminPatch>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      match state
        .snapshot()
        .dynamic_policy
        .admin_patch(&actor.name, id, body)
        .await
      {
        Ok(Some(policy)) => json_response(StatusCode::OK, &policy),
        Ok(None) => text_response(StatusCode::NOT_FOUND, "not found"),
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
      }
    }
    ::http::Method::DELETE => match state
      .snapshot()
      .dynamic_policy
      .admin_delete(&actor.name, id)
      .await
    {
      Ok(true) => json_response(StatusCode::OK, &json!({ "ok": true })),
      Ok(false) => text_response(StatusCode::NOT_FOUND, "not found"),
      Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
    },
    _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
  })
}

fn policy_id_from_path(path: &str) -> Option<i64> {
  path
    .strip_prefix("/admin/v1/dynamic-policies/")?
    .parse()
    .ok()
}

async fn collect_admin_json<T>(request: hyper::Request<Incoming>) -> Result<T, Response<ProxyBody>>
where
  T: for<'de> serde::Deserialize<'de>,
{
  let bytes = request
    .into_body()
    .collect()
    .await
    .map_err(|_| text_response(StatusCode::BAD_REQUEST, "failed to read request body"))?
    .to_bytes();
  if bytes.len() > 64 * 1024 {
    return Err(text_response(
      StatusCode::PAYLOAD_TOO_LARGE,
      "request body is too large",
    ));
  }
  serde_json::from_slice(&bytes)
    .map_err(|_| text_response(StatusCode::BAD_REQUEST, "invalid JSON request body"))
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
