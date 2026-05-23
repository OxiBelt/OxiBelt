use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;

use crate::ipm::{IpmDecision, IpmRequestContext, IpmRuntime};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::AdminActor;
use super::admin::json_response;
use super::admin_auth::admin_actor_is_allowed;
use super::admin_body::collect_admin_json;

pub(super) async fn ipm_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  actor: &AdminActor,
  ipm: &IpmRuntime,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if !matches!(
    path,
    "/admin/v1/ipm/principals"
      | "/admin/v1/ipm/credentials"
      | "/admin/v1/ipm/policies"
      | "/admin/v1/ipm/bindings"
      | "/admin/v1/ipm/simulate"
  ) {
    return None;
  }

  match (method, path) {
    (&::http::Method::GET, "/admin/v1/ipm/principals") => {
      if !admin_actor_is_allowed(actor, ipm, "ipm:ListPrincipals", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      Some(json_response(
        StatusCode::OK,
        &json!({ "principals": state.snapshot().ipm.list_principals() }),
      ))
    }
    (&::http::Method::GET, "/admin/v1/ipm/credentials") => {
      if !admin_actor_is_allowed(actor, ipm, "ipm:ListCredentials", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      Some(json_response(
        StatusCode::OK,
        &json!({ "credentials": state.snapshot().ipm.list_credentials() }),
      ))
    }
    (&::http::Method::GET, "/admin/v1/ipm/policies") => {
      if !admin_actor_is_allowed(actor, ipm, "ipm:ListPolicies", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      Some(json_response(
        StatusCode::OK,
        &json!({ "policies": state.snapshot().ipm.list_policies() }),
      ))
    }
    (&::http::Method::GET, "/admin/v1/ipm/bindings") => {
      if !admin_actor_is_allowed(actor, ipm, "ipm:ListBindings", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      Some(json_response(
        StatusCode::OK,
        &json!({ "bindings": state.snapshot().config.ipm.bindings }),
      ))
    }
    (&::http::Method::POST, "/admin/v1/ipm/simulate") => {
      if !admin_actor_is_allowed(actor, ipm, "ipm:Simulate", "*") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let body = match collect_admin_json::<IpmSimulationRequest>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      let decision = ipm.authorize(
        actor,
        &body.action,
        &body.resource,
        &IpmRequestContext::default(),
      );
      Some(json_response(
        StatusCode::OK,
        &json!({ "decision": if decision == IpmDecision::Allow { "allow" } else { "deny" } }),
      ))
    }
    _ => Some(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "method not allowed",
    )),
  }
}

#[derive(Debug, Deserialize)]
struct IpmSimulationRequest {
  action: String,
  resource: String,
}
