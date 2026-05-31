use std::net::SocketAddr;

use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::admin_audit::AdminAuditHandle;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::id::parse_operation_id;
use super::runtime::{AdminOperationError, AdminOperationRuntime};
use super::stream::{AdminOperationEventFormat, event_stream_response};
use super::types::{AdminOperationKind, AdminOperationSnapshot};
use super::websocket::websocket_response;
use crate::server::admin::json_response;
use crate::server::admin_auth::AdminAuthorization;
use crate::server::admin_control::AdminControlHandle;

#[derive(Debug, Deserialize)]
struct AdminOperationCreateRequest {
  kind: AdminOperationKind,
  #[serde(default)]
  request: Value,
}

pub(in crate::server) struct AdminOperationRouteContext {
  pub(in crate::server) state: AppHandle,
  pub(in crate::server) admin_control: AdminControlHandle,
  pub(in crate::server) operations: AdminOperationRuntime,
  pub(in crate::server) peer_addr: SocketAddr,
}

pub(in crate::server) async fn admin_operations_response(
  request: hyper::Request<Incoming>,
  context: AdminOperationRouteContext,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if path != "/admin/v1/operations" && !path.starts_with("/admin/v1/operations/") {
    return None;
  }

  if path == "/admin/v1/operations" {
    return Some(match *method {
      ::http::Method::GET => list_operations(&context.operations, authorization).await,
      ::http::Method::POST => create_operation(request, context, authorization).await,
      _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    });
  }

  let rest = path.strip_prefix("/admin/v1/operations/")?;
  let segments = rest.split('/').collect::<Vec<_>>();
  match segments.as_slice() {
    [id] => {
      let id = match parse_operation_id(id) {
        Ok(id) => id,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      Some(match *method {
        ::http::Method::GET => get_operation(&context.operations, authorization, id).await,
        ::http::Method::DELETE => cancel_operation(&context.operations, authorization, id).await,
        _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
      })
    }
    [id, "events"] => {
      let id = match parse_operation_id(id) {
        Ok(id) => id,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      Some(match *method {
        ::http::Method::GET => {
          watch_operation(request, &context.operations, authorization, id, false).await
        }
        _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
      })
    }
    [id, "events", "ws"] => {
      let id = match parse_operation_id(id) {
        Ok(id) => id,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      Some(match *method {
        ::http::Method::GET => {
          watch_operation(request, &context.operations, authorization, id, true).await
        }
        _ => text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
      })
    }
    _ => Some(text_response(StatusCode::NOT_FOUND, "not found")),
  }
}

pub(in crate::server) fn accepted_operation_response(
  snapshot: &AdminOperationSnapshot,
) -> Response<ProxyBody> {
  let location = format!("/admin/v1/operations/{}", snapshot.id);
  let mut response = json_response(StatusCode::ACCEPTED, snapshot);
  if let Ok(value) = ::http::HeaderValue::from_str(&location) {
    response
      .headers_mut()
      .insert(::http::header::LOCATION, value.clone());
    response
      .headers_mut()
      .insert(::http::HeaderName::from_static("operation-location"), value);
  }
  response.headers_mut().insert(
    ::http::HeaderName::from_static("preference-applied"),
    ::http::HeaderValue::from_static("respond-async"),
  );
  response
}

async fn list_operations(
  operations: &AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
) -> Response<ProxyBody> {
  if !authorization.is_allowed("admin:ListOperations", "operation/*") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  json_response(
    StatusCode::OK,
    &json!({ "operations": operations.list().await }),
  )
}

async fn get_operation(
  operations: &AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  id: &str,
) -> Response<ProxyBody> {
  let Some(snapshot) = operations.get(id).await else {
    return text_response(StatusCode::NOT_FOUND, "not found");
  };
  if !can_access_operation(authorization, &snapshot, "admin:ReadOperation") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  json_response(StatusCode::OK, &snapshot)
}

async fn cancel_operation(
  operations: &AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  id: &str,
) -> Response<ProxyBody> {
  let Some(snapshot) = operations.get(id).await else {
    return text_response(StatusCode::NOT_FOUND, "not found");
  };
  if !can_access_operation(authorization, &snapshot, "admin:CancelOperation") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  match operations.cancel(id).await {
    Ok(snapshot) => json_response(StatusCode::OK, &snapshot),
    Err(AdminOperationError::AlreadyTerminal) => {
      text_response(StatusCode::CONFLICT, "operation already finished")
    }
    Err(AdminOperationError::NotFound) => text_response(StatusCode::NOT_FOUND, "not found"),
    Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
  }
}

async fn watch_operation(
  request: hyper::Request<Incoming>,
  operations: &AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  id: &str,
  websocket: bool,
) -> Response<ProxyBody> {
  let Some(snapshot) = operations.get(id).await else {
    return text_response(StatusCode::NOT_FOUND, "not found");
  };
  if !can_access_operation(authorization, &snapshot, "admin:ReadOperation") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if websocket && !operations.config().websocket {
    return text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "WebSocket operation events are disabled",
    );
  }
  let Some((history, receiver, _snapshot)) = operations.subscribe(id).await else {
    return text_response(StatusCode::NOT_FOUND, "not found");
  };
  if websocket {
    return websocket_response(request, history, receiver);
  }
  let format = event_format(request.uri().query());
  event_stream_response(history, receiver, format)
}

async fn create_operation(
  request: hyper::Request<Incoming>,
  context: AdminOperationRouteContext,
  authorization: &AdminAuthorization<'_>,
) -> Response<ProxyBody> {
  let request_id = AdminAuditHandle::from_request(&request)
    .map(|audit| audit.request_id())
    .unwrap_or_else(|| "unknown".to_string());
  let if_match = request
    .headers()
    .get(::http::header::IF_MATCH)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string);
  let body =
    match crate::server::admin_body::collect_admin_json::<AdminOperationCreateRequest>(request)
      .await
    {
      Ok(body) => body,
      Err(response) => return response,
    };
  match body.kind {
    AdminOperationKind::CacheWarm => {
      crate::server::admin::enqueue_cache_warm_operation(
        body.request,
        context.state,
        context.operations,
        authorization,
        request_id,
        context.peer_addr,
      )
      .await
    }
    AdminOperationKind::OxiRuleReplay => {
      let snapshot = context.state.snapshot();
      crate::server::admin_ops::enqueue_oxirule_replay_operation(
        body.request,
        snapshot.as_ref(),
        context.operations,
        authorization,
        request_id,
      )
      .await
    }
    AdminOperationKind::DiagnosticsPreflight | AdminOperationKind::SupportBundle => {
      crate::server::admin_diagnostics::enqueue_diagnostics_operation(
        body.kind,
        body.request,
        context.state,
        context.admin_control,
        context.operations,
        authorization,
        request_id,
      )
      .await
    }
    AdminOperationKind::DynamicPolicyImport => {
      crate::server::admin::enqueue_dynamic_policy_import_operation(
        body.request,
        context.state,
        context.operations,
        authorization,
        request_id,
        if_match,
      )
      .await
    }
    AdminOperationKind::WebTransportSnapshot => {
      super::enqueue_webtransport_snapshot_operation(
        body.request,
        context.state,
        context.operations,
        authorization,
        request_id,
      )
      .await
    }
    AdminOperationKind::WebTransportDrain => {
      super::enqueue_webtransport_drain_operation(
        body.request,
        context.state,
        context.operations,
        authorization,
        request_id,
      )
      .await
    }
  }
}

fn event_format(query: Option<&str>) -> AdminOperationEventFormat {
  let Some(query) = query else {
    return AdminOperationEventFormat::Sse;
  };
  for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
    if key == "format" && value == "ndjson" {
      return AdminOperationEventFormat::Ndjson;
    }
  }
  AdminOperationEventFormat::Sse
}

pub(in crate::server) fn can_access_operation(
  authorization: &AdminAuthorization<'_>,
  snapshot: &AdminOperationSnapshot,
  action: &str,
) -> bool {
  if snapshot.actor == authorization.actor.name
    && snapshot.principal == authorization.actor.principal
  {
    return true;
  }
  authorization.is_allowed(action, &operation_resource(snapshot.kind, &snapshot.id))
    || authorization.is_allowed(action, "operation/*")
}

fn operation_resource(kind: AdminOperationKind, id: &str) -> String {
  format!("operation/{}/{id}", kind.as_str())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig};
  use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};
  use crate::server::admin_operations::types::AdminOperationState;

  fn actor(name: &str) -> IpmActor {
    IpmActor {
      name: name.to_string(),
      principal: name.to_string(),
      subject: format!("{name}@example.test"),
      groups: Vec::new(),
    }
  }

  fn snapshot(actor: &IpmActor) -> AdminOperationSnapshot {
    AdminOperationSnapshot {
      id: "op_550e8400-e29b-41d4-a716-446655440000".to_string(),
      kind: AdminOperationKind::CacheWarm,
      state: AdminOperationState::Running,
      created_at_unix_ms: 1,
      started_at_unix_ms: Some(2),
      finished_at_unix_ms: None,
      actor: actor.name.clone(),
      principal: actor.principal.clone(),
      request_id: "req1".to_string(),
      cancel_requested: false,
      progress: None,
      result: None,
      error: None,
    }
  }

  fn authorization<'a>(
    actor: &'a IpmActor,
    ipm: &'a IpmRuntime,
    context: &'a IpmRequestContext,
  ) -> AdminAuthorization<'a> {
    AdminAuthorization::new(actor, ipm, context)
  }

  #[test]
  fn creator_can_read_own_operation_without_operation_grant() {
    let actor = actor("creator");
    let ipm = IpmRuntime::test_with_actor_policy(
      "oxibelt",
      actor.clone(),
      IpmPolicyConfig {
        name: "empty".to_string(),
        version: "2026-05-30".to_string(),
        statements: Vec::new(),
      },
    );
    let context = IpmRequestContext::default();
    let auth = authorization(&actor, &ipm, &context);
    assert!(can_access_operation(
      &auth,
      &snapshot(&actor),
      "admin:ReadOperation"
    ));
  }

  #[test]
  fn non_creator_requires_matching_operation_grant() {
    let creator = actor("creator");
    let reader = actor("reader");
    let policy = IpmPolicyConfig {
      name: "operation-reader".to_string(),
      version: "2026-05-30".to_string(),
      statements: vec![IpmPolicyStatementConfig {
        effect: IpmPolicyEffect::Allow,
        actions: vec!["admin:ReadOperation".to_string()],
        resources: vec![
          "oxibelt:oxibelt:admin:operation/cache_warm/op_550e8400-e29b-41d4-a716-446655440000"
            .to_string(),
        ],
        conditions: Vec::new(),
      }],
    };
    let ipm = IpmRuntime::test_with_actor_policy("oxibelt", reader.clone(), policy);
    let context = IpmRequestContext::default();
    let auth = authorization(&reader, &ipm, &context);
    assert!(can_access_operation(
      &auth,
      &snapshot(&creator),
      "admin:ReadOperation"
    ));

    let denied = actor("denied");
    let ipm = IpmRuntime::test_with_actor_policy(
      "oxibelt",
      denied.clone(),
      IpmPolicyConfig {
        name: "empty".to_string(),
        version: "2026-05-30".to_string(),
        statements: Vec::new(),
      },
    );
    let auth = authorization(&denied, &ipm, &context);
    assert!(!can_access_operation(
      &auth,
      &snapshot(&creator),
      "admin:ReadOperation"
    ));
  }
}
