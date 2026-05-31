use std::time::Duration;

use ::http::{Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::server::admin_auth::AdminAuthorization;
use crate::state::AppHandle;
use crate::webtransport_admin::WebTransportSessionScope;

use super::{
  AdminOperationKind, AdminOperationRuntime, accepted_operation_response, enqueue_error_response,
  value_result,
};

#[derive(Debug, Default, Deserialize)]
struct WebTransportSnapshotRequest {
  #[serde(default)]
  scope: WebTransportSessionScope,
}

#[derive(Debug, Deserialize)]
struct WebTransportDrainRequest {
  #[serde(default)]
  scope: WebTransportSessionScope,
  #[serde(default)]
  grace_ms: Option<u64>,
  #[serde(default)]
  close_code: u32,
  #[serde(default = "default_drain_reason")]
  reason: String,
}

pub(in crate::server) async fn enqueue_webtransport_snapshot_operation(
  request: Value,
  state: AppHandle,
  operations: AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
) -> Response<ProxyBody> {
  let body = match serde_json::from_value::<WebTransportSnapshotRequest>(object_or_default(request))
  {
    Ok(body) => body,
    Err(_) => {
      return text_response(
        StatusCode::BAD_REQUEST,
        "invalid WebTransport snapshot body",
      );
    }
  };
  if !is_allowed_for_scope(
    authorization,
    "runtime:GetWebTransportSessions",
    &body.scope,
  ) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }

  let actor = authorization.actor.clone();
  match operations
    .enqueue(
      AdminOperationKind::WebTransportSnapshot,
      &actor,
      request_id,
      move |context| {
        let registry = state.snapshot().webtransport_admin.clone();
        async move {
          context.progress("snapshot", None, None).await;
          context.ensure_not_cancelled()?;
          let sessions = registry.list((!body.scope.is_empty()).then_some(&body.scope));
          value_result(json!({
            "sessions": sessions,
            "count": sessions.len(),
          }))
        }
      },
    )
    .await
  {
    Ok(snapshot) => accepted_operation_response(&snapshot),
    Err(error) => enqueue_error_response(error),
  }
}

pub(in crate::server) async fn enqueue_webtransport_drain_operation(
  request: Value,
  state: AppHandle,
  operations: AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
) -> Response<ProxyBody> {
  let body = match serde_json::from_value::<WebTransportDrainRequest>(object_or_default(request)) {
    Ok(body) => body,
    Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid WebTransport drain body"),
  };
  if !is_allowed_for_scope(
    authorization,
    "runtime:DrainWebTransportSessions",
    &body.scope,
  ) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }

  let actor = authorization.actor.clone();
  match operations
    .enqueue(
      AdminOperationKind::WebTransportDrain,
      &actor,
      request_id,
      move |context| {
        let snapshot = state.snapshot();
        let registry = snapshot.webtransport_admin.clone();
        let default_grace =
          Duration::from_millis(snapshot.config.runtime.drain.long_connection_close_delay_ms);
        async move {
          context.progress("installing_drain", None, None).await;
          context.ensure_not_cancelled()?;
          let grace = body
            .grace_ms
            .map(Duration::from_millis)
            .unwrap_or(default_grace);
          let installed = registry.install_drain_rule(
            context.id().to_string(),
            body.scope.clone(),
            body.close_code,
            body.reason.clone(),
          );

          let started = std::time::Instant::now();
          loop {
            context.ensure_not_cancelled().inspect_err(|_| {
              registry.remove_drain_rule(context.id());
            })?;
            let elapsed = started.elapsed();
            if elapsed >= grace {
              break;
            }
            let remaining = grace.saturating_sub(elapsed);
            context
              .progress(
                "grace",
                Some(elapsed.as_millis().min(u128::from(u64::MAX)) as u64),
                Some(grace.as_millis().min(u128::from(u64::MAX)) as u64),
              )
              .await;
            tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
          }

          context.progress("closing", None, None).await;
          let close_sent = registry
            .close_matching_drain_rule(context.id())
            .map_err(|error| error.to_string())?;
          registry.remove_drain_rule(context.id());
          value_result(json!({
            "drain_id": installed.drain_id,
            "matched_sessions": installed.matched_sessions,
            "close_sent": close_sent,
            "grace_ms": grace.as_millis().min(u128::from(u64::MAX)) as u64,
          }))
        }
      },
    )
    .await
  {
    Ok(snapshot) => accepted_operation_response(&snapshot),
    Err(error) => enqueue_error_response(error),
  }
}

fn is_allowed_for_scope(
  authorization: &AdminAuthorization<'_>,
  action: &str,
  scope: &WebTransportSessionScope,
) -> bool {
  resources_for_scope(scope)
    .iter()
    .all(|resource| authorization.is_allowed(action, resource))
}

fn resources_for_scope(scope: &WebTransportSessionScope) -> Vec<String> {
  let mut resources = Vec::new();
  if scope.is_empty() {
    resources.push("webtransport/session/*".to_string());
  }
  resources.extend(
    scope
      .session_ids
      .iter()
      .map(|id| format!("webtransport/session/{id}")),
  );
  if let Some(route) = &scope.route {
    resources.push(format!("webtransport/route/{route}"));
  }
  if let Some(upstream) = &scope.upstream {
    resources.push(format!("webtransport/upstream/{upstream}"));
  }
  if let Some(client_ip) = scope.client_ip {
    resources.push(format!("webtransport/client-ip/{client_ip}"));
  }
  if resources.is_empty() {
    resources.push("webtransport/session/*".to_string());
  }
  resources
}

fn default_drain_reason() -> String {
  "admin webtransport drain".to_string()
}

fn object_or_default(value: Value) -> Value {
  if value.is_null() { json!({}) } else { value }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig};
  use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};
  use crate::server::admin_auth::AdminAuthorization;

  fn actor() -> IpmActor {
    IpmActor {
      name: "ops".to_string(),
      principal: "ops".to_string(),
      subject: "ops@example.test".to_string(),
      groups: Vec::new(),
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
  fn scoped_webtransport_permission_is_required_for_all_resources() {
    let actor = actor();
    let ipm = IpmRuntime::test_with_actor_policy(
      "oxibelt",
      actor.clone(),
      IpmPolicyConfig {
        name: "route-only".to_string(),
        version: "2026-05-31".to_string(),
        statements: vec![IpmPolicyStatementConfig {
          effect: IpmPolicyEffect::Allow,
          actions: vec!["runtime:DrainWebTransportSessions".to_string()],
          resources: vec!["oxibelt:oxibelt:runtime:webtransport/route/app".to_string()],
          conditions: Vec::new(),
        }],
      },
    );
    let context = IpmRequestContext::default();
    let authorization = authorization(&actor, &ipm, &context);
    let route_scope = WebTransportSessionScope {
      route: Some("app".to_string()),
      ..WebTransportSessionScope::default()
    };
    assert!(is_allowed_for_scope(
      &authorization,
      "runtime:DrainWebTransportSessions",
      &route_scope
    ));

    let mixed_scope = WebTransportSessionScope {
      route: Some("app".to_string()),
      upstream: Some("origin".to_string()),
      ..WebTransportSessionScope::default()
    };
    assert!(!is_allowed_for_scope(
      &authorization,
      "runtime:DrainWebTransportSessions",
      &mixed_scope
    ));
  }
}
