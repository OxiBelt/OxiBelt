//! Routing, error mapping, and break-glass policy helpers for Admin WebTransport.

use std::net::SocketAddr;
use std::time::Duration;

use ::http::{Request, Response, StatusCode};
use tokio::sync::{OwnedSemaphorePermit, broadcast};
use tracing::warn;

use crate::admin_audit::AdminAuditHandle;
use crate::config::IpmBreakGlassAccessMode;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::{AppHandle, AppSnapshot};

use super::admin_auth::{AdminAuthorization, admin_authentication, admin_request_context};
use super::admin_operations::{
  AdminOperationError, AdminOperationEvent, AdminOperationRuntime, can_access_operation,
  parse_operation_id,
};

pub(super) const TERMINAL_EVENT_DRAIN_DELAY: Duration = Duration::from_millis(250);

pub(super) struct OperationEventSubscription {
  pub(super) history: Vec<AdminOperationEvent>,
  pub(super) receiver: broadcast::Receiver<AdminOperationEvent>,
  pub(super) permit: OwnedSemaphorePermit,
}

pub(super) async fn require_break_glass_activation(
  snapshot: &AppSnapshot,
  authenticated_with_break_glass: bool,
  principal: &str,
) -> Result<(), Response<ProxyBody>> {
  if !requires_break_glass_activation(
    snapshot.config.ipm.break_glass.access_mode,
    authenticated_with_break_glass,
  ) {
    return Ok(());
  }
  match snapshot
    .admin_mutations
    .active_break_glass_activation(principal)
    .await
  {
    Ok(Some(activation)) if activation.scopes.iter().any(|scope| scope == "admin") => Ok(()),
    Ok(_) => Err(text_response(
      StatusCode::FORBIDDEN,
      "break-glass activation is required",
    )),
    Err(error) => {
      warn!(error = %error, "failed to verify break-glass activation");
      Err(text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "break-glass activation store is unavailable",
      ))
    }
  }
}

fn requires_break_glass_activation(
  access_mode: IpmBreakGlassAccessMode,
  authenticated_with_break_glass: bool,
) -> bool {
  authenticated_with_break_glass && access_mode == IpmBreakGlassAccessMode::TwoFactorActivation
}

pub(super) fn error_response(error: AdminOperationError) -> Response<ProxyBody> {
  match error {
    AdminOperationError::Disabled => text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "WebTransport operation events are disabled",
    ),
    AdminOperationError::QueueFull => text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "too many active WebTransport operation event sessions",
    ),
    AdminOperationError::StoreFull
    | AdminOperationError::NotFound
    | AdminOperationError::AlreadyTerminal
    | AdminOperationError::IdempotencyConflict
    | AdminOperationError::Unavailable
    | AdminOperationError::Internal => {
      text_response(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
    }
  }
}

pub(super) fn matches_operation_event_path(path: &str) -> bool {
  path.starts_with("/admin/v1/operations/") && path.ends_with("/events/wt")
}

pub(super) fn operation_id_from_path(path: &str) -> anyhow::Result<&str> {
  let Some(rest) = path.strip_prefix("/admin/v1/operations/") else {
    anyhow::bail!("not an operation event WebTransport endpoint");
  };
  let mut segments = rest.split('/');
  match (
    segments.next(),
    segments.next(),
    segments.next(),
    segments.next(),
  ) {
    (Some(id), Some("events"), Some("wt"), None) => parse_operation_id(id),
    _ => anyhow::bail!("not an operation event WebTransport endpoint"),
  }
}

pub(super) async fn prepare_operation_event_subscription<B>(
  request: &Request<B>,
  state: &AppHandle,
  operations: &AdminOperationRuntime,
  peer_addr: SocketAddr,
  listener_current: bool,
) -> Result<OperationEventSubscription, Response<ProxyBody>> {
  let snapshot = state.snapshot();
  if !listener_current {
    return Err(text_response(StatusCode::NOT_FOUND, "not found"));
  }
  if !operations.config().webtransport {
    return Err(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "WebTransport operation events are disabled",
    ));
  }
  let operation_id = operation_id_from_path(request.uri().path())
    .map_err(|error| text_response(StatusCode::BAD_REQUEST, &error.to_string()))?;
  let context = admin_request_context(request, peer_addr);
  let audit = AdminAuditHandle::from_request(request);
  let authentication = match admin_authentication(request, &snapshot.config, &snapshot.ipm).await {
    Ok(authentication) => authentication,
    Err(failure) => {
      if snapshot.config.admin.workload_identity.enabled {
        snapshot
          .metrics
          .record_admin_workload_identity_authentication("rejected", failure.reason());
      }
      if let Some(audit) = &audit {
        failure.record_audit(audit);
      }
      return Err(text_response(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
  };
  if snapshot.config.admin.workload_identity.enabled {
    snapshot
      .metrics
      .record_admin_workload_identity_authentication("accepted", authentication.reason());
  }
  if let Some(audit) = &audit {
    authentication.record_audit(audit);
  }
  require_break_glass_activation(
    &snapshot,
    authentication.authenticated_with_break_glass(),
    &authentication.actor.principal,
  )
  .await?;
  let actor = &authentication.actor;
  let authorization = if let Some(audit) = audit {
    AdminAuthorization::new_with_audit(actor, &snapshot.ipm, &context, audit)
  } else {
    AdminAuthorization::new(actor, &snapshot.ipm, &context)
  };
  let (history, receiver, operation) = match operations.subscribe(operation_id).await {
    Ok(Some(subscription)) => subscription,
    Ok(None) => return Err(text_response(StatusCode::NOT_FOUND, "not found")),
    Err(error) => return Err(error_response(error)),
  };
  if !can_access_operation(&authorization, &operation, "admin:ReadOperation") {
    return Err(text_response(StatusCode::FORBIDDEN, "forbidden"));
  }
  let permit = operations
    .try_acquire_webtransport_session()
    .map_err(error_response)?;
  Ok(OperationEventSubscription {
    history,
    receiver,
    permit,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn inactive_two_factor_break_glass_is_gated_on_webtransport() {
    assert!(requires_break_glass_activation(
      IpmBreakGlassAccessMode::TwoFactorActivation,
      true,
    ));
    assert!(!requires_break_glass_activation(
      IpmBreakGlassAccessMode::Direct,
      true,
    ));
    assert!(!requires_break_glass_activation(
      IpmBreakGlassAccessMode::TwoFactorActivation,
      false,
    ));
  }
}
