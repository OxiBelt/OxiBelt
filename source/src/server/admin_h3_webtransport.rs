//! Routing, error mapping, and break-glass policy helpers for Admin WebTransport.

use ::http::{Response, StatusCode};
use tracing::warn;

use crate::config::IpmBreakGlassAccessMode;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppSnapshot;

use super::super::admin_operations::{AdminOperationError, parse_operation_id};

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
