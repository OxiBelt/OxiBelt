//! HTTP boundaries for immutable Kubernetes configuration rollout identity.

use ::http::{Response, StatusCode};

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::runtime_health::RuntimeSubsystem;
use crate::state::AppSnapshot;

pub(super) fn health_response(snapshot: &AppSnapshot, path: &str) -> Option<Response<ProxyBody>> {
  if path == snapshot.config.health.ready_path {
    if snapshot.lifecycle.reason() == "overload"
      && snapshot.config.overload.actions.hard.fail_readiness
    {
      let mut response = with_rollout_identity_headers(
        text_response(StatusCode::SERVICE_UNAVAILABLE, "overloaded"),
        snapshot,
      );
      if let Ok(value) =
        ::http::HeaderValue::from_str(&snapshot.overload.retry_after_seconds().to_string())
      {
        response
          .headers_mut()
          .insert(::http::header::RETRY_AFTER, value);
      }
      return Some(response);
    }
    if snapshot.lifecycle.is_draining() {
      return Some(with_rollout_identity_headers(
        text_response(StatusCode::SERVICE_UNAVAILABLE, "draining"),
        snapshot,
      ));
    }
    if !snapshot.config.rollout.is_ready() {
      return Some(with_rollout_identity_headers(
        text_response(
          StatusCode::SERVICE_UNAVAILABLE,
          "config revision not applied",
        ),
        snapshot,
      ));
    }
    #[cfg(feature = "admin-runtime")]
    if !snapshot.admin_mutations.cluster_rollout_ready() {
      return Some(with_rollout_identity_headers(
        text_response(
          StatusCode::SERVICE_UNAVAILABLE,
          "Admin cluster mutation authority unavailable",
        ),
        snapshot,
      ));
    }
    if !snapshot.runtime_health.is_ready() {
      return Some(with_rollout_identity_headers(
        text_response(
          StatusCode::SERVICE_UNAVAILABLE,
          "runtime subsystem unavailable",
        ),
        snapshot,
      ));
    }
    return Some(with_rollout_identity_headers(
      text_response(StatusCode::OK, "ready"),
      snapshot,
    ));
  }
  if path == snapshot.config.health.live_path {
    return Some(with_rollout_identity_headers(
      text_response(StatusCode::OK, "live"),
      snapshot,
    ));
  }
  None
}

#[cfg(feature = "admin-runtime")]
pub(super) fn immutable_mutation_rejected() -> Response<ProxyBody> {
  text_response(
    StatusCode::CONFLICT,
    "per-Pod configuration mutation is disabled in kubernetes_immutable rollout mode",
  )
}

fn with_rollout_identity_headers(
  response: Response<ProxyBody>,
  snapshot: &AppSnapshot,
) -> Response<ProxyBody> {
  let response =
    with_config_revision_headers(response, snapshot.config.rollout.applied_header_values());
  let response = with_backend_status_header(response, snapshot);
  let response = with_overload_status_header(response, snapshot);
  with_runtime_status_header(response, snapshot)
}

fn with_runtime_status_header(
  mut response: Response<ProxyBody>,
  snapshot: &AppSnapshot,
) -> Response<ProxyBody> {
  let acceleration_degraded = snapshot
    .runtime_health
    .subsystem_is_unhealthy(RuntimeSubsystem::CompioDirectH1);
  let value = if acceleration_degraded && snapshot.runtime_topology.direct_h1.active {
    "required_acceleration_degraded"
  } else if snapshot.runtime_health.is_ready() {
    "ready"
  } else {
    "runtime_unavailable"
  };
  response.headers_mut().insert(
    ::http::HeaderName::from_static("x-oxibelt-runtime-status"),
    ::http::HeaderValue::from_static(value),
  );
  response
}

fn with_backend_status_header(
  response: Response<ProxyBody>,
  snapshot: &AppSnapshot,
) -> Response<ProxyBody> {
  let status = snapshot
    .shared_state
    .as_deref()
    .map(|shared| shared.backend_failure_status())
    .unwrap_or("healthy");
  with_backend_status_value(response, status)
}

fn with_backend_status_value(
  mut response: Response<ProxyBody>,
  status: &'static str,
) -> Response<ProxyBody> {
  response.headers_mut().insert(
    ::http::HeaderName::from_static("x-oxibelt-backend-status"),
    ::http::HeaderValue::from_static(status),
  );
  response
}

fn with_overload_status_header(
  mut response: Response<ProxyBody>,
  snapshot: &AppSnapshot,
) -> Response<ProxyBody> {
  response.headers_mut().insert(
    ::http::HeaderName::from_static("x-oxibelt-overload-state"),
    ::http::HeaderValue::from_static(snapshot.overload.state_label()),
  );
  response
}

fn with_config_revision_headers(
  mut response: Response<ProxyBody>,
  identity: Option<(&str, &str)>,
) -> Response<ProxyBody> {
  let Some((revision, digest)) = identity else {
    return response;
  };
  if let Ok(value) = ::http::HeaderValue::from_bytes(revision.as_bytes()) {
    response.headers_mut().insert(
      ::http::HeaderName::from_static("x-oxibelt-config-revision"),
      value,
    );
  }
  if let Ok(value) = ::http::HeaderValue::from_bytes(digest.as_bytes()) {
    response.headers_mut().insert(
      ::http::HeaderName::from_static("x-oxibelt-config-digest"),
      value,
    );
  }
  response
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(feature = "admin-runtime")]
  #[test]
  fn immutable_mutation_boundary_returns_conflict() {
    assert_eq!(immutable_mutation_rejected().status(), StatusCode::CONFLICT,);
  }

  #[test]
  fn applied_rollout_headers_are_added_only_for_valid_values() {
    let response = with_config_revision_headers(
      text_response(StatusCode::OK, "ready"),
      Some(("gateway-config-abc123", &"a".repeat(64))),
    );
    assert_eq!(
      response.headers()["x-oxibelt-config-revision"],
      "gateway-config-abc123"
    );
    assert_eq!(
      response.headers()["x-oxibelt-config-digest"],
      "a".repeat(64)
    );

    let response = with_config_revision_headers(text_response(StatusCode::OK, "ready"), None);
    assert!(
      response
        .headers()
        .get("x-oxibelt-config-revision")
        .is_none()
    );
    assert!(response.headers().get("x-oxibelt-config-digest").is_none());
  }

  #[test]
  fn backend_status_header_uses_only_the_fixed_health_values() {
    let response = with_backend_status_value(text_response(StatusCode::OK, "ready"), "degraded");
    assert_eq!(response.headers()["x-oxibelt-backend-status"], "degraded");
  }
}
