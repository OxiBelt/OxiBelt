//! HTTP boundaries for immutable Kubernetes configuration rollout identity.

use ::http::{Response, StatusCode};

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppSnapshot;

pub(super) fn health_response(snapshot: &AppSnapshot, path: &str) -> Option<Response<ProxyBody>> {
  if path == snapshot.config.health.ready_path {
    if snapshot.lifecycle.is_draining() {
      return Some(text_response(StatusCode::SERVICE_UNAVAILABLE, "draining"));
    }
    if !snapshot.config.rollout.is_ready() {
      return Some(text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "config revision not applied",
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
  with_config_revision_headers(response, snapshot.config.rollout.applied_header_values())
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
}
