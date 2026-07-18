use super::*;
use http_body_util::BodyExt;

#[test]
fn inactive_break_glass_credentials_are_limited_to_activation_bootstrap_routes() {
  assert!(break_glass_activation_bootstrap_route(
    &Method::GET,
    "/admin/v1/break-glass/activations/self",
  ));
  assert!(break_glass_activation_bootstrap_route(
    &Method::POST,
    "/admin/v1/break-glass/activations",
  ));
  assert!(!break_glass_activation_bootstrap_route(
    &Method::POST,
    "/admin/v1/config/load",
  ));
}

#[test]
fn protected_route_set_covers_every_p1_13_operation_family() {
  for path in [
    "/admin/v1/config/load",
    "/admin/v1/config/rollback",
    "/admin/v1/files/sync",
    "/admin/v1/tls/downstream/reload",
    "/admin/v1/keys/rotate",
    "/admin/v1/config/secret-references/update",
    "/admin/v1/break-glass/activations",
    "/admin/v1/ipm/policies",
  ] {
    assert!(is_protected_write(&Method::POST, path), "missing {path}");
  }
  assert!(!is_protected_write(&Method::POST, "/admin/v1/ipm/simulate"));
  assert!(!is_protected_write(&Method::GET, "/admin/v1/config"));
}

#[test]
fn if_match_requires_one_strong_quoted_revision() {
  let mut headers = HeaderMap::new();
  assert_eq!(
    normalized_if_match(&headers)
      .expect_err("missing If-Match")
      .status(),
    StatusCode::PRECONDITION_REQUIRED
  );
  headers.insert(header::IF_MATCH, "\"r-2041\"".parse().expect("header"));
  assert_eq!(
    normalized_if_match(&headers).expect("strong ETag"),
    "r-2041"
  );
  headers.insert(header::IF_MATCH, "W/\"r-2041\"".parse().expect("header"));
  assert_eq!(
    normalized_if_match(&headers)
      .expect_err("weak ETag")
      .status(),
    StatusCode::BAD_REQUEST
  );
  headers.insert(header::IF_MATCH, "\"r-2041\"".parse().expect("header"));
  headers.append(header::IF_MATCH, "\"r-2042\"".parse().expect("header"));
  assert_eq!(
    normalized_if_match(&headers)
      .expect_err("duplicate If-Match")
      .status(),
    StatusCode::BAD_REQUEST
  );
}

#[test]
fn one_time_response_is_dropped_for_every_noncommitted_terminal() {
  assert!(winner_response_allowed(MutationState::Committed));
  for state in [
    MutationState::RolledBack,
    MutationState::RollbackFailed,
    MutationState::Indeterminate,
    MutationState::Failed,
  ] {
    assert!(
      !winner_response_allowed(state),
      "unexpected winner for {state:?}"
    );
  }
}

#[tokio::test]
async fn operational_precondition_failure_preserves_legacy_response() {
  let response = precondition_failed_response("r-2042");
  assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
  assert!(
    !response
      .headers()
      .contains_key(crate::admin_mutation::IDEMPOTENT_REPLAY_HEADER)
  );
  assert!(
    !response
      .headers()
      .contains_key(crate::admin_mutation::MUTATION_REQUEST_ID_HEADER)
  );
  let body = response
    .into_body()
    .collect()
    .await
    .expect("collect precondition response")
    .to_bytes();
  let payload: serde_json::Value =
    serde_json::from_slice(&body).expect("precondition response JSON");
  assert_eq!(
    payload,
    json!({
      "error": "If-Match does not match the active revision",
      "details": { "expected": "r-2042" },
    })
  );
}
