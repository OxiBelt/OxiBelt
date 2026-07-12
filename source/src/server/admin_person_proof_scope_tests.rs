use super::admin_resource_scope_tests::{
  log_safe_text, person_proof_clearance_list_scope_config, person_proof_status_scope_config,
  try_scoped_admin_response,
};

#[tokio::test]
async fn person_proof_status_requires_status_resource() {
  let Some(denied) = try_scoped_admin_response(
    "resource-person-proof-status-deny",
    person_proof_clearance_list_scope_config,
    "GET",
    "/admin/v1/waf/person-proof/status",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    denied.starts_with("HTTP/1.1 403 Forbidden")
      && denied.contains(r#""action":"waf:GetPersonProofStatus""#)
      && denied.contains(r#""resource":"oxibelt:oxibelt:waf:person-proof/status""#),
    "person proof status should require status resource: {}",
    log_safe_text(&denied)
  );

  let Some(allowed) = try_scoped_admin_response(
    "resource-person-proof-status-allow",
    person_proof_status_scope_config,
    "GET",
    "/admin/v1/waf/person-proof/status",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    allowed.starts_with("HTTP/1.1 200 OK") && allowed.contains(r#""store_scope":"disabled""#),
    "person proof status permission should reach handler: {}",
    log_safe_text(&allowed)
  );
}

#[tokio::test]
async fn person_proof_clearance_list_requires_wildcard_resource() {
  let Some(response) = try_scoped_admin_response(
    "resource-person-proof-list-deny",
    person_proof_status_scope_config,
    "GET",
    "/admin/v1/waf/person-proof/clearances?cursor=not-a-valid-cursor",
    "",
  )
  .await
  else {
    return;
  };

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"waf:ListPersonProofClearances""#)
      && response.contains(r#""resource":"oxibelt:oxibelt:waf:person-proof/clearance/*""#),
    "person proof clearance list should require wildcard resource: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn person_proof_clearance_revoke_requires_hash_resource() {
  let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  let Some(response) = try_scoped_admin_response(
    "resource-person-proof-revoke-deny",
    person_proof_status_scope_config,
    "POST",
    "/admin/v1/waf/person-proof/clearances/revoke",
    &format!(r#"{{"clearance_hash":"clearance:{hash}"}}"#),
  )
  .await
  else {
    return;
  };

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"waf:RevokePersonProofClearance""#)
      && response.contains(
        r#""resource":"oxibelt:oxibelt:waf:person-proof/clearance/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#
      ),
    "person proof clearance revoke should require hash resource: {}",
    log_safe_text(&response)
  );
}
