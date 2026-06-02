use std::net::SocketAddr;
use std::path::Path;

use crate::config::Config;

use super::admin_resource_scope_tests::{
  ipm_simulate_policy_status_only_config, ipm_simulate_principal_status_only_config, log_safe_text,
  parse_simulation_config, try_scoped_admin_response,
};

#[tokio::test]
async fn ipm_simulate_unknown_principal_requires_resource_before_lookup() {
  let Some(response) = try_scoped_admin_response(
    "ipm-simulate-unknown-principal-preauth",
    ipm_simulate_principal_status_only_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"principal":"ghost"}}"#,
  )
  .await
  else {
    return;
  };

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"ipm:SimulatePrincipal""#)
      && response.contains(r#""resource":"oxibelt:oxibelt:ipm:principal/ghost""#)
      && !response.contains("unknown IPM principal"),
    "unknown principal must not be enumerated before resource authorization: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn ipm_simulate_authorized_unknown_principal_returns_bad_request() {
  let Some(response) = try_scoped_admin_response(
    "ipm-simulate-unknown-principal-authorized",
    ipm_simulate_principal_wildcard_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"principal":"ghost"}}"#,
  )
  .await
  else {
    return;
  };

  assert!(
    response.starts_with("HTTP/1.1 400 Bad Request")
      && response.contains("unknown IPM principal ghost"),
    "authorized unknown principal should keep validation behavior: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn ipm_simulate_credential_requires_raw_and_resolved_resources() {
  let Some(raw_response) = try_scoped_admin_response(
    "ipm-simulate-credential-raw-preauth",
    ipm_simulate_principal_status_only_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"credential":"missing-token"}}"#,
  )
  .await
  else {
    return;
  };
  assert!(
    raw_response.starts_with("HTTP/1.1 403 Forbidden")
      && raw_response.contains(r#""resource":"oxibelt:oxibelt:ipm:credential/missing-token""#)
      && !raw_response.contains("unknown IPM credential"),
    "unknown credential must be authorized before lookup: {}",
    log_safe_text(&raw_response)
  );

  let Some(resolved_response) = try_scoped_admin_response(
    "ipm-simulate-credential-resolved-preauth",
    ipm_simulate_credential_only_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"credential":"operator-token"}}"#,
  )
  .await
  else {
    return;
  };
  assert!(
    resolved_response.starts_with("HTTP/1.1 403 Forbidden")
      && !resolved_response.contains(r#""resource":"oxibelt:oxibelt:ipm:principal/operator""#)
      && !resolved_response.contains("IPM credential operator-token"),
    "credential simulation should require the resolved principal without leaking it: {}",
    log_safe_text(&resolved_response)
  );
}

#[tokio::test]
async fn ipm_simulate_credential_wildcard_cannot_enumerate_owners_or_unknowns() {
  let Some(known_response) = try_scoped_admin_response(
    "ipm-simulate-credential-wildcard-known-preauth",
    ipm_simulate_credential_wildcard_only_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"credential":"operator-token"}}"#,
  )
  .await
  else {
    return;
  };
  let Some(missing_response) = try_scoped_admin_response(
    "ipm-simulate-credential-wildcard-missing-preauth",
    ipm_simulate_credential_wildcard_only_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"credential":"missing-token"}}"#,
  )
  .await
  else {
    return;
  };

  for response in [&known_response, &missing_response] {
    assert!(
      response.starts_with("HTTP/1.1 403 Forbidden")
        && !response.contains(r#""resource":"oxibelt:oxibelt:ipm:principal/operator""#)
        && !response.contains("unknown IPM credential")
        && !response.contains("is not active")
        && !response.contains("belongs to principal"),
      "credential wildcard caller must not enumerate credential ownership or existence: {}",
      log_safe_text(response)
    );
  }
}

#[tokio::test]
async fn ipm_simulate_credential_mismatch_requires_owner_before_error() {
  let Some(unauthorized_response) = try_scoped_admin_response(
    "ipm-simulate-credential-mismatch-owner-preauth",
    ipm_simulate_credential_and_deployer_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"credential":"operator-token","principal":"deployer"}}"#,
  )
  .await
  else {
    return;
  };
  assert!(
    unauthorized_response.starts_with("HTTP/1.1 403 Forbidden")
      && !unauthorized_response.contains(r#""resource":"oxibelt:oxibelt:ipm:principal/operator""#)
      && !unauthorized_response.contains("belongs to principal"),
    "credential owner mismatch must not reveal the actual owner before owner authorization: {}",
    log_safe_text(&unauthorized_response)
  );

  let Some(authorized_response) = try_scoped_admin_response(
    "ipm-simulate-credential-mismatch-authorized",
    ipm_simulate_principal_wildcard_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"credential":"operator-token","principal":"deployer"}}"#,
  )
  .await
  else {
    return;
  };
  assert!(
    authorized_response.starts_with("HTTP/1.1 400 Bad Request")
      && authorized_response
        .contains("IPM credential operator-token belongs to principal operator, not deployer"),
    "authorized caller should keep the post-authorization mismatch validation error: {}",
    log_safe_text(&authorized_response)
  );
}

#[tokio::test]
async fn ipm_simulate_credential_owner_authorized_still_simulates() {
  let Some(response) = try_scoped_admin_response(
    "ipm-simulate-credential-owner-authorized",
    ipm_simulate_principal_wildcard_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"credential":"operator-token"}}"#,
  )
  .await
  else {
    return;
  };

  assert!(
    response.starts_with("HTTP/1.1 200 OK") && response.contains(r#""principal":"operator""#),
    "authorized credential simulation should still reach normal simulation: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn ipm_simulate_authorized_unknown_credential_returns_bad_request() {
  let Some(response) = try_scoped_admin_response(
    "ipm-simulate-credential-unknown-authorized",
    ipm_simulate_principal_wildcard_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","target":{"credential":"missing-token"}}"#,
  )
  .await
  else {
    return;
  };

  assert!(
    response.starts_with("HTTP/1.1 400 Bad Request")
      && response.contains("unknown IPM credential missing-token"),
    "caller authorized for credential and principal wildcards should keep unknown credential validation: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn ipm_simulate_overlay_unknown_references_require_resources_first() {
  let Some(response) = try_scoped_admin_response(
    "ipm-simulate-overlay-unknown-preauth",
    ipm_simulate_policy_status_only_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","overlay":{"bindings":[{"group":"ghosts","policy":"missing"}]}}"#,
  )
  .await
  else {
    return;
  };

  assert!(
    response.starts_with("HTTP/1.1 403 Forbidden")
      && response.contains(r#""action":"ipm:SimulatePolicy""#)
      && response.contains(r#""resource":"oxibelt:oxibelt:ipm:policy/missing""#)
      && !response.contains("unknown policy"),
    "unknown overlay references must not be enumerated before resource authorization: {}",
    log_safe_text(&response)
  );
}

#[tokio::test]
async fn ipm_simulate_authorized_unknown_overlay_reference_returns_bad_request() {
  let Some(response) = try_scoped_admin_response(
    "ipm-simulate-overlay-unknown-authorized",
    ipm_simulate_policy_wildcard_config,
    "POST",
    "/admin/v1/ipm/simulate",
    r#"{"action":"config:GetStatus","resource":"oxibelt:oxibelt:config:*","overlay":{"bindings":[{"group":"ghosts","policy":"missing"}]}}"#,
  )
  .await
  else {
    return;
  };

  assert!(
    response.starts_with("HTTP/1.1 400 Bad Request")
      && response.contains("references unknown policy missing"),
    "authorized unknown overlay reference should keep validation behavior: {}",
    log_safe_text(&response)
  );
}

fn ipm_simulate_principal_wildcard_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_simulation_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["ipm:SimulatePrincipal"]
resources = [
  "oxibelt:oxibelt:ipm:simulation/current",
  "oxibelt:oxibelt:ipm:principal/*",
  "oxibelt:oxibelt:ipm:credential/*",
  "oxibelt:oxibelt:ipm:group/*",
]
"#,
  )
}

fn ipm_simulate_credential_only_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_simulation_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["ipm:SimulatePrincipal"]
resources = [
  "oxibelt:oxibelt:ipm:simulation/current",
  "oxibelt:oxibelt:ipm:credential/operator-token",
]
"#,
  )
}

fn ipm_simulate_credential_wildcard_only_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_simulation_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["ipm:SimulatePrincipal"]
resources = [
  "oxibelt:oxibelt:ipm:simulation/current",
  "oxibelt:oxibelt:ipm:credential/*",
]
"#,
  )
}

fn ipm_simulate_credential_and_deployer_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_simulation_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["ipm:SimulatePrincipal"]
resources = [
  "oxibelt:oxibelt:ipm:simulation/current",
  "oxibelt:oxibelt:ipm:credential/operator-token",
  "oxibelt:oxibelt:ipm:principal/deployer",
]
"#,
  )
}

fn ipm_simulate_policy_wildcard_config(
  cert_path: &Path,
  key_path: &Path,
  admin_bind: SocketAddr,
) -> Config {
  parse_simulation_config(
    cert_path,
    key_path,
    admin_bind,
    r#"
[[ipm.policies.statements]]
effect = "allow"
actions = ["ipm:SimulatePolicy"]
resources = [
  "oxibelt:oxibelt:ipm:simulation/current",
  "oxibelt:oxibelt:ipm:policy/*",
  "oxibelt:oxibelt:ipm:binding/*",
  "oxibelt:oxibelt:ipm:principal/*",
  "oxibelt:oxibelt:ipm:group/*",
]
"#,
  )
}
