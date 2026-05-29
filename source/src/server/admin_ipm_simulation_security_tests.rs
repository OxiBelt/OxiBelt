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
      && resolved_response.contains(r#""resource":"oxibelt:oxibelt:ipm:principal/operator""#),
    "credential simulation should also require the resolved principal resource: {}",
    log_safe_text(&resolved_response)
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
