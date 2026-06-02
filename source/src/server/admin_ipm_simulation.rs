use ::http::{Response, StatusCode};
use hyper::body::Incoming;

use crate::ipm::{IpmSimulationAuthorizationRequirements, IpmSimulationRequest};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_json;
use super::admin_ipm::ipm_error_response;
use super::admin_resource;

fn allowed(authorization: &AdminAuthorization<'_>, action: &str, resource_name: &str) -> bool {
  authorization.is_allowed(action, resource_name)
}

fn allowed_silently(
  authorization: &AdminAuthorization<'_>,
  action: &str,
  resource_name: &str,
) -> bool {
  authorization.is_allowed_silently(action, resource_name)
}

pub(super) async fn simulation_response(
  request: hyper::Request<Incoming>,
  authorization: &AdminAuthorization<'_>,
) -> Response<ProxyBody> {
  let body = match collect_admin_json::<IpmSimulationRequest>(request).await {
    Ok(body) => body,
    Err(response) => return response,
  };
  let requires_principal = body.requires_principal_simulation();
  let requires_policy = body.requires_policy_simulation();
  if requires_principal
    && !allowed(
      authorization,
      "ipm:SimulatePrincipal",
      admin_resource::ipm_simulation(),
    )
  {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if requires_policy
    && !allowed(
      authorization,
      "ipm:SimulatePolicy",
      admin_resource::ipm_simulation(),
    )
  {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if !requires_principal
    && !requires_policy
    && !allowed(
      authorization,
      "ipm:SimulateSelf",
      admin_resource::ipm_simulation(),
    )
  {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }

  let preliminary = body.preliminary_authorization_requirements();
  if requires_principal && !authorize_simulation_target_requirements(authorization, &preliminary) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if requires_policy && !authorize_simulation_overlay_requirements(authorization, &preliminary) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }

  if requires_principal {
    let credential_preflight = body.credential_owner_preflight(authorization.ipm);
    if !authorize_sensitive_simulation_target_requirements(
      authorization,
      &credential_preflight.requirements,
    ) {
      return text_response(StatusCode::FORBIDDEN, "forbidden");
    }
    if !credential_preflight.unresolved_credentials.is_empty()
      && !allowed_silently(
        authorization,
        "ipm:SimulatePrincipal",
        admin_resource::ipm_principal_wildcard(),
      )
    {
      return text_response(StatusCode::FORBIDDEN, "forbidden");
    }
  }

  let prepared = match authorization.ipm.admin_prepare_simulation(
    authorization.actor,
    authorization.context(),
    body,
  ) {
    Ok(prepared) => prepared,
    Err(error) => return ipm_error_response(error),
  };
  if requires_principal
    && !authorize_simulation_target_requirements(authorization, &prepared.requirements)
  {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if requires_policy
    && !authorize_simulation_overlay_requirements(authorization, &prepared.requirements)
  {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  json_response(StatusCode::OK, &prepared.response)
}

fn authorize_simulation_target_requirements(
  authorization: &AdminAuthorization<'_>,
  requirements: &IpmSimulationAuthorizationRequirements,
) -> bool {
  for principal in &requirements.target_principals {
    let resource = admin_resource::ipm_principal(principal);
    if !allowed(authorization, "ipm:SimulatePrincipal", &resource) {
      return false;
    }
  }
  for credential in &requirements.target_credentials {
    let resource = admin_resource::ipm_credential(credential);
    if !allowed(authorization, "ipm:SimulatePrincipal", &resource) {
      return false;
    }
  }
  for group in &requirements.target_groups {
    let resource = admin_resource::ipm_group(group);
    if !allowed(authorization, "ipm:SimulatePrincipal", &resource) {
      return false;
    }
  }
  true
}

fn authorize_sensitive_simulation_target_requirements(
  authorization: &AdminAuthorization<'_>,
  requirements: &IpmSimulationAuthorizationRequirements,
) -> bool {
  for principal in &requirements.target_principals {
    let resource = admin_resource::ipm_principal(principal);
    if !allowed_silently(authorization, "ipm:SimulatePrincipal", &resource) {
      return false;
    }
  }
  for credential in &requirements.target_credentials {
    let resource = admin_resource::ipm_credential(credential);
    if !allowed_silently(authorization, "ipm:SimulatePrincipal", &resource) {
      return false;
    }
  }
  for group in &requirements.target_groups {
    let resource = admin_resource::ipm_group(group);
    if !allowed_silently(authorization, "ipm:SimulatePrincipal", &resource) {
      return false;
    }
  }
  true
}

fn authorize_simulation_overlay_requirements(
  authorization: &AdminAuthorization<'_>,
  requirements: &IpmSimulationAuthorizationRequirements,
) -> bool {
  for policy in &requirements.overlay_policies {
    let resource = admin_resource::ipm_policy(policy);
    if !allowed(authorization, "ipm:SimulatePolicy", &resource) {
      return false;
    }
  }
  for binding in &requirements.overlay_bindings {
    let resource = admin_resource::ipm_binding(binding);
    if !allowed(authorization, "ipm:SimulatePolicy", &resource) {
      return false;
    }
  }
  for principal in &requirements.overlay_principals {
    let resource = admin_resource::ipm_principal(principal);
    if !allowed(authorization, "ipm:SimulatePolicy", &resource) {
      return false;
    }
  }
  for group in &requirements.overlay_groups {
    let resource = admin_resource::ipm_group(group);
    if !allowed(authorization, "ipm:SimulatePolicy", &resource) {
      return false;
    }
  }
  true
}
