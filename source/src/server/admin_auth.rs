use hyper::body::Incoming;
use ring::digest;
use subtle::ConstantTimeEq;

use crate::admin_tokens::{AdminTokenRuntime, VerifiedAdminToken};
use crate::config::{AdminConfig, AdminPermission, AdminRole};

#[derive(Debug, Clone)]
pub(super) struct AdminActor {
  pub(super) name: String,
  pub(super) roles: Vec<AdminRole>,
  pub(super) permissions: Vec<AdminPermission>,
  pub(super) deny_permissions: Vec<AdminPermission>,
}

pub(super) fn admin_actor(
  request: &hyper::Request<Incoming>,
  config: &AdminConfig,
  token_runtime: &AdminTokenRuntime,
) -> Option<AdminActor> {
  let actual = request
    .headers()
    .get(::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.strip_prefix("Bearer "))?;
  if config.token_store.enabled {
    return token_runtime.verify_bearer(actual).map(AdminActor::from);
  }
  if bearer_token_matches_env(&config.bearer_token_env, actual) {
    return Some(AdminActor {
      name: "admin".to_string(),
      roles: vec![AdminRole::Admin],
      permissions: Vec::new(),
      deny_permissions: Vec::new(),
    });
  }
  for token in &config.rbac.tokens {
    if bearer_token_matches_env(&token.bearer_token_env, actual) {
      return Some(AdminActor {
        name: token.name.clone(),
        roles: token.roles.clone(),
        permissions: token.permissions.clone(),
        deny_permissions: token.deny_permissions.clone(),
      });
    }
  }
  None
}

impl From<VerifiedAdminToken> for AdminActor {
  fn from(token: VerifiedAdminToken) -> Self {
    Self {
      name: token.name,
      roles: token.roles,
      permissions: token.permissions,
      deny_permissions: token.deny_permissions,
    }
  }
}

fn bearer_token_matches_env(env_name: &str, actual: &str) -> bool {
  std::env::var(env_name)
    .ok()
    .is_some_and(|expected| bearer_token_matches_expected(&expected, actual))
}

fn bearer_token_matches_expected(expected: &str, actual: &str) -> bool {
  if expected.is_empty() {
    return false;
  }
  let expected_digest = digest::digest(&digest::SHA256, expected.as_bytes());
  let actual_digest = digest::digest(&digest::SHA256, actual.as_bytes());
  expected_digest
    .as_ref()
    .ct_eq(actual_digest.as_ref())
    .into()
}

pub(super) fn admin_actor_has_role(actor: &AdminActor, role: AdminRole) -> bool {
  actor.roles.contains(&AdminRole::Admin) || actor.roles.contains(&role)
}

pub(super) fn admin_actor_has_any_role(actor: &AdminActor, roles: &[AdminRole]) -> bool {
  actor.roles.contains(&AdminRole::Admin) || roles.iter().any(|role| actor.roles.contains(role))
}

pub(super) fn admin_actor_has_permission(actor: &AdminActor, permission: AdminPermission) -> bool {
  if actor.deny_permissions.contains(&permission) {
    return false;
  }
  actor.permissions.contains(&permission)
    || actor.roles.contains(&AdminRole::Admin)
    || actor_role_grants_permission(actor, permission)
}

fn actor_role_grants_permission(actor: &AdminActor, permission: AdminPermission) -> bool {
  actor.roles.iter().any(|role| match role {
    AdminRole::ConfigOperator => matches!(
      permission,
      AdminPermission::ConfigRead
        | AdminPermission::ConfigValidate
        | AdminPermission::ConfigDiff
        | AdminPermission::ConfigLoad
        | AdminPermission::ConfigRollback
        | AdminPermission::FilesSyncConfig
        | AdminPermission::FilesSyncOxiRule
        | AdminPermission::FilesSyncOxiRuleGroup
        | AdminPermission::FilesDelete
        | AdminPermission::TlsDownstreamRead
        | AdminPermission::TlsDownstreamReload
    ),
    AdminRole::Viewer => matches!(
      permission,
      AdminPermission::ConfigRead | AdminPermission::TlsDownstreamRead
    ),
    _ => false,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn bearer_token_matches_expected_uses_digest_comparison_without_changing_semantics() {
    assert!(bearer_token_matches_expected(
      "secret-token",
      "secret-token"
    ));
    assert!(!bearer_token_matches_expected("secret-token", "secret"));
    assert!(!bearer_token_matches_expected(
      "secret-token",
      "secret-token-extra"
    ));
  }

  #[test]
  fn bearer_token_matches_expected_rejects_empty_expected_tokens() {
    assert!(!bearer_token_matches_expected("", ""));
    assert!(!bearer_token_matches_expected("", "secret-token"));
  }
}
