use hyper::body::Incoming;

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
) -> Option<AdminActor> {
  let actual = request
    .headers()
    .get(::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.strip_prefix("Bearer "))?;
  if std::env::var(&config.bearer_token_env)
    .ok()
    .is_some_and(|expected| !expected.is_empty() && expected == actual)
  {
    return Some(AdminActor {
      name: "admin".to_string(),
      roles: vec![AdminRole::Admin],
      permissions: Vec::new(),
      deny_permissions: Vec::new(),
    });
  }
  for token in &config.rbac.tokens {
    if std::env::var(&token.bearer_token_env)
      .ok()
      .is_some_and(|expected| !expected.is_empty() && expected == actual)
    {
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
