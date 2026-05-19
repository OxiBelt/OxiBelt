use ::http::StatusCode;

use crate::config::Config;

use super::AdminControlResponse;

pub(super) fn validate_admin_config_load_scope(
  actor_is_admin: bool,
  active: &Config,
  candidate: &Config,
) -> Result<(), AdminControlResponse> {
  if actor_is_admin || active.admin == candidate.admin {
    return Ok(());
  }
  Err(AdminControlResponse::error(
    StatusCode::FORBIDDEN,
    "admin configuration changes require admin role",
  ))
}
