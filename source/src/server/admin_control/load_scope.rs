use ::http::StatusCode;

use crate::config::Config;

use super::AdminControlResponse;

pub(super) fn validate_admin_config_load_scope(
  actor_can_manage_ipm: bool,
  active: &Config,
  candidate: &Config,
) -> Result<(), AdminControlResponse> {
  if actor_can_manage_ipm || (active.admin == candidate.admin && active.ipm == candidate.ipm) {
    return Ok(());
  }
  Err(AdminControlResponse::error(
    StatusCode::FORBIDDEN,
    "admin or IPM configuration changes require ipm:*",
  ))
}
