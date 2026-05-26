use ::http::StatusCode;

use crate::config::Config;

use super::AdminControlResponse;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ControlPlaneConfigPermissions {
  pub(crate) admin_update_config: bool,
  pub(crate) ipm_update_config: bool,
}

impl ControlPlaneConfigPermissions {
  pub(crate) fn can_update_all(self) -> bool {
    self.admin_update_config && self.ipm_update_config
  }
}

pub(crate) fn validate_control_plane_config_scope(
  permissions: ControlPlaneConfigPermissions,
  active: &Config,
  candidate: &Config,
) -> Result<(), AdminControlResponse> {
  let mut missing = Vec::new();
  if active.admin != candidate.admin && !permissions.admin_update_config {
    missing.push("admin:UpdateConfig");
  }
  if active.ipm != candidate.ipm && !permissions.ipm_update_config {
    missing.push("ipm:UpdateConfig");
  }
  if missing.is_empty() {
    return Ok(());
  }
  Err(AdminControlResponse::error(
    StatusCode::FORBIDDEN,
    format!(
      "admin or IPM configuration changes require {}",
      missing.join(" and ")
    ),
  ))
}
