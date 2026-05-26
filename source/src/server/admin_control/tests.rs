use ::http::StatusCode;

use super::*;

mod common {
  include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/rust/common/mod.rs"
  ));
}

fn load_temp_config(name: &str) -> (common::TempDir, Config) {
  let temp_dir = common::TempDir::new(name);
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  std::fs::create_dir_all(&config_dir).expect("config dir should be created");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, name);
  let config_path = config_dir.join("oxibelt.toml");
  std::fs::write(
    &config_path,
    common::minimal_config_toml_with_paths(
      cert_path.file_name().unwrap().to_str().unwrap(),
      key_path.file_name().unwrap().to_str().unwrap(),
    ),
  )
  .expect("config should be written");
  let config = Config::load(&config_path).expect("config should load");
  (temp_dir, config)
}

#[test]
fn non_admin_config_load_cannot_change_admin_config() {
  let (_temp_dir, active) = load_temp_config("admin-load-scope");
  let mut candidate = active.clone();
  candidate.admin.bearer_token_env = "OXIBELT_ESCALATED_ADMIN_TOKEN".to_string();

  let response = validate_control_plane_config_scope(
    ControlPlaneConfigPermissions::default(),
    &active,
    &candidate,
  )
  .expect_err("actor without admin:UpdateConfig should not change admin config");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
}

#[test]
fn config_load_cannot_change_ipm_without_ipm_management_permission() {
  let (_temp_dir, active) = load_temp_config("ipm-load-scope");
  let mut candidate = active.clone();
  candidate.ipm.enabled = true;

  let response = validate_control_plane_config_scope(
    ControlPlaneConfigPermissions::default(),
    &active,
    &candidate,
  )
  .expect_err("actor without ipm:UpdateConfig should not change IPM config");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
}

#[test]
fn admin_config_load_scope_allows_ipm_manager_or_non_control_plane_changes() {
  let (_temp_dir, active) = load_temp_config("admin-load-scope-allowed");
  let mut candidate = active.clone();
  candidate.logging.level = "debug".to_string();

  assert!(
    validate_control_plane_config_scope(
      ControlPlaneConfigPermissions::default(),
      &active,
      &candidate
    )
    .is_ok()
  );

  candidate.admin.bearer_token_env = "OXIBELT_ESCALATED_ADMIN_TOKEN".to_string();
  assert!(
    validate_control_plane_config_scope(
      ControlPlaneConfigPermissions {
        admin_update_config: true,
        ipm_update_config: false,
      },
      &active,
      &candidate
    )
    .is_ok()
  );

  candidate = active.clone();
  candidate.ipm.enabled = true;
  assert!(
    validate_control_plane_config_scope(
      ControlPlaneConfigPermissions {
        admin_update_config: false,
        ipm_update_config: true,
      },
      &active,
      &candidate
    )
    .is_ok()
  );
}

#[test]
fn control_plane_scope_requires_both_permissions_when_admin_and_ipm_change() {
  let (_temp_dir, active) = load_temp_config("control-plane-both");
  let mut candidate = active.clone();
  candidate.admin.bearer_token_env = "OXIBELT_ESCALATED_ADMIN_TOKEN".to_string();
  candidate.ipm.enabled = true;

  let response = validate_control_plane_config_scope(
    ControlPlaneConfigPermissions {
      admin_update_config: true,
      ipm_update_config: false,
    },
    &active,
    &candidate,
  )
  .expect_err("IPM change should still require ipm:UpdateConfig");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
  assert!(
    response.body["error"]
      .as_str()
      .expect("error should be a string")
      .contains("ipm:UpdateConfig")
  );
}

#[test]
fn rollback_scope_uses_current_to_snapshot_delta() {
  let (_temp_dir, snapshot) = load_temp_config("control-plane-rollback");
  let mut current = snapshot.clone();
  current.admin.bearer_token_env = "OXIBELT_ESCALATED_ADMIN_TOKEN".to_string();
  current.ipm.enabled = true;

  let response = validate_control_plane_config_scope(
    ControlPlaneConfigPermissions {
      admin_update_config: true,
      ipm_update_config: false,
    },
    &current,
    &snapshot,
  )
  .expect_err("rollback snapshot should require the permissions for protected deltas");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
  assert!(
    response.body["error"]
      .as_str()
      .expect("error should be a string")
      .contains("ipm:UpdateConfig")
  );

  validate_control_plane_config_scope(
    ControlPlaneConfigPermissions {
      admin_update_config: true,
      ipm_update_config: true,
    },
    &current,
    &snapshot,
  )
  .expect("rollback should pass when both protected config permissions are present");
}
