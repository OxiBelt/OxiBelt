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

  let response = validate_admin_config_load_scope(false, &active, &candidate)
    .expect_err("non-admin actor should not change admin config");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
}

#[test]
fn admin_config_load_scope_allows_admin_or_non_admin_non_admin_changes() {
  let (_temp_dir, active) = load_temp_config("admin-load-scope-allowed");
  let mut candidate = active.clone();
  candidate.logging.level = "debug".to_string();

  assert!(validate_admin_config_load_scope(false, &active, &candidate).is_ok());

  candidate.admin.bearer_token_env = "OXIBELT_ESCALATED_ADMIN_TOKEN".to_string();
  assert!(validate_admin_config_load_scope(true, &active, &candidate).is_ok());
}
