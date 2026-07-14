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
fn active_mutation_trust_root_cannot_replace_itself() {
  let (_temp_dir, mut active) = load_temp_config("mutation-trust-root-scope");
  active.admin.mutations.mode = crate::config::AdminMutationMode::Optional;
  let mut candidate = active.clone();
  candidate.admin.mutations.backend = Some("replacement-ledger".to_string());

  let response = validate_control_plane_config_scope(
    ControlPlaneConfigPermissions {
      admin_update_config: true,
      ipm_update_config: true,
    },
    &active,
    &candidate,
  )
  .expect_err("an in-flight mutation must not replace its trust root");

  assert_eq!(response.status, StatusCode::CONFLICT);
  assert!(
    response.body["error"]
      .as_str()
      .expect("error should be a string")
      .contains("trust root")
  );
}

#[test]
fn disabled_mutation_runtime_cannot_be_enabled_by_hot_admin_load() {
  let (_temp_dir, active) = load_temp_config("mutation-runtime-enable-scope");
  let mut candidate = active.clone();
  candidate.admin.mutations.mode = crate::config::AdminMutationMode::Optional;

  let response = validate_control_plane_config_scope(
    ControlPlaneConfigPermissions {
      admin_update_config: true,
      ipm_update_config: true,
    },
    &active,
    &candidate,
  )
  .expect_err("mutation runtime activation must require a restart");

  assert_eq!(response.status, StatusCode::CONFLICT);
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

#[tokio::test]
async fn oxirule_reload_snapshot_recomputes_person_proof_request_path_features() {
  let temp_dir = common::TempDir::new("admin-oxirule-person-proof-features");
  let (cert_path, key_path) =
    common::create_self_signed_cert(temp_dir.path(), "admin-oxirule-person-proof-features");
  let base_raw = common::minimal_config_toml(&cert_path, &key_path);
  let base_config: Config = toml::from_str(&base_raw).expect("base config should parse");
  base_config.validate().expect("base config should validate");
  let active = AppSnapshot::new(base_config)
    .await
    .expect("base snapshot should initialize");
  assert!(!active.waf.has_person_proof_api_paths());
  assert!(!active.request_path_features.person_proof_api);

  let candidate_raw = format!(
    "{}\n{}",
    base_raw,
    r#"
[waf]
enabled = true

[[waf.rules]]
name = "proof"
phase = "request"
priority = 10
when = "Request.Http.Path == '/protected'"

[[waf.rules.actions]]
type = "require_person_proof"
difficulty = 4
token_validity_seconds = 60
"#
  );
  let config: Config = toml::from_str(&candidate_raw).expect("candidate config should parse");
  config.validate().expect("candidate config should validate");
  assert!(active.config.non_waf_equivalent(&config));
  assert!(!active.config.waf_equivalent(&config));
  let waf = WafEngine::new_with_previous_limits_and_mitigation(
    &config,
    Some(&active.waf),
    active.shared_state.clone(),
    Some(active.limits.clone()),
    active.mitigation.clone(),
  )
  .expect("candidate WAF should rebuild");

  let snapshot = build_oxirule_reload_snapshot(&active, config, waf);

  assert!(snapshot.waf.has_person_proof_api_paths());
  assert!(
    snapshot
      .waf
      .has_person_proof_api_path("/.oxibelt/person-proof/session")
  );
  assert!(snapshot.request_path_features.person_proof_api);
}
