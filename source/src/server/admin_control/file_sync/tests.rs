use super::*;
use crate::server::admin_control::{
  AdminFileOperation, AdminFileOperationKind, AdminFileRoot, AdminFilesSyncRequest,
  ControlPlaneConfigPermissions,
};
use std::path::Path;

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
  let oxirule_dir = temp_dir.path().join("oxirule");
  std::fs::create_dir_all(&config_dir).expect("config dir should be created");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
  std::fs::create_dir_all(&oxirule_dir).expect("oxirule dir should be created");
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

fn load_temp_config_with_include(name: &str) -> (common::TempDir, Config) {
  let temp_dir = common::TempDir::new(name);
  let config_dir = temp_dir.path().join("config");
  let cert_dir = temp_dir.path().join("cert");
  let oxirule_dir = temp_dir.path().join("oxirule");
  std::fs::create_dir_all(&config_dir).expect("config dir should be created");
  std::fs::create_dir_all(&cert_dir).expect("cert dir should be created");
  std::fs::create_dir_all(&oxirule_dir).expect("oxirule dir should be created");
  let (cert_path, key_path) = common::create_self_signed_cert(&cert_dir, name);
  let config_path = config_dir.join("oxibelt.toml");
  let included_path = config_dir.join("included.toml");
  std::fs::write(&config_path, "include = \"included.toml\"\n")
    .expect("config entry should be written");
  std::fs::write(
    &included_path,
    common::minimal_config_toml_with_paths(
      cert_path.file_name().unwrap().to_str().unwrap(),
      key_path.file_name().unwrap().to_str().unwrap(),
    ),
  )
  .expect("included config should be written");
  let config = Config::load(&config_path).expect("config should load");
  (temp_dir, config)
}

fn config_dir(config: &Config) -> &Path {
  config
    .source_paths
    .config_dir
    .as_deref()
    .expect("config dir should be set")
}

fn included_config_content(config: &Config) -> String {
  std::fs::read_to_string(config_dir(config).join("included.toml"))
    .expect("included config should be readable")
}

#[cfg(unix)]
fn create_config_alias(config: &Config, alias: &str) {
  std::os::unix::fs::symlink(".", config_dir(config).join(alias))
    .expect("config alias symlink should be created");
}

fn put_request(root: AdminFileRoot, path: &str, content: &str) -> AdminFilesSyncRequest {
  AdminFilesSyncRequest {
    apply: AdminApplyMode::None,
    operations: vec![AdminFileOperation {
      op: AdminFileOperationKind::Put,
      root,
      path: path.to_string(),
      expected_sha256: None,
      content: Some(content.to_string()),
    }],
  }
}

fn delete_request(root: AdminFileRoot, path: &str) -> AdminFilesSyncRequest {
  AdminFilesSyncRequest {
    apply: AdminApplyMode::None,
    operations: vec![AdminFileOperation {
      op: AdminFileOperationKind::Delete,
      root,
      path: path.to_string(),
      expected_sha256: None,
      content: None,
    }],
  }
}

fn config_entry_relative_path(config: &Config) -> String {
  let config_dir = config
    .source_paths
    .config_dir
    .as_ref()
    .expect("config dir should be set");
  config
    .source_paths
    .config_entry
    .as_ref()
    .expect("config entry should be set")
    .strip_prefix(config_dir)
    .expect("config entry should be under config dir")
    .to_string_lossy()
    .to_string()
}

fn config_entry_content(config: &Config) -> String {
  std::fs::read_to_string(
    config
      .source_paths
      .config_entry
      .as_ref()
      .expect("config entry should be set"),
  )
  .expect("config should be readable")
}

fn put_config_entry(
  config: &Config,
  content: String,
  apply: AdminApplyMode,
) -> AdminFilesSyncRequest {
  AdminFilesSyncRequest {
    apply,
    operations: vec![AdminFileOperation {
      op: AdminFileOperationKind::Put,
      root: AdminFileRoot::Config,
      path: config_entry_relative_path(config),
      expected_sha256: None,
      content: Some(content),
    }],
  }
}

#[test]
fn file_sync_scope_rejects_staged_admin_config_change_without_permission() {
  let (_temp_dir, config) = load_temp_config("file-sync-admin-scope");
  let candidate = config_entry_content(&config)
    + "\n[admin]\nbearer_token_env = \"OXIBELT_ESCALATED_ADMIN_TOKEN\"\n";
  let request = put_config_entry(&config, candidate, AdminApplyMode::None);

  let response = validate_file_sync_control_plane_scope(
    &request,
    &config,
    ControlPlaneConfigPermissions::default(),
  )
  .expect_err("admin config staging should require admin:UpdateConfig");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
  assert!(
    response.body["error"]
      .as_str()
      .expect("error should be a string")
      .contains("admin:UpdateConfig")
  );
}

#[test]
fn file_sync_scope_rejects_staged_ipm_config_change_without_permission() {
  let (_temp_dir, config) = load_temp_config("file-sync-ipm-scope");
  let candidate = config_entry_content(&config) + "\n[ipm]\nenabled = true\n";
  let request = put_config_entry(&config, candidate, AdminApplyMode::OxiRule);

  let response = validate_file_sync_control_plane_scope(
    &request,
    &config,
    ControlPlaneConfigPermissions::default(),
  )
  .expect_err("IPM config staging should require ipm:UpdateConfig");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
  assert!(
    response.body["error"]
      .as_str()
      .expect("error should be a string")
      .contains("ipm:UpdateConfig")
  );
}

#[test]
fn file_sync_scope_rejects_downstream_tls_staging_of_control_plane_config() {
  let (_temp_dir, config) = load_temp_config("file-sync-downstream-tls-scope");
  let candidate = config_entry_content(&config)
    + "\n[admin]\nbind = \"127.0.0.1:19092\"\n[ipm]\nenabled = true\n";
  let request = put_config_entry(&config, candidate, AdminApplyMode::DownstreamTls);

  let response = validate_file_sync_control_plane_scope(
    &request,
    &config,
    ControlPlaneConfigPermissions {
      admin_update_config: true,
      ipm_update_config: false,
    },
  )
  .expect_err("downstream TLS apply should still protect staged IPM changes");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
  assert!(
    response.body["error"]
      .as_str()
      .expect("error should be a string")
      .contains("ipm:UpdateConfig")
  );
}

#[test]
fn file_sync_scope_rejects_full_reload_of_protected_disk_candidate() {
  let (_temp_dir, config) = load_temp_config("file-sync-full-disk-scope");
  let config_entry = config
    .source_paths
    .config_entry
    .as_ref()
    .expect("config entry should be set");
  let original = config_entry_content(&config);
  std::fs::write(
    config_entry,
    original + "\n[admin]\nbind = \"127.0.0.1:19092\"\n",
  )
  .expect("disk config should be changed");
  let mut request = put_request(
    AdminFileRoot::OxiRule,
    "rules/noop.oxirule.toml",
    "when = \"true\"\n",
  );
  request.apply = AdminApplyMode::Full;

  let response = validate_file_sync_control_plane_scope(
    &request,
    &config,
    ControlPlaneConfigPermissions::default(),
  )
  .expect_err("full reload should require admin:UpdateConfig for protected disk candidate");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
  assert!(
    response.body["error"]
      .as_str()
      .expect("error should be a string")
      .contains("admin:UpdateConfig")
  );
}

#[test]
fn file_sync_scope_allows_regular_config_changes_without_control_plane_permission() {
  let (_temp_dir, config) = load_temp_config("file-sync-regular-scope");
  let candidate = config_entry_content(&config).replace("level = \"info\"", "level = \"debug\"");
  let request = put_config_entry(&config, candidate, AdminApplyMode::Full);

  validate_file_sync_control_plane_scope(
    &request,
    &config,
    ControlPlaneConfigPermissions::default(),
  )
  .expect("non-control-plane config changes should keep existing config permissions sufficient");
}

#[cfg(unix)]
#[test]
fn file_sync_scope_rejects_symlinked_config_alias_admin_change_without_permission() {
  let (_temp_dir, config) = load_temp_config_with_include("file-sync-symlink-scope");
  create_config_alias(&config, "alias");
  let candidate = included_config_content(&config) + "\n[admin]\nbind = \"127.0.0.1:19092\"\n";
  let mut request = put_request(AdminFileRoot::Config, "alias/included.toml", &candidate);
  request.apply = AdminApplyMode::Full;

  let response = validate_file_sync_control_plane_scope(
    &request,
    &config,
    ControlPlaneConfigPermissions::default(),
  )
  .expect_err("symlinked config alias should not hide staged admin changes");

  assert_eq!(response.status, StatusCode::FORBIDDEN);
  assert!(
    response.body["error"]
      .as_str()
      .expect("error should be a string")
      .contains("admin:UpdateConfig")
  );
}

#[cfg(unix)]
#[test]
fn file_sync_rejects_duplicate_canonical_config_targets() {
  let (_temp_dir, config) = load_temp_config_with_include("file-sync-duplicate-canonical");
  create_config_alias(&config, "alias");
  let original = included_config_content(&config);
  let request = AdminFilesSyncRequest {
    apply: AdminApplyMode::None,
    operations: vec![
      AdminFileOperation {
        op: AdminFileOperationKind::Put,
        root: AdminFileRoot::Config,
        path: "included.toml".to_string(),
        expected_sha256: None,
        content: Some(original.replace("level = \"info\"", "level = \"debug\"")),
      },
      AdminFileOperation {
        op: AdminFileOperationKind::Put,
        root: AdminFileRoot::Config,
        path: "alias/included.toml".to_string(),
        expected_sha256: None,
        content: Some(original.replace("level = \"info\"", "level = \"warn\"")),
      },
    ],
  };

  let precheck_error =
    config_file_overrides(&request, &config).expect_err("duplicate aliases should be rejected");
  assert!(
    precheck_error
      .to_string()
      .contains("multiple config operations")
  );

  let commit_error = match commit_file_sync(&request, &config) {
    Ok(_) => panic!("duplicate aliases should not be committed"),
    Err(error) => error,
  };
  assert!(
    commit_error
      .to_string()
      .contains("multiple config operations")
  );
  assert_eq!(included_config_content(&config), original);
}

#[test]
fn file_sync_rejects_path_escape_and_checksum_mismatch() {
  let (_temp_dir, config) = load_temp_config("admin-file-sync-rejects");
  let escaped = AdminFilesSyncRequest {
    apply: AdminApplyMode::None,
    operations: vec![AdminFileOperation {
      op: AdminFileOperationKind::Put,
      root: AdminFileRoot::Config,
      path: "../escape.toml".to_string(),
      expected_sha256: None,
      content: Some("[config]\n".to_string()),
    }],
  };
  assert!(commit_file_sync(&escaped, &config).is_err());

  let mismatch = AdminFilesSyncRequest {
    apply: AdminApplyMode::None,
    operations: vec![AdminFileOperation {
      op: AdminFileOperationKind::Put,
      root: AdminFileRoot::Config,
      path: "oxibelt.toml".to_string(),
      expected_sha256: Some("00".repeat(32)),
      content: Some("[config]\n".to_string()),
    }],
  };
  assert!(commit_file_sync(&mismatch, &config).is_err());
}

#[test]
fn file_sync_put_accepts_oxirule_rule_files() {
  let (_temp_dir, config) = load_temp_config("admin-file-sync-rule");
  let valid = put_request(
    AdminFileRoot::OxiRule,
    "rules/main.oxirule.toml",
    "when = \"true\"\n",
  );

  let committed = commit_file_sync(&valid, &config).expect("rule file should sync");
  assert_eq!(committed.len(), 1);
  let rule_path = config
    .source_paths
    .oxirule_dir
    .as_ref()
    .expect("oxirule dir should be set")
    .join("rules/main.oxirule.toml");
  assert_eq!(
    std::fs::read_to_string(rule_path).expect("rule file should be written"),
    "when = \"true\"\n"
  );
}

#[test]
fn file_sync_put_validates_oxirule_group_files() {
  let (_temp_dir, config) = load_temp_config("admin-file-sync-group");
  let valid = AdminFilesSyncRequest {
    apply: AdminApplyMode::None,
    operations: vec![AdminFileOperation {
      op: AdminFileOperationKind::Put,
      root: AdminFileRoot::OxiRuleGroup,
      path: "groups/main.oxirule-group.toml".to_string(),
      expected_sha256: None,
      content: Some(
        r#"
[[rule_groups]]
name = "synced-group"
when = "true"
"#
        .to_string(),
      ),
    }],
  };
  let committed = commit_file_sync(&valid, &config).expect("group file should sync");
  assert_eq!(committed.len(), 1);

  let invalid = AdminFilesSyncRequest {
    apply: AdminApplyMode::None,
    operations: vec![AdminFileOperation {
      op: AdminFileOperationKind::Put,
      root: AdminFileRoot::OxiRuleGroup,
      path: "groups/bad.oxirule-group.toml".to_string(),
      expected_sha256: None,
      content: Some("[[rule_groups]]\nname = ''\n".to_string()),
    }],
  };
  assert!(commit_file_sync(&invalid, &config).is_err());
}

#[test]
fn file_sync_put_validates_oxirule_rulepack_files() {
  let (_temp_dir, config) = load_temp_config("admin-file-sync-rulepack");
  let valid = put_request(
    AdminFileRoot::OxiRuleRulepack,
    "rulepacks/main.oxirule-rulepack.toml",
    r#"
[rulepack]
schema_version = 1
name = "main"
version = "0.1.0"

[[group_files]]
content = '''
[[rule_groups]]
name = "main-group"
when = "true"
'''
"#,
  );
  let committed = commit_file_sync(&valid, &config).expect("rulepack file should sync");
  assert_eq!(committed.len(), 1);

  let invalid = put_request(
    AdminFileRoot::OxiRuleRulepack,
    "rulepacks/bad.oxirule-rulepack.toml",
    "[rulepack]\nschema_version = 1\nname = \"bad\"\nversion = \"0.1.0\"\n",
  );
  assert!(commit_file_sync(&invalid, &config).is_err());
}

#[test]
fn file_sync_rejects_cross_type_oxirule_paths() {
  let (_temp_dir, config) = load_temp_config("admin-file-sync-cross-type");
  let oxirule_dir = config
    .source_paths
    .oxirule_dir
    .as_ref()
    .expect("oxirule dir should be set");

  let group_path_as_rule = put_request(
    AdminFileRoot::OxiRule,
    "groups/bad.oxirule-group.toml",
    "[[rule_groups]]\nname = ''\n",
  );
  let error = match commit_file_sync(&group_path_as_rule, &config) {
    Ok(_) => panic!("group file path should not sync through OxiRule root"),
    Err(error) => error.to_string(),
  };
  assert!(error.contains("root oxirule can only manage .oxirule.toml files"));
  assert!(!oxirule_dir.join("groups/bad.oxirule-group.toml").exists());

  let rule_path_as_group = put_request(
    AdminFileRoot::OxiRuleGroup,
    "rules/main.oxirule.toml",
    "[[rule_groups]]\nname = \"valid\"\n",
  );
  let error = match commit_file_sync(&rule_path_as_group, &config) {
    Ok(_) => panic!("rule file path should not sync through OxiRule group root"),
    Err(error) => error.to_string(),
  };
  assert!(error.contains("root oxirule_group can only manage .oxirule-group.toml files"));
  assert!(!oxirule_dir.join("rules/main.oxirule.toml").exists());

  let rulepack_path_as_group = put_request(
    AdminFileRoot::OxiRuleGroup,
    "rulepacks/main.oxirule-rulepack.toml",
    "",
  );
  let error = match commit_file_sync(&rulepack_path_as_group, &config) {
    Ok(_) => panic!("rulepack file path should not sync through OxiRule group root"),
    Err(error) => error.to_string(),
  };
  assert!(error.contains("root oxirule_group can only manage .oxirule-group.toml files"));
  assert!(
    !oxirule_dir
      .join("rulepacks/main.oxirule-rulepack.toml")
      .exists()
  );

  let existing_group = oxirule_dir.join("groups/main.oxirule-group.toml");
  std::fs::create_dir_all(
    existing_group
      .parent()
      .expect("group file should have parent"),
  )
  .expect("group directory should be created");
  std::fs::write(&existing_group, "[[rule_groups]]\nname = \"existing\"\n")
    .expect("group file should be written");
  let delete_group_as_rule =
    delete_request(AdminFileRoot::OxiRule, "groups/main.oxirule-group.toml");
  let error = match commit_file_sync(&delete_group_as_rule, &config) {
    Ok(_) => panic!("group file path should not delete through OxiRule root"),
    Err(error) => error.to_string(),
  };
  assert!(error.contains("root oxirule can only manage .oxirule.toml files"));
  assert!(existing_group.exists());
}
