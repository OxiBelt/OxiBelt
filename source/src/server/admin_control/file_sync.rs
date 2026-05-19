use std::path::{Path, PathBuf};

use ::http::StatusCode;
use anyhow::{Context, anyhow, bail};
use ring::digest;
use tracing::{info, warn};

use crate::config::{Config, RuntimeOverrides};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use crate::server::ListenerSupervisor;

use super::{
  AdminApplyMode, AdminControlHandle, AdminControlResponse, AdminFileOperationKind, AdminFileRoot,
  AdminFilesSyncRequest, RollbackSnapshot, apply_downstream_tls_reload, apply_full_from_files,
  apply_oxirule_from_files, check_if_match, current_revision, etag_for_revision, record_operation,
};

const ADMIN_FILE_SYNC_BODY_LIMIT: usize = 1024 * 1024;

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_file_sync(
  actor: &str,
  if_match: Option<String>,
  request: AdminFilesSyncRequest,
  state: &AppHandle,
  listeners: &mut ListenerSupervisor,
  control: &AdminControlHandle,
  runtime_overrides: &RuntimeOverrides,
  rollback: &mut Option<RollbackSnapshot>,
) -> AdminControlResponse {
  if let Err(response) = check_if_match(control, if_match).await {
    return response;
  }
  let active = state.snapshot();
  let committed = match commit_file_sync(&request, &active.config) {
    Ok(committed) => committed,
    Err(error) => {
      record_operation(control, "files_sync", "rejected", Some(error.to_string())).await;
      return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
    }
  };
  let apply_result = match request.apply {
    AdminApplyMode::None => Ok(()),
    AdminApplyMode::OxiRule => {
      apply_oxirule_from_files(state, listeners, control, runtime_overrides, rollback).await
    }
    AdminApplyMode::Full => {
      apply_full_from_files(state, listeners, control, runtime_overrides, rollback).await
    }
    AdminApplyMode::DownstreamTls => {
      match apply_downstream_tls_reload(
        actor,
        Some(etag_for_revision(current_revision(control).await)),
        state,
        listeners,
        control,
        rollback,
      )
      .await
      .status
      {
        StatusCode::OK => Ok(()),
        status => Err(anyhow!("downstream TLS reload failed with status {status}")),
      }
    }
  };
  if let Err(error) = apply_result {
    if let Err(restore_error) = restore_committed_files(&committed) {
      warn!(error = %restore_error, "failed to restore files after admin file sync apply failure");
    }
    record_operation(control, "files_sync", "rejected", Some(error.to_string())).await;
    return AdminControlResponse::error(StatusCode::BAD_REQUEST, error.to_string());
  }
  info!(
    actor,
    operations = request.operations.len(),
    "admin file sync applied"
  );
  record_operation(control, "files_sync", "applied", None).await;
  AdminControlResponse::ok(serde_json::json!({
    "ok": true,
    "operations": request.operations.len(),
    "revision": current_revision(control).await,
  }))
}

fn commit_file_sync(
  request: &AdminFilesSyncRequest,
  config: &Config,
) -> anyhow::Result<Vec<CommittedFile>> {
  if request.operations.is_empty() || request.operations.len() > 128 {
    bail!("operations must contain 1 to 128 entries");
  }
  let mut committed = Vec::new();
  for (index, operation) in request.operations.iter().enumerate() {
    let target = resolve_sync_target(config, operation.root, &operation.path)?;
    verify_expected_hash(&target, operation.expected_sha256.as_deref())?;
    match operation.op {
      AdminFileOperationKind::Put => {
        let content = operation
          .content
          .as_ref()
          .ok_or_else(|| anyhow!("put operation {index} requires content"))?;
        validate_sync_content(operation.root, content)?;
        committed.push(write_sync_file(&target, content.as_bytes())?);
      }
      AdminFileOperationKind::Delete => {
        if operation.content.is_some() {
          bail!("delete operation {index} must not include content");
        }
        committed.push(delete_sync_file(&target)?);
      }
    }
  }
  Ok(committed)
}

fn resolve_sync_target(
  config: &Config,
  root: AdminFileRoot,
  path: &str,
) -> anyhow::Result<PathBuf> {
  if path.trim().is_empty() {
    bail!("file sync path must not be empty");
  }
  let relative = Path::new(path);
  if relative.to_str().is_none() {
    bail!("file sync path must be valid UTF-8");
  }
  let base = match root {
    AdminFileRoot::Config => config
      .source_paths
      .config_dir
      .as_ref()
      .ok_or_else(|| anyhow!("active configuration does not have a config directory"))?,
    AdminFileRoot::OxiRule | AdminFileRoot::OxiRuleGroup => config
      .source_paths
      .oxirule_dir
      .as_ref()
      .ok_or_else(|| anyhow!("active configuration does not have an OxiRule directory"))?,
  };
  let target =
    crate::config::resolve_local_config_file_path("admin file sync path", base, relative)?;
  ensure_parent_stays_under_base(base, &target)?;
  Ok(target)
}

fn ensure_parent_stays_under_base(base: &Path, target: &Path) -> anyhow::Result<()> {
  let parent = target
    .parent()
    .ok_or_else(|| anyhow!("file sync target has no parent directory"))?;
  std::fs::create_dir_all(parent)
    .with_context(|| format!("failed to create {}", parent.display()))?;
  let canonical_base = base.canonicalize().with_context(|| {
    format!(
      "failed to resolve file sync base directory {}",
      base.display()
    )
  })?;
  let canonical_parent = parent
    .canonicalize()
    .with_context(|| format!("failed to resolve {}", parent.display()))?;
  if !canonical_parent.starts_with(canonical_base) {
    bail!("file sync target must stay within the configured root");
  }
  Ok(())
}

fn validate_sync_content(root: AdminFileRoot, content: &str) -> anyhow::Result<()> {
  match root {
    AdminFileRoot::Config => {
      toml::from_str::<toml::Value>(content).context("failed to parse config TOML")?;
    }
    AdminFileRoot::OxiRule => {}
    AdminFileRoot::OxiRuleGroup => {
      crate::waf::validate_external_rule_group_file(content)?;
    }
  }
  Ok(())
}

fn verify_expected_hash(path: &Path, expected: Option<&str>) -> anyhow::Result<()> {
  let Some(expected) = expected else {
    return Ok(());
  };
  let Some(bytes) = read_optional_regular_file(path)? else {
    bail!("expected_sha256 did not match because target file is missing");
  };
  let actual = sha256_hex(&bytes);
  if !expected.eq_ignore_ascii_case(&actual) {
    bail!("expected_sha256 did not match target file");
  }
  Ok(())
}

fn write_sync_file(path: &Path, bytes: &[u8]) -> anyhow::Result<CommittedFile> {
  let previous = read_optional_regular_file(path)?;
  let parent = path
    .parent()
    .ok_or_else(|| anyhow!("file sync target has no parent directory"))?;
  let temp = parent.join(format!(
    ".oxibelt-sync-{}-{}.tmp",
    std::process::id(),
    sha256_hex(path.to_string_lossy().as_bytes())
  ));
  std::fs::write(&temp, bytes).with_context(|| format!("failed to write {}", temp.display()))?;
  std::fs::rename(&temp, path).with_context(|| format!("failed to replace {}", path.display()))?;
  Ok(CommittedFile {
    path: path.to_path_buf(),
    previous,
  })
}

fn delete_sync_file(path: &Path) -> anyhow::Result<CommittedFile> {
  let previous = read_optional_regular_file(path)?;
  if previous.is_some() {
    std::fs::remove_file(path).with_context(|| format!("failed to delete {}", path.display()))?;
  }
  Ok(CommittedFile {
    path: path.to_path_buf(),
    previous,
  })
}

fn read_optional_regular_file(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
  match std::fs::metadata(path) {
    Ok(metadata) => {
      if !metadata.is_file() {
        bail!("file sync target must be a regular file");
      }
      Ok(Some(std::fs::read(path).with_context(|| {
        format!("failed to read {}", path.display())
      })?))
    }
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
    Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
  }
}

struct CommittedFile {
  path: PathBuf,
  previous: Option<Vec<u8>>,
}

fn restore_committed_files(files: &[CommittedFile]) -> anyhow::Result<()> {
  for file in files.iter().rev() {
    match &file.previous {
      Some(bytes) => std::fs::write(&file.path, bytes)
        .with_context(|| format!("failed to restore {}", file.path.display()))?,
      None => match std::fs::remove_file(&file.path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
          return Err(error).with_context(|| format!("failed to remove {}", file.path.display()));
        }
      },
    }
  }
  Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
  let digest = digest::digest(&digest::SHA256, bytes);
  let mut out = String::with_capacity(digest.as_ref().len() * 2);
  for byte in digest.as_ref() {
    use std::fmt::Write as _;
    let _ = write!(&mut out, "{byte:02x}");
  }
  out
}

pub(super) fn validate_file_sync_payload(
  payload: &AdminFilesSyncRequest,
) -> Option<::http::Response<ProxyBody>> {
  let total_bytes = payload
    .operations
    .iter()
    .filter_map(|operation| operation.content.as_ref())
    .map(String::len)
    .sum::<usize>();
  if total_bytes > ADMIN_FILE_SYNC_BODY_LIMIT {
    return Some(text_response(
      StatusCode::PAYLOAD_TOO_LARGE,
      "file sync payload is too large",
    ));
  }
  None
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::server::admin_control::{
    AdminFileOperation, AdminFileOperationKind, AdminFileRoot, AdminFilesSyncRequest,
  };

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
}
