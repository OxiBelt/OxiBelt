use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use ::http::StatusCode;
use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use tracing::{info, warn};

use crate::config::{Config, RuntimeOverrides};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::super::file_sync_path;
use crate::server::ListenerSupervisor;

use super::{
  AdminApplyMode, AdminControlHandle, AdminControlResponse, AdminFileOperationKind, AdminFileRoot,
  AdminFilesSyncRequest, ControlPlaneConfigPermissions, RollbackSnapshot,
  apply_downstream_tls_reload, apply_full_from_files, apply_oxirule_from_files, check_if_match,
  current_revision, etag_for_revision, record_operation, validate_control_plane_config_scope,
};
mod cluster_checkpoint;
pub(crate) use cluster_checkpoint::{
  capture_cluster_before_images, restore_cluster_before_images, verify_cluster_file_state,
};
const ADMIN_FILE_SYNC_BODY_LIMIT: usize = 1024 * 1024;

#[allow(clippy::too_many_arguments)]
pub(super) async fn apply_file_sync(
  actor: &str,
  control_plane_permissions: ControlPlaneConfigPermissions,
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
  if let Err(response) =
    validate_file_sync_control_plane_scope(&request, &active.config, control_plane_permissions)
  {
    record_operation(
      control,
      "files_sync",
      "rejected",
      Some(
        response
          .body
          .get("error")
          .and_then(|value| value.as_str())
          .unwrap_or("admin or IPM configuration changes require additional permissions")
          .to_string(),
      ),
    )
    .await;
    return response;
  }
  let committed = match commit_file_sync(&request, &active.config) {
    Ok(committed) => committed,
    Err(error) => {
      record_operation(control, "files_sync", "rejected", Some(error.to_string())).await;
      let status = if error.downcast_ref::<IndeterminateFileSyncError>().is_some() {
        StatusCode::SERVICE_UNAVAILABLE
      } else {
        StatusCode::BAD_REQUEST
      };
      return AdminControlResponse::error(status, error.to_string());
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
      let message = format!(
        "file sync apply failed and rollback could not be proven: apply error: {error}; rollback error: {restore_error}"
      );
      record_operation(
        control,
        "files_sync",
        "indeterminate",
        Some(message.clone()),
      )
      .await;
      return AdminControlResponse::error(StatusCode::SERVICE_UNAVAILABLE, message);
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

fn validate_file_sync_control_plane_scope(
  request: &AdminFilesSyncRequest,
  active: &Config,
  permissions: ControlPlaneConfigPermissions,
) -> Result<(), AdminControlResponse> {
  match file_sync_control_plane_candidate(request, active) {
    Ok(Some(candidate)) => validate_control_plane_config_scope(permissions, active, &candidate),
    Ok(None) => Ok(()),
    Err(error) if permissions.can_update_all() => {
      tracing::debug!(error = %error, "pending file sync config scope could not be classified; allowing because actor can update admin and IPM config");
      Ok(())
    }
    Err(error) => Err(AdminControlResponse::error(
      StatusCode::FORBIDDEN,
      format!(
        "admin or IPM configuration changes require admin:UpdateConfig and ipm:UpdateConfig: {error}"
      ),
    )),
  }
}

fn file_sync_control_plane_candidate(
  request: &AdminFilesSyncRequest,
  active: &Config,
) -> anyhow::Result<Option<Config>> {
  let config_entry = active
    .source_paths
    .config_entry
    .as_ref()
    .ok_or_else(|| anyhow!("active configuration does not have a config entry"))?;
  if request
    .operations
    .iter()
    .any(|operation| operation.root == AdminFileRoot::Config)
  {
    let overrides = config_file_overrides(request, active)?;
    return Config::load_with_config_file_overrides(config_entry, &overrides).map(Some);
  }
  if request.apply == AdminApplyMode::Full {
    return Config::load(config_entry).map(Some);
  }
  Ok(None)
}

fn config_file_overrides(
  request: &AdminFilesSyncRequest,
  active: &Config,
) -> anyhow::Result<HashMap<PathBuf, Option<String>>> {
  let mut overrides = HashMap::new();
  for operation in &request.operations {
    if operation.root != AdminFileRoot::Config {
      continue;
    }
    let normalized_path = file_sync_path::normalized_relative_path(&operation.path)
      .map_err(|message| anyhow!("invalid file sync path: {message}"))?;
    file_sync_path::validate_root_path(operation.root, &normalized_path)
      .map_err(|message| anyhow!("invalid file sync path: {message}"))?;
    let target = resolve_config_sync_target(active, &normalized_path)?;
    let staged = match operation.op {
      AdminFileOperationKind::Put => {
        let content = operation
          .content
          .as_ref()
          .ok_or_else(|| anyhow!("put operation requires content"))?;
        Some(content.clone())
      }
      AdminFileOperationKind::Delete => None,
    };
    if overrides.insert(target.clone(), staged).is_some() {
      bail!(
        "file sync request contains multiple config operations for {}",
        target.display()
      );
    }
  }
  Ok(overrides)
}

fn config_sync_base(config: &Config) -> anyhow::Result<&Path> {
  config
    .source_paths
    .config_dir
    .as_deref()
    .ok_or_else(|| anyhow!("active configuration does not have a config directory"))
}

fn resolve_config_sync_target(config: &Config, path: &str) -> anyhow::Result<PathBuf> {
  let base = config_sync_base(config)?;
  let target =
    crate::config::resolve_local_config_file_path("admin file sync path", base, Path::new(path))?;
  let canonical_base = base.canonicalize().with_context(|| {
    format!(
      "failed to resolve file sync base directory {}",
      base.display()
    )
  })?;
  let canonical_target =
    crate::config::canonicalize_local_config_file_target("admin file sync path", &target)?;
  if !canonical_target.starts_with(&canonical_base) {
    bail!("file sync target must stay within the configured root");
  }
  Ok(canonical_target)
}

fn ensure_unique_config_sync_targets(
  request: &AdminFilesSyncRequest,
  config: &Config,
) -> anyhow::Result<()> {
  let mut targets = HashSet::new();
  for (index, operation) in request.operations.iter().enumerate() {
    if operation.root != AdminFileRoot::Config {
      continue;
    }
    let normalized_path = file_sync_path::normalized_relative_path(&operation.path)
      .map_err(|message| anyhow!("operation {index} has invalid file sync path: {message}"))?;
    file_sync_path::validate_root_path(operation.root, &normalized_path)
      .map_err(|message| anyhow!("operation {index} has invalid file sync path: {message}"))?;
    let target = resolve_config_sync_target(config, &normalized_path)?;
    if !targets.insert(target.clone()) {
      bail!(
        "file sync request contains multiple config operations for {}",
        target.display()
      );
    }
  }
  Ok(())
}

fn commit_file_sync(
  request: &AdminFilesSyncRequest,
  config: &Config,
) -> anyhow::Result<Vec<CommittedFile>> {
  if request.operations.is_empty() || request.operations.len() > 128 {
    bail!("operations must contain 1 to 128 entries");
  }
  ensure_unique_config_sync_targets(request, config)?;

  for (index, operation) in request.operations.iter().enumerate() {
    let normalized_path = file_sync_path::normalized_relative_path(&operation.path)
      .map_err(|message| anyhow!("operation {index} has invalid file sync path: {message}"))?;
    file_sync_path::validate_root_path(operation.root, &normalized_path)
      .map_err(|message| anyhow!("operation {index} has invalid file sync path: {message}"))?;
    let target = resolve_sync_target(config, operation.root, &normalized_path)?;
    verify_expected_hash(&target, operation.expected_sha256.as_deref())?;
    match operation.op {
      AdminFileOperationKind::Put => {
        let content = operation
          .content
          .as_ref()
          .ok_or_else(|| anyhow!("put operation {index} requires content"))?;
        validate_sync_content(operation.root, content)?;
      }
      AdminFileOperationKind::Delete if operation.content.is_some() => {
        bail!("delete operation {index} must not include content");
      }
      AdminFileOperationKind::Delete => {}
    }
  }

  let mut committed = Vec::new();
  for (index, operation) in request.operations.iter().enumerate() {
    let operation_result = (|| -> anyhow::Result<CommittedFile> {
      let normalized_path = file_sync_path::normalized_relative_path(&operation.path)
        .map_err(|message| anyhow!("operation {index} has invalid file sync path: {message}"))?;
      let target = resolve_sync_target(config, operation.root, &normalized_path)?;
      verify_expected_hash(&target, operation.expected_sha256.as_deref())?;
      match operation.op {
        AdminFileOperationKind::Put => {
          let content = operation
            .content
            .as_ref()
            .ok_or_else(|| anyhow!("put operation {index} requires content"))?;
          write_sync_file(&target, content.as_bytes())
        }
        AdminFileOperationKind::Delete => delete_sync_file(&target),
      }
    })();
    match operation_result {
      Ok(file) => committed.push(file),
      Err(error) => {
        if let Err(rollback_error) = restore_committed_files(&committed) {
          return Err(anyhow!(IndeterminateFileSyncError {
            operation_error: error.to_string(),
            rollback_error: rollback_error.to_string(),
          }));
        }
        return Err(error);
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
  let normalized_path =
    file_sync_path::normalized_relative_path(path).map_err(|message| anyhow!(message))?;
  file_sync_path::validate_root_path(root, &normalized_path).map_err(|message| anyhow!(message))?;
  let relative = Path::new(&normalized_path);
  let base = match root {
    AdminFileRoot::Config => {
      let target = resolve_config_sync_target(config, &normalized_path)?;
      ensure_parent_stays_under_base(config_sync_base(config)?, &target)?;
      return Ok(target);
    }
    AdminFileRoot::OxiRule
    | AdminFileRoot::OxiRuleGroup
    | AdminFileRoot::OxiRuleRulepack
    | AdminFileRoot::OxiRuleRulepackInstall => config
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
  let canonical_base = base.canonicalize().with_context(|| {
    format!(
      "failed to resolve file sync base directory {}",
      base.display()
    )
  })?;
  let projected_parent = crate::config::canonicalize_local_config_file_target(
    "admin file sync parent directory",
    parent,
  )?;
  if !projected_parent.starts_with(&canonical_base) {
    bail!("file sync target must stay within the configured root");
  }
  std::fs::create_dir_all(parent)
    .with_context(|| format!("failed to create {}", parent.display()))?;
  let canonical_parent = parent
    .canonicalize()
    .with_context(|| format!("failed to resolve {}", parent.display()))?;
  if !canonical_parent.starts_with(&canonical_base) {
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
    AdminFileRoot::OxiRuleRulepack => {
      crate::waf::validate_rulepack_manifest(content)?;
    }
    AdminFileRoot::OxiRuleRulepackInstall => {
      validate_rulepack_install_lock(content)?;
    }
  }
  Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackInstallLock {
  install: RulepackInstallSection,
  #[serde(default)]
  bindings: BTreeMap<String, String>,
  #[serde(default)]
  values: BTreeMap<String, String>,
  #[serde(default)]
  rule_overrides: Vec<crate::waf::RulepackOverride>,
  #[serde(default)]
  exceptions: Vec<crate::waf::RulepackException>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulepackInstallSection {
  name: String,
  version: String,
  source: String,
  #[serde(default)]
  source_commit: Option<String>,
  #[serde(default)]
  source_url: Option<String>,
  #[serde(default)]
  source_sha256: Option<String>,
  #[serde(default)]
  source_openpgp_signature_url: Option<String>,
  #[serde(default)]
  source_openpgp_signer_fingerprint: Option<String>,
  #[serde(default)]
  profile: Option<String>,
  effective_mode: crate::waf::WafMode,
  force_mode: bool,
  installed_at: String,
}

fn validate_rulepack_install_lock(content: &str) -> anyhow::Result<()> {
  let lock: RulepackInstallLock =
    toml::from_str(content).context("failed to parse rulepack install lock TOML")?;
  validate_lock_label("install.name", &lock.install.name)?;
  validate_lock_text("install.version", &lock.install.version, 128)?;
  validate_lock_text("install.source", &lock.install.source, 2048)?;
  validate_lock_text("install.installed_at", &lock.install.installed_at, 64)?;
  if let Some(value) = &lock.install.source_commit {
    validate_lock_text("install.source_commit", value, 128)?;
  }
  if let Some(value) = &lock.install.source_url {
    validate_lock_text("install.source_url", value, 2048)?;
  }
  if let Some(value) = &lock.install.source_sha256 {
    validate_sha256(value)?;
  }
  if let Some(value) = &lock.install.source_openpgp_signature_url {
    validate_lock_text("install.source_openpgp_signature_url", value, 2048)?;
  }
  if let Some(value) = &lock.install.source_openpgp_signer_fingerprint {
    validate_fingerprint(value)?;
  }
  if let Some(value) = &lock.install.profile {
    validate_lock_label("install.profile", value)?;
  }
  let _ = lock.install.effective_mode;
  let _ = lock.install.force_mode;
  validate_lock_map("bindings", &lock.bindings)?;
  validate_lock_map("values", &lock.values)?;
  crate::waf::validate_rulepack_overrides(
    "rulepack install lock",
    &lock.install.name,
    &lock.rule_overrides,
  )?;
  crate::waf::validate_rulepack_exception_list("rulepack install lock", &lock.exceptions)?;
  Ok(())
}

fn validate_lock_map(field: &str, values: &BTreeMap<String, String>) -> anyhow::Result<()> {
  for (name, value) in values {
    validate_lock_label(&format!("{field} key"), name)?;
    validate_lock_text(&format!("{field}.{name}"), value, 2048)?;
  }
  Ok(())
}

fn validate_lock_label(field: &str, value: &str) -> anyhow::Result<()> {
  validate_lock_text(field, value, 128)?;
  if !value
    .bytes()
    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
  {
    bail!("{field} contains unsupported characters");
  }
  Ok(())
}

fn validate_lock_text(field: &str, value: &str, max_len: usize) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field} must not be empty");
  }
  if value.len() > max_len || value.bytes().any(|byte| byte.is_ascii_control()) {
    bail!("{field} must be 1 to {max_len} printable bytes");
  }
  Ok(())
}

fn validate_sha256(value: &str) -> anyhow::Result<()> {
  if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("install.source_sha256 must be a 64-character hex SHA-256 digest");
  }
  Ok(())
}

fn validate_fingerprint(value: &str) -> anyhow::Result<()> {
  if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!(
      "install.source_openpgp_signer_fingerprint must be a full 40- or 64-character hex OpenPGP fingerprint"
    );
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

#[derive(Debug)]
struct IndeterminateFileSyncError {
  operation_error: String,
  rollback_error: String,
}

impl std::fmt::Display for IndeterminateFileSyncError {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      formatter,
      "file sync commit failed and rollback could not be proven: operation error: {}; rollback error: {}",
      self.operation_error, self.rollback_error
    )
  }
}

impl std::error::Error for IndeterminateFileSyncError {}

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
  let digest = crate::crypto::sha256(bytes);
  let mut out = String::with_capacity(digest.len() * 2);
  for byte in digest {
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
mod tests;
