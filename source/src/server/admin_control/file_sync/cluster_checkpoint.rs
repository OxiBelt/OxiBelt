//! Durable file before-images for cluster application and rollback.

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::server::file_sync_path;

use super::{
  AdminFileOperationKind, AdminFileRoot, AdminFilesSyncRequest, delete_sync_file,
  resolve_sync_target, sha256_hex, validate_sync_content, verify_expected_hash, write_sync_file,
};
use crate::server::admin_control::checkpoint::FileBeforeImage;

const MAX_CHECKPOINT_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CHECKPOINT_TOTAL_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn capture_cluster_before_images(
  request: &AdminFilesSyncRequest,
  config: &Config,
) -> anyhow::Result<Vec<FileBeforeImage>> {
  if request.operations.is_empty() || request.operations.len() > 128 {
    bail!("operations must contain 1 to 128 entries");
  }
  let mut targets = HashSet::new();
  let mut total_bytes = 0_usize;
  let mut images = Vec::with_capacity(request.operations.len());
  for (index, operation) in request.operations.iter().enumerate() {
    let path = file_sync_path::normalized_relative_path(&operation.path)
      .map_err(|message| anyhow!("operation {index} has invalid file sync path: {message}"))?;
    let target = resolve_sync_target(config, operation.root, &path)?;
    if !targets.insert(target.clone()) {
      bail!("file sync request contains duplicate targets");
    }
    verify_expected_hash(&target, operation.expected_sha256.as_deref())?;
    let applied_digest = match operation.op {
      AdminFileOperationKind::Put => {
        let content = operation
          .content
          .as_ref()
          .ok_or_else(|| anyhow!("put operation {index} requires content"))?;
        validate_sync_content(operation.root, content)?;
        Some(sha256_hex(content.as_bytes()))
      }
      AdminFileOperationKind::Delete if operation.content.is_some() => {
        bail!("delete operation {index} must not include content");
      }
      AdminFileOperationKind::Delete => None,
    };
    let previous = read_checkpoint_file(&target)?;
    total_bytes = total_bytes
      .checked_add(previous.as_ref().map_or(0, |value| value.len()))
      .context("checkpoint byte count overflow")?;
    if total_bytes > MAX_CHECKPOINT_TOTAL_BYTES {
      bail!("file sync before-images exceed the encrypted checkpoint bound");
    }
    images.push(FileBeforeImage {
      root: root_label(operation.root).to_string(),
      path,
      previous,
      applied_digest,
    });
  }
  Ok(images)
}

pub(crate) fn verify_cluster_file_state(
  images: &[FileBeforeImage],
  config: &Config,
  candidate: bool,
) -> anyhow::Result<()> {
  for image in images {
    let target = resolve_sync_target(config, parse_root_label(&image.root)?, &image.path)?;
    let actual = read_checkpoint_file(&target)?;
    let expected = if candidate {
      image.applied_digest.clone()
    } else {
      image
        .previous
        .as_ref()
        .map(|bytes| sha256_hex(bytes.as_slice()))
    };
    if actual
      .as_ref()
      .map(|bytes| sha256_hex(bytes.as_slice()))
      .as_deref()
      != expected.as_deref()
    {
      bail!("file state does not match the authenticated rollout checkpoint");
    }
  }
  Ok(())
}

pub(crate) fn restore_cluster_before_images(
  images: &[FileBeforeImage],
  config: &Config,
) -> anyhow::Result<()> {
  verify_cluster_file_state(images, config, true)?;
  for image in images.iter().rev() {
    let target = resolve_sync_target(config, parse_root_label(&image.root)?, &image.path)?;
    match &image.previous {
      Some(bytes) => drop(write_sync_file(&target, bytes)?),
      None => drop(delete_sync_file(&target)?),
    }
  }
  verify_cluster_file_state(images, config, false)
}

fn read_checkpoint_file(path: &Path) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
  let mut options = OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  }
  match options.open(path) {
    Ok(file) => {
      let metadata = file.metadata()?;
      if !metadata.is_file() || metadata.len() > MAX_CHECKPOINT_FILE_BYTES {
        bail!("file sync target is not a bounded regular file");
      }
      let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len().try_into()?));
      file
        .take(MAX_CHECKPOINT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
      if bytes.len() as u64 > MAX_CHECKPOINT_FILE_BYTES {
        bail!("file sync target grew past the checkpoint bound");
      }
      Ok(Some(bytes))
    }
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
    Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
  }
}

const fn root_label(root: AdminFileRoot) -> &'static str {
  match root {
    AdminFileRoot::Config => "config",
    AdminFileRoot::OxiRule => "oxirule",
    AdminFileRoot::OxiRuleGroup => "oxirule_group",
    AdminFileRoot::OxiRuleRulepack => "oxirule_rulepack",
    AdminFileRoot::OxiRuleRulepackInstall => "oxirule_rulepack_install",
  }
}

fn parse_root_label(root: &str) -> anyhow::Result<AdminFileRoot> {
  match root {
    "config" => Ok(AdminFileRoot::Config),
    "oxirule" => Ok(AdminFileRoot::OxiRule),
    "oxirule_group" => Ok(AdminFileRoot::OxiRuleGroup),
    "oxirule_rulepack" => Ok(AdminFileRoot::OxiRuleRulepack),
    "oxirule_rulepack_install" => Ok(AdminFileRoot::OxiRuleRulepackInstall),
    _ => bail!("checkpoint file root is invalid"),
  }
}
