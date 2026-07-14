//! Symlink-resistant filesystem helpers for the Admin audit spool.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, ensure};

pub(super) fn remove_uncommitted_temporary_files(directory: &Path) -> anyhow::Result<()> {
  for entry in fs::read_dir(directory)? {
    let entry = entry?;
    let name = entry.file_name();
    if !name.to_string_lossy().starts_with(".tmp-") {
      continue;
    }
    let metadata = fs::symlink_metadata(entry.path())?;
    ensure!(
      metadata.file_type().is_file(),
      "Admin audit spool temporary entry is not a regular file"
    );
    fs::remove_file(entry.path())?;
  }
  File::open(directory)?.sync_all()?;
  Ok(())
}

pub(super) fn secure_create_new(path: &Path) -> anyhow::Result<File> {
  OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    .open(path)
    .with_context(|| format!("failed to create Admin audit spool file {}", path.display()))
}

pub(super) fn secure_open_read(path: &Path) -> anyhow::Result<File> {
  let file = OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
    .open(path)
    .with_context(|| format!("failed to open Admin audit spool path {}", path.display()))?;
  let metadata = file.metadata()?;
  ensure!(
    metadata.file_type().is_file() || metadata.file_type().is_dir(),
    "Admin audit spool path is not a regular file or directory"
  );
  Ok(file)
}
