use std::fs::Metadata;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use tokio::fs::File;

#[derive(Debug)]
pub(crate) struct OpenedStaticFile {
  pub(crate) file: File,
  pub(crate) metadata: Metadata,
}

#[derive(Debug)]
pub(crate) enum StaticOpenError {
  NotFound,
  Forbidden(anyhow::Error),
}

impl StaticOpenError {
  fn forbidden(error: impl Into<anyhow::Error>) -> Self {
    Self::Forbidden(error.into())
  }
}

pub(crate) async fn open_verified_file(
  root: &Path,
  path: &Path,
) -> Result<OpenedStaticFile, StaticOpenError> {
  let file = match File::open(path).await {
    Ok(file) => file,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return Err(StaticOpenError::NotFound);
    }
    Err(error) => {
      return Err(StaticOpenError::forbidden(anyhow!(
        "failed to open static file {}: {error}",
        path.display()
      )));
    }
  };
  verify_opened_file(&file, root)
    .with_context(|| format!("static file fd failed validation {}", path.display()))
    .map_err(StaticOpenError::forbidden)?;
  let metadata = file
    .metadata()
    .await
    .with_context(|| format!("failed to inspect opened static file {}", path.display()))
    .map_err(StaticOpenError::forbidden)?;
  if !metadata.is_file() {
    return Err(StaticOpenError::forbidden(anyhow!(
      "opened static file is not a regular file"
    )));
  }
  Ok(OpenedStaticFile { file, metadata })
}

pub(crate) fn verify_opened_file(file: &File, root: &Path) -> anyhow::Result<PathBuf> {
  let target = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
    .context("failed to resolve opened static file descriptor")?;
  if !target.starts_with(root) {
    bail!("opened static file descriptor escapes static_root");
  }
  Ok(target)
}
