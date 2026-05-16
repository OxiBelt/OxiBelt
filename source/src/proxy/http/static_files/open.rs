use std::fs::Metadata;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use tokio::fs::File;

#[derive(Debug)]
pub(crate) struct OpenedStaticFile {
  pub(crate) file: File,
  pub(crate) path: PathBuf,
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
  #[cfg(target_os = "linux")]
  {
    if let Some(opened) = open_verified_file_with_openat2(root, path).await? {
      return Ok(opened);
    }
  }

  open_verified_file_with_procfs_fallback(root, path).await
}

async fn open_verified_file_with_procfs_fallback(
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
  let path = verify_opened_file(&file, root)
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
  Ok(OpenedStaticFile {
    file,
    path,
    metadata,
  })
}

pub(crate) fn verify_opened_file(file: &File, root: &Path) -> anyhow::Result<PathBuf> {
  let target = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
    .context("failed to resolve opened static file descriptor")?;
  if !target.starts_with(root) {
    bail!("opened static file descriptor escapes static_root");
  }
  Ok(target)
}

#[cfg(target_os = "linux")]
async fn open_verified_file_with_openat2(
  root: &Path,
  path: &Path,
) -> Result<Option<OpenedStaticFile>, StaticOpenError> {
  let root = root.to_path_buf();
  let path = path.to_path_buf();
  tokio::task::spawn_blocking(move || open_verified_file_with_openat2_blocking(&root, &path))
    .await
    .context("static file openat2 worker failed")
    .map_err(StaticOpenError::forbidden)?
}

#[cfg(target_os = "linux")]
fn open_verified_file_with_openat2_blocking(
  root: &Path,
  path: &Path,
) -> Result<Option<OpenedStaticFile>, StaticOpenError> {
  let opened = match open_regular_file_beneath_root(root, path)? {
    Some(opened) => opened,
    None => return Ok(None),
  };
  Ok(Some(opened))
}

#[cfg(target_os = "linux")]
fn open_regular_file_beneath_root(
  root: &Path,
  path: &Path,
) -> Result<Option<OpenedStaticFile>, StaticOpenError> {
  use nix::errno::Errno;
  use nix::fcntl::{OFlag, OpenHow, ResolveFlag, open, openat2};
  use nix::sys::stat::Mode;

  fn static_open_error(path: &Path, error: Errno) -> StaticOpenError {
    if error == Errno::ENOENT {
      return StaticOpenError::NotFound;
    }
    StaticOpenError::forbidden(anyhow!(
      "failed to open static file {} with openat2: {error}",
      path.display()
    ))
  }

  let relative = path.strip_prefix(root).map_err(|error| {
    StaticOpenError::forbidden(anyhow!(
      "static file path {} is not beneath static_root {}: {error}",
      path.display(),
      root.display()
    ))
  })?;
  let relative = if relative.as_os_str().is_empty() {
    Path::new(".")
  } else {
    relative
  };

  let root_fd = open(
    root,
    OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY,
    Mode::empty(),
  )
  .map_err(|error| static_open_error(root, error))?;
  let file_fd = match openat2(
    &root_fd,
    relative,
    OpenHow::new()
      .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC)
      .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_MAGICLINKS),
  ) {
    Ok(file_fd) => file_fd,
    Err(Errno::ENOSYS) => {
      return Ok(None);
    }
    Err(error) => return Err(static_open_error(path, error)),
  };
  let file = std::fs::File::from(file_fd);
  let metadata = file
    .metadata()
    .with_context(|| format!("failed to inspect opened static file {}", path.display()))
    .map_err(StaticOpenError::forbidden)?;
  if !metadata.is_file() {
    return Err(StaticOpenError::forbidden(anyhow!(
      "opened static file is not a regular file"
    )));
  }

  Ok(Some(OpenedStaticFile {
    file: File::from_std(file),
    path: path.to_path_buf(),
    metadata,
  }))
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) async fn open_verified_file_with_openat2_for_tests(
  root: &Path,
  path: &Path,
) -> Result<Option<OpenedStaticFile>, StaticOpenError> {
  open_verified_file_with_openat2(root, path).await
}
