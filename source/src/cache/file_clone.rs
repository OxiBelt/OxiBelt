//! Linux cache-file clone helpers with exact-byte userspace fallback.

#![allow(unsafe_code)]

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::path::Path;

use crate::config::CacheCopyFileRangeMode;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum CacheFileCloneOutcome {
  KernelCopy,
  UserspaceCopy,
}

pub(super) fn materialize_cache_file(
  source_path: &Path,
  source_offset: u64,
  len: usize,
  tmp_path: &Path,
  final_path: &Path,
  mode: CacheCopyFileRangeMode,
) -> io::Result<CacheFileCloneOutcome> {
  if mode != CacheCopyFileRangeMode::Off {
    match try_copy_file_range_to_tmp(source_path, source_offset, len, tmp_path) {
      Ok(()) => {
        std::fs::rename(tmp_path, final_path)?;
        return Ok(CacheFileCloneOutcome::KernelCopy);
      }
      Err(error) if mode == CacheCopyFileRangeMode::Required => {
        let _ = std::fs::remove_file(tmp_path);
        return Err(error);
      }
      Err(error) if copy_file_range_can_fallback(&error) => {
        let _ = std::fs::remove_file(tmp_path);
      }
      Err(error) => {
        let _ = std::fs::remove_file(tmp_path);
        return Err(error);
      }
    }
  }

  userspace_copy_to_tmp(source_path, source_offset, len, tmp_path)?;
  std::fs::rename(tmp_path, final_path)?;
  Ok(CacheFileCloneOutcome::UserspaceCopy)
}

#[cfg(target_os = "linux")]
fn try_copy_file_range_to_tmp(
  source_path: &Path,
  source_offset: u64,
  len: usize,
  tmp_path: &Path,
) -> io::Result<()> {
  let source = File::open(source_path)?;
  let dest = File::create(tmp_path)?;
  let mut src_offset =
    libc::loff_t::try_from(source_offset).map_err(|_| invalid_input("source offset too large"))?;
  let mut dst_offset: libc::loff_t = 0;
  let mut remaining = len;
  while remaining > 0 {
    let requested = remaining.min(1024 * 1024);
    let copied = unsafe {
      libc::copy_file_range(
        source.as_raw_fd(),
        &mut src_offset,
        dest.as_raw_fd(),
        &mut dst_offset,
        requested,
        0,
      )
    };
    if copied < 0 {
      return Err(io::Error::last_os_error());
    }
    if copied == 0 {
      return Err(io::Error::new(
        io::ErrorKind::WriteZero,
        "copy_file_range made no progress",
      ));
    }
    let copied = copied as usize;
    if copied != requested {
      return Err(io::Error::new(
        io::ErrorKind::Interrupted,
        "copy_file_range returned a short copy",
      ));
    }
    remaining -= copied;
  }
  Ok(())
}

#[cfg(not(target_os = "linux"))]
fn try_copy_file_range_to_tmp(
  _source_path: &Path,
  _source_offset: u64,
  _len: usize,
  _tmp_path: &Path,
) -> io::Result<()> {
  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "copy_file_range is Linux-only",
  ))
}

fn userspace_copy_to_tmp(
  source_path: &Path,
  source_offset: u64,
  len: usize,
  tmp_path: &Path,
) -> io::Result<()> {
  let mut source = File::open(source_path)?;
  source.seek(SeekFrom::Start(source_offset))?;
  let mut dest = File::create(tmp_path)?;
  let copied = io::copy(&mut source.take(len as u64), &mut dest)?;
  if copied != len as u64 {
    return Err(io::Error::new(
      io::ErrorKind::UnexpectedEof,
      "cache file clone source ended before expected length",
    ));
  }
  dest.flush()?;
  Ok(())
}

fn copy_file_range_can_fallback(error: &io::Error) -> bool {
  matches!(
    error.raw_os_error(),
    Some(libc::EXDEV | libc::EOPNOTSUPP | libc::EINVAL | libc::ENOSYS)
  ) || matches!(
    error.kind(),
    io::ErrorKind::Interrupted | io::ErrorKind::WriteZero
  )
}

fn invalid_input(message: &'static str) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn userspace_fallback_copies_exact_range() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let tmp = dir.path().join("dest.tmp");
    let final_path = dir.path().join("dest");
    std::fs::write(&source, b"0123456789").expect("write source");

    let outcome = materialize_cache_file(
      &source,
      2,
      5,
      &tmp,
      &final_path,
      CacheCopyFileRangeMode::Off,
    )
    .expect("copy should succeed");

    assert_eq!(outcome, CacheFileCloneOutcome::UserspaceCopy);
    assert_eq!(std::fs::read(final_path).expect("read dest"), b"23456");
    assert!(!tmp.exists());
  }

  #[test]
  fn userspace_fallback_rejects_short_source() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source = dir.path().join("source");
    let tmp = dir.path().join("dest.tmp");
    let final_path = dir.path().join("dest");
    std::fs::write(&source, b"abc").expect("write source");

    let error = materialize_cache_file(
      &source,
      0,
      4,
      &tmp,
      &final_path,
      CacheCopyFileRangeMode::Off,
    )
    .expect_err("short source should fail");

    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert!(!final_path.exists());
  }
}
