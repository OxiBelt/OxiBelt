//! Bounded reads for Linux platform files used after runtime confinement.
//!
//! Callers remain responsible for declaring every path in the generated
//! filesystem-access manifest.  Keeping the I/O here ensures procfs, sysfs,
//! and cgroup pseudo-files cannot make diagnostics or overload sampling
//! allocate without a fixed upper bound.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub(crate) const MAX_PLATFORM_TEXT_BYTES: u64 = 256 * 1024;
pub(crate) const MAX_PLATFORM_DIRECTORY_ENTRIES: usize = 1_048_576;

pub(crate) fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
  read_to_string_with_limit(path, MAX_PLATFORM_TEXT_BYTES)
}

pub(crate) fn read_to_string_with_limit(
  path: impl AsRef<Path>,
  maximum_bytes: u64,
) -> io::Result<String> {
  let path = path.as_ref();
  let file = File::open(path)?;
  let mut input = String::new();
  file
    .take(maximum_bytes.saturating_add(1))
    .read_to_string(&mut input)?;
  if input.len() as u64 > maximum_bytes {
    return Err(io::Error::new(
      io::ErrorKind::InvalidData,
      format!(
        "platform file {} exceeds {maximum_bytes} bytes",
        path.display()
      ),
    ));
  }
  Ok(input)
}

pub(crate) fn count_directory_entries(path: impl AsRef<Path>) -> io::Result<usize> {
  let path = path.as_ref();
  let mut count = 0_usize;
  for entry in std::fs::read_dir(path)? {
    entry?;
    count = count.saturating_add(1);
    if count > MAX_PLATFORM_DIRECTORY_ENTRIES {
      return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
          "platform directory {} exceeds {MAX_PLATFORM_DIRECTORY_ENTRIES} entries",
          path.display()
        ),
      ));
    }
  }
  Ok(count)
}

#[cfg(test)]
mod tests {
  use std::fs;

  use super::*;

  #[test]
  fn bounded_text_rejects_oversized_platform_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status");
    fs::write(&path, b"12345").unwrap();

    let error = read_to_string_with_limit(&path, 4).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
  }

  #[test]
  fn bounded_text_accepts_exact_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status");
    fs::write(&path, b"1234").unwrap();

    assert_eq!(read_to_string_with_limit(&path, 4).unwrap(), "1234");
  }
}
