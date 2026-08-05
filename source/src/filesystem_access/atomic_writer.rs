//! Recognition of Kubernetes AtomicWriter projection topology.
//!
//! This module never changes the path used for filesystem checks or Landlock
//! enforcement. It only returns a stable logical identity after proving that a
//! canonical target belongs to the generation selected by an exact `..data`
//! link and is reachable through the corresponding visible top-level link.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Eq, PartialEq)]
struct SymlinkSnapshot {
  device: u64,
  inode: u64,
  change_time: i64,
  change_time_nanoseconds: i64,
  target: PathBuf,
}

pub(super) fn digest_identity_path(logical: &Path, canonical: &Path) -> Option<PathBuf> {
  if !logical.is_absolute() || !canonical.is_absolute() {
    return None;
  }

  for timestamp_root in canonical.ancestors() {
    let timestamp_name = timestamp_root.file_name()?;
    if !is_timestamp_directory_name(timestamp_name.as_bytes()) {
      continue;
    }
    let volume_root = timestamp_root.parent()?;
    let relative_target = canonical.strip_prefix(timestamp_root).ok()?;

    if fs::symlink_metadata(timestamp_root)
      .ok()
      .is_none_or(|metadata| !metadata.is_dir() || metadata.file_type().is_symlink())
    {
      continue;
    }

    let data_link = volume_root.join("..data");
    let Some(data_snapshot) = exact_symlink_snapshot(&data_link, Path::new(timestamp_name)) else {
      continue;
    };
    if data_link.canonicalize().ok().as_deref() != Some(timestamp_root) {
      continue;
    }

    if relative_target.as_os_str().is_empty() {
      if logical == timestamp_root
        && exact_symlink_snapshot(&data_link, Path::new(timestamp_name)).as_ref()
          == Some(&data_snapshot)
      {
        return Some(volume_root.to_path_buf());
      }
      continue;
    }

    let top_name = match relative_target.components().next() {
      Some(Component::Normal(name)) => name,
      _ => continue,
    };

    let visible_top = volume_root.join(top_name);
    let expected_visible_target = Path::new("..data").join(top_name);
    let Some(visible_snapshot) = exact_symlink_snapshot(&visible_top, &expected_visible_target)
    else {
      continue;
    };

    let reconstructed = volume_root.join(relative_target);
    if (logical != reconstructed && logical != canonical)
      || reconstructed.canonicalize().ok().as_deref() != Some(canonical)
      || exact_symlink_snapshot(&data_link, Path::new(timestamp_name)).as_ref()
        != Some(&data_snapshot)
      || exact_symlink_snapshot(&visible_top, &expected_visible_target).as_ref()
        != Some(&visible_snapshot)
    {
      continue;
    }

    return Some(reconstructed);
  }
  None
}

fn exact_symlink_snapshot(path: &Path, expected_target: &Path) -> Option<SymlinkSnapshot> {
  let before = fs::symlink_metadata(path).ok()?;
  if !before.file_type().is_symlink() {
    return None;
  }
  let target = fs::read_link(path).ok()?;
  let after = fs::symlink_metadata(path).ok()?;
  let snapshot = |metadata: &fs::Metadata, target: PathBuf| SymlinkSnapshot {
    device: metadata.dev(),
    inode: metadata.ino(),
    change_time: metadata.ctime(),
    change_time_nanoseconds: metadata.ctime_nsec(),
    target,
  };
  let before = snapshot(&before, target.clone());
  let after = snapshot(&after, target);
  (before == after && before.target == expected_target).then_some(before)
}

fn is_timestamp_directory_name(name: &[u8]) -> bool {
  // AtomicWriter passes `..YYYY_MM_DD_HH_MM_SS.` to Go's MkdirTemp, which
  // appends the decimal representation of a random `uint32` (one to ten
  // digits). Keeping the prefix and suffix recognition exact prevents
  // ordinary dot-directories from acquiring a logical digest identity merely
  // because matching symlinks were present.
  if !(23..=32).contains(&name.len()) || &name[..2] != b".." {
    return false;
  }
  for separator in [6, 9, 12, 15, 18] {
    if name[separator] != b'_' {
      return false;
    }
  }
  if name[21] != b'.' {
    return false;
  }
  for range in [2..6, 7..9, 10..12, 13..15, 16..18, 19..21] {
    if !name[range].iter().all(u8::is_ascii_digit) {
      return false;
    }
  }
  if !name[22..].iter().all(u8::is_ascii_digit) {
    return false;
  }
  numeric_component(name, 7, 9).is_some_and(|value| (1..=12).contains(&value))
    && numeric_component(name, 10, 12).is_some_and(|value| (1..=31).contains(&value))
    && numeric_component(name, 13, 15).is_some_and(|value| value <= 23)
    && numeric_component(name, 16, 18).is_some_and(|value| value <= 59)
    && numeric_component(name, 19, 21).is_some_and(|value| value <= 59)
}

fn numeric_component(name: &[u8], start: usize, end: usize) -> Option<u8> {
  std::str::from_utf8(name.get(start..end)?)
    .ok()?
    .parse()
    .ok()
}

#[cfg(test)]
mod tests {
  use std::os::unix::fs::symlink;

  use super::*;

  const FIRST_GENERATION: &str = "..2026_08_05_12_34_56.1234567890";

  fn create_projection(volume: &Path, generation: &str, relative: &Path) -> (PathBuf, PathBuf) {
    let generation_root = volume.join(generation);
    let target = generation_root.join(relative);
    fs::create_dir_all(target.parent().expect("target parent")).expect("create generation");
    fs::write(&target, b"fixture").expect("write projected file");
    symlink(generation, volume.join("..data")).expect("create data link");
    let top = relative
      .components()
      .next()
      .expect("top component")
      .as_os_str();
    symlink(Path::new("..data").join(top), volume.join(top)).expect("create visible link");
    (
      volume.join(relative),
      target.canonicalize().expect("canonical target"),
    )
  }

  #[test]
  fn recognizes_flat_and_nested_projected_paths() {
    let flat_temp = tempfile::tempdir().expect("flat tempdir");
    let (flat_logical, flat_canonical) =
      create_projection(flat_temp.path(), FIRST_GENERATION, Path::new("tls.crt"));
    assert_eq!(
      digest_identity_path(&flat_logical, &flat_canonical),
      Some(flat_logical.clone())
    );
    assert_eq!(
      digest_identity_path(&flat_canonical, &flat_canonical),
      Some(flat_logical)
    );

    let nested_temp = tempfile::tempdir().expect("nested tempdir");
    let (nested_logical, nested_canonical) = create_projection(
      nested_temp.path(),
      FIRST_GENERATION,
      Path::new("nested/config/oxibelt.toml"),
    );
    assert_eq!(
      digest_identity_path(&nested_logical, &nested_canonical),
      Some(nested_logical)
    );
  }

  #[test]
  fn recognizes_the_selected_timestamp_root_for_rotation_parent_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (_logical, canonical) =
      create_projection(temp.path(), FIRST_GENERATION, Path::new("config"));
    let timestamp_root = canonical.parent().expect("timestamp root");

    assert_eq!(
      digest_identity_path(timestamp_root, timestamp_root),
      Some(temp.path().to_path_buf())
    );
  }

  #[test]
  fn rejects_missing_or_inconsistent_atomic_writer_links() {
    let missing = tempfile::tempdir().expect("missing tempdir");
    let generation = missing.path().join(FIRST_GENERATION);
    fs::create_dir(&generation).expect("create generation");
    fs::write(generation.join("config"), b"fixture").expect("write target");
    let canonical = generation.join("config").canonicalize().expect("canonical");
    let logical = missing.path().join("config");
    assert_eq!(digest_identity_path(&logical, &canonical), None);

    let inconsistent = tempfile::tempdir().expect("inconsistent tempdir");
    let (logical, canonical) =
      create_projection(inconsistent.path(), FIRST_GENERATION, Path::new("config"));
    fs::remove_file(&logical).expect("remove visible link");
    symlink("..data/other", &logical).expect("create inconsistent visible link");
    assert_eq!(digest_identity_path(&logical, &canonical), None);
  }

  #[test]
  fn rejects_escaping_and_lookalike_layouts() {
    let escaping = tempfile::tempdir().expect("escaping tempdir");
    let outside = tempfile::tempdir().expect("outside tempdir");
    fs::write(outside.path().join("config"), b"outside").expect("write outside target");
    symlink(outside.path(), escaping.path().join("..data")).expect("create escaping data link");
    symlink("..data/config", escaping.path().join("config")).expect("create visible escaping link");
    let canonical = escaping
      .path()
      .join("config")
      .canonicalize()
      .expect("canonical outside target");
    assert_eq!(
      digest_identity_path(&escaping.path().join("config"), &canonical),
      None
    );

    let lookalike = tempfile::tempdir().expect("lookalike tempdir");
    let (logical, canonical) = create_projection(
      lookalike.path(),
      "..2026_08_05_12_34_56.not-a-stamp",
      Path::new("config"),
    );
    assert_eq!(digest_identity_path(&logical, &canonical), None);
  }

  #[test]
  fn ordinary_symlinks_keep_their_canonical_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let actual = temp.path().join("actual");
    fs::write(&actual, b"fixture").expect("write target");
    let logical = temp.path().join("visible");
    symlink("actual", &logical).expect("create ordinary symlink");
    let canonical = logical.canonicalize().expect("canonical target");
    assert_eq!(digest_identity_path(&logical, &canonical), None);
  }

  #[test]
  fn revalidation_detects_an_atomic_data_link_replacement() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (_logical, _canonical) =
      create_projection(temp.path(), FIRST_GENERATION, Path::new("config"));
    let data_link = temp.path().join("..data");
    let before = exact_symlink_snapshot(&data_link, Path::new(FIRST_GENERATION))
      .expect("initial data-link snapshot");
    symlink(FIRST_GENERATION, temp.path().join("..data.next"))
      .expect("create replacement data link");
    fs::rename(temp.path().join("..data.next"), &data_link).expect("replace data link");
    let after = exact_symlink_snapshot(&data_link, Path::new(FIRST_GENERATION))
      .expect("replacement data-link snapshot");

    assert_ne!(before, after);
  }

  #[test]
  fn timestamp_name_validation_is_exact() {
    assert!(is_timestamp_directory_name(FIRST_GENERATION.as_bytes()));
    assert!(is_timestamp_directory_name(
      b"..2016_02_01_15_04_05.12345678"
    ));
    assert!(!is_timestamp_directory_name(
      b"..2026_13_05_12_34_56.1234567890"
    ));
    assert!(!is_timestamp_directory_name(
      b"..2026_08_05_12_34_56.12345678901"
    ));
    assert!(!is_timestamp_directory_name(
      b"..2026_08_05_12_34_56.123456789x"
    ));
  }
}
