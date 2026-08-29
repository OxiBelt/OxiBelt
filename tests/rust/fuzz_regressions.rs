#![allow(clippy::expect_used, reason = "repository contract test")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const REGRESSION_ROOT: &str = "../tests/fixtures/fuzz-regressions";

/// Every committed reproducer must be named here and replayed by a focused
/// test in this file or in the owning module. The empty initial registry makes
/// an unreviewed fixture fail closed instead of silently entering the tree.
const REGISTERED_FIXTURES: &[&str] = &[
  "http_body_coding/large-window.txt",
  "path_security_semantics/nested-percent-route-bypass.txt",
];

fn fixture_files(root: &Path, directory: &Path, output: &mut BTreeSet<String>) {
  for entry in std::fs::read_dir(directory).expect("regression directory should be readable") {
    let entry = entry.expect("regression entry should be readable");
    let file_type = entry
      .file_type()
      .expect("regression entry type should load");
    assert!(
      !file_type.is_symlink(),
      "fuzz regression fixtures must not be symlinks"
    );
    let path = entry.path();
    if file_type.is_dir() {
      fixture_files(root, &path, output);
    } else if path.file_name().and_then(|name| name.to_str()) != Some("README.md") {
      let relative = path
        .strip_prefix(root)
        .expect("fixture should stay below its root")
        .to_string_lossy()
        .replace('\\', "/");
      output.insert(relative);
    }
  }
}

#[test]
fn every_fuzz_regression_fixture_has_an_explicit_replay() {
  let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(REGRESSION_ROOT);
  let mut actual = BTreeSet::new();
  fixture_files(&root, &root, &mut actual);
  let registered = REGISTERED_FIXTURES
    .iter()
    .map(|fixture| (*fixture).to_string())
    .collect::<BTreeSet<_>>();
  assert_eq!(
    actual, registered,
    "add every minimized fixture to REGISTERED_FIXTURES and a deterministic replay test"
  );
}
