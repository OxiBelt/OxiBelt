//! Downstream compile and deterministic API snapshot contract for runtime embedding.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    .parent()
    .expect("source manifest must have a repository parent")
    .to_path_buf()
}

fn fixture_dir() -> PathBuf {
  repo_root().join("tests/fixtures/owned-embedded-runtime-api")
}

fn checker_output(
  fixture: Option<&std::path::Path>,
  current_dir: Option<&std::path::Path>,
) -> std::process::Output {
  let script = repo_root().join("tests/scripts/check-owned-embedded-runtime-api.sh");
  let mut command = Command::new("bash");
  command.arg(&script);
  if let Some(fixture) = fixture {
    command.env("OXIBELT_OWNED_EMBEDDED_RUNTIME_API_FIXTURE", fixture);
  }
  if let Some(current_dir) = current_dir {
    command.current_dir(current_dir);
  }
  command
    .output()
    .unwrap_or_else(|error| panic!("{} should start: {error}", script.display()))
}

fn copy_fixture(destination: &std::path::Path) {
  fs::create_dir_all(destination.join("src")).expect("fixture destination should be writable");
  for relative in ["Cargo.toml", "lifecycle-api.snapshot", "src/main.rs"] {
    fs::copy(fixture_dir().join(relative), destination.join(relative))
      .unwrap_or_else(|error| panic!("fixture {relative} should copy: {error}"));
  }
}

#[test]
fn downstream_fixture_compiles_and_matches_the_lifecycle_snapshot() {
  let script = repo_root().join("tests/scripts/check-owned-embedded-runtime-api.sh");
  let outside_repository = tempfile::tempdir().expect("outside-repository directory should exist");
  let output = checker_output(None, Some(outside_repository.path()));
  assert!(
    output.status.success(),
    "{} failed:\nstdout:\n{}\nstderr:\n{}",
    script.display(),
    String::from_utf8_lossy(&output.stdout),
    String::from_utf8_lossy(&output.stderr),
  );
}

#[test]
fn authoritative_snapshot_rejects_a_removed_compile_probe() {
  let temporary = tempfile::tempdir().expect("temporary fixture directory should exist");
  let fixture = temporary.path().join("fixture");
  copy_fixture(&fixture);

  let source_path = fixture.join("src/main.rs");
  let source = fs::read_to_string(&source_path).expect("fixture source should read");
  let removed = source.replace("surface_OxiBelt__builder", "removed_OxiBelt__builder");
  assert_ne!(
    source, removed,
    "fixture must retain the builder compile probe"
  );
  fs::write(&source_path, removed).expect("fixture source should be writable");

  let output = checker_output(Some(&fixture), None);
  assert!(
    !output.status.success(),
    "removing a compile probe must fail the authoritative snapshot check"
  );
  assert!(
    String::from_utf8_lossy(&output.stdout).contains("OxiBelt::builder"),
    "failure should identify the removed public surface"
  );
}

#[test]
fn fixture_inventory_rejects_a_cargo_lock_symlink_without_following_it() {
  let temporary = tempfile::tempdir().expect("temporary fixture directory should exist");
  let fixture = temporary.path().join("fixture");
  let outside_lock = temporary.path().join("outside-lock");
  copy_fixture(&fixture);
  fs::write(&outside_lock, "outside lock sentinel\n").expect("outside lock should be writable");
  symlink(&outside_lock, fixture.join("Cargo.lock")).expect("fixture lock symlink should create");

  let output = checker_output(Some(&fixture), None);
  assert!(
    !output.status.success(),
    "fixture Cargo.lock symlink must be rejected"
  );
  assert_eq!(
    fs::read_to_string(&outside_lock).expect("outside lock should remain readable"),
    "outside lock sentinel\n",
    "rejected fixture symlink must never be followed"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr).contains("fixture inventory"),
    "failure should identify the constrained fixture inventory"
  );
}

#[test]
fn fixture_inventory_rejects_an_unexpected_build_script_without_execution() {
  let temporary = tempfile::tempdir().expect("temporary fixture directory should exist");
  let fixture = temporary.path().join("fixture");
  let marker = temporary.path().join("build-script-executed");
  copy_fixture(&fixture);
  fs::write(
    fixture.join("build.rs"),
    format!("fn main() {{ std::fs::write({marker:?}, \"executed\").unwrap(); }}\n"),
  )
  .expect("unexpected build script should be writable");

  let output = checker_output(Some(&fixture), None);
  assert!(
    !output.status.success(),
    "unexpected fixture build script must be rejected"
  );
  assert!(
    !marker.exists(),
    "rejected fixture build script must never execute"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr).contains("fixture inventory"),
    "failure should identify the constrained fixture inventory"
  );
}

#[test]
fn cfg_disabled_fake_surface_probe_is_rejected() {
  let temporary = tempfile::tempdir().expect("temporary fixture directory should exist");
  let fixture = temporary.path().join("fixture");
  copy_fixture(&fixture);

  let source_path = fixture.join("src/main.rs");
  let source = fs::read_to_string(&source_path).expect("fixture source should read");
  let source = source.replace("surface_OxiBelt__builder", "removed_OxiBelt__builder");
  fs::write(
    &source_path,
    format!("{source}\n#[cfg(any())]\nfn surface_OxiBelt__builder() {{}}\n"),
  )
  .expect("fixture source should be writable");

  let output = checker_output(Some(&fixture), None);
  assert!(
    !output.status.success(),
    "cfg-disabled surface probe must be rejected"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr).contains("cfg attributes"),
    "failure should identify cfg suppression"
  );
}

#[test]
fn manifest_build_redirect_is_rejected_without_execution() {
  let temporary = tempfile::tempdir().expect("temporary fixture directory should exist");
  let fixture = temporary.path().join("fixture");
  let outside_build = temporary.path().join("outside-build.rs");
  let marker = temporary.path().join("build-redirect-executed");
  copy_fixture(&fixture);
  fs::write(
    &outside_build,
    format!("fn main() {{ std::fs::write({marker:?}, \"executed\").unwrap(); }}\n"),
  )
  .expect("outside build script should be writable");

  let manifest_path = fixture.join("Cargo.toml");
  let manifest = fs::read_to_string(&manifest_path).expect("fixture manifest should read");
  let manifest = manifest.replace("build = false\n", &format!("build = {outside_build:?}\n"));
  fs::write(&manifest_path, manifest).expect("fixture manifest should be writable");

  let output = checker_output(Some(&fixture), None);
  assert!(
    !output.status.success(),
    "manifest build redirect must be rejected"
  );
  assert!(
    !marker.exists(),
    "rejected manifest build redirect must never execute"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr).contains("canonical fixture manifest"),
    "failure should identify the canonical manifest requirement"
  );
}

#[test]
fn manifest_path_dependency_redirect_is_rejected() {
  let temporary = tempfile::tempdir().expect("temporary fixture directory should exist");
  let fixture = temporary.path().join("fixture");
  copy_fixture(&fixture);

  let manifest_path = fixture.join("Cargo.toml");
  let manifest = fs::read_to_string(&manifest_path).expect("fixture manifest should read");
  let manifest = manifest.replace(
    "path = \"../../../source\"",
    "path = \"/tmp/redirected-oxibelt-source\"",
  );
  fs::write(&manifest_path, manifest).expect("fixture manifest should be writable");

  let output = checker_output(Some(&fixture), None);
  assert!(
    !output.status.success(),
    "manifest path dependency redirect must be rejected"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr).contains("canonical fixture manifest"),
    "failure should identify the canonical manifest requirement"
  );
}

#[test]
fn retained_surface_source_mutation_is_rejected_before_cargo() {
  let temporary = tempfile::tempdir().expect("temporary fixture directory should exist");
  let fixture = temporary.path().join("fixture");
  copy_fixture(&fixture);

  let source_path = fixture.join("src/main.rs");
  let source = fs::read_to_string(&source_path).expect("fixture source should read");
  fs::write(&source_path, format!("{source}\n// source mutation\n"))
    .expect("fixture source should be writable");

  let output = checker_output(Some(&fixture), None);
  assert!(
    !output.status.success(),
    "retained-surface source mutation must be rejected"
  );
  assert!(
    String::from_utf8_lossy(&output.stderr).contains("canonical fixture source"),
    "failure should identify the canonical source requirement"
  );
}
