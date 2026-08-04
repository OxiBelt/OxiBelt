use std::fs;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;

#[cfg(target_os = "linux")]
const LANDLOCK_TEST_ROOT_ENV: &str = "OXIBELT_RUNTIME_CONFINEMENT_LANDLOCK_ROOT";

fn source_root() -> PathBuf {
  Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(root: &Path, files: &mut Vec<PathBuf>) {
  for entry in fs::read_dir(root).expect("source directory should be readable") {
    let entry = entry.expect("source entry should be readable");
    let path = entry.path();
    if path.is_dir() {
      rust_sources(&path, files);
    } else if path.extension().is_some_and(|extension| extension == "rs") {
      files.push(path);
    }
  }
}

#[test]
fn post_confinement_resolution_does_not_use_libc_nss() {
  let mut files = Vec::new();
  rust_sources(&source_root(), &mut files);
  let forbidden = ["tokio::net::lookup_host", ".to_socket_addrs()"];
  let mut violations = Vec::new();
  for path in files {
    let source = fs::read_to_string(&path).expect("Rust source should be readable");
    for token in forbidden {
      if source.contains(token) {
        violations.push(format!("{} contains {token}", path.display()));
      }
    }
  }
  assert!(
    violations.is_empty(),
    "runtime hostname resolution must use the bounded manifest-aware resolver:\n{}",
    violations.join("\n")
  );
}

#[cfg(target_os = "linux")]
#[test]
fn manifest_landlock_handles_ungranted_execute_and_special_creation() {
  use std::os::unix::fs::{PermissionsExt, symlink};
  use std::process::Command;

  use nix::errno::Errno;
  use nix::sys::stat::Mode;
  use nix::unistd::mkfifo;
  use oxibelt::config::{
    HardeningAutoMode, RuntimeHardeningConfig, RuntimeLandlockConfig, RuntimeLandlockMode,
  };
  use oxibelt::hardening::{
    LandlockFilesystemRight, LandlockManifestProjection, LandlockManifestRule,
    ReadOnlyRootfsCompatibility, apply_runtime_hardening_with_manifest,
  };

  let root = if let Some(child_root) = std::env::var_os(LANDLOCK_TEST_ROOT_ENV) {
    let child_root = PathBuf::from(child_root);
    assert!(!common::run_test_in_subprocess_with_env(
      "manifest_landlock_handles_ungranted_execute_and_special_creation",
      &[(LANDLOCK_TEST_ROOT_ENV, child_root.as_os_str())],
    ));
    child_root
  } else {
    let parent_root = common::TempDir::new("manifest-landlock-special-rights");
    assert!(common::run_test_in_subprocess_with_env(
      "manifest_landlock_handles_ungranted_execute_and_special_creation",
      &[(LANDLOCK_TEST_ROOT_ENV, parent_root.path().as_os_str())],
    ));
    return;
  };
  let executable = root.join("malformed-executable");
  let symlink_path = root.join("created-symlink");
  let fifo_path = root.join("created-fifo");

  fs::write(&executable, b"not an executable\n").expect("create executable preflight fixture");
  fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
    .expect("make preflight fixture executable");
  let preflight_exec = Command::new(&executable)
    .status()
    .expect_err("malformed executable should reach execve before Landlock is installed");
  assert_eq!(
    preflight_exec.raw_os_error(),
    Some(libc::ENOEXEC),
    "preflight must prove DAC and path traversal permit execution"
  );
  symlink("target", &symlink_path).expect("symlink creation should work before Landlock");
  fs::remove_file(&symlink_path).expect("remove preflight symlink");
  mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR)
    .expect("FIFO creation should work before Landlock");
  fs::remove_file(&fifo_path).expect("remove preflight FIFO");

  let config = RuntimeHardeningConfig {
    close_range: HardeningAutoMode::Off,
    landlock: RuntimeLandlockConfig {
      mode: RuntimeLandlockMode::Manifest,
      read_paths: Vec::new(),
      read_write_paths: vec![root.clone()],
    },
    ..RuntimeHardeningConfig::default()
  };
  let manifest = LandlockManifestProjection {
    manifest_digest: format!("sha256:{}", "0".repeat(64)),
    read_paths: Vec::new(),
    read_write_paths: vec![root.clone()],
    rules: vec![LandlockManifestRule {
      path: root.clone(),
      access: vec![
        LandlockFilesystemRight::ReadFile,
        LandlockFilesystemRight::ReadDir,
      ],
    }],
    read_only_rootfs: ReadOnlyRootfsCompatibility::Compatible,
    parent_scope_representable: true,
  };
  let snapshot = apply_runtime_hardening_with_manifest(&config, Some(&manifest))
    .expect("install manifest-derived Landlock confinement");

  for right in [
    LandlockFilesystemRight::Execute,
    LandlockFilesystemRight::MakeChar,
    LandlockFilesystemRight::MakeFifo,
    LandlockFilesystemRight::MakeBlock,
    LandlockFilesystemRight::MakeSym,
  ] {
    assert!(
      snapshot.landlock.effective_rights.contains(&right),
      "Landlock ruleset must handle {right:?}"
    );
    assert!(
      snapshot
        .landlock
        .effective_rules
        .iter()
        .all(|rule| !rule.access.contains(&right)),
      "manifest path grants must not allow {right:?}"
    );
  }

  let regular_file = root.join("allowed-regular-file");
  fs::write(&regular_file, b"allowed").expect("regular-file creation should remain allowed");
  assert_eq!(
    fs::read(&regular_file).expect("regular-file reads should remain allowed"),
    b"allowed"
  );

  let denied_exec = Command::new(&executable)
    .status()
    .expect_err("Landlock must deny execution even when read access is granted");
  assert_eq!(denied_exec.raw_os_error(), Some(libc::EACCES));
  let denied_symlink =
    symlink("target", &symlink_path).expect_err("Landlock must deny symlink creation");
  assert_eq!(denied_symlink.raw_os_error(), Some(libc::EACCES));
  let denied_fifo = mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR)
    .expect_err("Landlock must deny FIFO creation");
  assert_eq!(denied_fifo, Errno::EACCES);
}
