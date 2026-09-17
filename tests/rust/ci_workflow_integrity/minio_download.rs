use super::{repo_root, write_executable};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn helper_path() -> std::path::PathBuf {
  repo_root().join("tests/docker/ct_object_store_minio/prefetch-go-modules.sh")
}

fn shimmed_path(bin_dir: &Path) -> std::ffi::OsString {
  let mut entries = vec![bin_dir.to_path_buf()];
  if let Some(path) = std::env::var_os("PATH") {
    entries.extend(std::env::split_paths(&path));
  }
  std::env::join_paths(entries).expect("shimmed PATH should be representable")
}

fn write_timeout_shim(bin_dir: &Path) {
  write_executable(
    &bin_dir.join("timeout"),
    r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >>"${MINIO_TIMEOUT_LOG}"
attempts="$(wc -l <"${MINIO_TIMEOUT_LOG}")"
case "${MINIO_PREFETCH_SCENARIO}" in
  success) exit 0 ;;
  transient)
    [ "${attempts}" -eq 1 ] && exit 75
    exit 0
    ;;
  timeout) exit 124 ;;
  exhaustion) exit 88 ;;
  integrity) exit 1 ;;
  *) exit 64 ;;
esac
"#,
  );
  write_executable(
    &bin_dir.join("sleep"),
    r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >>"${MINIO_SLEEP_LOG}"
"#,
  );
}

fn run_helper(bin_dir: &Path, scenario: &str, temp_dir: &Path) -> Output {
  Command::new("sh")
    .arg(helper_path())
    .current_dir(repo_root())
    .env("PATH", shimmed_path(bin_dir))
    .env("MINIO_PREFETCH_SCENARIO", scenario)
    .env("MINIO_TIMEOUT_LOG", temp_dir.join("timeout.log"))
    .env("MINIO_SLEEP_LOG", temp_dir.join("sleep.log"))
    .output()
    .expect("MinIO Go module prefetch helper should execute")
}

fn logged_lines(path: &Path) -> Vec<String> {
  match fs::read_to_string(path) {
    Ok(text) => text.lines().map(str::to_owned).collect(),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
    Err(error) => panic!("test log should be readable: {error}"),
  }
}

#[test]
fn minio_go_module_prefetch_is_bounded_and_retries_only_acquisition() {
  let temp_dir =
    tempfile::tempdir().expect("temporary MinIO prefetch directory should be creatable");
  let bin_dir = temp_dir.path().join("bin");
  fs::create_dir(&bin_dir).expect("MinIO prefetch shim directory should be creatable");
  write_timeout_shim(&bin_dir);

  for (scenario, expected_attempts, expected_status) in [
    ("success", 1, 0),
    ("transient", 2, 0),
    ("timeout", 2, 124),
    ("exhaustion", 2, 88),
    ("integrity", 2, 1),
  ] {
    let case_dir = temp_dir.path().join(scenario);
    fs::create_dir(&case_dir).expect("MinIO prefetch case directory should be creatable");
    let output = run_helper(&bin_dir, scenario, &case_dir);
    assert_eq!(
      output.status.code(),
      Some(expected_status),
      "{scenario} should preserve the prefetch status: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
      logged_lines(&case_dir.join("timeout.log")),
      vec!["-s TERM -k 5 600 go mod download".to_owned(); expected_attempts],
      "{scenario} should use the bounded Go module download command"
    );
    assert_eq!(
      logged_lines(&case_dir.join("sleep.log")),
      vec!["5".to_owned(); expected_attempts.saturating_sub(1)],
      "{scenario} should back off only between attempts"
    );
  }
}

#[test]
fn minio_prefetch_failure_blocks_the_single_offline_read_only_compile() {
  let dockerfile =
    fs::read_to_string(repo_root().join("tests/docker/ct_object_store_minio/Dockerfile"))
      .expect("CT object-store MinIO Dockerfile should be readable");
  let prefetch = dockerfile
    .find("RUN prefetch-go-modules")
    .expect("Dockerfile should prefetch Go modules in a separate build layer");
  let build = dockerfile
    .find("CGO_ENABLED=0 GOPROXY=off go build -mod=readonly")
    .expect(
      "Dockerfile should compile once without dependency network downloads or version updates",
    );
  assert!(
    prefetch < build,
    "failed module prefetch must stop before compilation"
  );
  assert!(
    dockerfile.contains("RUN --network=none test"),
    "the compile layer must have no network access"
  );
  assert_eq!(
    dockerfile.matches("go build").count(),
    1,
    "MinIO should compile once"
  );
  assert!(
    !dockerfile.contains("GOSUMDB=off"),
    "Go checksum verification must remain enabled"
  );
  assert!(
    !dockerfile.contains("GONOSUMDB="),
    "Go checksum verification must not be bypassed"
  );
  assert!(
    !dockerfile.contains("GOPROXY=direct"),
    "the compile must not fall back to network downloads"
  );
}
