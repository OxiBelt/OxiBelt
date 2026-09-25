use super::{repo_root, write_executable};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn managed_upload_script() -> PathBuf {
  repo_root().join("tests/scripts/run-managed-upload-store.sh")
}

fn shimmed_path(bin_dir: &Path) -> std::ffi::OsString {
  let mut entries = vec![bin_dir.to_path_buf()];
  if let Some(path) = std::env::var_os("PATH") {
    entries.extend(std::env::split_paths(&path));
  }
  std::env::join_paths(entries).expect("shimmed PATH should be representable")
}

fn write_shims(bin_dir: &Path) {
  write_executable(
    &bin_dir.join("docker"),
    r#"#!/usr/bin/env bash
set -euo pipefail

record() {
  printf '%s\n' "$1" >>"${STUB_DOCKER_LOG}"
}

case "$1" in
  version)
    exit 0
    ;;
  info)
    printf '%s\n' 'name=rootless'
    ;;
  inspect)
    exit 1
    ;;
  run)
    if [[ " $* " == *" --version "* ]]; then
      printf '%s\n' 'mc version RELEASE.2025-08-13T08-35-41Z (commit-id=7394ce0dd2a80935aded936b09fa12cbb3cb8096)'
    fi
    if [[ " $* " == *" --entrypoint id "* ]]; then
      printf '%s\n' 1000
    fi
    ;;
  build|create|cp|start|network|volume|image)
    ;;
  port)
    if [[ "${3:-}" == "9000/tcp" ]]; then printf '%s\n' '127.0.0.1:9000'; else printf '%s\n' '127.0.0.1:5432'; fi
    ;;
  exec)
    [[ "${3:-}" == pg_isready ]] || exit 97
    record "pg_isready ${*:4}"
    attempt=0
    if [[ -f "${STUB_PG_ATTEMPTS}" ]]; then attempt="$(cat "${STUB_PG_ATTEMPTS}")"; fi
    attempt=$((attempt + 1))
    printf '%s\n' "${attempt}" >"${STUB_PG_ATTEMPTS}"
    case "${STUB_PG_SCENARIO}" in
      socket-only)
        [[ " $* " == *" --host 127.0.0.1 "* ]] && exit 2
        exit 0
        ;;
      delayed-tcp)
        [[ " $* " == *" --host 127.0.0.1 "* ]] || exit 0
        ((attempt >= 3)) && exit 0
        exit 2
        ;;
      exhausted)
        exit 2
        ;;
      *)
        exit 98
        ;;
    esac
    ;;
  logs)
    record "logs $*"
    printf '%s\n' 'stub PostgreSQL startup diagnostic' >&2
    ;;
  rm)
    record "rm $*"
    ;;
  *)
    printf 'unexpected fake docker command: %s\n' "$*" >&2
    exit 99
    ;;
esac
"#,
  );
  write_executable(
    &bin_dir.join("openssl"),
    r#"#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  req|x509)
    shift
    while (($#)); do
      case "$1" in
        -keyout|-out)
          : >"$2"
          shift 2
          ;;
        *) shift ;;
      esac
    done
    ;;
  s_client) ;;
  *) exit 97 ;;
esac
"#,
  );
  write_executable(&bin_dir.join("sleep"), "#!/usr/bin/env bash\nexit 0\n");
  write_executable(
    &bin_dir.join("managed-upload-test"),
    "#!/usr/bin/env bash\nexit 0\n",
  );
}

fn run_fixture(bin_dir: &Path, temp_dir: &Path, scenario: &str) -> Output {
  let docker_log = temp_dir.join("docker.log");
  let attempts = temp_dir.join("pg-attempts");
  fs::remove_file(&docker_log).ok();
  fs::remove_file(&attempts).ok();
  Command::new("bash")
    .arg(managed_upload_script())
    .arg("--test-binary")
    .arg(bin_dir.join("managed-upload-test"))
    .current_dir(repo_root())
    .env("PATH", shimmed_path(bin_dir))
    .env("STUB_DOCKER_LOG", &docker_log)
    .env("STUB_PG_ATTEMPTS", &attempts)
    .env("STUB_PG_SCENARIO", scenario)
    .output()
    .unwrap_or_else(|error| panic!("managed-upload {scenario} fixture should execute: {error}"))
}

fn docker_log(temp_dir: &Path) -> String {
  fs::read_to_string(temp_dir.join("docker.log")).expect("Docker calls should record")
}

#[test]
fn managed_upload_store_waits_for_final_postgres_tcp_listener() {
  let temp_dir = tempfile::Builder::new()
    .prefix("oxibelt-managed-upload-postgres-readiness-")
    .tempdir()
    .expect("managed-upload readiness fixture directory should be creatable");
  let bin_dir = temp_dir.path().join("bin");
  write_shims(&bin_dir);

  let socket_only = run_fixture(&bin_dir, temp_dir.path(), "socket-only");
  assert!(
    !socket_only.status.success(),
    "socket-only readiness must not pass"
  );
  let socket_only_stderr = String::from_utf8_lossy(&socket_only.stderr);
  assert!(
    socket_only_stderr.contains("PostgreSQL TCP listener did not become ready after 30 attempts")
  );
  assert!(socket_only_stderr.contains("stub PostgreSQL startup diagnostic"));
  let socket_only_log = docker_log(temp_dir.path());
  assert_eq!(socket_only_log.matches("pg_isready ").count(), 30);
  assert!(
    socket_only_log
      .lines()
      .filter(|line| line.starts_with("pg_isready "))
      .all(|line| line.contains("--host 127.0.0.1 --username oxibelt --dbname oxibelt")),
    "socket-only readiness must never use PostgreSQL's temporary Unix socket: {socket_only_log}"
  );
  assert!(socket_only_log.contains("logs logs --tail 200"));

  let delayed_tcp = run_fixture(&bin_dir, temp_dir.path(), "delayed-tcp");
  assert!(
    delayed_tcp.status.success(),
    "delayed final TCP listener should pass: {}",
    String::from_utf8_lossy(&delayed_tcp.stderr)
  );
  let delayed_tcp_log = docker_log(temp_dir.path());
  assert_eq!(delayed_tcp_log.matches("pg_isready ").count(), 3);
  assert!(!delayed_tcp_log.contains("logs logs"));

  let exhausted = run_fixture(&bin_dir, temp_dir.path(), "exhausted");
  assert!(!exhausted.status.success(), "exhausted readiness must fail");
  let exhausted_stderr = String::from_utf8_lossy(&exhausted.stderr);
  assert!(
    exhausted_stderr.contains("PostgreSQL TCP listener did not become ready after 30 attempts")
  );
  assert!(exhausted_stderr.contains("stub PostgreSQL startup diagnostic"));
  let exhausted_log = docker_log(temp_dir.path());
  assert_eq!(exhausted_log.matches("pg_isready ").count(), 30);
  let diagnostics = exhausted_log
    .find("logs logs --tail 200")
    .expect("timeout must collect bounded PostgreSQL logs");
  let cleanup = exhausted_log[diagnostics..]
    .find("rm rm -fv")
    .expect("timeout must clean PostgreSQL after diagnostics");
  assert!(cleanup > 0, "cleanup must follow PostgreSQL diagnostics");
}
