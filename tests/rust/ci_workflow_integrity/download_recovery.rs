use super::{repo_root, write_executable};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone)]
enum HttpReply {
  GatewayTimeout,
  Complete(Vec<u8>),
  Truncated(Vec<u8>),
}

fn fixture_tempdir(prefix: &str) -> tempfile::TempDir {
  tempfile::Builder::new()
    .prefix(prefix)
    .tempdir()
    .expect("temporary download fixture directory should be creatable")
}

fn sha256_hex(bytes: &[u8]) -> String {
  let mut encoded = String::with_capacity(64);
  for byte in Sha256::digest(bytes) {
    encoded.push_str(&format!("{byte:02x}"));
  }
  encoded
}

fn partial_files(parent: &Path, destination: &Path) -> Vec<PathBuf> {
  let prefix = format!(
    "{}.partial.",
    destination
      .file_name()
      .expect("download destination should have a filename")
      .to_string_lossy()
  );
  fs::read_dir(parent)
    .expect("download destination parent should remain readable")
    .filter_map(Result::ok)
    .map(|entry| entry.path())
    .filter(|path| {
      path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
    })
    .collect()
}

fn staging_directories(parent: &Path) -> Vec<PathBuf> {
  fs::read_dir(parent)
    .expect("installer parent should remain readable")
    .filter_map(Result::ok)
    .map(|entry| entry.path())
    .filter(|path| {
      path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with(".oxibelt-ci-tools."))
    })
    .collect()
}

fn shimmed_path(bin_dir: &Path) -> std::ffi::OsString {
  let mut entries = vec![bin_dir.to_path_buf()];
  if let Some(path) = std::env::var_os("PATH") {
    entries.extend(std::env::split_paths(&path));
  }
  std::env::join_paths(entries).expect("shimmed PATH should be representable")
}

fn read_http_request(stream: &mut TcpStream) {
  let mut request = Vec::new();
  let mut buffer = [0u8; 1024];
  while let Ok(read) = stream.read(&mut buffer) {
    if read == 0 {
      break;
    }
    request.extend_from_slice(&buffer[..read]);
    if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() > 16 * 1024 {
      break;
    }
  }
}

fn write_http_reply(stream: &mut TcpStream, reply: &HttpReply) {
  match reply {
    HttpReply::GatewayTimeout => {
      stream
        .write_all(
          b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .expect("fixture should return its 504 response");
    }
    HttpReply::Complete(body) => {
      write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
      )
      .expect("fixture should write a complete response header");
      stream
        .write_all(body)
        .expect("fixture should write the complete response body");
    }
    HttpReply::Truncated(body) => {
      write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len() + 64
      )
      .expect("fixture should write the truncated response header");
      stream
        .write_all(body)
        .expect("fixture should write the truncated response prefix");
      stream
        .shutdown(Shutdown::Both)
        .expect("fixture should close the truncated response");
    }
  }
}

fn local_http_fixture(replies: Vec<HttpReply>) -> (String, JoinHandle<usize>) {
  let listener = TcpListener::bind(("127.0.0.1", 0))
    .expect("loopback HTTP fixture should bind an ephemeral port");
  listener
    .set_nonblocking(true)
    .expect("loopback HTTP fixture should use bounded accepts");
  let address = listener
    .local_addr()
    .expect("loopback HTTP fixture should expose its address");
  let expected_requests = replies.len();
  let thread = thread::spawn(move || {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut served = 0;
    while served < expected_requests && Instant::now() < deadline {
      match listener.accept() {
        Ok((mut stream, _)) => {
          stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("loopback HTTP request should have a bounded read");
          read_http_request(&mut stream);
          write_http_reply(&mut stream, &replies[served]);
          served += 1;
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
          thread::sleep(Duration::from_millis(5));
        }
        Err(error) => panic!("loopback HTTP fixture accept failed: {error}"),
      }
    }
    served
  });
  (format!("http://{address}/artifact"), thread)
}

fn helper_command(
  helper: &Path,
  url: &str,
  expected_sha256: &str,
  destination: &Path,
  caller_trap: &Path,
) -> Command {
  let mut command = Command::new("bash");
  command
    .args([
      "-c",
      r#"set -euo pipefail
trap 'printf caller-trap-preserved >"$CALLER_TRAP_MARKER"' EXIT
source "$1"
if download_verified_sha256 "$2" "$3" "$4"; then
  status=0
else
  status=$?
fi
[[ "$-" == *u* ]]
[[ "$(set -o | sed -n 's/^pipefail[[:space:]]*//p')" == on ]]
exit "$status"
"#,
      "verified-download-test",
    ])
    .arg(helper)
    .arg(url)
    .arg(expected_sha256)
    .arg(destination)
    .current_dir(repo_root())
    .env("CALLER_TRAP_MARKER", caller_trap)
    .env("FAKE_COMPETING_DESTINATION", "")
    .env("FAKE_CURL_CALL_MARKER", "")
    .env("NO_PROXY", "127.0.0.1,localhost")
    .env("no_proxy", "127.0.0.1,localhost");
  command
}

fn run_helper(
  helper: &Path,
  url: &str,
  expected_sha256: &str,
  destination: &Path,
  caller_trap: &Path,
  path_override: Option<std::ffi::OsString>,
) -> Output {
  let mut command = helper_command(helper, url, expected_sha256, destination, caller_trap);
  if let Some(path) = path_override {
    command.env("PATH", path);
  }
  command
    .output()
    .expect("verified download helper should execute under Bash")
}

fn write_fast_retry_curl_shim(bin_dir: &Path) {
  write_executable(
    &bin_dir.join("curl"),
    r#"#!/usr/bin/env bash
set -euo pipefail
all_args="$*"
retry_count=0
retry_all_errors=0
output=""
while (($#)); do
  case "$1" in
    --retry)
      retry_count="$2"
      shift 2
      ;;
    --retry-all-errors)
      retry_all_errors=1
      shift
      ;;
    --output)
      output="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' "$all_args" >"$FAKE_CURL_ARGS"
[[ "$retry_count" == 8 && "$retry_all_errors" == 1 ]]
[[ -n "$output" ]]
for ((attempt = 1; attempt <= retry_count + 1; attempt += 1)); do
  printf '%s\n' "$attempt" >>"$FAKE_CURL_ATTEMPTS"
  if [[ "$FAKE_CURL_SCENARIO" == "http404" ]]; then
    printf '%s\n' "not found" >"$output"
  else
    printf '%s\n' "partial response" >"$output"
  fi
done
exit 22
"#,
  );
}

fn write_success_curl_shim(bin_dir: &Path) {
  write_executable(
    &bin_dir.join("curl"),
    r#"#!/usr/bin/env bash
set -euo pipefail
output=""
while (($#)); do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n "$output" ]]
if [[ -n "$FAKE_CURL_CALL_MARKER" ]]; then
  : >"$FAKE_CURL_CALL_MARKER"
fi
cat "$FAKE_DOWNLOAD_FIXTURE" >"$output"
if [[ -n "$FAKE_COMPETING_DESTINATION" ]]; then
  printf '%s\n' "concurrent destination" >"$FAKE_COMPETING_DESTINATION"
fi
"#,
  );
}

fn no_download_staging(parent: &Path, destination: &Path) {
  assert!(
    partial_files(parent, destination).is_empty(),
    "failed download must remove every private partial output"
  );
}

#[test]
fn verified_download_recovers_http_and_interrupted_transfers_atomically() {
  let helper = repo_root().join("tests/scripts/lib/verified-download.sh");
  let bytes = b"small pinned Kubernetes fixture\n";
  for (case, first_reply) in [
    ("http-504", HttpReply::GatewayTimeout),
    (
      "truncated-body",
      HttpReply::Truncated(bytes[..bytes.len() / 2].to_vec()),
    ),
  ] {
    let temp_dir = fixture_tempdir("oxibelt-verified-download-recovery-");
    let destination = temp_dir.path().join(format!("{case}.yaml"));
    let caller_trap = temp_dir.path().join(format!("{case}-caller-trap"));
    let (url, server) = local_http_fixture(vec![first_reply, HttpReply::Complete(bytes.to_vec())]);
    let output = run_helper(
      &helper,
      &url,
      &sha256_hex(bytes),
      &destination,
      &caller_trap,
      None,
    );
    let served = server.join().expect("loopback HTTP fixture should finish");
    assert!(
      output.status.success(),
      "{case} should recover on the subsequent complete response: {}",
      String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(served, 2, "{case} should make one recovery request");
    assert_eq!(
      fs::read(&destination).expect("verified bytes should be published"),
      bytes,
      "{case} should publish only the exact checksum-verified payload"
    );
    assert!(
      caller_trap.is_file(),
      "the helper subshell must preserve the caller's EXIT trap"
    );
    no_download_staging(temp_dir.path(), &destination);
  }
}

#[test]
fn verified_download_rejects_bad_digests_404_and_exhausted_retries() {
  let helper = repo_root().join("tests/scripts/lib/verified-download.sh");

  let temp_dir = fixture_tempdir("oxibelt-verified-download-digest-");
  let destination = temp_dir.path().join("gateway.yaml");
  let caller_trap = temp_dir.path().join("caller-trap");
  let wrong_bytes = b"bytes with the wrong pinned digest\n";
  let (url, server) = local_http_fixture(vec![HttpReply::Complete(wrong_bytes.to_vec())]);
  let output = run_helper(
    &helper,
    &url,
    &sha256_hex(b"different expected bytes\n"),
    &destination,
    &caller_trap,
    None,
  );
  assert!(!output.status.success(), "digest mismatch must fail closed");
  assert_eq!(
    server.join().expect("digest fixture should finish"),
    1,
    "checksum failure should not trigger another network request"
  );
  assert!(!destination.exists(), "wrong bytes must never be published");
  no_download_staging(temp_dir.path(), &destination);
  assert!(
    caller_trap.is_file(),
    "a helper failure must preserve the caller's EXIT trap"
  );

  for scenario in ["exhausted", "http404"] {
    let temp_dir = fixture_tempdir("oxibelt-verified-download-curl-failure-");
    let bin_dir = temp_dir.path().join("bin");
    write_fast_retry_curl_shim(&bin_dir);
    let destination = temp_dir.path().join(format!("{scenario}.yaml"));
    let caller_trap = temp_dir.path().join("caller-trap");
    let attempts = temp_dir.path().join("attempts");
    let arguments = temp_dir.path().join("curl-arguments");
    let mut command = helper_command(
      &helper,
      "https://fixture.invalid/artifact",
      &sha256_hex(b"valid bytes"),
      &destination,
      &caller_trap,
    );
    command
      .env("PATH", shimmed_path(&bin_dir))
      .env("FAKE_CURL_SCENARIO", scenario)
      .env("FAKE_CURL_ATTEMPTS", &attempts)
      .env("FAKE_CURL_ARGS", &arguments);
    let output = command
      .output()
      .expect("shimmed curl failure should execute");
    assert!(
      !output.status.success(),
      "{scenario} must fail closed after its bounded attempts"
    );
    assert_eq!(
      fs::read_to_string(&attempts)
        .expect("fake curl should record its bounded attempts")
        .lines()
        .count(),
      9,
      "{scenario} should respect the eight-retry limit without sleeping"
    );
    let args =
      fs::read_to_string(&arguments).expect("fake curl should record production arguments");
    for expected in [
      "--fail",
      "--location",
      "--silent",
      "--show-error",
      "--retry 8",
      "--retry-all-errors",
      "--connect-timeout 10",
      "--max-time 60",
      "--retry-max-time 300",
    ] {
      assert!(
        args.contains(expected),
        "the production downloader must pass curl option {expected}"
      );
    }
    assert!(
      !destination.exists(),
      "{scenario} must not publish the partial or error response"
    );
    no_download_staging(temp_dir.path(), &destination);
  }
}

#[test]
fn verified_download_rejects_both_atomic_publish_failure_shapes() {
  let helper = repo_root().join("tests/scripts/lib/verified-download.sh");
  let fixture = b"verified payload for publication\n";
  for (scenario, mv_body) in [
    ("mv-error", "#!/usr/bin/env bash\nexit 19\n"),
    (
      "mv-noop",
      "#!/usr/bin/env bash\nprintf '%s\\n' 'simulated successful no-op mv' >&2\nexit 0\n",
    ),
  ] {
    let temp_dir = fixture_tempdir("oxibelt-verified-download-publish-");
    let bin_dir = temp_dir.path().join("bin");
    write_success_curl_shim(&bin_dir);
    write_executable(&bin_dir.join("mv"), mv_body);
    let fixture_path = temp_dir.path().join("fixture");
    fs::write(&fixture_path, fixture).expect("download fixture should be writable");
    let destination = temp_dir.path().join("artifact");
    let caller_trap = temp_dir.path().join("caller-trap");
    let mut command = helper_command(
      &helper,
      "https://fixture.invalid/artifact",
      &sha256_hex(fixture),
      &destination,
      &caller_trap,
    );
    command
      .env("PATH", shimmed_path(&bin_dir))
      .env("FAKE_DOWNLOAD_FIXTURE", fixture_path);
    let output = command
      .output()
      .expect("publication-failure helper should execute");
    assert!(
      !output.status.success(),
      "{scenario} must not report successful publication"
    );
    assert!(
      !destination.exists(),
      "{scenario} must leave no final output"
    );
    assert!(
      caller_trap.is_file(),
      "{scenario} must preserve the caller's EXIT trap"
    );
    no_download_staging(temp_dir.path(), &destination);
  }

  let temp_dir = fixture_tempdir("oxibelt-verified-download-collision-");
  let bin_dir = temp_dir.path().join("bin");
  write_success_curl_shim(&bin_dir);
  let fixture_path = temp_dir.path().join("fixture");
  fs::write(&fixture_path, fixture).expect("download fixture should be writable");
  let destination = temp_dir.path().join("artifact");
  let caller_trap = temp_dir.path().join("caller-trap");
  let mut command = helper_command(
    &helper,
    "https://fixture.invalid/artifact",
    &sha256_hex(fixture),
    &destination,
    &caller_trap,
  );
  command
    .env("PATH", shimmed_path(&bin_dir))
    .env("FAKE_DOWNLOAD_FIXTURE", &fixture_path)
    .env("FAKE_COMPETING_DESTINATION", &destination);
  let output = command
    .output()
    .expect("concurrent destination collision should execute");
  assert!(
    !output.status.success(),
    "a destination created during download must make publication fail"
  );
  assert_eq!(
    fs::read(&destination).expect("concurrent destination should remain"),
    b"concurrent destination\n",
    "no-clobber publication must preserve the competing destination bytes"
  );
  no_download_staging(temp_dir.path(), &destination);

  let temp_dir = fixture_tempdir("oxibelt-verified-download-existing-");
  let bin_dir = temp_dir.path().join("bin");
  write_success_curl_shim(&bin_dir);
  let fixture_path = temp_dir.path().join("fixture");
  fs::write(&fixture_path, fixture).expect("download fixture should be writable");
  let destination = temp_dir.path().join("artifact");
  fs::write(&destination, b"preexisting destination\n")
    .expect("preexisting destination should be writable");
  let caller_trap = temp_dir.path().join("caller-trap");
  let curl_marker = temp_dir.path().join("curl-called");
  let mut command = helper_command(
    &helper,
    "https://fixture.invalid/artifact",
    &sha256_hex(fixture),
    &destination,
    &caller_trap,
  );
  command
    .env("PATH", shimmed_path(&bin_dir))
    .env("FAKE_DOWNLOAD_FIXTURE", fixture_path)
    .env("FAKE_CURL_CALL_MARKER", &curl_marker);
  let output = command
    .output()
    .expect("existing destination refusal should execute");
  assert!(
    !output.status.success(),
    "a preexisting destination must be refused"
  );
  assert!(
    !curl_marker.exists(),
    "preexisting destination must be rejected before running curl"
  );
  assert_eq!(
    fs::read(&destination).expect("preexisting destination should remain"),
    b"preexisting destination\n"
  );
  no_download_staging(temp_dir.path(), &destination);
}

fn replace_sha_assignment(source: &str, marker: &str, assignment: &str, digest: &str) -> String {
  let marker_at = source
    .find(marker)
    .unwrap_or_else(|| panic!("installer fixture copy should contain {marker}"));
  let assignment_at = marker_at
    + source[marker_at..]
      .find(assignment)
      .unwrap_or_else(|| panic!("installer fixture copy should contain {assignment}"));
  let value_start = assignment_at + assignment.len();
  let value_end = value_start
    + source[value_start..]
      .find('"')
      .expect("installer fixture digest should end with a quote");
  let mut output = source.to_owned();
  output.replace_range(value_start..value_end, digest);
  output
}

struct InstallerHarness {
  _temp_dir: tempfile::TempDir,
  script_dir: PathBuf,
  bin_dir: PathBuf,
  install_dir: PathBuf,
  github_path: PathBuf,
  urls: PathBuf,
  kind_fixture: PathBuf,
  kubectl_fixture: PathBuf,
  corrupt_fixture: PathBuf,
}

impl InstallerHarness {
  fn new(kind_report: &str, kubectl_version: &str) -> Self {
    let temp_dir = fixture_tempdir("oxibelt-kind-installer-");
    let script_dir = temp_dir.path().join("scripts");
    let bin_dir = temp_dir.path().join("bin");
    let install_dir = temp_dir.path().join("installed/oxibelt-ci-tools");
    let github_path = temp_dir.path().join("github-path");
    let urls = temp_dir.path().join("curl-urls");
    let kind_fixture = temp_dir.path().join("kind-fixture");
    let kubectl_fixture = temp_dir.path().join("kubectl-fixture");
    let corrupt_fixture = temp_dir.path().join("corrupt-fixture");
    fs::create_dir_all(script_dir.join("lib"))
      .expect("installer fixture scripts should be creatable");
    fs::create_dir_all(&bin_dir).expect("installer fixture bin should be creatable");

    let kind_contents = format!("#!/usr/bin/env bash\nprintf '%s\\n' '{}'\n", kind_report);
    let kubectl_contents = format!(
      "#!/usr/bin/env bash\n[[ \"$*\" == \"version --client=true --output=json\" ]]\nprintf '%s\\n' '{{\"clientVersion\":{{\"gitVersion\":\"{}\"}}}}'\n",
      kubectl_version
    );
    write_executable(&kind_fixture, &kind_contents);
    write_executable(&kubectl_fixture, &kubectl_contents);
    fs::write(&corrupt_fixture, b"unverified corrupted download\n")
      .expect("corrupt fixture should be writable");

    let original_installer =
      fs::read_to_string(repo_root().join("tests/scripts/install-ci-kind-kubectl.sh"))
        .expect("production installer should be readable");
    let fixture_installer = replace_sha_assignment(
      &original_installer,
      "kind_sha256=",
      "kind_sha256=\"",
      &sha256_hex(kind_contents.as_bytes()),
    );
    let fixture_installer = replace_sha_assignment(
      &fixture_installer,
      "v1.34.11)",
      "kubectl_sha256=\"",
      &sha256_hex(kubectl_contents.as_bytes()),
    );
    write_executable(
      &script_dir.join("install-ci-kind-kubectl.sh"),
      &fixture_installer,
    );
    fs::copy(
      repo_root().join("tests/scripts/lib/verified-download.sh"),
      script_dir.join("lib/verified-download.sh"),
    )
    .expect("verified download helper should copy into fixture scripts");
    write_installer_curl_shim(&bin_dir);
    fs::write(&github_path, "existing-path-entry\n")
      .expect("initial GITHUB_PATH fixture should be writable");

    Self {
      _temp_dir: temp_dir,
      script_dir,
      bin_dir,
      install_dir,
      github_path,
      urls,
      kind_fixture,
      kubectl_fixture,
      corrupt_fixture,
    }
  }

  fn run(&self, version: &str, scenario: &str, architecture: &str) -> Output {
    let mut command = Command::new("bash");
    command
      .arg(self.script_dir.join("install-ci-kind-kubectl.sh"))
      .arg(version)
      .arg(&self.install_dir)
      .current_dir(repo_root())
      .env("PATH", shimmed_path(&self.bin_dir))
      .env("GITHUB_PATH", &self.github_path)
      .env("FAKE_INSTALLER_SCENARIO", scenario)
      .env("FAKE_INSTALLER_URLS", &self.urls)
      .env("FAKE_KIND_FIXTURE", &self.kind_fixture)
      .env("FAKE_KUBECTL_FIXTURE", &self.kubectl_fixture)
      .env("FAKE_CORRUPT_FIXTURE", &self.corrupt_fixture);
    write_executable(
      &self.bin_dir.join("uname"),
      r#"#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' Linux ;;
  -m) printf '%s\n' "$FAKE_UNAME_ARCH" ;;
  *) exit 64 ;;
esac
"#,
    );
    command.env("FAKE_UNAME_ARCH", architecture);
    command
      .output()
      .expect("CI Kind and kubectl installer fixture should execute")
  }
}

fn write_installer_curl_shim(bin_dir: &Path) {
  write_executable(
    &bin_dir.join("curl"),
    r#"#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
while (($#)); do
  case "$1" in
    --output)
      output="$2"
      shift 2
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done
printf '%s\n' "$url" >>"$FAKE_INSTALLER_URLS"
[[ -n "$url" && -n "$output" ]]
if [[ "$url" == *"/kind-linux-amd64" ]]; then
  source="$FAKE_KIND_FIXTURE"
else
  source="$FAKE_KUBECTL_FIXTURE"
fi
case "$FAKE_INSTALLER_SCENARIO:$url" in
  kind-corrupt:*"/kind-linux-amd64")
    source="$FAKE_CORRUPT_FIXTURE"
    ;;
  kubectl-corrupt:*"/bin/linux/amd64/kubectl")
    source="$FAKE_CORRUPT_FIXTURE"
    ;;
  kubectl-download-failure:*"/bin/linux/amd64/kubectl")
    printf '%s\n' "partial second download" >"$output"
    exit 22
    ;;
esac
cp -- "$source" "$output"
"#,
  );
}

fn staging_directories_or_empty(parent: &Path) -> Vec<PathBuf> {
  if parent.is_dir() {
    staging_directories(parent)
  } else {
    Vec::new()
  }
}

fn assert_installer_failure_is_unpublished(harness: &InstallerHarness, output: &Output) {
  assert!(
    !output.status.success(),
    "installer failure case should return nonzero: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  assert!(
    !harness.install_dir.exists(),
    "installer failure must not publish its final directory"
  );
  assert_eq!(
    fs::read_to_string(&harness.github_path)
      .expect("GITHUB_PATH should remain readable")
      .as_str(),
    "existing-path-entry\n",
    "installer failure must leave GITHUB_PATH unchanged"
  );
  assert!(
    staging_directories_or_empty(
      harness
        .install_dir
        .parent()
        .expect("install directory should have its expected parent")
    )
    .is_empty(),
    "installer failure must remove its private staging directory"
  );
}

#[test]
fn kind_kubectl_installer_publishes_only_verified_tools_and_path() {
  let harness = InstallerHarness::new("kind v0.33.0 go1.24.1 linux/amd64", "v1.34.11");
  let output = harness.run("v1.34.11", "success", "x86_64");
  assert!(
    output.status.success(),
    "verified installer fixtures should succeed: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  let installed_kind = harness.install_dir.join("kind");
  let installed_kubectl = harness.install_dir.join("kubectl");
  assert_eq!(
    fs::read(&installed_kind).expect("Kind should be installed"),
    fs::read(&harness.kind_fixture).expect("Kind fixture should be readable")
  );
  assert_eq!(
    fs::read(&installed_kubectl).expect("kubectl should be installed"),
    fs::read(&harness.kubectl_fixture).expect("kubectl fixture should be readable")
  );
  assert_eq!(
    fs::read_to_string(&harness.github_path).expect("GITHUB_PATH should be updated"),
    format!("existing-path-entry\n{}\n", harness.install_dir.display())
  );
  assert_eq!(
    fs::read_to_string(&harness.urls)
      .expect("fake curl should record both pinned URLs")
      .lines()
      .collect::<Vec<_>>(),
    vec![
      "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64",
      "https://dl.k8s.io/release/v1.34.11/bin/linux/amd64/kubectl",
    ],
    "the installer should request only its pinned Kind and kubectl assets"
  );
  assert!(
    staging_directories_or_empty(
      harness
        .install_dir
        .parent()
        .expect("install directory should have its expected parent")
    )
    .is_empty(),
    "success should leave no private staging directory"
  );
}

#[test]
fn kind_kubectl_installer_fails_closed_before_network_or_path_publication() {
  let unsupported_version = InstallerHarness::new("kind v0.33.0 go1.24.1 linux/amd64", "v1.34.11");
  let output = unsupported_version.run("v1.99.0", "success", "x86_64");
  assert_installer_failure_is_unpublished(&unsupported_version, &output);
  assert!(
    !unsupported_version.urls.exists(),
    "unsupported kubectl versions must fail before network access"
  );

  let unsupported_arch = InstallerHarness::new("kind v0.33.0 go1.24.1 linux/amd64", "v1.34.11");
  let output = unsupported_arch.run("v1.34.11", "success", "aarch64");
  assert_installer_failure_is_unpublished(&unsupported_arch, &output);
  assert!(
    !unsupported_arch.urls.exists(),
    "unsupported architecture must fail before network access"
  );

  for scenario in [
    "kind-corrupt",
    "kubectl-corrupt",
    "kubectl-download-failure",
  ] {
    let harness = InstallerHarness::new("kind v0.33.0 go1.24.1 linux/amd64", "v1.34.11");
    let output = harness.run("v1.34.11", scenario, "x86_64");
    assert_installer_failure_is_unpublished(&harness, &output);
    let downloads = fs::read_to_string(&harness.urls)
      .expect("fake curl should record downloads before asset failure")
      .lines()
      .count();
    let expected_downloads = if scenario == "kind-corrupt" { 1 } else { 2 };
    assert_eq!(
      downloads, expected_downloads,
      "{scenario} should stop at the failing verified download"
    );
  }

  let wrong_kind_version = InstallerHarness::new("kind v0.34.0 go1.24.1 linux/amd64", "v1.34.11");
  let output = wrong_kind_version.run("v1.34.11", "success", "x86_64");
  assert_installer_failure_is_unpublished(&wrong_kind_version, &output);

  let wrong_kubectl_version = InstallerHarness::new("kind v0.33.0 go1.24.1 linux/amd64", "v1.35.8");
  let output = wrong_kubectl_version.run("v1.34.11", "success", "x86_64");
  assert_installer_failure_is_unpublished(&wrong_kubectl_version, &output);
}

#[test]
fn kind_kubectl_installer_refuses_existing_destinations_before_network() {
  let harness = InstallerHarness::new("kind v0.33.0 go1.24.1 linux/amd64", "v1.34.11");
  fs::create_dir_all(&harness.install_dir)
    .expect("existing install destination should be creatable");
  fs::write(harness.install_dir.join("sentinel"), b"leave me alone")
    .expect("existing install sentinel should be writable");
  let output = harness.run("v1.34.11", "success", "x86_64");
  assert!(
    !output.status.success(),
    "installer must refuse to replace an existing destination"
  );
  assert!(
    !harness.urls.exists(),
    "existing install destination should be rejected before network access"
  );
  assert_eq!(
    fs::read(harness.install_dir.join("sentinel"))
      .expect("existing destination sentinel should remain"),
    b"leave me alone"
  );
  assert_eq!(
    fs::read_to_string(&harness.github_path)
      .expect("GITHUB_PATH should remain readable")
      .as_str(),
    "existing-path-entry\n",
    "refused installation must leave GITHUB_PATH unchanged"
  );
}
