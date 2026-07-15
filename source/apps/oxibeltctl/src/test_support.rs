use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_ENV_CHILD: &str = "OXIBELT_OXIBELTCTL_TEST_ENV_CHILD";
const TEST_ENV_SENTINEL: &str = "OXIBELT_OXIBELTCTL_TEST_ENV_SENTINEL";
static NEXT_SENTINEL_ID: AtomicU64 = AtomicU64::new(0);

pub(super) fn run_test_in_subprocess_with_env<K, V>(test_name: &str, variables: &[(K, V)]) -> bool
where
  K: AsRef<OsStr>,
  V: AsRef<OsStr>,
{
  if std::env::var_os(TEST_ENV_CHILD).as_deref() == Some(OsStr::new(test_name)) {
    let sentinel = std::env::var_os(TEST_ENV_SENTINEL)
      .map(PathBuf::from)
      .expect("environment-test child should receive a sentinel path");
    std::fs::write(&sentinel, b"entered")
      .unwrap_or_else(|error| panic!("failed to write {}: {error}", sentinel.display()));
    return false;
  }

  let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("clock should be after Unix epoch")
    .as_nanos();
  let sentinel = std::env::temp_dir().join(format!(
    "oxibeltctl-env-test-{}-{nanos}-{}",
    std::process::id(),
    NEXT_SENTINEL_ID.fetch_add(1, Ordering::Relaxed)
  ));
  let mut command = Command::new(
    std::env::current_exe().expect("environment-test parent should locate its test executable"),
  );
  command
    .arg("--exact")
    .arg(test_name)
    .arg("--nocapture")
    .arg("--test-threads=1")
    .env(TEST_ENV_CHILD, test_name)
    .env(TEST_ENV_SENTINEL, &sentinel);
  for (key, value) in variables {
    command.env(key, value);
  }
  let output = command
    .output()
    .expect("environment-test parent should start its child test process");
  let entered = sentinel.is_file();
  let _ = std::fs::remove_file(&sentinel);
  assert!(
    entered,
    "environment-test child did not enter exact test {test_name}; stdout:\n{}\nstderr:\n{}",
    String::from_utf8_lossy(&output.stdout),
    String::from_utf8_lossy(&output.stderr)
  );
  assert!(
    output.status.success(),
    "environment-test child {test_name} failed with {}; stdout:\n{}\nstderr:\n{}",
    output.status,
    String::from_utf8_lossy(&output.stdout),
    String::from_utf8_lossy(&output.stderr)
  );
  true
}
