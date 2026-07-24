//! Focused dynamic checks for OxiBelt's two audited raw-syscall modules.

#[allow(dead_code)]
#[path = "../../../source/src/hardening/syscalls.rs"]
mod hardening_syscalls;
#[allow(dead_code)]
#[path = "../../../source/src/tcp_hop/syscalls.rs"]
mod tcp_hop_syscalls;

#[cfg(test)]
mod tests {
  use std::ffi::OsStr;
  use std::io::{Read, Write};
  use std::net::{TcpListener, TcpStream};
  use std::os::fd::AsFd;
  use std::os::unix::fs::OpenOptionsExt;
  use std::path::PathBuf;
  use std::process::Command;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicU64, Ordering};
  use std::thread;
  use std::time::{SystemTime, UNIX_EPOCH};

  use super::{hardening_syscalls, tcp_hop_syscalls};
  use tcp_hop_syscalls::MinHopProtocol;

  const ISOLATED_TEST_CHILD: &str = "OXIBELT_UNSAFE_HARNESS_CHILD";
  const ISOLATED_TEST_ROOT: &str = "OXIBELT_UNSAFE_HARNESS_ROOT";
  const ISOLATED_TEST_SENTINEL: &str = "OXIBELT_UNSAFE_HARNESS_SENTINEL";
  static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

  #[test]
  fn layout_and_pure_boundary_planning_contracts_hold() {
    let (ruleset, path_beneath) = hardening_syscalls::landlock_layout();
    assert_eq!(ruleset, (8, 8));
    assert!(path_beneath.0 >= 12);
    assert!(path_beneath.1 >= std::mem::align_of::<libc::c_int>());

    let v1 = hardening_syscalls::landlock_handled_access_fs(1);
    let v2 = hardening_syscalls::landlock_handled_access_fs(2);
    let v3 = hardening_syscalls::landlock_handled_access_fs(3);
    assert_eq!(v2, v1 | hardening_syscalls::LANDLOCK_ACCESS_FS_REFER);
    assert_eq!(v3, v2 | hardening_syscalls::LANDLOCK_ACCESS_FS_TRUNCATE);
    assert_eq!(
      hardening_syscalls::landlock_read_access_fs(v3),
      hardening_syscalls::LANDLOCK_ACCESS_FS_EXECUTE
        | hardening_syscalls::LANDLOCK_ACCESS_FS_READ_FILE
        | hardening_syscalls::LANDLOCK_ACCESS_FS_READ_DIR
    );
    assert_eq!(
      MinHopProtocol::Ipv4.socket_option(),
      (libc::IPPROTO_IP, libc::IP_MINTTL)
    );
    assert_eq!(
      MinHopProtocol::Ipv6.socket_option(),
      (libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT)
    );
    let (tcp_info_size, tcp_info_alignment) = tcp_hop_syscalls::tcp_info_layout();
    assert!(tcp_info_size >= std::mem::size_of::<u32>());
    assert!(tcp_info_alignment >= std::mem::align_of::<u32>());
  }

  #[test]
  fn syscall_close_range_cloexec_succeeds_in_isolated_child() {
    if run_in_isolated_child("tests::syscall_close_range_cloexec_succeeds_in_isolated_child") {
      return;
    }
    hardening_syscalls::close_range_cloexec().expect("close_range CLOEXEC should succeed");
  }

  #[test]
  fn syscall_landlock_allows_listed_path_and_denies_unlisted_path() {
    if run_in_isolated_child("tests::syscall_landlock_allows_listed_path_and_denies_unlisted_path")
    {
      return;
    }

    let root = isolated_test_root();
    let allowed = root.join("allowed");
    let denied = root.join("denied");
    std::fs::create_dir_all(&allowed).expect("allowed directory should be created");
    std::fs::create_dir_all(&denied).expect("denied directory should be created");
    std::fs::write(allowed.join("value"), b"allowed").expect("allowed file should be written");
    std::fs::write(denied.join("value"), b"denied").expect("denied file should be written");

    let Some(abi) = landlock_or_skip(
      hardening_syscalls::landlock_abi_version(),
      "Landlock ABI probe",
    ) else {
      return;
    };
    let handled = hardening_syscalls::landlock_handled_access_fs(abi);
    let Some(ruleset) = landlock_or_skip(
      hardening_syscalls::create_landlock_ruleset(handled),
      "Landlock ruleset creation",
    ) else {
      return;
    };
    let allowed_dir = std::fs::OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
      .open(&allowed)
      .expect("allowed directory should open with O_PATH");
    if landlock_or_skip(
      hardening_syscalls::add_landlock_path_rule(
        ruleset.as_fd(),
        allowed_dir.as_fd(),
        hardening_syscalls::landlock_read_access_fs(handled),
      ),
      "Landlock path rule installation",
    )
    .is_none()
    {
      return;
    }
    nix::sys::prctl::set_no_new_privs().expect("no_new_privs should be enabled");
    if landlock_or_skip(
      hardening_syscalls::restrict_landlock(ruleset.as_fd()),
      "Landlock restriction",
    )
    .is_none()
    {
      return;
    }

    assert_eq!(
      std::fs::read(allowed.join("value")).expect("allowed file should remain readable"),
      b"allowed"
    );
    let error = std::fs::read(denied.join("value")).expect_err("unlisted path should be denied");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
  }

  #[test]
  fn syscall_tcp_hop_and_info_work_on_loopback() {
    let (stream, peer) = loopback_pair();
    tcp_hop_syscalls::set_min_hop_count(stream.as_fd(), MinHopProtocol::Ipv4, 1)
      .expect("IP_MINTTL should be configurable on a loopback TCP socket");
    let _ = tcp_hop_syscalls::tcp_info_rtt_micros(stream.as_fd())
      .expect("TCP_INFO should be readable on a connected TCP socket");
    stream
      .shutdown(std::net::Shutdown::Both)
      .expect("client socket should shut down");
    peer.join().expect("loopback peer should finish");
  }

  #[test]
  fn concurrent_tcp_info_reads_use_borrowed_fd_without_races() {
    let (stream, peer) = loopback_pair();
    let stream = Arc::new(stream);
    let readers = (0..4)
      .map(|_| {
        let stream = Arc::clone(&stream);
        thread::spawn(move || {
          for _ in 0..256 {
            let _ = tcp_hop_syscalls::tcp_info_rtt_micros(stream.as_fd())
              .expect("concurrent TCP_INFO read should succeed");
          }
        })
      })
      .collect::<Vec<_>>();
    for reader in readers {
      reader.join().expect("TCP_INFO reader should finish");
    }
    stream
      .shutdown(std::net::Shutdown::Both)
      .expect("client socket should shut down");
    peer.join().expect("loopback peer should finish");
  }

  fn loopback_pair() -> (TcpStream, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
      .unwrap_or_else(|error| panic!("loopback listener should bind: {error}"));
    let address = listener
      .local_addr()
      .expect("listener address should resolve");
    let peer = thread::spawn(move || {
      let (mut stream, _) = listener.accept().expect("loopback peer should accept");
      let mut bytes = Vec::new();
      let _ = stream.read_to_end(&mut bytes);
    });
    let mut stream = TcpStream::connect(address).expect("loopback client should connect");
    stream
      .write_all(&[1])
      .expect("loopback client should write one byte");
    (stream, peer)
  }

  fn run_in_isolated_child(test_name: &str) -> bool {
    if std::env::var_os(ISOLATED_TEST_CHILD).as_deref() == Some(OsStr::new(test_name)) {
      let sentinel = std::env::var_os(ISOLATED_TEST_SENTINEL)
        .map(PathBuf::from)
        .expect("isolated child should receive a sentinel path");
      std::fs::write(&sentinel, b"entered").expect("isolated child should write its sentinel");
      return false;
    }

    let root = unique_test_root();
    std::fs::create_dir_all(&root).expect("isolated test root should be created");
    let sentinel = root.join("entered");
    let output =
      Command::new(std::env::current_exe().expect("isolated test should locate its executable"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(ISOLATED_TEST_CHILD, test_name)
        .env(ISOLATED_TEST_ROOT, &root)
        .env(ISOLATED_TEST_SENTINEL, &sentinel)
        .output()
        .expect("isolated test child should start");
    let entered = sentinel.is_file();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
      entered,
      "isolated child did not enter {test_name}; stdout:\n{}\nstderr:\n{}",
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr)
    );
    assert!(
      output.status.success(),
      "isolated child {test_name} failed with {}; stdout:\n{}\nstderr:\n{}",
      output.status,
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr)
    );
    true
  }

  fn isolated_test_root() -> PathBuf {
    std::env::var_os(ISOLATED_TEST_ROOT)
      .map(PathBuf::from)
      .expect("isolated child should receive its test root")
  }

  fn unique_test_root() -> PathBuf {
    let nanos = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("clock should be after Unix epoch")
      .as_nanos();
    std::env::temp_dir().join(format!(
      "oxibelt-unsafe-harness-{}-{nanos}-{}",
      std::process::id(),
      NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed)
    ))
  }

  fn unsupported_kernel_feature(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::ENOSYS || code == libc::EOPNOTSUPP)
  }

  fn landlock_or_skip<T>(result: std::io::Result<T>, operation: &str) -> Option<T> {
    match result {
      Ok(value) => Some(value),
      Err(error) if unsupported_kernel_feature(&error) => {
        eprintln!("{operation} is unsupported by this kernel: {error}");
        None
      }
      Err(error) => panic!("{operation} failed: {error}"),
    }
  }
}
