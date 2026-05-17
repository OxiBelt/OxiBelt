use std::sync::OnceLock;

static KERNEL_SENDFILE_AVAILABLE: OnceLock<bool> = OnceLock::new();

pub(super) fn kernel_sendfile_available() -> bool {
  *KERNEL_SENDFILE_AVAILABLE.get_or_init(probe_kernel_sendfile)
}

#[cfg(target_os = "linux")]
pub(super) fn sendfile_once(
  out_fd: &tokio::net::TcpStream,
  in_fd: &tokio::fs::File,
  offset: &mut libc::off64_t,
  count: usize,
) -> std::io::Result<usize> {
  nix::sys::sendfile::sendfile64(out_fd, in_fd, Some(offset), count).map_err(errno_to_io_error)
}

#[cfg(target_os = "linux")]
fn probe_kernel_sendfile() -> bool {
  match probe_kernel_sendfile_inner() {
    Ok(()) => true,
    Err(error) => {
      tracing::debug!(error = %error, "Linux kernel sendfile probe failed");
      false
    }
  }
}

#[cfg(not(target_os = "linux"))]
fn probe_kernel_sendfile() -> bool {
  false
}

#[cfg(target_os = "linux")]
fn probe_kernel_sendfile_inner() -> std::io::Result<()> {
  use std::io::{Read, Write};
  use std::os::unix::net::UnixStream;
  use std::time::{SystemTime, UNIX_EPOCH};

  let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_nanos())
    .unwrap_or_default();
  let path = std::env::temp_dir().join(format!(
    "oxibelt-sendfile-probe-{}-{nanos}",
    std::process::id()
  ));
  let mut file = std::fs::OpenOptions::new()
    .read(true)
    .write(true)
    .create_new(true)
    .open(&path)?;
  let cleanup = SendfileProbeCleanup { path };

  file.write_all(&[0x5a])?;
  file.flush()?;

  let (mut reader, writer) = UnixStream::pair()?;
  let mut offset: libc::off64_t = 0;
  let sent = nix::sys::sendfile::sendfile64(&writer, &file, Some(&mut offset), 1)
    .map_err(errno_to_io_error)?;
  if sent != 1 || offset != 1 {
    return Err(std::io::Error::other(format!(
      "sendfile probe copied {sent} bytes and advanced offset to {offset}"
    )));
  }

  let mut byte = [0_u8; 1];
  reader.read_exact(&mut byte)?;
  if byte != [0x5a] {
    return Err(std::io::Error::other(
      "sendfile probe copied unexpected byte",
    ));
  }

  drop(cleanup);
  Ok(())
}

#[cfg(target_os = "linux")]
fn errno_to_io_error(error: nix::errno::Errno) -> std::io::Error {
  if error == nix::errno::Errno::EAGAIN {
    std::io::Error::from(std::io::ErrorKind::WouldBlock)
  } else {
    std::io::Error::from_raw_os_error(error as i32)
  }
}

#[cfg(target_os = "linux")]
struct SendfileProbeCleanup {
  path: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl Drop for SendfileProbeCleanup {
  fn drop(&mut self) {
    let _ = std::fs::remove_file(&self.path);
  }
}
