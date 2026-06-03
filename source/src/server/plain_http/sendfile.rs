//! Linux sendfile support for static-file responses.
//! Kernel-assisted transfer is used only after static path and WAF checks have passed.

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

  let mut file = open_sendfile_probe_file()?;

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

  Ok(())
}

#[cfg(target_os = "linux")]
fn open_sendfile_probe_file() -> std::io::Result<std::fs::File> {
  let fd = nix::sys::memfd::memfd_create(
    "oxibelt-sendfile-probe",
    nix::sys::memfd::MFdFlags::MFD_CLOEXEC,
  )
  .map_err(errno_to_io_error)?;
  Ok(std::fs::File::from(fd))
}

#[cfg(target_os = "linux")]
fn errno_to_io_error(error: nix::errno::Errno) -> std::io::Error {
  if error == nix::errno::Errno::EAGAIN {
    std::io::Error::from(std::io::ErrorKind::WouldBlock)
  } else {
    std::io::Error::from_raw_os_error(error as i32)
  }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
  use std::io::{Read, Seek, Write};
  use std::os::fd::AsRawFd;

  use super::open_sendfile_probe_file;

  #[test]
  fn probe_file_is_anonymous_memfd() {
    let mut file = open_sendfile_probe_file().expect("probe file should open");
    file.write_all(b"probe").expect("probe file should write");
    file.rewind().expect("probe file should seek back to start");

    let mut contents = String::new();
    file
      .read_to_string(&mut contents)
      .expect("probe file should read back");
    assert_eq!(contents, "probe");

    let fd_target = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
      .expect("Linux proc fd link should be readable");
    let fd_target = fd_target.to_string_lossy();
    assert!(
      fd_target.starts_with("/memfd:oxibelt-sendfile-probe"),
      "probe file should not be backed by a filesystem path: {fd_target}"
    );
  }
}
