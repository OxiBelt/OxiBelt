use std::net::IpAddr;
use std::os::fd::AsRawFd;

use anyhow::{Context, bail};
use tokio::net::TcpStream;

pub fn apply_tcp_max_hop(stream: &TcpStream, peer_ip: IpAddr, max_hop: u8) -> anyhow::Result<()> {
  let min_hop_count = 255_i32.saturating_sub(i32::from(max_hop));
  match peer_ip {
    IpAddr::V4(_) => set_socket_hop_limit(
      stream,
      libc::IPPROTO_IP,
      libc::IP_MINTTL,
      min_hop_count,
      "IP_MINTTL",
    ),
    IpAddr::V6(_) => set_socket_hop_limit(
      stream,
      libc::IPPROTO_IPV6,
      libc::IPV6_MINHOPCOUNT,
      min_hop_count,
      "IPV6_MINHOPCOUNT",
    ),
  }
}

#[allow(unsafe_code)]
fn set_socket_hop_limit(
  stream: &TcpStream,
  level: libc::c_int,
  option: libc::c_int,
  value: libc::c_int,
  option_name: &str,
) -> anyhow::Result<()> {
  let option_length: libc::socklen_t = std::mem::size_of_val(&value)
    .try_into()
    .context("socket option length does not fit socklen_t")?;
  // SAFETY: `stream.as_raw_fd()` is a valid socket owned by Tokio for the duration of
  // this call, and `value` points to a properly aligned `c_int` with the exact length
  // passed to `setsockopt`.
  let result = unsafe {
    libc::setsockopt(
      stream.as_raw_fd(),
      level,
      option,
      std::ptr::addr_of!(value).cast(),
      option_length,
    )
  };

  if result != 0 {
    let error = std::io::Error::last_os_error();
    bail!("failed to set {option_name}: {error}");
  }

  Ok(())
}
