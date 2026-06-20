use std::net::IpAddr;
use std::os::fd::AsRawFd;

use anyhow::{Context, bail};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpTransportMetadata {
  pub mss: Option<u32>,
  pub rtt_ms: Option<u64>,
}

pub fn transport_metadata(stream: &TcpStream) -> TcpTransportMetadata {
  TcpTransportMetadata {
    mss: tcp_max_segment_size(stream),
    rtt_ms: tcp_rtt_ms(stream),
  }
}

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
  // SAFETY: `stream.as_raw_fd()` is a valid socket owned by the async TCP stream for the duration of
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

#[allow(unsafe_code)]
fn tcp_max_segment_size(stream: &TcpStream) -> Option<u32> {
  let mut value: libc::c_int = 0;
  let mut option_length: libc::socklen_t = std::mem::size_of_val(&value).try_into().ok()?;

  // SAFETY: `stream.as_raw_fd()` is a live TCP socket for the duration of the
  // call, and `value`/`option_length` point to initialized storage with the
  // exact size advertised to `getsockopt`.
  let result = unsafe {
    libc::getsockopt(
      stream.as_raw_fd(),
      libc::IPPROTO_TCP,
      libc::TCP_MAXSEG,
      std::ptr::addr_of_mut!(value).cast(),
      std::ptr::addr_of_mut!(option_length),
    )
  };

  if result == 0 && value >= 0 {
    Some(value as u32)
  } else {
    None
  }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn tcp_rtt_ms(stream: &TcpStream) -> Option<u64> {
  // Zero-initialize so older kernels returning a shorter tcp_info layout still
  // leave fields we do not receive as zero instead of uninitialized memory.
  let mut info = unsafe { std::mem::zeroed::<libc::tcp_info>() };
  let mut option_length: libc::socklen_t = std::mem::size_of_val(&info).try_into().ok()?;

  // SAFETY: `stream.as_raw_fd()` is a live TCP socket for the duration of the
  // call, and `info`/`option_length` point to initialized storage with the exact
  // size advertised to `getsockopt`.
  let result = unsafe {
    libc::getsockopt(
      stream.as_raw_fd(),
      libc::IPPROTO_TCP,
      libc::TCP_INFO,
      std::ptr::addr_of_mut!(info).cast(),
      std::ptr::addr_of_mut!(option_length),
    )
  };

  (result == 0).then(|| u64::from(info.tcpi_rtt) / 1000)
}

#[cfg(not(target_os = "linux"))]
fn tcp_rtt_ms(_stream: &TcpStream) -> Option<u64> {
  None
}
