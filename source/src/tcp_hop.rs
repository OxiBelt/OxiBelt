use std::net::IpAddr;
use std::os::fd::AsFd;

use anyhow::bail;
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
mod syscalls;

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
    IpAddr::V4(_) => set_socket_hop_limit(stream, MinHopProtocol::Ipv4, min_hop_count, "IP_MINTTL"),
    IpAddr::V6(_) => set_socket_hop_limit(
      stream,
      MinHopProtocol::Ipv6,
      min_hop_count,
      "IPV6_MINHOPCOUNT",
    ),
  }
}

#[cfg(target_os = "linux")]
use syscalls::MinHopProtocol;

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy)]
enum MinHopProtocol {
  Ipv4,
  Ipv6,
}

#[cfg(target_os = "linux")]
fn set_socket_hop_limit(
  stream: &TcpStream,
  protocol: MinHopProtocol,
  value: libc::c_int,
  option_name: &str,
) -> anyhow::Result<()> {
  if let Err(error) = syscalls::set_min_hop_count(stream.as_fd(), protocol, value) {
    bail!("failed to set {option_name}: {error}");
  }
  Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_socket_hop_limit(
  _stream: &TcpStream,
  _protocol: MinHopProtocol,
  _value: libc::c_int,
  option_name: &str,
) -> anyhow::Result<()> {
  bail!("failed to set {option_name}: minimum-hop socket options are Linux-only")
}

fn tcp_max_segment_size(stream: &TcpStream) -> Option<u32> {
  nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::TcpMaxSeg).ok()
}

#[cfg(target_os = "linux")]
fn tcp_rtt_ms(stream: &TcpStream) -> Option<u64> {
  syscalls::tcp_info_rtt_micros(stream.as_fd())
    .ok()
    .map(|rtt| u64::from(rtt) / 1000)
}

#[cfg(not(target_os = "linux"))]
fn tcp_rtt_ms(_stream: &TcpStream) -> Option<u64> {
  None
}

#[cfg(all(target_os = "linux", feature = "fuzzing"))]
pub(crate) fn fuzz_syscall_boundary(ipv6: bool) {
  let protocol = if ipv6 {
    MinHopProtocol::Ipv6
  } else {
    MinHopProtocol::Ipv4
  };
  let _ = protocol.socket_option();
  let _ = syscalls::tcp_info_layout();
}
