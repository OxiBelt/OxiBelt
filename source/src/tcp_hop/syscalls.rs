//! Audited raw Linux socket options for TCP hop validation and telemetry.
//!
//! # Safety model
//!
//! - Callers provide a live `BorrowedFd`, so the socket lifetime and ownership remain encoded in
//!   the type system and no descriptor is consumed.
//! - Callers must provide a TCP/IP socket for the options to succeed. `BorrowedFd` cannot encode
//!   the descriptor kind, but a different live descriptor fails with an OS error and cannot cause
//!   Rust memory unsafety.
//! - Socket-option values and output buffers are aligned Rust values whose exact sizes are passed
//!   to the kernel. No caller-controlled raw pointer or buffer length crosses this boundary.
//! - The zeroed `tcp_info` representation contains only integer fields; zero is valid for every
//!   field, including bytes omitted by an older kernel returning a shorter structure.
//! - The calls do not retain pointers after returning. Concurrent calls are independent kernel
//!   socket operations, though their observations may reflect concurrent network activity.
//! - `IP_MINTTL`, `IPV6_MINHOPCOUNT`, and `TCP_INFO` are Linux-specific behaviors. This module is
//!   compiled only for Linux.

#![allow(
  unsafe_code,
  reason = "the locked safe socket libraries do not expose minimum-hop or TCP_INFO operations"
)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MinHopProtocol {
  Ipv4,
  Ipv6,
}

impl MinHopProtocol {
  pub(crate) const fn socket_option(self) -> (libc::c_int, libc::c_int) {
    match self {
      Self::Ipv4 => (libc::IPPROTO_IP, libc::IP_MINTTL),
      Self::Ipv6 => (libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT),
    }
  }
}

pub(crate) fn set_min_hop_count(
  fd: BorrowedFd<'_>,
  protocol: MinHopProtocol,
  value: libc::c_int,
) -> io::Result<()> {
  let (level, option) = protocol.socket_option();
  let option_length = libc::socklen_t::try_from(std::mem::size_of_val(&value))
    .map_err(|_| io::Error::other("minimum-hop option size does not fit socklen_t"))?;
  // SAFETY: `fd` is a live borrowed descriptor for the call; a non-socket fails safely. `value` is
  // an aligned c_int whose exact size is advertised, the kernel does not retain its pointer, and
  // descriptor ownership stays with the caller.
  let result = unsafe {
    libc::setsockopt(
      fd.as_raw_fd(),
      level,
      option,
      std::ptr::addr_of!(value).cast(),
      option_length,
    )
  };
  syscall_unit(result)
}

pub(crate) fn tcp_info_rtt_micros(fd: BorrowedFd<'_>) -> io::Result<u32> {
  let mut info = MaybeUninit::<libc::tcp_info>::zeroed();
  let mut option_length = libc::socklen_t::try_from(std::mem::size_of::<libc::tcp_info>())
    .map_err(|_| io::Error::other("TCP_INFO size does not fit socklen_t"))?;
  // SAFETY: `fd` is a live borrowed descriptor; a non-TCP descriptor fails safely. `info` is
  // aligned writable storage initialized to all-zero bytes, `option_length` advertises its exact
  // capacity, and the kernel retains neither pointer after the call.
  let result = unsafe {
    libc::getsockopt(
      fd.as_raw_fd(),
      libc::IPPROTO_TCP,
      libc::TCP_INFO,
      info.as_mut_ptr().cast(),
      std::ptr::addr_of_mut!(option_length),
    )
  };
  syscall_unit(result)?;
  // SAFETY: The storage was fully zero-initialized before the kernel wrote up to its advertised
  // length. Every field in libc::tcp_info is integer data for which zero is a valid bit pattern,
  // so bytes omitted by an older kernel remain initialized and valid.
  let info = unsafe { info.assume_init() };
  Ok(info.tcpi_rtt)
}

#[allow(
  dead_code,
  reason = "used by the focused harness and fuzzing feature, but not ordinary runtime builds"
)]
pub(crate) const fn tcp_info_layout() -> (usize, usize) {
  (
    std::mem::size_of::<libc::tcp_info>(),
    std::mem::align_of::<libc::tcp_info>(),
  )
}

fn syscall_unit(result: libc::c_int) -> io::Result<()> {
  if result == 0 {
    Ok(())
  } else {
    Err(io::Error::last_os_error())
  }
}
