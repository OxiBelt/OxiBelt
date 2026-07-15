//! Audited raw Linux syscalls for process hardening.
//!
//! # Safety model
//!
//! - The safe functions in this module are the only caller-facing boundary; callers never pass
//!   raw pointers or transfer raw file-descriptor ownership.
//! - All pointers refer to aligned Rust `repr(C)` values for exactly the duration of one syscall.
//! - Every buffer length is derived with `size_of`, and Landlock descriptor lifetimes are encoded
//!   with `BorrowedFd` and `OwnedFd`.
//! - A successful ruleset creation transfers one kernel-owned descriptor into `OwnedFd` exactly
//!   once. Borrowed descriptors remain owned by their callers.
//! - Callers must use a Landlock ruleset descriptor for `ruleset_fd`, an `O_PATH` directory for
//!   `parent_fd`, and set `no_new_privs` before restriction. Descriptor kinds and call ordering
//!   are functional obligations that the kernel validates with an error; violating them cannot
//!   cause Rust memory unsafety.
//! - `close_range(CLOEXEC)` mutates the descriptor table shared by process threads. Landlock
//!   irreversibly restricts the calling thread and descendants; callers that require process-wide
//!   confinement must account for already-existing sibling threads. Tests use an isolated child.
//! - The syscall numbers, structures, flags, and error behavior are Linux-specific. This module
//!   is compiled only for Linux.

#![allow(
  unsafe_code,
  reason = "Landlock and close_range do not have complete safe wrappers in the locked dependencies"
)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;

pub(crate) const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub(crate) const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub(crate) const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub(crate) const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub(crate) const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub(crate) const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub(crate) const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub(crate) const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub(crate) const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub(crate) const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub(crate) const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub(crate) const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub(crate) const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub(crate) const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub(crate) const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_FS_V1_ACCESS: u64 = LANDLOCK_ACCESS_FS_EXECUTE
  | LANDLOCK_ACCESS_FS_WRITE_FILE
  | LANDLOCK_ACCESS_FS_READ_FILE
  | LANDLOCK_ACCESS_FS_READ_DIR
  | LANDLOCK_ACCESS_FS_REMOVE_DIR
  | LANDLOCK_ACCESS_FS_REMOVE_FILE
  | LANDLOCK_ACCESS_FS_MAKE_CHAR
  | LANDLOCK_ACCESS_FS_MAKE_DIR
  | LANDLOCK_ACCESS_FS_MAKE_REG
  | LANDLOCK_ACCESS_FS_MAKE_SOCK
  | LANDLOCK_ACCESS_FS_MAKE_FIFO
  | LANDLOCK_ACCESS_FS_MAKE_BLOCK
  | LANDLOCK_ACCESS_FS_MAKE_SYM;

#[repr(C)]
struct LandlockRulesetAttr {
  handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
  allowed_access: u64,
  parent_fd: libc::c_int,
}

pub(crate) fn close_range_cloexec() -> io::Result<()> {
  // SAFETY: The syscall receives only integer bounds and the Linux CLOEXEC flag. It does not
  // dereference memory or consume file-descriptor ownership. The shared descriptor-table effect
  // is part of this safe wrapper's documented startup-only contract.
  let result =
    unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
  syscall_unit(result)
}

pub(crate) fn landlock_abi_version() -> io::Result<i64> {
  // SAFETY: The VERSION query requires a null attribute pointer and zero size. No caller memory
  // or file descriptor is accessed, and all values use the Linux Landlock ABI constants.
  let result = unsafe {
    libc::syscall(
      libc::SYS_landlock_create_ruleset,
      std::ptr::null::<libc::c_void>(),
      0,
      LANDLOCK_CREATE_RULESET_VERSION,
    )
  };
  if result < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(result)
  }
}

pub(crate) fn create_landlock_ruleset(handled_access_fs: u64) -> io::Result<OwnedFd> {
  let attr = LandlockRulesetAttr { handled_access_fs };
  // SAFETY: `attr` is an aligned `repr(C)` LandlockRulesetAttr that remains alive for the call;
  // the advertised size is exact, the flags are zero, and no file descriptor is passed in.
  let result = unsafe {
    libc::syscall(
      libc::SYS_landlock_create_ruleset,
      std::ptr::addr_of!(attr),
      std::mem::size_of::<LandlockRulesetAttr>(),
      0,
    )
  };
  if result < 0 {
    return Err(io::Error::last_os_error());
  }
  let raw_fd = libc::c_int::try_from(result)
    .map_err(|_| io::Error::other("Landlock returned a descriptor outside c_int"))?;
  // SAFETY: A non-negative successful landlock_create_ruleset result is a newly owned descriptor.
  // This is its single ownership transfer, and `OwnedFd` closes it exactly once.
  Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

pub(crate) fn add_landlock_path_rule(
  ruleset_fd: BorrowedFd<'_>,
  parent_fd: BorrowedFd<'_>,
  allowed_access: u64,
) -> io::Result<()> {
  let attr = LandlockPathBeneathAttr {
    allowed_access,
    parent_fd: parent_fd.as_raw_fd(),
  };
  // SAFETY: Both borrowed descriptors remain live and caller-owned for the call; the caller's
  // descriptor-kind obligation affects only whether the kernel returns an error. `attr` is an
  // aligned `repr(C)` value with the exact kernel layout and lifetime, and the flags are zero.
  let result = unsafe {
    libc::syscall(
      libc::SYS_landlock_add_rule,
      ruleset_fd.as_raw_fd(),
      LANDLOCK_RULE_PATH_BENEATH,
      std::ptr::addr_of!(attr),
      0,
    )
  };
  syscall_unit(result)
}

pub(crate) fn restrict_landlock(ruleset_fd: BorrowedFd<'_>) -> io::Result<()> {
  // SAFETY: The borrowed descriptor remains valid and caller-owned for the call. Supplying the
  // wrong descriptor kind or omitting `no_new_privs` returns an error without affecting memory
  // safety. The syscall receives no pointer or buffer, and zero is the only supported flags value.
  let result =
    unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd.as_raw_fd(), 0) };
  syscall_unit(result)
}

pub(crate) const fn landlock_handled_access_fs(abi: i64) -> u64 {
  let mut access = LANDLOCK_FS_V1_ACCESS;
  if abi >= 2 {
    access |= LANDLOCK_ACCESS_FS_REFER;
  }
  if abi >= 3 {
    access |= LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  access
}

pub(crate) const fn landlock_read_access_fs(handled: u64) -> u64 {
  handled
    & (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
}

pub(crate) const fn landlock_read_write_access_fs(handled: u64) -> u64 {
  handled
}

#[allow(
  dead_code,
  reason = "used by the focused harness and fuzzing feature, but not ordinary runtime builds"
)]
pub(crate) const fn landlock_layout() -> ((usize, usize), (usize, usize)) {
  (
    (
      std::mem::size_of::<LandlockRulesetAttr>(),
      std::mem::align_of::<LandlockRulesetAttr>(),
    ),
    (
      std::mem::size_of::<LandlockPathBeneathAttr>(),
      std::mem::align_of::<LandlockPathBeneathAttr>(),
    ),
  )
}

fn syscall_unit(result: libc::c_long) -> io::Result<()> {
  if result == 0 {
    Ok(())
  } else {
    Err(io::Error::last_os_error())
  }
}
