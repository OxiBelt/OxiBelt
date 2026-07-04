//! Linux runtime hardening hooks that fail closed only when explicitly required.

#![allow(unsafe_code)]

use anyhow::{Context, bail};
use tracing::warn;

use crate::config::{
  HardeningAutoMode, RuntimeHardeningConfig, RuntimeLandlockConfig, RuntimeLandlockMode,
  RuntimeSeccompMode,
};

pub fn apply_runtime_hardening(config: &RuntimeHardeningConfig) -> anyhow::Result<()> {
  apply_close_range(config.close_range)?;
  apply_landlock(&config.landlock)?;
  apply_seccomp(config.seccomp.mode)?;
  Ok(())
}

fn apply_close_range(mode: HardeningAutoMode) -> anyhow::Result<()> {
  if mode == HardeningAutoMode::Off {
    return Ok(());
  }
  match close_range_cloexec() {
    Ok(()) => Ok(()),
    Err(error) if mode == HardeningAutoMode::Auto => {
      warn!(error = %error, "close_range(CLOSE_RANGE_CLOEXEC) unavailable; continuing");
      Ok(())
    }
    Err(error) => Err(error).context("close_range(CLOSE_RANGE_CLOEXEC) failed"),
  }
}

#[cfg(target_os = "linux")]
fn close_range_cloexec() -> anyhow::Result<()> {
  const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
  let result =
    unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
  if result == 0 {
    Ok(())
  } else {
    Err(std::io::Error::last_os_error().into())
  }
}

#[cfg(not(target_os = "linux"))]
fn close_range_cloexec() -> anyhow::Result<()> {
  bail!("close_range is Linux-only")
}

fn apply_landlock(config: &RuntimeLandlockConfig) -> anyhow::Result<()> {
  match config.mode {
    RuntimeLandlockMode::Off => Ok(()),
    RuntimeLandlockMode::Enforce => {
      install_landlock(config).context("failed to install Landlock filesystem sandbox")
    }
  }
}

#[cfg(target_os = "linux")]
fn install_landlock(config: &RuntimeLandlockConfig) -> anyhow::Result<()> {
  use std::fs::OpenOptions;
  use std::os::fd::{AsRawFd, FromRawFd};
  use std::os::unix::fs::OpenOptionsExt;

  if config.read_paths.is_empty() && config.read_write_paths.is_empty() {
    bail!("runtime.hardening.landlock.mode = \"enforce\" requires read_paths or read_write_paths");
  }

  let abi = landlock_abi_version()?;
  let handled_access = landlock_handled_access_fs(abi);
  let ruleset_attr = LandlockRulesetAttr {
    handled_access_fs: handled_access,
  };
  let ruleset_fd = unsafe {
    libc::syscall(
      libc::SYS_landlock_create_ruleset,
      &ruleset_attr as *const LandlockRulesetAttr,
      std::mem::size_of::<LandlockRulesetAttr>(),
      0,
    )
  };
  if ruleset_fd < 0 {
    return Err(std::io::Error::last_os_error()).context("landlock_create_ruleset failed");
  }
  let ruleset = unsafe { std::fs::File::from_raw_fd(ruleset_fd as libc::c_int) };

  let read_access = landlock_read_access_fs(handled_access);
  for path in &config.read_paths {
    let file = OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
      .open(path)
      .with_context(|| format!("failed to open Landlock read path {}", path.display()))?;
    add_landlock_path_rule(ruleset.as_raw_fd(), file.as_raw_fd(), read_access)
      .with_context(|| format!("failed to add Landlock read path {}", path.display()))?;
  }

  let read_write_access = landlock_read_write_access_fs(handled_access);
  for path in &config.read_write_paths {
    let file = OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
      .open(path)
      .with_context(|| format!("failed to open Landlock read-write path {}", path.display()))?;
    add_landlock_path_rule(ruleset.as_raw_fd(), file.as_raw_fd(), read_write_access)
      .with_context(|| format!("failed to add Landlock read-write path {}", path.display()))?;
  }

  enable_no_new_privs().context("failed to set no_new_privs before Landlock")?;
  let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) };
  if result == 0 {
    Ok(())
  } else {
    Err(std::io::Error::last_os_error()).context("landlock_restrict_self failed")
  }
}

#[cfg(not(target_os = "linux"))]
fn install_landlock(_config: &RuntimeLandlockConfig) -> anyhow::Result<()> {
  bail!("Landlock is Linux-only")
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
  handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockPathBeneathAttr {
  allowed_access: u64,
  parent_fd: libc::c_int,
}

#[cfg(target_os = "linux")]
fn landlock_abi_version() -> anyhow::Result<i64> {
  const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
  let result = unsafe {
    libc::syscall(
      libc::SYS_landlock_create_ruleset,
      std::ptr::null::<libc::c_void>(),
      0,
      LANDLOCK_CREATE_RULESET_VERSION,
    )
  };
  if result >= 0 {
    Ok(result)
  } else {
    Err(std::io::Error::last_os_error()).context("Landlock ABI version probe failed")
  }
}

#[cfg(target_os = "linux")]
fn add_landlock_path_rule(
  ruleset_fd: libc::c_int,
  parent_fd: libc::c_int,
  allowed_access: u64,
) -> anyhow::Result<()> {
  const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
  let path_attr = LandlockPathBeneathAttr {
    allowed_access,
    parent_fd,
  };
  let result = unsafe {
    libc::syscall(
      libc::SYS_landlock_add_rule,
      ruleset_fd,
      LANDLOCK_RULE_PATH_BENEATH,
      &path_attr as *const LandlockPathBeneathAttr,
      0,
    )
  };
  if result == 0 {
    Ok(())
  } else {
    Err(std::io::Error::last_os_error()).context("landlock_add_rule failed")
  }
}

#[cfg(target_os = "linux")]
fn landlock_handled_access_fs(abi: i64) -> u64 {
  let mut access = LANDLOCK_FS_V1_ACCESS;
  if abi >= 2 {
    access |= LANDLOCK_ACCESS_FS_REFER;
  }
  if abi >= 3 {
    access |= LANDLOCK_ACCESS_FS_TRUNCATE;
  }
  access
}

#[cfg(target_os = "linux")]
fn landlock_read_access_fs(handled: u64) -> u64 {
  handled
    & (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
}

#[cfg(target_os = "linux")]
fn landlock_read_write_access_fs(handled: u64) -> u64 {
  handled
}

#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
#[cfg(target_os = "linux")]
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

fn apply_seccomp(mode: RuntimeSeccompMode) -> anyhow::Result<()> {
  match mode {
    RuntimeSeccompMode::Off => Ok(()),
    RuntimeSeccompMode::Log | RuntimeSeccompMode::Enforce => {
      enable_no_new_privs().context("failed to set no_new_privs before seccomp")?;
      bail!(
        "runtime.hardening.seccomp.mode currently uses generated deploy/seccomp profiles; in-process seccomp filter installation is not available"
      )
    }
  }
}

#[cfg(target_os = "linux")]
fn enable_no_new_privs() -> anyhow::Result<()> {
  let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
  if result == 0 {
    Ok(())
  } else {
    Err(std::io::Error::last_os_error().into())
  }
}

#[cfg(not(target_os = "linux"))]
fn enable_no_new_privs() -> anyhow::Result<()> {
  bail!("no_new_privs is Linux-only")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{RuntimeLandlockConfig, RuntimeSeccompConfig};

  #[test]
  fn off_modes_do_not_require_linux_features() {
    let config = RuntimeHardeningConfig {
      close_range: HardeningAutoMode::Off,
      seccomp: RuntimeSeccompConfig {
        mode: RuntimeSeccompMode::Off,
      },
      landlock: RuntimeLandlockConfig {
        mode: RuntimeLandlockMode::Off,
        read_paths: Vec::new(),
        read_write_paths: Vec::new(),
      },
    };
    apply_runtime_hardening(&config).expect("off hardening should be a no-op");
  }
}
