//! Linux runtime hardening hooks that fail closed only when explicitly required.

use anyhow::{Context, bail};
use tracing::warn;

#[cfg(target_os = "linux")]
mod syscalls;

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
  syscalls::close_range_cloexec().map_err(Into::into)
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
  use std::os::fd::AsFd;
  use std::os::unix::fs::OpenOptionsExt;

  if config.read_paths.is_empty() && config.read_write_paths.is_empty() {
    bail!("runtime.hardening.landlock.mode = \"enforce\" requires read_paths or read_write_paths");
  }

  let abi = syscalls::landlock_abi_version().context("Landlock ABI version probe failed")?;
  let handled_access = syscalls::landlock_handled_access_fs(abi);
  let ruleset =
    syscalls::create_landlock_ruleset(handled_access).context("landlock_create_ruleset failed")?;

  let read_access = syscalls::landlock_read_access_fs(handled_access);
  for path in &config.read_paths {
    let file = OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
      .open(path)
      .with_context(|| format!("failed to open Landlock read path {}", path.display()))?;
    syscalls::add_landlock_path_rule(ruleset.as_fd(), file.as_fd(), read_access)
      .with_context(|| format!("failed to add Landlock read path {}", path.display()))?;
  }

  let read_write_access = syscalls::landlock_read_write_access_fs(handled_access);
  for path in &config.read_write_paths {
    let file = OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
      .open(path)
      .with_context(|| format!("failed to open Landlock read-write path {}", path.display()))?;
    syscalls::add_landlock_path_rule(ruleset.as_fd(), file.as_fd(), read_write_access)
      .with_context(|| format!("failed to add Landlock read-write path {}", path.display()))?;
  }

  enable_no_new_privs().context("failed to set no_new_privs before Landlock")?;
  syscalls::restrict_landlock(ruleset.as_fd()).context("landlock_restrict_self failed")
}

#[cfg(not(target_os = "linux"))]
fn install_landlock(_config: &RuntimeLandlockConfig) -> anyhow::Result<()> {
  bail!("Landlock is Linux-only")
}

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
  nix::sys::prctl::set_no_new_privs().map_err(Into::into)
}

#[cfg(all(target_os = "linux", feature = "fuzzing"))]
pub(crate) fn fuzz_syscall_boundary(abi: u8) {
  let handled = syscalls::landlock_handled_access_fs(i64::from(abi));
  let _ = syscalls::landlock_read_access_fs(handled);
  let _ = syscalls::landlock_read_write_access_fs(handled);
  let _ = syscalls::landlock_layout();
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
