//! Async runtime backend metadata and Monoio availability checks.

#[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
use anyhow::Context;
use serde::Serialize;

pub const ACTIVE_RUNTIME_NAME: &str = "tokio_compat";
pub const COMPATIBILITY_RUNTIME_NAME: &str = "tokio";
#[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
pub const TARGET_RUNTIME_NAME: &str = "monoio";
#[cfg(all(target_arch = "riscv64", target_os = "linux", target_env = "musl"))]
pub const TARGET_RUNTIME_NAME: &str = ACTIVE_RUNTIME_NAME;
#[cfg(all(target_arch = "riscv64", target_os = "linux", target_env = "musl"))]
const UNAVAILABLE_IO_DRIVER_NAME: &str = "unavailable";

#[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MonoioDriverSelection {
  IoUring,
  Legacy,
}

#[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
impl MonoioDriverSelection {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::IoUring => "io_uring",
      Self::Legacy => "legacy",
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeBackendSnapshot {
  pub target_runtime: &'static str,
  pub target_io_driver: &'static str,
  pub active_runtime: &'static str,
  pub compatibility_runtime: &'static str,
  pub compatibility_island_count: usize,
}

#[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
pub fn runtime_backend_snapshot() -> RuntimeBackendSnapshot {
  RuntimeBackendSnapshot {
    target_runtime: TARGET_RUNTIME_NAME,
    target_io_driver: detect_monoio_driver().as_str(),
    active_runtime: ACTIVE_RUNTIME_NAME,
    compatibility_runtime: COMPATIBILITY_RUNTIME_NAME,
    compatibility_island_count: 1,
  }
}

#[cfg(all(target_arch = "riscv64", target_os = "linux", target_env = "musl"))]
pub fn runtime_backend_snapshot() -> RuntimeBackendSnapshot {
  RuntimeBackendSnapshot {
    target_runtime: TARGET_RUNTIME_NAME,
    target_io_driver: UNAVAILABLE_IO_DRIVER_NAME,
    active_runtime: ACTIVE_RUNTIME_NAME,
    compatibility_runtime: COMPATIBILITY_RUNTIME_NAME,
    compatibility_island_count: 1,
  }
}

#[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
pub fn detect_monoio_driver() -> MonoioDriverSelection {
  if monoio::utils::detect_uring() {
    MonoioDriverSelection::IoUring
  } else {
    MonoioDriverSelection::Legacy
  }
}

#[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
pub fn validate_monoio_runtime_available() -> anyhow::Result<()> {
  let mut runtime = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
    .enable_all()
    .build()
    .context("failed to build Monoio runtime")?;
  runtime.block_on(async {});
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn snapshot_reports_monoio_backend_and_tokio_compatibility() {
    let snapshot = runtime_backend_snapshot();

    assert_eq!(snapshot.target_runtime, TARGET_RUNTIME_NAME);
    #[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
    assert!(matches!(snapshot.target_io_driver, "io_uring" | "legacy"));
    #[cfg(all(target_arch = "riscv64", target_os = "linux", target_env = "musl"))]
    assert_eq!(snapshot.target_io_driver, UNAVAILABLE_IO_DRIVER_NAME);
    assert_eq!(snapshot.active_runtime, ACTIVE_RUNTIME_NAME);
    assert_eq!(snapshot.compatibility_runtime, COMPATIBILITY_RUNTIME_NAME);
    assert_eq!(snapshot.compatibility_island_count, 1);
  }

  #[cfg(not(all(target_arch = "riscv64", target_os = "linux", target_env = "musl")))]
  #[test]
  fn monoio_runtime_builds_with_configured_driver() {
    validate_monoio_runtime_available().expect("Monoio runtime should build");
  }
}
