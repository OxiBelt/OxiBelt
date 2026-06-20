//! Async runtime backend metadata and Compio availability checks.

use anyhow::Context;
use compio_driver::DriverType;
use serde::Serialize;

pub const TARGET_RUNTIME_NAME: &str = "compio";
pub const ACTIVE_RUNTIME_NAME: &str = "compio";
pub const COMPATIBILITY_RUNTIME_NAME: &str = "tokio";
const UNAVAILABLE_IO_DRIVER_NAME: &str = "unavailable";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CompioDriverSelection {
  IoUring,
  Polling,
  Iocp,
}

impl CompioDriverSelection {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::IoUring => "io_uring",
      Self::Polling => "polling",
      Self::Iocp => "iocp",
    }
  }
}

impl From<DriverType> for CompioDriverSelection {
  fn from(value: DriverType) -> Self {
    match value {
      DriverType::IoUring => Self::IoUring,
      DriverType::Poll => Self::Polling,
      DriverType::IOCP => Self::Iocp,
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

pub fn runtime_backend_snapshot() -> RuntimeBackendSnapshot {
  RuntimeBackendSnapshot {
    target_runtime: TARGET_RUNTIME_NAME,
    target_io_driver: detect_compio_driver()
      .map(CompioDriverSelection::as_str)
      .unwrap_or(UNAVAILABLE_IO_DRIVER_NAME),
    active_runtime: ACTIVE_RUNTIME_NAME,
    compatibility_runtime: COMPATIBILITY_RUNTIME_NAME,
    compatibility_island_count: 1,
  }
}

pub fn detect_compio_driver() -> anyhow::Result<CompioDriverSelection> {
  let runtime = build_probe_runtime()?;
  Ok(runtime.driver_type().into())
}

pub fn validate_compio_runtime_available() -> anyhow::Result<()> {
  let runtime = build_probe_runtime()?;
  runtime.block_on(async {});
  Ok(())
}

fn build_probe_runtime() -> anyhow::Result<compio::runtime::Runtime> {
  let builder = compio::runtime::RuntimeBuilder::new();
  builder.build().context("failed to build Compio runtime")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn snapshot_reports_compio_backend_and_tokio_island() {
    let snapshot = runtime_backend_snapshot();

    assert_eq!(snapshot.target_runtime, TARGET_RUNTIME_NAME);
    assert!(matches!(
      snapshot.target_io_driver,
      "io_uring" | "polling" | "iocp" | UNAVAILABLE_IO_DRIVER_NAME
    ));
    assert_eq!(snapshot.active_runtime, ACTIVE_RUNTIME_NAME);
    assert_eq!(snapshot.compatibility_runtime, COMPATIBILITY_RUNTIME_NAME);
    assert_eq!(snapshot.compatibility_island_count, 1);
  }

  #[test]
  fn compio_runtime_builds_with_configured_driver() {
    validate_compio_runtime_available().expect("Compio runtime should build");
  }
}
