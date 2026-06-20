//! Async runtime backend metadata and Monoio availability checks.

use anyhow::Context;
use serde::Serialize;

pub const TARGET_RUNTIME_NAME: &str = "monoio";
pub const ACTIVE_RUNTIME_NAME: &str = "tokio_compat";
pub const COMPATIBILITY_RUNTIME_NAME: &str = "tokio";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MonoioDriverSelection {
  IoUring,
  Legacy,
}

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

pub fn runtime_backend_snapshot() -> RuntimeBackendSnapshot {
  RuntimeBackendSnapshot {
    target_runtime: TARGET_RUNTIME_NAME,
    target_io_driver: detect_monoio_driver().as_str(),
    active_runtime: ACTIVE_RUNTIME_NAME,
    compatibility_runtime: COMPATIBILITY_RUNTIME_NAME,
    compatibility_island_count: 1,
  }
}

pub fn detect_monoio_driver() -> MonoioDriverSelection {
  if monoio::utils::detect_uring() {
    MonoioDriverSelection::IoUring
  } else {
    MonoioDriverSelection::Legacy
  }
}

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

    assert_eq!(snapshot.target_runtime, "monoio");
    assert!(matches!(snapshot.target_io_driver, "io_uring" | "legacy"));
    assert_eq!(snapshot.active_runtime, "tokio_compat");
    assert_eq!(snapshot.compatibility_runtime, "tokio");
    assert_eq!(snapshot.compatibility_island_count, 1);
  }

  #[test]
  fn monoio_runtime_builds_with_configured_driver() {
    validate_monoio_runtime_available().expect("Monoio runtime should build");
  }
}
