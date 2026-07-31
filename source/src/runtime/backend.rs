//! Async runtime backend metadata and Compio availability checks.

use std::sync::OnceLock;

use compio_driver::DriverType;
use serde::Serialize;

use super::main_runtime::ActiveMainRuntime;

pub const TARGET_RUNTIME_NAME: &str = "compio";
pub const ACTIVE_RUNTIME_NAME: &str = "hybrid_compio";
pub const TOKIO_HYPER_RUNTIME_NAME: &str = "tokio_hyper";
pub const COMPATIBILITY_RUNTIME_NAME: &str = "tokio";
pub const NO_COMPATIBILITY_RUNTIME_NAME: &str = "none";
pub const UNAVAILABLE_IO_DRIVER_NAME: &str = "unavailable";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
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

static ACTIVE_RUNTIME_BACKEND: OnceLock<RuntimeBackendSnapshot> = OnceLock::new();

pub fn runtime_backend_snapshot() -> Option<RuntimeBackendSnapshot> {
  ACTIVE_RUNTIME_BACKEND.get().copied()
}

pub fn set_runtime_backend_snapshot(snapshot: RuntimeBackendSnapshot) {
  let _ = ACTIVE_RUNTIME_BACKEND.set(snapshot);
}

pub fn runtime_backend_snapshot_for(
  active_runtime: ActiveMainRuntime,
  target_io_driver: Option<CompioDriverSelection>,
) -> RuntimeBackendSnapshot {
  RuntimeBackendSnapshot {
    target_runtime: TARGET_RUNTIME_NAME,
    target_io_driver: target_io_driver
      .map(CompioDriverSelection::as_str)
      .unwrap_or(UNAVAILABLE_IO_DRIVER_NAME),
    active_runtime: match active_runtime {
      ActiveMainRuntime::Compio => ACTIVE_RUNTIME_NAME,
      ActiveMainRuntime::TokioHyper => TOKIO_HYPER_RUNTIME_NAME,
    },
    compatibility_runtime: match active_runtime {
      ActiveMainRuntime::Compio => COMPATIBILITY_RUNTIME_NAME,
      ActiveMainRuntime::TokioHyper => NO_COMPATIBILITY_RUNTIME_NAME,
    },
    compatibility_island_count: match active_runtime {
      ActiveMainRuntime::Compio => 1,
      ActiveMainRuntime::TokioHyper => 0,
    },
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
  super::compio::build_driver_runtime()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn snapshot_is_absent_before_explicit_initialization() {
    assert!(runtime_backend_snapshot().is_none());
  }

  #[test]
  fn snapshot_reports_hybrid_compio_backend_and_tokio_island() {
    let snapshot = runtime_backend_snapshot_for(
      ActiveMainRuntime::Compio,
      Some(CompioDriverSelection::IoUring),
    );

    assert_eq!(snapshot.target_runtime, TARGET_RUNTIME_NAME);
    assert_eq!(snapshot.target_io_driver, "io_uring");
    assert_eq!(snapshot.active_runtime, ACTIVE_RUNTIME_NAME);
    assert_eq!(snapshot.compatibility_runtime, COMPATIBILITY_RUNTIME_NAME);
    assert_eq!(snapshot.compatibility_island_count, 1);
  }

  #[test]
  fn snapshot_for_tokio_hyper_reports_no_compatibility_island() {
    let snapshot = runtime_backend_snapshot_for(ActiveMainRuntime::TokioHyper, None);

    assert_eq!(snapshot.target_runtime, TARGET_RUNTIME_NAME);
    assert_eq!(snapshot.target_io_driver, UNAVAILABLE_IO_DRIVER_NAME);
    assert_eq!(snapshot.active_runtime, TOKIO_HYPER_RUNTIME_NAME);
    assert_eq!(
      snapshot.compatibility_runtime,
      NO_COMPATIBILITY_RUNTIME_NAME
    );
    assert_eq!(snapshot.compatibility_island_count, 0);
  }

  #[test]
  fn compio_runtime_builds_with_configured_driver() {
    validate_compio_runtime_available().expect("Compio runtime should build");
  }
}
