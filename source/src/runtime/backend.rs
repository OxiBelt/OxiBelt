//! Metadata for OxiBelt's Tokio runtime or a caller-owned executor.
use super::main_runtime::ActiveMainRuntime;
use serde::Serialize;
use std::sync::OnceLock;

pub const TOKIO_HYPER_RUNTIME_NAME: &str = "tokio_hyper";
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub struct RuntimeBackendSnapshot {
  pub target_runtime: &'static str,
  pub active_runtime: &'static str,
}
static ACTIVE_RUNTIME_BACKEND: OnceLock<RuntimeBackendSnapshot> = OnceLock::new();
pub fn runtime_backend_snapshot() -> Option<RuntimeBackendSnapshot> {
  ACTIVE_RUNTIME_BACKEND.get().copied()
}
pub fn set_runtime_backend_snapshot(snapshot: RuntimeBackendSnapshot) {
  let _ = ACTIVE_RUNTIME_BACKEND.set(snapshot);
}
pub fn runtime_backend_snapshot_for(active_runtime: ActiveMainRuntime) -> RuntimeBackendSnapshot {
  RuntimeBackendSnapshot {
    target_runtime: TOKIO_HYPER_RUNTIME_NAME,
    active_runtime: active_runtime.as_str(),
  }
}
