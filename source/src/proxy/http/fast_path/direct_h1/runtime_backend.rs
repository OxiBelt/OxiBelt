//! Benchmark-only direct-H1 runtime backend selection.

use std::sync::OnceLock;

use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{
  DirectH1IoBackend, DirectH1IoBackendOutcome, FastPathMetricProtocol,
};

const EXPERIMENT_ENV: &str = "OXIBELT_EXPERIMENTAL_DIRECT_H1_IO";
const EXPERIMENT_ACK_ENV: &str = "OXIBELT_EXPERIMENTAL_DIRECT_H1_IO_ACK";
const COMPAT_ACK: &str = "benchmark-only";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectH1RuntimeBackend {
  TokioHyper,
  CompioExperimentFallback,
}

impl DirectH1RuntimeBackend {
  pub(super) fn current() -> Self {
    *BACKEND.get_or_init(|| {
      let mode = std::env::var(EXPERIMENT_ENV).ok();
      let ack = std::env::var(EXPERIMENT_ACK_ENV).ok();
      let backend = Self::from_env_values(mode.as_deref(), ack.as_deref());
      match (mode.as_deref(), ack.as_deref(), backend) {
        (Some("compio"), Some(COMPAT_ACK), Self::CompioExperimentFallback) => {
          tracing::warn!(
            "{}=compio is benchmark-only and has no verified Hyper-compatible Compio direct-H1 client yet; using tokio_hyper",
            EXPERIMENT_ENV
          );
        }
        (Some("compio"), _, Self::TokioHyper) => {
          tracing::warn!(
            "{}=compio ignored because {}={} was not supplied",
            EXPERIMENT_ENV,
            EXPERIMENT_ACK_ENV,
            COMPAT_ACK
          );
        }
        (Some(other), _, Self::TokioHyper) => {
          tracing::warn!(
            value = other,
            "{} ignored; supported value is compio",
            EXPERIMENT_ENV
          );
        }
        _ => {}
      }
      backend
    })
  }

  fn from_env_values(mode: Option<&str>, ack: Option<&str>) -> Self {
    match (mode, ack) {
      (Some("compio"), Some(COMPAT_ACK)) => Self::CompioExperimentFallback,
      _ => Self::TokioHyper,
    }
  }

  pub(super) fn record_attempt(self, metrics: &Metrics, protocol: FastPathMetricProtocol) {
    match self {
      Self::TokioHyper => metrics.record_direct_h1_io_backend_id(
        DirectH1IoBackend::TokioHyper,
        protocol,
        DirectH1IoBackendOutcome::Selected,
      ),
      Self::CompioExperimentFallback => {
        metrics.record_direct_h1_io_backend_id(
          DirectH1IoBackend::CompioExperiment,
          protocol,
          DirectH1IoBackendOutcome::Fallback,
        );
        metrics.record_direct_h1_io_backend_id(
          DirectH1IoBackend::TokioHyper,
          protocol,
          DirectH1IoBackendOutcome::Selected,
        );
      }
    }
  }
}

static BACKEND: OnceLock<DirectH1RuntimeBackend> = OnceLock::new();

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn compio_experiment_requires_ack() {
    assert_eq!(
      DirectH1RuntimeBackend::from_env_values(Some("compio"), Some(COMPAT_ACK)),
      DirectH1RuntimeBackend::CompioExperimentFallback
    );
    assert_eq!(
      DirectH1RuntimeBackend::from_env_values(Some("compio"), None),
      DirectH1RuntimeBackend::TokioHyper
    );
    assert_eq!(
      DirectH1RuntimeBackend::from_env_values(Some("compio"), Some("prod")),
      DirectH1RuntimeBackend::TokioHyper
    );
    assert_eq!(
      DirectH1RuntimeBackend::from_env_values(Some("tokio"), Some(COMPAT_ACK)),
      DirectH1RuntimeBackend::TokioHyper
    );
  }
}
