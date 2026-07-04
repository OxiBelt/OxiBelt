//! Direct-H1 runtime backend selection.

use crate::config::RuntimeDirectH1IoMode;
use crate::metrics::Metrics;
use crate::metrics::fast_path::labels::{
  DirectH1IoBackend, DirectH1IoBackendOutcome, FastPathMetricProtocol,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectH1RuntimeBackend {
  TokioHyper,
  Compio,
}

impl DirectH1RuntimeBackend {
  pub(super) fn from_config(mode: RuntimeDirectH1IoMode) -> Self {
    match mode {
      RuntimeDirectH1IoMode::Auto | RuntimeDirectH1IoMode::TokioHyper => Self::TokioHyper,
      RuntimeDirectH1IoMode::Compio => Self::Compio,
    }
  }

  pub(super) fn record_selected(self, metrics: &Metrics, protocol: FastPathMetricProtocol) {
    self.record_outcome(metrics, protocol, DirectH1IoBackendOutcome::Selected);
  }

  pub(super) fn record_fallback(self, metrics: &Metrics, protocol: FastPathMetricProtocol) {
    self.record_outcome(metrics, protocol, DirectH1IoBackendOutcome::Fallback);
  }

  pub(super) fn record_error(self, metrics: &Metrics, protocol: FastPathMetricProtocol) {
    self.record_outcome(metrics, protocol, DirectH1IoBackendOutcome::Error);
  }

  fn record_outcome(
    self,
    metrics: &Metrics,
    protocol: FastPathMetricProtocol,
    outcome: DirectH1IoBackendOutcome,
  ) {
    let backend = match self {
      Self::TokioHyper => DirectH1IoBackend::TokioHyper,
      Self::Compio => DirectH1IoBackend::Compio,
    };
    metrics.record_direct_h1_io_backend_id(backend, protocol, outcome);
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn resolves_from_runtime_config() {
    assert_eq!(
      DirectH1RuntimeBackend::from_config(RuntimeDirectH1IoMode::Auto),
      DirectH1RuntimeBackend::TokioHyper
    );
    assert_eq!(
      DirectH1RuntimeBackend::from_config(RuntimeDirectH1IoMode::Compio),
      DirectH1RuntimeBackend::Compio
    );
  }
}
