//! Direct-H1 runtime backend diagnostics.

use std::fmt::Write as _;

use super::labels::{DirectH1IoBackend, DirectH1IoBackendOutcome, FastPathMetricProtocol};
use super::{FastPathMetrics, PROTOCOLS};

pub(super) const COUNTER_COUNT: usize =
  DirectH1IoBackend::COUNT * PROTOCOLS.len() * DirectH1IoBackendOutcome::COUNT;

pub(super) fn record(metrics: &FastPathMetrics, backend: &str, protocol: &str, outcome: &str) {
  let Some(backend) = DirectH1IoBackend::from_str(backend) else {
    return;
  };
  let Some(protocol) = FastPathMetricProtocol::from_str(protocol) else {
    return;
  };
  let Some(outcome) = DirectH1IoBackendOutcome::from_str(outcome) else {
    return;
  };
  metrics.record_direct_h1_io_backend_id(backend, protocol, outcome);
}

pub(super) fn counter_index_id(
  backend: DirectH1IoBackend,
  protocol: FastPathMetricProtocol,
  outcome: DirectH1IoBackendOutcome,
) -> usize {
  (backend.index() * PROTOCOLS.len() + protocol.index()) * DirectH1IoBackendOutcome::COUNT
    + outcome.index()
}

pub(super) fn append_prometheus(metrics: &FastPathMetrics, output: &mut String) {
  for backend in DirectH1IoBackend::ALL {
    for protocol in FastPathMetricProtocol::ALL {
      for outcome in DirectH1IoBackendOutcome::ALL {
        append_counter(
          output,
          backend.as_str(),
          protocol.as_str(),
          outcome.as_str(),
          metrics.direct_h1_io_backend_counters[counter_index_id(backend, protocol, outcome)]
            .load(),
        );
      }
    }
  }
}

fn append_counter(output: &mut String, backend: &str, protocol: &str, outcome: &str, value: u64) {
  output.push_str("# TYPE oxibelt_http_direct_h1_io_backend_total counter\n");
  output.push_str("oxibelt_http_direct_h1_io_backend_total{backend=\"");
  output.push_str(backend);
  output.push_str("\",protocol=\"");
  output.push_str(protocol);
  output.push_str("\",outcome=\"");
  output.push_str(outcome);
  output.push_str("\"} ");
  let _ = write!(output, "{value}");
  output.push('\n');
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn records_only_known_direct_h1_io_backends() {
    let metrics = FastPathMetrics::default();
    metrics.record_direct_h1_io_backend("tokio_hyper", "h2", "selected");
    metrics.record_direct_h1_io_backend("compio_experiment", "h3", "fallback");
    metrics.record_direct_h1_io_backend("compio_experiment", "h3", "error");
    metrics.record_direct_h1_io_backend("monoio", "h2", "selected");
    metrics.record_direct_h1_io_backend("tokio_hyper", "h9", "selected");
    metrics.record_direct_h1_io_backend_id(
      DirectH1IoBackend::TokioHyper,
      FastPathMetricProtocol::H1,
      DirectH1IoBackendOutcome::Selected,
    );

    assert_eq!(
      metrics.direct_h1_io_backend_counters[counter_index_id(
        DirectH1IoBackend::TokioHyper,
        FastPathMetricProtocol::H2,
        DirectH1IoBackendOutcome::Selected,
      )]
      .load(),
      1
    );
    assert_eq!(
      metrics.direct_h1_io_backend_counters[counter_index_id(
        DirectH1IoBackend::CompioExperiment,
        FastPathMetricProtocol::H3,
        DirectH1IoBackendOutcome::Fallback,
      )]
      .load(),
      1
    );
    assert_eq!(
      metrics.direct_h1_io_backend_counters[counter_index_id(
        DirectH1IoBackend::CompioExperiment,
        FastPathMetricProtocol::H3,
        DirectH1IoBackendOutcome::Error,
      )]
      .load(),
      1
    );
    assert_eq!(
      metrics.direct_h1_io_backend_counters[counter_index_id(
        DirectH1IoBackend::TokioHyper,
        FastPathMetricProtocol::H1,
        DirectH1IoBackendOutcome::Selected,
      )]
      .load(),
      1
    );
  }
}
