//! Public fast-path metric forwarding methods.

impl super::Metrics {
  pub fn record_direct_h1_io_backend(&self, backend: &str, protocol: &str, outcome: &str) {
    self
      .fast_path
      .record_direct_h1_io_backend(backend, protocol, outcome);
  }

  pub fn record_fast_path_selection(
    &self,
    path: &str,
    protocol: &str,
    outcome: &str,
    reason: &str,
  ) {
    self
      .fast_path
      .record_selection(path, protocol, outcome, reason);
  }
}
