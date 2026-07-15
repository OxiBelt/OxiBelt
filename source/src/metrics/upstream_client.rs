//! Upstream HTTP client diagnostics with fixed low-cardinality labels.

use std::fmt::Write as _;

use super::{Metrics, StripedCounter};

const VERSIONS: [&str; 5] = ["h1", "h2", "h2c", "h3", "other"];
const SCHEMES: [&str; 3] = ["http", "https", "other"];
const POOLS: [&str; 3] = ["primary", "health", "other"];
const COUNTER_COUNT: usize = VERSIONS.len() * SCHEMES.len() * POOLS.len();
const H1_HTTP_PRIMARY_INDEX: usize = 0;

#[derive(Debug)]
pub(super) struct UpstreamClientMetrics {
  requests: [StripedCounter; COUNTER_COUNT],
  pool_misses: [StripedCounter; COUNTER_COUNT],
  connections_created: [StripedCounter; COUNTER_COUNT],
}

impl Default for UpstreamClientMetrics {
  fn default() -> Self {
    Self {
      requests: std::array::from_fn(|_| StripedCounter::default()),
      pool_misses: std::array::from_fn(|_| StripedCounter::default()),
      connections_created: std::array::from_fn(|_| StripedCounter::default()),
    }
  }
}

impl UpstreamClientMetrics {
  pub(super) fn record_h1_http_primary_request(&self) {
    self.requests[H1_HTTP_PRIMARY_INDEX].increment();
  }

  pub(super) fn record_h1_http_primary_pool_miss(&self) {
    self.pool_misses[H1_HTTP_PRIMARY_INDEX].increment();
  }

  pub(super) fn record_h1_http_primary_connection_created(&self) {
    self.connections_created[H1_HTTP_PRIMARY_INDEX].increment();
  }

  pub(super) fn record_request(&self, version: &str, scheme: &str, pool: &str) {
    if let Some(index) = counter_index(version, scheme, pool) {
      self.requests[index].increment();
    }
  }

  pub(super) fn record_pool_miss(&self, version: &str, scheme: &str, pool: &str) {
    if let Some(index) = counter_index(version, scheme, pool) {
      self.pool_misses[index].increment();
    }
  }

  pub(super) fn record_connection_created(&self, version: &str, scheme: &str, pool: &str) {
    if let Some(index) = counter_index(version, scheme, pool) {
      self.connections_created[index].increment();
    }
  }

  #[allow(
    clippy::expect_used,
    reason = "the loops enumerate the same fixed version, scheme, and pool label sets"
  )]
  pub(super) fn append_prometheus(&self, output: &mut String) {
    for version in VERSIONS {
      for scheme in SCHEMES {
        for pool in POOLS {
          let index = counter_index(version, scheme, pool).expect("fixed labels should exist");
          let requests = self.requests[index].load();
          let pool_misses = self.pool_misses[index].load();
          append_labeled_counter(
            output,
            "oxibelt_http_upstream_client_requests_total",
            version,
            scheme,
            pool,
            requests,
          );
          append_labeled_counter(
            output,
            "oxibelt_http_upstream_client_pool_misses_total",
            version,
            scheme,
            pool,
            pool_misses,
          );
          append_labeled_counter(
            output,
            "oxibelt_http_upstream_client_connections_created_total",
            version,
            scheme,
            pool,
            self.connections_created[index].load(),
          );
          append_labeled_gauge(
            output,
            "oxibelt_http_upstream_client_reuse_estimate",
            version,
            scheme,
            pool,
            reuse_estimate(requests, pool_misses),
          );
        }
      }
    }
  }
}

impl Metrics {
  pub(crate) fn record_http_upstream_h1_http_primary_request(&self) {
    self.upstream_client.record_h1_http_primary_request();
  }

  pub(crate) fn record_http_upstream_h1_http_primary_pool_miss(&self) {
    self.upstream_client.record_h1_http_primary_pool_miss();
  }

  pub(crate) fn record_http_upstream_h1_http_primary_connection_created(&self) {
    self
      .upstream_client
      .record_h1_http_primary_connection_created();
  }
}

fn counter_index(version: &str, scheme: &str, pool: &str) -> Option<usize> {
  let version_index = VERSIONS
    .iter()
    .position(|candidate| *candidate == version)?;
  let scheme_index = SCHEMES.iter().position(|candidate| *candidate == scheme)?;
  let pool_index = POOLS.iter().position(|candidate| *candidate == pool)?;
  Some((version_index * SCHEMES.len() + scheme_index) * POOLS.len() + pool_index)
}

fn reuse_estimate(requests: u64, pool_misses: u64) -> f64 {
  if requests == 0 {
    return 0.0;
  }
  let reused = requests.saturating_sub(pool_misses.min(requests));
  reused as f64 / requests as f64
}

fn append_labeled_counter(
  output: &mut String,
  name: &str,
  version: &str,
  scheme: &str,
  pool: &str,
  value: u64,
) {
  append_labeled_metric(output, name, "counter", version, scheme, pool, value);
}

fn append_labeled_gauge(
  output: &mut String,
  name: &str,
  version: &str,
  scheme: &str,
  pool: &str,
  value: f64,
) {
  append_labeled_metric(
    output,
    name,
    "gauge",
    version,
    scheme,
    pool,
    format_args!("{value:.6}"),
  );
}

fn append_labeled_metric(
  output: &mut String,
  name: &str,
  kind: &str,
  version: &str,
  scheme: &str,
  pool: &str,
  value: impl std::fmt::Display,
) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push(' ');
  output.push_str(kind);
  output.push('\n');
  output.push_str(name);
  output.push_str("{version=\"");
  output.push_str(version);
  output.push_str("\",scheme=\"");
  output.push_str(scheme);
  output.push_str("\",pool=\"");
  output.push_str(pool);
  output.push_str("\"} ");
  let _ = write!(output, "{value}");
  output.push('\n');
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn records_only_known_label_sets() {
    let metrics = UpstreamClientMetrics::default();
    metrics.record_request("h1", "http", "primary");
    metrics.record_pool_miss("h1", "http", "primary");
    metrics.record_connection_created("h1", "http", "primary");
    metrics.record_h1_http_primary_request();
    metrics.record_h1_http_primary_pool_miss();
    metrics.record_h1_http_primary_connection_created();
    metrics.record_request("h3", "https", "primary");
    metrics.record_pool_miss("h3", "https", "primary");
    metrics.record_connection_created("h3", "https", "primary");
    metrics.record_request("h9", "http", "primary");

    let index = counter_index("h1", "http", "primary").unwrap();
    assert_eq!(metrics.requests[index].load(), 2);
    assert_eq!(metrics.pool_misses[index].load(), 2);
    assert_eq!(metrics.connections_created[index].load(), 2);
    let h3_index = counter_index("h3", "https", "primary").unwrap();
    assert_eq!(metrics.requests[h3_index].load(), 1);
    assert_eq!(metrics.pool_misses[h3_index].load(), 1);
    assert_eq!(metrics.connections_created[h3_index].load(), 1);
  }

  #[test]
  fn reuse_estimate_is_saturating() {
    assert_eq!(reuse_estimate(0, 0), 0.0);
    assert_eq!(reuse_estimate(4, 1), 0.75);
    assert_eq!(reuse_estimate(4, 10), 0.0);
  }
}
