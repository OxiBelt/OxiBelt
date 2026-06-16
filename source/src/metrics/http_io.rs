//! HTTP transport I/O diagnostics with fixed low-cardinality labels.

use super::StripedCounter;

const PROTOCOLS: [&str; 2] = ["h1", "other"];
const TRANSPORTS: [&str; 3] = ["tcp", "tls", "other"];
const COUNTER_COUNT: usize = PROTOCOLS.len() * TRANSPORTS.len();

#[derive(Debug)]
pub(super) struct HttpIoMetrics {
  downstream_write_flushes: [StripedCounter; COUNTER_COUNT],
}

impl Default for HttpIoMetrics {
  fn default() -> Self {
    Self {
      downstream_write_flushes: std::array::from_fn(|_| StripedCounter::default()),
    }
  }
}

impl HttpIoMetrics {
  pub(super) fn record_downstream_write_flush(&self, protocol: &str, transport: &str) {
    if let Some(index) = counter_index(protocol, transport) {
      self.downstream_write_flushes[index].increment();
    }
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    for protocol in PROTOCOLS {
      for transport in TRANSPORTS {
        append_labeled_counter(
          output,
          protocol,
          transport,
          self.downstream_write_flushes
            [counter_index(protocol, transport).expect("fixed labels should exist")]
          .load(),
        );
      }
    }
  }
}

fn counter_index(protocol: &str, transport: &str) -> Option<usize> {
  let protocol_index = PROTOCOLS
    .iter()
    .position(|candidate| *candidate == protocol)?;
  let transport_index = TRANSPORTS
    .iter()
    .position(|candidate| *candidate == transport)?;
  Some(protocol_index * TRANSPORTS.len() + transport_index)
}

fn append_labeled_counter(output: &mut String, protocol: &str, transport: &str, value: u64) {
  output.push_str("# TYPE oxibelt_http_downstream_write_flushes_total counter\n");
  output.push_str("oxibelt_http_downstream_write_flushes_total{protocol=\"");
  output.push_str(protocol);
  output.push_str("\",transport=\"");
  output.push_str(transport);
  output.push_str("\"} ");
  output.push_str(&value.to_string());
  output.push('\n');
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn records_only_known_label_sets() {
    let metrics = HttpIoMetrics::default();
    metrics.record_downstream_write_flush("h1", "tls");
    metrics.record_downstream_write_flush("h9", "tls");

    assert_eq!(
      metrics.downstream_write_flushes[counter_index("h1", "tls").unwrap()].load(),
      1
    );
  }
}
