//! Fixed-cardinality process-local bandwidth shaping metrics.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::bandwidth::BandwidthDirection;

use super::Metrics;

const DIRECTIONS: [BandwidthDirection; 2] =
  [BandwidthDirection::Upload, BandwidthDirection::Download];
const TRAFFIC_CLASSES: [BandwidthTrafficClass; 5] = [
  BandwidthTrafficClass::Http,
  BandwidthTrafficClass::Tunnel,
  BandwidthTrafficClass::WebSocket,
  BandwidthTrafficClass::WebTransportStream,
  BandwidthTrafficClass::WebTransportDatagram,
];
const SERIES_COUNT: usize = DIRECTIONS.len() * TRAFFIC_CLASSES.len();

/// A bounded traffic-class label for bandwidth shaping metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BandwidthTrafficClass {
  Http,
  Tunnel,
  WebSocket,
  WebTransportStream,
  WebTransportDatagram,
}

impl BandwidthTrafficClass {
  const fn index(self) -> usize {
    match self {
      Self::Http => 0,
      Self::Tunnel => 1,
      Self::WebSocket => 2,
      Self::WebTransportStream => 3,
      Self::WebTransportDatagram => 4,
    }
  }

  const fn label(self) -> &'static str {
    match self {
      Self::Http => "http",
      Self::Tunnel => "tunnel",
      Self::WebSocket => "websocket",
      Self::WebTransportStream => "webtransport_stream",
      Self::WebTransportDatagram => "webtransport_datagram",
    }
  }
}

#[derive(Debug, Default)]
pub(super) struct BandwidthMetrics {
  shaped_bytes: [AtomicU64; SERIES_COUNT],
  waits: [AtomicU64; SERIES_COUNT],
  wait_duration_ns: [AtomicU64; SERIES_COUNT],
  cancelled_reservations: [AtomicU64; SERIES_COUNT],
  datagram_drop_newest: [AtomicU64; DIRECTIONS.len()],
}

impl Metrics {
  pub fn record_bandwidth_shaped_bytes(
    &self,
    direction: BandwidthDirection,
    traffic: BandwidthTrafficClass,
    bytes: u64,
  ) {
    self.bandwidth.shaped_bytes[series_index(direction, traffic)]
      .fetch_add(bytes, Ordering::Relaxed);
  }

  /// Records one deliberate limiter wait and its complete duration.
  pub fn record_bandwidth_wait(
    &self,
    direction: BandwidthDirection,
    traffic: BandwidthTrafficClass,
    duration: Duration,
  ) {
    let index = series_index(direction, traffic);
    self.bandwidth.waits[index].fetch_add(1, Ordering::Relaxed);
    self.bandwidth.wait_duration_ns[index].fetch_add(
      u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX),
      Ordering::Relaxed,
    );
  }

  pub fn record_bandwidth_cancelled_reservation(
    &self,
    direction: BandwidthDirection,
    traffic: BandwidthTrafficClass,
  ) {
    self.bandwidth.cancelled_reservations[series_index(direction, traffic)]
      .fetch_add(1, Ordering::Relaxed);
  }

  pub fn record_bandwidth_datagram_drop_newest(&self, direction: BandwidthDirection) {
    self.bandwidth.datagram_drop_newest[direction_index(direction)].fetch_add(1, Ordering::Relaxed);
  }
}

impl BandwidthMetrics {
  pub(super) fn append_prometheus(&self, output: &mut String) {
    append_counter_family(
      output,
      "oxibelt_bandwidth_shaped_bytes_total",
      &self.shaped_bytes,
    );
    append_counter_family(output, "oxibelt_bandwidth_waits_total", &self.waits);
    append_counter_family(
      output,
      "oxibelt_bandwidth_wait_duration_ns_total",
      &self.wait_duration_ns,
    );
    append_counter_family(
      output,
      "oxibelt_bandwidth_cancelled_reservations_total",
      &self.cancelled_reservations,
    );

    output.push_str("# TYPE oxibelt_bandwidth_datagram_drop_newest_total counter\n");
    for direction in DIRECTIONS {
      append_counter(
        output,
        "oxibelt_bandwidth_datagram_drop_newest_total",
        direction,
        BandwidthTrafficClass::WebTransportDatagram,
        self.datagram_drop_newest[direction_index(direction)].load(Ordering::Relaxed),
      );
    }
  }
}

fn append_counter_family(output: &mut String, name: &str, counters: &[AtomicU64; SERIES_COUNT]) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" counter\n");
  for direction in DIRECTIONS {
    for traffic in TRAFFIC_CLASSES {
      append_counter(
        output,
        name,
        direction,
        traffic,
        counters[series_index(direction, traffic)].load(Ordering::Relaxed),
      );
    }
  }
}

fn append_counter(
  output: &mut String,
  name: &str,
  direction: BandwidthDirection,
  traffic: BandwidthTrafficClass,
  value: u64,
) {
  output.push_str(name);
  output.push_str("{direction=\"");
  output.push_str(direction_label(direction));
  output.push_str("\",traffic=\"");
  output.push_str(traffic.label());
  output.push_str("\"} ");
  let _ = writeln!(output, "{value}");
}

const fn series_index(direction: BandwidthDirection, traffic: BandwidthTrafficClass) -> usize {
  direction_index(direction) * TRAFFIC_CLASSES.len() + traffic.index()
}

const fn direction_index(direction: BandwidthDirection) -> usize {
  match direction {
    BandwidthDirection::Upload => 0,
    BandwidthDirection::Download => 1,
  }
}

const fn direction_label(direction: BandwidthDirection) -> &'static str {
  match direction {
    BandwidthDirection::Upload => "upload",
    BandwidthDirection::Download => "download",
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn records_and_renders_only_fixed_bandwidth_labels() {
    let metrics = Metrics::default();
    metrics.record_bandwidth_shaped_bytes(
      BandwidthDirection::Upload,
      BandwidthTrafficClass::Http,
      17,
    );
    metrics.record_bandwidth_wait(
      BandwidthDirection::Download,
      BandwidthTrafficClass::WebTransportStream,
      Duration::from_nanos(23),
    );
    metrics.record_bandwidth_cancelled_reservation(
      BandwidthDirection::Upload,
      BandwidthTrafficClass::WebSocket,
    );
    metrics.record_bandwidth_datagram_drop_newest(BandwidthDirection::Download);

    let mut output = String::new();
    metrics.bandwidth.append_prometheus(&mut output);

    assert!(
      output
        .contains("oxibelt_bandwidth_shaped_bytes_total{direction=\"upload\",traffic=\"http\"} 17")
    );
    assert!(output.contains(
      "oxibelt_bandwidth_waits_total{direction=\"download\",traffic=\"webtransport_stream\"} 1"
    ));
    assert!(output.contains(
      "oxibelt_bandwidth_wait_duration_ns_total{direction=\"download\",traffic=\"webtransport_stream\"} 23"
    ));
    assert!(output.contains(
      "oxibelt_bandwidth_cancelled_reservations_total{direction=\"upload\",traffic=\"websocket\"} 1"
    ));
    assert!(output.contains(
      "oxibelt_bandwidth_datagram_drop_newest_total{direction=\"download\",traffic=\"webtransport_datagram\"} 1"
    ));
    assert!(!output.contains("route="));

    for name in [
      "oxibelt_bandwidth_shaped_bytes_total{",
      "oxibelt_bandwidth_waits_total{",
      "oxibelt_bandwidth_wait_duration_ns_total{",
      "oxibelt_bandwidth_cancelled_reservations_total{",
    ] {
      assert_eq!(output.matches(name).count(), SERIES_COUNT);
    }
    assert_eq!(
      output
        .matches("oxibelt_bandwidth_datagram_drop_newest_total{")
        .count(),
      DIRECTIONS.len()
    );
  }

  #[test]
  fn wait_duration_saturates_at_u64_nanoseconds() {
    let metrics = Metrics::default();
    metrics.record_bandwidth_wait(
      BandwidthDirection::Upload,
      BandwidthTrafficClass::Tunnel,
      Duration::MAX,
    );

    let index = series_index(BandwidthDirection::Upload, BandwidthTrafficClass::Tunnel);
    assert_eq!(
      metrics.bandwidth.wait_duration_ns[index].load(Ordering::Relaxed),
      u64::MAX
    );
  }
}
