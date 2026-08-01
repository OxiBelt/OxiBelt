//! Fixed-cardinality diagnostics for upstream HTTP/3 resolution and pooling.

use std::fmt::Write as _;
use std::time::Duration;

use super::{Metrics, StripedCounter};

macro_rules! fixed_metric_enum {
  ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(usize)]
    pub(crate) enum $name {
      $($variant),+
    }

    impl $name {
      const ALL: [Self; fixed_metric_enum!(@count $($variant),+)] = [$(Self::$variant),+];
      const COUNT: usize = Self::ALL.len();

      const fn as_str(self) -> &'static str {
        match self {
          $(Self::$variant => $label),+
        }
      }
    }
  };
  (@count $($variant:ident),+) => {
    <[()]>::len(&[$(fixed_metric_enum!(@unit $variant)),+])
  };
  (@unit $variant:ident) => { () };
}

fixed_metric_enum!(H3ResolverCacheEvent {
  Hit => "hit",
  Miss => "miss",
  Stale => "stale",
  Negative => "negative",
});

fixed_metric_enum!(H3ResolverErrorClass {
  Timeout => "timeout",
  Nxdomain => "nxdomain",
  Nodata => "nodata",
  Servfail => "servfail",
  Refused => "refused",
  Malformed => "malformed",
  Io => "io",
  Canceled => "canceled",
  Other => "other",
});

fixed_metric_enum!(H3ResolverOutcome {
  Success => "success",
  Negative => "negative",
  Error => "error",
  Canceled => "canceled",
});

fixed_metric_enum!(H3EndpointFamily {
  Ipv4 => "ipv4",
  Ipv6 => "ipv6",
  All => "all",
});

fixed_metric_enum!(H3EndpointAttemptOutcome {
  Started => "started",
  Won => "won",
  Failed => "failed",
  Canceled => "canceled",
});

fixed_metric_enum!(H3EndpointSelectionEvent {
  SuccessPreferred => "success_preferred",
  Rotated => "rotated",
  CooldownEntered => "cooldown_entered",
  CooldownSkipped => "cooldown_skipped",
  CooldownExpired => "cooldown_expired",
});

fixed_metric_enum!(H3PoolEvent {
  Reuse => "reuse",
  ConnectLeader => "connect_leader",
  ConnectCoalesced => "connect_coalesced",
  Created => "created",
  ConnectError => "connect_error",
  Expired => "expired",
  Idle => "idle",
  Closed => "closed",
  StaleGenerationDiscard => "stale_generation_discard",
  Saturated => "saturated",
  Shutdown => "shutdown",
});

fixed_metric_enum!(H3PoolWaitScope {
  MapLock => "map_lock",
  SlotState => "slot_state",
  Resolution => "resolution",
  Connection => "connection",
});

fixed_metric_enum!(H3PoolWaitOutcome {
  Immediate => "immediate",
  Ready => "ready",
  Timeout => "timeout",
  Canceled => "canceled",
  Error => "error",
});

const ATTEMPT_FAMILY_COUNT: usize = 2;

#[derive(Debug)]
pub(super) struct Http3UpstreamMetrics {
  resolver_cache_events: Box<[StripedCounter]>,
  resolver_errors: Box<[StripedCounter]>,
  resolver_duration_observations: Box<[StripedCounter]>,
  resolver_duration_ns: Box<[StripedCounter]>,
  candidate_count_sum: Box<[StripedCounter]>,
  candidate_count_observations: Box<[StripedCounter]>,
  endpoint_attempts: Box<[StripedCounter]>,
  endpoint_selection_events: Box<[StripedCounter]>,
  pool_events: Box<[StripedCounter]>,
  wait_observations: Box<[StripedCounter]>,
  wait_duration_ns: Box<[StripedCounter]>,
}

impl Default for Http3UpstreamMetrics {
  fn default() -> Self {
    Self {
      resolver_cache_events: striped_counters(H3ResolverCacheEvent::COUNT),
      resolver_errors: striped_counters(H3ResolverErrorClass::COUNT),
      resolver_duration_observations: striped_counters(H3ResolverOutcome::COUNT),
      resolver_duration_ns: striped_counters(H3ResolverOutcome::COUNT),
      candidate_count_sum: striped_counters(H3EndpointFamily::COUNT),
      candidate_count_observations: striped_counters(H3EndpointFamily::COUNT),
      endpoint_attempts: striped_counters(ATTEMPT_FAMILY_COUNT * H3EndpointAttemptOutcome::COUNT),
      endpoint_selection_events: striped_counters(H3EndpointSelectionEvent::COUNT),
      pool_events: striped_counters(H3PoolEvent::COUNT),
      wait_observations: striped_counters(H3PoolWaitScope::COUNT * H3PoolWaitOutcome::COUNT),
      wait_duration_ns: striped_counters(H3PoolWaitScope::COUNT * H3PoolWaitOutcome::COUNT),
    }
  }
}

impl Http3UpstreamMetrics {
  fn record_cache_event(&self, event: H3ResolverCacheEvent) {
    self.resolver_cache_events[event as usize].increment();
  }

  fn record_resolver_error(&self, class: H3ResolverErrorClass) {
    self.resolver_errors[class as usize].increment();
  }

  fn observe_resolver(&self, outcome: H3ResolverOutcome, duration: Duration) {
    self.resolver_duration_observations[outcome as usize].increment();
    self.resolver_duration_ns[outcome as usize].add(duration_ns(duration));
  }

  fn observe_candidates(&self, family: H3EndpointFamily, count: usize) {
    self.candidate_count_sum[family as usize].add(u64::try_from(count).unwrap_or(u64::MAX));
    self.candidate_count_observations[family as usize].increment();
  }

  fn record_endpoint_attempt(&self, family: H3EndpointFamily, outcome: H3EndpointAttemptOutcome) {
    let Some(family_index) = attempt_family_index(family) else {
      return;
    };
    self.endpoint_attempts[family_index * H3EndpointAttemptOutcome::COUNT + outcome as usize]
      .increment();
  }

  fn record_endpoint_selection(&self, event: H3EndpointSelectionEvent) {
    self.endpoint_selection_events[event as usize].increment();
  }

  fn record_pool_event(&self, event: H3PoolEvent) {
    self.pool_events[event as usize].increment();
  }

  fn observe_wait(&self, scope: H3PoolWaitScope, outcome: H3PoolWaitOutcome, duration: Duration) {
    let index = scope as usize * H3PoolWaitOutcome::COUNT + outcome as usize;
    self.wait_observations[index].increment();
    self.wait_duration_ns[index].add(duration_ns(duration));
  }

  pub(super) fn append_prometheus(&self, output: &mut String) {
    append_single_label_family(
      output,
      "oxibelt_http3_upstream_resolver_cache_events_total",
      "event",
      &H3ResolverCacheEvent::ALL,
      &self.resolver_cache_events,
      H3ResolverCacheEvent::as_str,
    );
    append_single_label_family(
      output,
      "oxibelt_http3_upstream_resolver_errors_total",
      "class",
      &H3ResolverErrorClass::ALL,
      &self.resolver_errors,
      H3ResolverErrorClass::as_str,
    );
    append_single_label_family(
      output,
      "oxibelt_http3_upstream_resolver_duration_observations_total",
      "outcome",
      &H3ResolverOutcome::ALL,
      &self.resolver_duration_observations,
      H3ResolverOutcome::as_str,
    );
    append_single_label_family(
      output,
      "oxibelt_http3_upstream_resolver_duration_ns_total",
      "outcome",
      &H3ResolverOutcome::ALL,
      &self.resolver_duration_ns,
      H3ResolverOutcome::as_str,
    );
    append_single_label_family(
      output,
      "oxibelt_http3_upstream_resolver_candidate_count_sum",
      "family",
      &H3EndpointFamily::ALL,
      &self.candidate_count_sum,
      H3EndpointFamily::as_str,
    );
    append_single_label_family(
      output,
      "oxibelt_http3_upstream_resolver_candidate_count_observations_total",
      "family",
      &H3EndpointFamily::ALL,
      &self.candidate_count_observations,
      H3EndpointFamily::as_str,
    );

    append_counter_type(output, "oxibelt_http3_upstream_endpoint_attempts_total");
    for family in [H3EndpointFamily::Ipv4, H3EndpointFamily::Ipv6] {
      let family_index = attempt_family_index(family).unwrap_or_default();
      for outcome in H3EndpointAttemptOutcome::ALL {
        append_two_label_sample(
          output,
          "oxibelt_http3_upstream_endpoint_attempts_total",
          "family",
          family.as_str(),
          "outcome",
          outcome.as_str(),
          self.endpoint_attempts[family_index * H3EndpointAttemptOutcome::COUNT + outcome as usize]
            .load(),
        );
      }
    }

    append_single_label_family(
      output,
      "oxibelt_http3_upstream_endpoint_selection_events_total",
      "event",
      &H3EndpointSelectionEvent::ALL,
      &self.endpoint_selection_events,
      H3EndpointSelectionEvent::as_str,
    );
    append_single_label_family(
      output,
      "oxibelt_http3_upstream_pool_events_total",
      "event",
      &H3PoolEvent::ALL,
      &self.pool_events,
      H3PoolEvent::as_str,
    );

    append_counter_type(
      output,
      "oxibelt_http3_upstream_pool_wait_observations_total",
    );
    append_counter_type(output, "oxibelt_http3_upstream_pool_wait_duration_ns_total");
    for scope in H3PoolWaitScope::ALL {
      for outcome in H3PoolWaitOutcome::ALL {
        let index = scope as usize * H3PoolWaitOutcome::COUNT + outcome as usize;
        append_two_label_sample(
          output,
          "oxibelt_http3_upstream_pool_wait_observations_total",
          "scope",
          scope.as_str(),
          "outcome",
          outcome.as_str(),
          self.wait_observations[index].load(),
        );
        append_two_label_sample(
          output,
          "oxibelt_http3_upstream_pool_wait_duration_ns_total",
          "scope",
          scope.as_str(),
          "outcome",
          outcome.as_str(),
          self.wait_duration_ns[index].load(),
        );
      }
    }
  }
}

impl Metrics {
  pub(crate) fn record_h3_resolver_cache_event(&self, event: H3ResolverCacheEvent) {
    self.http3_upstream.record_cache_event(event);
  }

  pub(crate) fn record_h3_resolver_error(&self, class: H3ResolverErrorClass) {
    self.http3_upstream.record_resolver_error(class);
  }

  pub(crate) fn observe_h3_resolver(&self, outcome: H3ResolverOutcome, duration: Duration) {
    self.http3_upstream.observe_resolver(outcome, duration);
  }

  pub(crate) fn observe_h3_resolver_candidates(&self, family: H3EndpointFamily, count: usize) {
    self.http3_upstream.observe_candidates(family, count);
  }

  pub(crate) fn record_h3_endpoint_attempt(
    &self,
    family: H3EndpointFamily,
    outcome: H3EndpointAttemptOutcome,
  ) {
    self.http3_upstream.record_endpoint_attempt(family, outcome);
  }

  pub(crate) fn record_h3_endpoint_selection(&self, event: H3EndpointSelectionEvent) {
    self.http3_upstream.record_endpoint_selection(event);
  }

  pub(crate) fn record_h3_pool_event(&self, event: H3PoolEvent) {
    self.http3_upstream.record_pool_event(event);
  }

  pub(crate) fn observe_h3_pool_wait(
    &self,
    scope: H3PoolWaitScope,
    outcome: H3PoolWaitOutcome,
    duration: Duration,
  ) {
    self.http3_upstream.observe_wait(scope, outcome, duration);
  }
}

fn attempt_family_index(family: H3EndpointFamily) -> Option<usize> {
  match family {
    H3EndpointFamily::Ipv4 => Some(0),
    H3EndpointFamily::Ipv6 => Some(1),
    H3EndpointFamily::All => None,
  }
}

fn duration_ns(duration: Duration) -> u64 {
  u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn striped_counters(count: usize) -> Box<[StripedCounter]> {
  (0..count).map(|_| StripedCounter::default()).collect()
}

fn append_single_label_family<T: Copy>(
  output: &mut String,
  name: &str,
  label_name: &str,
  values: &[T],
  counters: &[StripedCounter],
  label: impl Fn(T) -> &'static str,
) {
  append_counter_type(output, name);
  for (index, value) in values.iter().copied().enumerate() {
    let _ = writeln!(
      output,
      "{name}{{{label_name}=\"{}\"}} {}",
      label(value),
      counters[index].load()
    );
  }
}

fn append_counter_type(output: &mut String, name: &str) {
  output.push_str("# TYPE ");
  output.push_str(name);
  output.push_str(" counter\n");
}

#[allow(clippy::too_many_arguments)]
fn append_two_label_sample(
  output: &mut String,
  name: &str,
  first_name: &str,
  first_value: &str,
  second_name: &str,
  second_value: &str,
  value: u64,
) {
  let _ = writeln!(
    output,
    "{name}{{{first_name}=\"{first_value}\",{second_name}=\"{second_value}\"}} {value}"
  );
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cache::CacheStats;
  use crate::config::MetricsConfig;
  use crate::tls::TlsServerSessionStorageStats;

  #[test]
  fn metrics_use_only_closed_label_vocabularies() {
    let metrics = Metrics::new();
    metrics.record_h3_resolver_cache_event(H3ResolverCacheEvent::Hit);
    metrics.record_h3_resolver_error(H3ResolverErrorClass::Nxdomain);
    metrics.observe_h3_resolver(H3ResolverOutcome::Success, Duration::from_millis(2));
    metrics.observe_h3_resolver_candidates(H3EndpointFamily::Ipv4, 3);
    metrics.observe_h3_resolver_candidates(H3EndpointFamily::All, 3);
    metrics.record_h3_endpoint_attempt(H3EndpointFamily::Ipv6, H3EndpointAttemptOutcome::Won);
    metrics.record_h3_endpoint_selection(H3EndpointSelectionEvent::Rotated);
    metrics.record_h3_pool_event(H3PoolEvent::StaleGenerationDiscard);
    metrics.observe_h3_pool_wait(
      H3PoolWaitScope::SlotState,
      H3PoolWaitOutcome::Ready,
      Duration::from_micros(7),
    );

    let body = metrics.prometheus(
      &MetricsConfig::default(),
      CacheStats::default(),
      TlsServerSessionStorageStats::default(),
    );

    assert!(body.contains("oxibelt_http3_upstream_resolver_cache_events_total{event=\"hit\"} 1"));
    assert!(body.contains("oxibelt_http3_upstream_resolver_errors_total{class=\"nxdomain\"} 1"));
    assert!(body.contains(
      "oxibelt_http3_upstream_endpoint_attempts_total{family=\"ipv6\",outcome=\"won\"} 1"
    ));
    assert!(
      body
        .contains("oxibelt_http3_upstream_pool_events_total{event=\"stale_generation_discard\"} 1")
    );
    assert_eq!(
      body
        .matches("# TYPE oxibelt_http3_upstream_pool_events_total counter")
        .count(),
      1
    );
    assert!(!body.contains("hostname="));
    assert!(!body.contains("address="));
  }
}
