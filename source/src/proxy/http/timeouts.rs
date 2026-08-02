//! Resolved route and upstream deadlines shared by proxy transports.

use std::time::{Duration, Instant};

use crate::config::{Config, RouteConfig, UpstreamConfig};

#[derive(Clone, Copy)]
pub(crate) struct EffectiveTimeouts {
  pub(crate) response_send: Duration,
  pub(crate) websocket_idle: Duration,
  pub(crate) webtransport_idle: Duration,
  pub(crate) upstream_connect: Duration,
  pub(crate) upstream_request: Duration,
  pub(crate) upstream_first_byte: Duration,
  pub(crate) upstream_read: Duration,
  pub(crate) upstream_send: Duration,
  pub(crate) upstream_deadline: Option<Instant>,
}

impl EffectiveTimeouts {
  pub(crate) fn new(config: &Config, route: &RouteConfig, upstream: &UpstreamConfig) -> Self {
    let timeouts = &route.timeouts;
    let upstream_request_ms = timeouts
      .upstream_request_timeout_ms
      .unwrap_or(upstream.request_timeout_ms);
    let upstream_first_byte_ms = timeouts
      .upstream_first_byte_timeout_ms
      .unwrap_or(upstream.first_byte_timeout_ms)
      .min(upstream_request_ms);
    Self {
      response_send: Duration::from_millis(
        timeouts
          .response_send_timeout_ms
          .unwrap_or(config.limits.response_send_timeout_ms),
      ),
      websocket_idle: Duration::from_millis(
        timeouts
          .websocket_idle_timeout_ms
          .unwrap_or(config.limits.websocket_idle_timeout_ms),
      ),
      webtransport_idle: Duration::from_millis(
        timeouts
          .webtransport_idle_timeout_ms
          .unwrap_or(config.limits.webtransport_idle_timeout_ms),
      ),
      upstream_connect: Duration::from_millis(
        timeouts
          .upstream_connect_timeout_ms
          .unwrap_or(upstream.connect_timeout_ms),
      ),
      upstream_request: Duration::from_millis(upstream_request_ms),
      upstream_first_byte: Duration::from_millis(upstream_first_byte_ms),
      upstream_read: Duration::from_millis(
        timeouts
          .upstream_read_timeout_ms
          .unwrap_or(upstream.read_timeout_ms),
      ),
      upstream_send: Duration::from_millis(
        timeouts
          .upstream_send_timeout_ms
          .unwrap_or(upstream.send_timeout_ms),
      ),
      upstream_deadline: None,
    }
  }

  pub(crate) fn route_body_only(config: &Config, route: &RouteConfig) -> Duration {
    Duration::from_millis(
      route
        .timeouts
        .client_body_timeout_ms
        .unwrap_or(config.limits.client_body_timeout_ms),
    )
  }

  pub(crate) fn cap_upstream_to_deadline(self, deadline: Instant) -> Self {
    let mut capped =
      self.cap_upstream_to_remaining(deadline.saturating_duration_since(Instant::now()));
    capped.upstream_deadline = Some(
      capped
        .upstream_deadline
        .map_or(deadline, |existing| existing.min(deadline)),
    );
    capped
  }

  fn cap_upstream_to_remaining(mut self, remaining: Duration) -> Self {
    self.upstream_connect = self.upstream_connect.min(remaining);
    self.upstream_request = self.upstream_request.min(remaining);
    self.upstream_first_byte = self
      .upstream_first_byte
      .min(self.upstream_request)
      .min(remaining);
    self
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn timeouts(duration: Duration) -> EffectiveTimeouts {
    EffectiveTimeouts {
      response_send: duration,
      websocket_idle: duration,
      webtransport_idle: duration,
      upstream_connect: duration,
      upstream_request: duration,
      upstream_first_byte: duration,
      upstream_read: duration,
      upstream_send: duration,
      upstream_deadline: None,
    }
  }

  #[test]
  fn upstream_deadline_cap_limits_only_predispatch_budgets() {
    let original = timeouts(Duration::from_millis(100));
    let capped = original.cap_upstream_to_remaining(Duration::from_millis(25));

    assert_eq!(capped.upstream_connect, Duration::from_millis(25));
    assert_eq!(capped.upstream_request, Duration::from_millis(25));
    assert_eq!(capped.upstream_first_byte, Duration::from_millis(25));
    assert_eq!(capped.response_send, original.response_send);
    assert_eq!(capped.websocket_idle, original.websocket_idle);
    assert_eq!(capped.webtransport_idle, original.webtransport_idle);
    assert_eq!(capped.upstream_read, original.upstream_read);
    assert_eq!(capped.upstream_send, original.upstream_send);
    assert_eq!(capped.upstream_deadline, None);
  }

  #[test]
  fn upstream_deadline_cap_preserves_stricter_existing_limits() {
    let mut original = timeouts(Duration::from_millis(100));
    original.upstream_connect = Duration::from_millis(5);
    original.upstream_first_byte = Duration::from_millis(10);

    let capped = original.cap_upstream_to_remaining(Duration::from_millis(25));

    assert_eq!(capped.upstream_connect, Duration::from_millis(5));
    assert_eq!(capped.upstream_request, Duration::from_millis(25));
    assert_eq!(capped.upstream_first_byte, Duration::from_millis(10));
  }
}
