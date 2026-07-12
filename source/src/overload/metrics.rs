use std::fmt::Write as _;
use std::sync::atomic::Ordering;

use super::pressure::transition_index;
use super::{ControlPlane, OverloadBoundary, OverloadRuntime, OverloadState, Signal, WorkKind};

impl OverloadRuntime {
  pub fn append_prometheus(&self, output: &mut String) {
    append_metric(
      output,
      "oxibelt_overload_enabled",
      "gauge",
      u8::from(self.enabled.load(Ordering::Relaxed)),
    );
    output.push_str("# TYPE oxibelt_overload_state gauge\n");
    let current = self.state();
    for state in OverloadState::ALL {
      let _ = writeln!(
        output,
        "oxibelt_overload_state{{state=\"{}\"}} {}",
        state.as_str(),
        u8::from(state == current)
      );
    }
    output.push_str("# TYPE oxibelt_overload_signal_available gauge\n");
    for signal in Signal::ALL {
      let _ = writeln!(
        output,
        "oxibelt_overload_signal_available{{signal=\"{}\"}} {}",
        signal.as_str(),
        u8::from(self.signal_available[signal as usize].load(Ordering::Relaxed))
      );
    }
    output.push_str("# TYPE oxibelt_overload_active_work gauge\n");
    for kind in WorkKind::ALL {
      let _ = writeln!(
        output,
        "oxibelt_overload_active_work{{kind=\"{}\"}} {}",
        kind.as_str(),
        self.work[kind as usize].load(Ordering::Relaxed)
      );
    }
    let latest = self
      .latest
      .lock()
      .expect("overload latest sample lock poisoned");
    output.push_str("# TYPE oxibelt_overload_memory_bytes gauge\n");
    for (kind, value) in [
      ("rss", latest.rss_bytes),
      ("current", latest.memory_current_bytes),
      ("limit", latest.memory_limit_bytes),
      ("allocator_resident", 0),
    ] {
      let _ = writeln!(
        output,
        "oxibelt_overload_memory_bytes{{kind=\"{kind}\"}} {value}"
      );
    }
    let _ = writeln!(
      output,
      "oxibelt_overload_file_descriptors{{kind=\"used\"}} {}",
      latest.fd_used
    );
    let _ = writeln!(
      output,
      "oxibelt_overload_file_descriptors{{kind=\"limit\"}} {}",
      latest.fd_limit
    );
    let _ = writeln!(
      output,
      "oxibelt_overload_event_loop_lag_seconds {}",
      latest.event_loop_lag_ms as f64 / 1_000.0
    );
    output.push_str("# TYPE oxibelt_overload_resource_ratio gauge\n");
    for (resource, value) in [
      ("memory", latest.memory_ratio),
      ("file_descriptors", latest.fd_ratio),
      ("cpu", latest.cpu_ratio),
    ] {
      let _ = writeln!(
        output,
        "oxibelt_overload_resource_ratio{{resource=\"{resource}\"}} {value}"
      );
    }
    drop(latest);
    append_metric(
      output,
      "oxibelt_overload_allocator_resident_available",
      "gauge",
      0,
    );
    output.push_str("# TYPE oxibelt_overload_action_active gauge\n");
    let config = self
      .config
      .read()
      .expect("overload configuration lock poisoned");
    let state = self.state();
    for (level, action, active) in [
      (
        "soft",
        "disable_cache_fill",
        state != OverloadState::Normal && config.actions.soft.disable_cache_fill,
      ),
      (
        "soft",
        "compression_level_cap",
        state != OverloadState::Normal
          && config
            .actions
            .soft
            .compression_level_cap
            .is_some_and(|cap| cap > 0),
      ),
      (
        "soft",
        "reduce_retries",
        state != OverloadState::Normal && config.actions.soft.retry_budget_multiplier < 1.0,
      ),
      (
        "soft",
        "prefer_cached_or_stale",
        state != OverloadState::Normal && config.actions.soft.prefer_cached_or_stale,
      ),
      (
        "hard",
        "reject_new_connections",
        state == OverloadState::Hard && config.actions.hard.reject_new_connections,
      ),
      (
        "hard",
        "reject_new_streams",
        state == OverloadState::Hard && config.actions.hard.reject_new_streams,
      ),
      (
        "hard",
        "reject_new_requests",
        state == OverloadState::Hard && config.actions.hard.reject_new_requests,
      ),
      (
        "hard",
        "recoverable_drain",
        state == OverloadState::Hard && config.actions.hard.enter_recoverable_drain,
      ),
    ] {
      let _ = writeln!(
        output,
        "oxibelt_overload_action_active{{level=\"{level}\",action=\"{action}\"}} {}",
        u8::from(active)
      );
    }
    output.push_str("# TYPE oxibelt_overload_control_plane_active gauge\n");
    output.push_str("# TYPE oxibelt_overload_control_plane_capacity gauge\n");
    for plane in ControlPlane::ALL {
      let (connection_capacity, request_capacity) = match plane {
        ControlPlane::Admin => (
          config.reserved_capacity.admin_connections,
          config.reserved_capacity.admin_requests,
        ),
        ControlPlane::Health => (
          config.reserved_capacity.health_connections,
          config.reserved_capacity.health_requests,
        ),
        ControlPlane::Metrics => (
          config.reserved_capacity.metrics_connections,
          config.reserved_capacity.metrics_requests,
        ),
      };
      let index = plane as usize;
      let _ = writeln!(
        output,
        "oxibelt_overload_control_plane_active{{plane=\"{}\",kind=\"connection\"}} {}",
        plane.as_str(),
        self.control_connections[index].load(Ordering::Relaxed)
      );
      let _ = writeln!(
        output,
        "oxibelt_overload_control_plane_active{{plane=\"{}\",kind=\"request\"}} {}",
        plane.as_str(),
        self.control_requests[index].load(Ordering::Relaxed)
      );
      let _ = writeln!(
        output,
        "oxibelt_overload_control_plane_capacity{{plane=\"{}\",kind=\"connection\"}} {connection_capacity}",
        plane.as_str()
      );
      let _ = writeln!(
        output,
        "oxibelt_overload_control_plane_capacity{{plane=\"{}\",kind=\"request\"}} {request_capacity}",
        plane.as_str()
      );
    }
    drop(config);
    output.push_str("# TYPE oxibelt_overload_rejections_total counter\n");
    for boundary in OverloadBoundary::ALL {
      let _ = writeln!(
        output,
        "oxibelt_overload_rejections_total{{boundary=\"{}\"}} {}",
        boundary.as_str(),
        self.rejections[boundary as usize].load(Ordering::Relaxed)
      );
    }
    output.push_str("# TYPE oxibelt_overload_transitions_total counter\n");
    for from in OverloadState::ALL {
      for to in OverloadState::ALL {
        for signal in Signal::ALL {
          let value = self.transitions[transition_index(from, to, signal)].load(Ordering::Relaxed);
          if value > 0 {
            let _ = writeln!(
              output,
              "oxibelt_overload_transitions_total{{from=\"{}\",to=\"{}\",signal=\"{}\"}} {value}",
              from.as_str(),
              to.as_str(),
              signal.as_str()
            );
          }
        }
      }
    }
  }
}

fn append_metric(output: &mut String, name: &str, kind: &str, value: impl std::fmt::Display) {
  let _ = writeln!(output, "# TYPE {name} {kind}");
  let _ = writeln!(output, "{name} {value}");
}
