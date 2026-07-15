//! Bounded-cardinality Prometheus rendering for circuit-breaker state.

use std::fmt::Write as _;
use std::sync::atomic::Ordering;

use super::runtime::CircuitBreakerRuntime;
use super::types::{AdmissionRejectionReason, CircuitState, ResourceKind};

impl CircuitBreakerRuntime {
  pub fn append_prometheus(&self, output: &mut String) {
    output.push_str("# TYPE oxibelt_circuit_breaker_enabled gauge\n");
    let _ = writeln!(
      output,
      "oxibelt_circuit_breaker_enabled {}",
      u8::from(self.enabled.load(Ordering::Acquire))
    );
    let Ok(state) = self.state_guard() else {
      output.push_str("# TYPE oxibelt_circuit_breaker_state_unavailable gauge\n");
      output.push_str("oxibelt_circuit_breaker_state_unavailable 1\n");
      return;
    };
    output.push_str("# TYPE oxibelt_circuit_breaker_state_unavailable gauge\n");
    output.push_str("oxibelt_circuit_breaker_state_unavailable 0\n");
    output.push_str("# TYPE oxibelt_circuit_breaker_active gauge\n");
    output.push_str("# TYPE oxibelt_circuit_breaker_queued gauge\n");
    output.push_str("# TYPE oxibelt_circuit_breaker_state gauge\n");
    for (count, (scope_key, scope)) in state.scopes.iter().enumerate() {
      if count >= 4_096 {
        break;
      }
      let scope_kind = scope_key.kind();
      let scope_name = escape_label(scope_key.label());
      for resource in ResourceKind::ALL {
        let index = resource as usize;
        let _ = writeln!(
          output,
          "oxibelt_circuit_breaker_active{{scope_kind=\"{scope_kind}\",scope=\"{scope_name}\",kind=\"{}\"}} {}",
          resource.as_str(),
          scope.active[index]
        );
        let _ = writeln!(
          output,
          "oxibelt_circuit_breaker_queued{{scope_kind=\"{scope_kind}\",scope=\"{scope_name}\",kind=\"{}\"}} {}",
          resource.as_str(),
          scope.queued[index]
        );
      }
      for circuit_state in CircuitState::ALL {
        let _ = writeln!(
          output,
          "oxibelt_circuit_breaker_state{{scope_kind=\"{scope_kind}\",scope=\"{scope_name}\",state=\"{}\"}} {}",
          circuit_state.as_str(),
          u8::from(scope.circuit.state == circuit_state)
        );
      }
    }
    output.push_str("# TYPE oxibelt_circuit_breaker_rejections_total counter\n");
    for reason in AdmissionRejectionReason::ALL {
      let _ = writeln!(
        output,
        "oxibelt_circuit_breaker_rejections_total{{reason=\"{}\"}} {}",
        reason.as_str(),
        state.rejections[reason as usize]
      );
    }
    output.push_str("# TYPE oxibelt_circuit_breaker_queue_wait_milliseconds_total counter\n");
    let _ = writeln!(
      output,
      "oxibelt_circuit_breaker_queue_wait_milliseconds_total {}",
      state.queue_wait_ms
    );
    let _ = writeln!(
      output,
      "oxibelt_circuit_breaker_queue_waits_total {}",
      state.queue_waits
    );
    output.push_str("# TYPE oxibelt_upstream_attempts_total counter\n");
    for (kind, value) in [
      ("original", state.attempts[0]),
      ("retry", state.attempts[1]),
      ("hedge", state.attempts[2]),
      ("mirror", state.attempts[3]),
      ("background", state.attempts[4]),
    ] {
      let _ = writeln!(
        output,
        "oxibelt_upstream_attempts_total{{kind=\"{kind}\"}} {value}"
      );
    }
    output.push_str("# TYPE oxibelt_circuit_breaker_transitions_total counter\n");
    for from in CircuitState::ALL {
      for to in CircuitState::ALL {
        let value = state.transitions[from as usize][to as usize];
        if value > 0 {
          let _ = writeln!(
            output,
            "oxibelt_circuit_breaker_transitions_total{{from=\"{}\",to=\"{}\"}} {value}",
            from.as_str(),
            to.as_str()
          );
        }
      }
    }
    state.priority.append_prometheus(output);
  }
}

fn escape_label(value: &str) -> String {
  value
    .replace('\\', "\\\\")
    .replace('"', "\\\"")
    .replace('\n', "\\n")
}
