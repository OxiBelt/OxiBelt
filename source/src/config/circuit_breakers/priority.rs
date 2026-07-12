//! Priority-aware global request-admission configuration.

use anyhow::bail;
use serde::{Deserialize, Deserializer};

use crate::config::PriorityClass;

use super::CapacitySetting;

/// How a class reacts when its active capacity is exhausted.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PriorityRejectionPolicy {
  /// Wait in the class's bounded FIFO queue.
  #[default]
  Queue,
  /// Return the existing generic circuit-breaker rejection immediately.
  Reject,
}

/// Optional per-class override for the process-local priority scheduler.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CircuitBreakerPriorityClassConfig {
  pub name: PriorityClass,
  #[serde(default)]
  pub reserved_requests: Option<usize>,
  #[serde(default)]
  pub max_share: Option<f64>,
  #[serde(default)]
  pub max_pending_requests: Option<CapacitySetting>,
  #[serde(
    default,
    alias = "pending_queue_timeout",
    deserialize_with = "deserialize_optional_milliseconds"
  )]
  pub pending_queue_timeout_ms: Option<u64>,
  #[serde(default)]
  pub rejection_policy: Option<PriorityRejectionPolicy>,
}

/// Priority-aware global request admission.
///
/// Public route classes are fixed vocabulary. Reservation eligibility is decided at request
/// admission time from trusted local IPM or mTLS evidence, never from a client header.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CircuitBreakerPriorityConfig {
  #[serde(default = "default_enabled")]
  pub enabled: bool,
  #[serde(default)]
  pub classes: Vec<CircuitBreakerPriorityClassConfig>,
}

impl Default for CircuitBreakerPriorityConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      classes: Vec::new(),
    }
  }
}

impl CircuitBreakerPriorityConfig {
  pub(super) fn validate(&self, fixed_global_capacity: Option<usize>) -> anyhow::Result<()> {
    let mut seen = [false; PriorityClass::COUNT];
    for class in &self.classes {
      let index = class.name.index();
      if std::mem::replace(&mut seen[index], true) {
        bail!(
          "circuit_breakers.priority.classes contains duplicate class {}",
          class.name.as_str()
        );
      }
      if matches!(class.name, PriorityClass::Admin | PriorityClass::Health)
        && class.reserved_requests.unwrap_or_default() > 0
      {
        bail!(
          "circuit_breakers.priority.classes {} may not reserve public request capacity",
          class.name.as_str()
        );
      }
      if let Some(share) = class.max_share
        && (!share.is_finite() || !(0.0 < share && share <= 1.0))
      {
        bail!(
          "circuit_breakers.priority.classes {}.max_share must be finite and in (0, 1]",
          class.name.as_str()
        );
      }
      if class.pending_queue_timeout_ms == Some(0) {
        bail!(
          "circuit_breakers.priority.classes {}.pending_queue_timeout_ms must be greater than 0",
          class.name.as_str()
        );
      }
      if let Some(value) = class.max_pending_requests {
        value.validate(
          &format!(
            "circuit_breakers.priority.classes {}.max_pending_requests",
            class.name.as_str()
          ),
          true,
        )?;
      }
      if class.rejection_policy == Some(PriorityRejectionPolicy::Reject)
        && class
          .max_pending_requests
          .is_some_and(|value| value.fixed().is_some_and(|value| value > 0))
      {
        bail!(
          "circuit_breakers.priority.classes {} uses rejection_policy = \"reject\" and may not configure a positive queue",
          class.name.as_str()
        );
      }
    }

    let background = self.resolved_for_validation(PriorityClass::Background);
    let crawler = self.resolved_for_validation(PriorityClass::Crawler);
    if background.max_share + crawler.max_share >= 1.0 {
      bail!(
        "circuit_breakers.priority background and crawler maximum shares must sum to less than 1"
      );
    }
    // Automatic global capacity resolves to at least 64 requests. Checking that lower bound
    // keeps invalid reservations from surviving until runtime resource discovery.
    let global_capacity = fixed_global_capacity.unwrap_or(64);
    let reservations = PriorityClass::ALL
      .into_iter()
      .map(|class| self.resolved_for_validation(class).reserved_requests)
      .sum::<usize>();
    if reservations >= global_capacity {
      bail!(
        "circuit_breakers.priority reserved requests must leave at least one global shared request slot"
      );
    }
    for class in PriorityClass::ALL {
      let policy = self.resolved_for_validation(class);
      let class_capacity = max_class_requests(global_capacity, policy.max_share);
      if policy.reserved_requests > class_capacity {
        bail!(
          "circuit_breakers.priority class {} reserves more requests than its maximum share allows",
          class.as_str()
        );
      }
    }
    Ok(())
  }

  pub(crate) fn resolved_for_validation(&self, class: PriorityClass) -> PriorityClassPolicy {
    let mut policy = PriorityClassPolicy::default_for(class);
    if let Some(override_config) = self
      .classes
      .iter()
      .find(|candidate| candidate.name == class)
    {
      policy.apply(override_config);
    }
    policy
  }
}

/// Fully resolved, process-local class policy used by the runtime.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PriorityClassPolicy {
  pub(crate) reserved_requests: usize,
  pub(crate) max_share: f64,
  pub(crate) max_pending_requests: Option<CapacitySetting>,
  pub(crate) pending_queue_timeout_ms: Option<u64>,
  pub(crate) rejection_policy: PriorityRejectionPolicy,
}

impl PriorityClassPolicy {
  const fn default_for(class: PriorityClass) -> Self {
    match class {
      PriorityClass::Background => Self {
        reserved_requests: 0,
        max_share: 0.50,
        max_pending_requests: Some(CapacitySetting::Fixed(0)),
        pending_queue_timeout_ms: None,
        rejection_policy: PriorityRejectionPolicy::Reject,
      },
      PriorityClass::Crawler => Self {
        reserved_requests: 0,
        max_share: 0.25,
        max_pending_requests: Some(CapacitySetting::Fixed(0)),
        pending_queue_timeout_ms: None,
        rejection_policy: PriorityRejectionPolicy::Reject,
      },
      _ => Self {
        reserved_requests: 0,
        max_share: 1.0,
        max_pending_requests: None,
        pending_queue_timeout_ms: None,
        rejection_policy: PriorityRejectionPolicy::Queue,
      },
    }
  }

  fn apply(&mut self, override_config: &CircuitBreakerPriorityClassConfig) {
    if let Some(value) = override_config.reserved_requests {
      self.reserved_requests = value;
    }
    if let Some(value) = override_config.max_share {
      self.max_share = value;
    }
    if let Some(value) = override_config.max_pending_requests {
      self.max_pending_requests = Some(value);
    }
    if let Some(value) = override_config.pending_queue_timeout_ms {
      self.pending_queue_timeout_ms = Some(value);
    }
    if let Some(value) = override_config.rejection_policy {
      self.rejection_policy = value;
    }
  }
}

pub(crate) const fn max_class_requests(global_capacity: usize, max_share: f64) -> usize {
  if max_share >= 1.0 {
    return global_capacity;
  }
  (global_capacity as f64 * max_share).floor() as usize
}

const fn default_enabled() -> bool {
  true
}

fn deserialize_optional_milliseconds<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
  D: Deserializer<'de>,
{
  Option::<super::DurationLiteral>::deserialize(deserializer)?.map_or(Ok(None), |value| match value
  {
    super::DurationLiteral::Milliseconds(value) => Ok(Some(value)),
    super::DurationLiteral::Text(value) => super::parse_milliseconds(&value)
      .map(Some)
      .map_err(serde::de::Error::custom),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn class(name: PriorityClass) -> CircuitBreakerPriorityClassConfig {
    CircuitBreakerPriorityClassConfig {
      name,
      reserved_requests: None,
      max_share: None,
      max_pending_requests: None,
      pending_queue_timeout_ms: None,
      rejection_policy: None,
    }
  }

  #[test]
  fn defaults_limit_low_priority_traffic_without_reserving_public_slots() {
    let config = CircuitBreakerPriorityConfig::default();
    let background = config.resolved_for_validation(PriorityClass::Background);
    let crawler = config.resolved_for_validation(PriorityClass::Crawler);
    assert!(config.enabled);
    assert_eq!(background.reserved_requests, 0);
    assert_eq!(background.max_share, 0.50);
    assert_eq!(background.rejection_policy, PriorityRejectionPolicy::Reject);
    assert_eq!(crawler.reserved_requests, 0);
    assert_eq!(crawler.max_share, 0.25);
    assert_eq!(crawler.rejection_policy, PriorityRejectionPolicy::Reject);
    config
      .validate(Some(4))
      .expect("default priority policy should validate against a fixed global limit");
  }

  #[test]
  fn validation_rejects_duplicate_priority_class_overrides() {
    let config = CircuitBreakerPriorityConfig {
      enabled: true,
      classes: vec![
        class(PriorityClass::Interactive),
        class(PriorityClass::Interactive),
      ],
    };
    let error = config
      .validate(Some(8))
      .expect_err("duplicate priority classes must fail validation");
    assert!(error.to_string().contains("duplicate class interactive"));
  }

  #[test]
  fn validation_rejects_public_control_plane_reservations() {
    let mut admin = class(PriorityClass::Admin);
    admin.reserved_requests = Some(1);
    let config = CircuitBreakerPriorityConfig {
      enabled: true,
      classes: vec![admin],
    };
    let error = config
      .validate(Some(8))
      .expect_err("Admin listener capacity must remain separate from public routes");
    assert!(
      error
        .to_string()
        .contains("admin may not reserve public request capacity")
    );
  }

  #[test]
  fn validation_rejects_reservations_that_exceed_class_or_shared_capacity() {
    let mut background = class(PriorityClass::Background);
    background.reserved_requests = Some(3);
    let class_limited = CircuitBreakerPriorityConfig {
      enabled: true,
      classes: vec![background],
    };
    let error = class_limited
      .validate(Some(4))
      .expect_err("a reservation may not exceed its class share");
    assert!(
      error
        .to_string()
        .contains("background reserves more requests than its maximum share")
    );

    let mut callback = class(PriorityClass::SecurityCallback);
    callback.reserved_requests = Some(4);
    let no_shared_capacity = CircuitBreakerPriorityConfig {
      enabled: true,
      classes: vec![callback],
    };
    let error = no_shared_capacity
      .validate(Some(4))
      .expect_err("strict reservations must leave a shared slot");
    assert!(
      error
        .to_string()
        .contains("must leave at least one global shared request slot")
    );
  }

  #[test]
  fn rejection_policy_cannot_claim_a_positive_class_queue() {
    let mut interactive = class(PriorityClass::Interactive);
    interactive.rejection_policy = Some(PriorityRejectionPolicy::Reject);
    interactive.max_pending_requests = Some(CapacitySetting::Fixed(1));
    let config = CircuitBreakerPriorityConfig {
      enabled: true,
      classes: vec![interactive],
    };
    let error = config
      .validate(Some(8))
      .expect_err("rejecting classes must not declare a queue");
    assert!(
      error
        .to_string()
        .contains("may not configure a positive queue")
    );
  }
}
