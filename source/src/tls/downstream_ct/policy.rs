//! Pure, versioned embedded-SCT compliance profiles.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use super::log_list::CtLogListSnapshot;
use crate::config::DownstreamCtPolicy;

const SHORT_CERTIFICATE_LIFETIME_SECONDS: u64 = 180 * 24 * 60 * 60;

#[derive(Clone, Debug)]
pub(super) struct VerifiedEmbeddedSct {
  pub(super) log_id: [u8; 32],
  pub(super) timestamp_ms: u64,
  pub(super) extensions: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CtComplianceResult {
  pub compliant: bool,
  pub reason: &'static str,
  pub distinct_log_count: usize,
  pub distinct_operator_count: usize,
  pub required_log_count: usize,
}

pub(super) fn evaluate(
  policy: DownstreamCtPolicy,
  list: &CtLogListSnapshot,
  scts: &[VerifiedEmbeddedSct],
  not_before: u64,
  not_after: u64,
) -> CtComplianceResult {
  match policy {
    DownstreamCtPolicy::Chrome => chrome_v1(list, scts, not_before, not_after),
    DownstreamCtPolicy::Firefox => firefox_v1(list, scts, not_before, not_after),
  }
}

fn chrome_v1(
  list: &CtLogListSnapshot,
  scts: &[VerifiedEmbeddedSct],
  not_before: u64,
  not_after: u64,
) -> CtComplianceResult {
  embedded_v1(list, scts, not_before, not_after)
}

fn firefox_v1(
  list: &CtLogListSnapshot,
  scts: &[VerifiedEmbeddedSct],
  not_before: u64,
  not_after: u64,
) -> CtComplianceResult {
  // Kept as a separate policy entrypoint intentionally. Firefox v1 currently
  // uses the same embedded-SCT thresholds, but its revision can evolve without
  // changing the stable `policy = "firefox"` configuration value.
  embedded_v1(list, scts, not_before, not_after)
}

fn embedded_v1(
  list: &CtLogListSnapshot,
  scts: &[VerifiedEmbeddedSct],
  not_before: u64,
  not_after: u64,
) -> CtComplianceResult {
  let required_log_count =
    if not_after.saturating_sub(not_before) <= SHORT_CERTIFICATE_LIFETIME_SECONDS {
      2
    } else {
      3
    };
  if not_after <= not_before {
    return result(
      false,
      "ct_policy_certificate_lifetime",
      0,
      0,
      required_log_count,
    );
  }

  let earliest_sct_ms = scts
    .iter()
    .map(|sct| sct.timestamp_ms)
    .min()
    .unwrap_or(u64::MAX);
  let mut per_log = HashMap::<[u8; 32], &VerifiedEmbeddedSct>::new();
  for sct in scts {
    per_log
      .entry(sct.log_id)
      .and_modify(|current| {
        if sct.timestamp_ms < current.timestamp_ms {
          *current = sct;
        }
      })
      .or_insert(sct);
  }

  let mut qualifying_logs = HashSet::new();
  let mut qualifying_operators = HashSet::new();
  let mut has_current_log = false;
  for (log_id, sct) in per_log {
    let Some(log) = list.logs.get(&log_id) else {
      continue;
    };
    if let Some(interval) = log.temporal_interval
      && !(interval.start_inclusive..interval.end_exclusive).contains(&not_after)
    {
      continue;
    }
    if log.tiled && crate::ct::static_ct::parse_leaf_index_extension(&sct.extensions).is_err() {
      continue;
    }
    let state_acceptable = if log.state.is_currently_acceptable() {
      has_current_log = true;
      true
    } else if let Some(retired_at) = log.state.retired_at() {
      let retired_at_ms = retired_at.saturating_mul(1_000);
      earliest_sct_ms < retired_at_ms && sct.timestamp_ms < retired_at_ms
    } else {
      false
    };
    if !state_acceptable {
      continue;
    }
    qualifying_logs.insert(log_id);
    qualifying_operators.insert(log.operator_at(sct.timestamp_ms).to_string());
  }

  let log_count = qualifying_logs.len();
  let operator_count = qualifying_operators.len();
  if !has_current_log {
    return result(
      false,
      "ct_policy_log_state",
      log_count,
      operator_count,
      required_log_count,
    );
  }
  if log_count < required_log_count {
    return result(
      false,
      "ct_policy_insufficient_logs",
      log_count,
      operator_count,
      required_log_count,
    );
  }
  if operator_count < 2 {
    return result(
      false,
      "ct_policy_insufficient_operators",
      log_count,
      operator_count,
      required_log_count,
    );
  }
  result(
    true,
    "compliant",
    log_count,
    operator_count,
    required_log_count,
  )
}

fn result(
  compliant: bool,
  reason: &'static str,
  distinct_log_count: usize,
  distinct_operator_count: usize,
  required_log_count: usize,
) -> CtComplianceResult {
  CtComplianceResult {
    compliant,
    reason,
    distinct_log_count,
    distinct_operator_count,
    required_log_count,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::tls::downstream_ct::log_list::{
    CtLog, CtLogState, PreviousOperator, TemporalInterval,
  };

  fn list(states: [CtLogState; 3], operators: [&str; 3]) -> CtLogListSnapshot {
    let logs = states
      .into_iter()
      .zip(operators)
      .enumerate()
      .map(|(index, (state, operator))| {
        let mut id = [0; 32];
        id[0] = index as u8;
        (
          id,
          CtLog {
            key_spki: Vec::new(),
            operator: operator.to_string(),
            previous_operators: Vec::<PreviousOperator>::new(),
            state,
            temporal_interval: Some(TemporalInterval {
              start_inclusive: 0,
              end_exclusive: u64::MAX,
            }),
            tiled: false,
          },
        )
      })
      .collect();
    CtLogListSnapshot {
      version: "test".to_string(),
      timestamp: 1,
      logs,
    }
  }

  fn scts(count: usize) -> Vec<VerifiedEmbeddedSct> {
    (0..count)
      .map(|index| {
        let mut log_id = [0; 32];
        log_id[0] = index as u8;
        VerifiedEmbeddedSct {
          log_id,
          timestamp_ms: 1_000,
          extensions: Vec::new(),
        }
      })
      .collect()
  }

  #[test]
  fn lifetime_boundary_requires_two_then_three_distinct_logs() {
    let list = list(
      [
        CtLogState::Usable { since: 1 },
        CtLogState::Qualified { since: 1 },
        CtLogState::Readonly { since: 1 },
      ],
      ["a", "b", "c"],
    );
    assert!(
      evaluate(
        DownstreamCtPolicy::Chrome,
        &list,
        &scts(2),
        1,
        1 + SHORT_CERTIFICATE_LIFETIME_SECONDS,
      )
      .compliant
    );
    assert!(
      !evaluate(
        DownstreamCtPolicy::Chrome,
        &list,
        &scts(2),
        1,
        2 + SHORT_CERTIFICATE_LIFETIME_SECONDS,
      )
      .compliant
    );
    assert!(
      evaluate(
        DownstreamCtPolicy::Firefox,
        &list,
        &scts(3),
        1,
        2 + SHORT_CERTIFICATE_LIFETIME_SECONDS,
      )
      .compliant
    );
  }

  #[test]
  fn duplicate_operators_do_not_satisfy_diversity() {
    let list = list(
      [
        CtLogState::Usable { since: 1 },
        CtLogState::Usable { since: 1 },
        CtLogState::Usable { since: 1 },
      ],
      ["same", "same", "other"],
    );
    let result = evaluate(DownstreamCtPolicy::Chrome, &list, &scts(2), 1, 2);
    assert!(!result.compliant);
    assert_eq!(result.reason, "ct_policy_insufficient_operators");
  }

  #[test]
  fn retired_and_rejected_logs_follow_earliest_sct_timing() {
    let acceptable = list(
      [
        CtLogState::Usable { since: 1 },
        CtLogState::Retired { since: 2 },
        CtLogState::Rejected { since: 2 },
      ],
      ["a", "b", "c"],
    );
    let accepted = evaluate(DownstreamCtPolicy::Chrome, &acceptable, &scts(2), 1, 2);
    assert!(accepted.compliant);

    let retired_too_early = list(
      [
        CtLogState::Usable { since: 1 },
        CtLogState::Retired { since: 1 },
        CtLogState::Rejected { since: 1 },
      ],
      ["a", "b", "c"],
    );
    let rejected = evaluate(
      DownstreamCtPolicy::Chrome,
      &retired_too_early,
      &scts(3),
      1,
      2,
    );
    assert!(!rejected.compliant);
    assert_eq!(rejected.distinct_log_count, 1);
  }

  #[test]
  fn operator_history_is_selected_at_sct_issuance_time() {
    let mut list = list(
      [
        CtLogState::Usable { since: 1 },
        CtLogState::Usable { since: 1 },
        CtLogState::Usable { since: 1 },
      ],
      ["new", "new", "new"],
    );
    list.logs.get_mut(&[0; 32]).unwrap().previous_operators = vec![PreviousOperator {
      name: "old".to_string(),
      end_time: 2,
    }];
    let result = evaluate(DownstreamCtPolicy::Firefox, &list, &scts(2), 1, 2);
    assert!(result.compliant);
    assert_eq!(result.distinct_operator_count, 2);
  }

  #[test]
  fn duplicate_scts_from_one_log_count_once() {
    let list = list(
      [
        CtLogState::Usable { since: 1 },
        CtLogState::Usable { since: 1 },
        CtLogState::Usable { since: 1 },
      ],
      ["a", "b", "c"],
    );
    let mut duplicate = scts(1);
    duplicate.push(duplicate[0].clone());
    let result = evaluate(DownstreamCtPolicy::Chrome, &list, &duplicate, 1, 2);
    assert!(!result.compliant);
    assert_eq!(result.distinct_log_count, 1);
  }
}
