//! Staged Admin membership metrics with fixed, identity-free labels.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

use super::Metrics;

const TRANSITION_STATES: [&str; 9] = [
  "proposed",
  "learner",
  "catching_up",
  "ready",
  "activation_authorized",
  "fencing",
  "active",
  "cancelled",
  "indeterminate",
];

#[derive(Debug, Default)]
pub(super) struct AdminMembershipMetrics {
  active_members: AtomicU64,
  fenced_members: AtomicU64,
  pending_transition: [AtomicU64; TRANSITION_STATES.len()],
}

impl Metrics {
  pub(crate) fn set_admin_membership_status(
    &self,
    active_members: u64,
    fenced_members: u64,
    pending_state: Option<&str>,
  ) {
    self
      .admin_membership
      .active_members
      .store(active_members, Ordering::Relaxed);
    self
      .admin_membership
      .fenced_members
      .store(fenced_members, Ordering::Relaxed);
    for (index, state) in TRANSITION_STATES.iter().enumerate() {
      self.admin_membership.pending_transition[index]
        .store(u64::from(pending_state == Some(*state)), Ordering::Relaxed);
    }
  }

  pub(super) fn append_admin_membership_prometheus(&self, output: &mut String) {
    super::append_metric(
      output,
      "oxibelt_admin_membership_active_members",
      "gauge",
      self.admin_membership.active_members.load(Ordering::Relaxed),
    );
    super::append_metric(
      output,
      "oxibelt_admin_membership_fenced_members",
      "gauge",
      self.admin_membership.fenced_members.load(Ordering::Relaxed),
    );
    output.push_str("# TYPE oxibelt_admin_membership_pending_transition gauge\n");
    for (index, state) in TRANSITION_STATES.iter().enumerate() {
      let _ = writeln!(
        output,
        "oxibelt_admin_membership_pending_transition{{state=\"{state}\"}} {}",
        self.admin_membership.pending_transition[index].load(Ordering::Relaxed),
      );
    }
  }
}
