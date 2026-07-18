//! Pure state-transition and restart-recovery rules for Admin operations.

use std::fmt;

use super::types::{AdminOperationRecoveryClass, AdminOperationState};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::server) struct AdminOperationTransitionError {
  pub from: AdminOperationState,
  pub to: AdminOperationState,
}

impl fmt::Display for AdminOperationTransitionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "illegal admin operation transition from {} to {}",
      self.from.as_str(),
      self.to.as_str()
    )
  }
}

impl std::error::Error for AdminOperationTransitionError {}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::server) enum AdminOperationRecoveryAction {
  /// No recovery is required or allowed for an immutable terminal state.
  None,
  /// Return an operation whose effects have not begun to the durable queue.
  Requeue,
  /// Acquire a new fencing epoch and continue/restart execution.
  Reclaim,
  /// Acquire a new fencing epoch while preserving a committed cancellation request.
  ReclaimCancellation,
  /// Acquire a new fencing epoch and execute the registered compensation path.
  Compensate,
  /// Record that the side-effect outcome cannot be proven.
  MarkIndeterminate,
}

pub(in crate::server) const fn is_legal_admin_operation_transition(
  from: AdminOperationState,
  to: AdminOperationState,
) -> bool {
  use AdminOperationState as State;

  matches!(
    (from, to),
    (State::Accepted, State::Queued)
      | (State::Accepted, State::CancellationRequested)
      | (State::Queued, State::Claimed)
      | (State::Queued, State::CancellationRequested)
      | (State::Claimed, State::Running)
      | (State::Claimed, State::CancellationRequested)
      | (State::Running, State::CancellationRequested)
      | (State::Running, State::Succeeded)
      | (State::Running, State::Failed)
      | (State::Running, State::Indeterminate)
      | (
        State::CancellationRequested,
        State::Compensating
          | State::Succeeded
          | State::Failed
          | State::Cancelled
          | State::Indeterminate
      )
      | (
        State::Compensating,
        State::Cancelled | State::Failed | State::Indeterminate
      )
  )
}

pub(in crate::server) fn validate_admin_operation_transition(
  from: AdminOperationState,
  to: AdminOperationState,
) -> Result<(), AdminOperationTransitionError> {
  if is_legal_admin_operation_transition(from, to) {
    Ok(())
  } else {
    Err(AdminOperationTransitionError { from, to })
  }
}

/// Selects the conservative action after a worker lease or process is lost.
///
/// Recovery never reports success. The durable executor must still prove any terminal outcome and
/// commit it with a current fencing epoch.
pub(in crate::server) const fn admin_operation_recovery_action(
  state: AdminOperationState,
  recovery_class: AdminOperationRecoveryClass,
) -> AdminOperationRecoveryAction {
  use AdminOperationRecoveryAction as Action;
  use AdminOperationRecoveryClass as Recovery;
  use AdminOperationState as State;

  match state {
    State::Accepted | State::Queued | State::Claimed => Action::Requeue,
    State::Running => match recovery_class {
      Recovery::Resumable | Recovery::Restartable => Action::Reclaim,
      Recovery::Compensatable => Action::Compensate,
      Recovery::NonResumable => Action::MarkIndeterminate,
    },
    State::CancellationRequested => match recovery_class {
      Recovery::Resumable | Recovery::Restartable => Action::ReclaimCancellation,
      Recovery::Compensatable => Action::Compensate,
      Recovery::NonResumable => Action::MarkIndeterminate,
    },
    State::Compensating => match recovery_class {
      Recovery::Compensatable => Action::Compensate,
      Recovery::Resumable | Recovery::Restartable | Recovery::NonResumable => {
        Action::MarkIndeterminate
      }
    },
    State::Succeeded | State::Failed | State::Cancelled | State::Indeterminate | State::Expired => {
      Action::None
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const STATES: [AdminOperationState; 11] = [
    AdminOperationState::Accepted,
    AdminOperationState::Queued,
    AdminOperationState::Claimed,
    AdminOperationState::Running,
    AdminOperationState::CancellationRequested,
    AdminOperationState::Compensating,
    AdminOperationState::Succeeded,
    AdminOperationState::Failed,
    AdminOperationState::Cancelled,
    AdminOperationState::Indeterminate,
    AdminOperationState::Expired,
  ];

  const RECOVERY_CLASSES: [AdminOperationRecoveryClass; 4] = [
    AdminOperationRecoveryClass::Resumable,
    AdminOperationRecoveryClass::Restartable,
    AdminOperationRecoveryClass::Compensatable,
    AdminOperationRecoveryClass::NonResumable,
  ];

  #[test]
  fn transition_matrix_is_exact_and_terminals_are_immutable() {
    let expected = [
      (AdminOperationState::Accepted, AdminOperationState::Queued),
      (
        AdminOperationState::Accepted,
        AdminOperationState::CancellationRequested,
      ),
      (AdminOperationState::Queued, AdminOperationState::Claimed),
      (
        AdminOperationState::Queued,
        AdminOperationState::CancellationRequested,
      ),
      (AdminOperationState::Claimed, AdminOperationState::Running),
      (
        AdminOperationState::Claimed,
        AdminOperationState::CancellationRequested,
      ),
      (
        AdminOperationState::Running,
        AdminOperationState::CancellationRequested,
      ),
      (AdminOperationState::Running, AdminOperationState::Succeeded),
      (AdminOperationState::Running, AdminOperationState::Failed),
      (
        AdminOperationState::Running,
        AdminOperationState::Indeterminate,
      ),
      (
        AdminOperationState::CancellationRequested,
        AdminOperationState::Compensating,
      ),
      (
        AdminOperationState::CancellationRequested,
        AdminOperationState::Succeeded,
      ),
      (
        AdminOperationState::CancellationRequested,
        AdminOperationState::Failed,
      ),
      (
        AdminOperationState::CancellationRequested,
        AdminOperationState::Cancelled,
      ),
      (
        AdminOperationState::CancellationRequested,
        AdminOperationState::Indeterminate,
      ),
      (
        AdminOperationState::Compensating,
        AdminOperationState::Cancelled,
      ),
      (
        AdminOperationState::Compensating,
        AdminOperationState::Failed,
      ),
      (
        AdminOperationState::Compensating,
        AdminOperationState::Indeterminate,
      ),
    ];

    for from in STATES {
      for to in STATES {
        let should_be_legal = expected.contains(&(from, to));
        assert_eq!(
          is_legal_admin_operation_transition(from, to),
          should_be_legal,
          "unexpected transition decision for {} -> {}",
          from.as_str(),
          to.as_str()
        );
        assert_eq!(
          validate_admin_operation_transition(from, to).is_ok(),
          should_be_legal
        );
      }
    }

    for terminal in STATES.into_iter().filter(|state| state.is_terminal()) {
      assert!(
        STATES
          .into_iter()
          .all(|to| { !is_legal_admin_operation_transition(terminal, to) })
      );
    }
  }

  #[test]
  fn recovery_matrix_is_conservative_and_exhaustive() {
    use AdminOperationRecoveryAction as Action;
    use AdminOperationRecoveryClass as Recovery;
    use AdminOperationState as State;

    for recovery_class in RECOVERY_CLASSES {
      assert_eq!(
        admin_operation_recovery_action(State::Accepted, recovery_class),
        Action::Requeue
      );
      assert_eq!(
        admin_operation_recovery_action(State::Queued, recovery_class),
        Action::Requeue
      );
      assert_eq!(
        admin_operation_recovery_action(State::Claimed, recovery_class),
        Action::Requeue
      );
      for terminal in [
        State::Succeeded,
        State::Failed,
        State::Cancelled,
        State::Indeterminate,
        State::Expired,
      ] {
        assert_eq!(
          admin_operation_recovery_action(terminal, recovery_class),
          Action::None
        );
      }
    }

    for recovery_class in [Recovery::Resumable, Recovery::Restartable] {
      assert_eq!(
        admin_operation_recovery_action(State::Running, recovery_class),
        Action::Reclaim
      );
      assert_eq!(
        admin_operation_recovery_action(State::CancellationRequested, recovery_class),
        Action::ReclaimCancellation
      );
      assert_eq!(
        admin_operation_recovery_action(State::Compensating, recovery_class),
        Action::MarkIndeterminate
      );
    }

    assert_eq!(
      admin_operation_recovery_action(State::Running, Recovery::Compensatable),
      Action::Compensate
    );
    assert_eq!(
      admin_operation_recovery_action(State::CancellationRequested, Recovery::Compensatable),
      Action::Compensate
    );
    assert_eq!(
      admin_operation_recovery_action(State::Compensating, Recovery::Compensatable),
      Action::Compensate
    );

    for state in [
      State::Running,
      State::CancellationRequested,
      State::Compensating,
    ] {
      assert_eq!(
        admin_operation_recovery_action(state, Recovery::NonResumable),
        Action::MarkIndeterminate
      );
    }

    // Keep the product exhaustive if a state or recovery class is added.
    let evaluated = STATES
      .into_iter()
      .flat_map(|state| {
        RECOVERY_CLASSES
          .into_iter()
          .map(move |recovery| admin_operation_recovery_action(state, recovery))
      })
      .count();
    assert_eq!(evaluated, STATES.len() * RECOVERY_CLASSES.len());
  }
}
