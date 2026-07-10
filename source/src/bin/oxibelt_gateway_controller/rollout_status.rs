use super::rollout::{RolloutPhase, RolloutState};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RolloutStatus {
  pub phase: RolloutPhase,
  pub desired_revision: Option<String>,
  pub desired_content_digest: Option<String>,
  pub reason: Option<String>,
}

impl RolloutStatus {
  pub fn pending(reason: impl Into<String>) -> Self {
    Self {
      phase: RolloutPhase::Generated,
      desired_revision: None,
      desired_content_digest: None,
      reason: Some(reason.into()),
    }
  }

  pub fn failed(reason: impl Into<String>) -> Self {
    Self {
      phase: RolloutPhase::Failed,
      desired_revision: None,
      desired_content_digest: None,
      reason: Some(reason.into()),
    }
  }

  pub fn is_committed(&self) -> bool {
    self.phase.is_committed()
  }

  pub fn programmed(&self, accepted: bool) -> ProgrammedCondition {
    if !accepted {
      return ProgrammedCondition {
        programmed: false,
        reason: "Pending",
        message: "Resource is not accepted by OxiBelt",
      };
    }
    if self.is_committed() {
      return ProgrammedCondition {
        programmed: true,
        reason: "Programmed",
        message: "Desired immutable OxiBelt configuration is committed on every Ready replica",
      };
    }
    if self.reason.as_deref() == Some("ConvergenceLost") {
      return ProgrammedCondition {
        programmed: false,
        reason: "ConvergenceLost",
        message: "A Ready replica no longer proves the desired immutable OxiBelt configuration",
      };
    }
    match self.phase {
      RolloutPhase::Failed => ProgrammedCondition {
        programmed: false,
        reason: "RolloutFailed",
        message: "Desired OxiBelt configuration failed immutable rollout validation or convergence",
      },
      RolloutPhase::RollbackRequested => ProgrammedCondition {
        programmed: false,
        reason: "RollbackInProgress",
        message: "Desired OxiBelt configuration is not committed while the previous revision is restored",
      },
      RolloutPhase::RolledBack => ProgrammedCondition {
        programmed: false,
        reason: "RollbackComplete",
        message: "Desired OxiBelt configuration was rolled back and remains blocked until its revision changes",
      },
      _ => ProgrammedCondition {
        programmed: false,
        reason: "Pending",
        message: "Desired OxiBelt configuration is waiting for immutable workload convergence",
      },
    }
  }
}

impl From<&RolloutState> for RolloutStatus {
  fn from(state: &RolloutState) -> Self {
    Self {
      phase: state.phase,
      desired_revision: state.desired_revision.clone(),
      desired_content_digest: state.desired_content_digest.clone(),
      reason: state.failure.clone(),
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ProgrammedCondition {
  pub programmed: bool,
  pub reason: &'static str,
  pub message: &'static str,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn accepted_resources_wait_for_a_committed_rollout() {
    let pending = RolloutStatus::pending("WaitingForTarget");
    assert!(!pending.programmed(true).programmed);
    let committed = RolloutStatus {
      phase: RolloutPhase::Committed,
      desired_revision: Some("revision".to_string()),
      desired_content_digest: Some("digest".to_string()),
      reason: None,
    };
    assert!(committed.programmed(true).programmed);
  }

  #[test]
  fn lost_convergence_keeps_accepted_resources_unprogrammed() {
    let lost = RolloutStatus {
      phase: RolloutPhase::Generated,
      desired_revision: Some("revision".to_string()),
      desired_content_digest: Some("digest".to_string()),
      reason: Some("ConvergenceLost".to_string()),
    };
    let condition = lost.programmed(true);
    assert!(!condition.programmed);
    assert_eq!(condition.reason, "ConvergenceLost");
  }
}
