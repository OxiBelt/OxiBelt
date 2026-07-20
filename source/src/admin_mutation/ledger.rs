//! Mutation-ledger types and state-machine validation.
//!
//! This module deliberately contains no signature or request-body material. The
//! persisted fingerprint is computed by the protocol layer after authentication
//! and signature verification.

use anyhow::{bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 256;
pub(crate) const MAX_SAFE_RESPONSE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_ERROR_CODE_BYTES: usize = 128;

#[derive(Debug, Clone)]
pub(crate) struct MutationClaim {
  pub(crate) request_id: String,
  pub(crate) fingerprint: String,
  pub(crate) principal: String,
  pub(crate) signer_id: String,
  pub(crate) action: String,
  pub(crate) resource: String,
  pub(crate) expected_previous_revision: String,
  pub(crate) new_revision: String,
  pub(crate) content_digest: String,
  pub(crate) cluster_id: Option<String>,
  pub(crate) membership_revision: Option<String>,
  pub(crate) issued_at: String,
  pub(crate) expires_at: String,
  pub(crate) allowed_clock_skew_seconds: i64,
  pub(crate) retention_seconds: i64,
  pub(crate) audit_record_id: i64,
}

impl MutationClaim {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    for (name, value) in [
      ("request_id", self.request_id.as_str()),
      ("fingerprint", self.fingerprint.as_str()),
      ("principal", self.principal.as_str()),
      ("signer_id", self.signer_id.as_str()),
      ("action", self.action.as_str()),
      ("resource", self.resource.as_str()),
      (
        "expected_previous_revision",
        self.expected_previous_revision.as_str(),
      ),
      ("new_revision", self.new_revision.as_str()),
      ("content_digest", self.content_digest.as_str()),
    ] {
      validate_identifier(name, value, MAX_IDENTIFIER_BYTES)?;
    }
    if let Some(cluster_id) = self.cluster_id.as_deref() {
      validate_identifier("cluster_id", cluster_id, MAX_IDENTIFIER_BYTES)?;
    }
    if let Some(membership_revision) = self.membership_revision.as_deref() {
      validate_identifier(
        "membership_revision",
        membership_revision,
        MAX_IDENTIFIER_BYTES,
      )?;
    }
    ensure!(
      self.cluster_id.is_some() == self.membership_revision.is_some(),
      "cluster_id and membership_revision must be provided together"
    );
    ensure!(
      self.expected_previous_revision != self.new_revision,
      "new_revision must differ from expected_previous_revision"
    );
    ensure!(self.audit_record_id > 0, "audit_record_id must be positive");
    ensure!(
      (0..=300).contains(&self.allowed_clock_skew_seconds),
      "allowed_clock_skew_seconds must be between 0 and 300"
    );
    ensure!(
      (1..=31_536_000).contains(&self.retention_seconds),
      "retention_seconds must be between 1 and 31536000"
    );
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MutationState {
  Claimed,
  Validating,
  Applying,
  CanaryApplying,
  CanaryHealthy,
  Expanding,
  FullyApplied,
  Committed,
  Failed,
  RollingBack,
  RolledBack,
  RollbackFailed,
  Indeterminate,
}

impl MutationState {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::Claimed => "claimed",
      Self::Validating => "validating",
      Self::Applying => "applying",
      Self::CanaryApplying => "canary_applying",
      Self::CanaryHealthy => "canary_healthy",
      Self::Expanding => "expanding",
      Self::FullyApplied => "fully_applied",
      Self::Committed => "committed",
      Self::Failed => "failed",
      Self::RollingBack => "rolling_back",
      Self::RolledBack => "rolled_back",
      Self::RollbackFailed => "rollback_failed",
      Self::Indeterminate => "indeterminate",
    }
  }

  pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
    Ok(match value {
      "claimed" => Self::Claimed,
      "validating" => Self::Validating,
      "applying" => Self::Applying,
      "canary_applying" => Self::CanaryApplying,
      "canary_healthy" => Self::CanaryHealthy,
      "expanding" => Self::Expanding,
      "fully_applied" => Self::FullyApplied,
      "committed" => Self::Committed,
      "failed" => Self::Failed,
      "rolling_back" => Self::RollingBack,
      "rolled_back" => Self::RolledBack,
      "rollback_failed" => Self::RollbackFailed,
      "indeterminate" => Self::Indeterminate,
      _ => bail!("unknown mutation state"),
    })
  }

  pub(crate) const fn is_terminal(self) -> bool {
    matches!(
      self,
      Self::Committed
        | Self::Failed
        | Self::RolledBack
        | Self::RollbackFailed
        | Self::Indeterminate
    )
  }

  pub(crate) const fn blocks_resource(self) -> bool {
    matches!(self, Self::RollbackFailed | Self::Indeterminate)
  }

  pub(crate) const fn may_transition_to(self, next: Self) -> bool {
    match self {
      Self::Claimed => matches!(
        next,
        Self::Validating | Self::Applying | Self::Committed | Self::Failed | Self::Indeterminate
      ),
      Self::Validating => matches!(
        next,
        Self::Applying
          | Self::CanaryApplying
          | Self::Committed
          | Self::Failed
          | Self::Indeterminate
      ),
      Self::Applying => matches!(
        next,
        Self::FullyApplied
          | Self::Committed
          | Self::Failed
          | Self::RollingBack
          | Self::Indeterminate
      ),
      Self::CanaryApplying => matches!(
        next,
        Self::CanaryHealthy | Self::Failed | Self::RollingBack | Self::Indeterminate
      ),
      Self::CanaryHealthy => matches!(
        next,
        Self::Expanding | Self::Failed | Self::RollingBack | Self::Indeterminate
      ),
      Self::Expanding => matches!(
        next,
        Self::FullyApplied | Self::Failed | Self::RollingBack | Self::Indeterminate
      ),
      Self::FullyApplied => matches!(
        next,
        Self::Committed | Self::Failed | Self::RollingBack | Self::Indeterminate
      ),
      Self::RollingBack => matches!(
        next,
        Self::RolledBack | Self::RollbackFailed | Self::Indeterminate
      ),
      Self::Committed
      | Self::Failed
      | Self::RolledBack
      | Self::RollbackFailed
      | Self::Indeterminate => false,
    }
  }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MutationRecord {
  pub(crate) request_id: String,
  pub(crate) fingerprint: String,
  pub(crate) principal: String,
  pub(crate) signer_id: String,
  pub(crate) action: String,
  pub(crate) resource: String,
  pub(crate) expected_previous_revision: String,
  pub(crate) new_revision: String,
  pub(crate) content_digest: String,
  pub(crate) cluster_id: Option<String>,
  pub(crate) membership_revision: Option<String>,
  pub(crate) state: MutationState,
  pub(crate) http_status: Option<i32>,
  pub(crate) safe_response: Option<Value>,
  pub(crate) error_code: Option<String>,
  pub(crate) audit_record_id: i64,
  pub(crate) terminal_audit_record_id: Option<i64>,
  pub(crate) terminal_audit_confirmed: bool,
  pub(crate) issued_at: String,
  pub(crate) expires_at: String,
  pub(crate) created_at: String,
  pub(crate) updated_at: String,
}

impl MutationRecord {
  pub(crate) const fn terminal_response_ready(&self) -> bool {
    self.state.is_terminal() && self.terminal_audit_confirmed
  }

  pub(crate) const fn terminal_anchor_pending(&self) -> bool {
    self.state.is_terminal() && !self.terminal_audit_confirmed
  }

  pub(crate) fn classify_existing_claim(self, claim: &MutationClaim) -> ClaimOutcome {
    if self.fingerprint != claim.fingerprint || self.principal != claim.principal {
      ClaimOutcome::RequestConflict
    } else if self.terminal_response_ready() {
      ClaimOutcome::Replay(self)
    } else {
      ClaimOutcome::InProgress(self)
    }
  }
}

#[derive(Debug, Clone)]
pub(crate) enum ClaimOutcome {
  Claimed(MutationRecord),
  Replay(MutationRecord),
  InProgress(MutationRecord),
  RequestConflict,
  Expired,
  RevisionConflict { actual_revision: Option<String> },
  RevisionBusy { request_id: String },
  TargetConflict,
}

#[derive(Debug, Clone)]
pub(crate) struct TerminalMutation {
  pub(crate) state: MutationState,
  pub(crate) http_status: u16,
  pub(crate) safe_response: Option<Value>,
  pub(crate) error_code: Option<String>,
  pub(crate) terminal_audit_record_id: i64,
  /// Required anchoring leaves the terminal receipt hidden until the external
  /// checkpoint receipt is durable and the confirmation marker is promoted.
  pub(crate) audit_anchor_required: bool,
}

impl TerminalMutation {
  pub(crate) fn validate(&self) -> anyhow::Result<()> {
    ensure!(self.state.is_terminal(), "terminal mutation state required");
    ensure!(
      (100..=599).contains(&self.http_status),
      "http_status must be between 100 and 599"
    );
    ensure!(
      self.terminal_audit_record_id > 0,
      "terminal_audit_record_id must be positive"
    );
    if let Some(error_code) = self.error_code.as_deref() {
      validate_identifier("error_code", error_code, MAX_ERROR_CODE_BYTES)?;
    }
    if let Some(response) = self.safe_response.as_ref() {
      validate_safe_response(response)?;
    }
    Ok(())
  }
}

pub(crate) fn validate_identifier(
  name: &str,
  value: &str,
  maximum_bytes: usize,
) -> anyhow::Result<()> {
  ensure!(!value.is_empty(), "{name} must not be empty");
  ensure!(
    value.len() <= maximum_bytes,
    "{name} exceeds {maximum_bytes} bytes"
  );
  ensure!(
    value
      .bytes()
      .all(|byte| byte.is_ascii_graphic() && byte != b'\'' && byte != b'\"'),
    "{name} contains unsupported characters"
  );
  Ok(())
}

pub(crate) fn validate_safe_response(value: &Value) -> anyhow::Result<()> {
  let encoded = serde_json::to_vec(value)?;
  ensure!(
    encoded.len() <= MAX_SAFE_RESPONSE_BYTES,
    "safe response exceeds {MAX_SAFE_RESPONSE_BYTES} bytes"
  );
  validate_safe_value(value)
}

fn validate_safe_value(value: &Value) -> anyhow::Result<()> {
  match value {
    Value::Array(values) => {
      for value in values {
        validate_safe_value(value)?;
      }
    }
    Value::Object(values) => {
      for (key, value) in values {
        let normalized = key.to_ascii_lowercase().replace('-', "_");
        ensure!(
          !is_sensitive_key(&normalized),
          "safe response contains a sensitive field"
        );
        validate_safe_value(value)?;
      }
    }
    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
  }
  Ok(())
}

fn is_sensitive_key(key: &str) -> bool {
  key == "authorization"
    || key == "cookie"
    || key == "set_cookie"
    || key.contains("password")
    || key.contains("private_key")
    || key.contains("secret")
    || key.contains("signature")
    || key == "token"
    || key.ends_with("_token")
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn mutation_state_allows_only_forward_lifecycle_edges() {
    assert!(MutationState::Claimed.may_transition_to(MutationState::Validating));
    assert!(MutationState::Validating.may_transition_to(MutationState::CanaryApplying));
    assert!(MutationState::CanaryApplying.may_transition_to(MutationState::CanaryHealthy));
    assert!(MutationState::CanaryHealthy.may_transition_to(MutationState::Expanding));
    assert!(MutationState::Expanding.may_transition_to(MutationState::FullyApplied));
    assert!(MutationState::FullyApplied.may_transition_to(MutationState::Committed));
    assert!(!MutationState::Committed.may_transition_to(MutationState::Applying));
    assert!(!MutationState::Failed.may_transition_to(MutationState::Claimed));
  }

  #[test]
  fn indeterminate_and_rollback_failure_block_the_resource() {
    assert!(MutationState::Indeterminate.blocks_resource());
    assert!(MutationState::RollbackFailed.blocks_resource());
    assert!(!MutationState::Failed.blocks_resource());
  }

  #[test]
  fn safe_response_rejects_secret_bearing_fields_at_any_depth() {
    assert!(validate_safe_response(&json!({"result": {"token": "do-not-store"}})).is_err());
    assert!(validate_safe_response(&json!({"private-key": "do-not-store"})).is_err());
    assert!(validate_safe_response(&json!({"result": "redacted", "revision": "r-2"})).is_ok());
  }

  #[test]
  fn terminal_result_requires_terminal_state_and_durable_audit() {
    let applying = TerminalMutation {
      state: MutationState::Applying,
      http_status: 200,
      safe_response: None,
      error_code: None,
      terminal_audit_record_id: 42,
      audit_anchor_required: false,
    };
    assert!(applying.validate().is_err());

    let missing_audit = TerminalMutation {
      state: MutationState::Committed,
      http_status: 200,
      safe_response: None,
      error_code: None,
      terminal_audit_record_id: 0,
      audit_anchor_required: false,
    };
    assert!(missing_audit.validate().is_err());
  }
}
