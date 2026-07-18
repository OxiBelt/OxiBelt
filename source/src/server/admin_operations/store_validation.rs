//! Validation kept separate from PostgreSQL state transitions.

use super::*;

impl NewJournalOperation {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    super::super::id::parse_operation_id(&self.operation_id)?;
    for (name, value, maximum) in [
      ("operation_id", self.operation_id.as_str(), 256),
      ("actor", self.actor.as_str(), 256),
      ("request_id", self.request_id.as_str(), 256),
      (
        "submitter_worker_id",
        self.submitter_worker_id.as_str(),
        256,
      ),
      ("submitter_boot_id", self.submitter_boot_id.as_str(), 256),
      ("principal", self.principal.as_str(), 512),
      ("permission_action", self.permission_action.as_str(), 128),
    ] {
      validate_text(name, value, maximum)?;
    }
    if let Some(value) = self.redacted_resource.as_deref() {
      validate_text("redacted_resource", value, 512)?;
    }
    ensure!(
      is_sha256_digest(&self.resource_digest),
      "resource_digest must be canonical SHA-256"
    );
    ensure!(
      is_sha256_digest(&self.request_fingerprint),
      "request_fingerprint must be canonical SHA-256"
    );
    if let Some(value) = self.idempotency_key_digest.as_deref() {
      ensure!(
        value.len() == 76
          && value.strip_prefix("hmac-sha256:").is_some_and(|digest| {
            digest.len() == 64
              && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
          }),
        "idempotency key digest must be canonical HMAC-SHA-256"
      );
    }
    ensure!(
      self.schema_version > 0,
      "operation schema version must be positive"
    );
    ensure!(
      (60..=2_592_000).contains(&self.maximum_lifetime_seconds),
      "operation lifetime must be between 60 and 2592000 seconds"
    );
    ensure!(
      (1..=2_592_000).contains(&self.retention_seconds),
      "operation retention must be between 1 and 2592000 seconds"
    );
    if let Some(progress) = self.progress.as_ref() {
      validate_json("progress", progress, MAX_JSON_BYTES)?;
    }
    Ok(())
  }
}

impl WorkerIdentity {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    validate_text("worker_id", &self.worker_id, 256)?;
    validate_text("boot_id", &self.boot_id, 256)
  }
}

impl LeaseGuard {
  pub(super) fn validate(&self) -> anyhow::Result<()> {
    validate_text("operation_id", &self.operation_id, 256)?;
    validate_text("worker_id", &self.worker_id, 256)?;
    validate_text("boot_id", &self.boot_id, 256)?;
    ensure!(self.lease_epoch > 0, "lease epoch must be positive");
    ensure!(
      self.expected_revision > 0,
      "expected revision must be positive"
    );
    Ok(())
  }
}

impl JournalOperation {
  pub fn lease_guard(&self) -> Option<LeaseGuard> {
    Some(LeaseGuard {
      operation_id: self.operation_id.clone(),
      worker_id: self.owner_worker_id.clone()?,
      boot_id: self.owner_boot_id.clone()?,
      lease_epoch: self.lease_epoch,
      expected_revision: self.revision,
    })
  }

  /// Expected terminal revision when startup recovery must pass through the
  /// cancellation-requested state before recording an indeterminate receipt.
  pub fn incomplete_terminal_revision(&self) -> u64 {
    self.revision.saturating_add(
      if matches!(
        self.state,
        AdminOperationState::Accepted | AdminOperationState::Queued | AdminOperationState::Claimed
      ) {
        2
      } else {
        1
      },
    )
  }
}

pub(super) fn validate_text(name: &str, value: &str, maximum: usize) -> anyhow::Result<()> {
  ensure!(!value.is_empty(), "{name} must not be empty");
  ensure!(value.len() <= maximum, "{name} exceeds {maximum} bytes");
  ensure!(
    value
      .bytes()
      .all(|byte| byte.is_ascii_graphic() || byte == b' '),
    "{name} contains control characters"
  );
  Ok(())
}

pub(super) fn validate_event(event: &str) -> anyhow::Result<()> {
  validate_text("operation event", event, 128)
}

pub(super) fn validate_json(name: &str, value: &Value, maximum: usize) -> anyhow::Result<()> {
  ensure!(
    serde_json::to_vec(value)?.len() <= maximum,
    "{name} exceeds its persisted size limit"
  );
  Ok(())
}

pub(super) fn legal_transition(from: AdminOperationState, next: AdminOperationState) -> bool {
  crate::server::admin_operations::state_machine::validate_admin_operation_transition(from, next)
    .is_ok()
}

pub(super) fn classify_existing(
  existing: JournalOperation,
  operation: &NewJournalOperation,
) -> InsertOutcome {
  if existing.request_fingerprint == operation.request_fingerprint
    && existing.kind == operation.kind
    && existing.schema_version == operation.schema_version
  {
    InsertOutcome::Replay(existing)
  } else {
    InsertOutcome::Conflict(existing)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn operation() -> NewJournalOperation {
    NewJournalOperation {
      operation_id: "op_00000000-0000-4000-8000-000000000001".to_string(),
      actor: "admin".to_string(),
      request_id: "request-1".to_string(),
      submitter_worker_id: "worker-a".to_string(),
      submitter_boot_id: "worker-a-boot".to_string(),
      principal: "spiffe://example.test/admin".to_string(),
      permission_action: "operations.write".to_string(),
      redacted_resource: None,
      resource_digest: crate::server::admin_operations::artifact::sha256_digest(b"resource"),
      idempotency_key_digest: None,
      request_fingerprint: crate::server::admin_operations::artifact::sha256_digest(b"request"),
      kind: AdminOperationKind::SupportBundle,
      schema_version: 1,
      recovery_class: AdminOperationRecoveryClass::Restartable,
      progress: None,
      maximum_lifetime_seconds: 3600,
      retention_seconds: 3600,
    }
  }

  #[test]
  fn durable_identity_and_digest_validation_fail_closed() {
    operation().validate().expect("valid operation");
    let mut invalid = operation();
    invalid.operation_id = "op_not-a-uuid".to_string();
    assert!(invalid.validate().is_err());
    let mut raw_key = operation();
    raw_key.idempotency_key_digest = Some("raw-idempotency-key".to_string());
    assert!(raw_key.validate().is_err());
    let mut unbounded = operation();
    unbounded.maximum_lifetime_seconds = 2_592_001;
    assert!(unbounded.validate().is_err());
  }
}
