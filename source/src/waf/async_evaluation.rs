//! Async wrappers for WAF phases that consult shared Person proof state.

use tracing::warn;

use super::{
  AccessLogRecord, CompiledAccessLogFields, PersonProofRequestSnapshot, ResponseWafDecision,
  WafEngine, WafHttpTerminal, WafResponseInput, WafStreamClose, WafStreamDecision, WafStreamInput,
};

impl WafEngine {
  pub async fn evaluate_response_async(&self, input: WafResponseInput<'_>) -> ResponseWafDecision {
    if !self.enabled
      || !self
        .route_plan(input.request.route_name)
        .response()
        .enabled()
    {
      return ResponseWafDecision::default();
    }
    let person_proof = self
      .evaluate_person_proof_request_async(input.request)
      .await;
    self.evaluate_response_with_person_proof_snapshot(input, &person_proof.sanitized())
  }

  /// Evaluate a response without consulting Person proof state again.
  pub fn evaluate_response_with_person_proof_snapshot(
    &self,
    input: WafResponseInput<'_>,
    person_proof: &PersonProofRequestSnapshot,
  ) -> ResponseWafDecision {
    if !self.enabled
      || !self
        .route_plan(input.request.route_name)
        .response()
        .enabled()
    {
      return ResponseWafDecision::default();
    }

    match self.evaluate_response_inner_with_person_proof(input, &person_proof.status) {
      Ok(decision) => decision,
      Err(error) if self.should_fail_open(&error) => {
        warn!(error = %error, "WAF response evaluation failed open");
        ResponseWafDecision::default()
      }
      Err(error) => {
        warn!(error = %error, "WAF response evaluation failed closed");
        ResponseWafDecision {
          terminal: Some(WafHttpTerminal::response(
            http::StatusCode::FORBIDDEN,
            "WAF evaluation failed".to_string(),
          )),
          ..ResponseWafDecision::default()
        }
      }
    }
  }

  pub async fn evaluate_stream_async(&self, input: WafStreamInput<'_>) -> WafStreamDecision {
    if !self.enabled || !self.route_plan(input.request.route_name).stream().enabled() {
      return WafStreamDecision::default();
    }
    let person_proof = self
      .evaluate_person_proof_request_async(input.request)
      .await;
    self.evaluate_stream_with_person_proof_snapshot(input, &person_proof.sanitized())
  }

  /// Evaluate a stream unit with the request's already-resolved Person proof
  /// decision.  This keeps backend I/O out of payload-retaining frame loops.
  pub fn evaluate_stream_with_person_proof_snapshot(
    &self,
    input: WafStreamInput<'_>,
    person_proof: &PersonProofRequestSnapshot,
  ) -> WafStreamDecision {
    if !self.enabled || !self.route_plan(input.request.route_name).stream().enabled() {
      return WafStreamDecision::default();
    }

    match self.evaluate_stream_inner_with_person_proof(input, &person_proof.status) {
      Ok(decision) => decision,
      Err(error) if self.should_fail_open(&error) => {
        warn!(error = %error, "WAF stream evaluation failed open");
        WafStreamDecision::default()
      }
      Err(error) => {
        warn!(error = %error, "WAF stream evaluation failed closed");
        WafStreamDecision {
          close: Some(WafStreamClose::default()),
          ..WafStreamDecision::default()
        }
      }
    }
  }

  pub async fn build_system_access_log_async(
    &self,
    fields: &CompiledAccessLogFields,
    input: WafResponseInput<'_>,
  ) -> anyhow::Result<AccessLogRecord> {
    let person_proof = self
      .evaluate_person_proof_request_async(input.request)
      .await;
    self.build_system_access_log_with_person_proof_snapshot(
      fields,
      input,
      &person_proof.sanitized(),
    )
  }

  /// Build a system access-log record using a sanitized request snapshot.
  pub fn build_system_access_log_with_person_proof_snapshot(
    &self,
    fields: &CompiledAccessLogFields,
    input: WafResponseInput<'_>,
    person_proof: &PersonProofRequestSnapshot,
  ) -> anyhow::Result<AccessLogRecord> {
    self.build_system_access_log_with_person_proof(fields, input, &person_proof.status)
  }
}
