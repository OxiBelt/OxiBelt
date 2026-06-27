//! Request-scoped Person proof evaluation helpers.

use http::StatusCode;
use tracing::warn;

use super::{
  HeaderMutation, PersonProofRequestStatus, PersonProofState, RequestWafDecision,
  WafDuplicateMetadataPolicy, WafEngine, WafFailPolicy, WafHttpTerminal, WafRequestInput,
  person_proof_dynamic, person_proof_rate_limited_decision, request_metadata_has_duplicates,
};

#[derive(Debug, Clone)]
pub struct EvaluatedPersonProofRequest {
  pub(super) status: PersonProofRequestStatus,
}

impl EvaluatedPersonProofRequest {
  pub fn clearance_hash(&self) -> Option<&str> {
    self.status.clearance_hash.as_deref()
  }
}

impl WafEngine {
  pub fn evaluate_dynamic_person_proof_challenge(
    &self,
    input: WafRequestInput<'_>,
    status: StatusCode,
  ) -> anyhow::Result<RequestWafDecision> {
    let mut evaluated = None;
    self.evaluate_dynamic_person_proof_challenge_with_status(input, status, &mut evaluated)
  }

  pub fn evaluate_dynamic_person_proof_challenge_with_status(
    &self,
    input: WafRequestInput<'_>,
    status: StatusCode,
    evaluated: &mut Option<EvaluatedPersonProofRequest>,
  ) -> anyhow::Result<RequestWafDecision> {
    let mut decision = RequestWafDecision::default();
    if evaluated.is_none() {
      *evaluated = Some(self.evaluate_person_proof_request(input));
    }
    let person_proof = evaluated
      .as_ref()
      .expect("person proof status was initialized")
      .status
      .clone();
    if person_proof.rate_limited {
      return Ok(person_proof_rate_limited_decision());
    }
    let policy = person_proof_dynamic::challenge_policy(&self.person_proof, status)?;
    if person_proof.state == PersonProofState::Valid
      && person_proof.policy_key.as_deref() == Some(policy.key.as_str())
    {
      let mutation = self
        .person_proof
        .clearance_response_mutation(&person_proof)?;
      decision.response_header_mutations.extend(mutation);
      return Ok(decision);
    }
    decision.terminal = Some(self.person_proof.issue_challenge(input, policy)?.into());
    Ok(decision)
  }

  pub fn evaluate_person_proof_request(
    &self,
    input: WafRequestInput<'_>,
  ) -> EvaluatedPersonProofRequest {
    EvaluatedPersonProofRequest {
      status: self.person_proof.evaluate_request(input),
    }
  }

  pub fn person_proof_clearance_response_mutation(
    &self,
    evaluated: &EvaluatedPersonProofRequest,
  ) -> anyhow::Result<Option<HeaderMutation>> {
    self
      .person_proof
      .clearance_response_mutation(&evaluated.status)
  }

  pub fn evaluate_request(&self, input: WafRequestInput<'_>) -> RequestWafDecision {
    self.evaluate_request_with_person_proof(input, None, false)
  }

  pub fn evaluate_request_with_person_proof(
    &self,
    input: WafRequestInput<'_>,
    evaluated: Option<&EvaluatedPersonProofRequest>,
    suppress_clearance_mutation: bool,
  ) -> RequestWafDecision {
    if !self.enabled || !self.route_plan(input.route_name).request().enabled() {
      return RequestWafDecision::default();
    }
    if self.duplicate_metadata_policy == WafDuplicateMetadataPolicy::RejectRequest
      && request_metadata_has_duplicates(input)
    {
      return RequestWafDecision {
        terminal: Some(WafHttpTerminal::response(
          StatusCode::BAD_REQUEST,
          "duplicate request metadata".to_string(),
        )),
        ..RequestWafDecision::default()
      };
    }
    match self.evaluate_request_inner(
      input,
      evaluated.map(|status| &status.status),
      suppress_clearance_mutation,
    ) {
      Ok(decision) => decision,
      Err(error) => match self.fail_policy {
        WafFailPolicy::Open => {
          warn!(error = %error, "WAF request evaluation failed open");
          RequestWafDecision::default()
        }
        WafFailPolicy::Closed => {
          warn!(error = %error, "WAF request evaluation failed closed");
          RequestWafDecision {
            terminal: Some(WafHttpTerminal::response(
              StatusCode::FORBIDDEN,
              "WAF evaluation failed".to_string(),
            )),
            ..RequestWafDecision::default()
          }
        }
      },
    }
  }
}
