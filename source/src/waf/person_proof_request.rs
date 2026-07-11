//! Request-scoped Person proof evaluation helpers.

use anyhow::bail;
use http::{HeaderName, HeaderValue, StatusCode};
use tracing::{debug, warn};

use super::{
  BodyTextCaches, CompiledAction, CompiledRule, EvalContext, HeaderMutation, LimitMode,
  PersonProofPolicyState, PersonProofRequestStatus, PersonProofState, RateLimitCheck,
  RateLimitContext, RequestWafDecision, TransactionBudget, WafActionConfig,
  WafDuplicateMetadataPolicy, WafEngine, WafFailPolicy, WafHttpTerminal, WafMode, WafRequestInput,
  apply_crs_request_decision, apply_mitigation_http_action, person_proof_dynamic,
  person_proof_rate_limited_decision, record_request_tag, request_metadata_has_duplicates,
};

#[derive(Debug, Clone)]
pub struct EvaluatedPersonProofRequest {
  pub(super) status: PersonProofRequestStatus,
}

impl EvaluatedPersonProofRequest {
  pub fn clearance_hash(&self) -> Option<&str> {
    self.status.clearance_hash.as_deref()
  }

  /// Return the request-scoped decision data that later WAF phases may reuse.
  ///
  /// Issued clearances contain a bearer token and response metadata.  They are
  /// intentionally retained only by the request phase that may emit the
  /// mutation; response, stream, and logging phases must not keep them.
  pub fn sanitized(&self) -> PersonProofRequestSnapshot {
    let mut status = self.status.clone();
    status.clearance = None;
    PersonProofRequestSnapshot { status }
  }
}

/// Sanitized request-scoped Person proof decision for later WAF phases.
///
/// This preserves decision fields and the irreversible clearance hash without
/// retaining the raw clearance token, response header, or provider metadata.
#[derive(Debug, Clone)]
pub struct PersonProofRequestSnapshot {
  pub(super) status: PersonProofRequestStatus,
}

impl PersonProofRequestSnapshot {
  pub fn clearance_hash(&self) -> Option<&str> {
    self.status.clearance_hash.as_deref()
  }
}

impl WafEngine {
  pub async fn evaluate_person_proof_request_async(
    &self,
    input: WafRequestInput<'_>,
  ) -> EvaluatedPersonProofRequest {
    EvaluatedPersonProofRequest {
      status: self.person_proof.evaluate_request_async(input).await,
    }
  }

  pub fn evaluate_dynamic_person_proof_challenge(
    &self,
    input: WafRequestInput<'_>,
    status: StatusCode,
  ) -> anyhow::Result<RequestWafDecision> {
    let mut evaluated = None;
    self.evaluate_dynamic_person_proof_challenge_with_status(input, status, &mut evaluated)
  }

  /// Async dynamic-challenge evaluation for request paths backed by shared
  /// Person proof state.
  pub async fn evaluate_dynamic_person_proof_challenge_with_status_async(
    &self,
    input: WafRequestInput<'_>,
    status: StatusCode,
    evaluated: &mut Option<EvaluatedPersonProofRequest>,
  ) -> anyhow::Result<RequestWafDecision> {
    if evaluated.is_none() {
      *evaluated = Some(self.evaluate_person_proof_request_async(input).await);
    }
    self.evaluate_dynamic_person_proof_challenge_with_evaluated(
      input,
      status,
      evaluated
        .as_ref()
        .expect("person proof status was initialized"),
    )
  }

  pub fn evaluate_dynamic_person_proof_challenge_with_status(
    &self,
    input: WafRequestInput<'_>,
    status: StatusCode,
    evaluated: &mut Option<EvaluatedPersonProofRequest>,
  ) -> anyhow::Result<RequestWafDecision> {
    if evaluated.is_none() {
      *evaluated = Some(self.evaluate_person_proof_request(input));
    }
    self.evaluate_dynamic_person_proof_challenge_with_evaluated(
      input,
      status,
      evaluated
        .as_ref()
        .expect("person proof status was initialized"),
    )
  }

  fn evaluate_dynamic_person_proof_challenge_with_evaluated(
    &self,
    input: WafRequestInput<'_>,
    status: StatusCode,
    evaluated: &EvaluatedPersonProofRequest,
  ) -> anyhow::Result<RequestWafDecision> {
    let person_proof = &evaluated.status;
    let mut decision = RequestWafDecision::default();
    if person_proof.rate_limited {
      return Ok(person_proof_rate_limited_decision());
    }
    let policy = person_proof_dynamic::challenge_policy(&self.person_proof, status)?;
    if person_proof.state == PersonProofState::Valid
      && person_proof.policy_key.as_deref() == Some(policy.key.as_str())
    {
      let mutation = self
        .person_proof
        .clearance_response_mutation(person_proof)?;
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

  pub async fn evaluate_request_async(&self, input: WafRequestInput<'_>) -> RequestWafDecision {
    let evaluated = self.evaluate_person_proof_request_async(input).await;
    self
      .evaluate_request_with_person_proof_async(input, Some(&evaluated), false)
      .await
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

impl WafEngine {
  /// Async request evaluation for routes whose rate-limit or Person proof
  /// state is shared across instances.
  pub async fn evaluate_request_with_person_proof_async(
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
    match self
      .evaluate_request_inner_async(
        input,
        evaluated.map(|status| &status.status),
        suppress_clearance_mutation,
      )
      .await
    {
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

  async fn evaluate_request_inner_async(
    &self,
    input: WafRequestInput<'_>,
    evaluated_person_proof: Option<&PersonProofRequestStatus>,
    suppress_clearance_mutation: bool,
  ) -> anyhow::Result<RequestWafDecision> {
    let mut decision = RequestWafDecision::default();
    let mut active_tags = input.tags.to_owned();
    let person_proof = evaluated_person_proof
      .cloned()
      .unwrap_or_else(|| self.person_proof.evaluate_request(input));
    if person_proof.rate_limited {
      return Ok(person_proof_rate_limited_decision());
    }
    if let Some(tag) = self.person_proof.success_tag_for(&person_proof) {
      record_request_tag(
        &mut decision,
        &mut active_tags,
        tag.to_string(),
        "valid".to_string(),
      );
    }
    if !suppress_clearance_mutation
      && let Some(mutation) = self
        .person_proof
        .clearance_response_mutation(&person_proof)?
    {
      decision.response_header_mutations.push(mutation);
    }

    let mut active_person_proof = PersonProofPolicyState::default();
    let mut tx = TransactionBudget::new(&self.limits);
    for rule in self.route_plan(input.route_name).request().rules() {
      tx.check_total()?;
      let mut rule_person_proof = self.person_proof_status_for_rule(&person_proof, rule);
      active_person_proof.apply_to(&mut rule_person_proof);
      let matched = {
        let body_text_caches = BodyTextCaches::default();
        let request = WafRequestInput {
          tags: &active_tags,
          ..input
        };
        let ctx = EvalContext {
          phase: super::WafPhase::Request,
          mode: rule.mode,
          rule_name: "",
          rule_id: None,
          rule_tags: &[],
          request,
          response: None,
          stream: None,
          person_proof: &rule_person_proof,
          pattern_sets: &self.pattern_sets,
          regex_cache: None,
          locals: &[],
          limits: &self.limits,
          duplicate_metadata_policy: self.duplicate_metadata_policy,
          body_text_caches: &body_text_caches,
        };
        self.evaluate_rule(rule, &ctx, &mut tx)?
      };
      if !matched {
        continue;
      }
      rule.record_hit();
      debug!(
        rule = %rule.name,
        rule_id = rule.id.as_deref().unwrap_or_default(),
        internal_rule_id = %rule.internal_id,
        mode = rule.mode.as_str(),
        phase = "request",
        "WAF rule matched"
      );
      if rule.mode == WafMode::Monitor {
        continue;
      }
      let previous_tag_count = decision.tags.len();
      {
        let request = WafRequestInput {
          tags: &active_tags,
          ..input
        };
        active_person_proof = self
          .apply_request_actions_async(rule, request, &rule_person_proof, &mut decision, &mut tx)
          .await?;
      }
      for (key, value) in &decision.tags[previous_tag_count..] {
        active_tags.insert(key.clone(), value.clone());
      }
      if decision.terminal.is_some() {
        return Ok(decision);
      }
    }

    let request = WafRequestInput {
      tags: &active_tags,
      ..input
    };
    apply_crs_request_decision(self.crs.evaluate_request(request)?, &mut decision);
    if decision.terminal.is_some() {
      return Ok(decision);
    }

    Ok(decision)
  }
}

impl WafEngine {
  async fn apply_request_actions_async(
    &self,
    rule: &CompiledRule,
    input: WafRequestInput<'_>,
    rule_person_proof: &PersonProofRequestStatus,
    decision: &mut RequestWafDecision,
    tx: &mut TransactionBudget<'_>,
  ) -> anyhow::Result<PersonProofPolicyState> {
    let mut person_proof_policy = PersonProofPolicyState::from_status(rule_person_proof);
    for action in &rule.actions {
      tx.count_mutation()?;
      match action {
        CompiledAction::Config(WafActionConfig::Reject { status, body, .. }) => {
          decision.terminal = Some(WafHttpTerminal::response(
            StatusCode::from_u16(*status)?,
            body.clone().unwrap_or_else(|| "Blocked by WAF".to_string()),
          ));
          return Ok(person_proof_policy);
        }
        CompiledAction::Config(WafActionConfig::SilentClose { .. }) => {
          decision.terminal = Some(WafHttpTerminal::SilentClose);
          return Ok(person_proof_policy);
        }
        CompiledAction::Config(WafActionConfig::SetRequestHeader { name, value, .. }) => {
          let name = HeaderName::from_bytes(name.as_bytes())?;
          super::request_header_mutation::ensure_allowed(&rule.name, "set_request_header", &name)?;
          decision.request_header_mutations.push(HeaderMutation::Set {
            name,
            value: HeaderValue::from_str(value)?,
          });
        }
        CompiledAction::Config(WafActionConfig::RemoveRequestHeader { name, .. }) => {
          let name = HeaderName::from_bytes(name.as_bytes())?;
          super::request_header_mutation::ensure_allowed(
            &rule.name,
            "remove_request_header",
            &name,
          )?;
          decision
            .request_header_mutations
            .push(HeaderMutation::Remove { name });
        }
        CompiledAction::Config(WafActionConfig::SetTag { key, value, .. }) => {
          decision.tags.push((key.clone(), value.clone()));
        }
        CompiledAction::Config(WafActionConfig::RouteToUpstream { upstream, .. }) => {
          decision.upstream_override = Some(upstream.clone());
        }
        CompiledAction::Config(WafActionConfig::RouteToPool { pool, .. }) => {
          decision.upstream_pool_override = Some(pool.clone());
        }
        CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { policy, .. }) => {
          decision.load_balancing_policy = Some(policy.clone());
        }
        CompiledAction::Config(WafActionConfig::RateLimit {
          name,
          key,
          ipv4_prefix_bits,
          ipv6_prefix_bits,
          identity_parts,
          token_bindings,
          token_header,
          access_token_source,
          rate,
          burst,
          max_buckets,
          status,
          body,
          ..
        }) => {
          let context = RateLimitContext::route(
            input.peer_addr.ip(),
            input.route_name,
            input.uri.path(),
            input.headers,
          )
          .with_tls_fingerprint(input.tls.fingerprint.as_deref())
          .with_client_asn(input.client_asn)
          .with_tcp_max_hop(input.tcp_max_hop)
          .with_person_proof_clearance_hash(rule_person_proof.clearance_hash.as_deref());
          let check = RateLimitCheck {
            name,
            key: *key,
            token_header: token_header.as_deref(),
            access_token_source: *access_token_source,
            ipv4_prefix_bits: *ipv4_prefix_bits,
            ipv6_prefix_bits: *ipv6_prefix_bits,
            identity_parts,
            token_bindings,
            rate,
            burst: *burst,
            max_buckets: *max_buckets,
            mode: LimitMode::Enforcing,
            status: *status,
          };
          if let Some(status) = self
            .rate_limits
            .check_rate_limit_async(context, check)
            .await
          {
            decision.terminal = Some(WafHttpTerminal::response(
              status,
              body
                .clone()
                .unwrap_or_else(|| "rate limit exceeded".to_string()),
            ));
            return Ok(person_proof_policy);
          }
        }
        CompiledAction::Config(WafActionConfig::WeighPersonProof { weight, .. }) => {
          person_proof_policy.add_weight(*weight);
        }
        CompiledAction::Config(WafActionConfig::AllowPersonProof { .. }) => {
          person_proof_policy.allow();
        }
        CompiledAction::RequirePersonProof(policy) => {
          if person_proof_policy.challenge_suppressed(rule_person_proof) {
            continue;
          }
          decision.terminal = Some(
            self
              .person_proof
              .issue_challenge(input, policy.clone())?
              .into(),
          );
          return Ok(person_proof_policy);
        }
        CompiledAction::EmitMitigation(action) => {
          let body_text_caches = BodyTextCaches::default();
          let action_ctx = EvalContext {
            phase: super::WafPhase::Request,
            mode: rule.mode,
            rule_name: &rule.name,
            rule_id: rule.id.as_deref(),
            rule_tags: &rule.tags,
            request: input,
            response: None,
            stream: None,
            person_proof: rule_person_proof,
            pattern_sets: &self.pattern_sets,
            regex_cache: Some(&rule.regex_cache),
            locals: &[],
            limits: &self.limits,
            duplicate_metadata_policy: self.duplicate_metadata_policy,
            body_text_caches: &body_text_caches,
          };
          if let Some(terminal) =
            apply_mitigation_http_action(action, rule, &action_ctx, None, &self.mitigation, tx)?
          {
            decision.terminal = Some(terminal.into());
            return Ok(person_proof_policy);
          }
        }
        CompiledAction::Config(WafActionConfig::ContinueResponse { .. })
        | CompiledAction::Config(WafActionConfig::ReplaceResponse { .. })
        | CompiledAction::Config(WafActionConfig::RejectResponse { .. })
        | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. })
        | CompiledAction::Config(WafActionConfig::EmitMitigation { .. })
        | CompiledAction::Config(WafActionConfig::SetResponseHeader { .. })
        | CompiledAction::Config(WafActionConfig::RemoveResponseHeader { .. })
        | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
        | CompiledAction::Config(WafActionConfig::CloseStream { .. })
        | CompiledAction::EmitAccessLog { .. } => {
          bail!("invalid request-phase WAF action in rule {}", rule.name);
        }
      }
    }
    Ok(person_proof_policy)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sanitized_snapshot_preserves_decision_without_clearance_secrets() {
    let evaluated = EvaluatedPersonProofRequest {
      status: PersonProofRequestStatus {
        state: PersonProofState::Valid,
        mode: Some("built-in"),
        difficulty: Some(4),
        issued_at_unix_ms: Some(1),
        expires_at_unix_ms: Some(2),
        policy_key: Some("default".to_string()),
        rate_limited: false,
        weight: 3,
        allowed: true,
        clearance_hash: Some("sha256:clearance".to_string()),
        clearance: Some(crate::waf::PersonProofIssuedClearance {
          token: "clearance.v2.secret".to_string(),
          expires_unix_ms: 2,
          max_age_seconds: 60,
          response_header: None,
          metadata: serde_json::json!({"provider_token": "secret"}),
        }),
      },
    };

    let snapshot = evaluated.sanitized();

    assert_eq!(snapshot.clearance_hash(), Some("sha256:clearance"));
    assert!(snapshot.status.clearance.is_none());
    assert_eq!(
      evaluated
        .status
        .clearance
        .as_ref()
        .map(|clearance| clearance.token.as_str()),
      Some("clearance.v2.secret")
    );
  }
}
