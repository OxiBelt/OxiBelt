//! Request, response, stream, and system-access-log phase orchestration.

use super::*;

impl WafEngine {
  pub fn evaluate_response(&self, input: WafResponseInput<'_>) -> ResponseWafDecision {
    if !self.enabled
      || !self
        .route_plan(input.request.route_name)
        .response()
        .enabled()
    {
      return ResponseWafDecision::default();
    }

    match self.evaluate_response_inner(input) {
      Ok(decision) => decision,
      Err(error) => match self.fail_policy {
        WafFailPolicy::Open => {
          warn!(error = %error, "WAF response evaluation failed open");
          ResponseWafDecision::default()
        }
        WafFailPolicy::Closed => {
          warn!(error = %error, "WAF response evaluation failed closed");
          ResponseWafDecision {
            terminal: Some(WafHttpTerminal::response(
              StatusCode::FORBIDDEN,
              "WAF evaluation failed".to_string(),
            )),
            ..ResponseWafDecision::default()
          }
        }
      },
    }
  }

  pub fn evaluate_stream(&self, input: WafStreamInput<'_>) -> WafStreamDecision {
    if !self.enabled || !self.route_plan(input.request.route_name).stream().enabled() {
      return WafStreamDecision::default();
    }

    match self.evaluate_stream_inner(input) {
      Ok(decision) => decision,
      Err(error) => match self.fail_policy {
        WafFailPolicy::Open => {
          warn!(error = %error, "WAF stream evaluation failed open");
          WafStreamDecision::default()
        }
        WafFailPolicy::Closed => {
          warn!(error = %error, "WAF stream evaluation failed closed");
          WafStreamDecision {
            close: Some(WafStreamClose::default()),
            ..WafStreamDecision::default()
          }
        }
      },
    }
  }

  pub fn build_system_access_log(
    &self,
    fields: &CompiledAccessLogFields,
    input: WafResponseInput<'_>,
  ) -> anyhow::Result<AccessLogRecord> {
    let person_proof = self.person_proof.evaluate_request(input.request);
    self.build_system_access_log_with_person_proof(fields, input, &person_proof)
  }

  pub(super) fn build_system_access_log_with_person_proof(
    &self,
    fields: &CompiledAccessLogFields,
    input: WafResponseInput<'_>,
    person_proof: &PersonProofRequestStatus,
  ) -> anyhow::Result<AccessLogRecord> {
    let mut tx = TransactionBudget::new(&self.limits);
    let body_text_caches = BodyTextCaches::default();
    let ctx = EvalContext {
      phase: WafPhase::Response,
      mode: self.mode,
      rule_name: "",
      rule_id: None,
      rule_tags: &[],
      request: input.request,
      response: Some(input),
      stream: None,
      person_proof,
      pattern_sets: &self.pattern_sets,
      regex_cache: None,
      locals: &[],
      limits: &self.limits,
      duplicate_metadata_policy: self.duplicate_metadata_policy,
      body_text_caches: &body_text_caches,
    };
    AccessLogRecord::from_fields(&fields.fields, &ctx, &mut tx, "system")
  }

  pub(super) fn evaluate_request_inner(
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
    let body_text_caches = BodyTextCaches::default();
    for rule in self.route_plan(input.route_name).request().rules() {
      tx.check_total()?;
      let mut rule_person_proof = self.person_proof_status_for_rule(&person_proof, rule);
      active_person_proof.apply_to(&mut rule_person_proof);
      let matched = {
        let request = WafRequestInput {
          tags: &active_tags,
          ..input
        };
        let ctx = EvalContext {
          phase: WafPhase::Request,
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
        let action_ctx = EvalContext {
          phase: WafPhase::Request,
          mode: rule.mode,
          rule_name: &rule.name,
          rule_id: rule.id.as_deref(),
          rule_tags: &rule.tags,
          request,
          response: None,
          stream: None,
          person_proof: &rule_person_proof,
          pattern_sets: &self.pattern_sets,
          regex_cache: Some(&rule.regex_cache),
          locals: &[],
          limits: &self.limits,
          duplicate_metadata_policy: self.duplicate_metadata_policy,
          body_text_caches: &body_text_caches,
        };
        active_person_proof = apply_request_actions(
          rule,
          RequestActionContext {
            input: request,
            eval: &action_ctx,
            person_proof: &self.person_proof,
            rate_limits: &self.rate_limits,
            mitigation: &self.mitigation,
          },
          &mut decision,
          &mut tx,
        )?;
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

  pub(super) fn evaluate_response_inner(
    &self,
    input: WafResponseInput<'_>,
  ) -> anyhow::Result<ResponseWafDecision> {
    let person_proof = self.person_proof.evaluate_request(input.request);
    self.evaluate_response_inner_with_person_proof(input, &person_proof)
  }

  pub(super) fn evaluate_response_inner_with_person_proof(
    &self,
    input: WafResponseInput<'_>,
    person_proof: &PersonProofRequestStatus,
  ) -> anyhow::Result<ResponseWafDecision> {
    let mut decision = ResponseWafDecision::default();
    let mut tx = TransactionBudget::new(&self.limits);
    let body_text_caches = BodyTextCaches::default();

    for rule in self.route_plan(input.request.route_name).response().rules() {
      tx.check_total()?;
      let ctx = EvalContext {
        phase: WafPhase::Response,
        mode: rule.mode,
        rule_name: "",
        rule_id: None,
        rule_tags: &[],
        request: input.request,
        response: Some(input),
        stream: None,
        person_proof,
        pattern_sets: &self.pattern_sets,
        regex_cache: None,
        locals: &[],
        limits: &self.limits,
        duplicate_metadata_policy: self.duplicate_metadata_policy,
        body_text_caches: &body_text_caches,
      };
      let matched = self.evaluate_rule(rule, &ctx, &mut tx)?;
      if !matched {
        continue;
      }
      rule.record_hit();
      debug!(
        rule = %rule.name,
        rule_id = rule.id.as_deref().unwrap_or_default(),
        internal_rule_id = %rule.internal_id,
        mode = rule.mode.as_str(),
        phase = "response",
        "WAF rule matched"
      );
      if rule.mode == WafMode::Monitor {
        continue;
      }
      apply_response_actions(rule, &ctx, input, &self.mitigation, &mut decision, &mut tx)?;
      if decision.terminal.is_some() {
        return Ok(decision);
      }
    }

    apply_crs_response_decision(self.crs.evaluate_response(input)?, &mut decision);
    if decision.terminal.is_some() {
      return Ok(decision);
    }

    Ok(decision)
  }

  pub(super) fn evaluate_stream_inner(
    &self,
    input: WafStreamInput<'_>,
  ) -> anyhow::Result<WafStreamDecision> {
    let person_proof = self.person_proof.evaluate_request(input.request);
    self.evaluate_stream_inner_with_person_proof(input, &person_proof)
  }

  pub(super) fn evaluate_stream_inner_with_person_proof(
    &self,
    input: WafStreamInput<'_>,
    person_proof: &PersonProofRequestStatus,
  ) -> anyhow::Result<WafStreamDecision> {
    let mut decision = WafStreamDecision::default();
    let mut tx = TransactionBudget::new(&self.limits);
    let body_text_caches = BodyTextCaches::default();

    for rule in self.route_plan(input.request.route_name).stream().rules() {
      tx.check_total()?;
      let ctx = EvalContext {
        phase: WafPhase::Stream,
        mode: rule.mode,
        rule_name: "",
        rule_id: None,
        rule_tags: &[],
        request: input.request,
        response: None,
        stream: Some(input),
        person_proof,
        pattern_sets: &self.pattern_sets,
        regex_cache: None,
        locals: &[],
        limits: &self.limits,
        duplicate_metadata_policy: self.duplicate_metadata_policy,
        body_text_caches: &body_text_caches,
      };
      let matched = self.evaluate_rule(rule, &ctx, &mut tx)?;
      if !matched {
        continue;
      }
      rule.record_hit();
      debug!(
        rule = %rule.name,
        rule_id = rule.id.as_deref().unwrap_or_default(),
        internal_rule_id = %rule.internal_id,
        mode = rule.mode.as_str(),
        phase = "stream",
        "WAF rule matched"
      );
      if rule.mode == WafMode::Monitor {
        continue;
      }
      apply_stream_actions(rule, &ctx, input, &self.mitigation, &mut decision, &mut tx)?;
      if decision.close.is_some() {
        return Ok(decision);
      }
    }

    Ok(decision)
  }

  pub(super) fn active_hit_counters(&self) -> HashMap<WafRuleHitKey, Arc<AtomicU64>> {
    self
      .global_rules
      .iter()
      .chain(self.route_rules.values().flat_map(|rules| rules.iter()))
      .map(|rule| (rule.hit_key.clone(), rule.hit_counter.clone()))
      .collect()
  }

  pub(super) fn evaluate_rule(
    &self,
    rule: &CompiledRule,
    ctx: &EvalContext<'_>,
    tx: &mut TransactionBudget,
  ) -> anyhow::Result<bool> {
    tx.start_rule();
    let rule_ctx = EvalContext {
      rule_name: &rule.name,
      rule_id: rule.id.as_deref(),
      rule_tags: &rule.tags,
      regex_cache: Some(&rule.regex_cache),
      locals: &[],
      ..*ctx
    };
    let started_at = Instant::now();
    let value = rule.expression.eval(&rule_ctx, tx);
    rule.record_eval(started_at.elapsed());
    let value = value?;
    value
      .as_bool()
      .with_context(|| format!("WAF rule {} expression did not evaluate to Bool", rule.name))
  }

  pub(super) fn person_proof_status_for_rule(
    &self,
    global_status: &PersonProofRequestStatus,
    rule: &CompiledRule,
  ) -> PersonProofRequestStatus {
    if rule.person_proof_policies.is_empty() {
      return global_status.clone();
    }
    if let Some(policy_key) = global_status.policy_key.as_deref()
      && rule
        .person_proof_policies
        .iter()
        .any(|policy| policy.key == policy_key)
    {
      return global_status.clone();
    }
    PersonProofRequestStatus::default()
  }
}
