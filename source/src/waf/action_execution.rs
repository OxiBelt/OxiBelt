//! Request, response, and stream action execution.

use super::*;

pub(super) struct RequestActionContext<'a, 'ctx> {
  pub(super) input: WafRequestInput<'a>,
  pub(super) eval: &'ctx EvalContext<'a>,
  pub(super) person_proof: &'ctx PersonProofEngine,
  pub(super) rate_limits: &'ctx LimitState,
  pub(super) mitigation: &'ctx MitigationSink,
}

pub(super) fn apply_request_actions(
  rule: &CompiledRule,
  action_ctx: RequestActionContext<'_, '_>,
  decision: &mut RequestWafDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<PersonProofPolicyState> {
  let input = action_ctx.input;
  let ctx = action_ctx.eval;
  let person_proof = action_ctx.person_proof;
  let rate_limits = action_ctx.rate_limits;
  let mitigation = action_ctx.mitigation;
  let mut person_proof_policy = PersonProofPolicyState::from_status(ctx.person_proof);
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
        request_header_mutation::ensure_allowed(&rule.name, "set_request_header", &name)?;
        decision.request_header_mutations.push(HeaderMutation::Set {
          name,
          value: HeaderValue::from_str(value)?,
        });
      }
      CompiledAction::Config(WafActionConfig::RemoveRequestHeader { name, .. }) => {
        let name = HeaderName::from_bytes(name.as_bytes())?;
        request_header_mutation::ensure_allowed(&rule.name, "remove_request_header", &name)?;
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
        .with_person_proof_clearance_hash(ctx.person_proof.clearance_hash.as_deref());
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
        if let Some(status) = rate_limits.check_rate_limit_local(context, check) {
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
        if person_proof_policy.challenge_suppressed(ctx.person_proof) {
          continue;
        }
        decision.terminal = Some(person_proof.issue_challenge(input, policy.clone())?.into());
        return Ok(person_proof_policy);
      }
      CompiledAction::EmitMitigation(action) => {
        if let Some(terminal) =
          apply_mitigation_http_action(action, rule, ctx, None, mitigation, tx)?
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

pub(super) fn apply_response_actions(
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  input: WafResponseInput<'_>,
  mitigation: &MitigationSink,
  decision: &mut ResponseWafDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<()> {
  for action in &rule.actions {
    tx.count_mutation()?;
    match action {
      CompiledAction::Config(WafActionConfig::ContinueResponse { .. }) => return Ok(()),
      CompiledAction::Config(WafActionConfig::SilentClose { .. }) => {
        decision.terminal = Some(WafHttpTerminal::SilentClose);
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::ReplaceResponse { status, body, .. })
      | CompiledAction::Config(WafActionConfig::RejectResponse { status, body, .. }) => {
        decision.terminal = Some(WafHttpTerminal::response(
          StatusCode::from_u16(*status)?,
          body.clone().unwrap_or_else(|| "Blocked by WAF".to_string()),
        ));
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::SetResponseHeader { name, value, .. }) => {
        decision
          .response_header_mutations
          .push(HeaderMutation::Set {
            name: HeaderName::from_bytes(name.as_bytes())?,
            value: HeaderValue::from_str(value)?,
          });
      }
      CompiledAction::Config(WafActionConfig::RemoveResponseHeader { name, .. }) => {
        decision
          .response_header_mutations
          .push(HeaderMutation::Remove {
            name: HeaderName::from_bytes(name.as_bytes())?,
          });
      }
      CompiledAction::EmitAccessLog { fields } => {
        let action_ctx = EvalContext {
          rule_name: &rule.name,
          rule_id: rule.id.as_deref(),
          rule_tags: &rule.tags,
          response: Some(input),
          locals: &[],
          ..*ctx
        };
        decision.access_logs.push(AccessLogRecord::from_fields(
          fields,
          &action_ctx,
          tx,
          "waf",
        )?);
      }
      CompiledAction::EmitMitigation(action) => {
        if let Some(terminal) =
          apply_mitigation_http_action(action, rule, ctx, Some(input), mitigation, tx)?
        {
          decision.terminal = Some(terminal.into());
          return Ok(());
        }
      }
      CompiledAction::Config(WafActionConfig::Reject { .. })
      | CompiledAction::Config(WafActionConfig::RouteToPool { .. })
      | CompiledAction::Config(WafActionConfig::RouteToUpstream { .. })
      | CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { .. })
      | CompiledAction::Config(WafActionConfig::SetRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::SetTag { .. })
      | CompiledAction::Config(WafActionConfig::RateLimit { .. })
      | CompiledAction::Config(WafActionConfig::WeighPersonProof { .. })
      | CompiledAction::Config(WafActionConfig::AllowPersonProof { .. })
      | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
      | CompiledAction::Config(WafActionConfig::CloseStream { .. })
      | CompiledAction::RequirePersonProof(_)
      | CompiledAction::Config(WafActionConfig::EmitMitigation { .. })
      | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. }) => {
        bail!("invalid response-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
}

pub(super) fn apply_stream_actions(
  rule: &CompiledRule,
  ctx: &EvalContext<'_>,
  input: WafStreamInput<'_>,
  mitigation: &MitigationSink,
  decision: &mut WafStreamDecision,
  tx: &mut TransactionBudget,
) -> anyhow::Result<()> {
  for action in &rule.actions {
    tx.count_mutation()?;
    match action {
      CompiledAction::Config(WafActionConfig::CloseStream {
        websocket_code,
        webtransport_code,
        reason,
        ..
      }) => {
        decision.close = Some(WafStreamClose {
          websocket_code: *websocket_code,
          webtransport_code: *webtransport_code,
          reason: reason.clone(),
        });
        return Ok(());
      }
      CompiledAction::Config(WafActionConfig::SilentClose { .. }) => {
        decision.silent_close = true;
        return Ok(());
      }
      CompiledAction::EmitMitigation(action) => {
        if let Some(close) =
          apply_mitigation_stream_action(action, rule, ctx, input, mitigation, tx)?
        {
          decision.close = Some(close);
          return Ok(());
        }
      }
      CompiledAction::Config(WafActionConfig::Reject { .. })
      | CompiledAction::Config(WafActionConfig::ContinueResponse { .. })
      | CompiledAction::Config(WafActionConfig::ReplaceResponse { .. })
      | CompiledAction::Config(WafActionConfig::RejectResponse { .. })
      | CompiledAction::Config(WafActionConfig::EmitAccessLog { .. })
      | CompiledAction::Config(WafActionConfig::EmitMitigation { .. })
      | CompiledAction::Config(WafActionConfig::RouteToPool { .. })
      | CompiledAction::Config(WafActionConfig::RouteToUpstream { .. })
      | CompiledAction::Config(WafActionConfig::SetLoadBalancingPolicy { .. })
      | CompiledAction::Config(WafActionConfig::SetRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveRequestHeader { .. })
      | CompiledAction::Config(WafActionConfig::SetResponseHeader { .. })
      | CompiledAction::Config(WafActionConfig::RemoveResponseHeader { .. })
      | CompiledAction::Config(WafActionConfig::SetTag { .. })
      | CompiledAction::Config(WafActionConfig::RateLimit { .. })
      | CompiledAction::Config(WafActionConfig::WeighPersonProof { .. })
      | CompiledAction::Config(WafActionConfig::AllowPersonProof { .. })
      | CompiledAction::Config(WafActionConfig::RequirePersonProof { .. })
      | CompiledAction::RequirePersonProof(_)
      | CompiledAction::EmitAccessLog { .. } => {
        bail!("invalid stream-phase WAF action in rule {}", rule.name);
      }
    }
  }
  Ok(())
}

pub fn current_unix_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
    .unwrap_or_default()
}

pub fn apply_header_mutations(headers: &mut HeaderMap, mutations: &[HeaderMutation]) {
  for mutation in mutations {
    match mutation {
      HeaderMutation::Set { name, value } => {
        headers.insert(name, value.clone());
      }
      HeaderMutation::Append { name, value } => {
        headers.append(name, value.clone());
      }
      HeaderMutation::Remove { name } => {
        headers.remove(name);
      }
    }
  }
}
