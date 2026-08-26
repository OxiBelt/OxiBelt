//! WAF rule compilation, typed runtime IR, regex caches, and counter continuity.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn compile_rules(
  configs: &[WafRuleConfig],
  groups: RuleGroupScope<'_>,
  scope: WafRuleScope,
  default_mode: WafMode,
  previous_counters: &HashMap<WafRuleHitKey, Arc<AtomicU64>>,
  global_functions: Arc<FunctionMap>,
  route_functions: Option<Arc<FunctionMap>>,
  person_proof_defaults: &WafPersonProofConfig,
  limits: &WafLimits,
) -> anyhow::Result<Vec<CompiledRule>> {
  configs
    .iter()
    .map(|rule| {
      let resolved = resolve_rule(scope.label, rule, groups)
        .with_context(|| format!("failed to resolve WAF rule {} groups", rule.name))?;
      let expression = Parser::new(&resolved.when)
        .parse()
        .and_then(|expression| {
          expression.analyze_for_phase_with_functions(
            rule.phase,
            global_functions.as_ref(),
            route_functions.as_deref(),
          )
        })
        .with_context(|| format!("failed to compile WAF rule {}", rule.name))?;
      let actions = compile_actions(
        rule,
        &resolved.actions,
        scope.person_proof_scope(),
        person_proof_defaults,
        global_functions.as_ref(),
        route_functions.as_deref(),
      )
      .with_context(|| format!("failed to compile WAF rule {} actions", rule.name))?;
      let person_proof_policies = actions
        .iter()
        .filter_map(|action| match action {
          CompiledAction::RequirePersonProof(policy) => Some(policy.clone()),
          _ => None,
        })
        .collect();
      let mode = rule.mode.unwrap_or(default_mode);
      let hit_key = WafRuleHitKey {
        scope: scope.label.to_string(),
        route: scope.route.clone(),
        phase: rule.phase,
        name: rule.name.clone(),
        id: rule.id.clone().filter(|id| !id.is_empty()),
        mode,
      };
      let hit_counter = previous_counters.get(&hit_key).cloned().unwrap_or_default();
      let request_body_need = expression
        .request_body_need_with_functions(global_functions.as_ref(), route_functions.as_deref());
      let response_body_need = expression
        .response_body_need_with_functions(global_functions.as_ref(), route_functions.as_deref());
      let regex_cache = CompiledRegexCache::from_rule_expression(&expression, limits)
        .with_context(|| format!("failed to compile WAF rule {} regex literals", rule.name))?;
      Ok(CompiledRule {
        name: rule.name.clone(),
        id: rule.id.clone().filter(|id| !id.is_empty()),
        tags: rule.tags.clone(),
        scope: scope.label.to_string(),
        route: scope.route.clone(),
        internal_id: new_internal_rule_id()?,
        phase: rule.phase,
        priority: rule.priority,
        mode,
        hit_key,
        hit_counter,
        eval_counter: Arc::new(AtomicU64::new(0)),
        eval_duration_ns: Arc::new(AtomicU64::new(0)),
        request_body_need,
        response_body_need,
        regex_cache,
        expression,
        actions,
        person_proof_policies,
      })
    })
    .collect()
}

pub(super) fn build_route_plans(
  config: &Config,
  global_rules: &[CompiledRule],
  route_rules: &HashMap<String, Vec<CompiledRule>>,
  crs: &CrsEngine,
) -> (WafRoutePlan, HashMap<String, WafRoutePlan>) {
  let reject_duplicate_metadata =
    config.waf.duplicate_metadata_policy == WafDuplicateMetadataPolicy::RejectRequest;
  let build = |rules: &[CompiledRule]| {
    if !config.waf.enabled {
      return WafRoutePlan::disabled();
    }
    WafRoutePlan::new(
      phase_plan(
        global_rules,
        rules,
        WafPhase::Request,
        crs.has_request_rules() || reject_duplicate_metadata,
        if crs.requires_request_body_inspection() {
          BodyNeed::PrefixBytes
        } else {
          BodyNeed::None
        },
      ),
      phase_plan(
        global_rules,
        rules,
        WafPhase::Response,
        crs.has_response_rules(),
        if crs.requires_response_body_inspection() {
          BodyNeed::PrefixBytes
        } else {
          BodyNeed::None
        },
      ),
      phase_plan(global_rules, rules, WafPhase::Stream, false, BodyNeed::None),
    )
  };
  let default_route_plan = build(&[]);
  let route_plans = config
    .routes
    .iter()
    .map(|route| {
      (
        route.name.clone(),
        build(
          route_rules
            .get(&route.name)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        ),
      )
    })
    .collect();
  (default_route_plan, route_plans)
}

#[derive(Clone)]
pub(super) struct WafRuleScope {
  pub(super) label: &'static str,
  pub(super) route: Option<String>,
  pub(super) person_proof_scope: String,
}

impl WafRuleScope {
  pub(super) fn global() -> Self {
    Self {
      label: "global",
      route: None,
      person_proof_scope: "global".to_string(),
    }
  }

  pub(super) fn route(route_name: &str) -> Self {
    Self {
      label: "route",
      route: Some(route_name.to_string()),
      person_proof_scope: format!("route:{route_name}"),
    }
  }

  pub(super) fn person_proof_scope(&self) -> &str {
    &self.person_proof_scope
  }
}

pub(super) fn compile_actions(
  rule: &WafRuleConfig,
  actions: &[WafActionConfig],
  scope: &str,
  person_proof_defaults: &WafPersonProofConfig,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<Vec<CompiledAction>> {
  actions
    .iter()
    .enumerate()
    .map(|(action_index, action)| match action {
      WafActionConfig::EmitAccessLog { fields, .. } => Ok(CompiledAction::EmitAccessLog {
        fields: fields
          .iter()
          .map(|field| {
            Ok(CompiledAccessLogField {
              name: field.name.clone(),
              expression: Parser::new(&field.value)
                .parse()
                .and_then(|expression| {
                  expression.analyze_for_phase_with_functions(
                    WafPhase::Response,
                    global_functions,
                    route_functions,
                  )
                })
                .with_context(|| {
                  format!("failed to compile emit_access_log field {}", field.name)
                })?,
            })
          })
          .collect::<anyhow::Result<Vec<_>>>()?,
      }),
      WafActionConfig::RequirePersonProof { .. } => Ok(CompiledAction::RequirePersonProof(
        person_proof_policy::from_action(rule, scope, action_index, action, person_proof_defaults),
      )),
      WafActionConfig::EmitMitigation { .. } => Ok(CompiledAction::EmitMitigation(
        compile_mitigation_action(rule, action, global_functions, route_functions)?,
      )),
      WafActionConfig::SetRequestHeader { name, value, .. } if rule.phase == WafPhase::Request => {
        request_header_mutation::validate(
          rule.name.as_str(),
          "set_request_header",
          name,
          Some(value),
        )?;
        Ok(CompiledAction::Config(action.clone()))
      }
      WafActionConfig::RemoveRequestHeader { name, .. } if rule.phase == WafPhase::Request => {
        request_header_mutation::validate(rule.name.as_str(), "remove_request_header", name, None)?;
        Ok(CompiledAction::Config(action.clone()))
      }
      action => Ok(CompiledAction::Config(action.clone())),
    })
    .collect()
}

#[derive(Clone)]
pub struct CompiledAccessLogFields {
  pub(super) fields: Vec<CompiledAccessLogField>,
}

pub fn compile_access_log_fields(
  label: &str,
  fields: &[AccessLogFieldConfig],
) -> anyhow::Result<CompiledAccessLogFields> {
  validate_access_log_field_configs(label, fields)?;
  let empty_functions = FunctionMap::new();
  let fields = fields
    .iter()
    .map(|field| {
      Ok(CompiledAccessLogField {
        name: field.name.clone(),
        expression: Parser::new(&field.value)
          .parse()
          .and_then(|expression| {
            expression.analyze_for_phase_with_functions(WafPhase::Response, &empty_functions, None)
          })
          .with_context(|| format!("failed to compile {label} field {}", field.name))?,
      })
    })
    .collect::<anyhow::Result<Vec<_>>>()?;
  Ok(CompiledAccessLogFields { fields })
}

pub(super) fn new_internal_rule_id() -> anyhow::Result<String> {
  new_uuid_like_id("WAF internal rule id")
}

pub fn new_access_log_id() -> String {
  new_uuid_like_id("access log id").unwrap_or_else(|_| format!("fallback-{}", current_unix_ms()))
}

pub(super) fn new_uuid_like_id(label: &str) -> anyhow::Result<String> {
  let mut bytes = [0u8; 16];
  crate::crypto::random_fill(&mut bytes).map_err(|_| anyhow!("failed to generate {label}"))?;
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  Ok(format!(
    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
    bytes[0],
    bytes[1],
    bytes[2],
    bytes[3],
    bytes[4],
    bytes[5],
    bytes[6],
    bytes[7],
    bytes[8],
    bytes[9],
    bytes[10],
    bytes[11],
    bytes[12],
    bytes[13],
    bytes[14],
    bytes[15]
  ))
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(super) struct WafRuleHitKey {
  pub(super) scope: String,
  pub(super) route: Option<String>,
  pub(super) phase: WafPhase,
  pub(super) name: String,
  pub(super) id: Option<String>,
  pub(super) mode: WafMode,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct WafRuleHitSnapshot {
  pub scope: String,
  pub route: Option<String>,
  pub phase: String,
  pub name: String,
  pub id: Option<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  pub effective_mode: String,
  pub hits: u64,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub tuned_hits: Option<u64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_inbound_anomaly_score: Option<i64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_outbound_anomaly_score: Option<i64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_inbound_blocking_score: Option<i64>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub latest_outbound_blocking_score: Option<i64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct WafRuleCostSnapshot {
  pub scope: String,
  pub route: Option<String>,
  pub phase: String,
  pub name: String,
  pub id: Option<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  pub effective_mode: String,
  pub evaluations: u64,
  pub total_duration_ns: u64,
  pub average_duration_ns: u64,
}

#[derive(Clone)]
pub(super) struct CompiledRule {
  pub(super) name: String,
  pub(super) id: Option<String>,
  pub(super) tags: Vec<String>,
  pub(super) scope: String,
  pub(super) route: Option<String>,
  pub(super) internal_id: String,
  pub(super) phase: WafPhase,
  pub(super) priority: i64,
  pub(super) mode: WafMode,
  pub(super) hit_key: WafRuleHitKey,
  pub(super) hit_counter: Arc<AtomicU64>,
  pub(super) eval_counter: Arc<AtomicU64>,
  pub(super) eval_duration_ns: Arc<AtomicU64>,
  pub(super) request_body_need: BodyNeed,
  pub(super) response_body_need: BodyNeed,
  pub(super) regex_cache: CompiledRegexCache,
  pub(super) expression: Expr,
  pub(super) actions: Vec<CompiledAction>,
  pub(super) person_proof_policies: Vec<PersonProofPolicy>,
}

impl CompiledRule {
  pub(super) fn record_hit(&self) {
    self.hit_counter.fetch_add(1, Ordering::Relaxed);
  }

  pub(super) fn record_eval(&self, duration: Duration) {
    self.eval_counter.fetch_add(1, Ordering::Relaxed);
    self.eval_duration_ns.fetch_add(
      duration.as_nanos().min(u128::from(u64::MAX)) as u64,
      Ordering::Relaxed,
    );
  }

  pub(super) fn hit_snapshot(&self) -> WafRuleHitSnapshot {
    WafRuleHitSnapshot {
      scope: self.scope.clone(),
      route: self.route.clone(),
      phase: self.phase.as_str().to_string(),
      name: self.name.clone(),
      id: self.id.clone(),
      tags: self.tags.clone(),
      effective_mode: self.mode.as_str().to_string(),
      hits: self.hit_counter.load(Ordering::Relaxed),
      tuned_hits: None,
      latest_inbound_anomaly_score: None,
      latest_outbound_anomaly_score: None,
      latest_inbound_blocking_score: None,
      latest_outbound_blocking_score: None,
    }
  }

  pub(super) fn cost_snapshot(&self) -> WafRuleCostSnapshot {
    let evaluations = self.eval_counter.load(Ordering::Relaxed);
    let total_duration_ns = self.eval_duration_ns.load(Ordering::Relaxed);
    WafRuleCostSnapshot {
      scope: self.scope.clone(),
      route: self.route.clone(),
      phase: self.phase.as_str().to_string(),
      name: self.name.clone(),
      id: self.id.clone(),
      tags: self.tags.clone(),
      effective_mode: self.mode.as_str().to_string(),
      evaluations,
      total_duration_ns,
      average_duration_ns: total_duration_ns.checked_div(evaluations).unwrap_or(0),
    }
  }
}

#[derive(Clone)]
pub(super) enum CompiledAction {
  Config(WafActionConfig),
  RequirePersonProof(PersonProofPolicy),
  EmitAccessLog { fields: Vec<CompiledAccessLogField> },
  EmitMitigation(CompiledMitigationAction),
}

#[derive(Clone)]
pub(super) struct CompiledAccessLogField {
  pub(super) name: String,
  pub(super) expression: Expr,
}

#[derive(Clone, Default)]
pub(super) struct CompiledRegexCache {
  default: HashMap<String, HybridRegex>,
  header_name: HashMap<String, HybridRegex>,
}

impl CompiledRegexCache {
  pub(super) fn from_rule_expression(
    expression: &Expr,
    limits: &WafLimits,
  ) -> anyhow::Result<Self> {
    let program = expression.verified_program()?;
    let mut cache = Self::default();
    cache.collect_expression(program.root(), program, limits)?;
    Ok(cache)
  }

  pub(super) fn get(&self, flavor: RegexFlavor, pattern: &str) -> Option<&HybridRegex> {
    self.flavor(flavor).get(pattern)
  }

  fn flavor(&self, flavor: RegexFlavor) -> &HashMap<String, HybridRegex> {
    match flavor {
      RegexFlavor::Default => &self.default,
      RegexFlavor::HeaderName => &self.header_name,
    }
  }

  fn flavor_mut(&mut self, flavor: RegexFlavor) -> &mut HashMap<String, HybridRegex> {
    match flavor {
      RegexFlavor::Default => &mut self.default,
      RegexFlavor::HeaderName => &mut self.header_name,
    }
  }

  fn collect_expression(
    &mut self,
    expression: &VerifiedExpression,
    program: &VerifiedProgram,
    limits: &WafLimits,
  ) -> anyhow::Result<()> {
    match expression.kind() {
      VerifiedExprKindRef::Array(items) => {
        for item in items {
          self.collect_expression(item, program, limits)?;
        }
      }
      VerifiedExprKindRef::Member { receiver, .. } => {
        self.collect_expression(receiver, program, limits)?;
      }
      VerifiedExprKindRef::FunctionCall { args, .. } => {
        self.collect_call_regexes(expression, args, program, limits)?;
        for arg in args {
          self.collect_expression(arg, program, limits)?;
        }
      }
      VerifiedExprKindRef::ExpressionFunctionCall { args, body, .. } => {
        self.collect_call_regexes(expression, args, program, limits)?;
        for arg in args {
          self.collect_expression(arg, program, limits)?;
        }
        self.collect_expression(body, program, limits)?;
      }
      VerifiedExprKindRef::MethodCall { receiver, args, .. } => {
        self.collect_call_regexes(expression, args, program, limits)?;
        self.collect_expression(receiver, program, limits)?;
        for arg in args {
          self.collect_expression(arg, program, limits)?;
        }
      }
      VerifiedExprKindRef::Unary { expr, .. } => {
        self.collect_expression(expr, program, limits)?;
      }
      VerifiedExprKindRef::Binary { left, right, .. } => {
        self.collect_expression(left, program, limits)?;
        self.collect_expression(right, program, limits)?;
      }
      VerifiedExprKindRef::Null
      | VerifiedExprKindRef::Bool(_)
      | VerifiedExprKindRef::Int(_)
      | VerifiedExprKindRef::Float(_)
      | VerifiedExprKindRef::String(_)
      | VerifiedExprKindRef::Identifier(_) => {}
    }
    Ok(())
  }

  fn collect_call_regexes(
    &mut self,
    expression: &VerifiedExpression,
    args: &[VerifiedExpression],
    program: &VerifiedProgram,
    limits: &WafLimits,
  ) -> anyhow::Result<()> {
    let Some(ticket) = expression.capability_ticket() else {
      return Ok(());
    };
    let Some(capability) = program.required_capability_metadata().get(ticket) else {
      return Ok(());
    };
    for regex_arg in &capability.regex_args {
      let Some(pattern) = args
        .get(regex_arg.index)
        .and_then(expression::verified_string_literal)
      else {
        continue;
      };
      let flavor = oxibelt_regex_flavor(regex_arg.flavor);
      if self.flavor(flavor).contains_key(pattern) {
        continue;
      }
      let case_insensitive = flavor == RegexFlavor::HeaderName;
      self.flavor_mut(flavor).insert(
        pattern.to_string(),
        HybridRegex::compile(pattern, case_insensitive, limits)?,
      );
    }
    Ok(())
  }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(super) enum RegexFlavor {
  Default,
  HeaderName,
}

fn oxibelt_regex_flavor(flavor: ForgeRegexFlavor) -> RegexFlavor {
  match flavor {
    ForgeRegexFlavor::Default => RegexFlavor::Default,
    ForgeRegexFlavor::HeaderName => RegexFlavor::HeaderName,
  }
}
