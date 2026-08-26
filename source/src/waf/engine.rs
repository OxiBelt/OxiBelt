//! Engine construction, reload continuity, Admin state, and inspection planning.

use super::*;

impl WafEngine {
  pub fn new(config: &Config) -> anyhow::Result<Self> {
    Self::new_with_previous(config, None, None)
  }

  pub fn new_with_previous(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_limits_and_mitigation(
      config,
      previous,
      shared_state,
      None,
      previous
        .map(|waf| waf.mitigation.clone())
        .unwrap_or_else(MitigationSink::disabled),
    )
  }

  pub fn new_with_previous_and_limits(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
    rate_limits: Option<Arc<LimitState>>,
  ) -> anyhow::Result<Self> {
    Self::new_with_previous_limits_and_mitigation(
      config,
      previous,
      shared_state,
      rate_limits,
      previous
        .map(|waf| waf.mitigation.clone())
        .unwrap_or_else(MitigationSink::disabled),
    )
  }

  pub fn new_with_previous_limits_and_mitigation(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
    rate_limits: Option<Arc<LimitState>>,
    mitigation: MitigationSink,
  ) -> anyhow::Result<Self> {
    validate_config(config)?;

    let previous_counters = previous
      .map(WafEngine::active_hit_counters)
      .unwrap_or_default();
    let previous_crs_counters = previous
      .map(|engine| engine.crs.active_hit_counters())
      .unwrap_or_default();
    let rate_limits = rate_limits.unwrap_or_else(|| LimitState::new(shared_state.clone()));
    let pattern_sets = compile_pattern_sets(&config.waf.pattern_sets, &config.waf.limits)?;
    let global_functions = Arc::new(compile_global_functions(&config.waf.functions)?);
    let crs = CrsEngine::compile(&config.waf.crs, &config.waf.limits, &previous_crs_counters)?;
    let global_rules = compile_rules(
      &config.waf.rules,
      RuleGroupScope {
        global: &config.waf.rule_groups,
        route: None,
      },
      WafRuleScope::global(),
      config.waf.mode,
      &previous_counters,
      global_functions.clone(),
      None,
      &config.waf.person_proof,
      &config.waf.limits,
    )?;
    let mut route_rules = HashMap::new();
    for route in &config.routes {
      let functions = Arc::new(compile_route_functions(
        &format!("route {} WAF", route.name),
        &route.waf.functions,
        global_functions.as_ref(),
      )?);
      route_rules.insert(
        route.name.clone(),
        compile_rules(
          &route.waf.rules,
          RuleGroupScope {
            global: &config.waf.rule_groups,
            route: Some(&route.waf.rule_groups),
          },
          WafRuleScope::route(&route.name),
          config.waf.mode,
          &previous_counters,
          global_functions.clone(),
          Some(functions.clone()),
          &config.waf.person_proof,
          &config.waf.limits,
        )?,
      );
    }
    let mut person_proof_policies = global_rules
      .iter()
      .chain(route_rules.values().flat_map(|rules| rules.iter()))
      .flat_map(|rule| rule.person_proof_policies.iter().cloned())
      .collect::<Vec<_>>();
    if config.dynamic_policy.enabled {
      person_proof_policies.push(person_proof_dynamic::policy(&config.waf.person_proof));
    }
    let person_proof = PersonProofEngine::from_policies_with_previous(
      person_proof_policies,
      config.waf.limits.max_person_proof_reuse_tokens,
      previous.map(|waf| &waf.person_proof),
      shared_state,
    )?;
    let person_proof_tcp_max_hop = if config.waf.enabled {
      person_proof.tcp_max_hop()
    } else {
      None
    };
    let (default_route_plan, route_plans) =
      build_route_plans(config, &global_rules, &route_rules, &crs);

    Ok(Self {
      enabled: config.waf.enabled,
      mode: config.waf.mode,
      fail_policy: config.waf.fail_policy,
      duplicate_metadata_policy: config.waf.duplicate_metadata_policy,
      limits: config.waf.limits.clone(),
      pattern_sets,
      global_rules,
      route_rules,
      default_route_plan,
      route_plans,
      crs,
      rate_limits,
      mitigation,
      person_proof,
      person_proof_tcp_max_hop,
    })
  }

  pub async fn new_with_previous_limits_and_mitigation_async(
    config: &Config,
    previous: Option<&Self>,
    shared_state: Option<std::sync::Arc<SharedState>>,
    rate_limits: Option<Arc<LimitState>>,
    mitigation: MitigationSink,
  ) -> anyhow::Result<Self> {
    let mut engine = Self::new_with_previous_limits_and_mitigation(
      config,
      previous,
      shared_state,
      rate_limits,
      mitigation,
    )?;
    engine.person_proof.load_shared_secret().await?;
    Ok(engine)
  }

  pub fn person_proof_tcp_max_hop(&self) -> Option<u8> {
    self.person_proof_tcp_max_hop
  }

  #[cfg(feature = "admin-runtime")]
  pub fn person_proof_admin_status(&self) -> anyhow::Result<PersonProofAdminStatus> {
    self.person_proof.admin_status()
  }

  #[cfg(feature = "admin-runtime")]
  pub async fn person_proof_admin_status_async(&self) -> anyhow::Result<PersonProofAdminStatus> {
    self.person_proof.admin_status_async().await
  }

  #[cfg(feature = "admin-runtime")]
  pub fn person_proof_admin_clearances(
    &self,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofAdminClearancePage> {
    self.person_proof.admin_list_clearances(limit, cursor)
  }

  #[cfg(feature = "admin-runtime")]
  pub async fn person_proof_admin_clearances_async(
    &self,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofAdminClearancePage> {
    self
      .person_proof
      .admin_list_clearances_async(limit, cursor)
      .await
  }

  #[cfg(feature = "admin-runtime")]
  pub fn person_proof_admin_revoke_clearance(
    &self,
    hash: &str,
    ttl_seconds: Option<u64>,
  ) -> anyhow::Result<PersonProofAdminRevokeResult> {
    self.person_proof.admin_revoke_clearance(hash, ttl_seconds)
  }

  #[cfg(feature = "admin-runtime")]
  pub async fn person_proof_admin_revoke_clearance_async(
    &self,
    hash: &str,
    ttl_seconds: Option<u64>,
  ) -> anyhow::Result<PersonProofAdminRevokeResult> {
    self
      .person_proof
      .admin_revoke_clearance_async(hash, ttl_seconds)
      .await
  }

  #[cfg(feature = "admin-runtime")]
  pub async fn person_proof_admin_revoke_clearance_with_idempotency_async(
    &self,
    hash: &str,
    ttl_seconds: Option<u64>,
    idempotency_key: Option<&str>,
  ) -> anyhow::Result<PersonProofAdminRevokeResult> {
    self
      .person_proof
      .admin_revoke_clearance_with_idempotency_async(hash, ttl_seconds, idempotency_key)
      .await
  }

  #[cfg(feature = "admin-runtime")]
  pub fn normalize_person_proof_admin_clearance_hash(hash: &str) -> anyhow::Result<String> {
    PersonProofEngine::normalize_admin_clearance_hash(hash)
  }

  pub fn enabled(&self) -> bool {
    self.enabled
  }

  pub(crate) fn route_plan(&self, route_name: &str) -> &WafRoutePlan {
    if self.enabled {
      self
        .route_plans
        .get(route_name)
        .unwrap_or(&self.default_route_plan)
    } else {
      &self.default_route_plan
    }
  }

  pub fn rule_hit_snapshots(&self) -> Vec<WafRuleHitSnapshot> {
    let mut snapshots = self
      .global_rules
      .iter()
      .chain(self.route_rules.values().flat_map(|rules| rules.iter()))
      .map(CompiledRule::hit_snapshot)
      .collect::<Vec<_>>();
    snapshots.extend(self.crs.rule_hit_snapshots());
    snapshots.sort_by(|left, right| {
      left
        .scope
        .cmp(&right.scope)
        .then_with(|| left.route.cmp(&right.route))
        .then_with(|| left.phase.cmp(&right.phase))
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| left.id.cmp(&right.id))
        .then_with(|| left.effective_mode.cmp(&right.effective_mode))
    });
    snapshots
  }

  pub fn rule_cost_snapshots(&self) -> Vec<WafRuleCostSnapshot> {
    let mut snapshots = self
      .global_rules
      .iter()
      .chain(self.route_rules.values().flat_map(|rules| rules.iter()))
      .map(CompiledRule::cost_snapshot)
      .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
      left
        .scope
        .cmp(&right.scope)
        .then_with(|| left.route.cmp(&right.route))
        .then_with(|| left.phase.cmp(&right.phase))
        .then_with(|| left.name.cmp(&right.name))
        .then_with(|| left.id.cmp(&right.id))
        .then_with(|| left.effective_mode.cmp(&right.effective_mode))
    });
    snapshots
  }

  pub fn has_response_rules(&self, route_name: &str) -> bool {
    self.route_plan(route_name).response().enabled()
  }
  pub fn has_request_rules(&self, route_name: &str) -> bool {
    self.route_plan(route_name).request().enabled()
  }
  pub fn person_proof_api_path_role(&self, path: &str) -> Option<PersonProofApiPathRole> {
    person_proof_api::api_path_role(&self.person_proof, path)
  }
  pub fn has_person_proof_api_path(&self, path: &str) -> bool {
    self.person_proof_api_path_role(path).is_some()
  }
  pub fn has_person_proof_api_paths(&self) -> bool {
    !self.person_proof.policies.is_empty()
  }
  pub fn has_person_proof_verify_path(&self, path: &str) -> bool {
    self.person_proof_api_path_role(path) == Some(PersonProofApiPathRole::Verify)
  }
  pub fn person_proof_session_document(
    &self,
    input: WafRequestInput<'_>,
    session_path: &str,
    session: &str,
  ) -> anyhow::Result<Option<PersonProofSessionDocument>> {
    person_proof_api::session_document(&self.person_proof, input, session_path, session)
  }

  pub fn person_proof_openapi_document(&self, openapi_path: &str) -> Option<String> {
    person_proof_api::openapi_document(&self.person_proof, openapi_path)
  }

  pub fn begin_person_proof_session_challenge(
    &self,
    input: WafRequestInput<'_>,
    verify_path: &str,
    session: &str,
  ) -> anyhow::Result<Option<PersonProofProviderChallenge>> {
    person_proof_api::begin_session_challenge(&self.person_proof, input, verify_path, session)
  }

  pub fn begin_person_proof_provider_challenge(
    &self,
    input: WafRequestInput<'_>,
    verify_path: &str,
    challenge: &str,
  ) -> anyhow::Result<Option<PersonProofProviderChallenge>> {
    person_proof_v2::begin_provider_challenge(&self.person_proof, input, verify_path, challenge)
  }

  pub fn complete_person_proof_provider_challenge(
    &self,
    input: WafRequestInput<'_>,
    challenge: PersonProofProviderChallenge,
  ) -> anyhow::Result<PersonProofIssuedClearance> {
    person_proof_v2::complete_provider_challenge(&self.person_proof, input, challenge)
  }

  pub async fn complete_person_proof_provider_challenge_async(
    &self,
    input: WafRequestInput<'_>,
    challenge: PersonProofProviderChallenge,
  ) -> anyhow::Result<PersonProofIssuedClearance> {
    person_proof_v2::complete_provider_challenge_async(&self.person_proof, input, challenge).await
  }

  pub fn requires_request_body_inspection(&self, route_name: &str) -> bool {
    self
      .route_plan(route_name)
      .request_body_need()
      .requires_prefix()
  }

  pub fn requires_response_body_inspection(&self, route_name: &str) -> bool {
    self
      .route_plan(route_name)
      .response()
      .body_need()
      .requires_prefix()
  }

  pub fn request_body_need(&self, route_name: &str) -> BodyNeed {
    self.route_plan(route_name).request_body_need()
  }

  pub fn response_body_need(&self, route_name: &str) -> BodyNeed {
    self.route_plan(route_name).response().body_need()
  }

  pub fn plain_proxy_fast_path_safe(&self, route_name: &str) -> bool {
    self.route_plan(route_name).plain_proxy_fast_path_safe()
  }

  pub fn static_sendfile_fast_path_safe(&self, route_name: &str) -> bool {
    self.route_plan(route_name).static_sendfile_fast_path_safe()
  }

  pub fn requires_stream_inspection(&self, route_name: &str) -> bool {
    self.route_plan(route_name).stream().enabled()
  }
}
