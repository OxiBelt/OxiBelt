//! Static WAF scope, phase, function, action, and metadata validation.

use super::*;

pub fn validate_config(config: &Config) -> anyhow::Result<()> {
  validate_http_body_compression_config(config)?;
  if config.waf.limits.max_person_proof_reuse_tokens == 0 {
    bail!("waf.limits.max_person_proof_reuse_tokens must be greater than 0");
  }
  if config.waf.limits.max_advanced_regex_subject_bytes == 0 {
    bail!("waf.limits.max_advanced_regex_subject_bytes must be greater than 0");
  }
  if config.waf.limits.max_advanced_regex_backtracks == 0 {
    bail!("waf.limits.max_advanced_regex_backtracks must be greater than 0");
  }
  if has_emit_mitigation_actions(config) && !config.database.mitigation.enabled {
    bail!("emit_mitigation actions require database.mitigation.enabled = true");
  }
  if config.waf.crs.enabled {
    validate_crs_config(&config.waf.crs)?;
  }

  let upstream_names = config
    .upstreams
    .iter()
    .map(|upstream| upstream.name.as_str())
    .collect::<HashSet<_>>();
  let pool_names = config
    .upstream_pools
    .iter()
    .map(|pool| pool.name.as_str())
    .collect::<HashSet<_>>();
  let global_functions = compile_global_functions(&config.waf.functions)?;
  validate_rule_group_scope("global WAF", &config.waf.rule_groups)?;
  let global_validation = WafValidationContext {
    pattern_sets: &config.waf.pattern_sets,
    global_rule_groups: &config.waf.rule_groups,
    route_rule_groups: None,
    global_functions: &global_functions,
    route_functions: None,
    limits: &config.waf.limits,
    upstream_names: &upstream_names,
    pool_names: &pool_names,
  };
  validate_scope("global WAF", &config.waf.rules, &global_validation)?;

  for route in &config.routes {
    let route_functions = compile_route_functions(
      &format!("route {} WAF", route.name),
      &route.waf.functions,
      &global_functions,
    )?;
    validate_rule_group_scope(&format!("route {} WAF", route.name), &route.waf.rule_groups)?;
    let route_validation = WafValidationContext {
      pattern_sets: &config.waf.pattern_sets,
      global_rule_groups: &config.waf.rule_groups,
      route_rule_groups: Some(&route.waf.rule_groups),
      global_functions: &global_functions,
      route_functions: Some(&route_functions),
      limits: &config.waf.limits,
      upstream_names: &upstream_names,
      pool_names: &pool_names,
    };
    validate_scope(
      &format!("route {} WAF", route.name),
      &route.waf.rules,
      &route_validation,
    )?;
  }
  validate_unique_rule_ids(config)?;
  person_proof_config::validate_api_paths(config)?;

  Ok(())
}

fn has_emit_mitigation_actions(config: &Config) -> bool {
  fn action_is_mitigation(action: &WafActionConfig) -> bool {
    matches!(action, WafActionConfig::EmitMitigation { .. })
  }
  fn rule_has_mitigation(rule: &WafRuleConfig) -> bool {
    rule.actions.iter().any(action_is_mitigation)
      || rule
        .local_rule_groups
        .iter()
        .any(|group| group.actions.iter().any(action_is_mitigation))
  }

  config.waf.rules.iter().any(rule_has_mitigation)
    || config
      .routes
      .iter()
      .any(|route| route.waf.rules.iter().any(rule_has_mitigation))
    || config
      .waf
      .rule_groups
      .iter()
      .any(|group| group.actions.iter().any(action_is_mitigation))
    || config.routes.iter().any(|route| {
      route
        .waf
        .rule_groups
        .iter()
        .any(|group| group.actions.iter().any(action_is_mitigation))
    })
}

fn validate_unique_rule_ids(config: &Config) -> anyhow::Result<()> {
  let mut ids = HashMap::new();
  for rule in &config.waf.rules {
    remember_rule_id(&mut ids, "global WAF", rule)?;
  }
  for route in &config.routes {
    for rule in &route.waf.rules {
      remember_rule_id(&mut ids, &format!("route {} WAF", route.name), rule)?;
    }
  }
  Ok(())
}

fn remember_rule_id(
  ids: &mut HashMap<String, String>,
  scope: &str,
  rule: &WafRuleConfig,
) -> anyhow::Result<()> {
  let Some(id) = rule.id.as_deref().filter(|id| !id.is_empty()) else {
    return Ok(());
  };
  let label = format!("{scope} rule {}", rule.name);
  if let Some(previous) = ids.insert(id.to_string(), label.clone()) {
    bail!("duplicate WAF rule id {id} in {label}; already used by {previous}");
  }
  Ok(())
}

struct WafValidationContext<'a> {
  pattern_sets: &'a [WafPatternSetConfig],
  global_rule_groups: &'a [WafRuleGroupConfig],
  route_rule_groups: Option<&'a [WafRuleGroupConfig]>,
  global_functions: &'a FunctionMap,
  route_functions: Option<&'a FunctionMap>,
  limits: &'a WafLimits,
  upstream_names: &'a HashSet<&'a str>,
  pool_names: &'a HashSet<&'a str>,
}

fn validate_scope(
  scope: &str,
  rules: &[WafRuleConfig],
  ctx: &WafValidationContext<'_>,
) -> anyhow::Result<()> {
  validate_pattern_sets(ctx.pattern_sets, ctx.limits)?;

  let mut names = HashSet::new();
  for rule in rules {
    if rule.name.trim().is_empty() {
      bail!("{scope} rule name must not be empty");
    }
    if !names.insert(rule.name.as_str()) {
      bail!("{scope} contains duplicate WAF rule name {}", rule.name);
    }
    if rule.priority < 0 {
      bail!("WAF rule {} priority must not be negative", rule.name);
    }
    validate_rule_metadata(rule)?;
    if rule.path.is_some() {
      bail!(
        "WAF rule {} external path was not loaded; use Config::load for rule files",
        rule.name
      );
    }
    validate_rule_group_scope(
      &format!("{scope} rule {} external file", rule.name),
      &rule.local_rule_groups,
    )?;
    if let Some(expression) = rule.when.as_deref() {
      Parser::new(expression)
        .parse()
        .with_context(|| format!("failed to parse WAF rule {} expression", rule.name))?;
    }
    let resolved = resolve_rule(
      scope,
      rule,
      RuleGroupScope {
        global: ctx.global_rule_groups,
        route: ctx.route_rule_groups,
      },
    )?;
    let expression = resolved.when.as_str();
    let ast = Parser::new(expression)
      .parse()
      .with_context(|| format!("failed to parse WAF rule {} expression", rule.name))?;
    ast
      .validate_for_phase_with_functions(rule.phase, ctx.global_functions, ctx.route_functions)
      .with_context(|| format!("invalid WAF rule {} expression", rule.name))?;

    validate_actions(
      rule,
      &resolved.actions,
      ctx.upstream_names,
      ctx.pool_names,
      ctx.limits,
      ctx.global_functions,
      ctx.route_functions,
    )?;
  }

  Ok(())
}

fn validate_rule_metadata(rule: &WafRuleConfig) -> anyhow::Result<()> {
  if let Some(id) = rule.id.as_deref()
    && !is_valid_rule_label(id)
  {
    bail!("WAF rule {} id must match [A-Za-z0-9-]{{0,32}}", rule.name);
  }

  let mut tags = HashSet::new();
  for tag in &rule.tags {
    if !is_valid_rule_label(tag) {
      bail!("WAF rule {} tag must match [A-Za-z0-9-]{{0,32}}", rule.name);
    }
    if !tags.insert(tag.as_str()) {
      bail!("WAF rule {} contains duplicate tag {}", rule.name, tag);
    }
  }

  Ok(())
}

fn validate_actions(
  rule: &WafRuleConfig,
  actions: &[WafActionConfig],
  upstream_names: &HashSet<&str>,
  pool_names: &HashSet<&str>,
  limits: &WafLimits,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<()> {
  let mut mutations = 0usize;
  for action in actions {
    if action.priority() < 0 {
      bail!(
        "WAF rule {} action priority must not be negative",
        rule.name
      );
    }
    match action {
      WafActionConfig::Reject { status, .. } => {
        require_phase(rule, WafPhase::Request, "reject")?;
        validate_status(*status, &rule.name)?;
      }
      WafActionConfig::SilentClose {
        status,
        body,
        websocket_code,
        webtransport_code,
        reason,
        ..
      } => {
        if status.is_some()
          || body.is_some()
          || websocket_code.is_some()
          || webtransport_code.is_some()
          || reason.is_some()
        {
          bail!("WAF rule {} silent_close supports only priority", rule.name);
        }
      }
      WafActionConfig::ContinueResponse { .. } => {
        require_phase(rule, WafPhase::Response, "continue_response")?;
      }
      WafActionConfig::ReplaceResponse { status, .. }
      | WafActionConfig::RejectResponse { status, .. } => {
        require_phase(rule, WafPhase::Response, "response terminal action")?;
        validate_status(*status, &rule.name)?;
      }
      WafActionConfig::EmitAccessLog { fields, .. } => {
        require_phase(rule, WafPhase::Response, "emit_access_log")?;
        validate_access_log_field_configs_with_functions(
          &format!("WAF rule {} emit_access_log", rule.name),
          fields,
          global_functions,
          route_functions,
        )?;
      }
      WafActionConfig::EmitMitigation { .. } => {
        validate_mitigation_action(rule, action, global_functions, route_functions)?;
        mutations += 1;
      }
      WafActionConfig::RouteToUpstream { upstream, .. } => {
        require_phase(rule, WafPhase::Request, "route_to_upstream")?;
        if !upstream_names.contains(upstream.as_str()) {
          bail!(
            "WAF rule {} route_to_upstream references unknown upstream {}",
            rule.name,
            upstream
          );
        }
        mutations += 1;
      }
      WafActionConfig::RouteToPool { pool, .. } => {
        require_phase(rule, WafPhase::Request, "route_to_pool")?;
        if !pool_names.contains(pool.as_str()) {
          bail!(
            "WAF rule {} route_to_pool references unknown upstream pool {}",
            rule.name,
            pool
          );
        }
        mutations += 1;
      }
      WafActionConfig::SetLoadBalancingPolicy { policy, .. } => {
        require_phase(rule, WafPhase::Request, "set_load_balancing_policy")?;
        if !matches!(
          policy.as_str(),
          "power_of_two_choices"
            | "weighted_least_conn"
            | "rendezvous_hash"
            | "rendezvous_ip_hash"
            | "ewma"
            | "least_time"
        ) {
          bail!(
            "WAF rule {} set_load_balancing_policy uses unsupported policy {}",
            rule.name,
            policy
          );
        }
        mutations += 1;
      }
      WafActionConfig::SetRequestHeader { name, value, .. } => {
        require_phase(rule, WafPhase::Request, "set_request_header")?;
        request_header_mutation::validate(
          rule.name.as_str(),
          "set_request_header",
          name,
          Some(value),
        )?;
        mutations += 1;
      }
      WafActionConfig::RemoveRequestHeader { name, .. } => {
        require_phase(rule, WafPhase::Request, "remove_request_header")?;
        request_header_mutation::validate(rule.name.as_str(), "remove_request_header", name, None)?;
        mutations += 1;
      }
      WafActionConfig::SetResponseHeader { name, value, .. } => {
        require_phase(rule, WafPhase::Response, "set_response_header")?;
        validate_header(name, value)?;
        mutations += 1;
      }
      WafActionConfig::RemoveResponseHeader { name, .. } => {
        require_phase(rule, WafPhase::Response, "remove_response_header")?;
        validate_header_name(name)?;
        mutations += 1;
      }
      WafActionConfig::SetTag { key, value, .. } => {
        require_phase(rule, WafPhase::Request, "set_tag")?;
        if key.is_empty() || !is_valid_rule_label(key) || value.len() > 1024 {
          bail!("WAF rule {} set_tag exceeds tag size limits", rule.name);
        }
        mutations += 1;
      }
      WafActionConfig::RateLimit {
        name,
        key,
        ipv4_prefix_bits,
        ipv6_prefix_bits,
        identity_parts,
        token_bindings,
        token_header,
        access_token_source,
        rate,
        max_buckets,
        status,
        ..
      } => {
        require_phase(rule, WafPhase::Request, "rate_limit")?;
        if name.trim().is_empty() {
          bail!("WAF rule {} rate_limit name must not be empty", rule.name);
        }
        crate::limits::parse_rate(rate)
          .with_context(|| format!("invalid WAF rule {} rate_limit rate", rule.name))?;
        if *max_buckets == 0 {
          bail!(
            "WAF rule {} rate_limit max_buckets must be greater than 0",
            rule.name
          );
        }
        validate_status(*status, &rule.name)?;
        if let Some(token_header) = token_header {
          validate_header_name(token_header)?;
        }
        crate::config::validate_rate_limit_identity_config(
          crate::config::RateLimitIdentityValidation {
            label: "WAF rule rate_limit",
            name,
            key: *key,
            ipv4_prefix_bits: *ipv4_prefix_bits,
            ipv6_prefix_bits: *ipv6_prefix_bits,
            identity_parts,
            token_bindings,
            token_header: token_header.as_deref(),
            access_token_source: *access_token_source,
            waf_context: true,
          },
        )?;
        mutations += 1;
      }
      WafActionConfig::WeighPersonProof { weight, .. } => {
        require_phase(rule, WafPhase::Request, "weigh_person_proof")?;
        if !(-1_000_000..=1_000_000).contains(weight) {
          bail!(
            "WAF rule {} weigh_person_proof weight must be between -1000000 and 1000000",
            rule.name
          );
        }
        mutations += 1;
      }
      WafActionConfig::AllowPersonProof { .. } => {
        require_phase(rule, WafPhase::Request, "allow_person_proof")?;
        mutations += 1;
      }
      WafActionConfig::RequirePersonProof { status, .. } => {
        require_phase(rule, WafPhase::Request, "require_person_proof")?;
        validate_status(*status, &rule.name)?;
        validate_person_proof_settings(&rule.name, action)?;
      }
      WafActionConfig::CloseStream {
        websocket_code,
        webtransport_code: _,
        reason,
        ..
      } => {
        require_phase(rule, WafPhase::Stream, "close_stream")?;
        validate_websocket_close_code(*websocket_code, &rule.name)?;
        if reason.len() > 123 {
          bail!(
            "WAF rule {} close_stream reason exceeds 123 bytes",
            rule.name
          );
        }
      }
    }
  }

  if mutations > limits.max_mutations {
    bail!("WAF rule {} exceeds max_mutations", rule.name);
  }

  Ok(())
}

fn require_phase(rule: &WafRuleConfig, expected: WafPhase, action: &str) -> anyhow::Result<()> {
  if rule.phase != expected {
    bail!(
      "WAF rule {} action {action} is not valid in {:?} phase",
      rule.name,
      rule.phase
    );
  }
  Ok(())
}

pub(super) fn validate_status(status: u16, rule_name: &str) -> anyhow::Result<()> {
  StatusCode::from_u16(status)
    .with_context(|| format!("WAF rule {rule_name} has invalid HTTP status {status}"))?;
  Ok(())
}

pub(super) fn validate_websocket_close_code(code: u16, rule_name: &str) -> anyhow::Result<()> {
  if code < 1000 || matches!(code, 1004..=1006) || (1016..3000).contains(&code) || code >= 5000 {
    bail!("WAF rule {rule_name} has invalid WebSocket close code {code}");
  }
  Ok(())
}

fn validate_header(name: &str, value: &str) -> anyhow::Result<()> {
  validate_header_name(name)?;
  HeaderValue::from_str(value).context("invalid WAF header value")?;
  Ok(())
}

fn validate_header_name(name: &str) -> anyhow::Result<()> {
  HeaderName::from_bytes(name.as_bytes()).context("invalid WAF header name")?;
  Ok(())
}

pub fn validate_access_log_field_configs(
  label: &str,
  fields: &[AccessLogFieldConfig],
) -> anyhow::Result<()> {
  let empty_functions = FunctionMap::new();
  validate_access_log_field_configs_with_functions(label, fields, &empty_functions, None)
}

fn validate_access_log_field_configs_with_functions(
  label: &str,
  fields: &[AccessLogFieldConfig],
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<()> {
  if fields.is_empty() {
    bail!("{label} must define at least one field");
  }

  let mut names = HashSet::new();
  for field in fields {
    validate_access_log_field_name(label, &field.name)?;
    if matches!(field.name.as_str(), "event" | "timestamp_unix_ms") {
      bail!("{label} field {} uses a reserved field name", field.name);
    }
    if !names.insert(field.name.as_str()) {
      bail!("{label} contains duplicate field {}", field.name);
    }
    let expression = Parser::new(&field.value)
      .parse()
      .with_context(|| format!("failed to parse {label} field {}", field.name))?;
    let expression = expression
      .analyze_for_phase_with_functions(WafPhase::Response, global_functions, route_functions)
      .with_context(|| format!("invalid {label} field {}", field.name))?;
    if expression
      .request_body_need_with_functions(global_functions, route_functions)
      .requires_prefix()
    {
      bail!(
        "{label} field {} cannot read request body bytes",
        field.name
      );
    }
  }

  Ok(())
}

pub(super) fn validate_access_log_field_name(label: &str, field_name: &str) -> anyhow::Result<()> {
  if field_name.is_empty()
    || field_name.len() > 64
    || !field_name
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
  {
    bail!("{label} field names must match [A-Za-z0-9_.-]{{1,64}}");
  }
  Ok(())
}

fn validate_person_proof_settings(rule_name: &str, action: &WafActionConfig) -> anyhow::Result<()> {
  let WafActionConfig::RequirePersonProof {
    person_proof_mode,
    difficulty,
    ttl_seconds,
    cookie,
    clearance,
    token_bindings,
    direct_peer_ipv4_prefix_bits,
    direct_peer_ipv6_prefix_bits,
    tcp_max_hop,
    success_tag,
    custom_frontend_url,
    challenge_redirect_status,
    session_path,
    verify_path,
    openapi_path,
    third_party_provider,
    provider,
    proof_kind,
    proof_challenge_kind,
    proof_label,
    site_key,
    secret_env,
    provider_endpoint,
    provider_timeout_ms,
    provider_max_response_body_bytes,
    method,
    algorithm,
    challenge_url,
    ..
  } = action
  else {
    unreachable!("validate_person_proof_settings requires require_person_proof action");
  };

  if method.is_some() {
    bail!(
      "WAF rule {rule_name} require_person_proof method is no longer supported; use person_proof_mode instead"
    );
  }
  if algorithm.is_some() {
    bail!(
      "WAF rule {rule_name} require_person_proof algorithm is no longer supported; use person_proof_mode instead"
    );
  }
  if challenge_url.is_some() {
    bail!(
      "WAF rule {rule_name} require_person_proof challenge_url is no longer supported; use custom_frontend_url instead"
    );
  }
  if person_proof_mode.uses_pow() && !(1..=30).contains(difficulty) {
    bail!("WAF rule {rule_name} require_person_proof difficulty must be between 1 and 30");
  }
  if !(1..=86_400).contains(ttl_seconds) {
    bail!(
      "WAF rule {rule_name} require_person_proof token_validity_seconds must be between 1 and 86400"
    );
  }
  if cookie.is_some() {
    bail!(
      "WAF rule {rule_name} require_person_proof cookie is no longer supported; use clearance.cookie.key and clearance.sources instead"
    );
  }
  person_proof_config::validate_clearance_settings(rule_name, clearance)?;
  if token_bindings.is_empty() {
    bail!("WAF rule {rule_name} require_person_proof token_bindings must not be empty");
  }
  let mut seen_bindings = HashSet::new();
  for binding in token_bindings {
    if !seen_bindings.insert(*binding) {
      bail!(
        "WAF rule {rule_name} require_person_proof token_bindings contains duplicate {}",
        binding.as_str()
      );
    }
    if *binding == PersonProofTokenBinding::TcpMaxHop && tcp_max_hop.is_none() {
      bail!(
        "WAF rule {rule_name} require_person_proof token binding tcp_max_hop requires tcp_max_hop"
      );
    }
  }
  if *direct_peer_ipv4_prefix_bits > 32 {
    bail!(
      "WAF rule {rule_name} require_person_proof direct_peer_ipv4_prefix_bits must be between 0 and 32"
    );
  }
  if *direct_peer_ipv6_prefix_bits > 128 {
    bail!(
      "WAF rule {rule_name} require_person_proof direct_peer_ipv6_prefix_bits must be between 0 and 128"
    );
  }
  if let Some(tag) = success_tag
    && (tag.is_empty() || !is_valid_rule_label(tag))
  {
    bail!("WAF rule {rule_name} require_person_proof success_tag exceeds tag size limits");
  }
  person_proof_config::validate_redirect_settings(
    rule_name,
    *person_proof_mode,
    custom_frontend_url.as_deref(),
    *challenge_redirect_status,
    session_path.as_deref(),
    verify_path.as_deref(),
    openapi_path.as_deref(),
    *third_party_provider,
    provider.as_deref(),
    proof_kind.as_deref(),
    proof_challenge_kind.as_deref(),
    proof_label.as_deref(),
    site_key.as_deref(),
    secret_env.as_deref(),
    provider_endpoint.as_deref(),
    *provider_timeout_ms,
    *provider_max_response_body_bytes,
  )?;
  Ok(())
}

pub(super) fn is_valid_rule_label(value: &str) -> bool {
  value.len() <= 32
    && value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
