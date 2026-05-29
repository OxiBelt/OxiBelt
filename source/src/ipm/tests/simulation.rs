use super::*;

#[test]
fn uses_supplied_request_context() {
  let runtime = runtime_with_policy(IpmPolicyConfig {
    name: "test".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: vec!["route:Invoke".to_string()],
      resources: vec!["oxibelt:oxibelt:route:app".to_string()],
      conditions: vec![IpmConditionConfig {
        operator: IpmConditionOperator::IpAddress,
        key: "request.source_ip".to_string(),
        values: vec!["10.0.0.5/32".to_string()],
      }],
    }],
  });
  let actor = runtime.snapshot().principals["deployer"].actor.clone();

  let denied = simulation_request(serde_json::json!({
    "action": "route:Invoke",
    "resource": "oxibelt:oxibelt:route:app",
    "context": { "source_ip": "10.0.0.6" }
  }));
  let allowed = simulation_request(serde_json::json!({
    "action": "route:Invoke",
    "resource": "oxibelt:oxibelt:route:app",
    "context": { "source_ip": "10.0.0.5" }
  }));

  assert_eq!(
    runtime
      .admin_prepare_simulation(&actor, &IpmRequestContext::default(), denied)
      .expect("simulation should prepare")
      .response
      .decision,
    "deny"
  );
  assert_eq!(
    runtime
      .admin_prepare_simulation(&actor, &IpmRequestContext::default(), allowed)
      .expect("simulation should prepare")
      .response
      .decision,
    "allow"
  );
}

#[test]
fn response_lists_claim_keys_without_echoing_claim_values() {
  let runtime = runtime_with_policy(IpmPolicyConfig {
    name: "claims".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: vec!["route:Invoke".to_string()],
      resources: vec!["oxibelt:oxibelt:route:app".to_string()],
      conditions: vec![IpmConditionConfig {
        operator: IpmConditionOperator::StringEquals,
        key: "claim.env".to_string(),
        values: vec!["prod".to_string()],
      }],
    }],
  });
  let actor = runtime.snapshot().principals["deployer"].actor.clone();
  let request = simulation_request(serde_json::json!({
    "action": "route:Invoke",
    "resource": "oxibelt:oxibelt:route:app",
    "context": { "claims": { "secret": "do-not-return", "env": "prod" } }
  }));

  let prepared = runtime
    .admin_prepare_simulation(&actor, &IpmRequestContext::default(), request)
    .expect("simulation should prepare");
  let response = serde_json::to_value(&prepared.response).expect("response should serialize");

  assert_eq!(prepared.response.decision, "allow");
  assert_eq!(prepared.response.context.claim_keys, vec!["env", "secret"]);
  assert_eq!(
    response["context"]["claim_keys"],
    serde_json::json!(["env", "secret"])
  );
  assert!(
    !response.to_string().contains("do-not-return"),
    "simulation response must not echo claim values"
  );
}

#[test]
fn resolves_target_principal() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &[]).1);
  snapshot.principals.insert(
    "deployer".to_string(),
    principal("deployer", &["deployers"]).1,
  );
  snapshot
    .policies
    .insert("load".to_string(), policy("load", &["config:Load"]).1);
  snapshot
    .principal_bindings
    .insert("deployer".to_string(), vec!["load".to_string()]);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();
  let request = simulation_request(serde_json::json!({
    "action": "config:Load",
    "resource": "oxibelt:oxibelt:config:*",
    "target": { "principal": "deployer" }
  }));

  let prepared = runtime
    .admin_prepare_simulation(&actor, &IpmRequestContext::default(), request)
    .expect("simulation should prepare");

  assert_eq!(prepared.response.decision, "allow");
  assert_eq!(prepared.response.target.principal, "deployer");
  assert_eq!(
    prepared.requirements.target_principals,
    vec!["deployer".to_string()]
  );
}

#[test]
fn resolves_target_credential() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &[]).1);
  snapshot
    .principals
    .insert("deployer".to_string(), principal("deployer", &[]).1);
  snapshot
    .credentials
    .push(bearer_env_credential("deploy-token", "deployer", "PATH"));
  snapshot.policies.insert(
    "apply".to_string(),
    policy("apply", &["dynamic-policy:Apply"]).1,
  );
  snapshot
    .principal_bindings
    .insert("deployer".to_string(), vec!["apply".to_string()]);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();
  let request = simulation_request(serde_json::json!({
    "action": "dynamic-policy:Apply",
    "resource": "oxibelt:oxibelt:dynamic-policy:source/oxibeltctl/name/block",
    "target": { "credential": "deploy-token" }
  }));

  let prepared = runtime
    .admin_prepare_simulation(&actor, &IpmRequestContext::default(), request)
    .expect("simulation should prepare");

  assert_eq!(prepared.response.decision, "allow");
  assert_eq!(prepared.response.target.principal, "deployer");
  assert_eq!(
    prepared.requirements.target_credentials,
    vec!["deploy-token".to_string()]
  );
  assert_eq!(
    prepared.requirements.target_principals,
    vec!["deployer".to_string()]
  );
}

#[test]
fn rejects_inactive_target_credentials() {
  let base = bearer_env_credential("deploy-token", "deployer", "PATH");
  let mut disabled = base.clone();
  disabled.enabled = false;
  let mut revoked = base.clone();
  revoked.revoked = true;
  let mut expired = base;
  expired.expires_at_unix = Some(0);

  for (label, credential) in [
    ("disabled", disabled),
    ("revoked", revoked),
    ("expired", expired),
  ] {
    let mut snapshot = empty_snapshot();
    snapshot.principals.insert(
      "deployer".to_string(),
      principal("deployer", &["deployers"]).1,
    );
    snapshot.credentials.push(credential);
    let runtime = runtime_from_snapshot(
      snapshot,
      "OXIBELT_ADMIN_TOKEN",
      false,
      break_glass_verifier(),
    );
    let actor = IpmActor {
      name: "operator-token".to_string(),
      principal: "operator".to_string(),
      subject: "operator@example.com".to_string(),
      groups: Vec::new(),
    };
    let request = simulation_request(serde_json::json!({
      "action": "config:Load",
      "resource": "oxibelt:oxibelt:config:*",
      "target": { "credential": "deploy-token" }
    }));

    let error = runtime
      .admin_prepare_simulation(&actor, &IpmRequestContext::default(), request)
      .expect_err(label);
    assert!(error.to_string().contains("is not active"), "{error}");
  }
}

#[test]
fn overlay_can_change_policy_decision() {
  let runtime = runtime_with_policy(IpmPolicyConfig {
    name: "base".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: vec!["config:Load".to_string()],
      resources: vec!["*".to_string()],
      conditions: Vec::new(),
    }],
  });
  let actor = runtime.snapshot().principals["deployer"].actor.clone();
  let request = simulation_request(serde_json::json!({
    "action": "config:Load",
    "resource": "oxibelt:oxibelt:config:*",
    "overlay": {
      "policies": [{
        "name": "deny-load",
        "statements": [{
          "effect": "deny",
          "actions": ["config:Load"],
          "resources": ["*"]
        }]
      }],
      "bindings": [{
        "group": "ops",
        "policy": "deny-load"
      }]
    }
  }));

  let prepared = runtime
    .admin_prepare_simulation(&actor, &IpmRequestContext::default(), request)
    .expect("simulation should prepare");

  assert_eq!(prepared.response.decision, "deny");
  assert_eq!(prepared.response.overlay.policies, 1);
  assert_eq!(prepared.response.overlay.bindings, 1);
  assert_eq!(
    prepared.requirements.overlay_policies,
    vec!["deny-load".to_string()]
  );
}

fn simulation_request(value: serde_json::Value) -> IpmSimulationRequest {
  serde_json::from_value(value).expect("simulation request should parse")
}
