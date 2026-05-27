use super::*;

fn runtime_with_policy(policy: IpmPolicyConfig) -> IpmRuntime {
  IpmRuntime::test_with_actor_policy(
    "oxibelt",
    IpmActor {
      name: "deployer-token".to_string(),
      principal: "deployer".to_string(),
      subject: "deployer@example.com".to_string(),
      groups: vec!["ops".to_string()],
    },
    policy,
  )
}

fn runtime_from_snapshot(
  snapshot: IpmSnapshot,
  legacy_admin_env: &str,
  allow_legacy_bootstrap: bool,
  break_glass_verifier: Arc<tokio::sync::Semaphore>,
) -> IpmRuntime {
  IpmRuntime {
    inner: Arc::new(IpmRuntimeInner {
      namespace: "oxibelt".to_string(),
      static_snapshot: Arc::new(snapshot.clone()),
      snapshot: RwLock::new(Arc::new(snapshot)),
      store: None,
      last_refresh: RwLock::new(IpmRefreshState::ok(0)),
      legacy_admin_env: legacy_admin_env.to_string(),
      allow_legacy_bootstrap,
      break_glass_verifier,
    }),
  }
}

fn empty_runtime(legacy_admin_env: &str, allow_legacy_bootstrap: bool) -> IpmRuntime {
  runtime_from_snapshot(
    empty_snapshot(),
    legacy_admin_env,
    allow_legacy_bootstrap,
    break_glass_verifier(),
  )
}

fn empty_snapshot() -> IpmSnapshot {
  IpmSnapshot {
    generation: 0,
    fingerprint: 0,
    credentials: Vec::new(),
    principals: HashMap::new(),
    policies: HashMap::new(),
    principal_bindings: HashMap::new(),
    group_bindings: HashMap::new(),
    bindings: Vec::new(),
    counts: IpmSnapshotCounts::default(),
  }
}

fn principal(id: &str, groups: &[&str]) -> (String, IpmPrincipalRuntime) {
  (
    id.to_string(),
    IpmPrincipalRuntime {
      actor: IpmActor {
        name: id.to_string(),
        principal: id.to_string(),
        subject: format!("{id}@example.com"),
        groups: groups.iter().map(|group| (*group).to_string()).collect(),
      },
      enabled: true,
      source: IpmEntrySource::Config,
    },
  )
}

fn policy(name: &str, actions: &[&str]) -> (String, IpmPolicyRuntime) {
  (
    name.to_string(),
    IpmPolicyRuntime {
      policy: IpmPolicyConfig {
        name: name.to_string(),
        version: "2026-05-23".to_string(),
        statements: vec![IpmPolicyStatementConfig {
          effect: IpmPolicyEffect::Allow,
          actions: actions.iter().map(|action| (*action).to_string()).collect(),
          resources: vec!["*".to_string()],
          conditions: Vec::new(),
        }],
      },
      enabled: true,
      source: IpmEntrySource::Config,
    },
  )
}

fn subject_policy(name: &str, action: &str, subject: &str) -> (String, IpmPolicyRuntime) {
  (
    name.to_string(),
    IpmPolicyRuntime {
      policy: IpmPolicyConfig {
        name: name.to_string(),
        version: "2026-05-23".to_string(),
        statements: vec![IpmPolicyStatementConfig {
          effect: IpmPolicyEffect::Allow,
          actions: vec![action.to_string()],
          resources: vec!["*".to_string()],
          conditions: vec![IpmConditionConfig {
            operator: IpmConditionOperator::StringEquals,
            key: "principal.subject".to_string(),
            values: vec![subject.to_string()],
          }],
        }],
      },
      enabled: true,
      source: IpmEntrySource::Config,
    },
  )
}

fn bearer_env_credential(
  name: &str,
  principal: &str,
  bearer_token_env: &str,
) -> IpmCredentialRuntime {
  IpmCredentialRuntime {
    name: name.to_string(),
    principal: principal.to_string(),
    source: IpmEntrySource::Config,
    bearer_token_env: bearer_token_env.to_string(),
    break_glass_access_token_hash: None,
    enabled: true,
    revoked: false,
    expires_at: None,
    expires_at_unix: None,
    token_prefix: None,
    token_hash: None,
    token_hash_alg: None,
    previous_token_prefix: None,
    previous_token_hash: None,
    previous_token_overlap_until: None,
    previous_token_overlap_until_unix: None,
  }
}

fn break_glass_credential(name: &str, principal: &str, secret: &str) -> IpmCredentialRuntime {
  IpmCredentialRuntime {
    break_glass_access_token_hash: Some(test_argon2id_hash(secret)),
    bearer_token_env: String::new(),
    ..bearer_env_credential(name, principal, "")
  }
}

#[test]
fn explicit_deny_wins_over_allow() {
  let runtime = runtime_with_policy(IpmPolicyConfig {
    name: "test".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![
      IpmPolicyStatementConfig {
        effect: IpmPolicyEffect::Allow,
        actions: vec!["config:*".to_string()],
        resources: vec!["*".to_string()],
        conditions: Vec::new(),
      },
      IpmPolicyStatementConfig {
        effect: IpmPolicyEffect::Deny,
        actions: vec!["config:Load".to_string()],
        resources: vec!["*".to_string()],
        conditions: Vec::new(),
      },
    ],
  });
  let actor = runtime.snapshot().principals["deployer"].actor.clone();

  assert_eq!(
    runtime.authorize(
      &actor,
      "config:Load",
      "oxibelt:oxibelt:config:*",
      &IpmRequestContext::default()
    ),
    IpmDecision::Deny
  );
  assert_eq!(
    runtime.authorize(
      &actor,
      "config:Validate",
      "oxibelt:oxibelt:config:*",
      &IpmRequestContext::default()
    ),
    IpmDecision::Allow
  );
}

#[test]
fn conditions_must_match() {
  let runtime = runtime_with_policy(IpmPolicyConfig {
    name: "test".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: vec!["route:Invoke".to_string()],
      resources: vec!["oxibelt:oxibelt:route:app".to_string()],
      conditions: vec![IpmConditionConfig {
        operator: IpmConditionOperator::StringEquals,
        key: "request.method".to_string(),
        values: vec!["GET".to_string()],
      }],
    }],
  });
  let actor = runtime.snapshot().principals["deployer"].actor.clone();
  let mut context = IpmRequestContext {
    method: Some("POST".to_string()),
    ..IpmRequestContext::default()
  };

  assert_eq!(
    runtime.authorize(
      &actor,
      "route:Invoke",
      "oxibelt:oxibelt:route:app",
      &context
    ),
    IpmDecision::Deny
  );
  context.method = Some("GET".to_string());
  assert_eq!(
    runtime.authorize(
      &actor,
      "route:Invoke",
      "oxibelt:oxibelt:route:app",
      &context
    ),
    IpmDecision::Allow
  );
}

#[test]
fn missing_condition_values_do_not_match_negative_operators() {
  let runtime = runtime_with_policy(IpmPolicyConfig {
    name: "test".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![
      IpmPolicyStatementConfig {
        effect: IpmPolicyEffect::Allow,
        actions: vec!["route:Invoke".to_string()],
        resources: vec!["oxibelt:oxibelt:route:app".to_string()],
        conditions: vec![IpmConditionConfig {
          operator: IpmConditionOperator::StringNotEquals,
          key: "request.method".to_string(),
          values: vec!["POST".to_string()],
        }],
      },
      IpmPolicyStatementConfig {
        effect: IpmPolicyEffect::Allow,
        actions: vec!["stream:Connect".to_string()],
        resources: vec!["oxibelt:oxibelt:stream:app".to_string()],
        conditions: vec![IpmConditionConfig {
          operator: IpmConditionOperator::NotIpAddress,
          key: "request.source_ip".to_string(),
          values: vec!["192.0.2.0/24".to_string()],
        }],
      },
    ],
  });
  let actor = runtime.snapshot().principals["deployer"].actor.clone();

  assert_eq!(
    runtime.authorize(
      &actor,
      "route:Invoke",
      "oxibelt:oxibelt:route:app",
      &IpmRequestContext::default()
    ),
    IpmDecision::Deny
  );
  assert_eq!(
    runtime.authorize(
      &actor,
      "stream:Connect",
      "oxibelt:oxibelt:stream:app",
      &IpmRequestContext::default()
    ),
    IpmDecision::Deny
  );

  let context = IpmRequestContext {
    method: Some("GET".to_string()),
    source_ip: Some("198.51.100.10".parse().expect("test IP should parse")),
    ..IpmRequestContext::default()
  };
  assert_eq!(
    runtime.authorize(
      &actor,
      "route:Invoke",
      "oxibelt:oxibelt:route:app",
      &context
    ),
    IpmDecision::Allow
  );
  assert_eq!(
    runtime.authorize(
      &actor,
      "stream:Connect",
      "oxibelt:oxibelt:stream:app",
      &context
    ),
    IpmDecision::Allow
  );
}

#[test]
fn static_and_store_id_conflicts_fail_snapshot_merge() {
  let mut static_snapshot = empty_snapshot();
  static_snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ops"]).1);

  let store_snapshot = store::IpmStoreSnapshotParts {
    generation: 2,
    principals: vec![principal("admin", &[])],
    credentials: Vec::new(),
    policies: Vec::new(),
    bindings: Vec::new(),
  };

  let error = merge_store_snapshot(&static_snapshot, store_snapshot)
    .expect_err("conflicting store principal should be rejected");
  assert!(
    error
      .to_string()
      .contains("conflicts with static TOML principal")
  );
}

#[test]
fn db_current_and_previous_overlap_tokens_authenticate() {
  let current = token::generate_token().expect("token should generate");
  let previous = token::generate_token().expect("token should generate");
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot.credentials.push(IpmCredentialRuntime {
    name: "admin-token".to_string(),
    principal: "admin".to_string(),
    source: IpmEntrySource::Store,
    bearer_token_env: String::new(),
    break_glass_access_token_hash: None,
    enabled: true,
    revoked: false,
    expires_at: None,
    expires_at_unix: Some(now_unix().expect("now") + 3_600),
    token_prefix: Some(current.prefix),
    token_hash: Some(current.hash),
    token_hash_alg: Some(token::TOKEN_HASH_ALG.to_string()),
    previous_token_prefix: Some(previous.prefix),
    previous_token_hash: Some(previous.hash),
    previous_token_overlap_until: None,
    previous_token_overlap_until_unix: Some(now_unix().expect("now") + 300),
  });
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );

  assert_eq!(
    runtime
      .actor_from_bearer(&current.token)
      .map(|actor| actor.name),
    Some("admin-token".to_string())
  );
  assert_eq!(
    runtime
      .actor_from_bearer(&previous.token)
      .map(|actor| actor.name),
    Some("admin-token".to_string())
  );
}

#[test]
fn expired_revoked_and_expired_previous_tokens_are_denied() {
  let current = token::generate_token().expect("token should generate");
  let previous = token::generate_token().expect("token should generate");
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot.credentials.push(IpmCredentialRuntime {
    name: "admin-token".to_string(),
    principal: "admin".to_string(),
    source: IpmEntrySource::Store,
    bearer_token_env: String::new(),
    break_glass_access_token_hash: None,
    enabled: true,
    revoked: true,
    expires_at: None,
    expires_at_unix: Some(now_unix().expect("now") - 1),
    token_prefix: Some(current.prefix),
    token_hash: Some(current.hash),
    token_hash_alg: Some(token::TOKEN_HASH_ALG.to_string()),
    previous_token_prefix: Some(previous.prefix),
    previous_token_hash: Some(previous.hash),
    previous_token_overlap_until: None,
    previous_token_overlap_until_unix: Some(now_unix().expect("now") - 1),
  });
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );

  assert!(runtime.actor_from_bearer(&current.token).is_none());
  assert!(runtime.actor_from_bearer(&previous.token).is_none());
}

#[test]
fn token_digest_matching_accepts_only_expected_token() {
  let generated = token::generate_token().expect("token should generate");
  assert!(token::token_hash_matches(
    Some(token::TOKEN_HASH_ALG),
    &generated.hash,
    &generated.token
  ));
  assert!(!token::token_hash_matches(
    Some(token::TOKEN_HASH_ALG),
    &generated.hash,
    "obt_v1_wrong"
  ));
}

#[test]
fn legacy_bootstrap_bearer_is_ignored_when_disabled() {
  let bearer = std::env::var("PATH").expect("PATH should be available for tests");
  let runtime = empty_runtime("PATH", false);

  assert!(runtime.actor_from_bearer(&bearer).is_none());
}

#[test]
fn legacy_bootstrap_bearer_still_works_when_allowed() {
  let bearer = std::env::var("PATH").expect("PATH should be available for tests");
  let runtime = empty_runtime("PATH", true);

  let actor = runtime
    .actor_from_bearer(&bearer)
    .expect("legacy bootstrap actor should be returned");
  assert_eq!(actor.principal, "bootstrap-admin");
  assert_eq!(actor.groups, vec!["ipm-admin".to_string()]);
}

#[tokio::test]
async fn break_glass_access_bearer_is_admin_only() {
  let mut snapshot = empty_snapshot();
  snapshot.principals.insert(
    "break-glass-admin".to_string(),
    principal("break-glass-admin", &["ipm-admin"]).1,
  );
  snapshot.credentials.push(break_glass_credential(
    "break-glass-token",
    "break-glass-admin",
    "recovery-secret",
  ));
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );

  assert!(runtime.actor_from_bearer("recovery-secret").is_none());
  let actor = runtime
    .admin_actor_from_bearer("recovery-secret")
    .await
    .expect("break-glass access credential should authenticate on admin listeners");
  assert_eq!(actor.name, "break-glass-token");
  assert_eq!(actor.principal, "break-glass-admin");
}

#[tokio::test]
async fn break_glass_access_fails_closed_when_limiter_is_saturated() {
  let mut snapshot = empty_snapshot();
  snapshot.principals.insert(
    "break-glass-admin".to_string(),
    principal("break-glass-admin", &["ipm-admin"]).1,
  );
  snapshot.credentials.push(break_glass_credential(
    "break-glass-token",
    "break-glass-admin",
    "recovery-secret",
  ));
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    Arc::new(tokio::sync::Semaphore::new(0)),
  );

  assert!(
    runtime
      .admin_actor_from_bearer("recovery-secret")
      .await
      .is_none()
  );
}

#[tokio::test]
async fn low_cost_admin_credentials_do_not_need_break_glass_limiter() {
  let bearer = std::env::var("PATH").expect("PATH should be available for tests");
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot
    .credentials
    .push(bearer_env_credential("normal-token", "admin", "PATH"));
  snapshot.credentials.push(break_glass_credential(
    "break-glass-token",
    "admin",
    "recovery-secret",
  ));
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    Arc::new(tokio::sync::Semaphore::new(0)),
  );

  let actor = runtime
    .admin_actor_from_bearer(&bearer)
    .await
    .expect("normal bearer credential should not use break-glass limiter");
  assert_eq!(actor.name, "normal-token");
  assert_eq!(actor.principal, "admin");
}

#[tokio::test]
async fn legacy_bootstrap_does_not_need_break_glass_limiter() {
  let bearer = std::env::var("PATH").expect("PATH should be available for tests");
  let mut snapshot = empty_snapshot();
  snapshot.credentials.push(break_glass_credential(
    "break-glass-token",
    "break-glass-admin",
    "recovery-secret",
  ));
  let runtime = runtime_from_snapshot(
    snapshot,
    "PATH",
    true,
    Arc::new(tokio::sync::Semaphore::new(0)),
  );

  let actor = runtime
    .admin_actor_from_bearer(&bearer)
    .await
    .expect("legacy bootstrap should not use break-glass limiter");
  assert_eq!(actor.principal, "bootstrap-admin");
}

#[test]
fn non_admin_cannot_assign_credential_to_admin_principal() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();

  let error = runtime
    .ensure_actor_may_assign_credential_principal(&actor, None, "admin")
    .expect_err("non-admin actor must not mint credentials for admin principal");

  assert!(error.to_string().contains("requires an admin-capable"));
}

#[test]
fn non_admin_cannot_grant_ipm_admin_group() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();
  let groups = vec!["ipm-admin".to_string()];

  let error = runtime
    .ensure_actor_may_create_principal(&actor, "new-admin", "new-admin@example.com", &groups)
    .expect_err("non-admin actor must not create an ipm-admin principal");

  assert!(error.to_string().contains("requires an admin-capable"));
}

#[test]
fn non_admin_cannot_grant_group_bound_admin_policy() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  snapshot.policies.insert(
    "admin-policy".to_string(),
    policy("admin-policy", &["ipm:*"]).1,
  );
  snapshot
    .group_bindings
    .insert("ops-admin".to_string(), vec!["admin-policy".to_string()]);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();
  let groups = vec!["ops-admin".to_string()];

  let error = runtime
    .ensure_actor_may_create_principal(&actor, "new-admin", "new-admin@example.com", &groups)
    .expect_err("non-admin actor must not join a group with admin policy bindings");

  assert!(error.to_string().contains("requires an admin-capable"));
}

#[test]
fn non_admin_cannot_patch_subject_into_admin_policy_condition() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  snapshot.policies.insert(
    "subject-admin".to_string(),
    subject_policy("subject-admin", "ipm:UpdateConfig", "admin@example.com").1,
  );
  snapshot
    .group_bindings
    .insert("ops".to_string(), vec!["subject-admin".to_string()]);
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();

  let error = runtime
    .ensure_actor_may_patch_principal(&actor, "operator", Some("admin@example.com"), None)
    .expect_err("non-admin actor must not change subject into an admin-capable condition");

  assert!(error.to_string().contains("requires an admin-capable"));
}

#[test]
fn non_admin_cannot_create_or_bind_admin_policy() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  snapshot.policies.insert(
    "admin-policy".to_string(),
    policy("admin-policy", &["ipm:*"]).1,
  );
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["operator"].actor.clone();
  let admin_policy = runtime.snapshot().policies["admin-policy"].policy.clone();
  let create_error = runtime
    .ensure_actor_may_create_policy(&actor, &admin_policy)
    .expect_err("non-admin actor must not create admin-capable policies");
  assert!(
    create_error
      .to_string()
      .contains("requires an admin-capable")
  );

  let binding = IpmBindingCreate {
    id: Some("operator-admin".to_string()),
    principal: Some("operator".to_string()),
    group: None,
    policy: "admin-policy".to_string(),
    enabled: Some(true),
  };
  let bind_error = runtime
    .ensure_actor_may_create_binding(&actor, &binding)
    .expect_err("non-admin actor must not bind admin-capable policies");
  assert!(bind_error.to_string().contains("requires an admin-capable"));
}

#[test]
fn unknown_group_binding_is_rejected_before_refresh() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot.policies.insert(
    "read-only".to_string(),
    policy("read-only", &["ipm:GetStatus"]).1,
  );
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["admin"].actor.clone();
  let binding = IpmBindingCreate {
    id: Some("missing-group".to_string()),
    principal: None,
    group: Some("missing".to_string()),
    policy: "read-only".to_string(),
    enabled: Some(true),
  };

  let error = runtime
    .ensure_actor_may_create_binding(&actor, &binding)
    .expect_err("unknown groups must not be committed to the IPM store");

  assert!(error.to_string().contains("unknown IPM group missing"));
}

#[test]
fn admin_actor_can_grant_admin_authority() {
  let mut snapshot = empty_snapshot();
  snapshot
    .principals
    .insert("admin".to_string(), principal("admin", &["ipm-admin"]).1);
  snapshot
    .principals
    .insert("operator".to_string(), principal("operator", &["ops"]).1);
  snapshot.policies.insert(
    "admin-policy".to_string(),
    policy("admin-policy", &["ipm:*"]).1,
  );
  let runtime = runtime_from_snapshot(
    snapshot,
    "OXIBELT_ADMIN_TOKEN",
    false,
    break_glass_verifier(),
  );
  let actor = runtime.snapshot().principals["admin"].actor.clone();
  let groups = vec!["ipm-admin".to_string()];
  let binding = IpmBindingCreate {
    id: Some("operator-admin".to_string()),
    principal: Some("operator".to_string()),
    group: None,
    policy: "admin-policy".to_string(),
    enabled: Some(true),
  };

  runtime
    .ensure_actor_may_create_principal(&actor, "new-admin", "new-admin@example.com", &groups)
    .expect("admin actor should be able to create admin-capable principals");
  let admin_policy = runtime.snapshot().policies["admin-policy"].policy.clone();
  runtime
    .ensure_actor_may_create_policy(&actor, &admin_policy)
    .expect("admin actor should be able to create admin-capable policies");
  runtime
    .ensure_actor_may_create_binding(&actor, &binding)
    .expect("admin actor should be able to bind admin-capable policies");
}

fn test_argon2id_hash(secret: &str) -> String {
  use argon2::password_hash::SaltString;
  use argon2::{Algorithm, Params, PasswordHasher, Version};

  let params = Params::new(8, 1, 1, None).expect("test Argon2id params should build");
  let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
  let salt =
    SaltString::encode_b64(b"oxibelt-test-salt").expect("test salt should be valid base64 salt");
  argon2
    .hash_password(secret.as_bytes(), &salt)
    .expect("test Argon2id hash should build")
    .to_string()
}
