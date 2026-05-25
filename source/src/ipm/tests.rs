use super::*;

fn runtime_with_policy(policy: IpmPolicyConfig) -> IpmRuntime {
  let actor = IpmActor {
    name: "deployer-token".to_string(),
    principal: "deployer".to_string(),
    subject: "deployer@example.com".to_string(),
    groups: vec!["ops".to_string()],
  };
  IpmRuntime {
    inner: Arc::new(IpmRuntimeInner {
      namespace: "oxibelt".to_string(),
      credentials: Vec::new(),
      principals: HashMap::from([("deployer".to_string(), actor)]),
      policies: HashMap::from([("test".to_string(), policy)]),
      principal_bindings: HashMap::from([("deployer".to_string(), vec!["test".to_string()])]),
      group_bindings: HashMap::new(),
      legacy_admin_env: "OXIBELT_ADMIN_TOKEN".to_string(),
      allow_legacy_bootstrap: false,
      break_glass_verifier: break_glass_verifier(),
    }),
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
  let actor = runtime.inner.principals["deployer"].clone();

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
  let actor = runtime.inner.principals["deployer"].clone();
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
  let actor = runtime.inner.principals["deployer"].clone();

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
fn legacy_bootstrap_bearer_is_ignored_when_disabled() {
  let bearer = std::env::var("PATH").expect("PATH should be available for tests");
  let runtime = IpmRuntime {
    inner: Arc::new(IpmRuntimeInner {
      namespace: "oxibelt".to_string(),
      credentials: Vec::new(),
      principals: HashMap::new(),
      policies: HashMap::new(),
      principal_bindings: HashMap::new(),
      group_bindings: HashMap::new(),
      legacy_admin_env: "PATH".to_string(),
      allow_legacy_bootstrap: false,
      break_glass_verifier: break_glass_verifier(),
    }),
  };

  assert!(runtime.actor_from_bearer(&bearer).is_none());
}

#[test]
fn legacy_bootstrap_bearer_still_works_when_allowed() {
  let bearer = std::env::var("PATH").expect("PATH should be available for tests");
  let runtime = IpmRuntime {
    inner: Arc::new(IpmRuntimeInner {
      namespace: "oxibelt".to_string(),
      credentials: Vec::new(),
      principals: HashMap::new(),
      policies: HashMap::new(),
      principal_bindings: HashMap::new(),
      group_bindings: HashMap::new(),
      legacy_admin_env: "PATH".to_string(),
      allow_legacy_bootstrap: true,
      break_glass_verifier: break_glass_verifier(),
    }),
  };

  let actor = runtime
    .actor_from_bearer(&bearer)
    .expect("legacy bootstrap actor should be returned");
  assert_eq!(actor.principal, "bootstrap-admin");
  assert_eq!(actor.groups, vec!["ipm-admin".to_string()]);
}

#[tokio::test]
async fn break_glass_access_bearer_is_admin_only() {
  let actor = IpmActor {
    name: "break-glass-token".to_string(),
    principal: "break-glass-admin".to_string(),
    subject: "break-glass".to_string(),
    groups: vec!["ipm-admin".to_string()],
  };
  let runtime = IpmRuntime {
    inner: Arc::new(IpmRuntimeInner {
      namespace: "oxibelt".to_string(),
      credentials: vec![IpmCredentialConfig {
        name: "break-glass-token".to_string(),
        principal: "break-glass-admin".to_string(),
        bearer_token_env: String::new(),
        break_glass_access_token_hash: Some(test_argon2id_hash("recovery-secret")),
      }],
      principals: HashMap::from([("break-glass-admin".to_string(), actor)]),
      policies: HashMap::new(),
      principal_bindings: HashMap::new(),
      group_bindings: HashMap::new(),
      legacy_admin_env: "OXIBELT_ADMIN_TOKEN".to_string(),
      allow_legacy_bootstrap: false,
      break_glass_verifier: break_glass_verifier(),
    }),
  };

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
  let actor = IpmActor {
    name: "break-glass-token".to_string(),
    principal: "break-glass-admin".to_string(),
    subject: "break-glass".to_string(),
    groups: vec!["ipm-admin".to_string()],
  };
  let runtime = IpmRuntime {
    inner: Arc::new(IpmRuntimeInner {
      namespace: "oxibelt".to_string(),
      credentials: vec![IpmCredentialConfig {
        name: "break-glass-token".to_string(),
        principal: "break-glass-admin".to_string(),
        bearer_token_env: String::new(),
        break_glass_access_token_hash: Some(test_argon2id_hash("recovery-secret")),
      }],
      principals: HashMap::from([("break-glass-admin".to_string(), actor)]),
      policies: HashMap::new(),
      principal_bindings: HashMap::new(),
      group_bindings: HashMap::new(),
      legacy_admin_env: "OXIBELT_ADMIN_TOKEN".to_string(),
      allow_legacy_bootstrap: false,
      break_glass_verifier: Arc::new(tokio::sync::Semaphore::new(0)),
    }),
  };

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
  let actor = IpmActor {
    name: "normal-token".to_string(),
    principal: "admin".to_string(),
    subject: "admin@example.com".to_string(),
    groups: vec!["ipm-admin".to_string()],
  };
  let runtime = IpmRuntime {
    inner: Arc::new(IpmRuntimeInner {
      namespace: "oxibelt".to_string(),
      credentials: vec![
        IpmCredentialConfig {
          name: "normal-token".to_string(),
          principal: "admin".to_string(),
          bearer_token_env: "PATH".to_string(),
          break_glass_access_token_hash: None,
        },
        IpmCredentialConfig {
          name: "break-glass-token".to_string(),
          principal: "admin".to_string(),
          bearer_token_env: String::new(),
          break_glass_access_token_hash: Some(test_argon2id_hash("recovery-secret")),
        },
      ],
      principals: HashMap::from([("admin".to_string(), actor)]),
      policies: HashMap::new(),
      principal_bindings: HashMap::new(),
      group_bindings: HashMap::new(),
      legacy_admin_env: "OXIBELT_ADMIN_TOKEN".to_string(),
      allow_legacy_bootstrap: false,
      break_glass_verifier: Arc::new(tokio::sync::Semaphore::new(0)),
    }),
  };

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
  let runtime = IpmRuntime {
    inner: Arc::new(IpmRuntimeInner {
      namespace: "oxibelt".to_string(),
      credentials: vec![IpmCredentialConfig {
        name: "break-glass-token".to_string(),
        principal: "break-glass-admin".to_string(),
        bearer_token_env: String::new(),
        break_glass_access_token_hash: Some(test_argon2id_hash("recovery-secret")),
      }],
      principals: HashMap::new(),
      policies: HashMap::new(),
      principal_bindings: HashMap::new(),
      group_bindings: HashMap::new(),
      legacy_admin_env: "PATH".to_string(),
      allow_legacy_bootstrap: true,
      break_glass_verifier: Arc::new(tokio::sync::Semaphore::new(0)),
    }),
  };

  let actor = runtime
    .admin_actor_from_bearer(&bearer)
    .await
    .expect("legacy bootstrap should not use break-glass limiter");
  assert_eq!(actor.principal, "bootstrap-admin");
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
