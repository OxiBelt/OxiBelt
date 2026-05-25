use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, bail};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use http::HeaderMap;

use crate::config::{
  IpmConditionConfig, IpmConditionOperator, IpmCredentialConfig, IpmPolicyConfig, IpmPolicyEffect,
  IpmPolicyStatementConfig,
};

mod store;

#[derive(Debug, Clone, serde::Serialize)]
pub struct IpmActor {
  pub name: String,
  pub principal: String,
  pub subject: String,
  pub groups: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct IpmRequestContext {
  pub source_ip: Option<IpAddr>,
  pub method: Option<String>,
  pub host: Option<String>,
  pub path: Option<String>,
  pub route: Option<String>,
  pub protocol: Option<String>,
  pub claims: HashMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IpmDecision {
  Allow,
  Deny,
}

#[derive(Clone)]
pub struct IpmRuntime {
  inner: Arc<IpmRuntimeInner>,
}

struct IpmRuntimeInner {
  namespace: String,
  credentials: Vec<IpmCredentialConfig>,
  principals: HashMap<String, IpmActor>,
  policies: HashMap<String, IpmPolicyConfig>,
  principal_bindings: HashMap<String, Vec<String>>,
  group_bindings: HashMap<String, Vec<String>>,
  legacy_admin_env: String,
  allow_legacy_bootstrap: bool,
}

#[derive(Clone, Copy)]
enum CredentialScope {
  Admin,
  Downstream,
}

impl IpmRuntime {
  pub async fn new(config: &crate::config::Config) -> anyhow::Result<Self> {
    if config.ipm.enabled
      && let Some(backend_name) = config.ipm_backend_name()
    {
      let Some(backend) = config
        .shared_state
        .backends
        .iter()
        .find(|backend| backend.name == backend_name)
      else {
        bail!("IPM backend {backend_name} was not found");
      };
      match store::connect_postgres_pool(backend).await {
        Ok(pool) => {
          store::init_postgres(&pool)
            .await
            .context("failed to initialize IPM PostgreSQL tables")?;
        }
        Err(error) if !config.ipm.fail_closed => {
          tracing::warn!(error = %error, "IPM PostgreSQL connection failed; using static IPM config only");
        }
        Err(error) => return Err(error).context("failed to connect IPM PostgreSQL backend"),
      }
    }

    let principals = config
      .ipm
      .principals
      .iter()
      .map(|principal| {
        (
          principal.id.clone(),
          IpmActor {
            name: principal.id.clone(),
            principal: principal.id.clone(),
            subject: principal.subject.clone(),
            groups: principal.groups.clone(),
          },
        )
      })
      .collect::<HashMap<_, _>>();

    let policies = config
      .ipm
      .policies
      .iter()
      .map(|policy| (policy.name.clone(), policy.clone()))
      .collect::<HashMap<_, _>>();

    let mut principal_bindings: HashMap<String, Vec<String>> = HashMap::new();
    let mut group_bindings: HashMap<String, Vec<String>> = HashMap::new();
    for binding in &config.ipm.bindings {
      if let Some(principal) = &binding.principal {
        principal_bindings
          .entry(principal.clone())
          .or_default()
          .push(binding.policy.clone());
      }
      if let Some(group) = &binding.group {
        group_bindings
          .entry(group.clone())
          .or_default()
          .push(binding.policy.clone());
      }
    }

    Ok(Self {
      inner: Arc::new(IpmRuntimeInner {
        namespace: config.ipm.namespace.clone(),
        credentials: config.ipm.credentials.clone(),
        principals,
        policies,
        principal_bindings,
        group_bindings,
        legacy_admin_env: config.admin.bearer_token_env.clone(),
        allow_legacy_bootstrap: !config.ipm.enabled,
      }),
    })
  }

  pub fn namespace(&self) -> &str {
    &self.inner.namespace
  }

  pub fn actor_from_headers(&self, headers: &HeaderMap) -> Option<IpmActor> {
    let bearer = headers
      .get(http::header::AUTHORIZATION)
      .and_then(|value| value.to_str().ok())
      .and_then(|value| value.strip_prefix("Bearer "))?;
    self.actor_from_bearer(bearer)
  }

  pub fn admin_actor_from_headers(&self, headers: &HeaderMap) -> Option<IpmActor> {
    let bearer = headers
      .get(http::header::AUTHORIZATION)
      .and_then(|value| value.to_str().ok())
      .and_then(|value| value.strip_prefix("Bearer "))?;
    self.admin_actor_from_bearer(bearer)
  }

  pub fn actor_from_bearer(&self, bearer: &str) -> Option<IpmActor> {
    self.actor_from_bearer_for_scope(bearer, CredentialScope::Downstream)
  }

  pub fn admin_actor_from_bearer(&self, bearer: &str) -> Option<IpmActor> {
    self.actor_from_bearer_for_scope(bearer, CredentialScope::Admin)
  }

  fn actor_from_bearer_for_scope(&self, bearer: &str, scope: CredentialScope) -> Option<IpmActor> {
    for credential in &self.inner.credentials {
      if credential_matches(credential, bearer, scope)
        && let Some(actor) = self.inner.principals.get(&credential.principal)
      {
        let mut actor = actor.clone();
        actor.name = credential.name.clone();
        return Some(actor);
      }
    }

    if self.inner.allow_legacy_bootstrap && bearer_matches_env(&self.inner.legacy_admin_env, bearer)
    {
      return Some(IpmActor {
        name: "bootstrap-admin".to_string(),
        principal: "bootstrap-admin".to_string(),
        subject: "bootstrap-admin".to_string(),
        groups: vec!["ipm-admin".to_string()],
      });
    }

    None
  }

  pub fn authorize(
    &self,
    actor: &IpmActor,
    action: &str,
    resource: &str,
    context: &IpmRequestContext,
  ) -> IpmDecision {
    let policies = self.policies_for_actor(actor);
    let mut saw_allow = false;
    for policy in policies {
      for statement in &policy.statements {
        if !statement_matches(actor, action, resource, context, statement) {
          continue;
        }
        match statement.effect {
          IpmPolicyEffect::Deny => return IpmDecision::Deny,
          IpmPolicyEffect::Allow => saw_allow = true,
        }
      }
    }
    if saw_allow {
      IpmDecision::Allow
    } else {
      IpmDecision::Deny
    }
  }

  pub fn list_principals(&self) -> Vec<IpmActor> {
    let mut principals = self
      .inner
      .principals
      .values()
      .cloned()
      .collect::<Vec<IpmActor>>();
    principals.sort_by(|left, right| left.principal.cmp(&right.principal));
    principals
  }

  pub fn list_policies(&self) -> Vec<IpmPolicyConfig> {
    let mut policies = self
      .inner
      .policies
      .values()
      .cloned()
      .collect::<Vec<IpmPolicyConfig>>();
    policies.sort_by(|left, right| left.name.cmp(&right.name));
    policies
  }

  pub fn list_credentials(&self) -> Vec<RedactedIpmCredential> {
    let mut credentials = self
      .inner
      .credentials
      .iter()
      .map(|credential| RedactedIpmCredential {
        name: credential.name.clone(),
        principal: credential.principal.clone(),
        bearer_token_env: credential.bearer_token_env.clone(),
        break_glass_access: credential.break_glass_access_token_hash.is_some(),
      })
      .collect::<Vec<_>>();
    credentials.sort_by(|left, right| left.name.cmp(&right.name));
    credentials
  }

  #[cfg(test)]
  pub(crate) fn test_with_actor_policy(
    namespace: &str,
    actor: IpmActor,
    policy: IpmPolicyConfig,
  ) -> Self {
    let principal = actor.principal.clone();
    let policy_name = policy.name.clone();
    Self {
      inner: Arc::new(IpmRuntimeInner {
        namespace: namespace.to_string(),
        credentials: Vec::new(),
        principals: HashMap::from([(principal.clone(), actor)]),
        policies: HashMap::from([(policy_name.clone(), policy)]),
        principal_bindings: HashMap::from([(principal, vec![policy_name])]),
        group_bindings: HashMap::new(),
        legacy_admin_env: "OXIBELT_ADMIN_TOKEN".to_string(),
        allow_legacy_bootstrap: false,
      }),
    }
  }

  fn policies_for_actor(&self, actor: &IpmActor) -> Vec<&IpmPolicyConfig> {
    let mut names = Vec::new();
    if let Some(policies) = self.inner.principal_bindings.get(&actor.principal) {
      names.extend(policies.iter().cloned());
    }
    for group in &actor.groups {
      if group == "ipm-admin" {
        return vec![bootstrap_admin_policy()];
      }
      if let Some(policies) = self.inner.group_bindings.get(group) {
        names.extend(policies.iter().cloned());
      }
    }
    let mut seen = HashSet::new();
    names
      .into_iter()
      .filter(|name| seen.insert(name.clone()))
      .filter_map(|name| self.inner.policies.get(&name))
      .collect()
  }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactedIpmCredential {
  pub name: String,
  pub principal: String,
  pub bearer_token_env: String,
  pub break_glass_access: bool,
}

pub fn resource(namespace: &str, service: &str, name: &str) -> String {
  format!("oxibelt:{namespace}:{service}:{name}")
}

pub fn default_context() -> IpmRequestContext {
  IpmRequestContext::default()
}

fn statement_matches(
  actor: &IpmActor,
  action: &str,
  resource: &str,
  context: &IpmRequestContext,
  statement: &IpmPolicyStatementConfig,
) -> bool {
  statement
    .actions
    .iter()
    .any(|pattern| pattern_matches(pattern, action))
    && statement
      .resources
      .iter()
      .any(|pattern| pattern_matches(pattern, resource))
    && statement
      .conditions
      .iter()
      .all(|condition| condition_matches(actor, resource, context, condition))
}

fn condition_matches(
  actor: &IpmActor,
  resource: &str,
  context: &IpmRequestContext,
  condition: &IpmConditionConfig,
) -> bool {
  let actual = condition_values(actor, resource, context, &condition.key);
  if actual.is_empty() {
    return false;
  }
  match condition.operator {
    IpmConditionOperator::StringEquals => actual
      .iter()
      .any(|actual| condition.values.iter().any(|expected| actual == expected)),
    IpmConditionOperator::StringNotEquals => actual
      .iter()
      .all(|actual| condition.values.iter().all(|expected| actual != expected)),
    IpmConditionOperator::StringLike => actual.iter().any(|actual| {
      condition
        .values
        .iter()
        .any(|expected| pattern_matches(expected, actual))
    }),
    IpmConditionOperator::IpAddress => actual
      .iter()
      .any(|actual| ip_condition(actual, &condition.values, true)),
    IpmConditionOperator::NotIpAddress => actual
      .iter()
      .all(|actual| ip_condition(actual, &condition.values, false)),
    IpmConditionOperator::Bool => actual.iter().any(|actual| {
      condition
        .values
        .iter()
        .any(|expected| actual.eq_ignore_ascii_case(expected))
    }),
    IpmConditionOperator::DateBefore | IpmConditionOperator::DateAfter => {
      actual.iter().any(|actual| {
        let Ok(actual) = actual.parse::<i64>() else {
          return false;
        };
        condition.values.iter().any(|expected| {
          expected
            .parse::<i64>()
            .is_ok_and(|expected| match condition.operator {
              IpmConditionOperator::DateBefore => actual < expected,
              IpmConditionOperator::DateAfter => actual > expected,
              _ => false,
            })
        })
      })
    }
  }
}

fn condition_values(
  actor: &IpmActor,
  resource: &str,
  context: &IpmRequestContext,
  key: &str,
) -> Vec<String> {
  match key {
    "principal.subject" => vec![actor.subject.clone()],
    "principal.groups" => actor.groups.clone(),
    "request.source_ip" => context
      .source_ip
      .map(|ip| ip.to_string())
      .into_iter()
      .collect(),
    "request.method" => context.method.clone().into_iter().collect(),
    "request.host" => context.host.clone().into_iter().collect(),
    "request.path" => context.path.clone().into_iter().collect(),
    "request.route" => context.route.clone().into_iter().collect(),
    "request.protocol" => context.protocol.clone().into_iter().collect(),
    "resource.service" => resource_parts(resource)
      .map(|parts| parts.0)
      .into_iter()
      .collect(),
    "resource.name" => resource_parts(resource)
      .map(|parts| parts.1)
      .into_iter()
      .collect(),
    "time.now" => now_unix()
      .ok()
      .map(|now| now.to_string())
      .into_iter()
      .collect(),
    _ if key.starts_with("claim.") => context
      .claims
      .get(&key["claim.".len()..])
      .cloned()
      .into_iter()
      .collect(),
    _ => Vec::new(),
  }
}

fn resource_parts(resource: &str) -> Option<(String, String)> {
  let parts = resource.splitn(4, ':').collect::<Vec<_>>();
  if parts.len() == 4 && parts[0] == "oxibelt" {
    Some((parts[2].to_string(), parts[3].to_string()))
  } else {
    None
  }
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
  if pattern == "*" {
    return true;
  }
  let mut remainder = value;
  let mut first = true;
  for part in pattern.split('*') {
    if part.is_empty() {
      continue;
    }
    let Some(index) = remainder.find(part) else {
      return false;
    };
    if first && !pattern.starts_with('*') && index != 0 {
      return false;
    }
    remainder = &remainder[index + part.len()..];
    first = false;
  }
  pattern.ends_with('*') || remainder.is_empty()
}

fn ip_condition(actual: &str, expected: &[String], positive: bool) -> bool {
  let Ok(ip) = actual.parse::<IpAddr>() else {
    return !positive;
  };
  let matched = expected
    .iter()
    .any(|cidr| crate::identity::Cidr::parse(cidr).is_ok_and(|cidr| cidr.contains(ip)));
  if positive { matched } else { !matched }
}

fn bearer_matches_env(env_name: &str, actual: &str) -> bool {
  if env_name.trim().is_empty() {
    return false;
  }
  std::env::var(env_name).ok().is_some_and(|expected| {
    if expected.is_empty() {
      return false;
    }
    let expected_digest = ring::digest::digest(&ring::digest::SHA256, expected.as_bytes());
    let actual_digest = ring::digest::digest(&ring::digest::SHA256, actual.as_bytes());
    use subtle::ConstantTimeEq;
    expected_digest
      .as_ref()
      .ct_eq(actual_digest.as_ref())
      .into()
  })
}

fn credential_matches(
  credential: &IpmCredentialConfig,
  bearer: &str,
  scope: CredentialScope,
) -> bool {
  if bearer_matches_env(&credential.bearer_token_env, bearer) {
    return true;
  }
  if !matches!(scope, CredentialScope::Admin) {
    return false;
  }
  credential
    .break_glass_access_token_hash
    .as_deref()
    .is_some_and(|hash| bearer_matches_argon2id_hash(hash, bearer))
}

fn bearer_matches_argon2id_hash(hash: &str, actual: &str) -> bool {
  if hash.trim().is_empty() || actual.is_empty() {
    return false;
  }
  let Ok(parsed) = PasswordHash::new(hash) else {
    return false;
  };
  Argon2::default()
    .verify_password(actual.as_bytes(), &parsed)
    .is_ok()
}

fn now_unix() -> anyhow::Result<i64> {
  let duration = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_err(|_| anyhow::anyhow!("system clock is before UNIX epoch"))?;
  i64::try_from(duration.as_secs()).map_err(Into::into)
}

fn bootstrap_admin_policy() -> &'static IpmPolicyConfig {
  static POLICY: std::sync::OnceLock<IpmPolicyConfig> = std::sync::OnceLock::new();
  POLICY.get_or_init(|| IpmPolicyConfig {
    name: "bootstrap-admin".to_string(),
    version: "2026-05-23".to_string(),
    statements: vec![IpmPolicyStatementConfig {
      effect: IpmPolicyEffect::Allow,
      actions: vec!["*".to_string()],
      resources: vec!["*".to_string()],
      conditions: Vec::new(),
    }],
  })
}

pub fn validate_authorization_input(action: &str, resource: &str) -> anyhow::Result<()> {
  if action.trim().is_empty() || resource.trim().is_empty() {
    bail!("IPM authorization action and resource must not be empty");
  }
  Ok(())
}

#[cfg(test)]
mod tests;
