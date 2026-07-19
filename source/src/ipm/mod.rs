use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
#[cfg(feature = "admin-runtime")]
use std::sync::RwLock;

use anyhow::{Context, bail};
use arc_swap::ArcSwap;
#[cfg(feature = "admin-runtime")]
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use http::HeaderMap;
#[cfg(feature = "admin-runtime")]
use tokio::sync::Semaphore;
use tracing::warn;

use crate::config::{
  IpmConditionConfig, IpmConditionOperator, IpmPolicyConfig, IpmPolicyEffect,
  IpmPolicyStatementConfig,
};

#[cfg(feature = "admin-runtime")]
mod admin;
#[cfg(feature = "admin-runtime")]
mod admin_bindings;
#[cfg(feature = "admin-runtime")]
mod admin_references;
#[cfg(feature = "admin-runtime")]
mod admin_support;
#[cfg(feature = "admin-runtime")]
mod admin_transaction;
#[cfg(feature = "admin-runtime")]
mod admin_types;
#[cfg(feature = "admin-runtime")]
mod lists;
mod refresh;
#[cfg(feature = "admin-runtime")]
mod simulation;
mod snapshot;
#[cfg(feature = "admin-runtime")]
mod state_access;
mod store;
mod token;
#[cfg(feature = "admin-runtime")]
mod workload_identity;
#[cfg(feature = "admin-runtime")]
pub(crate) use admin_transaction::{
  IpmAdminMutation, IpmMutationCheckpoint, IpmTransactionalMutationResult,
};
#[cfg(feature = "admin-runtime")]
pub use admin_types::*;
#[cfg(feature = "admin-runtime")]
pub use simulation::{
  IpmPreparedSimulation, IpmSimulationAuthorizationRequirements, IpmSimulationRequest,
  IpmSimulationResponse,
};
pub(crate) use snapshot::{
  IpmBindingRuntime, IpmCredentialRuntime, IpmPolicyRuntime, IpmPrincipalRuntime, IpmSnapshot,
  merge_store_snapshot, static_snapshot,
};
pub use snapshot::{
  IpmSnapshotCounts, RedactedIpmBinding, RedactedIpmCredential, RedactedIpmPolicy,
};
#[cfg(feature = "admin-runtime")]
pub(crate) use workload_identity::{
  IpmAdminBearerAuthentication, IpmAdminCredentialKind, IpmPresentedWorkloadIdentity,
  IpmWorkloadIdentity, IpmWorkloadIdentityError,
};

#[cfg(feature = "admin-runtime")]
const BREAK_GLASS_AUTH_CONCURRENCY: usize = 1;

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

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpmEntrySource {
  Config,
  Store,
}

#[derive(Clone)]
pub struct IpmRuntime {
  inner: Arc<IpmRuntimeInner>,
}

struct IpmRuntimeInner {
  namespace: String,
  static_snapshot: Arc<IpmSnapshot>,
  snapshot: ArcSwap<IpmSnapshot>,
  store: Option<store::IpmStore>,
  #[cfg(feature = "admin-runtime")]
  last_refresh: RwLock<IpmRefreshState>,
  legacy_admin_env: String,
  allow_legacy_bootstrap: bool,
  #[cfg(feature = "admin-runtime")]
  break_glass_verifier: Arc<Semaphore>,
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone)]
struct IpmRefreshState {
  ok: bool,
  generation: i64,
  error: Option<String>,
}

#[cfg(feature = "admin-runtime")]
impl IpmRefreshState {
  fn ok(generation: i64) -> Self {
    Self {
      ok: true,
      generation,
      error: None,
    }
  }

  fn failed(generation: i64, error: String) -> Self {
    Self {
      ok: false,
      generation,
      error: Some(error),
    }
  }
}

impl IpmRuntime {
  pub async fn new(config: &crate::config::Config) -> anyhow::Result<Self> {
    let static_snapshot = static_snapshot(config)?;
    let mut active_snapshot = static_snapshot.clone();
    let mut store_runtime = None;
    #[cfg(feature = "admin-runtime")]
    let mut refresh_state = IpmRefreshState::ok(active_snapshot.generation);

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
          let store = store::IpmStore::new(pool, config.ipm.namespace.clone());
          match store.load_snapshot(&static_snapshot).await {
            Ok(snapshot) => {
              active_snapshot = snapshot;
              #[cfg(feature = "admin-runtime")]
              {
                refresh_state = IpmRefreshState::ok(active_snapshot.generation);
              }
            }
            Err(error) if !config.ipm.fail_closed => {
              let message = error.to_string();
              warn!(error = %message, "IPM PostgreSQL snapshot load failed; using static IPM config only");
              #[cfg(feature = "admin-runtime")]
              {
                refresh_state = IpmRefreshState::failed(active_snapshot.generation, message);
              }
            }
            Err(error) => return Err(error).context("failed to load IPM PostgreSQL snapshot"),
          }
          store_runtime = Some(store);
        }
        Err(error) if !config.ipm.fail_closed => {
          tracing::warn!(error = %error, "IPM PostgreSQL connection failed; using static IPM config only");
          #[cfg(feature = "admin-runtime")]
          {
            refresh_state = IpmRefreshState::failed(active_snapshot.generation, error.to_string());
          }
        }
        Err(error) => return Err(error).context("failed to connect IPM PostgreSQL backend"),
      }
    }

    let runtime = Self {
      inner: Arc::new(IpmRuntimeInner {
        namespace: config.ipm.namespace.clone(),
        static_snapshot: Arc::new(static_snapshot),
        snapshot: ArcSwap::from_pointee(active_snapshot),
        store: store_runtime,
        #[cfg(feature = "admin-runtime")]
        last_refresh: RwLock::new(refresh_state),
        legacy_admin_env: config.admin.bearer_token_env.clone(),
        allow_legacy_bootstrap: !config.ipm.enabled,
        #[cfg(feature = "admin-runtime")]
        break_glass_verifier: break_glass_verifier(),
      }),
    };
    runtime.spawn_store_refresh_task();
    Ok(runtime)
  }

  pub fn namespace(&self) -> &str {
    &self.inner.namespace
  }

  pub(crate) fn snapshot(&self) -> Arc<IpmSnapshot> {
    self.inner.snapshot.load_full()
  }

  pub fn actor_from_headers(&self, headers: &HeaderMap) -> Option<IpmActor> {
    let bearer = headers
      .get(http::header::AUTHORIZATION)
      .and_then(|value| value.to_str().ok())
      .and_then(|value| value.strip_prefix("Bearer "))?;
    self.actor_from_bearer(bearer)
  }

  pub fn actor_from_bearer(&self, bearer: &str) -> Option<IpmActor> {
    self.actor_from_regular_bearer(bearer)
  }

  fn actor_from_regular_bearer(&self, bearer: &str) -> Option<IpmActor> {
    let snapshot = self.snapshot();
    for credential in &snapshot.credentials {
      if credential_matches(credential, bearer)
        && let Some(principal) = snapshot.principals.get(&credential.principal)
        && principal.enabled
      {
        let mut actor = principal.actor.clone();
        actor.name = credential.name.clone();
        self.record_credential_use(credential);
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

  #[cfg(feature = "admin-runtime")]
  async fn break_glass_actor_from_bearer(&self, bearer: &str) -> Option<IpmActor> {
    let snapshot = self.snapshot();
    for credential in &snapshot.credentials {
      if !credential.is_active_at(now_unix().ok()) {
        continue;
      }
      let Some(hash) = credential.break_glass_access_token_hash.as_deref() else {
        continue;
      };
      if bearer_matches_argon2id_hash_bounded(self.inner.break_glass_verifier.clone(), hash, bearer)
        .await
        && let Some(principal) = snapshot.principals.get(&credential.principal)
        && principal.enabled
      {
        let mut actor = principal.actor.clone();
        actor.name = credential.name.clone();
        return Some(actor);
      }
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
    let snapshot = self.snapshot();
    authorize_snapshot(&snapshot, actor, action, resource, context)
  }
}

pub(super) fn authorize_snapshot(
  snapshot: &IpmSnapshot,
  actor: &IpmActor,
  action: &str,
  resource: &str,
  context: &IpmRequestContext,
) -> IpmDecision {
  let policies = policies_for_actor_in_snapshot(snapshot, actor);
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

impl IpmRuntime {
  fn spawn_store_refresh_task(&self) {
    refresh::spawn_store_refresh_task(&self.inner);
  }

  #[cfg(feature = "admin-runtime")]
  async fn refresh_store(&self) -> anyhow::Result<()> {
    refresh::refresh_store_inner(&self.inner).await.map(|_| ())
  }

  fn record_credential_use(&self, credential: &IpmCredentialRuntime) {
    if credential.source != IpmEntrySource::Store {
      return;
    }
    let Some(store) = self.inner.store.clone() else {
      return;
    };
    let credential_id = credential.name.clone();
    tokio::spawn(async move {
      if let Err(error) = store.record_credential_use(&credential_id).await {
        warn!(credential = %credential_id, error = %error, "failed to update IPM credential last-used metadata");
      }
    });
  }

  #[cfg(test)]
  pub(crate) fn test_with_actor_policy(
    namespace: &str,
    actor: IpmActor,
    policy: IpmPolicyConfig,
  ) -> Self {
    let principal = actor.principal.clone();
    let policy_name = policy.name.clone();
    let snapshot = IpmSnapshot {
      generation: 0,
      fingerprint: 0,
      credentials: Vec::new(),
      principals: HashMap::from([(
        principal.clone(),
        IpmPrincipalRuntime {
          actor,
          enabled: true,
          #[cfg(feature = "admin-runtime")]
          source: IpmEntrySource::Config,
        },
      )]),
      policies: HashMap::from([(
        policy_name.clone(),
        IpmPolicyRuntime {
          policy,
          enabled: true,
          #[cfg(feature = "admin-runtime")]
          source: IpmEntrySource::Config,
        },
      )]),
      principal_bindings: HashMap::from([(principal, vec![policy_name])]),
      group_bindings: HashMap::new(),
      bindings: Vec::new(),
      counts: IpmSnapshotCounts::default(),
    };
    Self {
      inner: Arc::new(IpmRuntimeInner {
        namespace: namespace.to_string(),
        static_snapshot: Arc::new(snapshot.clone()),
        snapshot: ArcSwap::from_pointee(snapshot),
        store: None,
        #[cfg(feature = "admin-runtime")]
        last_refresh: RwLock::new(IpmRefreshState::ok(0)),
        legacy_admin_env: "OXIBELT_ADMIN_TOKEN".to_string(),
        allow_legacy_bootstrap: false,
        #[cfg(feature = "admin-runtime")]
        break_glass_verifier: break_glass_verifier(),
      }),
    }
  }
}

fn policies_for_actor_in_snapshot(
  snapshot: &IpmSnapshot,
  actor: &IpmActor,
) -> Vec<IpmPolicyConfig> {
  let mut names = Vec::new();
  if let Some(policies) = snapshot.principal_bindings.get(&actor.principal) {
    names.extend(policies.iter().cloned());
  }
  for group in &actor.groups {
    if group == "ipm-admin" {
      return vec![bootstrap_admin_policy().clone()];
    }
    if let Some(policies) = snapshot.group_bindings.get(group) {
      names.extend(policies.iter().cloned());
    }
  }
  let mut seen = HashSet::new();
  names
    .into_iter()
    .filter(|name| seen.insert(name.clone()))
    .filter_map(|name| snapshot.policies.get(&name))
    .filter(|policy| policy.enabled)
    .map(|policy| policy.policy.clone())
    .collect()
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
    let expected_digest = crate::crypto::sha256(expected.as_bytes());
    let actual_digest = crate::crypto::sha256(actual.as_bytes());
    use subtle::ConstantTimeEq;
    expected_digest.ct_eq(&actual_digest).into()
  })
}

fn credential_matches(credential: &IpmCredentialRuntime, bearer: &str) -> bool {
  let now = now_unix().ok();
  if !credential.is_active_at(now) {
    return false;
  }
  if !credential.bearer_token_env.is_empty() {
    return bearer_matches_env(&credential.bearer_token_env, bearer);
  }
  if credential.token_hash.as_deref().is_some_and(|hash| {
    token::token_hash_matches(credential.token_hash_alg.as_deref(), hash, bearer)
  }) {
    return true;
  }
  credential.previous_token_active_at(now)
    && credential
      .previous_token_hash
      .as_deref()
      .is_some_and(|hash| {
        token::token_hash_matches(credential.token_hash_alg.as_deref(), hash, bearer)
      })
}

#[cfg(feature = "admin-runtime")]
async fn bearer_matches_argon2id_hash_bounded(
  verifier: Arc<Semaphore>,
  hash: &str,
  actual: &str,
) -> bool {
  if hash.trim().is_empty() || actual.is_empty() {
    return false;
  }
  let Ok(permit) = verifier.try_acquire_owned() else {
    tracing::debug!("break-glass access verification limiter is saturated");
    return false;
  };
  let hash = hash.to_string();
  let actual = actual.to_string();
  match tokio::task::spawn_blocking(move || {
    let _permit = permit;
    bearer_matches_argon2id_hash(&hash, &actual)
  })
  .await
  {
    Ok(result) => result,
    Err(error) => {
      tracing::warn!(error = %error, "break-glass access verification task failed");
      false
    }
  }
}

#[cfg(feature = "admin-runtime")]
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

#[cfg(feature = "admin-runtime")]
fn break_glass_verifier() -> Arc<Semaphore> {
  Arc::new(Semaphore::new(BREAK_GLASS_AUTH_CONCURRENCY))
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
