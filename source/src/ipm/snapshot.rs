use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use anyhow::bail;

use crate::config::{IpmPolicyConfig, IpmPolicyStatementConfig};

use super::{IpmActor, IpmEntrySource, store};

#[derive(Debug, Clone)]
pub(crate) struct IpmSnapshot {
  pub(crate) generation: i64,
  pub(crate) fingerprint: u64,
  pub(crate) credentials: Vec<IpmCredentialRuntime>,
  pub(crate) principals: HashMap<String, IpmPrincipalRuntime>,
  pub(crate) policies: HashMap<String, IpmPolicyRuntime>,
  pub(crate) principal_bindings: HashMap<String, Vec<String>>,
  pub(crate) group_bindings: HashMap<String, Vec<String>>,
  pub(crate) bindings: Vec<IpmBindingRuntime>,
  pub(crate) counts: IpmSnapshotCounts,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct IpmSnapshotCounts {
  pub config_principals: usize,
  pub store_principals: usize,
  pub config_credentials: usize,
  pub store_credentials: usize,
  pub config_policies: usize,
  pub store_policies: usize,
  pub config_bindings: usize,
  pub store_bindings: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct IpmPrincipalRuntime {
  pub(crate) actor: IpmActor,
  pub(crate) enabled: bool,
  pub(crate) source: IpmEntrySource,
}

#[derive(Debug, Clone)]
pub(crate) struct IpmPolicyRuntime {
  pub(crate) policy: IpmPolicyConfig,
  pub(crate) enabled: bool,
  pub(crate) source: IpmEntrySource,
}

#[derive(Debug, Clone)]
pub(crate) struct IpmBindingRuntime {
  pub(crate) id: String,
  pub(crate) principal: Option<String>,
  pub(crate) group: Option<String>,
  pub(crate) policy: String,
  pub(crate) enabled: bool,
  pub(crate) source: IpmEntrySource,
}

#[derive(Debug, Clone)]
pub(crate) struct IpmCredentialRuntime {
  pub(crate) name: String,
  pub(crate) principal: String,
  pub(crate) source: IpmEntrySource,
  pub(crate) bearer_token_env: String,
  pub(crate) break_glass_access_token_hash: Option<String>,
  pub(crate) enabled: bool,
  pub(crate) revoked: bool,
  pub(crate) expires_at: Option<String>,
  pub(crate) expires_at_unix: Option<i64>,
  pub(crate) token_prefix: Option<String>,
  pub(crate) token_hash: Option<String>,
  pub(crate) token_hash_alg: Option<String>,
  pub(crate) previous_token_prefix: Option<String>,
  pub(crate) previous_token_hash: Option<String>,
  pub(crate) previous_token_overlap_until: Option<String>,
  pub(crate) previous_token_overlap_until_unix: Option<i64>,
}

impl IpmCredentialRuntime {
  pub(crate) fn is_active_at(&self, now: Option<i64>) -> bool {
    if !self.enabled || self.revoked {
      return false;
    }
    if let (Some(expires_at), Some(now)) = (self.expires_at_unix, now)
      && expires_at <= now
    {
      return false;
    }
    true
  }

  pub(crate) fn previous_token_active_at(&self, now: Option<i64>) -> bool {
    let Some(overlap_until) = self.previous_token_overlap_until_unix else {
      return false;
    };
    now.is_some_and(|now| overlap_until > now)
  }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactedIpmCredential {
  pub name: String,
  pub principal: String,
  pub source: IpmEntrySource,
  pub enabled: bool,
  pub revoked: bool,
  pub bearer_token_env: String,
  pub break_glass_access: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub expires_at: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub token_prefix: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub previous_token_prefix: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub previous_token_overlap_until: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactedIpmPolicy {
  pub name: String,
  pub version: String,
  pub statements: Vec<IpmPolicyStatementConfig>,
  pub enabled: bool,
  pub source: IpmEntrySource,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactedIpmBinding {
  pub id: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub principal: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub group: Option<String>,
  pub policy: String,
  pub enabled: bool,
  pub source: IpmEntrySource,
}

pub(crate) fn static_snapshot(config: &crate::config::Config) -> anyhow::Result<IpmSnapshot> {
  let principals = config
    .ipm
    .principals
    .iter()
    .map(|principal| {
      (
        principal.id.clone(),
        IpmPrincipalRuntime {
          actor: IpmActor {
            name: principal.id.clone(),
            principal: principal.id.clone(),
            subject: principal.subject.clone(),
            groups: principal.groups.clone(),
          },
          enabled: true,
          source: IpmEntrySource::Config,
        },
      )
    })
    .collect::<HashMap<_, _>>();

  let policies = config
    .ipm
    .policies
    .iter()
    .map(|policy| {
      (
        policy.name.clone(),
        IpmPolicyRuntime {
          policy: policy.clone(),
          enabled: true,
          source: IpmEntrySource::Config,
        },
      )
    })
    .collect::<HashMap<_, _>>();

  let credentials = config
    .ipm
    .credentials
    .iter()
    .map(|credential| IpmCredentialRuntime {
      name: credential.name.clone(),
      principal: credential.principal.clone(),
      source: IpmEntrySource::Config,
      bearer_token_env: credential.bearer_token_env.clone(),
      break_glass_access_token_hash: credential.break_glass_access_token_hash.clone(),
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
    })
    .collect::<Vec<_>>();

  let mut bindings = Vec::new();
  let mut principal_bindings: HashMap<String, Vec<String>> = HashMap::new();
  let mut group_bindings: HashMap<String, Vec<String>> = HashMap::new();
  for binding in &config.ipm.bindings {
    let id = static_binding_id(
      binding.principal.as_deref(),
      binding.group.as_deref(),
      &binding.policy,
    );
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
    bindings.push(IpmBindingRuntime {
      id,
      principal: binding.principal.clone(),
      group: binding.group.clone(),
      policy: binding.policy.clone(),
      enabled: true,
      source: IpmEntrySource::Config,
    });
  }

  let counts = IpmSnapshotCounts {
    config_principals: principals.len(),
    config_credentials: credentials.len(),
    config_policies: policies.len(),
    config_bindings: bindings.len(),
    ..IpmSnapshotCounts::default()
  };
  let mut snapshot = IpmSnapshot {
    generation: 0,
    fingerprint: 0,
    credentials,
    principals,
    policies,
    principal_bindings,
    group_bindings,
    bindings,
    counts,
  };
  snapshot.fingerprint = fingerprint_snapshot(&snapshot);
  Ok(snapshot)
}

fn static_binding_id(principal: Option<&str>, group: Option<&str>, policy: &str) -> String {
  match (principal, group) {
    (Some(principal), None) => format!("principal.{principal}.{policy}"),
    (None, Some(group)) => format!("group.{group}.{policy}"),
    _ => format!("binding.{policy}"),
  }
}

pub(crate) fn merge_store_snapshot(
  static_snapshot: &IpmSnapshot,
  store_snapshot: store::IpmStoreSnapshotParts,
) -> anyhow::Result<IpmSnapshot> {
  let mut snapshot = static_snapshot.clone();
  snapshot.generation = store_snapshot.generation;
  snapshot.counts.store_principals = store_snapshot.principals.len();
  snapshot.counts.store_credentials = store_snapshot.credentials.len();
  snapshot.counts.store_policies = store_snapshot.policies.len();
  snapshot.counts.store_bindings = store_snapshot.bindings.len();

  for (id, principal) in store_snapshot.principals {
    if snapshot.principals.contains_key(&id) {
      bail!("IPM store principal {id} conflicts with static TOML principal");
    }
    snapshot.principals.insert(id, principal);
  }
  for credential in store_snapshot.credentials {
    if snapshot
      .credentials
      .iter()
      .any(|existing| existing.name == credential.name)
    {
      bail!(
        "IPM store credential {} conflicts with static TOML credential",
        credential.name
      );
    }
    if !snapshot.principals.contains_key(&credential.principal) {
      bail!(
        "IPM store credential {} references unknown principal {}",
        credential.name,
        credential.principal
      );
    }
    snapshot.credentials.push(credential);
  }
  for (id, policy) in store_snapshot.policies {
    if snapshot.policies.contains_key(&id) {
      bail!("IPM store policy {id} conflicts with static TOML policy");
    }
    snapshot.policies.insert(id, policy);
  }
  let known_groups = snapshot
    .principals
    .values()
    .flat_map(|principal| principal.actor.groups.iter().cloned())
    .collect::<HashSet<_>>();
  let static_binding_ids = snapshot
    .bindings
    .iter()
    .map(|binding| binding.id.clone())
    .collect::<HashSet<_>>();
  for binding in store_snapshot.bindings {
    if static_binding_ids.contains(&binding.id) {
      bail!(
        "IPM store binding {} conflicts with static TOML binding",
        binding.id
      );
    }
    if !snapshot.policies.contains_key(&binding.policy) {
      bail!(
        "IPM store binding {} references unknown policy {}",
        binding.id,
        binding.policy
      );
    }
    if let Some(principal) = &binding.principal
      && !snapshot.principals.contains_key(principal)
    {
      bail!(
        "IPM store binding {} references unknown principal {}",
        binding.id,
        principal
      );
    }
    if let Some(group) = &binding.group
      && !known_groups.contains(group)
    {
      bail!(
        "IPM store binding {} references unknown group {}",
        binding.id,
        group
      );
    }
    if binding.enabled {
      if let Some(principal) = &binding.principal {
        snapshot
          .principal_bindings
          .entry(principal.clone())
          .or_default()
          .push(binding.policy.clone());
      }
      if let Some(group) = &binding.group {
        snapshot
          .group_bindings
          .entry(group.clone())
          .or_default()
          .push(binding.policy.clone());
      }
    }
    snapshot.bindings.push(binding);
  }
  snapshot.fingerprint = fingerprint_snapshot(&snapshot);
  Ok(snapshot)
}

fn fingerprint_snapshot(snapshot: &IpmSnapshot) -> u64 {
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  snapshot.generation.hash(&mut hasher);
  for principal in sorted_keys(&snapshot.principals) {
    principal.hash(&mut hasher);
    if let Some(runtime) = snapshot.principals.get(&principal) {
      runtime.actor.subject.hash(&mut hasher);
      runtime.actor.groups.hash(&mut hasher);
      runtime.enabled.hash(&mut hasher);
    }
  }
  for credential in &snapshot.credentials {
    credential.name.hash(&mut hasher);
    credential.principal.hash(&mut hasher);
    credential.enabled.hash(&mut hasher);
    credential.revoked.hash(&mut hasher);
    credential.expires_at.hash(&mut hasher);
    credential.token_hash.hash(&mut hasher);
    credential.previous_token_hash.hash(&mut hasher);
    credential.previous_token_overlap_until.hash(&mut hasher);
  }
  for policy in sorted_keys(&snapshot.policies) {
    policy.hash(&mut hasher);
    if let Some(runtime) = snapshot.policies.get(&policy) {
      runtime.enabled.hash(&mut hasher);
      serde_json::to_string(&runtime.policy)
        .unwrap_or_default()
        .hash(&mut hasher);
    }
  }
  for binding in &snapshot.bindings {
    binding.id.hash(&mut hasher);
    binding.principal.hash(&mut hasher);
    binding.group.hash(&mut hasher);
    binding.policy.hash(&mut hasher);
    binding.enabled.hash(&mut hasher);
  }
  hasher.finish()
}

fn sorted_keys<T>(map: &HashMap<String, T>) -> Vec<String> {
  let mut keys = map.keys().cloned().collect::<Vec<_>>();
  keys.sort();
  keys
}
