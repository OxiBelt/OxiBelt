use std::collections::HashSet;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use super::{Config, validate_optional_non_empty, validate_runtime_identifier};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_ipm_namespace")]
  pub namespace: String,
  #[serde(default)]
  pub backend: Option<String>,
  #[serde(default = "default_true")]
  pub fail_closed: bool,
  #[serde(default)]
  pub credentials: Vec<IpmCredentialConfig>,
  #[serde(default)]
  pub principals: Vec<IpmPrincipalConfig>,
  #[serde(default)]
  pub policies: Vec<IpmPolicyConfig>,
  #[serde(default)]
  pub bindings: Vec<IpmPolicyBindingConfig>,
  #[serde(default)]
  pub trust: Vec<IpmTrustMappingConfig>,
  #[serde(default)]
  pub break_glass: IpmBreakGlassConfig,
}

impl Default for IpmConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      namespace: default_ipm_namespace(),
      backend: None,
      fail_closed: true,
      credentials: Vec::new(),
      principals: Vec::new(),
      policies: Vec::new(),
      bindings: Vec::new(),
      trust: Vec::new(),
      break_glass: IpmBreakGlassConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmCredentialConfig {
  pub name: String,
  pub principal: String,
  #[serde(default)]
  pub bearer_token_env: String,
  #[serde(default)]
  pub break_glass_access_token_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmBreakGlassConfig {
  #[serde(default = "default_break_glass_argon2id_memory_mib")]
  pub argon2id_memory_mib: u32,
}

impl Default for IpmBreakGlassConfig {
  fn default() -> Self {
    Self {
      argon2id_memory_mib: default_break_glass_argon2id_memory_mib(),
    }
  }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmPrincipalConfig {
  pub id: String,
  pub subject: String,
  #[serde(default)]
  pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmPolicyConfig {
  pub name: String,
  #[serde(default = "default_ipm_policy_version")]
  pub version: String,
  #[serde(default)]
  pub statements: Vec<IpmPolicyStatementConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmPolicyStatementConfig {
  pub effect: IpmPolicyEffect,
  #[serde(default)]
  pub actions: Vec<String>,
  #[serde(default)]
  pub resources: Vec<String>,
  #[serde(default)]
  pub conditions: Vec<IpmConditionConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpmPolicyEffect {
  Allow,
  Deny,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmConditionConfig {
  pub operator: IpmConditionOperator,
  pub key: String,
  #[serde(default)]
  pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum IpmConditionOperator {
  StringEquals,
  StringLike,
  StringNotEquals,
  IpAddress,
  NotIpAddress,
  Bool,
  DateBefore,
  DateAfter,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmPolicyBindingConfig {
  #[serde(default)]
  pub principal: Option<String>,
  #[serde(default)]
  pub group: Option<String>,
  pub policy: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct IpmTrustMappingConfig {
  pub source: IpmTrustSource,
  pub claim: String,
  pub value: String,
  #[serde(default)]
  pub principal: Option<String>,
  #[serde(default)]
  pub group: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpmTrustSource {
  Oidc,
  Mtls,
  ExternalAuth,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Serialize)]
pub struct RouteIpmConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub action: Option<String>,
}

impl RouteIpmConfig {
  pub(super) fn validate(&self, route_name: &str) -> anyhow::Result<()> {
    if !self.enabled {
      return Ok(());
    }
    if let Some(action) = &self.action {
      validate_ipm_action(&format!("route {route_name} ipm.action"), action)?;
    }
    Ok(())
  }
}

impl Config {
  pub(crate) fn ipm_backend_name(&self) -> Option<&str> {
    self
      .ipm
      .backend
      .as_deref()
      .or(self.shared_state.default_backend.as_deref())
      .or_else(|| {
        self
          .shared_state
          .backends
          .first()
          .map(|backend| backend.name.as_str())
      })
  }

  pub(super) fn validate_ipm(&self) -> anyhow::Result<()> {
    validate_runtime_identifier("ipm.namespace", &self.ipm.namespace)?;
    validate_optional_non_empty("ipm.backend", self.ipm.backend.as_deref())?;
    validate_break_glass_argon2id_memory_mib(self.ipm.break_glass.argon2id_memory_mib)?;
    if self.ipm.enabled
      && let Some(backend_name) = self.ipm_backend_name()
    {
      if !self.shared_state.enabled {
        bail!("ipm.backend requires shared_state.enabled = true");
      }
      let Some(backend) = self
        .shared_state
        .backends
        .iter()
        .find(|backend| backend.name == backend_name)
      else {
        bail!("ipm backend references unknown shared_state backend {backend_name}");
      };
      if backend.kind != super::SharedStateBackendKind::Postgres {
        bail!("ipm backend {backend_name} must use kind = \"postgres\"");
      }
    }

    let mut principal_ids = HashSet::new();
    let mut groups = HashSet::new();
    for principal in &self.ipm.principals {
      validate_runtime_identifier("ipm.principals.id", &principal.id)?;
      validate_optional_non_empty("ipm.principals.subject", Some(&principal.subject))?;
      if !principal_ids.insert(principal.id.as_str()) {
        bail!("duplicate ipm principal {}", principal.id);
      }
      for group in &principal.groups {
        validate_runtime_identifier("ipm.principals.groups", group)?;
        groups.insert(group.as_str());
      }
    }

    let mut credential_names = HashSet::new();
    for credential in &self.ipm.credentials {
      validate_runtime_identifier("ipm.credentials.name", &credential.name)?;
      validate_runtime_identifier("ipm.credentials.principal", &credential.principal)?;
      let has_bearer_env = !credential.bearer_token_env.trim().is_empty();
      let has_break_glass_hash = credential
        .break_glass_access_token_hash
        .as_deref()
        .is_some_and(|hash| !hash.trim().is_empty());
      if has_bearer_env == has_break_glass_hash {
        bail!(
          "ipm credential {} must set exactly one of bearer_token_env or break_glass_access_token_hash",
          credential.name
        );
      }
      if has_bearer_env {
        validate_optional_non_empty(
          "ipm.credentials.bearer_token_env",
          Some(&credential.bearer_token_env),
        )?;
      }
      if let Some(hash) = credential.break_glass_access_token_hash.as_deref() {
        validate_argon2id_hash_memory(
          &format!(
            "ipm credential {} break_glass_access_token_hash",
            credential.name
          ),
          hash,
          self.ipm.break_glass.argon2id_memory_mib,
        )?;
      }
      if !credential_names.insert(credential.name.as_str()) {
        bail!("duplicate ipm credential {}", credential.name);
      }
      if !principal_ids.contains(credential.principal.as_str()) {
        bail!(
          "ipm credential {} references unknown principal {}",
          credential.name,
          credential.principal
        );
      }
      if self.ipm.enabled
        && has_bearer_env
        && std::env::var(&credential.bearer_token_env)
          .ok()
          .is_none_or(|token| token.is_empty())
      {
        bail!(
          "IPM bearer token environment variable {} must be set and non-empty",
          credential.bearer_token_env
        );
      }
    }

    let mut policy_names = HashSet::new();
    for policy in &self.ipm.policies {
      validate_runtime_identifier("ipm.policies.name", &policy.name)?;
      validate_optional_non_empty("ipm.policies.version", Some(&policy.version))?;
      if !policy_names.insert(policy.name.as_str()) {
        bail!("duplicate ipm policy {}", policy.name);
      }
      if policy.statements.is_empty() {
        bail!(
          "ipm policy {} must include at least one statement",
          policy.name
        );
      }
      for statement in &policy.statements {
        validate_ipm_statement(&policy.name, statement)?;
      }
    }

    for binding in &self.ipm.bindings {
      if binding.principal.is_some() == binding.group.is_some() {
        bail!("ipm policy binding must set exactly one of principal or group");
      }
      if let Some(principal) = &binding.principal
        && !principal_ids.contains(principal.as_str())
      {
        bail!("ipm binding references unknown principal {principal}");
      }
      if let Some(group) = &binding.group {
        validate_runtime_identifier("ipm.bindings.group", group)?;
        if !groups.contains(group.as_str()) {
          bail!("ipm binding references unknown group {group}");
        }
      }
      if !policy_names.contains(binding.policy.as_str()) {
        bail!("ipm binding references unknown policy {}", binding.policy);
      }
    }

    for trust in &self.ipm.trust {
      validate_optional_non_empty("ipm.trust.claim", Some(&trust.claim))?;
      validate_optional_non_empty("ipm.trust.value", Some(&trust.value))?;
      if trust.principal.is_some() == trust.group.is_some() {
        bail!("ipm trust mapping must set exactly one of principal or group");
      }
      if let Some(principal) = &trust.principal
        && !principal_ids.contains(principal.as_str())
      {
        bail!("ipm trust mapping references unknown principal {principal}");
      }
      if let Some(group) = &trust.group {
        validate_runtime_identifier("ipm.trust.group", group)?;
      }
    }

    if self.admin.enabled && self.ipm.enabled && self.ipm.credentials.is_empty() {
      bail!("admin.enabled with ipm.enabled requires at least one [[ipm.credentials]] entry");
    }

    Ok(())
  }
}

fn validate_break_glass_argon2id_memory_mib(memory_mib: u32) -> anyhow::Result<()> {
  if memory_mib == 0 || memory_mib > max_break_glass_argon2id_memory_mib() {
    bail!(
      "ipm.break_glass.argon2id_memory_mib must be between 1 and {}",
      max_break_glass_argon2id_memory_mib()
    );
  }
  Ok(())
}

fn validate_argon2id_hash_memory(
  field: &str,
  hash: &str,
  max_memory_mib: u32,
) -> anyhow::Result<()> {
  if !hash.starts_with("$argon2id$") {
    bail!("{field} must be an Argon2id PHC string");
  }
  argon2::PasswordHash::new(hash).with_context(|| format!("{field} is not a valid PHC string"))?;
  let Some(memory_kib) = argon2id_memory_kib(hash) else {
    bail!("{field} must include an Argon2id memory parameter");
  };
  let max_memory_kib = max_memory_mib.saturating_mul(1024);
  if memory_kib > max_memory_kib {
    bail!(
      "{field} requires {memory_kib} KiB, above ipm.break_glass.argon2id_memory_mib = {max_memory_mib} MiB"
    );
  }
  Ok(())
}

fn argon2id_memory_kib(hash: &str) -> Option<u32> {
  hash
    .split('$')
    .find(|segment| segment.contains("m="))
    .and_then(|params| {
      params.split(',').find_map(|part| {
        part
          .strip_prefix("m=")
          .and_then(|value| value.parse::<u32>().ok())
      })
    })
}

pub(crate) fn validate_ipm_action(field: &str, action: &str) -> anyhow::Result<()> {
  if action == "*" {
    return Ok(());
  }
  let Some((service, verb)) = action.split_once(':') else {
    bail!("{field} must use service:Action syntax");
  };
  validate_ipm_service(field, service)?;
  if verb == "*" {
    return Ok(());
  }
  let allowed = allowed_actions_for_service(service);
  if !allowed.contains(&verb) {
    bail!("{field} contains unsupported action {action}");
  }
  Ok(())
}

fn validate_ipm_statement(
  policy_name: &str,
  statement: &IpmPolicyStatementConfig,
) -> anyhow::Result<()> {
  if statement.actions.is_empty() {
    bail!("ipm policy {policy_name} statement must include at least one action");
  }
  if statement.resources.is_empty() {
    bail!("ipm policy {policy_name} statement must include at least one resource");
  }
  for action in &statement.actions {
    validate_ipm_action(&format!("ipm policy {policy_name} action"), action)?;
  }
  for resource in &statement.resources {
    validate_ipm_resource(&format!("ipm policy {policy_name} resource"), resource)?;
  }
  for condition in &statement.conditions {
    validate_ipm_condition(policy_name, condition)?;
  }
  Ok(())
}

fn validate_ipm_resource(field: &str, resource: &str) -> anyhow::Result<()> {
  if resource == "*" {
    return Ok(());
  }
  let parts = resource.splitn(4, ':').collect::<Vec<_>>();
  if parts.len() != 4 || parts[0] != "oxibelt" {
    bail!("{field} must use oxibelt:<namespace>:<service>:<resource> syntax");
  }
  validate_runtime_identifier(field, parts[1])?;
  validate_ipm_service(field, parts[2])?;
  validate_optional_non_empty(field, Some(parts[3]))?;
  Ok(())
}

fn validate_ipm_condition(policy_name: &str, condition: &IpmConditionConfig) -> anyhow::Result<()> {
  if condition.values.is_empty() {
    bail!("ipm policy {policy_name} condition must include at least one value");
  }
  validate_ipm_condition_key(&condition.key)
    .with_context(|| format!("ipm policy {policy_name} condition key"))?;
  Ok(())
}

fn validate_ipm_condition_key(key: &str) -> anyhow::Result<()> {
  if key.starts_with("claim.") && key.len() > "claim.".len() {
    return Ok(());
  }
  match key {
    "principal.subject" | "principal.groups" | "request.source_ip" | "request.method"
    | "request.host" | "request.path" | "request.route" | "request.protocol"
    | "resource.service" | "resource.name" | "time.now" => Ok(()),
    _ => bail!("unsupported IPM condition key {key}"),
  }
}

fn validate_ipm_service(field: &str, service: &str) -> anyhow::Result<()> {
  if matches!(
    service,
    "ipm"
      | "config"
      | "cache"
      | "upstream-pool"
      | "dynamic-policy"
      | "waf"
      | "lifecycle"
      | "diagnostics"
      | "runtime"
      | "route"
      | "stream"
      | "turn"
  ) {
    Ok(())
  } else {
    bail!("{field} contains unsupported IPM service {service}")
  }
}

fn allowed_actions_for_service(service: &str) -> &'static [&'static str] {
  match service {
    "ipm" => &[
      "ListPrincipals",
      "GetPrincipal",
      "CreatePrincipal",
      "UpdatePrincipal",
      "DeletePrincipal",
      "ListCredentials",
      "GetCredential",
      "CreateCredential",
      "UpdateCredential",
      "DeleteCredential",
      "ListPolicies",
      "GetPolicy",
      "CreatePolicy",
      "UpdatePolicy",
      "DeletePolicy",
      "ListBindings",
      "CreateBinding",
      "DeleteBinding",
      "Simulate",
    ],
    "config" => &[
      "GetStatus",
      "GetEffective",
      "Validate",
      "Diff",
      "Load",
      "Rollback",
      "SyncFiles",
      "ReadDownstreamTls",
      "ReloadDownstreamTls",
    ],
    "cache" => &[
      "ExplainKey",
      "Warm",
      "PurgeObject",
      "PurgePrefix",
      "PurgeTag",
    ],
    "upstream-pool" => &["List", "Get", "AddServer", "UpdateServer", "RemoveServer"],
    "dynamic-policy" => &[
      "List", "Get", "Create", "Update", "Delete", "Import", "Export",
    ],
    "waf" => &[
      "GetRuleHits",
      "GetRuleCosts",
      "GetCrsCompatibility",
      "PutOxiRule",
      "DeleteOxiRule",
      "PutOxiRuleGroup",
      "DeleteOxiRuleGroup",
      "ReloadOxiRule",
      "CheckOxiRule",
      "CheckOxiRuleGroup",
      "TestOxiRule",
      "ExplainOxiRule",
      "EstimateOxiRuleCost",
      "ReplayOxiRule",
      "ListOxiRuleTemplates",
      "RenderOxiRuleTemplate",
      "PlanOxiRuleFalsePositive",
    ],
    "lifecycle" => &["Get", "Drain", "Undrain"],
    "diagnostics" => &[
      "ReadPreflight",
      "RunPreflight",
      "RunProbe",
      "ReadSupportBundle",
    ],
    "runtime" => &["ReadSnapshot", "ReadIntrospection"],
    "route" => &["Invoke"],
    "stream" => &["Connect"],
    "turn" => &["Allocate"],
    _ => &[],
  }
}

fn default_ipm_namespace() -> String {
  "oxibelt".to_string()
}

fn default_ipm_policy_version() -> String {
  "2026-05-23".to_string()
}

fn default_break_glass_argon2id_memory_mib() -> u32 {
  128
}

fn max_break_glass_argon2id_memory_mib() -> u32 {
  16 * 1024
}

fn default_true() -> bool {
  true
}
