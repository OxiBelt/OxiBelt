use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::config::{
  IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig, validate_ipm_statement,
  validate_runtime_identifier,
};

use super::{
  IpmActor, IpmBindingCreate, IpmBindingRuntime, IpmDecision, IpmEntrySource, IpmPolicyCreate,
  IpmPolicyRuntime, IpmRequestContext, IpmRuntime, IpmSnapshot, authorize_snapshot, now_unix,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpmSimulationRequest {
  pub action: String,
  pub resource: String,
  #[serde(default)]
  pub target: Option<IpmSimulationTarget>,
  #[serde(default)]
  pub context: Option<IpmSimulationContext>,
  #[serde(default)]
  pub overlay: Option<IpmSimulationOverlay>,
}

impl IpmSimulationRequest {
  pub fn requires_principal_simulation(&self) -> bool {
    self
      .target
      .as_ref()
      .is_some_and(IpmSimulationTarget::has_overrides)
  }

  pub fn requires_policy_simulation(&self) -> bool {
    self
      .overlay
      .as_ref()
      .is_some_and(IpmSimulationOverlay::has_changes)
  }

  pub fn preliminary_authorization_requirements(&self) -> IpmSimulationAuthorizationRequirements {
    let mut requirements = IpmSimulationAuthorizationRequirements::default();
    if let Some(target) = self.target.as_ref().filter(|target| target.has_overrides()) {
      collect_target_requirements(target, &mut requirements);
    }
    if let Some(overlay) = self
      .overlay
      .as_ref()
      .filter(|overlay| overlay.has_changes())
    {
      collect_overlay_requirements(overlay, &mut requirements);
    }
    requirements
  }

  pub(crate) fn credential_owner_preflight(
    &self,
    runtime: &IpmRuntime,
  ) -> IpmSimulationCredentialPreflight {
    let mut preflight = IpmSimulationCredentialPreflight::default();
    let Some(target) = self.target.as_ref().filter(|target| target.has_overrides()) else {
      return preflight;
    };
    let Some(credential_id) = &target.credential else {
      return preflight;
    };

    let snapshot = runtime.snapshot();
    match snapshot
      .credentials
      .iter()
      .find(|credential| credential.name == *credential_id)
    {
      Some(credential) => push_unique(
        &mut preflight.requirements.target_principals,
        credential.principal.clone(),
      ),
      None => push_unique(&mut preflight.unresolved_credentials, credential_id.clone()),
    }
    preflight
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpmSimulationTarget {
  #[serde(default)]
  pub principal: Option<String>,
  #[serde(default)]
  pub credential: Option<String>,
  #[serde(default)]
  pub subject: Option<String>,
  #[serde(default)]
  pub groups: Option<Vec<String>>,
}

impl IpmSimulationTarget {
  fn has_overrides(&self) -> bool {
    self.principal.is_some()
      || self.credential.is_some()
      || self.subject.is_some()
      || self.groups.is_some()
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpmSimulationContext {
  #[serde(default)]
  pub source_ip: Option<IpAddr>,
  #[serde(default)]
  pub method: Option<String>,
  #[serde(default)]
  pub host: Option<String>,
  #[serde(default)]
  pub path: Option<String>,
  #[serde(default)]
  pub route: Option<String>,
  #[serde(default)]
  pub protocol: Option<String>,
  #[serde(default)]
  pub claims: HashMap<String, String>,
}

impl IpmSimulationContext {
  fn to_runtime_context(&self) -> IpmRequestContext {
    IpmRequestContext {
      source_ip: self.source_ip,
      method: self.method.clone(),
      host: self.host.clone(),
      path: self.path.clone(),
      route: self.route.clone(),
      protocol: self.protocol.clone(),
      claims: self.claims.clone(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpmSimulationOverlay {
  #[serde(default)]
  pub policies: Vec<IpmPolicyCreate>,
  #[serde(default)]
  pub bindings: Vec<IpmBindingCreate>,
}

impl IpmSimulationOverlay {
  fn has_changes(&self) -> bool {
    !self.policies.is_empty() || !self.bindings.is_empty()
  }
}

#[derive(Debug, Clone, Default)]
pub struct IpmSimulationAuthorizationRequirements {
  pub target_principals: Vec<String>,
  pub target_credentials: Vec<String>,
  pub target_groups: Vec<String>,
  pub overlay_principals: Vec<String>,
  pub overlay_groups: Vec<String>,
  pub overlay_policies: Vec<String>,
  pub overlay_bindings: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct IpmSimulationCredentialPreflight {
  pub(crate) requirements: IpmSimulationAuthorizationRequirements,
  pub(crate) unresolved_credentials: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IpmPreparedSimulation {
  pub requirements: IpmSimulationAuthorizationRequirements,
  pub response: IpmSimulationResponse,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmSimulationResponse {
  pub decision: &'static str,
  pub target: IpmSimulationTargetSummary,
  pub context: IpmSimulationContextSummary,
  pub overlay: IpmSimulationOverlaySummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmSimulationTargetSummary {
  pub principal: String,
  pub subject: String,
  pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmSimulationContextSummary {
  #[serde(skip_serializing_if = "Option::is_none")]
  pub source_ip: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub method: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub host: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub path: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub route: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub protocol: Option<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub claim_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpmSimulationOverlaySummary {
  pub policies: usize,
  pub bindings: usize,
}

impl IpmRuntime {
  pub fn admin_prepare_simulation(
    &self,
    current_actor: &IpmActor,
    current_context: &IpmRequestContext,
    request: IpmSimulationRequest,
  ) -> anyhow::Result<IpmPreparedSimulation> {
    validate_simulation_action_resource(&request.action, &request.resource)?;

    let mut requirements = IpmSimulationAuthorizationRequirements::default();
    let mut snapshot = (*self.snapshot()).clone();
    let target = resolve_simulation_target(
      &snapshot,
      current_actor,
      request.target.as_ref(),
      &mut requirements,
    )?;
    let context = request
      .context
      .as_ref()
      .map(IpmSimulationContext::to_runtime_context)
      .unwrap_or_else(|| current_context.clone());
    let overlay_summary = if let Some(overlay) = request.overlay.as_ref() {
      apply_simulation_overlay(&mut snapshot, &target, overlay, &mut requirements)?
    } else {
      IpmSimulationOverlaySummary {
        policies: 0,
        bindings: 0,
      }
    };

    let decision = authorize_snapshot(
      &snapshot,
      &target,
      &request.action,
      &request.resource,
      &context,
    );
    Ok(IpmPreparedSimulation {
      requirements,
      response: IpmSimulationResponse {
        decision: if decision == IpmDecision::Allow {
          "allow"
        } else {
          "deny"
        },
        target: IpmSimulationTargetSummary {
          principal: target.principal,
          subject: target.subject,
          groups: target.groups,
        },
        context: context_summary(&context),
        overlay: overlay_summary,
      },
    })
  }
}

fn validate_simulation_action_resource(action: &str, resource: &str) -> anyhow::Result<()> {
  let statement = IpmPolicyStatementConfig {
    effect: IpmPolicyEffect::Allow,
    actions: vec![action.to_string()],
    resources: vec![resource.to_string()],
    conditions: Vec::new(),
  };
  validate_ipm_statement("simulation", &statement)
}

fn resolve_simulation_target(
  snapshot: &IpmSnapshot,
  current_actor: &IpmActor,
  target: Option<&IpmSimulationTarget>,
  requirements: &mut IpmSimulationAuthorizationRequirements,
) -> anyhow::Result<IpmActor> {
  let Some(target) = target.filter(|target| target.has_overrides()) else {
    return Ok(current_actor.clone());
  };

  let mut actor = if let Some(credential_id) = &target.credential {
    push_unique(&mut requirements.target_credentials, credential_id.clone());
    let credential = snapshot
      .credentials
      .iter()
      .find(|credential| credential.name == *credential_id)
      .with_context(|| format!("unknown IPM credential {credential_id}"))?;
    if !credential.is_active_at(now_unix().ok()) {
      bail!("IPM credential {credential_id} is not active");
    }
    if let Some(principal) = &target.principal
      && principal != &credential.principal
    {
      bail!(
        "IPM credential {credential_id} belongs to principal {}, not {principal}",
        credential.principal
      );
    }
    let mut actor = principal_actor(snapshot, &credential.principal)?;
    actor.name = credential.name.clone();
    push_unique(
      &mut requirements.target_principals,
      credential.principal.clone(),
    );
    actor
  } else if let Some(principal) = &target.principal {
    push_unique(&mut requirements.target_principals, principal.clone());
    principal_actor(snapshot, principal)?
  } else {
    current_actor.clone()
  };

  if let Some(subject) = &target.subject {
    validate_non_empty("simulation target subject", subject)?;
    actor.subject = subject.clone();
  }
  if let Some(groups) = &target.groups {
    for group in groups {
      validate_runtime_identifier("simulation target group", group)?;
      push_unique(&mut requirements.target_groups, group.clone());
    }
    actor.groups = groups.clone();
  }
  Ok(actor)
}

fn principal_actor(snapshot: &IpmSnapshot, principal: &str) -> anyhow::Result<IpmActor> {
  let principal_record = snapshot
    .principals
    .get(principal)
    .with_context(|| format!("unknown IPM principal {principal}"))?;
  if !principal_record.enabled {
    bail!("IPM principal {principal} is disabled");
  }
  Ok(principal_record.actor.clone())
}

fn apply_simulation_overlay(
  snapshot: &mut IpmSnapshot,
  target: &IpmActor,
  overlay: &IpmSimulationOverlay,
  requirements: &mut IpmSimulationAuthorizationRequirements,
) -> anyhow::Result<IpmSimulationOverlaySummary> {
  for policy in &overlay.policies {
    validate_runtime_identifier("simulation overlay policy name", &policy.name)?;
    if policy.statements.is_empty() {
      bail!(
        "simulation overlay policy {} must include at least one statement",
        policy.name
      );
    }
    for statement in &policy.statements {
      validate_ipm_statement(&policy.name, statement)?;
    }
    push_unique(&mut requirements.overlay_policies, policy.name.clone());
    snapshot.policies.insert(
      policy.name.clone(),
      IpmPolicyRuntime {
        policy: IpmPolicyConfig {
          name: policy.name.clone(),
          version: policy.version.clone(),
          statements: policy.statements.clone(),
        },
        enabled: policy.enabled.unwrap_or(true),
        source: IpmEntrySource::Store,
      },
    );
  }

  for binding in &overlay.bindings {
    validate_overlay_binding(snapshot, target, binding, requirements)?;
    let id = generated_binding_id(binding);
    snapshot.bindings.retain(|existing| existing.id != id);
    snapshot.bindings.push(IpmBindingRuntime {
      id,
      principal: binding.principal.clone(),
      group: binding.group.clone(),
      policy: binding.policy.clone(),
      enabled: binding.enabled.unwrap_or(true),
      source: IpmEntrySource::Store,
    });
  }
  rebuild_binding_indexes(snapshot);

  Ok(IpmSimulationOverlaySummary {
    policies: overlay.policies.len(),
    bindings: overlay.bindings.len(),
  })
}

fn validate_overlay_binding(
  snapshot: &IpmSnapshot,
  target: &IpmActor,
  binding: &IpmBindingCreate,
  requirements: &mut IpmSimulationAuthorizationRequirements,
) -> anyhow::Result<()> {
  let id = generated_binding_id(binding);
  validate_runtime_identifier("simulation overlay binding id", &id)?;
  if binding.principal.is_some() == binding.group.is_some() {
    bail!("simulation overlay binding must set exactly one of principal or group");
  }
  if !snapshot.policies.contains_key(&binding.policy) {
    bail!(
      "simulation overlay binding {id} references unknown policy {}",
      binding.policy
    );
  }
  push_unique(&mut requirements.overlay_bindings, id);
  push_unique(&mut requirements.overlay_policies, binding.policy.clone());

  if let Some(principal) = &binding.principal {
    if !snapshot.principals.contains_key(principal) && principal != &target.principal {
      bail!("simulation overlay binding references unknown principal {principal}");
    }
    push_unique(&mut requirements.overlay_principals, principal.clone());
  }
  if let Some(group) = &binding.group {
    validate_runtime_identifier("simulation overlay binding group", group)?;
    let known_groups = known_groups(snapshot, target);
    if !known_groups.contains(group) {
      bail!("simulation overlay binding references unknown group {group}");
    }
    push_unique(&mut requirements.overlay_groups, group.clone());
  }
  Ok(())
}

fn rebuild_binding_indexes(snapshot: &mut IpmSnapshot) {
  snapshot.principal_bindings.clear();
  snapshot.group_bindings.clear();
  for binding in &snapshot.bindings {
    if !binding.enabled {
      continue;
    }
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
}

fn known_groups(snapshot: &IpmSnapshot, target: &IpmActor) -> HashSet<String> {
  snapshot
    .principals
    .values()
    .flat_map(|principal| principal.actor.groups.iter().cloned())
    .chain(target.groups.iter().cloned())
    .collect()
}

fn generated_binding_id(binding: &IpmBindingCreate) -> String {
  binding
    .id
    .clone()
    .unwrap_or_else(|| match (&binding.principal, &binding.group) {
      (Some(principal), None) => format!("principal.{principal}.{}", binding.policy),
      (None, Some(group)) => format!("group.{group}.{}", binding.policy),
      _ => format!("binding.{}", binding.policy),
    })
}

fn collect_target_requirements(
  target: &IpmSimulationTarget,
  requirements: &mut IpmSimulationAuthorizationRequirements,
) {
  if let Some(principal) = &target.principal {
    push_unique(&mut requirements.target_principals, principal.clone());
  }
  if let Some(credential) = &target.credential {
    push_unique(&mut requirements.target_credentials, credential.clone());
  }
  if let Some(groups) = &target.groups {
    for group in groups {
      push_unique(&mut requirements.target_groups, group.clone());
    }
  }
}

fn collect_overlay_requirements(
  overlay: &IpmSimulationOverlay,
  requirements: &mut IpmSimulationAuthorizationRequirements,
) {
  for policy in &overlay.policies {
    push_unique(&mut requirements.overlay_policies, policy.name.clone());
  }
  for binding in &overlay.bindings {
    push_unique(
      &mut requirements.overlay_bindings,
      generated_binding_id(binding),
    );
    push_unique(&mut requirements.overlay_policies, binding.policy.clone());
    if let Some(principal) = &binding.principal {
      push_unique(&mut requirements.overlay_principals, principal.clone());
    }
    if let Some(group) = &binding.group {
      push_unique(&mut requirements.overlay_groups, group.clone());
    }
  }
}

fn context_summary(context: &IpmRequestContext) -> IpmSimulationContextSummary {
  let mut claim_keys = context.claims.keys().cloned().collect::<Vec<_>>();
  claim_keys.sort();
  IpmSimulationContextSummary {
    source_ip: context.source_ip.map(|ip| ip.to_string()),
    method: context.method.clone(),
    host: context.host.clone(),
    path: context.path.clone(),
    route: context.route.clone(),
    protocol: context.protocol.clone(),
    claim_keys,
  }
}

fn validate_non_empty(field: &str, value: &str) -> anyhow::Result<()> {
  if value.trim().is_empty() {
    bail!("{field} must not be empty");
  }
  Ok(())
}

fn push_unique(values: &mut Vec<String>, value: String) {
  if !values.iter().any(|existing| existing == &value) {
    values.push(value);
  }
}
