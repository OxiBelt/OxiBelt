//! Admin-facing redacted projections of the active IPM snapshot.

use super::{IpmActor, IpmRuntime, RedactedIpmBinding, RedactedIpmCredential, RedactedIpmPolicy};

impl IpmRuntime {
  pub fn list_principals(&self) -> Vec<IpmActor> {
    let snapshot = self.snapshot();
    let mut principals = snapshot
      .principals
      .values()
      .map(|principal| principal.actor.clone())
      .collect::<Vec<_>>();
    principals.sort_by(|left, right| left.principal.cmp(&right.principal));
    principals
  }

  pub fn list_policies(&self) -> Vec<RedactedIpmPolicy> {
    let snapshot = self.snapshot();
    let mut policies = snapshot
      .policies
      .values()
      .map(|policy| RedactedIpmPolicy {
        name: policy.policy.name.clone(),
        version: policy.policy.version.clone(),
        statements: policy.policy.statements.clone(),
        enabled: policy.enabled,
        source: policy.source,
      })
      .collect::<Vec<_>>();
    policies.sort_by(|left, right| left.name.cmp(&right.name));
    policies
  }

  pub fn list_credentials(&self) -> Vec<RedactedIpmCredential> {
    let snapshot = self.snapshot();
    let mut credentials = snapshot
      .credentials
      .iter()
      .map(|credential| RedactedIpmCredential {
        name: credential.name.clone(),
        principal: credential.principal.clone(),
        bearer_token_env: credential.bearer_token_env.clone(),
        break_glass_access: credential.break_glass_access_token_hash.is_some(),
        source: credential.source,
        enabled: credential.enabled,
        revoked: credential.revoked,
        expires_at: credential.expires_at.clone(),
        token_prefix: credential.token_prefix.clone(),
        previous_token_prefix: credential.previous_token_prefix.clone(),
        previous_token_overlap_until: credential.previous_token_overlap_until.clone(),
      })
      .collect::<Vec<_>>();
    credentials.sort_by(|left, right| left.name.cmp(&right.name));
    credentials
  }

  pub fn list_bindings(&self) -> Vec<RedactedIpmBinding> {
    let snapshot = self.snapshot();
    let mut bindings = snapshot
      .bindings
      .iter()
      .map(|binding| RedactedIpmBinding {
        id: binding.id.clone(),
        principal: binding.principal.clone(),
        group: binding.group.clone(),
        policy: binding.policy.clone(),
        enabled: binding.enabled,
        source: binding.source,
      })
      .collect::<Vec<_>>();
    bindings.sort_by(|left, right| left.id.cmp(&right.id));
    bindings
  }
}
