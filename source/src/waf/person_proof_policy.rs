//! Person proof policy compilation.
//! Policy state is separated from token issuance so route decisions remain inspectable.

use super::person_proof::PersonProofPolicy;
use super::person_proof::{PersonProofClearancePolicy, PersonProofRequestStatus, PersonProofState};
use super::person_proof_v2;
use super::{WafActionConfig, WafPersonProofConfig, WafRuleConfig};

#[derive(Debug, Clone, Default)]
pub(super) struct PersonProofPolicyState {
  weight: i64,
  allowed: bool,
}

impl PersonProofPolicyState {
  pub(super) fn from_status(status: &PersonProofRequestStatus) -> Self {
    Self {
      weight: status.weight,
      allowed: status.allowed,
    }
  }

  pub(super) fn apply_to(&self, status: &mut PersonProofRequestStatus) {
    status.weight = self.weight;
    status.allowed = self.allowed;
  }

  pub(super) fn add_weight(&mut self, weight: i64) {
    self.weight = self.weight.saturating_add(weight);
  }

  pub(super) fn allow(&mut self) {
    self.allowed = true;
  }

  pub(super) fn challenge_suppressed(&self, status: &PersonProofRequestStatus) -> bool {
    status.state == PersonProofState::Valid || self.allowed
  }
}

pub(super) fn from_action(
  rule: &WafRuleConfig,
  scope: &str,
  action_index: usize,
  action: &WafActionConfig,
  defaults: &WafPersonProofConfig,
) -> PersonProofPolicy {
  let WafActionConfig::RequirePersonProof {
    priority: _,
    person_proof_mode,
    difficulty,
    ttl_seconds,
    cookie: _,
    clearance,
    token_bindings,
    direct_peer_ipv4_prefix_bits,
    direct_peer_ipv6_prefix_bits,
    tcp_max_hop,
    single_use,
    success_tag,
    status,
    custom_frontend_url,
    challenge_redirect_status,
    session_path,
    verify_path,
    openapi_path,
    third_party_provider,
    provider,
    provider_metadata,
    site_key,
    secret_env,
    provider_endpoint,
    provider_timeout_ms,
    provider_fail_policy,
    provider_max_response_body_bytes,
    send_remote_ip,
    ..
  } = action
  else {
    unreachable!("person_proof_policy::from_action requires require_person_proof action");
  };
  let rule_key = rule
    .id
    .as_deref()
    .filter(|id| !id.is_empty())
    .unwrap_or(&rule.name);
  PersonProofPolicy {
    key: format!("{scope}:{rule_key}:{action_index}"),
    mode: *person_proof_mode,
    third_party_provider: *third_party_provider,
    difficulty: *difficulty,
    ttl_seconds: *ttl_seconds,
    clearance: PersonProofClearancePolicy::from_config(clearance),
    token_bindings: token_bindings.clone(),
    direct_peer_ipv4_prefix_bits: *direct_peer_ipv4_prefix_bits,
    direct_peer_ipv6_prefix_bits: *direct_peer_ipv6_prefix_bits,
    tcp_max_hop: *tcp_max_hop,
    single_use: *single_use,
    success_tag: success_tag.clone(),
    status: *status,
    provider: person_proof_v2::PersonProofProviderConfig {
      custom_frontend_url: custom_frontend_url.clone(),
      challenge_redirect_status: *challenge_redirect_status,
      session_path: session_path
        .clone()
        .unwrap_or_else(|| defaults.session_path.clone()),
      verify_path: verify_path
        .clone()
        .unwrap_or_else(|| defaults.verify_path.clone()),
      openapi_path: openapi_path
        .clone()
        .unwrap_or_else(|| defaults.openapi_path.clone()),
      provider: provider.clone(),
      provider_metadata: provider_metadata.clone(),
      site_key: site_key.clone(),
      secret_env: secret_env.clone(),
      provider_endpoint: provider_endpoint.as_deref().cloned(),
      provider_timeout_ms: *provider_timeout_ms,
      provider_fail_policy: *provider_fail_policy,
      provider_max_response_body_bytes: *provider_max_response_body_bytes,
      send_remote_ip: *send_remote_ip,
    },
  }
}
