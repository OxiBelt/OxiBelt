//! Dynamic Person proof challenge evaluation.
//! Dynamic outcomes are folded back into the same clearance boundary as static policy.

use anyhow::Context;
use http::StatusCode;

use super::defaults::{
  default_person_proof_challenge_redirect_status, default_person_proof_difficulty,
  default_person_proof_direct_peer_ipv4_prefix_bits,
  default_person_proof_direct_peer_ipv6_prefix_bits,
  default_person_proof_provider_max_response_body_bytes, default_person_proof_provider_timeout_ms,
  default_person_proof_single_use, default_person_proof_token_bindings,
  default_person_proof_token_validity_seconds, default_true,
};
use super::person_proof::{PersonProofClearancePolicy, PersonProofEngine, PersonProofPolicy};
use super::{PersonProofClearanceConfig, PersonProofMode, WafPersonProofConfig};

const DYNAMIC_POLICY_PERSON_PROOF_KEY: &str = "dynamic-policy:challenge:v1";

pub(super) fn challenge_policy(
  engine: &PersonProofEngine,
  status: StatusCode,
) -> anyhow::Result<PersonProofPolicy> {
  let mut policy = engine
    .policies
    .iter()
    .find(|policy| policy.key == DYNAMIC_POLICY_PERSON_PROOF_KEY)
    .cloned()
    .context("dynamic policy Person proof challenge policy is unavailable")?;
  policy.status = status.as_u16();
  Ok(policy)
}

pub(super) fn policy(defaults: &WafPersonProofConfig) -> PersonProofPolicy {
  PersonProofPolicy {
    key: DYNAMIC_POLICY_PERSON_PROOF_KEY.to_string(),
    mode: PersonProofMode::BuiltIn,
    third_party_provider: None,
    difficulty: default_person_proof_difficulty(),
    ttl_seconds: default_person_proof_token_validity_seconds(),
    clearance: PersonProofClearancePolicy::from_config(&PersonProofClearanceConfig::default()),
    token_bindings: default_person_proof_token_bindings(),
    direct_peer_ipv4_prefix_bits: default_person_proof_direct_peer_ipv4_prefix_bits(),
    direct_peer_ipv6_prefix_bits: default_person_proof_direct_peer_ipv6_prefix_bits(),
    tcp_max_hop: None,
    single_use: default_person_proof_single_use(),
    success_tag: None,
    status: StatusCode::FORBIDDEN.as_u16(),
    provider: super::person_proof_v2::PersonProofProviderConfig {
      custom_frontend_url: None,
      challenge_redirect_status: default_person_proof_challenge_redirect_status(),
      session_path: defaults.session_path.clone(),
      verify_path: defaults.verify_path.clone(),
      openapi_path: defaults.openapi_path.clone(),
      provider: None,
      provider_metadata: serde_json::Value::Null,
      proof_kind: None,
      proof_challenge_kind: None,
      proof_label: None,
      site_key: None,
      secret_env: None,
      provider_endpoint: None,
      provider_timeout_ms: default_person_proof_provider_timeout_ms(),
      provider_fail_policy: Default::default(),
      provider_max_response_body_bytes: default_person_proof_provider_max_response_body_bytes(),
      send_remote_ip: default_true(),
    },
  }
}
