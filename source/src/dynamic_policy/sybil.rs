//! Dynamic policy Sybil identity configuration adapters.

use crate::config::DynamicPolicyConfig;
use crate::limits::sybil_identity::SybilIdentitySpec;

pub(super) fn sybil_spec(config: &DynamicPolicyConfig) -> SybilIdentitySpec<'_> {
  SybilIdentitySpec {
    ipv4_prefix_bits: config.matching.ipv4_prefix_bits,
    ipv6_prefix_bits: config.matching.ipv6_prefix_bits,
    identity_parts: &config.matching.composite_identity_parts,
    token_bindings: &config.matching.token_bindings,
  }
}
