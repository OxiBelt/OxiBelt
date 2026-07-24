//! Stable diagnostic rule codes.
//!
//! Dotted finding identifiers predate the public doctor contract.  Keep them
//! as compatibility aliases while exposing short, stable codes to people and
//! automation.  New public rules must be added here rather than deriving a
//! code from user-controlled input.

/// Returns the stable machine-readable code for a diagnostic identifier.
pub(super) fn code_for(id: &str) -> String {
  match id {
    "admin.public_without_mtls" => "ADM-001".to_string(),
    "kubernetes.controller_rollout_wiring" => "K8S-004".to_string(),
    "kubernetes.multi_instance_missing_revision" => "K8S-005".to_string(),
    "kubernetes.unsupported_server_version" => "K8S-006".to_string(),
    "kubernetes.required_gateway_api_missing" => "K8S-007".to_string(),
    "kubernetes.component_version_skew" => "K8S-009".to_string(),
    "real_ip.no_trusted_proxies" => "PROXY-002".to_string(),
    "tls.http3_host_key_missing" => "TLS-013".to_string(),
    "shared_state.redis_plaintext_remote" => "STATE-008".to_string(),
    "waf.decoded_body_limit_exceeds_request_limit" => "WAF-021".to_string(),
    "admin.audit_not_durable" => "AUD-003".to_string(),
    "release.image_not_digest_pinned" => "REL-012".to_string(),
    _ => legacy_code(id),
  }
}

// Retain stable codes for pre-contract findings without forcing an unrelated
// renumbering of their long-standing dotted identifiers. FNV-1a is used only
// as a deterministic label, never for a security decision.
fn legacy_code(id: &str) -> String {
  let mut hash = 0x811c_9dc5_u32;
  for byte in id.bytes() {
    hash ^= u32::from(byte);
    hash = hash.wrapping_mul(0x0100_0193);
  }
  format!("LEGACY-{hash:08X}")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn required_public_rules_have_fixed_codes() {
    assert_eq!(code_for("admin.public_without_mtls"), "ADM-001");
    assert_eq!(code_for("kubernetes.controller_rollout_wiring"), "K8S-004");
    assert_eq!(
      code_for("kubernetes.multi_instance_missing_revision"),
      "K8S-005"
    );
    assert_eq!(code_for("kubernetes.unsupported_server_version"), "K8S-006");
    assert_eq!(
      code_for("kubernetes.required_gateway_api_missing"),
      "K8S-007"
    );
    assert_eq!(code_for("kubernetes.component_version_skew"), "K8S-009");
    assert_eq!(code_for("real_ip.no_trusted_proxies"), "PROXY-002");
    assert_eq!(code_for("tls.http3_host_key_missing"), "TLS-013");
    assert_eq!(code_for("shared_state.redis_plaintext_remote"), "STATE-008");
    assert_eq!(
      code_for("waf.decoded_body_limit_exceeds_request_limit"),
      "WAF-021"
    );
    assert_eq!(code_for("admin.audit_not_durable"), "AUD-003");
    assert_eq!(code_for("release.image_not_digest_pinned"), "REL-012");
  }

  #[test]
  fn legacy_codes_are_deterministic() {
    assert_eq!(
      code_for("cache.key_missing_host"),
      code_for("cache.key_missing_host")
    );
    assert_ne!(
      code_for("cache.key_missing_host"),
      code_for("cache.key_missing_scheme")
    );
  }
}
