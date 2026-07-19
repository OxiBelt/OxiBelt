use super::*;

#[test]
fn key_rotation_rejects_raw_material_and_traversal() {
  let pem = KeyRotationRequest {
    target: KeyRotationTarget::DownstreamTlsDefault,
    name: None,
    reference: "-----BEGIN PRIVATE KEY-----".to_string(),
    sha256: "a".repeat(64),
  };
  assert!(validate_key_rotation(&pem).is_err());

  let traversal = KeyRotationRequest {
    reference: "../private.pem".to_string(),
    ..pem
  };
  assert!(validate_key_rotation(&traversal).is_err());
  assert!(active_reference_shape(&traversal.reference).is_err());
}

#[test]
fn key_rotation_wire_targets_are_limited_to_supported_downstream_tls_paths() {
  for target in ["admin_tls", "quic_host_key", "remote_signer"] {
    let value = serde_json::json!({
      "target": target,
      "reference": "private.pem",
      "sha256": "a".repeat(64),
    });
    assert!(serde_json::from_value::<KeyRotationRequest>(value).is_err());
  }
}

#[test]
fn secret_reference_allowlist_excludes_control_plane_backends() {
  assert_eq!(
    SecretReferenceField::parse("tls.remote_signer.token_env"),
    Ok(SecretReferenceField::TlsRemoteSignerTokenEnv)
  );
  assert!(SecretReferenceField::parse("admin.mutations.backend/connection_url_env").is_err());
  assert!(SecretReferenceField::parse("admin.audit.backend/connection_url_env").is_err());
  assert!(SecretReferenceField::parse("shared_state.backends/replay/connection_url_env").is_err());
}

#[test]
fn file_and_environment_references_have_distinct_pinning_rules() {
  let file = SecretReferenceUpdateRequest {
    schema_version: 1,
    field: "tls.remote_signer.token_file".to_string(),
    reference: "signer/token.b64".to_string(),
    sha256: Some("b".repeat(64)),
  };
  assert!(validate_secret_reference(&file).is_ok());

  let mut environment = SecretReferenceUpdateRequest {
    schema_version: 1,
    field: "tls.remote_signer.token_env".to_string(),
    reference: "OXIBELT_KEYSIGNER_TOKEN_NEXT".to_string(),
    sha256: None,
  };
  assert!(validate_secret_reference(&environment).is_ok());
  environment.sha256 = Some("c".repeat(64));
  assert!(validate_secret_reference(&environment).is_err());
}

#[test]
fn break_glass_ttl_and_reason_are_bounded() {
  assert!(
    validate_break_glass_activation(
      &BreakGlassActivationRequest {
        ttl_seconds: 900,
        reason: Some("recover locked policy".to_string()),
      },
      900,
    )
    .is_ok()
  );
  assert!(
    validate_break_glass_activation(
      &BreakGlassActivationRequest {
        ttl_seconds: 901,
        reason: None,
      },
      900,
    )
    .is_err()
  );
}

#[test]
fn revoke_path_requires_one_canonical_uuid_component() {
  let id = "018f0a2c-b4d2-7c55-8e21-a5ca349955f1";
  assert_eq!(
    break_glass_revoke_id(&format!("/admin/v1/break-glass/activations/{id}/revoke")),
    Some(id)
  );
  assert!(is_canonical_uuid(id));
  assert!(break_glass_revoke_id("/admin/v1/break-glass/activations/a/b/revoke").is_none());
}

fn active_reference_shape(reference: &str) -> Result<(), &'static str> {
  validate_safe_reference(reference)?;
  validate_relative_path(reference)
}
