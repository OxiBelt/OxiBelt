use std::io::Write;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use clap::Parser;
use http::Method;
use oxibelt::admin_mutation::{MUTATION_HEADER, SignerBinding, SignerRegistry, TranscriptContext};
use tempfile::NamedTempFile;

use crate::cli::{Cli, MutationArgs};
use crate::mutation_signer::{MutationSigner, is_protected_mutation};

const NOW: i64 = 1_752_494_730;

#[test]
fn signs_exact_admin_json_bytes_with_ed25519() {
  let key_pair = Ed25519KeyPair::generate().expect("test key generation");
  let key_file = write_private_key(&key_pair, 0o600);
  let signer =
    MutationSigner::from_args_at(&mutation_args(key_file.path()), NOW).expect("test signer loads");
  let body = br#"{"config":"safe"}"#;
  let headers = signer
    .headers_for_request(
      &Method::POST,
      "/admin/v1/config/load",
      body,
      Some("\"oxibelt-config-1\""),
    )
    .expect("request signs");
  assert!(headers.contains_key(MUTATION_HEADER));

  let registry = SignerRegistry::new([SignerBinding::ed25519(
    "controller-1",
    "controller",
    key_pair.public_key().as_ref(),
  )
  .expect("public key binds")])
  .expect("registry builds");
  let context = TranscriptContext {
    method: &Method::POST,
    path_and_query: "/admin/v1/config/load",
    ipm_namespace: "oxibelt",
    authenticated_principal: "controller",
    body,
    precondition_revision: "oxibelt-config-1",
    now_unix_seconds: NOW,
    maximum_validity_seconds: 600,
    maximum_clock_skew_seconds: 30,
  };
  let verified = registry
    .verify(&headers, &context)
    .expect("signature verifies");
  assert_eq!(
    verified.envelope.unsigned.request_id,
    "550e8400-e29b-41d4-a716-446655440000"
  );
  assert_eq!(verified.envelope.unsigned.issued_at, "2025-07-14T12:05:30Z");
  assert_eq!(
    verified.envelope.unsigned.expires_at,
    "2025-07-14T12:10:30Z"
  );
}

#[test]
fn exact_retry_reuses_header_but_request_substitution_is_rejected() {
  let key_pair = Ed25519KeyPair::generate().expect("test key generation");
  let key_file = write_private_key(&key_pair, 0o600);
  let signer =
    MutationSigner::from_args_at(&mutation_args(key_file.path()), NOW).expect("test signer loads");
  let first = signer
    .headers_for_request(
      &Method::POST,
      "/admin/v1/files/sync",
      b"same",
      Some("\"oxibelt-config-1\""),
    )
    .expect("first request signs");
  let retry = signer
    .headers_for_request(
      &Method::POST,
      "/admin/v1/files/sync",
      b"same",
      Some("\"oxibelt-config-1\""),
    )
    .expect("exact retry signs");
  assert_eq!(first, retry);
  assert!(
    signer
      .headers_for_request(
        &Method::POST,
        "/admin/v1/files/sync",
        b"changed",
        Some("\"oxibelt-config-1\""),
      )
      .is_err()
  );
  assert!(
    signer
      .headers_for_request(
        &Method::POST,
        "/admin/v1/files/sync",
        b"same",
        Some("\"oxibelt-config-2\""),
      )
      .is_err()
  );
}

#[test]
fn explicit_timestamps_reproduce_an_envelope_across_cli_invocations() {
  let key_pair = Ed25519KeyPair::generate().expect("test key generation");
  let key_file = write_private_key(&key_pair, 0o600);
  let mut args = mutation_args(key_file.path());
  args.issued_at = Some("2025-07-14T12:05:30Z".to_string());
  args.expires_at = Some("2025-07-14T12:10:30Z".to_string());
  let first = MutationSigner::from_args_at(&args, NOW)
    .expect("first signer loads")
    .headers_for_request(
      &Method::POST,
      "/admin/v1/config/load",
      b"same",
      Some("\"oxibelt-config-1\""),
    )
    .expect("first request signs");
  let retry = MutationSigner::from_args_at(&args, NOW)
    .expect("retry signer loads")
    .headers_for_request(
      &Method::POST,
      "/admin/v1/config/load",
      b"same",
      Some("\"oxibelt-config-1\""),
    )
    .expect("retry signs");
  assert_eq!(first, retry);
}

#[test]
fn signs_only_the_p1_13_protected_mutation_set() {
  assert!(is_protected_mutation(
    &Method::POST,
    "/admin/v1/config/rollback"
  ));
  assert!(is_protected_mutation(
    &Method::DELETE,
    "/admin/v1/ipm/credentials/deploy-bot"
  ));
  assert!(is_protected_mutation(
    &Method::POST,
    "/admin/v1/break-glass/activations/abc/revoke"
  ));
  assert!(!is_protected_mutation(
    &Method::POST,
    "/admin/v1/ipm/simulate/self"
  ));
  assert!(!is_protected_mutation(
    &Method::POST,
    "/admin/v1/dynamic-policies/apply"
  ));
  assert!(!is_protected_mutation(
    &Method::GET,
    "/admin/v1/config/status"
  ));
}

#[test]
fn mutation_flags_require_explicit_signing_opt_in() {
  let result = Cli::try_parse_from([
    "oxibeltctl",
    "--mutation-signer-id",
    "controller-1",
    "status",
  ]);
  assert!(result.is_err());
}

#[test]
fn parses_complete_mutation_signing_configuration() {
  let parsed = Cli::try_parse_from([
    "oxibeltctl",
    "--sign-mutation",
    "--mutation-signer-id",
    "controller-1",
    "--mutation-principal",
    "controller",
    "--mutation-ed25519-key-file",
    "/run/keys/controller.pk8",
    "--mutation-expected-revision",
    "r-2041",
    "--mutation-new-revision",
    "r-2042",
    "--mutation-cluster-id",
    "edge-a",
    "--mutation-membership-revision",
    "sha256:09d252f349bb467a3e2c0da336d9539a119a0105ec63d6b45c6b35865f4892fa",
    "--mutation-request-id",
    "550e8400-e29b-41d4-a716-446655440000",
    "--mutation-issued-at",
    "2025-07-14T12:05:30Z",
    "--mutation-expires-at",
    "2025-07-14T12:10:30Z",
    "status",
  ])
  .expect("complete signing flags parse");
  assert!(parsed.admin.mutation.enabled);
  assert_eq!(
    parsed.admin.mutation.ed25519_key_file.as_deref(),
    Some(std::path::Path::new("/run/keys/controller.pk8"))
  );
}

#[cfg(feature = "mutation-pqc")]
#[test]
fn signs_with_both_hybrid_components() {
  use aws_lc_rs::encoding::AsDer;
  use aws_lc_rs::unstable::signature::{ML_DSA_44_SIGNING, PqdsaKeyPair};

  let ed25519 = Ed25519KeyPair::generate().expect("test Ed25519 key generation");
  let ml_dsa_44 = PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).expect("test ML-DSA key generation");
  let ed25519_file = write_private_key(&ed25519, 0o600);
  let ml_dsa_file = write_key_bytes(
    ml_dsa_44
      .to_pkcs8()
      .expect("serialize test ML-DSA key")
      .as_ref(),
    0o600,
  );
  let mut args = mutation_args(ed25519_file.path());
  args.ml_dsa_44_key_file = Some(ml_dsa_file.path().to_path_buf());
  let signer = MutationSigner::from_args_at(&args, NOW).expect("hybrid signer loads");
  let body = b"hybrid";
  let headers = signer
    .headers_for_request(
      &Method::POST,
      "/admin/v1/config/load",
      body,
      Some("\"oxibelt-config-1\""),
    )
    .expect("hybrid request signs");

  let ml_dsa_public = ml_dsa_44
    .public_key()
    .as_der()
    .expect("serialize ML-DSA public key");
  let registry = SignerRegistry::new([SignerBinding::ed25519_ml_dsa_44(
    "controller-1",
    "controller",
    ed25519.public_key().as_ref(),
    ml_dsa_public.as_ref().to_vec(),
  )
  .expect("hybrid public keys bind")])
  .expect("hybrid registry builds");
  registry
    .verify(
      &headers,
      &TranscriptContext {
        method: &Method::POST,
        path_and_query: "/admin/v1/config/load",
        ipm_namespace: "oxibelt",
        authenticated_principal: "controller",
        body,
        precondition_revision: "oxibelt-config-1",
        now_unix_seconds: NOW,
        maximum_validity_seconds: 600,
        maximum_clock_skew_seconds: 30,
      },
    )
    .expect("both signatures verify");
}

#[cfg(unix)]
#[test]
fn rejects_group_or_world_accessible_private_keys() {
  let key_pair = Ed25519KeyPair::generate().expect("test key generation");
  let key_file = write_private_key(&key_pair, 0o644);
  let error = MutationSigner::from_args_at(&mutation_args(key_file.path()), NOW)
    .err()
    .expect("insecure permissions fail");
  assert!(error.to_string().contains("group or other users"));
}

fn mutation_args(key_file: &std::path::Path) -> MutationArgs {
  MutationArgs {
    enabled: true,
    signer_id: Some("controller-1".to_string()),
    principal: Some("controller".to_string()),
    ed25519_key_file: Some(key_file.to_path_buf()),
    ed25519_key_file_env: None,
    ml_dsa_44_key_file: None,
    ml_dsa_44_key_file_env: None,
    namespace: "oxibelt".to_string(),
    expected_revision: Some("r-2041".to_string()),
    new_revision: Some("r-2042".to_string()),
    cluster_id: Some("edge-a".to_string()),
    membership_revision: Some(
      "sha256:09d252f349bb467a3e2c0da336d9539a119a0105ec63d6b45c6b35865f4892fa".to_string(),
    ),
    request_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
    issued_at: None,
    expires_at: None,
    validity_seconds: 300,
  }
}

fn write_private_key(key_pair: &Ed25519KeyPair, mode: u32) -> NamedTempFile {
  let document = key_pair.to_pkcs8().expect("serialize test key");
  write_key_bytes(document.as_ref(), mode)
}

fn write_key_bytes(bytes: &[u8], mode: u32) -> NamedTempFile {
  let mut file = NamedTempFile::new().expect("temporary key file");
  file.write_all(bytes).expect("write test key");
  file.flush().expect("flush test key");
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(mode))
      .expect("set test key permissions");
  }
  let _ = mode;
  file
}
