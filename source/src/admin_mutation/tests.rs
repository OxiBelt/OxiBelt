use super::*;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use base64::Engine;
use http::{HeaderMap, HeaderValue, Method, Response};

const NOW: i64 = 1_752_494_730;

fn digest(value: &[u8]) -> String {
  super::envelope::sha256_labelled(&[], value)
}

fn unsigned(body: &[u8]) -> UnsignedMutationEnvelope {
  UnsignedMutationEnvelope {
    version: "1".to_string(),
    signer_id: "controller-1".to_string(),
    request_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    issued_at: "2025-07-14T12:00:00Z".to_string(),
    expires_at: "2025-07-14T12:10:00Z".to_string(),
    expected_previous_revision: "r-2041".to_string(),
    new_revision: "r-2042".to_string(),
    content_digest: digest(body),
    target: MutationTarget {
      cluster_id: "edge-a".to_string(),
      membership_revision: digest(b"member-a\nmember-b"),
    },
  }
}

fn context<'a>(body: &'a [u8], principal: &'a str) -> TranscriptContext<'a> {
  TranscriptContext {
    method: &Method::POST,
    path_and_query: "/admin/v1/config/load?validate=true",
    ipm_namespace: "default",
    authenticated_principal: principal,
    body,
    precondition_revision: "oxibelt-config-1",
    now_unix_seconds: NOW,
    maximum_validity_seconds: 900,
    maximum_clock_skew_seconds: 30,
  }
}

fn signed_headers(body: &[u8], principal: &str) -> (HeaderMap, SignerRegistry, Ed25519KeyPair) {
  let key_pair = Ed25519KeyPair::generate().expect("test key generation should succeed");
  let unsigned = unsigned(body);
  let transcript = mutation_transcript(
    &unsigned,
    SignatureSuite::Ed25519,
    &context(body, principal),
  )
  .expect("test envelope should be valid");
  let signature = MutationSignature::Ed25519(
    key_pair
      .sign(&transcript)
      .as_ref()
      .try_into()
      .expect("Ed25519 signatures have a fixed length"),
  );
  let encoded = encode_mutation_header(&unsigned, &signature).expect("encoding should succeed");
  let mut headers = HeaderMap::new();
  headers.insert(
    MUTATION_HEADER,
    HeaderValue::from_str(&encoded).expect("base64url is header safe"),
  );
  let public_key: [u8; 32] = key_pair
    .public_key()
    .as_ref()
    .try_into()
    .expect("Ed25519 public keys have a fixed length");
  let registry =
    SignerRegistry::new([
      SignerBinding::ed25519("controller-1", principal, public_key)
        .expect("test signer should be valid"),
    ])
    .expect("test registry should be valid");
  (headers, registry, key_pair)
}

#[test]
fn verifies_ed25519_envelope_and_returns_stable_fingerprint() {
  let body = br#"{"config":"safe"}"#;
  let (headers, registry, _) = signed_headers(body, "spiffe://example/controller");
  let first = registry
    .verify(&headers, &context(body, "spiffe://example/controller"))
    .expect("valid envelope should verify");
  let second = registry
    .verify(&headers, &context(body, "spiffe://example/controller"))
    .expect("replay should verify identically");
  assert_eq!(first.fingerprint, second.fingerprint);
  assert_eq!(first.envelope.unsigned.new_revision, "r-2042");
}

#[test]
fn rejects_body_path_and_principal_substitution() {
  let body = b"safe";
  let (headers, registry, _) = signed_headers(body, "controller-a");

  let body_error = registry
    .verify(&headers, &context(b"changed", "controller-a"))
    .expect_err("changed body must fail");
  assert_eq!(body_error.kind(), MutationProtocolErrorKind::DigestMismatch);

  let path_context = TranscriptContext {
    path_and_query: "/admin/v1/config/rollback",
    ..context(body, "controller-a")
  };
  let path_error = registry
    .verify(&headers, &path_context)
    .expect_err("changed path must fail");
  assert_eq!(
    path_error.kind(),
    MutationProtocolErrorKind::InvalidSignature
  );

  let precondition_context = TranscriptContext {
    precondition_revision: "oxibelt-config-2",
    ..context(body, "controller-a")
  };
  let precondition_error = registry
    .verify(&headers, &precondition_context)
    .expect_err("changed If-Match precondition must fail");
  assert_eq!(
    precondition_error.kind(),
    MutationProtocolErrorKind::InvalidSignature
  );

  let principal_error = registry
    .verify(&headers, &context(body, "controller-b"))
    .expect_err("changed principal must fail");
  assert_eq!(
    principal_error.kind(),
    MutationProtocolErrorKind::PrincipalMismatch
  );
}

#[test]
fn rejects_duplicate_header_unknown_json_fields_and_noncanonical_base64() {
  let body = b"safe";
  let (headers, _, _) = signed_headers(body, "controller-a");
  let value = headers[MUTATION_HEADER].clone();
  let mut duplicated = headers.clone();
  duplicated.append(MUTATION_HEADER, value.clone());
  assert_eq!(
    parse_mutation_header(&duplicated)
      .expect_err("duplicate header must fail")
      .kind(),
    MutationProtocolErrorKind::InvalidEnvelope
  );

  let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(value.as_bytes())
    .expect("test header decodes");
  let mut object: serde_json::Value = serde_json::from_slice(&decoded).expect("test JSON parses");
  object["unexpected"] = serde_json::Value::Bool(true);
  let unknown = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .encode(serde_json::to_vec(&object).expect("test JSON encodes"));
  let mut unknown_headers = HeaderMap::new();
  unknown_headers.insert(
    MUTATION_HEADER,
    HeaderValue::from_str(&unknown).expect("test header is valid"),
  );
  assert!(parse_mutation_header(&unknown_headers).is_err());

  let mut padded = value.to_str().expect("test header is ASCII").to_string();
  padded.push('=');
  let mut padded_headers = HeaderMap::new();
  padded_headers.insert(
    MUTATION_HEADER,
    HeaderValue::from_str(&padded).expect("padding is header safe"),
  );
  assert!(parse_mutation_header(&padded_headers).is_err());
}

#[test]
fn reordered_json_produces_the_same_transcript() {
  let body = b"safe";
  let unsigned = unsigned(body);
  let original = mutation_transcript(&unsigned, SignatureSuite::Ed25519, &context(body, "p"))
    .expect("valid transcript");
  let signature = MutationSignature::Ed25519([7; 64]);
  let encoded = encode_mutation_header(&unsigned, &signature).expect("encoding should succeed");
  let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(encoded)
    .expect("test envelope decodes");
  let value: serde_json::Value = serde_json::from_slice(&decoded).expect("test envelope parses");
  let reordered = serde_json::json!({
    "signature": value["signature"],
    "target": value["target"],
    "content_digest": value["content_digest"],
    "new_revision": value["new_revision"],
    "expected_previous_revision": value["expected_previous_revision"],
    "expires_at": value["expires_at"],
    "issued_at": value["issued_at"],
    "request_id": value["request_id"],
    "signer_id": value["signer_id"],
    "version": value["version"]
  });
  let reordered = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .encode(serde_json::to_vec(&reordered).expect("test JSON encodes"));
  let mut headers = HeaderMap::new();
  headers.insert(
    MUTATION_HEADER,
    HeaderValue::from_str(&reordered).expect("test header is valid"),
  );
  let parsed = parse_mutation_header(&headers).expect("reordered envelope should parse");
  let actual = mutation_transcript(
    &parsed.unsigned,
    parsed.signature.suite(),
    &context(body, "p"),
  )
  .expect("valid transcript");
  assert_eq!(actual, original);
}

#[test]
fn rejects_noncanonical_or_out_of_policy_fields() {
  let body = b"safe";
  let mut value = unsigned(body);
  value.request_id = "550E8400-E29B-41D4-A716-446655440000".to_string();
  assert!(mutation_transcript(&value, SignatureSuite::Ed25519, &context(body, "p")).is_err());

  let mut value = unsigned(body);
  value.issued_at = "2025-07-14T12:00:00+00:00".to_string();
  assert_eq!(
    mutation_transcript(&value, SignatureSuite::Ed25519, &context(body, "p"))
      .expect_err("noncanonical timestamp must fail")
      .kind(),
    MutationProtocolErrorKind::InvalidTimestamp
  );

  let mut value = unsigned(body);
  value.expires_at = "2025-07-14T13:00:00Z".to_string();
  assert_eq!(
    mutation_transcript(&value, SignatureSuite::Ed25519, &context(body, "p"))
      .expect_err("long validity must fail")
      .kind(),
    MutationProtocolErrorKind::ValidityWindowTooLong
  );

  let mut value = unsigned(body);
  value.expires_at = "2025-07-14T11:59:59Z".to_string();
  assert_eq!(
    mutation_transcript(&value, SignatureSuite::Ed25519, &context(body, "p"))
      .expect_err("invalid interval must fail")
      .kind(),
    MutationProtocolErrorKind::InvalidTimestamp
  );
}

#[test]
fn attaches_mutation_response_headers() {
  let mut response = Response::new(());
  attach_mutation_response_headers(
    &mut response,
    MutationResponseMetadata {
      request_id: "550e8400-e29b-41d4-a716-446655440000",
      revision: "r-2042",
      replayed: true,
    },
  );
  assert_eq!(
    response.headers()[MUTATION_REQUEST_ID_HEADER],
    "550e8400-e29b-41d4-a716-446655440000"
  );
  assert_eq!(response.headers()[MUTATION_REVISION_HEADER], "r-2042");
  assert_eq!(response.headers()[IDEMPOTENT_REPLAY_HEADER], "true");
}

#[cfg(feature = "mutation-pqc")]
#[test]
fn hybrid_signature_requires_both_algorithms() {
  use aws_lc_rs::encoding::AsDer;
  use aws_lc_rs::unstable::signature::{ML_DSA_44_SIGNING, PqdsaKeyPair};

  let body = b"safe";
  let principal = "controller-a";
  let unsigned = unsigned(body);
  let context = context(body, principal);
  let transcript = mutation_transcript(&unsigned, SignatureSuite::Ed25519MlDsa44, &context)
    .expect("test transcript should be valid");
  let ed25519 = Ed25519KeyPair::generate().expect("test Ed25519 key generation should succeed");
  let ml_dsa =
    PqdsaKeyPair::generate(&ML_DSA_44_SIGNING).expect("test ML-DSA key generation should succeed");
  let mut ml_dsa_signature = vec![0; ML_DSA_44_SIGNING.signature_len()];
  ml_dsa
    .sign(&transcript, &mut ml_dsa_signature)
    .expect("test ML-DSA signing should succeed");
  let signature = MutationSignature::Ed25519MlDsa44 {
    ed25519: ed25519
      .sign(&transcript)
      .as_ref()
      .try_into()
      .expect("Ed25519 signature has a fixed length"),
    ml_dsa_44: ml_dsa_signature,
  };
  let encoded = encode_mutation_header(&unsigned, &signature).expect("encoding should succeed");
  let mut headers = HeaderMap::new();
  headers.insert(
    MUTATION_HEADER,
    HeaderValue::from_str(&encoded).expect("encoded envelope is header safe"),
  );
  let registry = SignerRegistry::new([SignerBinding::ed25519_ml_dsa_44(
    "controller-1",
    principal,
    ed25519.public_key().as_ref().to_vec(),
    ml_dsa
      .public_key()
      .as_der()
      .expect("ML-DSA public key encodes")
      .as_ref()
      .to_vec(),
  )
  .expect("hybrid signer should be valid")])
  .expect("test registry should be valid");
  assert!(registry.verify(&headers, &context).is_ok());

  let mut parsed = parse_mutation_header(&headers).expect("test envelope parses");
  let MutationSignature::Ed25519MlDsa44 { ml_dsa_44, .. } = &mut parsed.signature else {
    panic!("expected hybrid signature");
  };
  ml_dsa_44[0] ^= 1;
  let tampered = encode_mutation_header(&parsed.unsigned, &parsed.signature)
    .expect("tampered envelope still encodes");
  headers.insert(
    MUTATION_HEADER,
    HeaderValue::from_str(&tampered).expect("encoded envelope is header safe"),
  );
  assert_eq!(
    registry
      .verify(&headers, &context)
      .expect_err("one bad hybrid component must fail")
      .kind(),
    MutationProtocolErrorKind::InvalidSignature
  );

  headers.insert(
    MUTATION_HEADER,
    HeaderValue::from_str(&encoded).expect("encoded envelope is header safe"),
  );
  let mut parsed = parse_mutation_header(&headers).expect("test envelope parses");
  let MutationSignature::Ed25519MlDsa44 { ed25519, .. } = &mut parsed.signature else {
    panic!("expected hybrid signature");
  };
  ed25519[0] ^= 1;
  let tampered = encode_mutation_header(&parsed.unsigned, &parsed.signature)
    .expect("tampered envelope still encodes");
  headers.insert(
    MUTATION_HEADER,
    HeaderValue::from_str(&tampered).expect("encoded envelope is header safe"),
  );
  assert_eq!(
    registry
      .verify(&headers, &context)
      .expect_err("bad classical hybrid component must fail")
      .kind(),
    MutationProtocolErrorKind::InvalidSignature
  );
}
