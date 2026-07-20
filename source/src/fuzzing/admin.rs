use std::fmt::Write as _;

use http::header::HeaderValue;
use http::{HeaderMap, Method};
use sha2::{Digest, Sha256};

use crate::admin_mutation::{
  MUTATION_HEADER, MutationSignature, MutationTarget, TranscriptContext, UnsignedMutationEnvelope,
  encode_mutation_header, mutation_transcript, parse_mutation_header,
};

pub fn exercise_admin_json_mutations(data: &[u8]) {
  #[cfg(feature = "admin-runtime")]
  crate::server::fuzz_admin_json_mutation(data);
}

pub fn exercise_admin_mutation_envelope(data: &[u8]) {
  const MAX_HEADER_BYTES: usize = 8 * 1024;
  let data = &data[..data.len().min(MAX_HEADER_BYTES)];
  let mut headers = HeaderMap::new();
  if let Ok(value) = HeaderValue::from_bytes(data) {
    headers.append(MUTATION_HEADER, value.clone());
    if data.first().is_some_and(|byte| byte & 1 == 1) {
      headers.append(MUTATION_HEADER, value);
    }
  }
  if let Ok(envelope) = parse_mutation_header(&headers) {
    let _ = encode_mutation_header(&envelope.unsigned, &envelope.signature);
    exercise_transcript(&envelope.unsigned, envelope.signature.suite(), data);
  }

  let body = data.get(1..).unwrap_or_default();
  let digest = Sha256::digest(body);
  let mut content_digest = String::from("sha256:");
  for byte in digest {
    let _ = write!(content_digest, "{byte:02x}");
  }
  let unsigned = UnsignedMutationEnvelope {
    version: "1".to_string(),
    signer_id: "fuzz-signer".to_string(),
    request_id: "018f4d2a-7b6c-7d8e-8f90-123456789abc".to_string(),
    issued_at: "2026-01-01T00:00:00Z".to_string(),
    expires_at: "2026-01-01T00:05:00Z".to_string(),
    expected_previous_revision: "revision-old".to_string(),
    new_revision: "revision-new".to_string(),
    content_digest,
    target: MutationTarget {
      cluster_id: "fuzz-cluster".to_string(),
      membership_revision: format!("sha256:{}", "0".repeat(64)),
    },
  };
  let signature = MutationSignature::Ed25519([data.first().copied().unwrap_or_default(); 64]);
  if let Ok(encoded) = encode_mutation_header(&unsigned, &signature)
    && let Ok(value) = HeaderValue::from_str(&encoded)
  {
    let mut canonical = HeaderMap::new();
    canonical.insert(MUTATION_HEADER, value);
    let _ = parse_mutation_header(&canonical);
  }
  exercise_transcript(&unsigned, signature.suite(), body);
}

fn exercise_transcript(
  unsigned: &UnsignedMutationEnvelope,
  suite: crate::admin_mutation::SignatureSuite,
  body: &[u8],
) {
  let method = Method::POST;
  let context = TranscriptContext {
    method: &method,
    path_and_query: "/admin/v1/config",
    ipm_namespace: "default",
    authenticated_principal: "fuzz-principal",
    body,
    precondition_revision: "revision-old",
    now_unix_seconds: 1_767_225_601,
    maximum_validity_seconds: 600,
    maximum_clock_skew_seconds: 30,
  };
  let _ = mutation_transcript(unsigned, suite, &context);
}

pub fn exercise_cluster_rollout_state(data: &[u8]) {
  crate::admin_mutation::fuzz_cluster_rollout(data);
}
