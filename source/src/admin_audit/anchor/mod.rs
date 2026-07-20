//! Versioned, externally verifiable Admin audit checkpoints.
//!
//! Checkpoints deliberately contain only chain and deployment metadata. Event
//! payloads stay in the local audit store and private signing keys stay in the
//! purpose-bound keysigner process.

use anyhow::{Context, ensure};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::event::canonical_json_bytes;

mod local;
#[cfg(test)]
mod postgres_tests;
mod runtime;
mod sink;

pub(crate) use local::{
  AnchorCandidateOutcome, AnchorOutboxEntry, AnchorStreamIdentity, initialize_local_anchor,
  load_pending_outbox, observed_position, pending_usage, record_event_in_transaction,
  seal_candidate, seal_due_candidate,
};
pub(crate) use runtime::{AuditAnchorRuntime, AuditAnchorStatus};
pub(crate) use sink::{AuditAnchorSink, PostgresAnchorSink, postgres_database_identity};
pub(crate) use sink::{load_terminal_confirmation_checkpoints, promote_terminal_confirmations};

pub const AUDIT_CHECKPOINT_FORMAT_VERSION: &str = "oxibelt.admin.audit.checkpoint/v1";
pub const AUDIT_CHECKPOINT_SIGNING_ALGORITHM: &str = "ed25519";
pub const AUDIT_CHECKPOINT_GENESIS_DIGEST: &str =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) const CHECKPOINT_SIGNATURE_DOMAIN: &[u8] =
  b"oxibelt.admin.audit.checkpoint.signature/v1\0";
const CHECKPOINT_BODY_DOMAIN: &[u8] = b"oxibelt.admin.audit.checkpoint.body/v1\0";
const CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"oxibelt.admin.audit.checkpoint.digest/v1\0";

/// Metadata signed for one contiguous range of a per-instance event chain.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheckpointBodyV1 {
  pub format_version: String,
  pub namespace: String,
  pub stream_id: String,
  pub instance_id: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub cluster_id: Option<String>,
  pub membership_epoch: String,
  pub deployment_epoch: String,
  pub checkpoint_ordinal: u64,
  pub chain_id: String,
  pub first_sequence: u64,
  pub last_sequence: u64,
  pub chain_head: String,
  pub previous_checkpoint_digest: String,
  pub wall_timestamp: String,
  pub source_database_timestamp: String,
  pub signing_key_id: String,
  pub signing_algorithm: String,
}

/// Signed checkpoint representation stored by the external authority.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuditCheckpointV1 {
  pub body: AuditCheckpointBodyV1,
  pub signature: String,
  pub checkpoint_digest: String,
}

#[derive(Serialize)]
struct SignedCheckpointDigestInput<'a> {
  body: &'a AuditCheckpointBodyV1,
  signature: &'a str,
}

/// Independent PostgreSQL acknowledgement retained in the local outbox.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorReceiptV1 {
  pub authority_id: String,
  pub namespace: String,
  pub stream_id: String,
  pub checkpoint_ordinal: u64,
  pub checkpoint_digest: String,
  pub authority_received_at: String,
}

pub fn checkpoint_body_digest(body: &AuditCheckpointBodyV1) -> anyhow::Result<[u8; 32]> {
  validate_checkpoint_body(body)?;
  let canonical = canonical_json_bytes(&serde_json::to_value(body)?)?;
  let mut input = Vec::with_capacity(CHECKPOINT_BODY_DOMAIN.len() + canonical.len());
  input.extend_from_slice(CHECKPOINT_BODY_DOMAIN);
  input.extend_from_slice(&canonical);
  Ok(crate::crypto::sha256(&input))
}

pub fn checkpoint_signing_transcript(body: &AuditCheckpointBodyV1) -> anyhow::Result<Vec<u8>> {
  let digest = checkpoint_body_digest(body)?;
  let mut transcript = Vec::with_capacity(CHECKPOINT_SIGNATURE_DOMAIN.len() + digest.len());
  transcript.extend_from_slice(CHECKPOINT_SIGNATURE_DOMAIN);
  transcript.extend_from_slice(&digest);
  Ok(transcript)
}

pub fn compute_checkpoint_digest(
  body: &AuditCheckpointBodyV1,
  signature: &str,
) -> anyhow::Result<String> {
  validate_signature_encoding(signature)?;
  let value = serde_json::to_value(SignedCheckpointDigestInput { body, signature })?;
  let canonical = canonical_json_bytes(&value)?;
  let mut input = Vec::with_capacity(CHECKPOINT_DIGEST_DOMAIN.len() + canonical.len());
  input.extend_from_slice(CHECKPOINT_DIGEST_DOMAIN);
  input.extend_from_slice(&canonical);
  Ok(format!(
    "sha256:{}",
    hex_encode(&crate::crypto::sha256(&input))
  ))
}

pub fn assemble_signed_checkpoint(
  body: AuditCheckpointBodyV1,
  signature: &[u8],
) -> anyhow::Result<SignedAuditCheckpointV1> {
  ensure!(
    signature.len() == 64,
    "audit checkpoint Ed25519 signature must be 64 bytes"
  );
  let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
  let checkpoint_digest = compute_checkpoint_digest(&body, &signature)?;
  Ok(SignedAuditCheckpointV1 {
    body,
    signature,
    checkpoint_digest,
  })
}

pub fn verify_checkpoint_signature(
  checkpoint: &SignedAuditCheckpointV1,
  public_key: &[u8],
) -> anyhow::Result<()> {
  validate_checkpoint_body(&checkpoint.body)?;
  ensure!(
    public_key.len() == 32,
    "audit checkpoint Ed25519 public key must be 32 bytes"
  );
  let signature = decode_signature(&checkpoint.signature)?;
  let expected_digest = compute_checkpoint_digest(&checkpoint.body, &checkpoint.signature)?;
  ensure!(
    checkpoint.checkpoint_digest == expected_digest,
    "audit checkpoint digest does not match its signed representation"
  );
  let transcript = checkpoint_signing_transcript(&checkpoint.body)?;
  UnparsedPublicKey::new(&ED25519, public_key)
    .verify(&transcript, &signature)
    .map_err(|_| anyhow::anyhow!("audit checkpoint Ed25519 signature is invalid"))
}

pub fn validate_checkpoint_body(body: &AuditCheckpointBodyV1) -> anyhow::Result<()> {
  ensure!(
    body.format_version == AUDIT_CHECKPOINT_FORMAT_VERSION,
    "unsupported Admin audit checkpoint format version"
  );
  for (label, value) in [
    ("namespace", body.namespace.as_str()),
    ("stream ID", body.stream_id.as_str()),
    ("instance ID", body.instance_id.as_str()),
    ("membership epoch", body.membership_epoch.as_str()),
    ("deployment epoch", body.deployment_epoch.as_str()),
    ("chain ID", body.chain_id.as_str()),
    ("wall timestamp", body.wall_timestamp.as_str()),
    (
      "source database timestamp",
      body.source_database_timestamp.as_str(),
    ),
    ("signing key ID", body.signing_key_id.as_str()),
  ] {
    ensure!(
      !value.is_empty(),
      "audit checkpoint {label} must not be empty"
    );
    ensure!(value.len() <= 253, "audit checkpoint {label} is too long");
    ensure!(
      !value.chars().any(char::is_control),
      "audit checkpoint {label} contains control characters"
    );
  }
  if let Some(cluster_id) = &body.cluster_id {
    ensure!(
      !cluster_id.is_empty(),
      "audit checkpoint cluster ID must not be empty"
    );
    ensure!(
      cluster_id.len() <= 253,
      "audit checkpoint cluster ID is too long"
    );
    ensure!(
      !cluster_id.chars().any(char::is_control),
      "audit checkpoint cluster ID contains control characters"
    );
  }
  ensure!(
    body.checkpoint_ordinal > 0,
    "audit checkpoint ordinal must be positive"
  );
  ensure!(
    body.first_sequence <= body.last_sequence,
    "audit checkpoint sequence range is reversed"
  );
  ensure!(
    body.chain_id.len() == 32
      && body
        .chain_id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
    "audit checkpoint chain ID must contain 32 lowercase hexadecimal characters"
  );
  validate_sha256_digest(&body.stream_id, "stream ID")?;
  validate_sha256_digest(&body.chain_head, "chain head")?;
  validate_sha256_digest(
    &body.previous_checkpoint_digest,
    "previous checkpoint digest",
  )?;
  ensure!(
    body.signing_algorithm == AUDIT_CHECKPOINT_SIGNING_ALGORITHM,
    "unsupported Admin audit checkpoint signing algorithm"
  );
  Ok(())
}

pub fn validate_checkpoint_continuity(
  previous: Option<&SignedAuditCheckpointV1>,
  current: &SignedAuditCheckpointV1,
) -> anyhow::Result<()> {
  validate_checkpoint_body(&current.body)?;
  match previous {
    None => {
      ensure!(
        current.body.checkpoint_ordinal == 1,
        "first audit checkpoint ordinal must be 1"
      );
      ensure!(
        current.body.previous_checkpoint_digest == AUDIT_CHECKPOINT_GENESIS_DIGEST,
        "first audit checkpoint must link to the genesis digest"
      );
    }
    Some(previous) => {
      ensure!(
        current.body.namespace == previous.body.namespace
          && current.body.stream_id == previous.body.stream_id
          && current.body.instance_id == previous.body.instance_id,
        "audit checkpoint stream identity changed"
      );
      ensure!(
        current.body.checkpoint_ordinal == previous.body.checkpoint_ordinal.saturating_add(1),
        "audit checkpoint ordinal is not contiguous"
      );
      ensure!(
        current.body.previous_checkpoint_digest == previous.checkpoint_digest,
        "audit checkpoint predecessor digest does not match"
      );
      if current.body.chain_id == previous.body.chain_id {
        ensure!(
          current.body.first_sequence == previous.body.last_sequence.saturating_add(1),
          "audit checkpoint event sequence is not contiguous"
        );
      }
    }
  }
  Ok(())
}

fn validate_signature_encoding(signature: &str) -> anyhow::Result<()> {
  let _ = decode_signature(signature)?;
  Ok(())
}

fn decode_signature(signature: &str) -> anyhow::Result<[u8; 64]> {
  let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(signature)
    .context("audit checkpoint signature must be unpadded base64url")?;
  bytes
    .try_into()
    .map_err(|_| anyhow::anyhow!("audit checkpoint Ed25519 signature must be 64 bytes"))
}

fn validate_sha256_digest(value: &str, label: &str) -> anyhow::Result<()> {
  let Some(encoded) = value.strip_prefix("sha256:") else {
    anyhow::bail!("audit checkpoint {label} must use sha256:<lowercase-hex>");
  };
  ensure!(
    encoded.len() == 64
      && encoded
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
    "audit checkpoint {label} must contain 64 lowercase hexadecimal characters"
  );
  Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
  }
  output
}

#[cfg(test)]
mod tests {
  use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

  use super::*;

  fn body() -> AuditCheckpointBodyV1 {
    AuditCheckpointBodyV1 {
      format_version: AUDIT_CHECKPOINT_FORMAT_VERSION.to_string(),
      namespace: "oxibelt".to_string(),
      stream_id: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        .to_string(),
      instance_id: "edge-0".to_string(),
      cluster_id: Some("edge".to_string()),
      membership_epoch: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        .to_string(),
      deployment_epoch: "deploy-7".to_string(),
      checkpoint_ordinal: 1,
      chain_id: "00112233445566778899aabbccddeeff".to_string(),
      first_sequence: 0,
      last_sequence: 3,
      chain_head: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        .to_string(),
      previous_checkpoint_digest: AUDIT_CHECKPOINT_GENESIS_DIGEST.to_string(),
      wall_timestamp: "2026-07-19T00:00:00.000Z".to_string(),
      source_database_timestamp: "2026-07-19 00:00:00+00".to_string(),
      signing_key_id: "audit-2026-07".to_string(),
      signing_algorithm: AUDIT_CHECKPOINT_SIGNING_ALGORITHM.to_string(),
    }
  }

  #[test]
  fn checkpoint_signature_and_digest_round_trip() {
    let key_pair = Ed25519KeyPair::generate().expect("generate Ed25519 key");
    let transcript = checkpoint_signing_transcript(&body()).expect("checkpoint transcript");
    let checkpoint = assemble_signed_checkpoint(body(), key_pair.sign(&transcript).as_ref())
      .expect("signed checkpoint");
    verify_checkpoint_signature(&checkpoint, key_pair.public_key().as_ref())
      .expect("checkpoint signature should verify");
  }

  #[test]
  fn checkpoint_has_no_event_or_request_material() {
    let body = serde_json::to_value(body()).expect("serialize checkpoint body");
    let object = body.as_object().expect("checkpoint body object");
    for forbidden in [
      "event",
      "actor",
      "credential",
      "request_id",
      "content",
      "secret",
      "token",
    ] {
      assert!(
        object.keys().all(|key| !key.contains(forbidden)),
        "checkpoint field must not contain {forbidden}"
      );
    }
  }

  #[test]
  fn genesis_digest_stays_stable_for_authority_fixtures() {
    assert_eq!(
      AUDIT_CHECKPOINT_GENESIS_DIGEST,
      format!("sha256:{}", "0".repeat(64))
    );
  }
}
