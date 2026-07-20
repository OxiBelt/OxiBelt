use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, ensure};
use oxibelt::admin_audit::anchor::{
  SignedAuditCheckpointV1, validate_checkpoint_continuity, verify_checkpoint_signature,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::audit_verify::{
  AuditWitness, ExpectedStream, ExpectedStreamsManifest, TrustedHmacKey, TrustedKey,
  VerificationReport, VerificationStatus, WitnessHead, new_witness,
};

const INTEGRITY_DOMAIN: &[u8] = b"oxibelt.admin.audit.integrity/v1\0";
const GENESIS_EVENT_HASH: [u8; 32] = [0_u8; 32];

pub(crate) struct VerificationEvidence {
  pub(crate) streams: Vec<StreamEvidence>,
}

pub(crate) struct StreamEvidence {
  pub(crate) expected: ExpectedStream,
  pub(crate) local_rows: Vec<LocalAuditRow>,
  pub(crate) checkpoints: Vec<Value>,
  pub(crate) authority_head: Option<AuthorityHead>,
}

pub(crate) struct LocalAuditRow {
  pub(crate) id: i64,
  pub(crate) payload: Option<Value>,
}

pub(crate) struct AuthorityHead {
  pub(crate) checkpoint_ordinal: u64,
  pub(crate) checkpoint_digest: String,
}

#[derive(Default)]
struct LocalChains {
  chains: BTreeMap<String, BTreeMap<u64, String>>,
  event_count: usize,
  valid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckpointLocalMatch {
  Match,
  MissingLocalTail,
  Mismatch,
}

pub(crate) fn verify_evidence(
  manifest: &ExpectedStreamsManifest,
  trusted_keys: &BTreeMap<String, TrustedKey>,
  trusted_hmac_keys: &BTreeMap<String, TrustedHmacKey>,
  prior_witness: Option<&AuditWitness>,
  evidence: VerificationEvidence,
) -> anyhow::Result<(VerificationReport, AuditWitness)> {
  ensure!(
    evidence.streams.len() == manifest.streams.len(),
    "verification backend returned an unexpected stream count"
  );
  let mut report = VerificationReport::new(manifest.namespace.clone(), manifest.streams.len());
  let expected_ids = manifest
    .streams
    .iter()
    .map(|stream| stream.stream_id.as_str())
    .collect::<BTreeSet<_>>();
  if let Some(witness) = prior_witness
    && witness
      .streams
      .keys()
      .any(|stream_id| !expected_ids.contains(stream_id.as_str()))
  {
    report.finding(
      "witness_contains_unexpected_stream",
      VerificationStatus::Invalid,
      None,
    );
  }

  let mut next_heads = BTreeMap::new();
  for stream in evidence.streams {
    let findings_before = report.findings.len();
    let stream_id = stream.expected.stream_id.as_str();
    let local = verify_local_events(&stream, trusted_hmac_keys, &mut report)?;
    report.events_verified = report.events_verified.saturating_add(local.event_count);
    let checkpoints = parse_and_verify_checkpoints(&stream, trusted_keys, &local, &mut report);
    report.checkpoints_verified = report
      .checkpoints_verified
      .saturating_add(checkpoints.len());
    verify_authority_head(&stream, &checkpoints, &mut report);
    verify_local_coverage(&local, &checkpoints, stream_id, &mut report);
    verify_prior_witness(
      prior_witness.and_then(|witness| witness.streams.get(stream_id)),
      &checkpoints,
      stream_id,
      &mut report,
    );

    if let Some(last) = checkpoints.last() {
      next_heads.insert(
        stream_id.to_string(),
        WitnessHead {
          checkpoint_ordinal: last.body.checkpoint_ordinal,
          checkpoint_digest: last.checkpoint_digest.clone(),
        },
      );
    }
    if report.findings.len() == findings_before {
      report.streams_verified = report.streams_verified.saturating_add(1);
    }
  }
  Ok((report, new_witness(manifest.namespace.clone(), next_heads)))
}

fn verify_local_events(
  stream: &StreamEvidence,
  trusted_hmac_keys: &BTreeMap<String, TrustedHmacKey>,
  report: &mut VerificationReport,
) -> anyhow::Result<LocalChains> {
  let stream_id = stream.expected.stream_id.as_str();
  if stream.local_rows.is_empty() {
    report.finding(
      "local_stream_has_no_events",
      VerificationStatus::Incomplete,
      Some(stream_id),
    );
    return Ok(LocalChains::default());
  }
  let mut chains: BTreeMap<String, BTreeMap<u64, String>> = BTreeMap::new();
  let mut valid = true;
  let mut previous_row_id = 0_i64;
  let mut unavailable_hmac_keys = BTreeSet::new();
  for row in &stream.local_rows {
    if row.id <= previous_row_id {
      report.finding(
        "local_event_row_order_invalid",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    }
    previous_row_id = row.id;
    let Some(payload) = row.payload.as_ref() else {
      report.finding(
        "local_event_payload_missing",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    };
    let event_instance = value_string(payload, "instance_id");
    if event_instance != Some(stream.expected.instance_id.as_str()) {
      report.finding(
        "local_event_instance_mismatch",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    }
    let integrity = payload.get("integrity").and_then(Value::as_object);
    let Some(integrity) = integrity else {
      report.finding(
        "local_event_integrity_missing",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    };
    let Some(chain_id) = integrity.get("chain_id").and_then(Value::as_str) else {
      report.finding(
        "local_event_integrity_malformed",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    };
    let Some(sequence) = integrity.get("sequence").and_then(Value::as_u64) else {
      report.finding(
        "local_event_integrity_malformed",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    };
    let Some(previous_hash) = integrity.get("previous_hash").and_then(Value::as_str) else {
      report.finding(
        "local_event_integrity_malformed",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    };
    let Some(event_hash) = integrity.get("event_hash").and_then(Value::as_str) else {
      report.finding(
        "local_event_integrity_malformed",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    };
    let chain = chains.entry(chain_id.to_string()).or_default();
    let expected_previous = if sequence == 0 {
      encode_hex(&GENESIS_EVENT_HASH)
    } else {
      chain.get(&(sequence - 1)).cloned().unwrap_or_default()
    };
    if expected_previous != previous_hash || chain.contains_key(&sequence) {
      report.finding(
        "local_event_chain_discontinuity",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      valid = false;
      continue;
    }
    match calculate_event_hash(payload, integrity) {
      Ok(expected) if expected == event_hash => {
        chain.insert(sequence, event_hash.to_string());
        if integrity.get("algorithm").and_then(Value::as_str) == Some("hmac_sha256")
          && let Some(key_id) = integrity.get("key_id").and_then(Value::as_str)
        {
          let tag = integrity
            .get("tag")
            .and_then(Value::as_str)
            .and_then(|tag| decode_hex::<32>(tag).ok());
          match (trusted_hmac_keys.get(key_id), tag) {
            (Some(key), Some(tag))
              if key.key_id == key_id
                && aws_lc_rs::hmac::verify(
                  &aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key.key),
                  &decode_hex::<32>(event_hash)?,
                  &tag,
                )
                .is_ok() => {}
            (None, Some(_)) if unavailable_hmac_keys.insert(key_id.to_string()) => {
              report.finding(
                "local_hmac_integrity_key_unavailable",
                VerificationStatus::Incomplete,
                Some(stream_id),
              );
            }
            _ => {
              report.finding(
                "local_event_hmac_invalid",
                VerificationStatus::Invalid,
                Some(stream_id),
              );
              valid = false;
            }
          }
        }
      }
      _ => {
        report.finding(
          "local_event_hash_mismatch",
          VerificationStatus::Invalid,
          Some(stream_id),
        );
        valid = false;
      }
    }
  }
  Ok(LocalChains {
    event_count: chains.values().map(BTreeMap::len).sum(),
    chains,
    valid,
  })
}

fn parse_and_verify_checkpoints(
  stream: &StreamEvidence,
  trusted_keys: &BTreeMap<String, TrustedKey>,
  local: &LocalChains,
  report: &mut VerificationReport,
) -> Vec<SignedAuditCheckpointV1> {
  let stream_id = stream.expected.stream_id.as_str();
  if stream.checkpoints.is_empty() {
    report.finding(
      "external_checkpoint_missing",
      VerificationStatus::Incomplete,
      Some(stream_id),
    );
    return Vec::new();
  }
  let mut verified: Vec<SignedAuditCheckpointV1> = Vec::new();
  let mut last_epoch_position = None;
  let mut active_signing_key: Option<String> = None;
  let mut retired_signing_keys = BTreeSet::new();
  for value in &stream.checkpoints {
    let checkpoint: SignedAuditCheckpointV1 = match serde_json::from_value(value.clone()) {
      Ok(checkpoint) => checkpoint,
      Err(_) => {
        report.finding(
          "external_checkpoint_malformed",
          VerificationStatus::Invalid,
          Some(stream_id),
        );
        continue;
      }
    };
    let body = &checkpoint.body;
    if body.namespace != report.namespace
      || body.stream_id != stream.expected.stream_id
      || body.instance_id != stream.expected.instance_id
      || body.cluster_id != stream.expected.cluster_id
    {
      report.finding(
        "checkpoint_identity_mismatch",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      continue;
    }
    let Some(epoch_position) = stream
      .expected
      .epoch_position(&body.membership_epoch, &body.deployment_epoch)
    else {
      report.finding(
        "checkpoint_epoch_unexpected",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      continue;
    };
    if last_epoch_position.is_some_and(|previous| epoch_position < previous) {
      report.finding(
        "checkpoint_epoch_order_invalid",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      continue;
    }
    if !stream
      .expected
      .signing_key_allowed(&body.signing_key_id, body.checkpoint_ordinal)
    {
      report.finding(
        "checkpoint_signing_key_out_of_policy",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      continue;
    }
    let Some(key) = trusted_keys.get(&body.signing_key_id) else {
      report.finding(
        "checkpoint_signing_key_untrusted",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      continue;
    };
    if key.key_id != body.signing_key_id
      || verify_checkpoint_signature(&checkpoint, &key.public_key).is_err()
    {
      report.finding(
        "checkpoint_signature_invalid",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      continue;
    }
    if validate_checkpoint_continuity(verified.last(), &checkpoint).is_err() {
      report.finding(
        "checkpoint_continuity_invalid",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      continue;
    }
    if verified
      .last()
      .is_some_and(|previous| previous.body.chain_id != body.chain_id && body.first_sequence != 0)
    {
      report.finding(
        "checkpoint_chain_restart_invalid",
        VerificationStatus::Invalid,
        Some(stream_id),
      );
      continue;
    }
    match checkpoint_matches_local(local, &checkpoint) {
      CheckpointLocalMatch::Match => {}
      CheckpointLocalMatch::MissingLocalTail => {
        report.finding(
          "local_tail_truncation_detected",
          VerificationStatus::Invalid,
          Some(stream_id),
        );
        continue;
      }
      CheckpointLocalMatch::Mismatch => {
        report.finding(
          "checkpoint_local_evidence_mismatch",
          VerificationStatus::Invalid,
          Some(stream_id),
        );
        continue;
      }
    }
    if active_signing_key
      .as_deref()
      .is_some_and(|active| active != body.signing_key_id)
    {
      if retired_signing_keys.contains(&body.signing_key_id) {
        report.finding(
          "checkpoint_signing_key_rollback",
          VerificationStatus::Invalid,
          Some(stream_id),
        );
        continue;
      }
      if let Some(active) = active_signing_key.replace(body.signing_key_id.clone()) {
        retired_signing_keys.insert(active);
      }
    } else if active_signing_key.is_none() {
      active_signing_key = Some(body.signing_key_id.clone());
    }
    last_epoch_position = Some(epoch_position);
    verified.push(checkpoint);
  }
  if verified.last().is_none_or(|checkpoint| {
    !stream.expected.is_current_epoch(
      &checkpoint.body.membership_epoch,
      &checkpoint.body.deployment_epoch,
    )
  }) {
    report.finding(
      "checkpoint_current_epoch_missing",
      VerificationStatus::Incomplete,
      Some(stream_id),
    );
  }
  verified
}

fn checkpoint_matches_local(
  local: &LocalChains,
  checkpoint: &SignedAuditCheckpointV1,
) -> CheckpointLocalMatch {
  if !local.valid {
    return CheckpointLocalMatch::Mismatch;
  }
  let Some(chain) = local.chains.get(&checkpoint.body.chain_id) else {
    return CheckpointLocalMatch::Mismatch;
  };
  if chain
    .last_key_value()
    .is_some_and(|(last_sequence, _)| *last_sequence < checkpoint.body.last_sequence)
  {
    return CheckpointLocalMatch::MissingLocalTail;
  }
  if !(checkpoint.body.first_sequence..=checkpoint.body.last_sequence)
    .all(|sequence| chain.contains_key(&sequence))
  {
    return CheckpointLocalMatch::Mismatch;
  }
  if chain
    .get(&checkpoint.body.last_sequence)
    .is_some_and(|hash| checkpoint.body.chain_head == format!("sha256:{hash}"))
  {
    CheckpointLocalMatch::Match
  } else {
    CheckpointLocalMatch::Mismatch
  }
}

fn verify_authority_head(
  stream: &StreamEvidence,
  checkpoints: &[SignedAuditCheckpointV1],
  report: &mut VerificationReport,
) {
  let stream_id = stream.expected.stream_id.as_str();
  match (stream.authority_head.as_ref(), checkpoints.last()) {
    (Some(head), Some(last))
      if head.checkpoint_ordinal == last.body.checkpoint_ordinal
        && head.checkpoint_digest == last.checkpoint_digest => {}
    (None, None) => {}
    _ => report.finding(
      "authority_head_mismatch",
      VerificationStatus::Invalid,
      Some(stream_id),
    ),
  }
}

fn verify_local_coverage(
  local: &LocalChains,
  checkpoints: &[SignedAuditCheckpointV1],
  stream_id: &str,
  report: &mut VerificationReport,
) {
  if !local.valid || local.chains.is_empty() {
    return;
  }
  let mut covered = BTreeMap::<&str, u64>::new();
  for checkpoint in checkpoints {
    covered
      .entry(&checkpoint.body.chain_id)
      .and_modify(|sequence| *sequence = (*sequence).max(checkpoint.body.last_sequence))
      .or_insert(checkpoint.body.last_sequence);
  }
  for (chain_id, events) in &local.chains {
    let last_local = events.last_key_value().map(|(sequence, _)| *sequence);
    let last_covered = covered.get(chain_id.as_str()).copied();
    if last_local != last_covered {
      report.finding(
        "local_events_not_externally_anchored",
        VerificationStatus::Incomplete,
        Some(stream_id),
      );
    }
  }
}

fn verify_prior_witness(
  prior: Option<&WitnessHead>,
  checkpoints: &[SignedAuditCheckpointV1],
  stream_id: &str,
  report: &mut VerificationReport,
) {
  let Some(prior) = prior else {
    return;
  };
  let Some(current) = checkpoints.last() else {
    report.finding(
      "authority_rollback_detected",
      VerificationStatus::Invalid,
      Some(stream_id),
    );
    return;
  };
  if current.body.checkpoint_ordinal < prior.checkpoint_ordinal {
    report.finding(
      "authority_rollback_detected",
      VerificationStatus::Invalid,
      Some(stream_id),
    );
    return;
  }
  let matches = checkpoints.iter().any(|checkpoint| {
    checkpoint.body.checkpoint_ordinal == prior.checkpoint_ordinal
      && checkpoint.checkpoint_digest == prior.checkpoint_digest
  });
  if !matches {
    report.finding(
      "authority_rollback_or_fork_detected",
      VerificationStatus::Invalid,
      Some(stream_id),
    );
  }
}

fn calculate_event_hash(
  payload: &Value,
  integrity: &serde_json::Map<String, Value>,
) -> anyhow::Result<String> {
  let chain_id = integrity
    .get("chain_id")
    .and_then(Value::as_str)
    .context("chain ID missing")?;
  let sequence = integrity
    .get("sequence")
    .and_then(Value::as_u64)
    .context("sequence missing")?;
  let previous_hash = integrity
    .get("previous_hash")
    .and_then(Value::as_str)
    .context("previous hash missing")?;
  let algorithm = integrity
    .get("algorithm")
    .and_then(Value::as_str)
    .context("algorithm missing")?;
  let algorithm_code = match algorithm {
    "sha256" => 1,
    "hmac_sha256" => 2,
    _ => anyhow::bail!("unsupported event integrity algorithm"),
  };
  let key_id = integrity
    .get("key_id")
    .and_then(Value::as_str)
    .unwrap_or_default();
  if algorithm_code == 1 {
    ensure!(key_id.is_empty(), "hash-only event contains a key ID");
  } else {
    ensure!(!key_id.is_empty(), "HMAC event is missing its key ID");
    let tag = integrity
      .get("tag")
      .and_then(Value::as_str)
      .context("HMAC event is missing its tag")?;
    let _ = decode_hex::<32>(tag).context("HMAC event tag is malformed")?;
  }
  let mut unsigned = payload.clone();
  unsigned
    .as_object_mut()
    .context("event payload must be a JSON object")?
    .insert("integrity".to_string(), Value::Null);
  let canonical = canonical_json_bytes(&unsigned)?;
  let chain_id = decode_hex::<16>(chain_id)?;
  let previous_hash = decode_hex::<32>(previous_hash)?;
  let key_id_length = u32::try_from(key_id.len())?;
  let payload_length = u64::try_from(canonical.len())?;
  let mut input = Vec::with_capacity(
    INTEGRITY_DOMAIN.len() + 16 + 8 + 32 + 1 + 4 + key_id.len() + 8 + canonical.len(),
  );
  input.extend_from_slice(INTEGRITY_DOMAIN);
  input.extend_from_slice(&chain_id);
  input.extend_from_slice(&sequence.to_be_bytes());
  input.extend_from_slice(&previous_hash);
  input.push(algorithm_code);
  input.extend_from_slice(&key_id_length.to_be_bytes());
  input.extend_from_slice(key_id.as_bytes());
  input.extend_from_slice(&payload_length.to_be_bytes());
  input.extend_from_slice(&canonical);
  Ok(encode_hex(&Sha256::digest(input)))
}

fn canonical_json_bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
  let mut output = Vec::new();
  write_canonical_json(value, &mut output)?;
  Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> anyhow::Result<()> {
  match value {
    Value::Null => output.extend_from_slice(b"null"),
    Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
    Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
    Value::String(value) => serde_json::to_writer(output, value)?,
    Value::Array(values) => {
      output.push(b'[');
      for (index, value) in values.iter().enumerate() {
        if index != 0 {
          output.push(b',');
        }
        write_canonical_json(value, output)?;
      }
      output.push(b']');
    }
    Value::Object(values) => {
      output.push(b'{');
      let mut entries = values.iter().collect::<Vec<_>>();
      entries.sort_by_key(|(key, _)| *key);
      for (index, (key, value)) in entries.into_iter().enumerate() {
        if index != 0 {
          output.push(b',');
        }
        serde_json::to_writer(&mut *output, key)?;
        output.push(b':');
        write_canonical_json(value, output)?;
      }
      output.push(b'}');
    }
  }
  Ok(())
}

fn value_string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
  value.get(field).and_then(Value::as_str)
}

fn decode_hex<const N: usize>(value: &str) -> anyhow::Result<[u8; N]> {
  ensure!(value.len() == N * 2, "hex value has unexpected length");
  let mut output = [0_u8; N];
  for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
    let high = decode_hex_digit(pair[0])?;
    let low = decode_hex_digit(pair[1])?;
    output[index] = high << 4 | low;
  }
  Ok(output)
}

fn decode_hex_digit(value: u8) -> anyhow::Result<u8> {
  match value {
    b'0'..=b'9' => Ok(value - b'0'),
    b'a'..=b'f' => Ok(value - b'a' + 10),
    _ => anyhow::bail!("hex value must use lowercase hexadecimal"),
  }
}

fn encode_hex(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
  }
  output
}

#[cfg(test)]
pub(crate) fn calculate_event_hash_for_test(payload: &Value) -> anyhow::Result<String> {
  let integrity = payload
    .get("integrity")
    .and_then(Value::as_object)
    .context("test event integrity missing")?;
  calculate_event_hash(payload, integrity)
}
