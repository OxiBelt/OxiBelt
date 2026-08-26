//! Downstream embedded-SCT verification and policy enforcement.

mod der;
mod log_list;
mod policy;
mod runtime;

use std::collections::HashSet;

use anyhow::{Context, anyhow, bail};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};

use crate::ct::rfc6962::{
  SignedCertificateTimestampV1, SignedEntryV1, TimestampedEntryV1, encode_sct_signed_input,
};

pub(crate) use runtime::DownstreamCtRuntime;
pub use runtime::{CertificateCtStatus, DownstreamCtRuntimeStatus};

const MAX_EMBEDDED_SCTS: usize = 256;
const MAX_FUTURE_SKEW_MILLIS: u64 = 300_000;

#[derive(Debug)]
struct CertificateEvaluation {
  identity: String,
  present_count: usize,
  verified: Vec<policy::VerifiedEmbeddedSct>,
  invalid_count: usize,
  not_before: u64,
  not_after: u64,
}

fn evaluate_certificate_chain(
  chain: &[rustls::pki_types::CertificateDer<'static>],
  list: &log_list::CtLogListSnapshot,
  now: u64,
) -> anyhow::Result<CertificateEvaluation> {
  let leaf_der = chain
    .first()
    .ok_or_else(|| anyhow!("ct_missing_leaf_certificate"))?
    .as_ref();
  let issuer_der = chain
    .get(1)
    .ok_or_else(|| anyhow!("ct_missing_issuer_certificate"))?
    .as_ref();
  let leaf = Certificate::from_der(leaf_der).context("ct_leaf_parse")?;
  let issuer = Certificate::from_der(issuer_der).context("ct_issuer_parse")?;
  if leaf.tbs_certificate().issuer() != issuer.tbs_certificate().subject() {
    bail!("ct_issuer_mismatch");
  }
  let certificate_signature_algorithm = leaf
    .signature_algorithm()
    .to_der()
    .context("ct_leaf_signature_algorithm")?;
  let certificate_tbs = leaf
    .tbs_certificate()
    .to_der()
    .context("ct_leaf_tbs_encode")?;
  let certificate_signature = leaf
    .signature()
    .as_bytes()
    .ok_or_else(|| anyhow!("ct_leaf_signature_bits"))?;
  super::verify_certificate_signature(
    issuer_der,
    &certificate_signature_algorithm,
    &certificate_tbs,
    certificate_signature,
  )
  .context("ct_issuer_signature")?;

  let issuer_spki = issuer
    .tbs_certificate()
    .subject_public_key_info()
    .to_der()
    .context("ct_issuer_spki_encode")?;
  let issuer_key_hash: [u8; 32] = crate::crypto::sha256(&issuer_spki);
  let validity = leaf.tbs_certificate().validity();
  let not_before = validity.not_before.to_unix_duration().as_secs();
  let not_after = validity.not_after.to_unix_duration().as_secs();
  if not_after <= not_before {
    bail!("ct_certificate_lifetime");
  }
  let identity = hex_sha256(leaf_der);
  let Some(material) = der::extract_embedded_sct_material(leaf_der)? else {
    return Ok(CertificateEvaluation {
      identity,
      present_count: 0,
      verified: Vec::new(),
      invalid_count: 0,
      not_before,
      not_after,
    });
  };
  let encoded_scts = split_sct_list(&material.sct_list)?;
  let present_count = encoded_scts.len();
  let mut verified = Vec::new();
  let mut invalid_count = 0;
  let mut seen_logs = HashSet::new();
  for encoded in encoded_scts {
    let result = verify_one_sct(
      encoded,
      &material.tbs_certificate,
      issuer_key_hash,
      list,
      now,
      not_after,
    );
    match result {
      Ok(sct) if seen_logs.insert(sct.log_id) => verified.push(sct),
      Ok(_) | Err(_) => invalid_count += 1,
    }
  }
  Ok(CertificateEvaluation {
    identity,
    present_count,
    verified,
    invalid_count,
    not_before,
    not_after,
  })
}

fn verify_one_sct(
  encoded: &[u8],
  tbs_certificate: &[u8],
  issuer_key_hash: [u8; 32],
  list: &log_list::CtLogListSnapshot,
  now: u64,
  not_after: u64,
) -> anyhow::Result<policy::VerifiedEmbeddedSct> {
  let sct = SignedCertificateTimestampV1::decode(encoded).map_err(|_| anyhow!("ct_sct_parse"))?;
  if sct.timestamp
    > now
      .saturating_mul(1_000)
      .saturating_add(MAX_FUTURE_SKEW_MILLIS)
  {
    bail!("ct_sct_timestamp_invalid");
  }
  if sct.timestamp > not_after.saturating_mul(1_000) {
    bail!("ct_sct_timestamp_invalid");
  }
  let log = list
    .logs
    .get(&sct.log_id)
    .ok_or_else(|| anyhow!("ct_sct_unknown_log"))?;
  let transcript = encode_sct_signed_input(&TimestampedEntryV1 {
    timestamp: sct.timestamp,
    signed_entry: SignedEntryV1::Precertificate {
      issuer_key_hash,
      tbs_certificate: tbs_certificate.to_vec(),
    },
    extensions: sct.extensions.clone(),
  })
  .map_err(|_| anyhow!("ct_sct_transcript"))?;
  log_list::verify_sct_signature(
    log,
    sct.signature.signature_algorithm,
    &transcript,
    &sct.signature.signature,
  )?;
  Ok(policy::VerifiedEmbeddedSct {
    log_id: sct.log_id,
    timestamp_ms: sct.timestamp,
    extensions: sct.extensions,
  })
}

fn split_sct_list(mut input: &[u8]) -> anyhow::Result<Vec<&[u8]>> {
  let declared = read_u16(&mut input)?;
  if input.len() != usize::from(declared) {
    bail!("ct_sct_list_length");
  }
  let mut output = Vec::new();
  while !input.is_empty() {
    if output.len() == MAX_EMBEDDED_SCTS {
      bail!("ct_sct_count");
    }
    let length = usize::from(read_u16(&mut input)?);
    if length == 0 || length > input.len() {
      bail!("ct_sct_length");
    }
    let (sct, rest) = input.split_at(length);
    output.push(sct);
    input = rest;
  }
  Ok(output)
}

#[cfg(feature = "fuzzing")]
pub(super) fn exercise_fuzzing(data: &[u8]) {
  use std::collections::HashMap;

  use log_list::{CtLog, CtLogListSnapshot, CtLogState, TemporalInterval};

  let _ = split_sct_list(data);
  let _ = der::extract_embedded_sct_material(data);
  log_list::exercise_parser_fuzzing(data);

  let mut logs = HashMap::new();
  let mut scts = Vec::new();
  for index in 0..3 {
    let selector = data.get(index).copied().unwrap_or_default();
    let mut log_id = [0_u8; 32];
    log_id[0] = index as u8;
    let since = u64::from(selector).saturating_add(1);
    let state = match selector % 6 {
      0 => CtLogState::Pending { since },
      1 => CtLogState::Qualified { since },
      2 => CtLogState::Usable { since },
      3 => CtLogState::Readonly { since },
      4 => CtLogState::Retired { since },
      _ => CtLogState::Rejected { since },
    };
    logs.insert(
      log_id,
      CtLog {
        key_spki: Vec::new(),
        operator: format!("operator-{}", selector % 3),
        previous_operators: Vec::new(),
        state,
        temporal_interval: Some(TemporalInterval {
          start_inclusive: 0,
          end_exclusive: u64::MAX,
        }),
        tiled: false,
      },
    );
    scts.push(policy::VerifiedEmbeddedSct {
      log_id,
      timestamp_ms: u64::from(selector).saturating_mul(1_000),
      extensions: data.get(3..8).unwrap_or_default().to_vec(),
    });
  }
  let list = CtLogListSnapshot {
    version: "fuzz".to_string(),
    timestamp: 1,
    logs,
  };
  let not_before = u64::from(data.get(8).copied().unwrap_or_default());
  let lifetime = if data.get(9).copied().unwrap_or_default() & 1 == 0 {
    180 * 24 * 60 * 60
  } else {
    181 * 24 * 60 * 60
  };
  for selected_policy in [
    crate::config::DownstreamCtPolicy::Chrome,
    crate::config::DownstreamCtPolicy::Firefox,
  ] {
    let _ = policy::evaluate(
      selected_policy,
      &list,
      &scts,
      not_before,
      not_before.saturating_add(lifetime),
    );
  }
}

fn read_u16(input: &mut &[u8]) -> anyhow::Result<u16> {
  let bytes = input
    .get(..2)
    .ok_or_else(|| anyhow!("ct_tls_vector_short"))?;
  *input = &input[2..];
  Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn hex_sha256(input: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let digest = crate::crypto::sha256(input);
  let mut output = String::with_capacity(64);
  for byte in digest {
    output.push(HEX[usize::from(byte >> 4)] as char);
    output.push(HEX[usize::from(byte & 0x0f)] as char);
  }
  output
}

fn classify_error(error: &anyhow::Error) -> &'static str {
  let message = format!("{error:#}");
  for code in [
    "ct_sct_extension_duplicate",
    "ct_sct_extension_critical",
    "ct_sct_extension_parse",
    "ct_sct_list_length",
    "ct_sct_length",
    "ct_sct_count",
    "ct_sct_parse",
    "ct_sct_unknown_log",
    "ct_sct_signature_invalid",
    "ct_sct_signature_algorithm_mismatch",
    "ct_sct_timestamp_invalid",
    "ct_log_list_missing",
    "ct_log_list_stale",
    "ct_log_list_parse",
    "ct_log_list_signature_invalid",
    "ct_log_list_semantic_error",
    "ct_policy_insufficient_logs",
    "ct_policy_insufficient_operators",
    "ct_policy_log_state",
    "ct_issuer_mismatch",
    "ct_issuer_signature",
    "ct_missing_issuer_certificate",
    "ct_missing_leaf_certificate",
  ] {
    if message.contains(code) {
      return code;
    }
  }
  "ct_error"
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sct_list_requires_exact_nested_lengths() {
    assert_eq!(split_sct_list(&[0, 3, 0, 1, 9]).unwrap(), vec![&[9][..]]);
    assert!(split_sct_list(&[0, 2, 0, 1, 9]).is_err());
    assert!(split_sct_list(&[0, 1, 0]).is_err());
    assert!(split_sct_list(&[0, 2, 0, 0]).is_err());
  }
}
