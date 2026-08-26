//! Authenticated Chromium v3 CT Log-list parsing and semantic validation.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, anyhow, bail};
use base64::Engine as _;
use serde::Deserialize;

use super::der::{PublicKeyKind, signature_public_key};

pub(super) const LOG_LIST_MAX_AGE_SECONDS: u64 = 70 * 24 * 60 * 60;
const MAX_FUTURE_SKEW_SECONDS: u64 = 300;
const MAX_LOGS: usize = 4_096;
const MAX_OPERATORS: usize = 1_024;
const MAX_PREVIOUS_OPERATORS: usize = 64;
const LOG_LIST_SIGNING_KEY_DER_BASE64: &str = concat!(
  "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsu0BHGnQ++W2CTdyZyxv",
  "HHRALOZPlnu/VMVgo2m+JZ8MNbAOH2cgXb8mvOj8flsX/qPMuKIaauO+PwROMjiq",
  "fUpcFm80Kl7i97ZQyBDYKm3MkEYYpGN+skAR2OebX9G2DfDqFY8+jUpOOWtBNr3L",
  "rmVcwx+FcFdMjGDlrZ5JRmoJ/SeGKiORkbbu9eY1Wd0uVhz/xI5bQb0OgII7hEj+",
  "i/IPbJqOHgB8xQ5zWAJJ0DmG+FM6o7gk403v6W3S8qRYiR84c50KppGwe4YqSMkF",
  "bLDleGQWLoaDSpEWtESisb4JiLaY4H+Kk0EyAhPSb+49JfUozYl+lf7iFN3qRq/S",
  "IXXTh6z0S7Qa8EYDhKGCrpI03/+qprwy+my6fpWHi6aUIk4holUCmWvFxZDfixox",
  "K0RlqbFDl2JXMBquwlQpm8u5wrsic1ksIv9z8x9zh4PJqNpCah0ciemI3YGRQqSe",
  "/mRRXBiSn9YQBUPcaeqCYan+snGADFwHuXCd9xIAdFBolw9R9HTedHGUfVXPJDiF",
  "4VusfX6BRR/qaadB+bqEArF/TzuDUr6FvOR4o8lUUxgLuZ/7HO+bHnaPFKYHHSm+",
  "+z1lVDhhYuSZ8ax3T0C3FZpb7HMjZtpEorSV5ElKJEJwrhrBCMOD8L01EoSPrGlS",
  "1w22i9uGHMn/uGQKo28u7AsCAwEAAQ=="
);

#[derive(Clone, Debug)]
pub(super) struct CtLogListSnapshot {
  pub(super) version: String,
  pub(super) timestamp: u64,
  pub(super) logs: HashMap<[u8; 32], CtLog>,
}

impl CtLogListSnapshot {
  pub(super) fn is_stale_at(&self, now: u64) -> bool {
    now.saturating_sub(self.timestamp) >= LOG_LIST_MAX_AGE_SECONDS
  }
}

#[derive(Clone, Debug)]
pub(super) struct CtLog {
  pub(super) key_spki: Vec<u8>,
  pub(super) operator: String,
  pub(super) previous_operators: Vec<PreviousOperator>,
  pub(super) state: CtLogState,
  pub(super) temporal_interval: Option<TemporalInterval>,
  pub(super) tiled: bool,
}

impl CtLog {
  pub(super) fn operator_at(&self, timestamp_ms: u64) -> &str {
    let timestamp = timestamp_ms / 1_000;
    self
      .previous_operators
      .iter()
      .find(|operator| timestamp < operator.end_time)
      .map(|operator| operator.name.as_str())
      .unwrap_or(&self.operator)
  }
}

#[derive(Clone, Debug)]
pub(super) struct PreviousOperator {
  pub(super) name: String,
  pub(super) end_time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CtLogState {
  Pending { since: u64 },
  Qualified { since: u64 },
  Usable { since: u64 },
  Readonly { since: u64 },
  Retired { since: u64 },
  Rejected { since: u64 },
}

impl CtLogState {
  pub(super) const fn is_currently_acceptable(self) -> bool {
    matches!(
      self,
      Self::Qualified { .. } | Self::Usable { .. } | Self::Readonly { .. }
    )
  }

  pub(super) const fn retired_at(self) -> Option<u64> {
    match self {
      Self::Retired { since } => Some(since),
      _ => None,
    }
  }

  fn since(self) -> u64 {
    match self {
      Self::Pending { since }
      | Self::Qualified { since }
      | Self::Usable { since }
      | Self::Readonly { since }
      | Self::Retired { since }
      | Self::Rejected { since } => since,
    }
  }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TemporalInterval {
  pub(super) start_inclusive: u64,
  pub(super) end_exclusive: u64,
}

pub(super) fn parse_and_verify_log_list(
  json: &[u8],
  signature: &[u8],
  now: u64,
) -> anyhow::Result<CtLogListSnapshot> {
  verify_log_list_signature(json, signature)?;
  parse_log_list(json, now)
}

fn verify_log_list_signature(json: &[u8], signature: &[u8]) -> anyhow::Result<()> {
  if signature.len() != 512 {
    bail!("ct_log_list_signature_length");
  }
  let spki = decode_base64(LOG_LIST_SIGNING_KEY_DER_BASE64, 4_096)
    .map_err(|_| anyhow!("ct_log_list_signing_key"))?;
  let (kind, key) = signature_public_key(&spki)?;
  if kind != PublicKeyKind::Rsa {
    bail!("ct_log_list_signing_key");
  }
  aws_lc_rs::signature::UnparsedPublicKey::new(
    &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
    key,
  )
  .verify(json, signature)
  .map_err(|_| anyhow!("ct_log_list_signature_invalid"))
}

fn parse_log_list(json: &[u8], now: u64) -> anyhow::Result<CtLogListSnapshot> {
  let raw: RawLogList = serde_json::from_slice(json).context("ct_log_list_parse")?;
  if raw.is_all_logs.unwrap_or(false) {
    bail!("ct_log_list_wrong_list");
  }
  validate_string(&raw.version, 1, 64, "ct_log_list_version")?;
  parse_version(&raw.version)?;
  let timestamp = parse_rfc3339(&raw.log_list_timestamp)?;
  if timestamp > now.saturating_add(MAX_FUTURE_SKEW_SECONDS) {
    bail!("ct_log_list_future");
  }
  if raw.operators.is_empty() || raw.operators.len() > MAX_OPERATORS {
    bail!("ct_log_list_operator_count");
  }
  let mut operator_names = HashSet::new();
  let mut logs = HashMap::new();
  for operator in raw.operators {
    validate_string(&operator.name, 1, 256, "ct_log_list_operator_name")?;
    if !operator_names.insert(operator.name.clone()) {
      bail!("ct_log_list_duplicate_operator");
    }
    if operator.email.is_empty() || operator.email.len() > 64 {
      bail!("ct_log_list_operator_email_count");
    }
    for email in &operator.email {
      validate_string(email, 3, 320, "ct_log_list_operator_email")?;
    }
    for raw_log in operator.logs {
      insert_log(&mut logs, &operator.name, raw_log, false)?;
    }
    for raw_log in operator.tiled_logs {
      insert_log(&mut logs, &operator.name, raw_log, true)?;
    }
    if logs.len() > MAX_LOGS {
      bail!("ct_log_list_log_count");
    }
  }
  if logs.is_empty() {
    bail!("ct_log_list_log_count");
  }
  Ok(CtLogListSnapshot {
    version: raw.version,
    timestamp,
    logs,
  })
}

#[cfg(feature = "fuzzing")]
pub(super) fn exercise_parser_fuzzing(json: &[u8]) {
  let _ = parse_log_list(json, 1_788_000_000);
}

pub(super) fn parse_version(value: &str) -> anyhow::Result<(u64, u64)> {
  let (major, minor) = value
    .split_once('.')
    .ok_or_else(|| anyhow!("ct_log_list_version"))?;
  if major.is_empty()
    || minor.is_empty()
    || !major.bytes().all(|byte| byte.is_ascii_digit())
    || !minor.bytes().all(|byte| byte.is_ascii_digit())
  {
    bail!("ct_log_list_version");
  }
  Ok((major.parse()?, minor.parse()?))
}

fn insert_log(
  logs: &mut HashMap<[u8; 32], CtLog>,
  operator: &str,
  raw: RawLog,
  tiled: bool,
) -> anyhow::Result<()> {
  let key_spki = decode_base64(&raw.key, 8_192)?;
  signature_public_key(&key_spki)?;
  let log_id_bytes = decode_base64(&raw.log_id, 32)?;
  let log_id: [u8; 32] = log_id_bytes
    .try_into()
    .map_err(|_| anyhow!("ct_log_list_log_id"))?;
  if crate::crypto::sha256(&key_spki) != log_id {
    bail!("ct_log_list_log_id_mismatch");
  }
  if raw.mmd == 0 || raw.mmd > 86_400 {
    bail!("ct_log_list_mmd");
  }
  let state = parse_state(raw.state)?;
  if state.since() == 0 {
    bail!("ct_log_list_state_timestamp");
  }
  let temporal_interval = raw
    .temporal_interval
    .map(|interval| {
      let start_inclusive = parse_rfc3339(&interval.start_inclusive)?;
      let end_exclusive = parse_rfc3339(&interval.end_exclusive)?;
      if start_inclusive >= end_exclusive {
        bail!("ct_log_list_temporal_interval");
      }
      Ok(TemporalInterval {
        start_inclusive,
        end_exclusive,
      })
    })
    .transpose()?;
  if raw.previous_operators.len() > MAX_PREVIOUS_OPERATORS {
    bail!("ct_log_list_previous_operator_count");
  }
  let mut previous_names = HashSet::new();
  let mut last_end = 0;
  let mut previous_operators = Vec::new();
  for previous in raw.previous_operators {
    validate_string(&previous.name, 1, 256, "ct_log_list_previous_operator_name")?;
    let end_time = parse_rfc3339(&previous.end_time)?;
    if end_time <= last_end || !previous_names.insert(previous.name.clone()) {
      bail!("ct_log_list_previous_operator_order");
    }
    last_end = end_time;
    previous_operators.push(PreviousOperator {
      name: previous.name,
      end_time,
    });
  }
  let log = CtLog {
    key_spki,
    operator: operator.to_string(),
    previous_operators,
    state,
    temporal_interval,
    tiled,
  };
  if logs.insert(log_id, log).is_some() {
    bail!("ct_log_list_duplicate_log_id");
  }
  Ok(())
}

fn parse_state(state: RawState) -> anyhow::Result<CtLogState> {
  let entries = [
    state.pending.as_ref().map(|value| (0, value)),
    state.qualified.as_ref().map(|value| (1, value)),
    state.usable.as_ref().map(|value| (2, value)),
    state.readonly.as_ref().map(|value| (3, value)),
    state.retired.as_ref().map(|value| (4, value)),
    state.rejected.as_ref().map(|value| (5, value)),
  ]
  .into_iter()
  .flatten()
  .collect::<Vec<_>>();
  if entries.len() != 1 {
    bail!("ct_log_list_state");
  }
  let (kind, details) = entries[0];
  let since = parse_rfc3339(&details.timestamp)?;
  Ok(match kind {
    0 => CtLogState::Pending { since },
    1 => CtLogState::Qualified { since },
    2 => CtLogState::Usable { since },
    3 => CtLogState::Readonly { since },
    4 => CtLogState::Retired { since },
    5 => CtLogState::Rejected { since },
    _ => return Err(anyhow!("ct_log_list_state")),
  })
}

pub(super) fn verify_sct_signature(
  log: &CtLog,
  signature_algorithm: u8,
  transcript: &[u8],
  signature: &[u8],
) -> anyhow::Result<()> {
  let (kind, key) = signature_public_key(&log.key_spki)?;
  match (kind, signature_algorithm) {
    (PublicKeyKind::P256, crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA) => {
      aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        key,
      )
      .verify(transcript, signature)
      .map_err(|_| anyhow!("ct_sct_signature_invalid"))
    }
    (PublicKeyKind::Rsa, crate::ct::rfc6962::SIGNATURE_ALGORITHM_RSA) => {
      aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
        key,
      )
      .verify(transcript, signature)
      .map_err(|_| anyhow!("ct_sct_signature_invalid"))
    }
    _ => bail!("ct_sct_signature_algorithm_mismatch"),
  }
}

fn decode_base64(value: &str, max_decoded: usize) -> anyhow::Result<Vec<u8>> {
  if value.len() > max_decoded.saturating_mul(2).saturating_add(8) {
    bail!("ct_log_list_base64_too_large");
  }
  let decoded = base64::engine::general_purpose::STANDARD
    .decode(value)
    .map_err(|_| anyhow!("ct_log_list_base64"))?;
  if decoded.len() > max_decoded
    || base64::engine::general_purpose::STANDARD.encode(&decoded) != value
  {
    bail!("ct_log_list_base64");
  }
  Ok(decoded)
}

fn validate_string(value: &str, min: usize, max: usize, code: &'static str) -> anyhow::Result<()> {
  if !(min..=max).contains(&value.len()) || value.chars().any(char::is_control) {
    bail!(code);
  }
  Ok(())
}

pub(super) fn parse_rfc3339(value: &str) -> anyhow::Result<u64> {
  let bytes = value.as_bytes();
  if bytes.len() != 20
    || bytes.get(4) != Some(&b'-')
    || bytes.get(7) != Some(&b'-')
    || bytes.get(10) != Some(&b'T')
    || bytes.get(13) != Some(&b':')
    || bytes.get(16) != Some(&b':')
    || bytes.get(19) != Some(&b'Z')
  {
    bail!("ct_log_list_timestamp");
  }
  let year = decimal(bytes, 0, 4)?;
  let month = decimal(bytes, 5, 2)?;
  let day = decimal(bytes, 8, 2)?;
  let hour = decimal(bytes, 11, 2)?;
  let minute = decimal(bytes, 14, 2)?;
  let second = decimal(bytes, 17, 2)?;
  if !(1970..=9999).contains(&year)
    || !(1..=12).contains(&month)
    || day == 0
    || day > days_in_month(year, month)
    || hour > 23
    || minute > 59
    || second > 59
  {
    bail!("ct_log_list_timestamp");
  }
  let days = days_before_year(year) - days_before_year(1970)
    + days_before_month(year, month)
    + u64::from(day - 1);
  Ok(days * 86_400 + u64::from(hour) * 3_600 + u64::from(minute) * 60 + u64::from(second))
}

fn decimal(bytes: &[u8], start: usize, len: usize) -> anyhow::Result<u32> {
  let digits = bytes
    .get(start..start + len)
    .ok_or_else(|| anyhow!("ct_log_list_timestamp"))?;
  if !digits.iter().all(u8::is_ascii_digit) {
    bail!("ct_log_list_timestamp");
  }
  Ok(
    digits
      .iter()
      .fold(0, |value, byte| value * 10 + u32::from(byte - b'0')),
  )
}

const fn leap(year: u32) -> bool {
  year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_in_month(year: u32, month: u32) -> u32 {
  match month {
    2 if leap(year) => 29,
    2 => 28,
    4 | 6 | 9 | 11 => 30,
    _ => 31,
  }
}

fn days_before_year(year: u32) -> u64 {
  let preceding = u64::from(year - 1);
  preceding * 365 + preceding / 4 - preceding / 100 + preceding / 400
}

fn days_before_month(year: u32, month: u32) -> u64 {
  (1..month)
    .map(|value| u64::from(days_in_month(year, value)))
    .sum()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLogList {
  version: String,
  log_list_timestamp: String,
  #[serde(default)]
  is_all_logs: Option<bool>,
  operators: Vec<RawOperator>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOperator {
  name: String,
  email: Vec<String>,
  logs: Vec<RawLog>,
  tiled_logs: Vec<RawLog>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLog {
  #[allow(dead_code)]
  description: Option<String>,
  key: String,
  log_id: String,
  mmd: u64,
  #[allow(dead_code)]
  url: Option<String>,
  #[allow(dead_code)]
  submission_url: Option<String>,
  #[allow(dead_code)]
  monitoring_url: Option<String>,
  #[allow(dead_code)]
  dns: Option<String>,
  #[allow(dead_code)]
  log_type: Option<String>,
  state: RawState,
  #[serde(default)]
  temporal_interval: Option<RawTemporalInterval>,
  #[serde(default)]
  previous_operators: Vec<RawPreviousOperator>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTemporalInterval {
  start_inclusive: String,
  end_exclusive: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPreviousOperator {
  name: String,
  end_time: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawState {
  pending: Option<RawStateDetails>,
  qualified: Option<RawStateDetails>,
  usable: Option<RawStateDetails>,
  readonly: Option<RawStateDetails>,
  retired: Option<RawStateDetails>,
  rejected: Option<RawStateDetails>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStateDetails {
  timestamp: String,
  #[allow(dead_code)]
  final_tree_head: Option<RawFinalTreeHead>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFinalTreeHead {
  #[allow(dead_code)]
  tree_size: u64,
  #[allow(dead_code)]
  sha256_root_hash: String,
}

#[cfg(test)]
mod tests {
  use super::*;
  use aws_lc_rs::rand::SystemRandom;
  use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};

  #[test]
  fn official_signing_key_is_a_supported_rsa_key() {
    let key = decode_base64(LOG_LIST_SIGNING_KEY_DER_BASE64, 4_096).expect("key base64");
    assert_eq!(
      signature_public_key(&key).expect("RSA SPKI").0,
      PublicKeyKind::Rsa
    );
  }

  #[test]
  fn timestamp_parser_is_strict_and_handles_leap_days() {
    assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z").unwrap(), 0);
    assert!(parse_rfc3339("2024-02-29T23:59:59Z").is_ok());
    assert!(parse_rfc3339("2023-02-29T00:00:00Z").is_err());
    assert!(parse_rfc3339("2024-01-01T00:00:00+00:00").is_err());
  }

  #[test]
  fn chrome_log_list_age_boundary_is_seventy_days() {
    let snapshot = CtLogListSnapshot {
      version: "1.1".to_string(),
      timestamp: 100,
      logs: HashMap::new(),
    };
    assert!(!snapshot.is_stale_at(100 + LOG_LIST_MAX_AGE_SECONDS - 1));
    assert!(snapshot.is_stale_at(100 + LOG_LIST_MAX_AGE_SECONDS));
  }

  #[test]
  fn malformed_signature_fails_before_json_is_trusted() {
    let error = parse_and_verify_log_list(b"{}", &[0; 512], 0).unwrap_err();
    assert!(error.to_string().contains("ct_log_list_signature_invalid"));
  }

  #[test]
  fn p256_sct_signature_verification_is_cryptographic() {
    const P256_SPKI_PREFIX: &[u8] = &[
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
      0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let random = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
      .expect("generate CT test key");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
      .expect("parse CT test key");
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(key_pair.public_key().as_ref());
    let log = CtLog {
      key_spki: spki,
      operator: "test-operator".to_string(),
      previous_operators: Vec::new(),
      state: CtLogState::Usable { since: 1 },
      temporal_interval: None,
      tiled: false,
    };
    let transcript = b"rfc6962 precertificate transcript";
    let signature = key_pair
      .sign(&random, transcript)
      .expect("sign CT test transcript");

    verify_sct_signature(
      &log,
      crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA,
      transcript,
      signature.as_ref(),
    )
    .expect("valid SCT signature");
    assert!(
      verify_sct_signature(
        &log,
        crate::ct::rfc6962::SIGNATURE_ALGORITHM_ECDSA,
        b"different certificate transcript",
        signature.as_ref(),
      )
      .is_err()
    );
  }

  #[test]
  #[ignore = "requires explicitly downloaded official Chromium v3 list and signature"]
  fn downloaded_official_log_list_signature_and_schema_validate() {
    let json_path = std::env::var("OXIBELT_TEST_CT_LOG_LIST_JSON")
      .expect("OXIBELT_TEST_CT_LOG_LIST_JSON must name the downloaded JSON list");
    let signature_path = std::env::var("OXIBELT_TEST_CT_LOG_LIST_SIGNATURE")
      .expect("OXIBELT_TEST_CT_LOG_LIST_SIGNATURE must name its detached signature");
    let json = std::fs::read(json_path).expect("read official CT Log list");
    let signature = std::fs::read(signature_path).expect("read official CT Log-list signature");
    let now = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .expect("system clock")
      .as_secs();
    let list = parse_and_verify_log_list(&json, &signature, now)
      .expect("official signed CT Log list should validate");
    assert!(!list.logs.is_empty());
    assert!(!list.is_stale_at(now));
  }
}
