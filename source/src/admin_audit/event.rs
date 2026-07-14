//! Versioned Admin audit event primitives.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ADMIN_AUDIT_SCHEMA_VERSION: &str = "oxibelt.admin.audit/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPhase {
  Intent,
  Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
  Accepted,
  Applied,
  Rejected,
  Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityAlgorithm {
  Sha256,
  HmacSha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityEnvelope {
  pub algorithm: IntegrityAlgorithm,
  pub chain_id: String,
  pub sequence: u64,
  pub previous_hash: String,
  pub event_hash: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub key_id: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct OccurrenceTimestamp {
  pub unix_ms: u64,
  pub rfc3339: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuditEvent {
  pub schema_version: String,
  pub event_id: String,
  pub timestamp: String,
  pub timestamp_unix_ms: u64,
  pub instance_id: String,
  pub phase: AuditPhase,
  pub request_id: String,
  pub mutation_request_id: Option<String>,
  pub actor: Option<String>,
  pub principal: Option<String>,
  pub subject: Option<String>,
  pub groups: Vec<String>,
  pub workload_identity_kind: Option<String>,
  pub workload_identity: Option<String>,
  pub workload_principal: Option<String>,
  pub certificate_fingerprint_sha256: Option<String>,
  pub credential_kind: Option<String>,
  pub credential_identity: Option<String>,
  pub credential_principal: Option<String>,
  pub credential_id: Option<String>,
  pub authentication_reason: Option<String>,
  pub peer: String,
  pub source_ip: Option<String>,
  pub source_address: Option<String>,
  pub scheme: String,
  pub method: String,
  pub path: String,
  pub service: Option<String>,
  pub operation: String,
  pub durability_action: Option<String>,
  pub action: Option<String>,
  pub resource: Option<String>,
  pub target_kind: Option<String>,
  pub target_id: Option<String>,
  pub previous_revision: Option<String>,
  pub desired_revision: Option<String>,
  pub content_digest: Option<String>,
  pub status: u16,
  pub result: AuditResult,
  pub outcome: String,
  pub error_code: Option<String>,
  pub error: Option<String>,
  pub request_summary: Value,
  pub integrity: Option<IntegrityEnvelope>,
  #[serde(skip, default)]
  pub(crate) durable_required: bool,
  #[serde(skip, default)]
  pub(crate) lifecycle_managed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminAuditRecord {
  pub id: i64,
  pub namespace: String,
  pub schema_version: String,
  pub event_id: Option<String>,
  pub timestamp: Option<String>,
  pub timestamp_unix_ms: Option<u64>,
  pub instance_id: Option<String>,
  pub phase: Option<AuditPhase>,
  pub request_id: String,
  pub mutation_request_id: Option<String>,
  pub actor: Option<String>,
  pub principal: Option<String>,
  pub subject: Option<String>,
  pub groups: Vec<String>,
  pub workload_identity_kind: Option<String>,
  pub workload_identity: Option<String>,
  pub workload_principal: Option<String>,
  pub certificate_fingerprint_sha256: Option<String>,
  pub credential_kind: Option<String>,
  pub credential_identity: Option<String>,
  pub credential_principal: Option<String>,
  pub credential_id: Option<String>,
  pub authentication_reason: Option<String>,
  pub peer: String,
  pub source_ip: Option<String>,
  pub source_address: Option<String>,
  pub scheme: String,
  pub method: String,
  pub path: String,
  pub service: Option<String>,
  pub operation: String,
  pub durability_action: Option<String>,
  pub action: Option<String>,
  pub resource: Option<String>,
  pub target_kind: Option<String>,
  pub target_id: Option<String>,
  pub previous_revision: Option<String>,
  pub desired_revision: Option<String>,
  pub content_digest: Option<String>,
  pub status: i32,
  pub result: Option<AuditResult>,
  pub outcome: String,
  pub error_code: Option<String>,
  pub error: Option<String>,
  pub request_summary: Value,
  pub integrity: Option<IntegrityEnvelope>,
  pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct AdminAuditQuery {
  pub limit: i64,
  pub outcome: Option<String>,
  pub actor: Option<String>,
  pub principal: Option<String>,
  pub service: Option<String>,
  pub operation: Option<String>,
  pub request_id: Option<String>,
  pub path_prefix: Option<String>,
  pub before_id: Option<i64>,
}

pub(super) fn generate_event_id() -> anyhow::Result<String> {
  random_128_bit_id("Admin audit event ID")
}

pub(super) fn generate_chain_id() -> anyhow::Result<String> {
  random_128_bit_id("Admin audit integrity chain ID")
}

fn random_128_bit_id(label: &str) -> anyhow::Result<String> {
  let mut bytes = [0_u8; 16];
  crate::crypto::random_fill(&mut bytes).with_context(|| format!("failed to generate {label}"))?;
  Ok(hex_encode(&bytes))
}

pub(super) fn occurrence_timestamp() -> anyhow::Result<OccurrenceTimestamp> {
  let unix_ms = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system time is before the Unix epoch")?
    .as_millis();
  let unix_ms = u64::try_from(unix_ms).context("system time exceeds the supported range")?;
  let rfc3339 = format_unix_ms_rfc3339(unix_ms)?;
  Ok(OccurrenceTimestamp { unix_ms, rfc3339 })
}

pub(super) fn format_unix_ms_rfc3339(unix_ms: u64) -> anyhow::Result<String> {
  let seconds = unix_ms / 1_000;
  let milliseconds = unix_ms % 1_000;
  let seconds = i64::try_from(seconds).context("timestamp exceeds the supported range")?;
  let days = seconds.div_euclid(86_400);
  let seconds_of_day = seconds.rem_euclid(86_400);
  let (year, month, day) = civil_from_days(days);
  if !(1970..=9999).contains(&year) {
    bail!("timestamp is outside the supported RFC 3339 range");
  }
  let hour = seconds_of_day / 3_600;
  let minute = seconds_of_day % 3_600 / 60;
  let second = seconds_of_day % 60;
  Ok(format!(
    "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z"
  ))
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
  let days = days_since_epoch + 719_468;
  let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
  let day_of_era = days - era * 146_097;
  let year_of_era =
    (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
  let mut year = year_of_era + era * 400;
  let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  let month_prime = (5 * day_of_year + 2) / 153;
  let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
  let month = month_prime + if month_prime < 10 { 3 } else { -9 };
  year += i64::from(month <= 2);
  (year, month, day)
}

/// Returns compact JSON with all object keys sorted recursively.
pub(super) fn canonical_json_bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
  let mut output = Vec::new();
  write_canonical_json(value, &mut output)?;
  Ok(output)
}

pub(super) fn unsigned_event_value(event: &AdminAuditEvent) -> anyhow::Result<Value> {
  let mut value = serde_json::to_value(event)?;
  let object = value
    .as_object_mut()
    .context("Admin audit event must serialize as an object")?;
  object.insert("integrity".to_string(), Value::Null);
  Ok(value)
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
      entries.sort_unstable_by_key(|(left, _)| *left);
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

pub(super) fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut output = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    output.push(HEX[(byte >> 4) as usize] as char);
    output.push(HEX[(byte & 0x0f) as usize] as char);
  }
  output
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  #[test]
  fn schema_enums_use_stable_wire_values() {
    assert_eq!(ADMIN_AUDIT_SCHEMA_VERSION, "oxibelt.admin.audit/v1");
    assert_eq!(serde_json::to_value(AuditPhase::Intent).unwrap(), "intent");
    assert_eq!(
      serde_json::to_value(AuditPhase::Terminal).unwrap(),
      "terminal"
    );
    assert_eq!(
      serde_json::to_value(AuditResult::Accepted).unwrap(),
      "accepted"
    );
    assert_eq!(
      serde_json::to_value(AuditResult::Applied).unwrap(),
      "applied"
    );
    assert_eq!(
      serde_json::to_value(AuditResult::Rejected).unwrap(),
      "rejected"
    );
    assert_eq!(
      serde_json::to_value(AuditResult::Indeterminate).unwrap(),
      "indeterminate"
    );
    assert_eq!(
      serde_json::to_value(IntegrityAlgorithm::Sha256).unwrap(),
      "sha256"
    );
    assert_eq!(
      serde_json::to_value(IntegrityAlgorithm::HmacSha256).unwrap(),
      "hmac_sha256"
    );
  }

  #[test]
  fn canonical_json_sorts_every_object_without_reordering_arrays() {
    let first = json!({
      "z": {"b": 2, "a": 1},
      "a": [{"d": 4, "c": 3}, 2, 1],
      "escaped": "line\nquote\""
    });
    let second = serde_json::from_str::<Value>(
      r#"{"escaped":"line\nquote\"","a":[{"c":3,"d":4},2,1],"z":{"a":1,"b":2}}"#,
    )
    .unwrap();
    let expected = br#"{"a":[{"c":3,"d":4},2,1],"escaped":"line\nquote\"","z":{"a":1,"b":2}}"#;

    assert_eq!(canonical_json_bytes(&first).unwrap(), expected);
    assert_eq!(
      canonical_json_bytes(&first).unwrap(),
      canonical_json_bytes(&second).unwrap()
    );
  }

  #[test]
  fn random_ids_are_128_bit_lowercase_hex() {
    let event_id = generate_event_id().unwrap();
    let chain_id = generate_chain_id().unwrap();

    for identifier in [&event_id, &chain_id] {
      assert_eq!(identifier.len(), 32);
      assert!(
        identifier
          .bytes()
          .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
      );
    }
  }

  #[test]
  fn unix_milliseconds_have_canonical_utc_representation() {
    assert_eq!(
      format_unix_ms_rfc3339(0).unwrap(),
      "1970-01-01T00:00:00.000Z"
    );
    assert_eq!(
      format_unix_ms_rfc3339(946_684_800_123).unwrap(),
      "2000-01-01T00:00:00.123Z"
    );
    assert!(format_unix_ms_rfc3339(u64::MAX).is_err());

    let occurrence = occurrence_timestamp().unwrap();
    assert_eq!(occurrence.rfc3339.len(), 24);
    assert!(occurrence.rfc3339.ends_with('Z'));
    assert_eq!(
      occurrence.rfc3339,
      format_unix_ms_rfc3339(occurrence.unix_ms).unwrap()
    );
  }
}
