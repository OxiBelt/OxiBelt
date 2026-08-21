//! Tamper-evident chaining for versioned Admin audit events.

use anyhow::{Context, bail, ensure};
use base64::Engine as _;
use futures_util::TryStreamExt as _;
use serde_json::Value;
use sqlx::{Pool, Postgres, Row};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::event::{
  AdminAuditEvent, IntegrityAlgorithm, IntegrityEnvelope, canonical_json_bytes, generate_chain_id,
  hex_encode, unsigned_event_value,
};
use super::{AdminAuditRuntime, store};

const INTEGRITY_DOMAIN: &[u8] = b"oxibelt.admin.audit.integrity/v1\0";
const HASH_BYTES: usize = 32;
const CHAIN_ID_BYTES: usize = 16;
const GENESIS_HASH: [u8; HASH_BYTES] = [0_u8; HASH_BYTES];

#[derive(Clone)]
pub(super) struct AuditHmacKey {
  key: Zeroizing<[u8; HASH_BYTES]>,
  key_id: String,
}

impl AuditHmacKey {
  pub(super) fn from_environment(environment_name: &str, key_id: &str) -> anyhow::Result<Self> {
    ensure!(
      !environment_name.is_empty() && environment_name.trim() == environment_name,
      "Admin audit HMAC key environment name must not be empty or padded"
    );
    let encoded = Zeroizing::new(
      std::env::var(environment_name)
        .with_context(|| format!("failed to read Admin audit HMAC key {environment_name}"))?,
    );
    Self::from_base64(encoded.trim(), key_id)
  }

  pub(super) fn from_base64(encoded: &str, key_id: &str) -> anyhow::Result<Self> {
    validate_key_id(key_id)?;
    let decoded = Zeroizing::new(
      base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("Admin audit HMAC key must contain base64")?,
    );
    ensure!(
      decoded.len() == HASH_BYTES,
      "Admin audit HMAC key must contain exactly 32 bytes"
    );
    let mut key = Zeroizing::new([0_u8; HASH_BYTES]);
    key.copy_from_slice(decoded.as_slice());
    Ok(Self {
      key,
      key_id: key_id.to_string(),
    })
  }

  pub(super) fn key_id(&self) -> &str {
    &self.key_id
  }
}

fn validate_key_id(key_id: &str) -> anyhow::Result<()> {
  ensure!(
    !key_id.is_empty() && key_id.trim() == key_id,
    "Admin audit HMAC key ID must not be empty or padded"
  );
  ensure!(
    key_id.len() <= 128,
    "Admin audit HMAC key ID must be at most 128 bytes"
  );
  ensure!(
    !key_id.bytes().any(|byte| byte.is_ascii_control()),
    "Admin audit HMAC key ID must not contain control characters"
  );
  Ok(())
}

#[derive(Clone)]
pub(super) struct IntegrityChain {
  chain_id: String,
  next_sequence: u64,
  previous_hash: [u8; HASH_BYTES],
  hmac_key: Option<AuditHmacKey>,
}

impl IntegrityChain {
  pub(super) fn new(hmac_key: Option<AuditHmacKey>) -> anyhow::Result<Self> {
    Ok(Self {
      chain_id: generate_chain_id()?,
      next_sequence: 0,
      previous_hash: GENESIS_HASH,
      hmac_key,
    })
  }

  pub(super) fn restore(
    chain_id: String,
    next_sequence: u64,
    previous_hash: &str,
    hmac_key: Option<AuditHmacKey>,
  ) -> anyhow::Result<Self> {
    validate_chain_id(&chain_id)?;
    let previous_hash = decode_hex::<HASH_BYTES>(previous_hash, "previous event hash")?;
    Ok(Self {
      chain_id,
      next_sequence,
      previous_hash,
      hmac_key,
    })
  }

  pub(super) fn chain_id(&self) -> &str {
    &self.chain_id
  }

  pub(super) fn next_sequence(&self) -> u64 {
    self.next_sequence
  }

  pub(super) fn previous_hash(&self) -> String {
    hex_encode(&self.previous_hash)
  }

  /// Seals canonical event JSON that does not yet contain an integrity envelope.
  pub(super) fn seal(&mut self, payload: &Value) -> anyhow::Result<IntegrityEnvelope> {
    let next_sequence = self
      .next_sequence
      .checked_add(1)
      .context("Admin audit integrity sequence is exhausted")?;
    let canonical_payload = canonical_json_bytes(payload)?;
    let algorithm = algorithm_for(self.hmac_key.as_ref());
    let key_id = self
      .hmac_key
      .as_ref()
      .map(|hmac_key| hmac_key.key_id().to_string());
    let event_hash = calculate_event_hash(
      &self.chain_id,
      self.next_sequence,
      &self.previous_hash,
      algorithm,
      key_id.as_deref(),
      &canonical_payload,
    )?;
    let tag = self
      .hmac_key
      .as_ref()
      .map(|hmac_key| hex_encode(&crate::crypto::hmac_sha256(&*hmac_key.key, &event_hash)));
    let envelope = IntegrityEnvelope {
      algorithm,
      chain_id: self.chain_id.clone(),
      sequence: self.next_sequence,
      previous_hash: hex_encode(&self.previous_hash),
      event_hash: hex_encode(&event_hash),
      key_id,
      tag,
    };
    self.next_sequence = next_sequence;
    self.previous_hash = event_hash;
    Ok(envelope)
  }
}

pub(super) async fn restore_postgres_chain(
  pool: &Pool<Postgres>,
  namespace: &str,
  instance_id: &str,
  hmac_key: Option<AuditHmacKey>,
) -> anyhow::Result<IntegrityChain> {
  let latest = sqlx::query(
    "SELECT integrity->>'chain_id' AS chain_id, event_payload::text AS event_payload
       FROM oxibelt_admin_audit
      WHERE namespace=$1 AND instance_id=$2
        AND integrity IS NOT NULL AND event_payload IS NOT NULL
      ORDER BY id DESC
      LIMIT 1",
  )
  .bind(namespace)
  .bind(instance_id)
  .fetch_optional(pool)
  .await
  .context("failed to locate the current Admin audit integrity chain")?;
  let Some(latest) = latest else {
    return IntegrityChain::new(hmac_key);
  };
  let chain_id: String = latest.try_get("chain_id")?;
  validate_chain_id(&chain_id)?;
  let latest_payload: String = latest.try_get("event_payload")?;
  let latest_event: AdminAuditEvent = serde_json::from_str(&latest_payload)
    .context("latest stored Admin audit event payload is not valid JSON")?;
  ensure!(
    latest_event.instance_id == instance_id,
    "latest stored Admin audit event instance identity changed"
  );
  let latest_envelope = latest_event
    .integrity
    .as_ref()
    .context("latest stored Admin audit event is missing integrity metadata")?;
  ensure!(
    latest_envelope.chain_id == chain_id,
    "latest stored Admin audit event chain identity changed"
  );
  let configured_authority_matches = match hmac_key.as_ref() {
    Some(key) => {
      latest_envelope.algorithm == IntegrityAlgorithm::HmacSha256
        && latest_envelope.key_id.as_deref() == Some(key.key_id())
    }
    None => {
      latest_envelope.algorithm == IntegrityAlgorithm::Sha256 && latest_envelope.key_id.is_none()
    }
  };
  if !configured_authority_matches {
    return IntegrityChain::new(hmac_key);
  }
  let mut rows = sqlx::query(
    "SELECT event_payload::text AS event_payload
       FROM oxibelt_admin_audit
      WHERE namespace=$1 AND instance_id=$2
        AND integrity->>'chain_id'=$3 AND event_payload IS NOT NULL
      ORDER BY ((integrity->>'sequence')::bigint) ASC, id ASC",
  )
  .bind(namespace)
  .bind(instance_id)
  .bind(&chain_id)
  .fetch(pool);
  let mut verifier = IntegrityVerifier::restore(
    chain_id.clone(),
    0,
    &hex_encode(&GENESIS_HASH),
    hmac_key.clone(),
  )?;
  let mut previous_hash = hex_encode(&GENESIS_HASH);
  let mut next_sequence = 0_u64;
  while let Some(row) = rows
    .try_next()
    .await
    .context("failed to stream the current Admin audit integrity chain")?
  {
    let payload: String = row.try_get("event_payload")?;
    let event: AdminAuditEvent = serde_json::from_str(&payload)
      .context("stored Admin audit event payload is not valid JSON")?;
    let envelope = event
      .integrity
      .as_ref()
      .context("stored Admin audit event is missing integrity metadata")?;
    ensure!(
      event.instance_id == instance_id,
      "stored Admin audit event instance identity changed"
    );
    verifier.verify_and_advance(&unsigned_event_value(&event)?, envelope)?;
    previous_hash.clone_from(&envelope.event_hash);
    next_sequence = envelope
      .sequence
      .checked_add(1)
      .context("Admin audit integrity sequence is exhausted")?;
  }
  ensure!(
    next_sequence > 0,
    "current Admin audit integrity chain has no recoverable events"
  );
  IntegrityChain::restore(chain_id, next_sequence, &previous_hash, hmac_key)
}

impl AdminAuditRuntime {
  pub(super) async fn persist_direct_postgres_event(
    &self,
    event: AdminAuditEvent,
  ) -> anyhow::Result<AdminAuditEvent> {
    let durable = self
      .store
      .as_ref()
      .context("required Admin audit PostgreSQL store is unavailable")?;
    let mut current = self.direct_integrity.lock().await;
    let mut staged = current.clone();
    let event = self.seal_with_chain(event, &mut staged)?;
    let required =
      event.durable_required || self.requires_durability(event.durability_action.as_deref());
    let mut tx = durable.pool.begin().await?;
    store::insert_record_returning_id_tx(&mut tx, &durable.namespace, &event).await?;
    let outcome = self
      .anchor
      .record_event_tx(&mut tx, &event, required)
      .await?;
    if required
      && matches!(
        outcome,
        super::anchor::AnchorCandidateOutcome::CapacityExceeded
      )
    {
      anyhow::bail!("Admin audit anchor pending capacity is exhausted");
    }
    tx.commit().await?;
    *current = staged;
    self.anchor.after_event(&event, outcome, required).await?;
    Ok(event)
  }

  pub(super) async fn enqueue_direct_event(
    &self,
    event: AdminAuditEvent,
    permit: mpsc::OwnedPermit<AdminAuditEvent>,
  ) -> anyhow::Result<AdminAuditEvent> {
    let mut current = self.direct_integrity.lock().await;
    let mut staged = current.clone();
    let event = self.seal_with_chain(event, &mut staged)?;
    drop(permit.send(event.clone()));
    *current = staged;
    Ok(event)
  }

  pub(super) fn seal_with_chain(
    &self,
    mut event: AdminAuditEvent,
    chain: &mut IntegrityChain,
  ) -> anyhow::Result<AdminAuditEvent> {
    event.integrity = None;
    event.integrity = Some(chain.seal(&unsigned_event_value(&event)?)?);
    ensure!(
      serde_json::to_vec(&event)?.len() <= self.max_event_bytes,
      "Admin audit event exceeds the configured event limit"
    );
    Ok(event)
  }
}

pub(super) struct IntegrityVerifier {
  chain_id: String,
  next_sequence: u64,
  previous_hash: [u8; HASH_BYTES],
  hmac_key: Option<AuditHmacKey>,
}

impl IntegrityVerifier {
  #[cfg(test)]
  pub(super) fn new(chain_id: String, hmac_key: Option<AuditHmacKey>) -> anyhow::Result<Self> {
    Self::restore(chain_id, 0, &hex_encode(&GENESIS_HASH), hmac_key)
  }

  pub(super) fn restore(
    chain_id: String,
    next_sequence: u64,
    previous_hash: &str,
    hmac_key: Option<AuditHmacKey>,
  ) -> anyhow::Result<Self> {
    validate_chain_id(&chain_id)?;
    Ok(Self {
      chain_id,
      next_sequence,
      previous_hash: decode_hex::<HASH_BYTES>(previous_hash, "previous event hash")?,
      hmac_key,
    })
  }

  pub(super) fn verify_and_advance(
    &mut self,
    payload: &Value,
    envelope: &IntegrityEnvelope,
  ) -> anyhow::Result<()> {
    ensure!(
      envelope.chain_id == self.chain_id,
      "Admin audit integrity chain ID does not match"
    );
    ensure!(
      envelope.sequence == self.next_sequence,
      "Admin audit integrity sequence is out of order"
    );
    let envelope_previous_hash =
      decode_hex::<HASH_BYTES>(&envelope.previous_hash, "previous event hash")?;
    ensure!(
      envelope_previous_hash == self.previous_hash,
      "Admin audit previous event hash does not match"
    );

    let expected_algorithm = algorithm_for(self.hmac_key.as_ref());
    ensure!(
      envelope.algorithm == expected_algorithm,
      "Admin audit integrity algorithm does not match the configured chain"
    );
    match self.hmac_key.as_ref() {
      Some(hmac_key) => {
        ensure!(
          envelope.key_id.as_deref() == Some(hmac_key.key_id()),
          "Admin audit HMAC key ID does not match"
        );
      }
      None => ensure!(
        envelope.key_id.is_none() && envelope.tag.is_none(),
        "hash-only Admin audit envelopes must not contain HMAC metadata"
      ),
    }

    let canonical_payload = canonical_json_bytes(payload)?;
    let expected_event_hash = calculate_event_hash(
      &self.chain_id,
      self.next_sequence,
      &self.previous_hash,
      expected_algorithm,
      envelope.key_id.as_deref(),
      &canonical_payload,
    )?;
    let event_hash = decode_hex::<HASH_BYTES>(&envelope.event_hash, "event hash")?;
    ensure!(
      event_hash == expected_event_hash,
      "Admin audit event hash does not match"
    );

    if let Some(hmac_key) = self.hmac_key.as_ref() {
      let tag = envelope
        .tag
        .as_deref()
        .context("Admin audit HMAC envelope is missing its tag")?;
      let tag = decode_hex::<HASH_BYTES>(tag, "HMAC tag")?;
      ensure!(
        crate::crypto::verify_hmac_sha256(&*hmac_key.key, &event_hash, &tag),
        "Admin audit HMAC tag does not match"
      );
    }

    self.next_sequence = self
      .next_sequence
      .checked_add(1)
      .context("Admin audit integrity sequence is exhausted")?;
    self.previous_hash = event_hash;
    Ok(())
  }
}

fn algorithm_for(hmac_key: Option<&AuditHmacKey>) -> IntegrityAlgorithm {
  if hmac_key.is_some() {
    IntegrityAlgorithm::HmacSha256
  } else {
    IntegrityAlgorithm::Sha256
  }
}

fn calculate_event_hash(
  chain_id: &str,
  sequence: u64,
  previous_hash: &[u8; HASH_BYTES],
  algorithm: IntegrityAlgorithm,
  key_id: Option<&str>,
  canonical_payload: &[u8],
) -> anyhow::Result<[u8; HASH_BYTES]> {
  validate_chain_id(chain_id)?;
  let chain_id = decode_hex::<CHAIN_ID_BYTES>(chain_id, "chain ID")?;
  let key_id = key_id.unwrap_or_default().as_bytes();
  let key_id_len = u32::try_from(key_id.len()).context("Admin audit HMAC key ID is too long")?;
  let payload_len =
    u64::try_from(canonical_payload.len()).context("Admin audit canonical payload is too large")?;
  let mut input = Vec::with_capacity(
    INTEGRITY_DOMAIN.len()
      + CHAIN_ID_BYTES
      + 8
      + HASH_BYTES
      + 1
      + 4
      + key_id.len()
      + 8
      + canonical_payload.len(),
  );
  input.extend_from_slice(INTEGRITY_DOMAIN);
  input.extend_from_slice(&chain_id);
  input.extend_from_slice(&sequence.to_be_bytes());
  input.extend_from_slice(previous_hash);
  input.push(match algorithm {
    IntegrityAlgorithm::Sha256 => 1,
    IntegrityAlgorithm::HmacSha256 => 2,
  });
  input.extend_from_slice(&key_id_len.to_be_bytes());
  input.extend_from_slice(key_id);
  input.extend_from_slice(&payload_len.to_be_bytes());
  input.extend_from_slice(canonical_payload);
  Ok(crate::crypto::sha256(&input))
}

fn validate_chain_id(chain_id: &str) -> anyhow::Result<()> {
  let _ = decode_hex::<CHAIN_ID_BYTES>(chain_id, "chain ID")?;
  Ok(())
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> anyhow::Result<[u8; N]> {
  ensure!(
    value.len() == N * 2,
    "Admin audit {label} must contain exactly {} lowercase hexadecimal characters",
    N * 2
  );
  let mut output = [0_u8; N];
  for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
    let high = decode_hex_digit(pair[0]).with_context(|| format!("Admin audit {label}"))?;
    let low = decode_hex_digit(pair[1]).with_context(|| format!("Admin audit {label}"))?;
    output[index] = high << 4 | low;
  }
  Ok(output)
}

fn decode_hex_digit(value: u8) -> anyhow::Result<u8> {
  match value {
    b'0'..=b'9' => Ok(value - b'0'),
    b'a'..=b'f' => Ok(value - b'a' + 10),
    _ => bail!("must use lowercase hexadecimal"),
  }
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  const CHAIN_ID: &str = "00112233445566778899aabbccddeeff";
  const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

  fn hash_chain() -> IntegrityChain {
    IntegrityChain::restore(CHAIN_ID.to_string(), 0, ZERO_HASH, None).unwrap()
  }

  #[test]
  fn deterministic_hash_chain_detects_payload_tampering() {
    let payload = json!({"action": "config.load", "request_id": "abc"});
    let envelope = hash_chain().seal(&payload).unwrap();
    let repeated = hash_chain().seal(&payload).unwrap();
    assert_eq!(envelope, repeated);

    let mut verifier = IntegrityVerifier::new(CHAIN_ID.to_string(), None).unwrap();
    verifier.verify_and_advance(&payload, &envelope).unwrap();

    let mut verifier = IntegrityVerifier::new(CHAIN_ID.to_string(), None).unwrap();
    let error = verifier
      .verify_and_advance(
        &json!({"action": "config.rollback", "request_id": "abc"}),
        &envelope,
      )
      .unwrap_err();
    assert!(error.to_string().contains("event hash does not match"));
  }

  #[test]
  fn verifier_rejects_reordered_or_missing_events_without_advancing() {
    let mut chain = hash_chain();
    let first_payload = json!({"event": 1});
    let second_payload = json!({"event": 2});
    let first = chain.seal(&first_payload).unwrap();
    let second = chain.seal(&second_payload).unwrap();

    let mut verifier = IntegrityVerifier::new(CHAIN_ID.to_string(), None).unwrap();
    let error = verifier
      .verify_and_advance(&second_payload, &second)
      .unwrap_err();
    assert!(error.to_string().contains("sequence is out of order"));
    verifier.verify_and_advance(&first_payload, &first).unwrap();
    verifier
      .verify_and_advance(&second_payload, &second)
      .unwrap();
  }

  #[test]
  fn hmac_chain_requires_matching_key_algorithm_and_key_id() {
    let encoded_key = base64::engine::general_purpose::STANDARD.encode([7_u8; HASH_BYTES]);
    let key = AuditHmacKey::from_base64(&encoded_key, "audit-2026-07").unwrap();
    let payload = json!({"event": "protected"});
    let mut chain =
      IntegrityChain::restore(CHAIN_ID.to_string(), 0, ZERO_HASH, Some(key.clone())).unwrap();
    let envelope = chain.seal(&payload).unwrap();

    let mut verifier = IntegrityVerifier::new(CHAIN_ID.to_string(), Some(key.clone())).unwrap();
    verifier.verify_and_advance(&payload, &envelope).unwrap();

    let other_encoded = base64::engine::general_purpose::STANDARD.encode([8_u8; HASH_BYTES]);
    let other_key = AuditHmacKey::from_base64(&other_encoded, "audit-2026-07").unwrap();
    let mut verifier = IntegrityVerifier::new(CHAIN_ID.to_string(), Some(other_key)).unwrap();
    assert!(
      verifier
        .verify_and_advance(&payload, &envelope)
        .unwrap_err()
        .to_string()
        .contains("HMAC tag does not match")
    );

    let mut downgraded = envelope.clone();
    downgraded.algorithm = IntegrityAlgorithm::Sha256;
    downgraded.key_id = None;
    downgraded.tag = None;
    let mut verifier = IntegrityVerifier::new(CHAIN_ID.to_string(), Some(key)).unwrap();
    assert!(
      verifier
        .verify_and_advance(&payload, &downgraded)
        .unwrap_err()
        .to_string()
        .contains("algorithm does not match")
    );
  }

  #[test]
  fn validates_hmac_keys_key_ids_and_chain_state() {
    assert!(AuditHmacKey::from_base64("not-base64", "key-1").is_err());
    let short_key = base64::engine::general_purpose::STANDARD.encode([1_u8; 31]);
    assert!(AuditHmacKey::from_base64(&short_key, "key-1").is_err());
    let valid_key = base64::engine::general_purpose::STANDARD.encode([1_u8; HASH_BYTES]);
    assert!(AuditHmacKey::from_base64(&valid_key, "").is_err());
    assert!(AuditHmacKey::from_base64(&valid_key, " padded ").is_err());
    assert!(IntegrityChain::restore("ABC".to_string(), 0, ZERO_HASH, None).is_err());
    assert!(IntegrityVerifier::new("A".repeat(32), None).is_err());
  }

  #[test]
  fn random_chain_starts_at_genesis_and_advances_state() {
    let mut chain = IntegrityChain::new(None).unwrap();
    assert_eq!(chain.chain_id().len(), 32);
    assert_eq!(chain.next_sequence(), 0);
    assert_eq!(chain.previous_hash(), ZERO_HASH);

    let envelope = chain.seal(&json!({"event": 1})).unwrap();
    assert_eq!(envelope.sequence, 0);
    assert_eq!(chain.next_sequence(), 1);
    assert_eq!(chain.previous_hash(), envelope.event_hash);
  }
}
