use anyhow::anyhow;
#[cfg(feature = "admin-runtime")]
use anyhow::bail;
#[cfg(feature = "admin-runtime")]
use base64::Engine;
#[cfg(feature = "admin-runtime")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "admin-runtime")]
use super::enumeration::{EnumerationCursor, EnumerationLimits};
#[cfg(all(test, feature = "admin-runtime"))]
use super::now_unix_ms;
use super::{Backend, SharedState, SharedStateFeature, ttl_from_expires_ms};
#[cfg(feature = "admin-runtime")]
use super::{PersonProofRevocationIdempotency, PersonProofRevocationResult};

const PERSON_PROOF_REUSE_CLEARANCE_PREFIX: &str = "person-proof:reuse:clearance:";
const PERSON_PROOF_REUSE_CHALLENGE_PREFIX: &str = "person-proof:reuse:challenge:";
const PERSON_PROOF_REVOKED_CLEARANCE_PREFIX: &str = "person-proof:revoked:clearance:";
#[cfg(feature = "admin-runtime")]
const PERSON_PROOF_CLEARANCE_CURSOR_VERSION: u8 = 1;
#[cfg(feature = "admin-runtime")]
const PERSON_PROOF_CLEARANCE_CURSOR_MAX_BYTES: usize = 4_096;

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Default, Serialize)]
pub struct PersonProofSharedStatus {
  pub active_clearance_count: usize,
  pub challenge_replay_marker_count: usize,
  pub revoked_clearance_count: usize,
  pub legacy_raw_key_count: usize,
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Serialize)]
pub struct PersonProofSharedClearance {
  pub clearance_hash: String,
  pub expires_at_unix_ms: Option<i64>,
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Clone, Serialize)]
pub struct PersonProofSharedClearancePage {
  pub clearances: Vec<PersonProofSharedClearance>,
  pub next_cursor: Option<String>,
}

#[cfg(feature = "admin-runtime")]
#[derive(Debug, Deserialize, Serialize)]
struct PersonProofClearanceCursor {
  version: u8,
  scope: String,
  position: EnumerationCursor,
}

impl SharedState {
  pub async fn person_proof_secret(&self) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(backend) = &self.person_proof else {
      return Ok(None);
    };
    let key = self.key("person-proof:secret:v1");
    let result = backend.get_or_init_bytes(&key, 32, None).await;
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    let secret = result?;
    let bytes: [u8; 32] = secret
      .as_slice()
      .try_into()
      .map_err(|_| anyhow!("shared person proof secret has invalid length"))?;
    Ok(Some(bytes))
  }

  pub fn person_proof_enabled(&self) -> bool {
    self.person_proof.is_some()
  }

  pub async fn person_proof_remember(&self, key: &str, expires_at_ms: i64) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(true);
    };
    let ttl = ttl_from_expires_ms(expires_at_ms);
    let result = backend
      .put_if_absent(&self.key(&format!("person-proof:reuse:{key}")), b"1", ttl)
      .await;
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    result
  }

  pub async fn person_proof_consume(&self, key: &str) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(false);
    };
    let result = backend
      .take_key(&self.key(&format!("person-proof:reuse:{key}")))
      .await;
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    result
  }

  pub async fn person_proof_mark_challenge_used(
    &self,
    token: &str,
    hash: &str,
    expires_at_ms: i64,
  ) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(true);
    };
    let legacy_key = self.key(&format!("{PERSON_PROOF_REUSE_CHALLENGE_PREFIX}{token}"));
    let hash_key = self.key(&format!("{PERSON_PROOF_REUSE_CHALLENGE_PREFIX}{hash}"));
    let ttl = ttl_from_expires_ms(expires_at_ms);
    let result = backend
      .person_proof_mark_challenge_used(&legacy_key, &hash_key, ttl)
      .await;
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    result
  }

  pub async fn person_proof_consume_clearance(
    &self,
    token: &str,
    hash: &str,
  ) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(false);
    };
    let revoked_key = self.key(&format!("{PERSON_PROOF_REVOKED_CLEARANCE_PREFIX}{hash}"));
    let key = self.key(&format!("{PERSON_PROOF_REUSE_CLEARANCE_PREFIX}{hash}"));
    let legacy_key = self.key(&format!("{PERSON_PROOF_REUSE_CLEARANCE_PREFIX}{token}"));
    let result = backend
      .person_proof_consume_clearance(&revoked_key, &key, &legacy_key)
      .await;
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    result
  }

  pub async fn person_proof_clearance_revoked(&self, hash: &str) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(false);
    };
    let result = backend
      .get(&self.key(&format!("{PERSON_PROOF_REVOKED_CLEARANCE_PREFIX}{hash}")))
      .await;
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    result.map(|value| value.is_some())
  }

  #[cfg(feature = "admin-runtime")]
  pub(crate) async fn person_proof_revoke_clearance_hash(
    &self,
    hash: &str,
    expires_at_ms: i64,
    idempotency: Option<&PersonProofRevocationIdempotency>,
  ) -> anyhow::Result<PersonProofRevocationResult> {
    let Some(backend) = &self.person_proof else {
      return Ok(PersonProofRevocationResult {
        removed_active: false,
        expires_at_ms,
      });
    };
    let ttl = ttl_from_expires_ms(expires_at_ms)
      .ok_or_else(|| anyhow!("person proof clearance revocation has already expired"))?;
    let tombstone_key = self.key(&format!("{PERSON_PROOF_REVOKED_CLEARANCE_PREFIX}{hash}"));
    let active_key = self.key(&format!("{PERSON_PROOF_REUSE_CLEARANCE_PREFIX}{hash}"));
    let idempotency_key = idempotency.map(|record| {
      self.key(&format!(
        "admin-idempotency:person-proof-revoke:{}",
        record.key_digest
      ))
    });
    let result = backend
      .person_proof_revoke_clearance(
        &tombstone_key,
        &active_key,
        ttl,
        expires_at_ms,
        idempotency_key.as_deref(),
        idempotency.map(|record| record.request_fingerprint.as_str()),
      )
      .await;
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    result
  }

  #[cfg(feature = "admin-runtime")]
  pub async fn person_proof_admin_status(&self) -> anyhow::Result<PersonProofSharedStatus> {
    let Some(backend) = &self.person_proof else {
      return Ok(PersonProofSharedStatus::default());
    };
    let prefix = self.key("person-proof:");
    let result = match tokio::time::timeout(
      self.operation_timeout,
      backend.person_proof_status(&prefix, self.enumeration),
    )
    .await
    {
      Ok(result) => result,
      Err(_) => Err(anyhow!("person proof shared status enumeration timed out")),
    };
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    result
  }

  #[cfg(feature = "admin-runtime")]
  pub async fn person_proof_list_clearances(
    &self,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofSharedClearancePage> {
    let Some(backend) = &self.person_proof else {
      return Ok(PersonProofSharedClearancePage {
        clearances: Vec::new(),
        next_cursor: None,
      });
    };
    let prefix = self.key(PERSON_PROOF_REUSE_CLEARANCE_PREFIX);
    let position = decode_clearance_cursor(cursor, &prefix, backend)?;
    let result = match tokio::time::timeout(
      self.operation_timeout,
      backend.person_proof_clearances(&prefix, limit, position, self.enumeration),
    )
    .await
    {
      Ok(result) => result,
      Err(_) => Err(anyhow!("person proof clearance enumeration timed out")),
    };
    self.observe_backend_result(SharedStateFeature::PersonProof, &result);
    let (clearances, next_cursor) = result?;
    Ok(PersonProofSharedClearancePage {
      clearances,
      next_cursor: next_cursor
        .map(|position| encode_clearance_cursor(&prefix, backend, position))
        .transpose()?,
    })
  }
}

impl Backend {
  async fn person_proof_mark_challenge_used(
    &self,
    legacy_key: &str,
    hash_key: &str,
    ttl: Option<std::time::Duration>,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_put_if_absent", || {
            redis.person_proof_mark_challenge_used_atomic(legacy_key, hash_key, ttl)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_put_if_absent", || {
            pg.person_proof_mark_challenge_used_atomic(legacy_key, hash_key, ttl)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => {
        memory.person_proof_mark_challenge_used_atomic(legacy_key, hash_key, ttl)
      }
    }
  }

  async fn person_proof_consume_clearance(
    &self,
    revoked_key: &str,
    hash_key: &str,
    legacy_key: &str,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_take", || {
            redis.person_proof_consume_clearance_atomic(revoked_key, hash_key, legacy_key)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_take", || {
            pg.person_proof_consume_clearance_atomic(revoked_key, hash_key, legacy_key)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => {
        memory.person_proof_consume_clearance_atomic(revoked_key, hash_key, legacy_key)
      }
    }
  }

  #[cfg(feature = "admin-runtime")]
  #[allow(clippy::too_many_arguments)]
  async fn person_proof_revoke_clearance(
    &self,
    tombstone_key: &str,
    active_key: &str,
    ttl: std::time::Duration,
    expires_at_ms: i64,
    idempotency_key: Option<&str>,
    request_fingerprint: Option<&str>,
  ) -> anyhow::Result<PersonProofRevocationResult> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("value_put", || {
            redis.person_proof_revoke_clearance_atomic(
              tombstone_key,
              active_key,
              ttl,
              expires_at_ms,
              idempotency_key,
              request_fingerprint,
            )
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("value_put", || {
            pg.person_proof_revoke_clearance_atomic(
              tombstone_key,
              active_key,
              ttl,
              expires_at_ms,
              idempotency_key,
              request_fingerprint,
            )
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.person_proof_revoke_clearance_atomic(
        tombstone_key,
        active_key,
        ttl,
        expires_at_ms,
        idempotency_key,
        request_fingerprint,
      ),
    }
  }

  #[cfg(feature = "admin-runtime")]
  async fn person_proof_status(
    &self,
    prefix: &str,
    limits: EnumerationLimits,
  ) -> anyhow::Result<PersonProofSharedStatus> {
    let mut cursor = None;
    let mut status = PersonProofSharedStatus::default();
    let mut examined = 0_usize;
    for _ in 0..limits.max_rounds() {
      let remaining = limits.max_items.saturating_sub(examined);
      if remaining == 0 {
        self.record_enumeration("person_proof_status", "cap_exhausted", 1);
        bail!("person proof status enumeration reached its configured item limit");
      }
      let page = self
        .enumeration_keys(
          prefix,
          cursor.as_ref(),
          limits.page_size.min(remaining).max(1),
          "person_proof_status",
        )
        .await?;
      for key in &page.keys {
        person_proof_status_add_key(&mut status, key, prefix);
      }
      examined = examined.saturating_add(page.keys.len());
      cursor = page.next_cursor;
      if cursor.is_none() {
        return Ok(status);
      }
    }
    self.record_enumeration("person_proof_status", "cap_exhausted", 1);
    bail!("person proof status enumeration reached its configured scan-round limit")
  }

  #[cfg(feature = "admin-runtime")]
  async fn person_proof_clearances(
    &self,
    prefix: &str,
    limit: usize,
    cursor: Option<EnumerationCursor>,
    limits: EnumerationLimits,
  ) -> anyhow::Result<(Vec<PersonProofSharedClearance>, Option<EnumerationCursor>)> {
    let mut cursor = cursor;
    let mut clearances = Vec::new();
    let mut examined = 0_usize;
    for _ in 0..limits.max_rounds() {
      if clearances.len() >= limit {
        return Ok((clearances, cursor));
      }
      if examined >= limits.max_items {
        self.record_enumeration("person_proof_clearances", "cap_exhausted", 1);
        return Ok((clearances, cursor));
      }
      let remaining_results = limit.saturating_sub(clearances.len()).max(1);
      let remaining_items = limits.max_items.saturating_sub(examined).max(1);
      let page = self
        .enumeration_keys(
          prefix,
          cursor.as_ref(),
          limits
            .page_size
            .min(remaining_results)
            .min(remaining_items)
            .max(1),
          "person_proof_clearances",
        )
        .await?;
      let expirations = self
        .enumeration_expirations(&page.keys, "person_proof_clearances")
        .await?;
      for (key, expiration) in page.keys.iter().zip(expirations) {
        examined = examined.saturating_add(1);
        let Some(expires_at_unix_ms) = expiration else {
          continue;
        };
        if let Some(entry) = person_proof_clearance_from_key(key, prefix, expires_at_unix_ms) {
          clearances.push(entry);
        }
      }
      cursor = page.next_cursor;
      if cursor.is_none() {
        return Ok((clearances, None));
      }
    }
    self.record_enumeration("person_proof_clearances", "cap_exhausted", 1);
    bail!("person proof clearance enumeration reached its configured scan-round limit")
  }
}

#[cfg(feature = "admin-runtime")]
fn person_proof_status_add_key(
  status: &mut PersonProofSharedStatus,
  key: &str,
  person_proof_prefix: &str,
) {
  let reuse_prefix = format!("{person_proof_prefix}reuse:");
  let clearance_prefix = format!("{person_proof_prefix}reuse:clearance:");
  let challenge_prefix = format!("{person_proof_prefix}reuse:challenge:");
  let revoked_prefix = format!("{person_proof_prefix}revoked:clearance:");
  if let Some(hash) = key.strip_prefix(&clearance_prefix) {
    if is_sha256_hex(hash) {
      status.active_clearance_count += 1;
    } else {
      status.legacy_raw_key_count += 1;
    }
  } else if let Some(hash) = key.strip_prefix(&challenge_prefix) {
    if is_sha256_hex(hash) {
      status.challenge_replay_marker_count += 1;
    } else {
      status.legacy_raw_key_count += 1;
    }
  } else if let Some(hash) = key.strip_prefix(&revoked_prefix) {
    if is_sha256_hex(hash) {
      status.revoked_clearance_count += 1;
    }
  } else if key.starts_with(&reuse_prefix) {
    status.legacy_raw_key_count += 1;
  }
}

#[cfg(feature = "admin-runtime")]
fn encode_clearance_cursor(
  prefix: &str,
  backend: &Backend,
  position: EnumerationCursor,
) -> anyhow::Result<String> {
  let payload = PersonProofClearanceCursor {
    version: PERSON_PROOF_CLEARANCE_CURSOR_VERSION,
    scope: clearance_cursor_scope(prefix, backend),
    position,
  };
  let raw = serde_json::to_vec(&payload)?;
  Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

#[cfg(feature = "admin-runtime")]
fn decode_clearance_cursor(
  cursor: Option<&str>,
  prefix: &str,
  backend: &Backend,
) -> anyhow::Result<Option<EnumerationCursor>> {
  let Some(cursor) = cursor else {
    return Ok(None);
  };
  if cursor.len() > PERSON_PROOF_CLEARANCE_CURSOR_MAX_BYTES {
    bail!("person proof clearance cursor is invalid");
  }
  let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(cursor)
    .map_err(|_| anyhow!("person proof clearance cursor is invalid"))?;
  let decoded: PersonProofClearanceCursor = serde_json::from_slice(&raw)
    .map_err(|_| anyhow!("person proof clearance cursor is invalid"))?;
  if decoded.version != PERSON_PROOF_CLEARANCE_CURSOR_VERSION
    || decoded.scope != clearance_cursor_scope(prefix, backend)
  {
    bail!("person proof clearance cursor is invalid");
  }
  Ok(Some(decoded.position))
}

#[cfg(feature = "admin-runtime")]
fn clearance_cursor_scope(prefix: &str, backend: &Backend) -> String {
  let backend_scope = backend.enumeration_cursor_scope();
  let mut scope = Vec::with_capacity(
    prefix
      .len()
      .saturating_add(backend_scope.len())
      .saturating_add(1),
  );
  scope.extend_from_slice(prefix.as_bytes());
  scope.push(0);
  scope.extend_from_slice(backend_scope.as_bytes());
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(crate::crypto::sha256(&scope))
}

#[cfg(feature = "admin-runtime")]
fn person_proof_clearance_from_key(
  key: &str,
  prefix: &str,
  expires_at_unix_ms: Option<i64>,
) -> Option<PersonProofSharedClearance> {
  let hash = key.strip_prefix(prefix)?;
  is_sha256_hex(hash).then(|| PersonProofSharedClearance {
    clearance_hash: format!("clearance:{hash}"),
    expires_at_unix_ms,
  })
}

#[cfg(feature = "admin-runtime")]
fn is_sha256_hex(value: &str) -> bool {
  value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(all(test, feature = "admin-runtime"))]
mod tests;
