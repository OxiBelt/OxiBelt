use anyhow::{Context, anyhow};
use serde::Serialize;

#[cfg(test)]
use super::MemoryBackend;
#[cfg(test)]
use super::purge_expired_values;
use super::{Backend, PostgresBackend, RedisBackend, SharedState};
use super::{now_unix_ms, ttl_from_expires_ms};

const PERSON_PROOF_REUSE_CLEARANCE_PREFIX: &str = "person-proof:reuse:clearance:";
const PERSON_PROOF_REUSE_CHALLENGE_PREFIX: &str = "person-proof:reuse:challenge:";
const PERSON_PROOF_REVOKED_CLEARANCE_PREFIX: &str = "person-proof:revoked:clearance:";
const PERSON_PROOF_ADMIN_SCAN_COUNT: usize = 128;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PersonProofSharedStatus {
  pub active_clearance_count: usize,
  pub challenge_replay_marker_count: usize,
  pub revoked_clearance_count: usize,
  pub legacy_raw_key_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonProofSharedClearance {
  pub clearance_hash: String,
  pub expires_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonProofSharedClearancePage {
  pub clearances: Vec<PersonProofSharedClearance>,
  pub next_cursor: Option<String>,
}

impl SharedState {
  pub async fn person_proof_secret(&self) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(backend) = &self.person_proof else {
      return Ok(None);
    };
    let key = self.key("person-proof:secret:v1");
    let secret = backend.get_or_init_bytes(&key, 32, None).await?;
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
    backend
      .put_if_absent(&self.key(&format!("person-proof:reuse:{key}")), b"1", ttl)
      .await
  }

  pub async fn person_proof_consume(&self, key: &str) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(false);
    };
    backend
      .take_key(&self.key(&format!("person-proof:reuse:{key}")))
      .await
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
    if backend.get(&legacy_key).await?.is_some() {
      return Ok(false);
    }
    let ttl = ttl_from_expires_ms(expires_at_ms);
    backend
      .put_if_absent(
        &self.key(&format!("{PERSON_PROOF_REUSE_CHALLENGE_PREFIX}{hash}")),
        b"1",
        ttl,
      )
      .await
  }

  pub async fn person_proof_consume_clearance(
    &self,
    token: &str,
    hash: &str,
  ) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(false);
    };
    let key = self.key(&format!("{PERSON_PROOF_REUSE_CLEARANCE_PREFIX}{hash}"));
    if backend.take_key(&key).await? {
      return Ok(true);
    }
    let legacy_key = self.key(&format!("{PERSON_PROOF_REUSE_CLEARANCE_PREFIX}{token}"));
    backend.take_key(&legacy_key).await
  }

  pub async fn person_proof_clearance_revoked(&self, hash: &str) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(false);
    };
    backend
      .get(&self.key(&format!("{PERSON_PROOF_REVOKED_CLEARANCE_PREFIX}{hash}")))
      .await
      .map(|value| value.is_some())
  }

  pub async fn person_proof_revoke_clearance_hash(
    &self,
    hash: &str,
    expires_at_ms: i64,
  ) -> anyhow::Result<bool> {
    let Some(backend) = &self.person_proof else {
      return Ok(false);
    };
    let ttl = ttl_from_expires_ms(expires_at_ms);
    backend
      .put(
        &self.key(&format!("{PERSON_PROOF_REVOKED_CLEARANCE_PREFIX}{hash}")),
        b"1",
        ttl,
      )
      .await?;
    backend
      .take_key(&self.key(&format!("{PERSON_PROOF_REUSE_CLEARANCE_PREFIX}{hash}")))
      .await
  }

  pub async fn person_proof_admin_status(&self) -> anyhow::Result<PersonProofSharedStatus> {
    let Some(backend) = &self.person_proof else {
      return Ok(PersonProofSharedStatus::default());
    };
    backend
      .person_proof_status(&self.key("person-proof:"))
      .await
  }

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
    backend
      .person_proof_clearances(
        &self.key(PERSON_PROOF_REUSE_CLEARANCE_PREFIX),
        limit,
        cursor,
      )
      .await
  }
}

impl Backend {
  async fn person_proof_status(&self, prefix: &str) -> anyhow::Result<PersonProofSharedStatus> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("person_proof", || redis.person_proof_status(prefix))
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("person_proof", || pg.person_proof_status(prefix))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.person_proof_status(prefix),
    }
  }

  async fn person_proof_clearances(
    &self,
    prefix: &str,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofSharedClearancePage> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute("person_proof", || {
            redis.person_proof_clearances(prefix, limit, cursor)
          })
          .await
      }
      Self::Postgres(pg) => {
        pg.runtime
          .execute("person_proof", || {
            pg.person_proof_clearances(prefix, limit, cursor)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.person_proof_clearances(prefix, limit, cursor),
    }
  }
}

#[cfg(test)]
impl MemoryBackend {
  fn person_proof_status(&self, prefix: &str) -> anyhow::Result<PersonProofSharedStatus> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    Ok(person_proof_status_from_keys(
      values.keys().filter(|key| key.starts_with(prefix)),
      prefix,
    ))
  }

  fn person_proof_clearances(
    &self,
    prefix: &str,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofSharedClearancePage> {
    let offset = parse_person_proof_cursor(cursor)?;
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let now = now_unix_ms();
    purge_expired_values(&mut values, now);
    let mut entries = values
      .iter()
      .filter_map(|(key, value)| person_proof_clearance_from_key(key, prefix, value.expires_at_ms))
      .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.clearance_hash.cmp(&right.clearance_hash));
    let page = entries
      .into_iter()
      .skip(offset)
      .take(limit.saturating_add(1))
      .collect::<Vec<_>>();
    let next_cursor = (page.len() > limit).then(|| (offset + limit).to_string());
    Ok(PersonProofSharedClearancePage {
      clearances: page.into_iter().take(limit).collect(),
      next_cursor,
    })
  }
}

impl RedisBackend {
  async fn person_proof_status(&self, prefix: &str) -> anyhow::Result<PersonProofSharedStatus> {
    let mut cursor = "0".to_string();
    let mut keys = Vec::new();
    loop {
      let (batch, next_cursor) = self
        .scan_keys(
          &format!("{prefix}*"),
          &cursor,
          PERSON_PROOF_ADMIN_SCAN_COUNT,
        )
        .await?;
      keys.extend(batch);
      let Some(next_cursor) = next_cursor else {
        break;
      };
      cursor = next_cursor;
    }
    Ok(person_proof_status_from_keys(keys.iter(), prefix))
  }

  async fn person_proof_clearances(
    &self,
    prefix: &str,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofSharedClearancePage> {
    let mut cursor = cursor.unwrap_or("0").to_string();
    let mut entries = Vec::new();
    let next_cursor = loop {
      let (keys, next_cursor) = self
        .scan_keys(
          &format!("{prefix}*"),
          &cursor,
          PERSON_PROOF_ADMIN_SCAN_COUNT,
        )
        .await?;
      for key in keys {
        let expires_at_ms = self.expires_at_ms(&key).await?;
        if expires_at_ms == Some(0) {
          continue;
        }
        if let Some(entry) = person_proof_clearance_from_key(&key, prefix, expires_at_ms) {
          entries.push(entry);
        }
        if entries.len() >= limit {
          break;
        }
      }
      if entries.len() >= limit || next_cursor.is_none() {
        break next_cursor;
      }
      cursor = next_cursor.expect("checked above");
    };
    Ok(PersonProofSharedClearancePage {
      clearances: entries,
      next_cursor,
    })
  }
}

impl PostgresBackend {
  async fn person_proof_status(&self, prefix: &str) -> anyhow::Result<PersonProofSharedStatus> {
    let pattern = format!("{prefix}%");
    let keys: Vec<String> = sqlx::query_scalar(
      "SELECT key FROM oxibelt_shared_state WHERE key LIKE $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(pattern)
    .bind(now_unix_ms())
    .fetch_all(&self.pool)
    .await?;
    Ok(person_proof_status_from_keys(keys.iter(), prefix))
  }

  async fn person_proof_clearances(
    &self,
    prefix: &str,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofSharedClearancePage> {
    let offset = parse_person_proof_cursor(cursor)?;
    let pattern = format!("{prefix}%");
    let fetch_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
    let offset = i64::try_from(offset).unwrap_or(i64::MAX);
    let rows: Vec<(String, Option<i64>)> = sqlx::query_as(
      "SELECT key, expires_at_ms FROM oxibelt_shared_state WHERE key LIKE $1 AND (expires_at_ms IS NULL OR expires_at_ms > $2) ORDER BY key LIMIT $3 OFFSET $4",
    )
    .bind(pattern)
    .bind(now_unix_ms())
    .bind(fetch_limit)
    .bind(offset)
    .fetch_all(&self.pool)
    .await?;
    let mut entries = rows
      .into_iter()
      .filter_map(|(key, expires_at_ms)| {
        person_proof_clearance_from_key(&key, prefix, expires_at_ms)
      })
      .collect::<Vec<_>>();
    let next_cursor = (entries.len() > limit).then(|| {
      offset
        .saturating_add(i64::try_from(limit).unwrap_or(i64::MAX))
        .to_string()
    });
    entries.truncate(limit);
    Ok(PersonProofSharedClearancePage {
      clearances: entries,
      next_cursor,
    })
  }
}

fn parse_person_proof_cursor(cursor: Option<&str>) -> anyhow::Result<usize> {
  let Some(cursor) = cursor else {
    return Ok(0);
  };
  cursor
    .parse::<usize>()
    .context("person proof cursor must be an unsigned offset")
}

fn person_proof_status_from_keys<'a>(
  keys: impl Iterator<Item = &'a String>,
  person_proof_prefix: &str,
) -> PersonProofSharedStatus {
  let reuse_prefix = format!("{person_proof_prefix}reuse:");
  let clearance_prefix = format!("{person_proof_prefix}reuse:clearance:");
  let challenge_prefix = format!("{person_proof_prefix}reuse:challenge:");
  let revoked_prefix = format!("{person_proof_prefix}revoked:clearance:");
  let mut status = PersonProofSharedStatus::default();
  for key in keys {
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
  status
}

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

fn is_sha256_hex(value: &str) -> bool {
  value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
  use super::*;

  const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  #[tokio::test]
  async fn person_proof_admin_projection_lists_only_hash_keyed_clearances() {
    let state = SharedState::test_memory("test");
    let expires = now_unix_ms() + 60_000;
    assert!(
      state
        .person_proof_remember(&format!("clearance:{HASH_A}"), expires)
        .await
        .expect("hash clearance should store")
    );
    assert!(
      state
        .person_proof_mark_challenge_used("session.v1.raw", HASH_B, expires)
        .await
        .expect("hash challenge should store")
    );
    assert!(
      state
        .person_proof_remember("clearance:clearance.v2.raw", expires)
        .await
        .expect("legacy clearance should store")
    );

    let status = state
      .person_proof_admin_status()
      .await
      .expect("status should load");
    assert_eq!(status.active_clearance_count, 1);
    assert_eq!(status.challenge_replay_marker_count, 1);
    assert_eq!(status.legacy_raw_key_count, 1);

    let page = state
      .person_proof_list_clearances(10, None)
      .await
      .expect("clearance list should load");
    assert_eq!(page.clearances.len(), 1);
    assert_eq!(
      page.clearances[0].clearance_hash,
      format!("clearance:{HASH_A}")
    );
  }

  #[tokio::test]
  async fn person_proof_revocation_tombstone_blocks_and_removes_hash_key() {
    let state = SharedState::test_memory("test");
    let expires = now_unix_ms() + 60_000;
    assert!(
      state
        .person_proof_remember(&format!("clearance:{HASH_A}"), expires)
        .await
        .expect("hash clearance should store")
    );
    assert!(
      state
        .person_proof_revoke_clearance_hash(HASH_A, expires)
        .await
        .expect("revocation should store tombstone")
    );
    assert!(
      state
        .person_proof_clearance_revoked(HASH_A)
        .await
        .expect("revocation should be readable")
    );
    let status = state
      .person_proof_admin_status()
      .await
      .expect("status should load");
    assert_eq!(status.active_clearance_count, 0);
    assert_eq!(status.revoked_clearance_count, 1);
  }

  #[tokio::test]
  async fn person_proof_consume_clearance_honors_legacy_raw_key() {
    let state = SharedState::test_memory("test");
    let expires = now_unix_ms() + 60_000;
    assert!(
      state
        .person_proof_remember("clearance:clearance.v2.raw", expires)
        .await
        .expect("legacy clearance should store")
    );
    assert!(
      state
        .person_proof_consume_clearance("clearance.v2.raw", HASH_A)
        .await
        .expect("legacy clearance should consume")
    );
    assert!(
      !state
        .person_proof_consume_clearance("clearance.v2.raw", HASH_A)
        .await
        .expect("legacy clearance should be gone")
    );
  }
}
