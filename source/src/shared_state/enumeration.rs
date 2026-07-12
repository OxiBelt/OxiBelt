//! Bounded, namespace-scoped shared-state enumeration primitives.
//!
//! Redis `SCAN` is intentionally treated as a weakly consistent cursor. The
//! cursor retains an offset into the input scan response so a page boundary
//! cannot discard the tail of a stable scan response.

use std::collections::HashMap;

#[cfg(test)]
use anyhow::anyhow;
use anyhow::bail;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::MemoryBackend;
#[cfg(test)]
use super::purge_expired_values;
use super::{Backend, PostgresBackend, RedisBackend, Resp, now_unix_ms};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum EnumerationCursor {
  Redis { cursor: String, offset: usize },
  Keyset { key: String },
}

#[derive(Debug, Clone, Copy)]
pub(super) struct EnumerationLimits {
  pub(super) page_size: usize,
  pub(super) max_items: usize,
}

impl EnumerationLimits {
  pub(super) fn max_rounds(self) -> usize {
    self
      .max_items
      .div_ceil(self.page_size.max(1))
      .saturating_mul(2)
      .saturating_add(1)
  }
}

#[derive(Debug, Clone)]
pub(super) struct KeyPage {
  pub(super) keys: Vec<String>,
  pub(super) next_cursor: Option<EnumerationCursor>,
  scanned_keys: usize,
}

impl Backend {
  pub(super) async fn enumeration_keys(
    &self,
    prefix: &str,
    cursor: Option<&EnumerationCursor>,
    limit: usize,
    operation: &'static str,
  ) -> anyhow::Result<KeyPage> {
    let cursor = cursor.cloned();
    let page = match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute(operation, || {
            redis.enumeration_keys(prefix, cursor.as_ref(), limit)
          })
          .await
      }
      Self::Postgres(postgres) => {
        postgres
          .runtime
          .execute(operation, || {
            postgres.enumeration_keys(prefix, cursor.as_ref(), limit)
          })
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.enumeration_keys(prefix, cursor.as_ref(), limit),
    }?;
    self.record_enumeration(operation, "pages", 1);
    self.record_enumeration(operation, "scanned_keys", page.scanned_keys);
    self.record_enumeration(operation, "returned_keys", page.keys.len());
    Ok(page)
  }

  pub(super) async fn enumeration_values(
    &self,
    keys: &[String],
    operation: &'static str,
  ) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute(operation, || redis.enumeration_values(keys))
          .await
      }
      Self::Postgres(postgres) => {
        postgres
          .runtime
          .execute(operation, || postgres.enumeration_values(keys))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.enumeration_values(keys),
    }
  }

  pub(super) async fn enumeration_expirations(
    &self,
    keys: &[String],
    operation: &'static str,
  ) -> anyhow::Result<Vec<Option<Option<i64>>>> {
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute(operation, || redis.enumeration_expirations(keys))
          .await
      }
      Self::Postgres(postgres) => {
        postgres
          .runtime
          .execute(operation, || postgres.enumeration_expirations(keys))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.enumeration_expirations(keys),
    }
  }

  pub(super) async fn enumeration_delete(
    &self,
    keys: &[String],
    operation: &'static str,
  ) -> anyhow::Result<()> {
    if keys.is_empty() {
      return Ok(());
    }
    match self {
      Self::Redis(redis) => {
        redis
          .runtime
          .execute(operation, || redis.enumeration_delete(keys))
          .await
      }
      Self::Postgres(postgres) => {
        postgres
          .runtime
          .execute(operation, || postgres.enumeration_delete(keys))
          .await
      }
      #[cfg(test)]
      Self::Memory(memory) => memory.enumeration_delete(keys),
    }
  }

  pub(super) fn record_enumeration(&self, scope: &'static str, event: &'static str, count: usize) {
    match self {
      Self::Redis(redis) => redis.runtime.metrics.record_shared_state_enumeration(
        redis.runtime.name.as_ref(),
        redis.runtime.kind,
        scope,
        event,
        count,
      ),
      Self::Postgres(postgres) => postgres.runtime.metrics.record_shared_state_enumeration(
        postgres.runtime.name.as_ref(),
        postgres.runtime.kind,
        scope,
        event,
        count,
      ),
      #[cfg(test)]
      Self::Memory(_) => {}
    }
  }

  pub(super) fn enumeration_cursor_scope(&self) -> String {
    match self {
      Self::Redis(redis) => format!("{}:{}", redis.runtime.kind, redis.runtime.name),
      Self::Postgres(postgres) => format!("{}:{}", postgres.runtime.kind, postgres.runtime.name),
      #[cfg(test)]
      Self::Memory(_) => "memory".to_string(),
    }
  }
}

impl RedisBackend {
  async fn enumeration_keys(
    &self,
    prefix: &str,
    cursor: Option<&EnumerationCursor>,
    limit: usize,
  ) -> anyhow::Result<KeyPage> {
    let (scan_cursor, offset) = match cursor {
      None => ("0".to_string(), 0),
      Some(EnumerationCursor::Redis { cursor, offset }) => {
        if cursor.is_empty() || !cursor.bytes().all(|byte| byte.is_ascii_digit()) {
          bail!("Redis enumeration cursor is invalid");
        }
        (cursor.clone(), *offset)
      }
      Some(_) => bail!("Redis enumeration cursor does not match this backend"),
    };
    let response = self
      .command(&[
        b"SCAN".to_vec(),
        scan_cursor.as_bytes().to_vec(),
        b"MATCH".to_vec(),
        format!("{prefix}*").into_bytes(),
        b"COUNT".to_vec(),
        limit.max(1).to_string().into_bytes(),
      ])
      .await?;
    let Resp::Array(items) = response else {
      bail!("unexpected Redis SCAN response");
    };
    if items.len() != 2 {
      bail!("unexpected Redis SCAN item count");
    }
    let next_scan_cursor = match &items[0] {
      Resp::Bulk(Some(bytes)) => String::from_utf8(bytes.clone())?,
      Resp::Simple(value) => value.clone(),
      other => bail!("unexpected Redis SCAN cursor response: {other:?}"),
    };
    if next_scan_cursor.is_empty() || !next_scan_cursor.bytes().all(|byte| byte.is_ascii_digit()) {
      bail!("Redis SCAN returned an invalid cursor");
    }
    let scan_keys = match &items[1] {
      Resp::Array(values) => values
        .iter()
        .filter_map(|value| match value {
          Resp::Bulk(Some(bytes)) => String::from_utf8(bytes.clone()).ok(),
          Resp::Simple(value) => Some(value.clone()),
          _ => None,
        })
        .collect::<Vec<_>>(),
      other => bail!("unexpected Redis SCAN key response: {other:?}"),
    };
    let start = offset.min(scan_keys.len());
    let end = start.saturating_add(limit.max(1)).min(scan_keys.len());
    let keys = scan_keys[start..end].to_vec();
    let next_cursor = if end < scan_keys.len() {
      Some(EnumerationCursor::Redis {
        cursor: scan_cursor,
        offset: end,
      })
    } else if next_scan_cursor != "0" {
      Some(EnumerationCursor::Redis {
        cursor: next_scan_cursor,
        offset: 0,
      })
    } else {
      None
    };
    Ok(KeyPage {
      scanned_keys: scan_keys.len(),
      keys,
      next_cursor,
    })
  }

  async fn enumeration_values(&self, keys: &[String]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
    if keys.is_empty() {
      return Ok(Vec::new());
    }
    let mut command = Vec::with_capacity(keys.len().saturating_add(1));
    command.push(b"MGET".to_vec());
    command.extend(keys.iter().map(|key| key.as_bytes().to_vec()));
    let response = self.command(&command).await?;
    let Resp::Array(values) = response else {
      bail!("unexpected Redis MGET response");
    };
    if values.len() != keys.len() {
      bail!("Redis MGET response length does not match request");
    }
    values
      .into_iter()
      .map(|value| match value {
        Resp::Bulk(Some(bytes)) => Ok(Some(bytes)),
        Resp::Bulk(None) | Resp::Nil => Ok(None),
        Resp::Error(error) => bail!("Redis MGET error: {error}"),
        other => bail!("unexpected Redis MGET item: {other:?}"),
      })
      .collect()
  }

  async fn enumeration_expirations(
    &self,
    keys: &[String],
  ) -> anyhow::Result<Vec<Option<Option<i64>>>> {
    let commands = keys
      .iter()
      .map(|key| vec![b"PTTL".to_vec(), key.as_bytes().to_vec()])
      .collect::<Vec<_>>();
    self
      .pool
      .pipeline(&commands)
      .await?
      .into_iter()
      .map(|response| match response {
        Resp::Int(ttl) if ttl >= 0 => Ok(Some(Some(now_unix_ms().saturating_add(ttl)))),
        Resp::Int(-1) => Ok(Some(None)),
        Resp::Int(-2) => Ok(None),
        Resp::Error(error) => bail!("Redis PTTL error: {error}"),
        other => bail!("unexpected Redis PTTL response: {other:?}"),
      })
      .collect()
  }

  async fn enumeration_delete(&self, keys: &[String]) -> anyhow::Result<()> {
    let mut command = Vec::with_capacity(keys.len().saturating_add(1));
    command.push(b"DEL".to_vec());
    command.extend(keys.iter().map(|key| key.as_bytes().to_vec()));
    match self.command(&command).await? {
      Resp::Int(_) => Ok(()),
      Resp::Error(error) => bail!("Redis DEL error: {error}"),
      other => bail!("unexpected Redis DEL response: {other:?}"),
    }
  }
}

impl PostgresBackend {
  async fn enumeration_keys(
    &self,
    prefix: &str,
    cursor: Option<&EnumerationCursor>,
    limit: usize,
  ) -> anyhow::Result<KeyPage> {
    let last_key = match cursor {
      None => None,
      Some(EnumerationCursor::Keyset { key }) => Some(key.as_str()),
      Some(_) => bail!("PostgreSQL enumeration cursor does not match this backend"),
    };
    let pattern = sql_like_prefix(prefix);
    let now = now_unix_ms();
    let fetch_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
    let mut keys: Vec<String> = if let Some(last_key) = last_key {
      sqlx::query_scalar(
        "SELECT key FROM oxibelt_shared_state WHERE key LIKE $1 ESCAPE E'\\\\' AND key > $2 AND (expires_at_ms IS NULL OR expires_at_ms > $3) ORDER BY key LIMIT $4",
      )
      .bind(pattern)
      .bind(last_key)
      .bind(now)
      .bind(fetch_limit)
      .fetch_all(&self.pool)
      .await?
    } else {
      sqlx::query_scalar(
        "SELECT key FROM oxibelt_shared_state WHERE key LIKE $1 ESCAPE E'\\\\' AND (expires_at_ms IS NULL OR expires_at_ms > $2) ORDER BY key LIMIT $3",
      )
      .bind(pattern)
      .bind(now)
      .bind(fetch_limit)
      .fetch_all(&self.pool)
      .await?
    };
    let scanned_keys = keys.len();
    let next_cursor = if keys.len() > limit {
      keys.truncate(limit);
      keys
        .last()
        .cloned()
        .map(|key| EnumerationCursor::Keyset { key })
    } else {
      None
    };
    Ok(KeyPage {
      scanned_keys,
      keys,
      next_cursor,
    })
  }

  async fn enumeration_values(&self, keys: &[String]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
    if keys.is_empty() {
      return Ok(Vec::new());
    }
    let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
      "SELECT key, value FROM oxibelt_shared_state WHERE key = ANY($1) AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(keys)
    .bind(now_unix_ms())
    .fetch_all(&self.pool)
    .await?;
    let values = rows.into_iter().collect::<HashMap<_, _>>();
    Ok(keys.iter().map(|key| values.get(key).cloned()).collect())
  }

  async fn enumeration_expirations(
    &self,
    keys: &[String],
  ) -> anyhow::Result<Vec<Option<Option<i64>>>> {
    if keys.is_empty() {
      return Ok(Vec::new());
    }
    let rows: Vec<(String, Option<i64>)> = sqlx::query_as(
      "SELECT key, expires_at_ms FROM oxibelt_shared_state WHERE key = ANY($1) AND (expires_at_ms IS NULL OR expires_at_ms > $2)",
    )
    .bind(keys)
    .bind(now_unix_ms())
    .fetch_all(&self.pool)
    .await?;
    let expirations = rows.into_iter().collect::<HashMap<_, _>>();
    Ok(
      keys
        .iter()
        .map(|key| expirations.get(key).copied())
        .collect(),
    )
  }

  async fn enumeration_delete(&self, keys: &[String]) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM oxibelt_shared_state WHERE key = ANY($1)")
      .bind(keys)
      .execute(&self.pool)
      .await?;
    Ok(())
  }
}

#[cfg(test)]
impl MemoryBackend {
  fn enumeration_keys(
    &self,
    prefix: &str,
    cursor: Option<&EnumerationCursor>,
    limit: usize,
  ) -> anyhow::Result<KeyPage> {
    let last_key = match cursor {
      None => None,
      Some(EnumerationCursor::Keyset { key }) => Some(key),
      Some(_) => bail!("memory enumeration cursor does not match this backend"),
    };
    let mut values = self
      .values
      .lock()
      .map_err(|_| anyhow!("shared state memory values are unavailable"))?;
    purge_expired_values(&mut values, now_unix_ms());
    let mut keys = values
      .keys()
      .filter(|key| key.starts_with(prefix))
      .filter(|key| last_key.is_none_or(|last_key| key.as_str() > last_key.as_str()))
      .cloned()
      .collect::<Vec<_>>();
    keys.sort();
    let scanned_keys = keys.len();
    let next_cursor = if keys.len() > limit {
      keys.truncate(limit);
      keys
        .last()
        .cloned()
        .map(|key| EnumerationCursor::Keyset { key })
    } else {
      None
    };
    Ok(KeyPage {
      scanned_keys,
      keys,
      next_cursor,
    })
  }

  fn enumeration_values(&self, keys: &[String]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
    let mut values = self
      .values
      .lock()
      .map_err(|_| anyhow!("shared state memory values are unavailable"))?;
    purge_expired_values(&mut values, now_unix_ms());
    Ok(
      keys
        .iter()
        .map(|key| values.get(key).map(|value| value.value.clone()))
        .collect(),
    )
  }

  fn enumeration_expirations(&self, keys: &[String]) -> anyhow::Result<Vec<Option<Option<i64>>>> {
    let mut values = self
      .values
      .lock()
      .map_err(|_| anyhow!("shared state memory values are unavailable"))?;
    purge_expired_values(&mut values, now_unix_ms());
    Ok(
      keys
        .iter()
        .map(|key| values.get(key).map(|value| value.expires_at_ms))
        .collect(),
    )
  }

  fn enumeration_delete(&self, keys: &[String]) -> anyhow::Result<()> {
    let mut values = self
      .values
      .lock()
      .map_err(|_| anyhow!("shared state memory values are unavailable"))?;
    for key in keys {
      values.remove(key);
    }
    Ok(())
  }
}

fn sql_like_prefix(prefix: &str) -> String {
  let mut escaped = String::with_capacity(prefix.len().saturating_add(1));
  for character in prefix.chars() {
    if matches!(character, '%' | '_' | '\\') {
      escaped.push('\\');
    }
    escaped.push(character);
  }
  escaped.push('%');
  escaped
}

#[cfg(test)]
mod tests {
  use super::sql_like_prefix;

  #[test]
  fn sql_like_prefix_escapes_namespace_wildcards() {
    assert_eq!(sql_like_prefix("tenant_a:cache:"), "tenant\\_a:cache:%");
  }
}
