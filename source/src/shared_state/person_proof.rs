use anyhow::{anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::enumeration::{EnumerationCursor, EnumerationLimits};
#[cfg(test)]
use super::now_unix_ms;
use super::{Backend, SharedState, ttl_from_expires_ms};

const PERSON_PROOF_REUSE_CLEARANCE_PREFIX: &str = "person-proof:reuse:clearance:";
const PERSON_PROOF_REUSE_CHALLENGE_PREFIX: &str = "person-proof:reuse:challenge:";
const PERSON_PROOF_REVOKED_CLEARANCE_PREFIX: &str = "person-proof:revoked:clearance:";
const PERSON_PROOF_CLEARANCE_CURSOR_VERSION: u8 = 1;
const PERSON_PROOF_CLEARANCE_CURSOR_MAX_BYTES: usize = 4_096;

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
    let prefix = self.key("person-proof:");
    tokio::time::timeout(
      self.operation_timeout,
      backend.person_proof_status(&prefix, self.enumeration),
    )
    .await
    .map_err(|_| anyhow!("person proof shared status enumeration timed out"))?
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
    let prefix = self.key(PERSON_PROOF_REUSE_CLEARANCE_PREFIX);
    let position = decode_clearance_cursor(cursor, &prefix, backend)?;
    let (clearances, next_cursor) = tokio::time::timeout(
      self.operation_timeout,
      backend.person_proof_clearances(&prefix, limit, position, self.enumeration),
    )
    .await
    .map_err(|_| anyhow!("person proof clearance enumeration timed out"))??;
    Ok(PersonProofSharedClearancePage {
      clearances,
      next_cursor: next_cursor
        .map(|position| encode_clearance_cursor(&prefix, backend, position))
        .transpose()?,
    })
  }
}

impl Backend {
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
  use std::io::{Error, ErrorKind};
  use std::sync::Arc;
  use std::time::Duration;

  use super::*;
  use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
  use tokio::net::TcpListener;
  use tokio::net::tcp::OwnedReadHalf;

  const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  async fn read_resp_command(
    reader: &mut BufReader<OwnedReadHalf>,
  ) -> std::io::Result<Vec<Vec<u8>>> {
    let mut header = String::new();
    reader.read_line(&mut header).await?;
    let count = header
      .strip_prefix('*')
      .and_then(|line| line.trim_end().parse::<usize>().ok())
      .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid RESP array header"))?;
    let mut command = Vec::with_capacity(count);
    for _ in 0..count {
      let mut length = String::new();
      reader.read_line(&mut length).await?;
      let length = length
        .strip_prefix('$')
        .and_then(|line| line.trim_end().parse::<usize>().ok())
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid RESP bulk header"))?;
      let mut value = vec![0; length + 2];
      reader.read_exact(&mut value).await?;
      if value[length..] != *b"\r\n" {
        return Err(Error::new(
          ErrorKind::InvalidData,
          "invalid RESP bulk terminator",
        ));
      }
      value.truncate(length);
      command.push(value);
    }
    Ok(command)
  }

  fn scan_response(keys: &[String]) -> Vec<u8> {
    let mut response = format!("*2\r\n$1\r\n0\r\n*{}\r\n", keys.len()).into_bytes();
    for key in keys {
      response.extend_from_slice(format!("${}\r\n", key.len()).as_bytes());
      response.extend_from_slice(key.as_bytes());
      response.extend_from_slice(b"\r\n");
    }
    response
  }

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

  #[tokio::test]
  async fn person_proof_clearance_cursor_is_opaque_scoped_and_complete() {
    let state = SharedState::test_memory("cursor-a");
    let expires = now_unix_ms() + 60_000;
    for hash in [HASH_A, HASH_B] {
      assert!(
        state
          .person_proof_remember(&format!("clearance:{hash}"), expires)
          .await
          .expect("hash clearance should store")
      );
    }

    let first = state
      .person_proof_list_clearances(1, None)
      .await
      .expect("first clearance page should load");
    assert_eq!(first.clearances.len(), 1);
    assert_eq!(
      first.clearances[0].clearance_hash,
      format!("clearance:{HASH_A}")
    );
    let cursor = first.next_cursor.expect("first page should continue");
    assert_ne!(
      cursor, "1",
      "shared cursors must not expose numeric offsets"
    );

    let second = state
      .person_proof_list_clearances(1, Some(&cursor))
      .await
      .expect("second clearance page should load");
    assert_eq!(second.clearances.len(), 1);
    assert_eq!(
      second.clearances[0].clearance_hash,
      format!("clearance:{HASH_B}")
    );
    assert!(second.next_cursor.is_none());

    let other_scope = SharedState::test_memory("cursor-b");
    assert!(
      other_scope
        .person_proof_list_clearances(1, Some(&cursor))
        .await
        .expect_err("a cursor from another namespace must be rejected")
        .to_string()
        .contains("cursor is invalid")
    );
    assert!(
      state
        .person_proof_list_clearances(1, Some("not-a-cursor"))
        .await
        .expect_err("a malformed cursor must be rejected")
        .to_string()
        .contains("cursor is invalid")
    );
  }

  #[tokio::test]
  async fn redis_clearance_pages_replay_scan_tails_and_pipeline_ttls() {
    let listener = match TcpListener::bind("127.0.0.1:0").await {
      Ok(listener) => listener,
      Err(error) if error.kind() == ErrorKind::PermissionDenied => return,
      Err(error) => panic!("test listener should bind: {error}"),
    };
    let address = listener
      .local_addr()
      .expect("test listener should have an address");
    let namespace = "redis-clearance-pages";
    let prefix = format!("{namespace}:{PERSON_PROOF_REUSE_CLEARANCE_PREFIX}");
    let keys = vec![format!("{prefix}{HASH_A}"), format!("{prefix}{HASH_B}")];
    let expected_match = format!("{prefix}*").into_bytes();
    let server = tokio::spawn(async move {
      let (stream, _) = listener.accept().await.expect("client should connect");
      let (reader, mut writer) = stream.into_split();
      let mut reader = BufReader::new(reader);

      for expected_count in [b"1".as_slice(), b"1".as_slice()] {
        assert_eq!(
          read_resp_command(&mut reader)
            .await
            .expect("SCAN should use RESP framing"),
          vec![
            b"SCAN".to_vec(),
            b"0".to_vec(),
            b"MATCH".to_vec(),
            expected_match.clone(),
            b"COUNT".to_vec(),
            expected_count.to_vec(),
          ]
        );
        writer
          .write_all(&scan_response(&keys))
          .await
          .expect("SCAN response should write");
        let pttl = read_resp_command(&mut reader)
          .await
          .expect("PTTL should use RESP framing");
        assert_eq!(pttl[0], b"PTTL");
        writer
          .write_all(b":60000\r\n")
          .await
          .expect("PTTL response should write");
      }

      assert_eq!(
        read_resp_command(&mut reader)
          .await
          .expect("third SCAN should use RESP framing"),
        vec![
          b"SCAN".to_vec(),
          b"0".to_vec(),
          b"MATCH".to_vec(),
          expected_match,
          b"COUNT".to_vec(),
          b"2".to_vec(),
        ]
      );
      writer
        .write_all(&scan_response(&keys))
        .await
        .expect("third SCAN response should write");
      assert_eq!(
        read_resp_command(&mut reader)
          .await
          .expect("first pipelined PTTL should use RESP framing"),
        vec![b"PTTL".to_vec(), keys[0].as_bytes().to_vec()]
      );
      assert_eq!(
        read_resp_command(&mut reader)
          .await
          .expect("second pipelined PTTL should use RESP framing"),
        vec![b"PTTL".to_vec(), keys[1].as_bytes().to_vec()]
      );
      writer
        .write_all(b":60000\r\n:60000\r\n")
        .await
        .expect("pipelined PTTL responses should write");
    });

    let state = SharedState::test_redis_with_features(
      namespace,
      &format!("redis://{address}"),
      crate::metrics::Metrics::new(),
      true,
      false,
    );
    let first = state
      .person_proof_list_clearances(1, None)
      .await
      .expect("first Redis clearance page should load");
    assert_eq!(
      first.clearances[0].clearance_hash,
      format!("clearance:{HASH_A}")
    );
    let cursor = first.next_cursor.expect("first Redis page should continue");
    let second = state
      .person_proof_list_clearances(1, Some(&cursor))
      .await
      .expect("second Redis clearance page should load");
    assert_eq!(
      second.clearances[0].clearance_hash,
      format!("clearance:{HASH_B}")
    );
    assert!(second.next_cursor.is_none());

    let full_page = state
      .person_proof_list_clearances(2, None)
      .await
      .expect("Redis clearance page should pipeline TTL reads");
    assert_eq!(full_page.clearances.len(), 2);
    tokio::time::timeout(Duration::from_secs(1), server)
      .await
      .expect("Redis fixture should finish")
      .expect("Redis fixture should not panic");
  }

  #[tokio::test]
  async fn person_proof_status_fails_instead_of_returning_partial_counts_at_the_cap() {
    let mut state = SharedState::test_memory("status-cap");
    Arc::get_mut(&mut state)
      .expect("test state should have one owner")
      .enumeration = EnumerationLimits {
      page_size: 1,
      max_items: 1,
    };
    let expires = now_unix_ms() + 60_000;
    for hash in [HASH_A, HASH_B] {
      assert!(
        state
          .person_proof_remember(&format!("clearance:{hash}"), expires)
          .await
          .expect("hash clearance should store")
      );
    }

    assert!(
      state
        .person_proof_admin_status()
        .await
        .expect_err("status must not report partial counts at the configured cap")
        .to_string()
        .contains("configured item limit")
    );
  }
}
