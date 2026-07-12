use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::net::tcp::OwnedReadHalf;

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn read_resp_command(reader: &mut BufReader<OwnedReadHalf>) -> std::io::Result<Vec<Vec<u8>>> {
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
      .person_proof_revoke_clearance_hash(HASH_A, expires, None)
      .await
      .expect("revocation should store tombstone")
      .removed_active
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
