use super::*;

#[derive(Serialize, Deserialize)]
pub(super) struct RedisQueryCacheIndexMember {
  version: u8,
  epoch: u64,
  storage_variant: String,
  entry_key: String,
  lookup_index_key: String,
  chunk_key_prefix: String,
  chunk_count: usize,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RedisQueryCacheExpiryRef {
  pub(super) target_key: String,
  pub(super) member: Vec<u8>,
}

pub(super) fn encode_redis_member(member: &QueryCacheIndexMember) -> anyhow::Result<Vec<u8>> {
  let mut encoded = format!("{:016x}:", member.epoch).into_bytes();
  encoded.extend(serde_json::to_vec(&RedisQueryCacheIndexMember {
    version: member.version,
    epoch: member.epoch,
    storage_variant: member.storage_variant.clone(),
    entry_key: member.entry_key.clone(),
    lookup_index_key: member.lookup_index_key.clone(),
    chunk_key_prefix: member.chunk_key_prefix.clone(),
    chunk_count: member.chunk_count,
  })?);
  Ok(encoded)
}

pub(super) fn decode_redis_member(encoded: &[u8]) -> anyhow::Result<QueryCacheIndexMember> {
  if encoded.len() < 18 || encoded.get(16) != Some(&b':') {
    bail!("invalid Redis QUERY cache index member");
  }
  let epoch = u64::from_str_radix(std::str::from_utf8(&encoded[..16])?, 16)?;
  let redis_member: RedisQueryCacheIndexMember = serde_json::from_slice(&encoded[17..])?;
  let member = QueryCacheIndexMember {
    version: redis_member.version,
    epoch: redis_member.epoch,
    storage_variant: redis_member.storage_variant,
    entry_key: redis_member.entry_key,
    lookup_index_key: redis_member.lookup_index_key,
    chunk_key_prefix: redis_member.chunk_key_prefix,
    chunk_count: redis_member.chunk_count,
    expires_at_ms: 0,
  };
  if member.version != QUERY_CACHE_INDEX_VERSION || member.epoch != epoch {
    bail!("invalid Redis QUERY cache index member version or epoch");
  }
  Ok(member)
}

pub(super) fn encode_redis_expiry_ref(target_key: &str, member: &[u8]) -> anyhow::Result<Vec<u8>> {
  serde_json::to_vec(&RedisQueryCacheExpiryRef {
    target_key: target_key.to_string(),
    member: member.to_vec(),
  })
  .map_err(Into::into)
}

pub(super) fn decode_redis_expiry_ref(encoded: &[u8]) -> anyhow::Result<RedisQueryCacheExpiryRef> {
  serde_json::from_slice(encoded).map_err(Into::into)
}

pub(super) fn validate_redis_expiry_ref(
  expiry_key: &str,
  expiry_ref: &RedisQueryCacheExpiryRef,
) -> anyhow::Result<()> {
  validate_target_namespace(expiry_key, &expiry_ref.target_key)
}

pub(super) fn validate_target_namespace(expiry_key: &str, target_key: &str) -> anyhow::Result<()> {
  let namespace = query_cache_namespace(expiry_key)?;
  validate_target_logical_namespace(namespace, target_key)
}

pub(super) fn validate_target_logical_namespace(
  namespace: &str,
  target_key: &str,
) -> anyhow::Result<()> {
  let target_prefix = format!("{namespace}:cache:q1-target-v1:");
  if !target_key.starts_with(&target_prefix) {
    bail!("QUERY expiry reference crosses a shared-state namespace");
  }
  Ok(())
}

pub(super) fn query_cache_namespace(expiry_key: &str) -> anyhow::Result<&str> {
  expiry_key
    .strip_suffix(":cache:q1-expiry-v1")
    .context("invalid QUERY expiry-index key")
}

pub(super) fn validate_redis_member(
  target_key: &str,
  encoded: &[u8],
  member: &QueryCacheIndexMember,
) -> anyhow::Result<()> {
  if !encoded.starts_with(format!("{:016x}:", member.epoch).as_bytes()) {
    bail!("invalid Redis QUERY target-index member epoch prefix");
  }
  validate_member_keys(target_key, member)
}

pub(super) fn validate_member_keys(
  target_key: &str,
  member: &QueryCacheIndexMember,
) -> anyhow::Result<()> {
  let (namespace, digest) = target_key
    .rsplit_once(":cache:q1-target-v1:")
    .context("invalid Redis QUERY target-index key")?;
  if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("invalid Redis QUERY target-index digest");
  }
  if member.version != QUERY_CACHE_INDEX_VERSION
    || !member
      .storage_variant
      .starts_with(&format!("q1-epoch:{}:", member.epoch))
  {
    bail!("invalid Redis QUERY target-index member identity");
  }
  let expected_entry = format!("{namespace}:cache:entry:{}", member.storage_variant);
  if member.entry_key != expected_entry {
    bail!("invalid Redis QUERY target-index entry key");
  }
  let lookup_prefix = format!("{namespace}:cache:index:");
  let lookup_tail = member
    .lookup_index_key
    .strip_prefix(&lookup_prefix)
    .context("invalid Redis QUERY lookup-index key")?;
  let (lookup_digest, variant_digest) = lookup_tail
    .split_once(':')
    .context("invalid Redis QUERY lookup-index key")?;
  if lookup_digest.len() != 64
    || variant_digest.len() != 64
    || !lookup_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    || !variant_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
  {
    bail!("invalid Redis QUERY lookup-index digest");
  }
  let expected_chunk_prefix = if member.chunk_count == 0 {
    String::new()
  } else {
    format!(
      "{namespace}:cache:chunk:{}:",
      hex_encode(&crate::crypto::sha256(member.storage_variant.as_bytes()))
    )
  };
  if member.chunk_key_prefix != expected_chunk_prefix {
    bail!("invalid Redis QUERY chunk-key prefix");
  }
  Ok(())
}
