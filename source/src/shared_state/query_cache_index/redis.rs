use super::*;

impl RedisBackend {
  pub(super) async fn query_cache_publish(
    &self,
    target_key: &str,
    expiry_key: &str,
    member: &QueryCacheIndexMember,
    entry_value: &[u8],
    ttl: Option<Duration>,
  ) -> anyhow::Result<()> {
    let encoded_member = encode_redis_member(member)?;
    validate_redis_member(target_key, &encoded_member, member)?;
    let expiry_ref = encode_redis_expiry_ref(target_key, &encoded_member)?;
    let ttl_ms = ttl
      .map(atomic_updates::ttl_millis)
      .unwrap_or_default()
      .to_string();
    let script = r#"
      local ttl = tonumber(ARGV[1])
      if ttl > 0 then
        redis.call('PSETEX', KEYS[1], ttl, ARGV[2])
        redis.call('PSETEX', KEYS[2], ttl, ARGV[3])
      else
        redis.call('SET', KEYS[1], ARGV[2])
        redis.call('SET', KEYS[2], ARGV[3])
      end
      redis.call('ZADD', KEYS[3], 0, ARGV[4])
      redis.call('ZADD', KEYS[4], ARGV[5], ARGV[6])
      if ttl > 0 then
        local current = redis.call('PTTL', KEYS[3])
        if current < ttl then redis.call('PEXPIRE', KEYS[3], ttl) end
      end
      return 1
    "#;
    let response = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"4".to_vec(),
        member.entry_key.as_bytes().to_vec(),
        member.lookup_index_key.as_bytes().to_vec(),
        target_key.as_bytes().to_vec(),
        expiry_key.as_bytes().to_vec(),
        ttl_ms.into_bytes(),
        entry_value.to_vec(),
        member.storage_variant.as_bytes().to_vec(),
        encoded_member,
        member.expires_at_ms.to_string().into_bytes(),
        expiry_ref,
      ])
      .await?;
    if response.into_i64()? != 1 {
      bail!("Redis QUERY cache publish script did not commit");
    }
    Ok(())
  }

  pub(super) async fn query_cache_cleanup_before(
    &self,
    target_key: &str,
    expiry_key: &str,
    before_epoch: u64,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    let maximum = format!("({before_epoch:016x}:");
    let response = self
      .command(&[
        b"ZRANGEBYLEX".to_vec(),
        target_key.as_bytes().to_vec(),
        b"-".to_vec(),
        maximum.into_bytes(),
        b"LIMIT".to_vec(),
        b"0".to_vec(),
        limit.to_string().into_bytes(),
      ])
      .await?;
    let Resp::Array(items) = response else {
      bail!("unexpected Redis QUERY target-index response");
    };
    let mut removed = 0usize;
    for item in items {
      let encoded = match item {
        Resp::Bulk(Some(encoded)) => encoded,
        other => bail!("unexpected Redis QUERY target-index member: {other:?}"),
      };
      let member = match decode_redis_member(&encoded) {
        Ok(member)
          if member.epoch < before_epoch
            && validate_redis_member(target_key, &encoded, &member).is_ok() =>
        {
          member
        }
        _ => {
          self
            .query_cache_remove_member(target_key, expiry_key, &encoded)
            .await?;
          continue;
        }
      };
      self.query_cache_delete_chunks(&member).await?;
      self
        .query_cache_finalize_delete(target_key, expiry_key, &encoded, &member)
        .await?;
      removed = removed.saturating_add(1);
    }
    let remaining = self
      .command(&[
        b"ZRANGEBYLEX".to_vec(),
        target_key.as_bytes().to_vec(),
        b"-".to_vec(),
        format!("({before_epoch:016x}:").into_bytes(),
        b"LIMIT".to_vec(),
        b"0".to_vec(),
        b"1".to_vec(),
      ])
      .await?;
    let remaining = matches!(remaining, Resp::Array(ref items) if !items.is_empty());
    Ok(QueryCacheCleanupBatch { removed, remaining })
  }

  pub(super) async fn query_cache_cleanup_expired(
    &self,
    expiry_key: &str,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    let cutoff = now_unix_ms();
    let response = self
      .command(&[
        b"ZRANGEBYSCORE".to_vec(),
        expiry_key.as_bytes().to_vec(),
        b"-inf".to_vec(),
        cutoff.to_string().into_bytes(),
        b"LIMIT".to_vec(),
        b"0".to_vec(),
        limit.to_string().into_bytes(),
      ])
      .await?;
    let Resp::Array(items) = response else {
      bail!("unexpected Redis QUERY expiry-index response");
    };
    let mut removed = 0usize;
    for item in items {
      let encoded_ref = match item {
        Resp::Bulk(Some(encoded)) => encoded,
        other => bail!("unexpected Redis QUERY expiry-index member: {other:?}"),
      };
      let expiry_ref = match decode_redis_expiry_ref(&encoded_ref) {
        Ok(expiry_ref) if validate_redis_expiry_ref(expiry_key, &expiry_ref).is_ok() => expiry_ref,
        _ => {
          self
            .query_cache_remove_expiry_ref(expiry_key, &encoded_ref)
            .await?;
          continue;
        }
      };
      let valid_member = decode_redis_member(&expiry_ref.member).is_ok_and(|member| {
        validate_redis_member(&expiry_ref.target_key, &expiry_ref.member, &member).is_ok()
      });
      if !valid_member {
        self
          .query_cache_remove_expiry_ref(expiry_key, &encoded_ref)
          .await?;
        continue;
      }
      if self
        .query_cache_finalize_expiry(
          &expiry_ref.target_key,
          expiry_key,
          &expiry_ref.member,
          &encoded_ref,
          cutoff,
        )
        .await?
      {
        removed = removed.saturating_add(1);
      }
    }
    let remaining = self
      .command(&[
        b"ZRANGEBYSCORE".to_vec(),
        expiry_key.as_bytes().to_vec(),
        b"-inf".to_vec(),
        cutoff.to_string().into_bytes(),
        b"LIMIT".to_vec(),
        b"0".to_vec(),
        b"1".to_vec(),
      ])
      .await?;
    let remaining = matches!(remaining, Resp::Array(ref items) if !items.is_empty());
    Ok(QueryCacheCleanupBatch { removed, remaining })
  }

  async fn query_cache_delete_chunks(&self, member: &QueryCacheIndexMember) -> anyhow::Result<()> {
    if member.chunk_count == 0 {
      return Ok(());
    }
    for start in (0..member.chunk_count).step_by(REDIS_CHUNK_DELETE_BATCH) {
      let end = start
        .saturating_add(REDIS_CHUNK_DELETE_BATCH)
        .min(member.chunk_count);
      let mut command = Vec::with_capacity(end.saturating_sub(start).saturating_add(1));
      command.push(b"DEL".to_vec());
      command.extend(
        (start..end).map(|index| format!("{}{index}", member.chunk_key_prefix).into_bytes()),
      );
      let _ = self.command(&command).await?;
    }
    Ok(())
  }

  async fn query_cache_finalize_delete(
    &self,
    target_key: &str,
    expiry_key: &str,
    encoded_member: &[u8],
    member: &QueryCacheIndexMember,
  ) -> anyhow::Result<()> {
    let script = r#"
      redis.call('DEL', KEYS[1])
      if redis.call('GET', KEYS[2]) == ARGV[1] then redis.call('DEL', KEYS[2]) end
      redis.call('ZREM', KEYS[3], ARGV[2])
      redis.call('ZREM', KEYS[4], ARGV[3])
      if redis.call('ZCARD', KEYS[3]) == 0 then redis.call('DEL', KEYS[3]) end
      return 1
    "#;
    let response = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"4".to_vec(),
        member.entry_key.as_bytes().to_vec(),
        member.lookup_index_key.as_bytes().to_vec(),
        target_key.as_bytes().to_vec(),
        expiry_key.as_bytes().to_vec(),
        member.storage_variant.as_bytes().to_vec(),
        encoded_member.to_vec(),
        encode_redis_expiry_ref(target_key, encoded_member)?,
      ])
      .await?;
    let _ = response.into_i64()?;
    Ok(())
  }

  async fn query_cache_finalize_expiry(
    &self,
    target_key: &str,
    expiry_key: &str,
    encoded_member: &[u8],
    encoded_ref: &[u8],
    cutoff: i64,
  ) -> anyhow::Result<bool> {
    // Redis expires the entry, lookup pointer, and chunks independently. This
    // script only prunes index membership, and first rechecks the score so a
    // concurrent TTL extension cannot lose live membership.
    let script = r#"
      local score = redis.call('ZSCORE', KEYS[2], ARGV[2])
      if score and tonumber(score) <= tonumber(ARGV[3]) then
        redis.call('ZREM', KEYS[1], ARGV[1])
        redis.call('ZREM', KEYS[2], ARGV[2])
        if redis.call('ZCARD', KEYS[1]) == 0 then redis.call('DEL', KEYS[1]) end
        return 1
      end
      return 0
    "#;
    Ok(
      self
        .command(&[
          b"EVAL".to_vec(),
          script.as_bytes().to_vec(),
          b"2".to_vec(),
          target_key.as_bytes().to_vec(),
          expiry_key.as_bytes().to_vec(),
          encoded_member.to_vec(),
          encoded_ref.to_vec(),
          cutoff.to_string().into_bytes(),
        ])
        .await?
        .into_i64()?
        == 1,
    )
  }

  async fn query_cache_remove_member(
    &self,
    target_key: &str,
    expiry_key: &str,
    encoded_member: &[u8],
  ) -> anyhow::Result<()> {
    let script =
      "redis.call('ZREM', KEYS[1], ARGV[1]); redis.call('ZREM', KEYS[2], ARGV[2]); return 1";
    let _ = self
      .command(&[
        b"EVAL".to_vec(),
        script.as_bytes().to_vec(),
        b"2".to_vec(),
        target_key.as_bytes().to_vec(),
        expiry_key.as_bytes().to_vec(),
        encoded_member.to_vec(),
        encode_redis_expiry_ref(target_key, encoded_member)?,
      ])
      .await?;
    Ok(())
  }

  async fn query_cache_remove_expiry_ref(
    &self,
    expiry_key: &str,
    encoded_ref: &[u8],
  ) -> anyhow::Result<()> {
    let _ = self
      .command(&[
        b"ZREM".to_vec(),
        expiry_key.as_bytes().to_vec(),
        encoded_ref.to_vec(),
      ])
      .await?;
    Ok(())
  }
}
