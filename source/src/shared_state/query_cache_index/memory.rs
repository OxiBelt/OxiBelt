use super::*;

#[cfg(test)]
impl MemoryBackend {
  pub(super) fn query_cache_publish(
    &self,
    target_key: &str,
    member: &QueryCacheIndexMember,
    entry_value: &[u8],
  ) -> anyhow::Result<()> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let mut indexes = self
      .query_cache_indexes
      .lock()
      .expect("memory QUERY cache index lock poisoned");
    values.insert(
      member.entry_key.clone(),
      MemoryValue {
        value: entry_value.to_vec(),
        expires_at_ms: Some(member.expires_at_ms),
      },
    );
    values.insert(
      member.lookup_index_key.clone(),
      MemoryValue {
        value: member.storage_variant.as_bytes().to_vec(),
        expires_at_ms: Some(member.expires_at_ms),
      },
    );
    indexes
      .entry(target_key.to_string())
      .or_default()
      .insert(member.storage_variant.clone(), member.clone());
    Ok(())
  }

  pub(super) fn query_cache_cleanup_before(
    &self,
    target_key: &str,
    before_epoch: u64,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    self.query_cache_cleanup_matching(limit, |key, member| {
      key == target_key && member.epoch < before_epoch
    })
  }

  pub(super) fn query_cache_cleanup_expired(
    &self,
    limit: usize,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    let now = now_unix_ms();
    self.query_cache_cleanup_matching(limit, |_, member| member.expires_at_ms <= now)
  }

  fn query_cache_cleanup_matching(
    &self,
    limit: usize,
    matches: impl Fn(&str, &QueryCacheIndexMember) -> bool,
  ) -> anyhow::Result<QueryCacheCleanupBatch> {
    let mut values = self
      .values
      .lock()
      .expect("memory shared state lock poisoned");
    let mut indexes = self
      .query_cache_indexes
      .lock()
      .expect("memory QUERY cache index lock poisoned");
    let selected = indexes
      .iter()
      .flat_map(|(target, members)| {
        members
          .values()
          .filter(|member| matches(target, member))
          .map(|member| (target.clone(), member.clone()))
      })
      .take(limit)
      .collect::<Vec<_>>();
    let mut removed = 0usize;
    for (target, member) in &selected {
      if validate_member_keys(target, member).is_err() {
        if let Some(members) = indexes.get_mut(target) {
          members.remove(&member.storage_variant);
        }
        continue;
      }
      values.remove(&member.entry_key);
      for index in 0..member.chunk_count {
        values.remove(&format!("{}{index}", member.chunk_key_prefix));
      }
      if values
        .get(&member.lookup_index_key)
        .is_some_and(|value| value.value == member.storage_variant.as_bytes())
      {
        values.remove(&member.lookup_index_key);
      }
      if let Some(members) = indexes.get_mut(target) {
        members.remove(&member.storage_variant);
      }
      removed = removed.saturating_add(1);
    }
    indexes.retain(|_, members| !members.is_empty());
    let remaining = indexes
      .iter()
      .any(|(target, members)| members.values().any(|member| matches(target, member)));
    Ok(QueryCacheCleanupBatch { removed, remaining })
  }
}
