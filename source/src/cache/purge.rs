//! Purge, invalidation, bounded statistics, and key explanation.

use super::*;

impl ResponseCache {
  /// Invalidates only Q1 variants of one target after a successful unsafe or
  /// unknown-method origin response.  Administrative purges deliberately stay
  /// broad; this internal path must not alter GET/HEAD entries.
  pub async fn invalidate_query_target_async(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> anyhow::Result<usize> {
    let target = CacheQueryInvalidationTarget::new(policy, scheme, host, uri, partition);
    let shared_epoch = match self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    {
      Some(shared) => match shared
        .cache_advance_query_epoch(policy, scheme, host, uri)
        .await
      {
        Ok(epoch) => Some(epoch),
        Err(error) => {
          let local_epoch = self.advance_query_generation(&target);
          self.fills.fence_query_target(&target);
          self
            .query_cleanup
            .enqueue(target.clone(), local_epoch, false, false);
          self.mark_query_invalidation_failed(target);
          return Err(
            error.context("QUERY cache invalidation could not advance the shared target epoch"),
          );
        }
      },
      None => None,
    };
    let external_epoch = if shared_epoch.is_none()
      && self
        .policy(Some(policy))
        .is_some_and(|item| item.external_handler.is_some())
    {
      match self.external_query_epoch(&target, true).await {
        Some(epoch) => Some(epoch),
        None => {
          self.mark_query_invalidation_failed(target);
          anyhow::bail!("QUERY cache invalidation could not advance the external target epoch");
        }
      }
    } else {
      None
    };
    let effective_epoch =
      self.advance_query_generation_to(&target, shared_epoch.or(external_epoch));
    self.fills.fence_query_target(&target);
    let shared_pending = self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
      .is_some();
    let external_pending = self
      .policy(Some(policy))
      .is_some_and(|item| item.external_handler.is_some());
    self
      .query_cleanup
      .enqueue(target, effective_epoch, shared_pending, external_pending);
    Ok(0)
  }

  /// Invalidates QUERY variants for every configured policy at a target. This
  /// is used for unsafe/unknown origin responses, whose route does not need to
  /// select the same cache policy as earlier QUERY requests.
  pub async fn invalidate_query_target_async_all_policies(
    &self,
    scheme: &str,
    host: &str,
    uri: &str,
  ) -> anyhow::Result<usize> {
    let query_method =
      Method::from_bytes(b"QUERY").map_err(|_| anyhow::anyhow!("invalid QUERY method"))?;
    let policies = self
      .policies
      .keys()
      .filter(|policy| self.policy_enabled(Some(policy), &query_method))
      .cloned()
      .collect::<Vec<_>>();
    let mut count = 0usize;
    let mut failed = false;
    for policy in policies {
      match self
        .invalidate_query_target_async(&policy, scheme, host, uri, None)
        .await
      {
        Ok(purged) => count = count.saturating_add(purged),
        Err(_) => failed = true,
      }
    }
    if failed {
      anyhow::bail!("QUERY cache invalidation did not reach every configured cache backend");
    }
    Ok(count)
  }

  #[cfg(test)]
  pub(crate) fn invalidate_query_target(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> usize {
    let target = CacheQueryInvalidationTarget::new(policy, scheme, host, uri, partition);
    let before_epoch = self.advance_query_generation(&target);
    self.fills.fence_query_target(&target);
    self.invalidate_query_target_inner(&target, before_epoch)
  }

  #[cfg(test)]
  fn invalidate_query_target_inner(
    &self,
    target: &CacheQueryInvalidationTarget,
    before_epoch: u64,
  ) -> usize {
    let mut count = 0usize;
    loop {
      let (removed, more) = self.cleanup_local_query_target_batch(target, before_epoch, 128);
      count = count.saturating_add(removed);
      if !more {
        return count;
      }
    }
  }

  pub fn purge_exact(&self, policy: &str, scheme: &str, host: &str, uri: &str) -> usize {
    self.purge_exact_partition(policy, scheme, host, uri, None)
  }

  pub fn purge_exact_partition(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> usize {
    let mut inner = self.inner_guard();
    let keys = inner
      .entries
      .iter()
      .filter(|(_, entry)| {
        entry.policy == policy
          && entry.scheme == scheme
          && entry.host == host
          && entry.uri == uri
          && partition.is_none_or(|partition| entry.partition == partition)
      })
      .map(|(key, _)| key.clone())
      .collect::<Vec<_>>();
    let count = keys.len();
    for key in keys {
      remove_entry(&mut inner, &key);
    }
    count
  }

  pub async fn purge_exact_partition_async(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    uri: &str,
    partition: Option<&str>,
  ) -> anyhow::Result<usize> {
    let count = self.purge_exact_partition(policy, scheme, host, uri, partition);
    let shared_count = match self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    {
      Some(shared) => {
        shared
          .cache_purge_exact(policy, scheme, host, uri, partition)
          .await?
      }
      None => 0,
    };
    Ok(count.saturating_add(shared_count))
  }

  pub fn purge_prefix(&self, policy: &str, scheme: &str, host: &str, path_prefix: &str) -> usize {
    self.purge_prefix_partition(policy, scheme, host, path_prefix, None)
  }

  pub fn purge_prefix_partition(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    path_prefix: &str,
    partition: Option<&str>,
  ) -> usize {
    let mut inner = self.inner_guard();
    let keys = inner
      .entries
      .iter()
      .filter(|(_, entry)| {
        entry.policy == policy
          && partition.is_none_or(|partition| entry.partition == partition)
          && entry.scheme == scheme
          && entry.host == host
          && entry
            .uri
            .parse::<Uri>()
            .ok()
            .is_some_and(|uri| uri.path().starts_with(path_prefix))
      })
      .map(|(key, _)| key.clone())
      .collect::<Vec<_>>();
    let count = keys.len();
    for key in keys {
      remove_entry(&mut inner, &key);
    }
    count
  }

  pub async fn purge_prefix_partition_async(
    &self,
    policy: &str,
    scheme: &str,
    host: &str,
    path_prefix: &str,
    partition: Option<&str>,
  ) -> anyhow::Result<usize> {
    let count = self.purge_prefix_partition(policy, scheme, host, path_prefix, partition);
    let shared_count = match self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    {
      Some(shared) => {
        shared
          .cache_purge_prefix(policy, scheme, host, path_prefix, partition)
          .await?
      }
      None => 0,
    };
    Ok(count.saturating_add(shared_count))
  }

  pub fn purge_tag(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
  ) -> usize {
    self.purge_tag_partition(policy, tag, scheme, host, None)
  }

  pub fn purge_tag_partition(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
    partition: Option<&str>,
  ) -> usize {
    let mut inner = self.inner_guard();
    let keys = inner
      .entries
      .iter()
      .filter(|(_, entry)| {
        entry.policy == policy
          && partition.is_none_or(|partition| entry.partition == partition)
          && scheme.is_none_or(|scheme| entry.scheme == scheme)
          && host.is_none_or(|host| entry.host == host)
          && entry.tags.iter().any(|candidate| candidate == tag)
      })
      .map(|(key, _)| key.clone())
      .collect::<Vec<_>>();
    let count = keys.len();
    for key in keys {
      remove_entry(&mut inner, &key);
    }
    count
  }

  pub async fn purge_tag_partition_async(
    &self,
    policy: &str,
    tag: &str,
    scheme: Option<&str>,
    host: Option<&str>,
    partition: Option<&str>,
  ) -> anyhow::Result<usize> {
    let count = self.purge_tag_partition(policy, tag, scheme, host, partition);
    let shared_count = match self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    {
      Some(shared) => {
        shared
          .cache_purge_tag(policy, tag, scheme, host, partition)
          .await?
      }
      None => 0,
    };
    Ok(count.saturating_add(shared_count))
  }

  pub fn stats(&self) -> CacheStats {
    let inner = self.inner_guard();
    let mut stats = CacheStats {
      memory_bytes: inner.memory_size,
      disk_bytes: inner.disk_size,
      tmpfs_bytes: inner.tmpfs_size,
      disk_recovered_entries_total: inner.disk_recovered_entries_total,
      disk_recovery_errors_total: inner.disk_recovery_errors_total,
      disk_recovery_removed_files_total: inner.disk_recovery_removed_files_total,
      ..CacheStats::default()
    };
    for entry in inner.entries.values() {
      match entry.body {
        StoredBody::Memory(_) => stats.memory_entries += 1,
        StoredBody::Tmpfs(_) => stats.tmpfs_entries += 1,
        StoredBody::Disk(_) => stats.disk_entries += 1,
      }
    }
    stats
  }

  pub fn strip_surrogate_control(&self, policy_name: Option<&str>) -> bool {
    self.policy(policy_name).is_some()
      && self.config.surrogate.enabled
      && self.config.surrogate.strip_response_header
  }

  pub fn explain_key(
    &self,
    ctx: CacheLookupContext<'_>,
    response_headers: Option<&HeaderMap>,
  ) -> CacheKeyExplain {
    let policy = self.policy(ctx.policy_name);
    let mut reasons = Vec::new();
    if !self.config.enabled {
      reasons.push("cache disabled".to_string());
    }
    let cacheable_method = self.is_cacheable_method(ctx.method);
    if !cacheable_method {
      reasons.push("method not configured as cacheable".to_string());
    }
    let bypassed = super::lookup::cache_request_bypassed(&ctx, &self.bypass_request_headers);
    if bypassed {
      reasons.push("request carries a bypass header or Cache-Control: no-store".to_string());
    }
    let (policy_name, partition, base_key, vary_fields, variant_key) = if let Some(policy) = policy
    {
      let request_headers = super::lookup::cache_view_headers(&ctx);
      let operation = self.operation_context(
        ctx.policy_name,
        ctx.scheme,
        ctx.host,
        ctx.method,
        ctx.uri,
        request_headers,
        ctx.query_identity,
        ctx.certificate_identity,
        ctx.proxy_protocol_identity,
      );
      let Some(operation) = operation else {
        reasons.push("QUERY cache identity is required".to_string());
        return CacheKeyExplain {
          policy: policy.name.clone(),
          enabled: self.config.enabled,
          cacheable_method,
          bypassed,
          partition: String::new(),
          base_key: String::new(),
          variant_key: None,
          vary_fields: Vec::new(),
          reasons,
        };
      };
      let partition = operation.partition;
      let base_key = if ctx.method.as_str() == "QUERY" {
        operation.base_key
      } else {
        // Legacy explanation exposes the logical key, never certificate or
        // PROXY identity partition material.
        expanded_cache_key(
          &policy.cache_key,
          ctx.scheme,
          ctx.host,
          ctx.uri,
          request_headers,
        )
      };
      let (vary_fields, variant_key) = if let Some(headers) = response_headers {
        match vary_matchers_result(
          headers,
          request_headers,
          ctx.certificate_identity,
          policy.max_vary_fields,
          MAX_VARY_VALUE_BYTES,
        ) {
          Ok(vary) => {
            let vary_fields = vary.iter().map(|item| item.name.clone()).collect();
            let variant_key = Some(variant_key(&partition, &base_key, &vary));
            (vary_fields, variant_key)
          }
          Err(reason) => {
            reasons.push(reason.to_string());
            (Vec::new(), None)
          }
        }
      } else {
        (Vec::new(), None)
      };
      (
        policy.name.clone(),
        partition,
        base_key,
        vary_fields,
        variant_key,
      )
    } else {
      reasons.push("unknown cache policy".to_string());
      (
        ctx.policy_name.unwrap_or("default").to_string(),
        String::new(),
        String::new(),
        Vec::new(),
        None,
      )
    };
    CacheKeyExplain {
      policy: policy_name,
      enabled: self.config.enabled && policy.is_some(),
      cacheable_method,
      bypassed,
      partition,
      base_key,
      variant_key,
      vary_fields,
      reasons,
    }
  }

  pub fn remember_purge_nonce(&self, nonce: &str, ttl: Duration) -> bool {
    let now = SystemTime::now();
    let expires_at = now + ttl;
    let mut inner = self.inner_guard();
    while let Some(oldest) = inner.purge_nonce_order.front() {
      let expired = inner
        .purge_nonces
        .get(oldest)
        .is_none_or(|expires| *expires <= now);
      if !expired {
        break;
      }
      if let Some(oldest) = inner.purge_nonce_order.pop_front() {
        inner.purge_nonces.remove(&oldest);
      }
    }
    if inner.purge_nonces.contains_key(nonce) {
      return false;
    }
    inner.purge_nonces.insert(nonce.to_string(), expires_at);
    inner.purge_nonce_order.push_back(nonce.to_string());
    while inner.purge_nonces.len() > 16_384 {
      let Some(oldest) = inner.purge_nonce_order.pop_front() else {
        break;
      };
      inner.purge_nonces.remove(&oldest);
    }
    true
  }
}
