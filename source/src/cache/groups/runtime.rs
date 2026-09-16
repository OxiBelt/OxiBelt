//! Cache-group request snapshots and integration with cache policy.

use anyhow::{Result, bail, ensure};
use http::{HeaderMap, Method, StatusCode};
use std::sync::{Arc, Mutex};

use super::fields::{GroupField, parse_groups, parse_invalidation};
use super::model::{Seed, Selector, digest};
use super::{CacheGroupOrigin, CacheGroupStamp};
use crate::cache::{CacheInsertContext, CacheLookupContext, CachePreparedInsert, ResponseCache};

#[derive(Clone, Debug)]
pub struct CacheGroupRequest {
  pub(crate) origin: CacheGroupOrigin,
  snapshot: Arc<Mutex<Option<CacheGroupStamp>>>,
}

impl CacheGroupRequest {
  pub fn new(origin: CacheGroupOrigin) -> Self {
    Self {
      origin,
      snapshot: Arc::new(Mutex::new(None)),
    }
  }
  pub(in crate::cache) fn snapshot(&self) -> Option<CacheGroupStamp> {
    self.snapshot.lock().ok()?.clone()
  }
  fn bind(&self, stamp: CacheGroupStamp) -> Result<()> {
    let mut snapshot = self
      .snapshot
      .lock()
      .map_err(|_| anyhow::anyhow!("cache group request state poisoned"))?;
    if let Some(existing) = snapshot.as_ref() {
      ensure!(
        existing.policy == stamp.policy
          && existing.origin == stamp.origin
          && existing.partition == stamp.partition,
        "cache group request scope changed"
      );
    } else {
      *snapshot = Some(stamp);
    }
    Ok(())
  }
}

#[derive(Debug)]
pub(in crate::cache) struct CacheGroupPublication {
  policy: String,
  stamp: CacheGroupStamp,
  variant: String,
  publication: String,
  previous: Option<Seed>,
}

impl ResponseCache {
  pub fn groups_enabled(&self, policy: &str) -> bool {
    self.config.enabled
      && self
        .policy(Some(policy))
        .is_some_and(|policy| policy.groups_enabled)
  }

  pub(crate) async fn bind_group_request(&self, ctx: CacheLookupContext<'_>) -> bool {
    let policy = ctx.policy_name.unwrap_or("default");
    if !self.groups_enabled(policy) {
      return true;
    }
    if self.groups.fenced(policy) && !self.recover_group_policy(policy).await {
      return false;
    }
    let Some(request) = ctx.group_request else {
      return false;
    };
    let Some(runtime) = self.policy(Some(policy)) else {
      return false;
    };
    let partition = super::super::expanded_cache_key(
      &runtime.partition_key,
      ctx.scheme,
      ctx.host,
      ctx.uri,
      super::super::lookup::cache_view_headers(&ctx),
    );
    if let Some(stamp) = request.snapshot() {
      return stamp.policy == policy
        && stamp.origin == request.origin
        && stamp.partition == partition;
    }
    let result = if self.group_uses_remote(policy) {
      match self.group_authority_read(policy).await {
        Ok(mut state)
          if state
            .scopes
            .contains_key(&super::model::scope_key(&request.origin, &partition)) =>
        {
          state.snapshot(policy, &request.origin, &partition)
        }
        Ok(_) => {
          self
            .group_authority_update(policy, |state| {
              state.snapshot(policy, &request.origin, &partition)
            })
            .await
        }
        Err(error) => Err(error),
      }
    } else {
      self
        .groups
        .local_snapshot(policy, &request.origin, &partition)
    }
    .and_then(|stamp| request.bind(stamp));
    if let Err(error) = result {
      tracing::warn!(error = %error, "cache group snapshot unavailable; bypassing cache");
      return false;
    }
    true
  }

  pub(in crate::cache) fn group_key(
    &self,
    policy: &str,
    key: String,
    request: Option<&CacheGroupRequest>,
  ) -> Option<String> {
    if !self.groups_enabled(policy) {
      return Some(key);
    }
    let origin = request?.origin.as_origin();
    Some(format!(
      "\0oxibelt-cache-groups-v1\0{}",
      digest(format!("{}:{}{}:{}", origin.len(), origin, key.len(), key).as_bytes())
    ))
  }

  pub(in crate::cache) fn prepare_group_stamp(
    &self,
    ctx: &CacheInsertContext<'_>,
    headers: &HeaderMap,
    tags: Vec<String>,
  ) -> Result<Option<CacheGroupStamp>> {
    let policy = ctx.policy_name.unwrap_or("default");
    if !self.groups_enabled(policy) {
      return Ok(None);
    }
    ensure!(!self.groups.fenced(policy), "cache group policy fenced");
    let request = ctx
      .group_request
      .ok_or_else(|| anyhow::anyhow!("cache group origin missing"))?;
    let mut stamp = request
      .snapshot()
      .ok_or_else(|| anyhow::anyhow!("cache group fill snapshot missing"))?;
    let runtime = self
      .policy(Some(policy))
      .ok_or_else(|| anyhow::anyhow!("cache group policy missing"))?;
    let partition = super::super::expanded_cache_key(
      &runtime.partition_key,
      ctx.scheme,
      ctx.host,
      ctx.uri,
      super::super::insert::cache_insert_view_headers(ctx),
    );
    ensure!(
      stamp.policy == policy && stamp.origin == request.origin && stamp.partition == partition,
      "cache group scope mismatch"
    );
    stamp.target = ctx.uri.to_string();
    stamp.groups = match parse_groups(headers) {
      GroupField::Absent => Vec::new(),
      GroupField::Valid(groups) => groups,
      GroupField::Invalid | GroupField::Bounded => {
        bail!("cache group membership invalid or over bound")
      }
    };
    stamp.tags = tags;
    Ok(Some(stamp))
  }

  pub(crate) async fn group_entry_current(
    &self,
    policy: &str,
    stamp: Option<&CacheGroupStamp>,
  ) -> bool {
    if !self.groups_enabled(policy) {
      return stamp.is_none();
    }
    if self.groups.fenced(policy) {
      return false;
    }
    let Some(stamp) = stamp else {
      return false;
    };
    if stamp.policy != policy {
      return false;
    }
    if !self.group_uses_remote(policy) {
      return self.groups.local_current(policy, stamp);
    }
    match self.group_authority_read(policy).await {
      Ok(state) => state.current(stamp),
      Err(error) => {
        tracing::warn!(error = %error, "cache group validation unavailable; bypassing cache");
        false
      }
    }
  }

  pub(in crate::cache) fn group_entry_matches(
    &self,
    ctx: &CacheLookupContext<'_>,
    entry: &crate::cache::CacheEntry,
  ) -> bool {
    if !self.groups_enabled(ctx.policy_name.unwrap_or("default")) {
      return entry.group_stamp.is_none();
    }
    let Some(snapshot) = ctx.group_request.and_then(CacheGroupRequest::snapshot) else {
      return false;
    };
    let Some(stamp) = &entry.group_stamp else {
      return false;
    };
    stamp.policy == snapshot.policy
      && stamp.origin == snapshot.origin
      && stamp.partition == snapshot.partition
      && (stamp.target == ctx.uri.to_string()
        || entry.nvs_alias
          && entry
            .no_vary_search
            .as_ref()
            .is_some_and(|nvs| nvs.owner_uri == stamp.target))
  }

  pub(in crate::cache) fn group_entry_current_local(
    &self,
    policy: &str,
    stamp: Option<&CacheGroupStamp>,
  ) -> bool {
    if !self.groups_enabled(policy) {
      return stamp.is_none();
    }
    if self.groups.fenced(policy) {
      return false;
    }
    let Some(stamp) = stamp else {
      return false;
    };
    stamp.policy == policy && self.groups.local_current(policy, stamp)
  }

  pub(in crate::cache) async fn publish_group_prepared(
    &self,
    prepared: &CachePreparedInsert,
  ) -> Result<Option<CacheGroupPublication>> {
    let Some(stamp) = &prepared.group_stamp else {
      ensure!(!prepared.policy.groups_enabled, "cache group stamp missing");
      return Ok(None);
    };
    ensure!(
      !self.groups.fenced(&stamp.policy),
      "cache group policy fenced"
    );
    let expires = prepared
      .metadata
      .expires_at
      .max(
        prepared
          .metadata
          .stale_if_error_until
          .unwrap_or(prepared.metadata.expires_at),
      )
      .max(
        prepared
          .metadata
          .stale_while_revalidate_until
          .unwrap_or(prepared.metadata.expires_at),
      );
    let publication = super::authority::incarnation()?;
    let previous = self
      .group_authority_update(&stamp.policy, |state| {
        ensure!(
          prepared
            .group_previous
            .as_ref()
            .is_none_or(|previous| state.current(previous)),
          "cache group revalidation owner was invalidated"
        );
        state.publish(
          stamp,
          &prepared.variant_key,
          millis(expires),
          millis(std::time::SystemTime::now()),
          &publication,
        )
      })
      .await?;
    Ok(Some(CacheGroupPublication {
      policy: stamp.policy.clone(),
      stamp: stamp.clone(),
      variant: prepared.variant_key.clone(),
      publication,
      previous,
    }))
  }

  pub(in crate::cache) fn publish_group_prepared_local(
    &self,
    prepared: &CachePreparedInsert,
  ) -> Result<Option<CacheGroupPublication>> {
    let Some(stamp) = &prepared.group_stamp else {
      ensure!(!prepared.policy.groups_enabled, "cache group stamp missing");
      return Ok(None);
    };
    ensure!(
      !self.groups.fenced(&stamp.policy),
      "cache group policy fenced"
    );
    ensure!(
      prepared.group_published || !self.group_uses_remote(&stamp.policy),
      "remote cache group publication must be awaited"
    );
    if prepared.group_published {
      ensure!(
        self.groups.local_current(&stamp.policy, stamp),
        "cache group fill was invalidated"
      );
      return Ok(None);
    }
    let expires = prepared
      .metadata
      .expires_at
      .max(
        prepared
          .metadata
          .stale_if_error_until
          .unwrap_or(prepared.metadata.expires_at),
      )
      .max(
        prepared
          .metadata
          .stale_while_revalidate_until
          .unwrap_or(prepared.metadata.expires_at),
      );
    let publication = super::authority::incarnation()?;
    let previous = self.groups.local_update(&stamp.policy, |state| {
      ensure!(
        prepared
          .group_previous
          .as_ref()
          .is_none_or(|previous| state.current(previous)),
        "cache group revalidation owner was invalidated"
      );
      state.publish(
        stamp,
        &prepared.variant_key,
        millis(expires),
        millis(std::time::SystemTime::now()),
        &publication,
      )
    })?;
    Ok(Some(CacheGroupPublication {
      policy: stamp.policy.clone(),
      stamp: stamp.clone(),
      variant: prepared.variant_key.clone(),
      publication,
      previous,
    }))
  }

  pub(in crate::cache) async fn rollback_group_publication(
    &self,
    publication: CacheGroupPublication,
  ) {
    self.rollback_group_publication_inner(publication).await;
  }

  /// Streaming rename can replace the previous disk body before metadata
  /// insertion succeeds, so a failed streamed replacement must not restore
  /// that prior seed.
  pub(in crate::cache) async fn discard_group_publication(
    &self,
    mut publication: CacheGroupPublication,
  ) {
    publication.previous = None;
    self.rollback_group_publication_inner(publication).await;
  }

  async fn rollback_group_publication_inner(&self, publication: CacheGroupPublication) {
    if self
      .group_authority_update(&publication.policy, |state| {
        state.rollback_publish(
          &publication.stamp,
          &publication.variant,
          &publication.publication,
          publication.previous.clone(),
        )
      })
      .await
      .is_err()
    {
      self.groups.fence(&publication.policy);
    }
  }

  pub(in crate::cache) fn rollback_group_publication_local(
    &self,
    publication: CacheGroupPublication,
  ) {
    if self
      .groups
      .local_update(&publication.policy, |state| {
        state.rollback_publish(
          &publication.stamp,
          &publication.variant,
          &publication.publication,
          publication.previous.clone(),
        )
      })
      .is_err()
    {
      self.groups.fence(&publication.policy);
    }
  }

  pub async fn purge_group_async(
    &self,
    policy: &str,
    origin: &CacheGroupOrigin,
    group: &str,
    partition: Option<&str>,
  ) -> Result<usize> {
    ensure!(
      self.groups_enabled(policy),
      "cache groups disabled for policy"
    );
    ensure!(
      group.len() <= 256 && group.bytes().all(|b| (0x20..=0x7e).contains(&b)),
      "invalid cache group name"
    );
    self
      .invalidate_groups(
        policy,
        Some(origin),
        partition,
        None,
        None,
        Selector::Groups(vec![group.into()]),
        &[],
      )
      .await
  }

  #[allow(clippy::too_many_arguments)]
  pub(in crate::cache) async fn invalidate_groups(
    &self,
    policy: &str,
    origin: Option<&CacheGroupOrigin>,
    partition: Option<&str>,
    host: Option<&str>,
    scheme: Option<&str>,
    selector: Selector,
    explicit: &[String],
  ) -> Result<usize> {
    let result = self
      .group_authority_update(policy, |state| {
        if let Some(shared) = self
          .shared_state
          .as_ref()
          .filter(|shared| shared.has_cache())
        {
          let count = state.scopes.values().try_fold(0usize, |sum, scope| {
            sum
              .checked_add(scope.entries.len())
              .ok_or_else(|| anyhow::anyhow!("cache group enumeration overflow"))
          })?;
          ensure!(
            count <= shared.cache_group_enumeration_max_items(),
            "cache group shared enumeration bound exceeded"
          );
        }
        if let (Some(origin), Some(partition)) = (origin, partition) {
          state.snapshot(policy, origin, partition)?;
        }
        state.invalidate(
          origin,
          partition,
          host,
          scheme,
          &selector,
          explicit,
          millis(std::time::SystemTime::now()),
        )
      })
      .await;
    self
      .group_metrics
      .record_cache_group_invalidation(result.is_ok());
    if result.is_err() {
      self.groups.fence(policy);
    }
    result
  }

  pub(crate) async fn groups_after_origin_response(
    &self,
    ctx: CacheLookupContext<'_>,
    status: StatusCode,
    headers: &HeaderMap,
  ) {
    if matches!(
      *ctx.method,
      Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) || ctx.method.as_str() == "QUERY"
    {
      return;
    }
    let policy = ctx.policy_name.unwrap_or("default");
    if !self.groups_enabled(policy) {
      return;
    }
    let Some(request) = ctx.group_request else {
      self.groups.fence(policy);
      return;
    };
    let Some(runtime) = self.policy(Some(policy)) else {
      return;
    };
    let partition = super::super::expanded_cache_key(
      &runtime.partition_key,
      ctx.scheme,
      ctx.host,
      ctx.uri,
      ctx.request_headers,
    );
    let explicit = match parse_invalidation(headers) {
      GroupField::Valid(groups) => groups,
      _ => Vec::new(),
    };
    let selector = if status.is_success() || status.is_redirection() {
      Selector::Exact(ctx.uri.to_string())
    } else {
      Selector::Groups(explicit.clone())
    };
    if !status.is_success() && !status.is_redirection() && explicit.is_empty() {
      return;
    }
    if let Err(error) = self
      .invalidate_groups(
        policy,
        Some(&request.origin),
        Some(&partition),
        None,
        None,
        selector,
        &explicit,
      )
      .await
    {
      tracing::warn!(error = %error, "cache group invalidation failed; cache reuse fenced while preserving origin response");
    }
  }
}

pub(in crate::cache) fn millis(time: std::time::SystemTime) -> u64 {
  time
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis()
    .min(u64::MAX as u128) as u64
}
