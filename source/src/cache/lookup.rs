//! Cache construction and lookup orchestration.

use super::*;

impl ResponseCache {
  pub fn new(
    config: &CacheConfig,
    shared_state: Option<Arc<SharedState>>,
  ) -> anyhow::Result<Arc<Self>> {
    let metrics = crate::metrics::Metrics::new();
    Self::new_with_external_and_health(
      config,
      shared_state,
      ExternalCacheRuntime::disabled(metrics.clone()),
      Arc::new(RuntimeHealth::default()),
      metrics,
    )
  }

  pub(crate) fn new_with_external_and_health(
    config: &CacheConfig,
    shared_state: Option<Arc<SharedState>>,
    external_cache: ExternalCacheRuntime,
    runtime_health: Arc<RuntimeHealth>,
    metrics: Arc<crate::metrics::Metrics>,
  ) -> anyhow::Result<Arc<Self>> {
    let tmpfs_dir = if config.enabled && config.store == CacheStore::Tmpfs {
      let dir = config
        .tmpfs_dir
        .clone()
        .unwrap_or_else(default_cache_tmpfs_dir);
      Some(validated_tmpfs_dir(&dir)?)
    } else {
      None
    };
    let disk_dir = if config.enabled && cache_needs_disk_dir(config) {
      let dir = config
        .disk_dir
        .as_ref()
        .ok_or_else(|| anyhow!("cache.disk_dir is required when cache.store uses disk"))?;
      Some(validated_disk_dir(dir)?)
    } else {
      config.disk_dir.clone()
    };

    let default_memory_limit = config
      .memory_max_size_bytes
      .unwrap_or_else(|| auto_memory_cache_limit(config));
    let default_policy = CachePolicyRuntime {
      name: "default".to_string(),
      store: config.store,
      cache_key: config.cache_key.clone(),
      partition_key: config.partition_key.clone(),
      default_ttl_seconds: config.default_ttl_seconds,
      negative_statuses: cache_status_codes(&config.negative_statuses),
      negative_ttl_seconds: config.negative_ttl_seconds,
      memory_max_size_bytes: default_memory_limit,
      disk_max_size_bytes: config.disk_max_size_bytes,
      tag_headers: cache_tag_headers(&config.tag_headers),
      max_tags_per_entry: config.max_tags_per_entry,
      max_tag_bytes: config.max_tag_bytes,
      max_vary_fields: config.max_vary_fields,
      max_vary_variants_per_key: config.max_vary_variants_per_key,
      background_refresh: config.background_refresh,
      background_refresh_max_concurrent: config.background_refresh_max_concurrent,
      lock_wait_timeout: Duration::from_millis(config.lock_wait_timeout_ms),
      external_handler: external_handler_selection(config.external_handler.as_deref(), None),
      admission: admission_runtime(&config.admission, &config.negative_statuses),
      stale_if_error: config.stale_if_error.clone(),
      rules: Vec::new(),
    };
    let mut policies = HashMap::new();
    policies.insert(default_policy.name.clone(), default_policy);
    for policy in &config.policies {
      let runtime = policy_runtime(config, policy, default_memory_limit);
      policies.insert(runtime.name.clone(), runtime);
    }
    let refresh_limiters = policies
      .iter()
      .map(|(name, policy)| {
        (
          name.clone(),
          Arc::new(Semaphore::new(policy.background_refresh_max_concurrent)),
        )
      })
      .collect();

    let (query_cleanup, query_cleanup_receiver) =
      query_cleanup::QueryCleanupDispatcher::new(&config.query_cleanup, metrics.clone());
    let cache = Arc::new(Self {
      config: config.clone(),
      policies,
      bypass_request_headers: cache_tag_headers(&config.bypass_request_headers),
      refresh_limiters,
      tmpfs_dir,
      disk_dir,
      fills: fill::CacheFillCoordinator::new(runtime_health.clone()),
      inner: Mutex::new(CacheInner::default()),
      disk_recovery: Mutex::new(None),
      disk_rebuild_requested: AtomicBool::new(false),
      runtime_health,
      shared_state,
      external_cache,
      query_cleanup,
      overload: ArcSwapOption::empty(),
    });
    cache
      .query_cleanup
      .start(Arc::downgrade(&cache), query_cleanup_receiver);
    cache.rebuild_disk_entries_at_startup();
    Ok(cache)
  }

  pub fn enabled(&self) -> bool {
    self.config.enabled
  }

  pub(crate) fn set_overload_runtime(&self, overload: Arc<OverloadRuntime>) {
    self.overload.store(Some(overload));
  }

  pub(in crate::cache) fn inner_guard(&self) -> MutexGuard<'_, CacheInner> {
    let mut inner = match self.inner.lock() {
      Ok(inner) => inner,
      Err(poisoned) => {
        let error =
          RuntimeSubsystemError::RecoverableStatePoisoned(RuntimeSubsystem::ResponseCache);
        warn!(error = %error, "resetting disposable runtime state");
        let mut inner = poisoned.into_inner();
        *inner = CacheInner::default();
        self.inner.clear_poison();
        self
          .runtime_health
          .record_lock_recovery(RuntimeSubsystem::ResponseCache);
        self.runtime_health.set_subsystem_state(
          PROCESS_GENERATION,
          RuntimeSubsystem::ResponseCache,
          RuntimeSubsystemState::Degraded,
          false,
        );
        self.disk_rebuild_requested.store(true, Ordering::Release);
        inner
      }
    };
    self.advance_disk_rebuild(&mut inner);
    inner
  }

  pub(crate) fn shared_cache_enabled(&self) -> bool {
    self
      .shared_state
      .as_ref()
      .is_some_and(|shared| shared.has_cache())
  }

  pub fn policy_enabled(&self, policy_name: Option<&str>, method: &Method) -> bool {
    self.config.enabled && self.policy(policy_name).is_some() && self.is_cacheable_method(method)
  }

  /// Describe why this cache would forward the request before the response is available.
  ///
  /// This intentionally does not distinguish URI misses from Vary misses: lookup
  /// currently exposes neither distinction to the forwarding path.
  pub(crate) fn diagnostic_forward_reason(
    &self,
    policy_name: Option<&str>,
    method: &Method,
    headers: &HeaderMap,
  ) -> Option<&'static str> {
    if !self.config.enabled || self.policy(policy_name).is_none() {
      return None;
    }
    if !self.is_cacheable_method(method) {
      return Some("method");
    }
    if request_no_store(headers, &self.bypass_request_headers) {
      return Some("bypass");
    }
    Some("miss")
  }

  pub fn is_cacheable_method(&self, method: &Method) -> bool {
    // HTTP method tokens are case-sensitive.  Preserve the historical
    // case-insensitive configuration matching for existing methods, but never
    // let a spelling such as `query` enter a bodyless generic cache key.
    if method.as_str() == "QUERY" {
      return self.config.cache_methods.iter().any(|item| item == "QUERY");
    }
    if method.as_str().eq_ignore_ascii_case("QUERY") {
      return false;
    }
    if method == Method::HEAD {
      return self
        .config
        .cache_methods
        .iter()
        .any(|item| item.eq_ignore_ascii_case(Method::GET.as_str()))
        || self
          .config
          .cache_methods
          .iter()
          .any(|item| item.eq_ignore_ascii_case(Method::HEAD.as_str()));
    }
    self
      .config
      .cache_methods
      .iter()
      .any(|item| item.eq_ignore_ascii_case(method.as_str()))
  }

  #[allow(clippy::too_many_arguments)]
  pub(super) fn operation_context(
    &self,
    policy_name: Option<&str>,
    scheme: &str,
    host: &str,
    method: &Method,
    uri: &Uri,
    request_headers: &HeaderMap,
    query_identity: Option<&CacheQueryIdentity>,
    certificate_identity: Option<&CacheCertificateIdentity>,
    proxy_protocol_identity: Option<&CacheProxyProtocolIdentity>,
  ) -> Option<CacheOperationContext> {
    let policy = self.policy(policy_name)?.clone();
    let base_key = certificate_partitioned_base_key(
      expanded_cache_key(&policy.cache_key, scheme, host, uri, request_headers),
      certificate_identity,
    );
    let partition = expanded_cache_key(&policy.partition_key, scheme, host, uri, request_headers);
    let base_key = match proxy_protocol_identity {
      Some(identity) => identity.partition(base_key),
      None => base_key,
    };
    let is_query = method.as_str() == "QUERY";
    let base_key = match (is_query, query_identity) {
      (true, Some(identity)) => query_partitioned_base_key(base_key, identity),
      (true, None) => return None,
      (false, _) => base_key,
    };
    let uri = uri.to_string();
    let query_target = is_query.then(|| {
      CacheQueryInvalidationTarget::new(&policy.name, scheme, host, &uri, Some(&partition))
    });
    let lookup_key = index::LookupKey::new(&policy.name, &partition, scheme, host, &uri, &base_key);
    let fill_key = format!(
      "{}\n{}\n{}\n{}\n{}\n{}",
      policy.name,
      partition,
      method.as_str(),
      scheme,
      host,
      base_key
    );
    Some(CacheOperationContext {
      policy,
      partition,
      base_key,
      lookup_key,
      fill_key,
      scheme: scheme.to_string(),
      host: host.to_string(),
      uri,
      query_target,
    })
  }

  pub fn lookup(&self, ctx: CacheLookupContext<'_>) -> Option<CacheLookup> {
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return None;
    }
    // RFC 9111 requires these origin preconditions to be evaluated by the
    // origin. A cached QUERY response may still be stored after that request.
    if query_context_origin_precondition_bypass(&ctx) {
      return None;
    }
    if cache_request_bypassed(&ctx, &self.bypass_request_headers) {
      return None;
    }
    let request_headers = cache_view_headers(&ctx);
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
    )?;
    if self.query_target_cache_bypassed(&operation) {
      return None;
    }
    if !self.bind_query_generation(ctx.query_identity, &operation) {
      return None;
    }
    let now = SystemTime::now();
    let (key, entry) = {
      let mut inner = self.inner_guard();
      let key = inner
        .index
        .candidates(&operation.lookup_key)
        .and_then(|candidates| {
          candidates.into_iter().find(|key| {
            inner.entries.get(key).is_some_and(|entry| {
              vary_matches(&entry.vary, request_headers)
                && entry.no_vary_search.as_ref().is_none_or(|nvs| {
                  self.nvs_current_locked(&inner, &entry.policy, &entry.scheme, &entry.host, nvs)
                })
                && (!is_query_v1_base_key(&operation.base_key)
                  || entry.query_target_epoch
                    == ctx
                      .query_identity
                      .and_then(CacheQueryIdentity::query_target_epoch))
            })
          })
        });
      let Some(key) = key else {
        drop(inner);
        return self.lookup_shared(
          &operation.policy.name,
          operation.policy.background_refresh,
          &operation.partition,
          &operation.base_key,
          ctx,
        );
      };

      let expired = inner.entries.get(&key).is_some_and(|entry| {
        let mut retain_until = entry.stale_if_error_until.unwrap_or(entry.expires_at);
        if is_query_v1_base_key(&entry.base_key) {
          retain_until = retain_until.max(
            entry
              .stale_while_revalidate_until
              .unwrap_or(entry.expires_at),
          );
        }
        retain_until <= now
      });
      if expired {
        remove_entry(&mut inner, &key);
        return None;
      }
      let entry = inner.entries.get(&key).cloned()?;
      (key, entry)
    };
    let Some(cache_entry) = entry.to_cache_entry() else {
      let mut inner = self.inner_guard();
      remove_entry(&mut inner, &key);
      return None;
    };
    if request_no_cache(request_headers) || entry.must_revalidate || entry.expires_at <= now {
      let validators = validator_headers(&entry.headers);
      if !request_no_cache(request_headers)
        && !entry.must_revalidate
        && entry
          .stale_while_revalidate_until
          .is_some_and(|until| until > now)
      {
        return Some(CacheLookup::Stale(StaleEntry {
          entry: cache_entry,
          request_headers: validators,
          serve_stale_on_error: (!is_query_v1_base_key(&entry.base_key) || !entry.must_revalidate)
            && entry.stale_if_error_until.is_some_and(|until| until > now),
          background_refresh: operation.policy.background_refresh,
        }));
      }
      if validators.is_empty() {
        if is_query_v1_base_key(&entry.base_key)
          && (request_no_cache(request_headers) || entry.must_revalidate)
        {
          return None;
        }
        if entry
          .stale_while_revalidate_until
          .is_some_and(|until| until > now)
        {
          return Some(CacheLookup::Stale(StaleEntry {
            entry: cache_entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: (!is_query_v1_base_key(&entry.base_key)
              || !entry.must_revalidate)
              && entry.stale_if_error_until.is_some_and(|until| until > now),
            background_refresh: entry
              .stale_while_revalidate_until
              .is_some_and(|until| until > now)
              && operation.policy.background_refresh,
          }));
        }
        if entry.stale_if_error_until.is_some_and(|until| until > now) {
          return Some(CacheLookup::Revalidate(Revalidation {
            entry: cache_entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: true,
          }));
        }
        return None;
      }
      return Some(CacheLookup::Revalidate(Revalidation {
        entry: cache_entry,
        request_headers: validators,
        serve_stale_on_error: (!is_query_v1_base_key(&entry.base_key) || !entry.must_revalidate)
          && entry.stale_if_error_until.is_some_and(|until| until > now),
      }));
    }
    Some(CacheLookup::Fresh(cache_entry))
  }

  pub(super) fn lookup_shared(
    &self,
    policy: &str,
    background_refresh: bool,
    partition: &str,
    base_key: &str,
    ctx: CacheLookupContext<'_>,
  ) -> Option<CacheLookup> {
    // Synchronous cache APIs are deliberately L1-only. Request paths use
    // `lookup_async` whenever a shared backend is configured.
    let _ = (policy, background_refresh, partition, base_key, ctx);
    None
  }

  pub async fn lookup_async(&self, ctx: CacheLookupContext<'_>) -> Option<CacheLookup> {
    let result = self.lookup_exact_async(ctx.clone()).await?;
    let entry = match &result {
      CacheLookup::Fresh(entry) => entry,
      CacheLookup::Stale(stale) => &stale.entry,
      CacheLookup::Revalidate(revalidation) => &revalidation.entry,
    };
    if let Some(metadata) = &entry.no_vary_search {
      let policy = self.policy(ctx.policy_name)?;
      let uri = metadata.owner_uri.parse::<Uri>().ok()?;
      if self
        .nvs_epoch(
          &nvs::target(&policy.name, ctx.scheme, ctx.host, &uri),
          false,
        )
        .await
        != Some(metadata.epoch)
        || self
          .nvs_epoch(&nvs::policy_target(&policy.name), false)
          .await
          != Some(metadata.policy_epoch)
      {
        return None;
      }
    }
    Some(result)
  }

  async fn lookup_exact_async(&self, ctx: CacheLookupContext<'_>) -> Option<CacheLookup> {
    let is_query = ctx.method.as_str() == "QUERY";
    if !is_query && let Some(lookup) = self.lookup(ctx.clone()) {
      return Some(lookup);
    }
    if !self.policy_enabled(ctx.policy_name, ctx.method)
      || cache_request_bypassed(&ctx, &self.bypass_request_headers)
      || query_context_origin_precondition_bypass(&ctx)
    {
      return None;
    }
    let operation = self.operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      cache_view_headers(&ctx),
      ctx.query_identity,
      ctx.certificate_identity,
      ctx.proxy_protocol_identity,
    )?;
    if self.query_target_cache_bypassed(&operation) {
      return None;
    }
    if !self
      .bind_query_generation_async(ctx.query_identity, &operation)
      .await
    {
      return None;
    }
    if is_query && let Some(lookup) = self.lookup(ctx.clone()) {
      return Some(lookup);
    }
    self
      .lookup_shared_async(
        &operation.policy.name,
        operation.policy.background_refresh,
        operation.policy.max_vary_variants_per_key,
        &operation.partition,
        &operation.base_key,
        ctx,
      )
      .await
  }

  pub(super) fn promote_shared_lookup(&self, ctx: CacheLookupContext<'_>, lookup: &CacheLookup) {
    let entry = match lookup {
      CacheLookup::Fresh(entry) => entry.clone(),
      CacheLookup::Stale(stale) => stale.entry.clone(),
      CacheLookup::Revalidate(revalidation) => revalidation.entry.clone(),
    };
    if entry.body_file.is_some() {
      return;
    }
    self.insert_with_external(
      CacheInsertContext {
        no_vary_search: None,
        proxy_protocol_identity: ctx.proxy_protocol_identity,
        policy_name: ctx.policy_name,
        scheme: ctx.scheme,
        host: ctx.host,
        method: ctx.method,
        uri: ctx.uri,
        request_headers: ctx.request_headers,
        query_identity: ctx.query_identity,
        certificate_identity: ctx.certificate_identity,
      },
      entry,
      false,
    );
  }
}

pub(super) fn cache_view_headers<'a>(ctx: &'a CacheLookupContext<'_>) -> &'a HeaderMap {
  ctx
    .query_identity
    .map(CacheQueryIdentity::cache_view_headers)
    .unwrap_or(ctx.request_headers)
}

pub(super) fn cache_request_bypassed(
  ctx: &CacheLookupContext<'_>,
  bypass_headers: &[HeaderName],
) -> bool {
  request_no_store(ctx.request_headers, bypass_headers)
    || ctx
      .query_identity
      .is_some_and(|identity| request_no_store(identity.cache_view_headers(), bypass_headers))
}

/// QUERY's origin preconditions cannot be answered from a cached response.
/// Keep legacy method behavior unchanged while forwarding QUERY for origin
/// evaluation as RFC 9111 requires.
pub(crate) fn query_origin_precondition_bypass(method: &Method, headers: &HeaderMap) -> bool {
  method.as_str() == "QUERY"
    && (headers.contains_key(http::header::IF_MATCH)
      || headers.contains_key(http::header::IF_UNMODIFIED_SINCE))
}

pub(super) fn query_context_origin_precondition_bypass(ctx: &CacheLookupContext<'_>) -> bool {
  query_origin_precondition_bypass(ctx.method, ctx.request_headers)
    || ctx.query_identity.is_some_and(|identity| {
      query_origin_precondition_bypass(ctx.method, identity.cache_view_headers())
    })
}

impl ResponseCache {
  pub(super) fn query_target_cache_bypassed(&self, operation: &CacheOperationContext) -> bool {
    operation.query_target.as_ref().is_some_and(|target| {
      self
        .inner_guard()
        .failed_query_invalidations
        .contains(&query_epoch_bucket(target))
    })
  }

  pub(super) fn mark_query_invalidation_failed(&self, target: CacheQueryInvalidationTarget) {
    let mut inner = self.inner_guard();
    inner
      .failed_query_invalidations
      .insert(query_epoch_bucket(&target));
    if self.persist_disk_query_epochs(&inner).is_err() {
      tracing::warn!("QUERY invalidation failure state could not be persisted");
    }
  }

  pub(super) fn prepared_query_cache_bypassed(&self, prepared: &CachePreparedInsert) -> bool {
    prepared.query_target.as_ref().is_some_and(|target| {
      let generation_current = prepared.query_generation.as_ref().is_some_and(|bound| {
        bound.target == *target
          && self
            .inner_guard()
            .query_invalidation_generations
            .get(&query_epoch_bucket(target))
            .copied()
            .unwrap_or(0)
            == bound.value
      });
      !generation_current
        || self.fills.is_fenced(&prepared.fill_key)
        || self
          .inner_guard()
          .failed_query_invalidations
          .contains(&query_epoch_bucket(target))
    })
  }

  pub(super) fn prepared_generation_current_locked(
    &self,
    inner: &CacheInner,
    prepared: &CachePreparedInsert,
  ) -> bool {
    if let Some(nvs) = prepared.no_vary_search.as_ref()
      && !self.nvs_current_locked(
        inner,
        &prepared.policy.name,
        &prepared.scheme,
        &prepared.host,
        nvs,
      )
    {
      return false;
    }
    let Some(target) = prepared.query_target.as_ref() else {
      return true;
    };
    let Some(bound) = prepared.query_generation.as_ref() else {
      return false;
    };
    bound.target == *target
      && inner
        .query_invalidation_generations
        .get(&query_epoch_bucket(target))
        .copied()
        .unwrap_or(0)
        == bound.value
      && !inner
        .failed_query_invalidations
        .contains(&query_epoch_bucket(target))
  }

  pub(super) fn bind_query_generation(
    &self,
    identity: Option<&CacheQueryIdentity>,
    operation: &CacheOperationContext,
  ) -> bool {
    let (Some(identity), Some(target)) = (identity, operation.query_target.as_ref()) else {
      return operation.query_target.is_none();
    };
    if identity.query_cache_epoch_rejected() {
      return false;
    }
    let inner = self.inner_guard();
    let current = inner
      .query_invalidation_generations
      .get(&query_epoch_bucket(target))
      .copied()
      .unwrap_or(0);
    let mut generation = identity
      .generation
      .lock()
      .unwrap_or_else(|error| error.into_inner());
    match generation.as_ref() {
      Some(bound) => bound.target == *target && bound.value == current,
      None => {
        *generation = Some(CacheQueryGeneration {
          target: target.clone(),
          value: current,
        });
        true
      }
    }
  }

  /// Binds Q1 work to the durable target epoch before an L2/L3 operation.
  /// The local generation map is advanced to the durable value first, so a
  /// request that was admitted before another replica invalidated the target
  /// cannot later publish under a current generation.
  pub(super) async fn bind_query_generation_async(
    &self,
    identity: Option<&CacheQueryIdentity>,
    operation: &CacheOperationContext,
  ) -> bool {
    let (Some(identity), Some(target)) = (identity, operation.query_target.as_ref()) else {
      return operation.query_target.is_none();
    };
    if let Some(shared) = self
      .shared_state
      .as_ref()
      .filter(|shared| shared.has_cache())
    {
      let Ok(epoch) = shared
        .cache_query_epoch(&target.policy, &target.scheme, &target.host, &target.uri)
        .await
      else {
        identity.reject_query_cache_epoch();
        return false;
      };
      let mut inner = self.inner_guard();
      let current = inner
        .query_invalidation_generations
        .entry(query_epoch_bucket(target))
        .or_default();
      if epoch < *current {
        identity.reject_query_cache_epoch();
        return false;
      }
      *current = epoch;
    } else if operation.policy.external_handler.is_some() {
      let Some(epoch) = self.external_query_epoch(target, false).await else {
        identity.reject_query_cache_epoch();
        return false;
      };
      let mut inner = self.inner_guard();
      let current = inner
        .query_invalidation_generations
        .entry(query_epoch_bucket(target))
        .or_default();
      if epoch < *current {
        identity.reject_query_cache_epoch();
        return false;
      }
      *current = epoch;
    }
    self.bind_query_generation(Some(identity), operation)
  }

  pub(super) fn advance_query_generation(&self, target: &CacheQueryInvalidationTarget) -> u64 {
    self.advance_query_generation_to(target, None)
  }

  pub(super) fn advance_query_generation_to(
    &self,
    target: &CacheQueryInvalidationTarget,
    durable_epoch: Option<u64>,
  ) -> u64 {
    let mut inner = self.inner_guard();
    let current = inner
      .query_invalidation_generations
      .get(&query_epoch_bucket(target))
      .copied()
      .unwrap_or(0);
    let next = durable_epoch.unwrap_or_else(|| current.saturating_add(1));
    if durable_epoch.is_some() && next < current {
      return current;
    }
    inner
      .query_invalidation_generations
      .insert(query_epoch_bucket(target), next);
    if self.persist_disk_query_epochs(&inner).is_err() {
      inner
        .failed_query_invalidations
        .insert(query_epoch_bucket(target));
    }
    next
  }
}

pub(super) fn query_epoch_bucket(target: &CacheQueryInvalidationTarget) -> (String, u16) {
  let material = format!(
    "{}\n{}\n{}\n{}",
    target.policy, target.scheme, target.host, target.uri
  );
  let digest = crate::crypto::sha256(material.as_bytes());
  (
    target.policy.clone(),
    u16::from_be_bytes([digest[0], digest[1]]) % crate::cache::QUERY_EPOCH_BUCKETS,
  )
}
