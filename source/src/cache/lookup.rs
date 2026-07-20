//! Cache construction and lookup orchestration.

use super::*;

impl ResponseCache {
  pub fn new(
    config: &CacheConfig,
    shared_state: Option<Arc<SharedState>>,
  ) -> anyhow::Result<Arc<Self>> {
    Self::new_with_external_and_health(
      config,
      shared_state,
      ExternalCacheRuntime::disabled(crate::metrics::Metrics::new()),
      Arc::new(RuntimeHealth::default()),
    )
  }

  pub(crate) fn new_with_external_and_health(
    config: &CacheConfig,
    shared_state: Option<Arc<SharedState>>,
    external_cache: ExternalCacheRuntime,
    runtime_health: Arc<RuntimeHealth>,
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
      overload: ArcSwapOption::empty(),
    });
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

  pub fn is_cacheable_method(&self, method: &Method) -> bool {
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

  pub(super) fn operation_context(
    &self,
    policy_name: Option<&str>,
    scheme: &str,
    host: &str,
    method: &Method,
    uri: &Uri,
    request_headers: &HeaderMap,
  ) -> Option<CacheOperationContext> {
    let policy = self.policy(policy_name)?.clone();
    let base_key = expanded_cache_key(&policy.cache_key, scheme, host, uri, request_headers);
    let partition = expanded_cache_key(&policy.partition_key, scheme, host, uri, request_headers);
    let uri = uri.to_string();
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
    })
  }

  pub fn lookup(&self, ctx: CacheLookupContext<'_>) -> Option<CacheLookup> {
    if !self.policy_enabled(ctx.policy_name, ctx.method) {
      return None;
    }
    if request_no_store(ctx.request_headers, &self.bypass_request_headers) {
      return None;
    }
    let operation = self.operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
    )?;
    let now = SystemTime::now();
    let (key, entry) = {
      let mut inner = self.inner_guard();
      let key = inner
        .index
        .candidates(&operation.lookup_key)
        .and_then(|candidates| {
          candidates.into_iter().find(|key| {
            inner
              .entries
              .get(key)
              .is_some_and(|entry| vary_matches(&entry.vary, ctx.request_headers))
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

      let expired = inner
        .entries
        .get(&key)
        .is_some_and(|entry| entry.stale_if_error_until.unwrap_or(entry.expires_at) <= now);
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
    if request_no_cache(ctx.request_headers) || entry.must_revalidate || entry.expires_at <= now {
      let validators = validator_headers(&entry.headers);
      if !request_no_cache(ctx.request_headers)
        && !entry.must_revalidate
        && entry
          .stale_while_revalidate_until
          .is_some_and(|until| until > now)
      {
        return Some(CacheLookup::Stale(StaleEntry {
          entry: cache_entry,
          request_headers: validators,
          serve_stale_on_error: entry.stale_if_error_until.is_some_and(|until| until > now),
          background_refresh: operation.policy.background_refresh,
        }));
      }
      if validators.is_empty() {
        if entry
          .stale_while_revalidate_until
          .is_some_and(|until| until > now)
        {
          return Some(CacheLookup::Stale(StaleEntry {
            entry: cache_entry,
            request_headers: HeaderMap::new(),
            serve_stale_on_error: entry.stale_if_error_until.is_some_and(|until| until > now),
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
        serve_stale_on_error: entry.stale_if_error_until.is_some_and(|until| until > now),
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
    if let Some(lookup) = self.lookup(ctx.clone()) {
      return Some(lookup);
    }
    if !self.policy_enabled(ctx.policy_name, ctx.method)
      || request_no_store(ctx.request_headers, &self.bypass_request_headers)
    {
      return None;
    }
    let operation = self.operation_context(
      ctx.policy_name,
      ctx.scheme,
      ctx.host,
      ctx.method,
      ctx.uri,
      ctx.request_headers,
    )?;
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
        policy_name: ctx.policy_name,
        scheme: ctx.scheme,
        host: ctx.host,
        method: ctx.method,
        uri: ctx.uri,
        request_headers: ctx.request_headers,
      },
      entry,
      false,
    );
  }
}
