//! Proxy, buffering, compression, and cache validation.

use super::*;

impl Config {
  pub(super) fn validate_proxy(&self) -> anyhow::Result<()> {
    if self.proxy.retry.tries == 0 {
      bail!("proxy.retry.tries must be greater than 0");
    }
    if self.proxy.retry.timeout_ms == 0 {
      bail!("proxy.retry.timeout_ms must be greater than 0");
    }
    if self.proxy.retry.total_budget_ms == Some(0) {
      bail!("proxy.retry.total_budget_ms must be greater than 0");
    }
    if self.proxy.retry.per_attempt_timeout_ms == Some(0) {
      bail!("proxy.retry.per_attempt_timeout_ms must be greater than 0");
    }
    if self.proxy.retry.backoff_max_ms > 0
      && self.proxy.retry.backoff_base_ms > self.proxy.retry.backoff_max_ms
    {
      bail!(
        "proxy.retry.backoff_max_ms must be 0 or greater than or equal to proxy.retry.backoff_base_ms"
      );
    }
    if self.proxy.http.direct_h1_small_request_body_max_bytes == 0 {
      bail!("proxy.http.direct_h1_small_request_body_max_bytes must be greater than 0");
    }
    #[cfg(not(target_os = "linux"))]
    if self.runtime.direct_h1_io == RuntimeDirectH1IoMode::Compio {
      bail!("runtime.direct_h1_io = \"compio\" is Linux-only");
    }
    if self.proxy.http2.max_concurrent_streams == 0
      || self.proxy.http2.max_send_buf_size == 0
      || self.proxy.http2.keep_alive_timeout_ms == 0
      || self
        .proxy
        .http2
        .initial_stream_window_bytes
        .is_some_and(|value| value == 0)
      || self
        .proxy
        .http2
        .initial_connection_window_bytes
        .is_some_and(|value| value == 0)
      || self
        .proxy
        .http2
        .max_frame_size_bytes
        .is_some_and(|value| value == 0)
    {
      bail!(
        "proxy.http2 numeric values must be greater than 0, except keep_alive_interval_ms = 0 disables keep-alive pings"
      );
    }
    if self.proxy.http2.adaptive_window
      && (self.proxy.http2.initial_stream_window_bytes.is_some()
        || self.proxy.http2.initial_connection_window_bytes.is_some()
        || self.proxy.http2.max_frame_size_bytes.is_some())
    {
      bail!("proxy.http2 manual window and frame-size values require adaptive_window = false");
    }
    self
      .proxy
      .upstream_revocation
      .validate("proxy.upstream_revocation")?;
    const HTTP2_MAX_WINDOW_BYTES: u32 = (1 << 31) - 1;
    if self
      .proxy
      .http2
      .initial_stream_window_bytes
      .is_some_and(|value| value > HTTP2_MAX_WINDOW_BYTES)
      || self
        .proxy
        .http2
        .initial_connection_window_bytes
        .is_some_and(|value| value > HTTP2_MAX_WINDOW_BYTES)
    {
      bail!("proxy.http2 initial window values must be at most 2147483647 bytes");
    }
    const HTTP2_MIN_MAX_FRAME_SIZE_BYTES: u32 = 16_384;
    const HTTP2_MAX_MAX_FRAME_SIZE_BYTES: u32 = 16_777_215;
    if self.proxy.http2.max_frame_size_bytes.is_some_and(|value| {
      !(HTTP2_MIN_MAX_FRAME_SIZE_BYTES..=HTTP2_MAX_MAX_FRAME_SIZE_BYTES).contains(&value)
    }) {
      bail!("proxy.http2.max_frame_size_bytes must be between 16384 and 16777215 bytes");
    }
    if self.proxy.static_files.open_file_cache_max_entries > 0
      && self.proxy.static_files.open_file_cache_ttl_ms == 0
    {
      bail!(
        "proxy.static_files.open_file_cache_ttl_ms must be greater than 0 when open_file_cache_max_entries is set"
      );
    }
    if self.proxy.static_files.sendfile_chunk_bytes == 0 {
      bail!("proxy.static_files.sendfile_chunk_bytes must be greater than 0");
    }
    if self.proxy.static_files.hot_object_cache_max_bytes > 0 {
      if self.proxy.static_files.open_file_cache_max_entries == 0 {
        bail!(
          "proxy.static_files.hot_object_cache_max_bytes requires open_file_cache_max_entries greater than 0"
        );
      }
      if self.proxy.static_files.hot_object_cache_max_file_bytes == 0 {
        bail!(
          "proxy.static_files.hot_object_cache_max_file_bytes must be greater than 0 when hot_object_cache_max_bytes is set"
        );
      }
    }
    self.validate_buffering()?;
    for cidr in &self.proxy.real_ip.trusted_proxies {
      crate::identity::Cidr::parse(cidr)
        .with_context(|| format!("invalid proxy.real_ip.trusted_proxies entry {cidr}"))?;
    }
    Ok(())
  }

  pub(super) fn validate_buffering(&self) -> anyhow::Result<()> {
    let mut requires_temp_dir = false;
    validate_effective_buffering(
      "proxy.buffering",
      self.proxy.buffering.request,
      self.proxy.buffering.max_temp_file_bytes,
      &mut requires_temp_dir,
    )?;
    validate_effective_buffering(
      "proxy.buffering",
      self.proxy.buffering.response,
      self.proxy.buffering.max_temp_file_bytes,
      &mut requires_temp_dir,
    )?;

    for route in &self.routes {
      let request = route
        .buffering
        .request
        .unwrap_or(self.proxy.buffering.request);
      let response = route
        .buffering
        .response
        .unwrap_or(self.proxy.buffering.response);
      let max_temp_file_bytes = route
        .buffering
        .max_temp_file_bytes
        .unwrap_or(self.proxy.buffering.max_temp_file_bytes);
      validate_effective_buffering(
        &format!("route {} buffering", route.name),
        request,
        max_temp_file_bytes,
        &mut requires_temp_dir,
      )?;
      validate_effective_buffering(
        &format!("route {} buffering", route.name),
        response,
        max_temp_file_bytes,
        &mut requires_temp_dir,
      )?;
    }

    if requires_temp_dir {
      let dir =
        self.proxy.buffering.temp_dir.as_ref().ok_or_else(|| {
          anyhow!("proxy.buffering.temp_dir is required when buffering uses spool")
        })?;
      crate::cache::validate_disk_dir(dir)?;
    }
    Ok(())
  }

  pub(super) fn validate_compression(&self) -> anyhow::Result<()> {
    validate_compression_level("compression.level", self.compression.level)?;
    validate_compression_proxied("compression.proxied", &self.compression.proxied)?;
    validate_compression_statuses("compression.statuses", &self.compression.statuses)?;
    validate_compression_mime_types("compression.mime_types", &self.compression.mime_types)?;

    let mut names = HashSet::new();
    for policy in &self.compression.policies {
      if policy.name.trim().is_empty() {
        bail!("compression policy name must not be empty");
      }
      if matches!(policy.name.as_str(), "default" | "off") {
        bail!("compression policy name {} is reserved", policy.name);
      }
      if !names.insert(policy.name.as_str()) {
        bail!("duplicate compression policy name {}", policy.name);
      }
      validate_compression_level(
        &format!("compression policy {} level", policy.name),
        policy.level,
      )?;
      validate_compression_proxied(
        &format!("compression policy {} proxied", policy.name),
        &policy.proxied,
      )?;
      validate_compression_statuses(
        &format!("compression policy {} statuses", policy.name),
        &policy.statuses,
      )?;
      validate_compression_mime_types(
        &format!("compression policy {} mime_types", policy.name),
        &policy.mime_types,
      )?;
    }

    Ok(())
  }

  pub(super) fn validate_cache(&self) -> anyhow::Result<()> {
    if self.cache.max_size_bytes == 0 {
      bail!("cache.max_size_bytes must be greater than 0");
    }
    if let Some(memory_max_size_bytes) = self.cache.memory_max_size_bytes
      && memory_max_size_bytes == 0
    {
      bail!("cache.memory_max_size_bytes must be greater than 0 when configured");
    }
    if let Some(disk_max_size_bytes) = self.cache.disk_max_size_bytes
      && disk_max_size_bytes == 0
    {
      bail!("cache.disk_max_size_bytes must be greater than 0 when configured");
    }
    if !(0.0..=1.0).contains(&self.cache.memory_auto_fraction)
      || self.cache.memory_auto_fraction == 0.0
    {
      bail!("cache.memory_auto_fraction must be greater than 0.0 and less than or equal to 1.0");
    }
    if self.cache.default_ttl_seconds == 0 {
      bail!("cache.default_ttl_seconds must be greater than 0");
    }
    if self.cache.store == CacheStore::Tmpfs && self.cache.enabled {
      let dir = self
        .cache
        .tmpfs_dir
        .clone()
        .unwrap_or_else(default_cache_tmpfs_dir);
      crate::cache::validate_tmpfs_dir(&dir)?;
    }
    if self.cache.enabled && self.cache.store.uses_disk() {
      let dir = self
        .cache
        .disk_dir
        .as_ref()
        .ok_or_else(|| anyhow!("cache.disk_dir is required when cache.store uses disk"))?;
      crate::cache::validate_disk_dir(dir)?;
      if self.cache.disk_max_size_bytes.is_none() {
        bail!("cache.disk_max_size_bytes is required when cache.store uses disk");
      }
    }
    for status in &self.cache.negative_statuses {
      http::StatusCode::from_u16(*status)
        .with_context(|| format!("cache.negative_statuses contains invalid status {status}"))?;
    }
    if !self.cache.negative_statuses.is_empty() && self.cache.negative_ttl_seconds == 0 {
      bail!("cache.negative_ttl_seconds must be greater than 0 when negative_statuses is set");
    }
    validate_cache_tag_headers("cache.tag_headers", &self.cache.tag_headers)?;
    if self.cache.max_tags_per_entry == 0 {
      bail!("cache.max_tags_per_entry must be greater than 0");
    }
    if self.cache.max_tag_bytes == 0 {
      bail!("cache.max_tag_bytes must be greater than 0");
    }
    if self.cache.max_vary_fields == 0 {
      bail!("cache.max_vary_fields must be greater than 0");
    }
    if self.cache.max_vary_variants_per_key == 0 {
      bail!("cache.max_vary_variants_per_key must be greater than 0");
    }
    validate_cache_bypass_headers(
      "cache.bypass_request_headers",
      &self.cache.bypass_request_headers,
    )?;
    if self.cache.stream_chunk_bytes == 0 {
      bail!("cache.stream_chunk_bytes must be greater than 0");
    }
    if self.cache.background_refresh_max_concurrent == 0 {
      bail!("cache.background_refresh_max_concurrent must be greater than 0");
    }
    if self.cache.lock_wait_timeout_ms == 0 {
      bail!("cache.lock_wait_timeout_ms must be greater than 0");
    }
    #[cfg(not(target_os = "linux"))]
    if self.cache.copy_file_range == CacheCopyFileRangeMode::Required {
      bail!("cache.copy_file_range = \"required\" is Linux-only");
    }
    validate_cache_admission("cache.admission", &self.cache.admission, &self.cache)?;
    validate_cache_stale_if_error("cache.stale_if_error", &self.cache.stale_if_error)?;
    let external_handler_names = cache_external::validate_external_handlers(&self.cache)?;
    cache_external::validate_external_handler_reference(
      "cache.external_handler",
      self.cache.external_handler.as_deref(),
      &external_handler_names,
      false,
    )?;

    let mut names = HashSet::new();
    for policy in &self.cache.policies {
      if policy.name.trim().is_empty() {
        bail!("cache policy name must not be empty");
      }
      if policy.name == "default" {
        bail!("cache policy name default is reserved");
      }
      if !names.insert(policy.name.as_str()) {
        bail!("duplicate cache policy name {}", policy.name);
      }
      if let Some(default_ttl_seconds) = policy.default_ttl_seconds
        && default_ttl_seconds == 0
      {
        bail!(
          "cache policy {} default_ttl_seconds must be greater than 0",
          policy.name
        );
      }
      if let Some(negative_statuses) = &policy.negative_statuses {
        for status in negative_statuses {
          http::StatusCode::from_u16(*status).with_context(|| {
            format!(
              "cache policy {} negative_statuses contains invalid status {status}",
              policy.name
            )
          })?;
        }
        if !negative_statuses.is_empty() && policy.negative_ttl_seconds.unwrap_or(0) == 0 {
          bail!(
            "cache policy {} negative_ttl_seconds must be greater than 0 when negative_statuses is set",
            policy.name
          );
        }
      } else if policy.negative_ttl_seconds.is_some() {
        bail!(
          "cache policy {} negative_ttl_seconds requires negative_statuses",
          policy.name
        );
      }
      if let Some(memory_max_size_bytes) = policy.memory_max_size_bytes
        && memory_max_size_bytes == 0
      {
        bail!(
          "cache policy {} memory_max_size_bytes must be greater than 0",
          policy.name
        );
      }
      if let Some(disk_max_size_bytes) = policy.disk_max_size_bytes
        && disk_max_size_bytes == 0
      {
        bail!(
          "cache policy {} disk_max_size_bytes must be greater than 0",
          policy.name
        );
      }
      if let Some(tag_headers) = &policy.tag_headers {
        validate_cache_tag_headers(
          &format!("cache policy {} tag_headers", policy.name),
          tag_headers,
        )?;
      }
      if policy.max_tags_per_entry == Some(0) {
        bail!(
          "cache policy {} max_tags_per_entry must be greater than 0",
          policy.name
        );
      }
      if policy.max_tag_bytes == Some(0) {
        bail!(
          "cache policy {} max_tag_bytes must be greater than 0",
          policy.name
        );
      }
      if policy.max_vary_fields == Some(0) {
        bail!(
          "cache policy {} max_vary_fields must be greater than 0",
          policy.name
        );
      }
      if policy.max_vary_variants_per_key == Some(0) {
        bail!(
          "cache policy {} max_vary_variants_per_key must be greater than 0",
          policy.name
        );
      }
      if policy.background_refresh_max_concurrent == Some(0) {
        bail!(
          "cache policy {} background_refresh_max_concurrent must be greater than 0",
          policy.name
        );
      }
      if policy.lock_wait_timeout_ms == Some(0) {
        bail!(
          "cache policy {} lock_wait_timeout_ms must be greater than 0",
          policy.name
        );
      }
      if let Some(admission) = &policy.admission {
        validate_cache_admission(
          &format!("cache policy {} admission", policy.name),
          admission,
          &self.cache,
        )?;
      }
      if let Some(stale_if_error) = &policy.stale_if_error {
        validate_cache_stale_if_error(
          &format!("cache policy {} stale_if_error", policy.name),
          stale_if_error,
        )?;
      }
      cache_external::validate_external_handler_reference(
        &format!("cache policy {} external_handler", policy.name),
        policy.external_handler.as_deref(),
        &external_handler_names,
        true,
      )?;
      if policy.store == Some(CacheStore::Tmpfs) && self.cache.enabled {
        let dir = self
          .cache
          .tmpfs_dir
          .clone()
          .unwrap_or_else(default_cache_tmpfs_dir);
        crate::cache::validate_tmpfs_dir(&dir)?;
      }
      if policy.store.is_some_and(CacheStore::uses_disk) {
        let dir = self
          .cache
          .disk_dir
          .as_ref()
          .ok_or_else(|| anyhow!("cache.disk_dir is required when cache policy uses disk"))?;
        if self.cache.enabled {
          crate::cache::validate_disk_dir(dir)?;
        }
        if policy
          .disk_max_size_bytes
          .or(self.cache.disk_max_size_bytes)
          .is_none()
        {
          bail!(
            "cache.disk_max_size_bytes or cache policy {} disk_max_size_bytes is required when policy uses disk",
            policy.name
          );
        }
      }
      for rule in &policy.rules {
        if rule.mime_types.is_empty() {
          bail!(
            "cache policy {} rule must include at least one MIME pattern",
            policy.name
          );
        }
        validate_compression_mime_types(
          &format!("cache policy {} rule mime_types", policy.name),
          &rule.mime_types,
        )?;
        if rule.store.uses_disk() {
          let dir = self.cache.disk_dir.as_ref().ok_or_else(|| {
            anyhow!("cache.disk_dir is required when cache policy rule uses disk")
          })?;
          if self.cache.enabled {
            crate::cache::validate_disk_dir(dir)?;
          }
          if policy
            .disk_max_size_bytes
            .or(self.cache.disk_max_size_bytes)
            .is_none()
          {
            bail!(
              "cache.disk_max_size_bytes or cache policy {} disk_max_size_bytes is required when rule uses disk",
              policy.name
            );
          }
        }
      }
    }
    Ok(())
  }
}
