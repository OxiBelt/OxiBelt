//! Async shared-cache lookup bridge.

use tracing::warn;

use crate::config::BackendFailureMode;
use crate::shared_state::SharedStateFeature;

use super::{CacheLookup, CacheLookupContext, ResponseCache, request_no_cache};

impl ResponseCache {
  pub(super) async fn lookup_shared_async(
    &self,
    policy: &str,
    background_refresh: bool,
    max_vary_variants: usize,
    partition: &str,
    base_key: &str,
    ctx: CacheLookupContext<'_>,
  ) -> Option<CacheLookup> {
    let shared = self.shared_state.as_ref()?;
    if !shared.has_cache() {
      return None;
    }
    let uri = ctx.uri.to_string();
    match shared
      .cache_lookup(
        policy,
        ctx.scheme,
        ctx.host,
        partition,
        base_key,
        &uri,
        ctx.method,
        super::lookup::cache_view_headers(&ctx),
        request_no_cache(super::lookup::cache_view_headers(&ctx)),
        background_refresh,
        max_vary_variants,
        ctx
          .query_identity
          .and_then(crate::cache::CacheQueryIdentity::query_target_epoch),
      )
      .await
    {
      Ok(Some(lookup)) => {
        let entry = match &lookup {
          CacheLookup::Fresh(entry) => entry,
          CacheLookup::Stale(stale) => &stale.entry,
          CacheLookup::Revalidate(revalidation) => &revalidation.entry,
        };
        if let Some(metadata) = entry.no_vary_search.as_ref() {
          let owner_uri = metadata.owner_uri.parse().ok()?;
          if !metadata.valid()
            || metadata.owner_uri != uri
            || self
              .nvs_epoch(
                &super::nvs::target(policy, ctx.scheme, ctx.host, &owner_uri),
                false,
              )
              .await
              != Some(metadata.epoch)
            || self
              .nvs_epoch(&super::nvs::policy_target(policy), false)
              .await
              != Some(metadata.policy_epoch)
          {
            return None;
          }
        }
        if matches!(lookup, CacheLookup::Fresh(_)) {
          self.promote_shared_lookup(ctx, &lookup);
        }
        Some(lookup)
      }
      Ok(None) => None,
      Err(error) => {
        if shared.backend_failure_mode(SharedStateFeature::Cache)
          == BackendFailureMode::LocalFallback
        {
          shared.record_backend_local_fallback(SharedStateFeature::Cache);
        }
        warn!(error = %error, "shared cache lookup failed; falling back to local miss");
        None
      }
    }
  }
}
