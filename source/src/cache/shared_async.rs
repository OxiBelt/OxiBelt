//! Async shared-cache lookup bridge.

use tracing::warn;

use super::{CacheLookup, CacheLookupContext, ResponseCache, request_no_cache};

impl ResponseCache {
  pub(super) async fn lookup_shared_async(
    &self,
    policy: &str,
    background_refresh: bool,
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
        ctx.request_headers,
        request_no_cache(ctx.request_headers),
        background_refresh,
      )
      .await
    {
      Ok(Some(lookup)) => {
        if matches!(lookup, CacheLookup::Fresh(_)) {
          self.promote_shared_lookup(ctx, &lookup);
        }
        Some(lookup)
      }
      Ok(None) => None,
      Err(error) => {
        warn!(error = %error, "shared cache lookup failed; falling back to local miss");
        None
      }
    }
  }
}
