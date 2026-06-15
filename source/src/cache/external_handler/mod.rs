//! External cache handler client and protocol glue.
//! OxiBelt remains authoritative for cache policy; handlers store already-admitted records.

mod client;
mod protocol;
mod runtime;

pub(crate) use client::{ExternalCacheLookupHit, ExternalCachePublishBody};
pub(crate) use protocol::{
  CACHE_KEY_VERSION, ExternalCacheBody, ExternalCacheEntryMetadata, ExternalCacheHeader,
  ExternalCacheLookupRequest, ExternalCachePurgeKind, ExternalCachePurgeRequest, ExternalCacheVary,
  PROTOCOL_VERSION,
};
pub(crate) use runtime::{ExternalCachePurgeReport, ExternalCacheRuntime};
