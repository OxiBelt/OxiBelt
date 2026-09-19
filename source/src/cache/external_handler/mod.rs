//! External cache handler client and protocol glue.
//! OxiBelt remains authoritative for cache policy; handlers store already-admitted records.

mod client;
mod dictionary_client;
mod group_client;
mod group_protocol;
mod nvs_client;
mod nvs_protocol;
mod protocol;
mod runtime;

pub(crate) use client::ExternalCacheHttpClient;
pub(crate) use client::{ExternalCacheLookupHit, ExternalCachePublishBody};
pub(crate) use dictionary_client::{DictionaryStorageOperation, DictionaryStorageRequest};
pub(crate) use group_protocol::UnsupportedCacheGroups;
pub(crate) use nvs_protocol::{ExternalCacheNvsCandidatesRequest, ExternalCacheNvsEpochRequest};
pub(crate) use protocol::{
  CACHE_DICTIONARY_REPRESENTATION_CAPABILITY, CACHE_KEY_VERSION, ExternalCacheBody,
  ExternalCacheEntryMetadata, ExternalCacheHeader, ExternalCacheLookupRequest,
  ExternalCacheQueryCleanupRequest, ExternalCacheQueryEpochRequest, ExternalCacheVary,
  PROTOCOL_VERSION, required_capabilities_for_cache_key_version,
};
#[cfg(feature = "admin-runtime")]
pub(crate) use protocol::{ExternalCachePurgeKind, ExternalCachePurgeRequest};
#[cfg(feature = "admin-runtime")]
pub(crate) use runtime::ExternalCachePurgeReport;
pub(crate) use runtime::ExternalCacheQueryCleanupReport;
pub(crate) use runtime::ExternalCacheRuntime;
