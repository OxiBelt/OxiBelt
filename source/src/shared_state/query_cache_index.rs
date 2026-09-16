//! Backend-native target indexes for bounded QUERY cache cleanup.

use super::cache_store::{shared_cache_chunk_stem, shared_cache_retention_until_ms};
use super::*;

const QUERY_CACHE_INDEX_VERSION: u8 = 1;
const REDIS_CHUNK_DELETE_BATCH: usize = 128;
const QUERY_CACHE_EXPIRY_BATCH: usize = 128;
const QUERY_CACHE_EXPIRY_MAX_PAGES: usize = 4;
const QUERY_CACHE_EXPIRY_TRIGGER_WRITES: u64 = 64;
const QUERY_CACHE_EXPIRY_INTERVAL: Duration = Duration::from_secs(60);

mod codec;
mod dispatch;
#[cfg(test)]
mod memory;
mod operations;
mod postgres;
mod redis;
#[cfg(test)]
mod tests;

use codec::*;
