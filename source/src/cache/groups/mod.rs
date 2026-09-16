//! RFC 9875 grouping, origin isolation, and bounded invalidation coherence.

mod authority;
mod fields;
pub(super) mod model;
mod origin;
mod response_guard;
mod runtime;

pub(super) use authority::GroupRuntime;
pub use model::CacheGroupStamp;
pub use origin::CacheGroupOrigin;
pub use runtime::CacheGroupRequest;

pub(super) fn metadata_size(stamp: Option<&CacheGroupStamp>) -> usize {
  stamp.map_or(0, |stamp| {
    serde_json::to_vec(stamp).map_or(usize::MAX, |bytes| bytes.len())
  })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod lifecycle_tests;

#[cfg(test)]
mod activation_tests;
