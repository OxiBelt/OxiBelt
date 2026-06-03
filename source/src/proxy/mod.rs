//! Data-plane protocol handlers.
//! Shared policy remains in sibling modules so HTTP, HTTP/3, and stream handling stay comparable.

pub mod http;
pub(crate) mod http3;
pub(crate) mod stream_waf;
