//! Direct upstream HTTP/2 transport for the plain-proxy fast path.
//! It is limited to direct empty-body safe requests and falls back for all broader semantics.

#[cfg(test)]
use super::request_body::FastPathRequestBodyMode;
#[cfg(test)]
use crate::config::{HttpVersion, ProxyProtocolEgressMode};
#[cfg(test)]
use crate::metrics::fast_path::labels::FastPathTransportMissReason;
#[cfg(test)]
use crate::proxy::http::EffectiveTimeouts;
#[cfg(test)]
use http::Method;

mod connection;
mod metrics;
mod pool;
mod request;
mod send;

pub(in crate::proxy::http::fast_path) use self::pool::DirectH2Lease;
pub(crate) use self::pool::DirectH2Pools;
use self::pool::{DirectH2Pool, DirectH2Response, DirectH2Sender};
#[cfg(test)]
use self::request::PreparedDirectH2Request;
#[cfg(test)]
use self::request::empty_body;
#[cfg(test)]
use self::send::direct_h2_guard_miss;
pub(in crate::proxy::http::fast_path) use self::send::{
  DirectH2SendResult, release_response_body, try_send_direct_h2,
};

const DIRECT_H2_MAX_SLOTS: usize = 16;
const DIRECT_H2_STREAMS_PER_SLOT_SOFT_LIMIT: usize = 32;

#[cfg(test)]
mod tests;
