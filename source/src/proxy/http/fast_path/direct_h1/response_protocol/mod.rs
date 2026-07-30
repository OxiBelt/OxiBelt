//! Incremental, transport-independent upstream HTTP/1 response protocol engine.

mod chunked;
mod engine;
mod head;
mod types;

pub(crate) use self::engine::ResponseProtocolEngine;
#[cfg(test)]
pub(crate) use self::types::ResponseStateLabel;
pub(crate) use self::types::{
  ResponseBodyMode, ResponseEvent, ResponseProtocolError, ResponseProtocolFailureReason,
  ResponseProtocolLimits, ResponseState, ResponseStep,
};

#[cfg(test)]
mod differential_tests;
#[cfg(test)]
mod tests;
