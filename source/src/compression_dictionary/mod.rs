//! RFC 9842 representation dictionaries. Configuration, wire parsing, codecs,
//! and runtime storage have separate ownership and trust boundaries.

pub mod codec;
pub mod fields;
pub mod runtime;
pub(crate) mod storage;
