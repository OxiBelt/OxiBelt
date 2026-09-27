#![deny(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

//! Admin mutation protocol, durable state, and fixed-member rollout mechanics.

pub mod admin_mutation;
