#![deny(unsafe_code)]
#![cfg_attr(feature = "fuzzing", allow(dead_code))]

#[cfg(feature = "fuzzing")]
mod config_migrate_transform;
#[cfg(feature = "fuzzing")]
mod fingerprint;
#[cfg(feature = "fuzzing")]
mod supply_chain_workload_policy;

#[cfg(feature = "fuzzing")]
pub mod fuzzing;
