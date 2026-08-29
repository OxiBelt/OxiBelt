#![deny(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]
#![recursion_limit = "256"]

//! Application entrypoints and module wiring for the OxiBelt proxy runtime.
//! Keep this crate root declarative so ownership stays in focused modules.

#[cfg(not(target_os = "linux"))]
compile_error!("oxibelt-proxy intentionally targets Linux only.");

#[cfg(not(any(
  target_arch = "x86_64",
  target_arch = "aarch64",
  target_arch = "riscv64"
)))]
compile_error!("oxibelt-proxy supports only x86_64, aarch64, and riscv64.");

pub mod access_log;
pub mod activation_plan;
#[cfg(feature = "admin-runtime")]
pub mod admin_audit;
#[cfg(feature = "admin-runtime")]
pub mod admin_client;
#[cfg(feature = "admin-runtime")]
pub(crate) mod admin_list;
#[cfg(feature = "admin-runtime")]
pub mod admin_mutation;
mod application;
pub mod bandwidth;
pub mod cache;
pub mod circuit_breakers;
pub mod client_identity;
pub mod config;
pub mod control_http;
pub(crate) mod crypto;
pub mod ct;
pub mod ct_runtime;
pub mod diagnostics;
pub mod dynamic_policy;
pub mod external_auth;
pub mod filesystem_access;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod h2_tuning;
pub mod hardening;
pub mod identity;
pub mod ipm;
pub mod lifecycle;
pub mod limits;
mod listener_socket;
pub mod metrics;
pub mod mitigation;
pub mod netport_switcher;
pub mod overload;
pub(crate) mod platform_fs;
pub(crate) mod platform_resources;
mod pool_health;
pub mod pools;
mod process_globals;
pub mod proxy;
pub mod proxy_protocol;
pub mod proxy_protocol_egress;
pub mod quic;
pub mod reload;
pub mod remote_signer;
pub mod routes;
pub mod runtime;
pub(crate) mod runtime_health;
pub mod runtime_introspection;
pub(crate) mod secret_activation;
pub mod server;
pub mod shared_state;
pub(crate) mod sni_forward;
pub mod state;
pub mod stream;
#[cfg(feature = "admin-runtime")]
pub(crate) mod stream_control;
mod tcp_hop;
mod tcp_socket;
pub mod telemetry;
pub mod tls;
pub mod turn;
pub mod upstream_control;
pub mod upstream_discovery;
pub(crate) mod upstream_resolution;
pub mod waf;
#[cfg(feature = "admin-runtime")]
pub mod webtransport_admin;

pub use application::{
  ApplicationBuildError, EmbeddedServer, OwnedServer, OxiBelt, OxiBeltBuilder, RunOptions,
  StartupReport,
};
pub use process_globals::{
  ProcessGlobalError, ProcessGlobalHook, ProcessGlobalHookReport, ProcessGlobalHookStatus,
  ProcessGlobalHooks, ProcessGlobalReason, ProcessGlobalReport, ProcessGlobalSelection,
  ProcessPolicy, RuntimePolicy,
};

#[cfg(test)]
mod simd_bench;

use config::Config;

/// Runs OxiBelt with a validated, in-memory configuration.
#[deprecated(
  since = "0.7.1",
  note = "use OxiBelt::builder with explicit runtime and process policies"
)]
#[allow(deprecated)]
pub async fn run(config: Config) -> anyhow::Result<()> {
  run_with_options(config, RunOptions::default()).await
}

/// Runs OxiBelt with explicit runtime metadata for reload and admin surfaces.
#[deprecated(
  since = "0.7.1",
  note = "use OxiBelt::builder with explicit runtime and process policies"
)]
pub async fn run_with_options(config: Config, options: RunOptions) -> anyhow::Result<()> {
  if config.runtime.hardening.landlock.mode != config::RuntimeLandlockMode::Off {
    anyhow::bail!(
      "embedded_runtime_landlock_ownership_unproven: deprecated run wrappers cannot install configured Landlock; migrate to the explicit owned-runtime API"
    );
  }
  let handle = OxiBelt::builder(config)
    .run_options(options)
    .runtime_policy(RuntimePolicy::CurrentRuntime)
    .process_policy(ProcessPolicy::Embedded(ProcessGlobalHooks::CallerManaged))
    .build_embedded()?
    .start()
    .await?;
  let result = handle.wait().await?;
  if result.outcome == server::ShutdownOutcome::Failed {
    anyhow::bail!("server lifecycle failed");
  }
  Ok(())
}

/// Applies the process-wide crypto primitive provider choices from a loaded config.
#[deprecated(
  since = "0.7.1",
  note = "select crypto ownership through OxiBelt::builder and ProcessGlobalHooks"
)]
pub fn configure_crypto_runtime(config: &Config) {
  if crypto::configure_runtime(&config.crypto).is_err() {
    tracing::error!(
      code = "PROCESS_GLOBAL_CRYPTO_CONFLICT",
      "configured crypto primitives conflict with the active process claim"
    );
  }
}
