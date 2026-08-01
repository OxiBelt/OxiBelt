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
pub mod cache;
pub mod circuit_breakers;
pub mod client_identity;
pub mod config;
pub mod control_http;
pub(crate) mod crypto;
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
mod pool_health;
pub mod pools;
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

#[cfg(test)]
mod simd_bench;

use anyhow::Context;
use config::{Config, RuntimeOverrides};
use state::{AppHandle, AppSnapshot};

/// Runtime options that are not part of the persistent configuration file.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
  pub config_path: Option<std::path::PathBuf>,
  pub runtime_overrides: RuntimeOverrides,
}

/// Runs OxiBelt with a validated, in-memory configuration.
pub async fn run(config: Config) -> anyhow::Result<()> {
  run_with_options(config, RunOptions::default()).await
}

/// Runs OxiBelt with explicit runtime metadata for reload and admin surfaces.
pub async fn run_with_options(mut config: Config, options: RunOptions) -> anyhow::Result<()> {
  config.resolve_rollout_identity_from_environment()?;
  runtime::init_startup_logging(&config.logging)?;
  if let Some(mode) = config.runtime.hardening.seccomp.legacy_mode() {
    tracing::warn!(
      code = "CFG_RUNTIME_SECCOMP_MODE_COMPATIBILITY_ALIAS",
      legacy_mode = ?mode,
      expectation = config.runtime.hardening.seccomp.expectation.as_str(),
      "legacy runtime.hardening.seccomp.mode maps to runtime.hardening.seccomp.expectation"
    );
  }
  config.validate()?;
  if config.runtime.hardening.landlock.mode != config::RuntimeLandlockMode::Off {
    anyhow::bail!(
      "embedded_runtime_landlock_ownership_unproven: run_with_options cannot install thread-scoped Landlock for a caller-owned runtime; use the standalone binary or set runtime.hardening.landlock.mode = \"off\""
    );
  }
  configure_crypto_runtime(&config);
  netport_switcher::ensure_required_runtime_socket(&config)?;
  let filesystem_manifest = filesystem_access::FilesystemAccessManifest::from_config(&config)
    .context("failed to generate filesystem-access manifest")?;
  let manifest_projection = filesystem_manifest.landlock_projection();
  let hardening = hardening::apply_runtime_hardening_with_manifest_and_policy(
    &config.runtime.hardening,
    Some(&manifest_projection),
    hardening::RequiredHardeningFailurePolicy::for_operational_profile(
      config.operational_profile.as_ref(),
    ),
  )?;
  tracing::info!(
    hardening = %serde_json::to_string(&hardening)?,
    "resolved runtime hardening contract"
  );
  let telemetry = runtime::init_telemetry(&config)?;
  config.log_worker_resolution();
  tls::install_configured_provider(&config.crypto)?;

  let state = AppHandle::new(
    AppSnapshot::new_with_telemetry_and_hardening(config, telemetry, hardening)
      .await
      .context("failed to initialize application state")?,
  );
  server::serve(state, options.config_path, options.runtime_overrides).await
}

/// Applies the process-wide crypto primitive provider choices from a loaded config.
pub fn configure_crypto_runtime(config: &Config) {
  crypto::configure_runtime(&config.crypto);
}
