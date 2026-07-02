#![deny(unsafe_code)]

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
pub mod admin_audit;
pub mod admin_client;
pub(crate) mod admin_list;
pub mod cache;
pub mod client_identity;
pub mod config;
pub mod control_http;
pub(crate) mod crypto;
pub mod diagnostics;
pub mod dynamic_policy;
pub mod external_auth;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
mod h2_tuning;
pub mod identity;
pub mod ipm;
pub mod lifecycle;
pub mod limits;
mod listener_socket;
pub mod metrics;
pub mod mitigation;
pub mod netport_switcher;
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
pub mod runtime_introspection;
pub mod server;
pub mod shared_state;
pub(crate) mod sni_forward;
pub mod state;
pub mod stream;
pub(crate) mod stream_control;
mod tcp_hop;
mod tcp_socket;
pub mod telemetry;
pub mod tls;
pub mod turn;
pub mod upstream_control;
pub mod upstream_discovery;
pub mod waf;
pub mod webtransport_admin;

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
pub async fn run_with_options(config: Config, options: RunOptions) -> anyhow::Result<()> {
  let observability = runtime::init_observability(&config)?;
  config.validate()?;
  netport_switcher::ensure_required_runtime_socket(&config)?;
  config.log_worker_resolution();
  tls::install_default_provider()?;

  let state = AppHandle::new(
    AppSnapshot::new_with_telemetry(config, observability.into_telemetry())
      .await
      .context("failed to initialize application state")?,
  );
  server::serve(state, options.config_path, options.runtime_overrides).await
}
