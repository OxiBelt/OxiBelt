#![deny(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("oxibelt-proxy intentionally targets Linux only.");

#[cfg(not(any(
  target_arch = "x86_64",
  target_arch = "aarch64",
  target_arch = "riscv64"
)))]
compile_error!("oxibelt-proxy supports only x86_64, aarch64, and riscv64.");

pub mod access_log;
pub mod cache;
pub mod config;
pub mod control_http;
pub mod dynamic_policy;
pub mod external_auth;
mod h2_tuning;
pub mod identity;
pub mod lifecycle;
pub mod limits;
mod listener_socket;
pub mod metrics;
pub mod mitigation;
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
pub mod server;
pub mod shared_state;
pub mod state;
pub mod stream;
mod tcp_hop;
mod tcp_socket;
pub mod tls;
pub mod turn;
pub mod upstream_control;
pub mod upstream_discovery;
pub mod waf;

use anyhow::Context;
use config::{Config, RuntimeOverrides};
use state::{AppHandle, AppSnapshot};

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
  pub config_path: Option<std::path::PathBuf>,
  pub runtime_overrides: RuntimeOverrides,
}

pub async fn run(config: Config) -> anyhow::Result<()> {
  run_with_options(config, RunOptions::default()).await
}

pub async fn run_with_options(config: Config, options: RunOptions) -> anyhow::Result<()> {
  runtime::init_tracing(&config.logging)?;
  config.validate()?;
  config.log_worker_resolution();
  tls::install_default_provider()?;

  let state = AppHandle::new(
    AppSnapshot::new(config)
      .await
      .context("failed to initialize application state")?,
  );
  server::serve(state, options.config_path, options.runtime_overrides).await
}
