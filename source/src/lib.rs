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
pub mod config;
pub mod proxy;
pub mod routes;
pub mod runtime;
pub mod server;
pub mod state;
mod tcp_hop;
pub mod tls;
pub mod waf;

use std::sync::Arc;

use anyhow::Context;
use config::Config;
use state::AppState;

pub async fn run(config: Config) -> anyhow::Result<()> {
  runtime::init_tracing(&config.logging)?;
  config.validate()?;
  tls::install_default_provider()?;

  let state = Arc::new(
    AppState::new(config)
      .await
      .context("failed to initialize application state")?,
  );
  server::serve(state).await
}
