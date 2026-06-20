//! Tokio compatibility runtime for dependencies that still require Tokio types.

use anyhow::Context;
use tokio::runtime::{Builder, Runtime};

pub fn build_runtime(worker_threads: usize) -> anyhow::Result<Runtime> {
  let mut builder = Builder::new_multi_thread();
  builder.enable_all();
  builder.worker_threads(worker_threads);
  builder
    .build()
    .context("failed to build Tokio compatibility runtime")
}
