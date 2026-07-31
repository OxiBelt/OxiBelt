//! Portable type boundary for the Linux-only Compio direct-H1 service.

use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::Handle;

use crate::metrics::Metrics;
use crate::runtime_health::RuntimeHealth;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompioDirectH1ServicePlan {
  pub(crate) generation: u64,
  pub(crate) worker_count: usize,
  pub(crate) queue_capacity_per_worker: usize,
  pub(crate) max_waiters: usize,
  pub(crate) queue_wait_timeout: Duration,
  pub(crate) max_connections_global: usize,
  pub(crate) max_connections_per_origin: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CompioDirectH1ShutdownSummary {
  pub(crate) workers_started: usize,
  pub(crate) workers_joined: usize,
  pub(crate) worker_failures: usize,
  pub(crate) operations_cancelled: usize,
  pub(crate) queued_operations_rejected: usize,
}

#[derive(Clone)]
pub(crate) struct CompioDirectH1Staged {
  service: Arc<CompioDirectH1Service>,
}

impl CompioDirectH1Staged {
  pub(crate) fn service(&self) -> Arc<CompioDirectH1Service> {
    Arc::clone(&self.service)
  }

  pub(crate) fn activate(
    &self,
    runtime_generation: u64,
    required: bool,
  ) -> Arc<CompioDirectH1Service> {
    self
      .service
      .activate_generation(self.service.plan.generation, runtime_generation, required);
    Arc::clone(&self.service)
  }
}

pub(crate) struct CompioDirectH1Service {
  plan: CompioDirectH1ServicePlan,
}

impl CompioDirectH1Service {
  pub(crate) fn stage(
    _plan: CompioDirectH1ServicePlan,
    _metrics: Arc<Metrics>,
    _tokio_handle: Handle,
    _runtime_health: Arc<RuntimeHealth>,
  ) -> anyhow::Result<CompioDirectH1Staged> {
    anyhow::bail!("persistent Compio direct-H1 service is Linux-only")
  }

  pub(crate) fn plan(&self) -> &CompioDirectH1ServicePlan {
    &self.plan
  }

  pub(crate) fn activate_generation(
    &self,
    _plan_generation: u64,
    _runtime_generation: u64,
    _required: bool,
  ) {
  }

  pub(crate) fn is_healthy(&self) -> bool {
    false
  }

  pub(crate) fn is_required(&self) -> bool {
    false
  }

  pub(crate) fn begin_drain(&self) {}

  pub(crate) async fn shutdown(
    &self,
    _deadline: tokio::time::Instant,
  ) -> CompioDirectH1ShutdownSummary {
    CompioDirectH1ShutdownSummary::default()
  }
}
