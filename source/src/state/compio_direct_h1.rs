//! Snapshot staging for the process-local Compio direct-H1 worker service.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::Context;

use crate::circuit_breakers::CompioDirectH1Budget;
use crate::config::RuntimeDirectH1IoMode;
use crate::metrics::Metrics;
use crate::proxy::http::fast_path::direct_h1::{
  CompioDirectH1Service, CompioDirectH1ServicePlan, CompioDirectH1Staged,
};
use crate::runtime_health::RuntimeHealth;

use super::AppSnapshot;

const MAX_OVERLAPPING_FLEETS: usize = 2;

#[derive(Debug, Default)]
pub(crate) struct CompioDirectH1OverlapBudget {
  fleets: AtomicUsize,
}

impl CompioDirectH1OverlapBudget {
  fn try_reserve(self: &Arc<Self>) -> anyhow::Result<Arc<CompioDirectH1FleetReservation>> {
    self
      .fleets
      .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        (current < MAX_OVERLAPPING_FLEETS).then_some(current + 1)
      })
      .map_err(|current| {
        anyhow::anyhow!(
          "Compio direct-H1 fleet overlap budget exhausted at {current}/{MAX_OVERLAPPING_FLEETS}; wait for the retired fleet to stop before staging another replacement"
        )
      })?;
    Ok(Arc::new(CompioDirectH1FleetReservation {
      budget: Arc::clone(self),
      released: AtomicBool::new(false),
      published: AtomicBool::new(false),
    }))
  }

  #[cfg(test)]
  pub(super) fn fleets(&self) -> usize {
    self.fleets.load(Ordering::Acquire)
  }
}

#[derive(Debug)]
pub(crate) struct CompioDirectH1FleetReservation {
  budget: Arc<CompioDirectH1OverlapBudget>,
  released: AtomicBool,
  published: AtomicBool,
}

impl CompioDirectH1FleetReservation {
  pub(super) fn release(&self) {
    if self.released.swap(true, Ordering::AcqRel) {
      return;
    }
    let released =
      self
        .budget
        .fleets
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
          current.checked_sub(1)
        });
    debug_assert!(
      released.is_ok(),
      "Compio direct-H1 fleet reservation accounting must not underflow"
    );
  }

  fn can_publish(&self, service: &CompioDirectH1Service) -> bool {
    !self.released.load(Ordering::Acquire)
      && (!self.published.load(Ordering::Acquire) || service.is_healthy())
  }

  fn mark_published(&self) {
    self.published.store(true, Ordering::Release);
  }
}

impl Drop for CompioDirectH1FleetReservation {
  fn drop(&mut self) {
    self.release();
  }
}

type StagedService = (
  Arc<CompioDirectH1OverlapBudget>,
  Option<Arc<CompioDirectH1Service>>,
  Option<CompioDirectH1Staged>,
  Option<Arc<CompioDirectH1FleetReservation>>,
);

pub(super) fn stage_service(
  effective_io: RuntimeDirectH1IoMode,
  budget: Option<CompioDirectH1Budget>,
  plan_generation: u64,
  metrics: Arc<Metrics>,
  runtime_health: Arc<RuntimeHealth>,
  previous: Option<&AppSnapshot>,
) -> anyhow::Result<StagedService> {
  let overlap_budget = previous
    .map(|snapshot| Arc::clone(&snapshot.compio_direct_h1_overlap_budget))
    .unwrap_or_default();
  if effective_io != RuntimeDirectH1IoMode::Compio {
    return Ok((overlap_budget, None, None, None));
  }
  let budget = budget.context("Compio direct-H1 mode is missing its resolved service budget")?;
  let plan = service_plan(budget, plan_generation);
  if let Some(service) = previous.and_then(|snapshot| snapshot.compio_direct_h1_service.as_ref())
    && service.plan() == &plan
    && let Some(reservation) =
      previous.and_then(|snapshot| snapshot.compio_direct_h1_fleet_reservation.as_ref())
    && reservation.can_publish(service)
  {
    return Ok((
      overlap_budget,
      Some(Arc::clone(service)),
      None,
      Some(Arc::clone(reservation)),
    ));
  }

  let (service, staged, reservation) =
    stage_new_service(plan, metrics, runtime_health, &overlap_budget)?;
  Ok((
    overlap_budget,
    Some(service),
    Some(staged),
    Some(reservation),
  ))
}

fn stage_new_service(
  plan: CompioDirectH1ServicePlan,
  metrics: Arc<Metrics>,
  runtime_health: Arc<RuntimeHealth>,
  overlap_budget: &Arc<CompioDirectH1OverlapBudget>,
) -> anyhow::Result<(
  Arc<CompioDirectH1Service>,
  CompioDirectH1Staged,
  Arc<CompioDirectH1FleetReservation>,
)> {
  let reservation = overlap_budget.try_reserve()?;
  let tokio_handle = tokio::runtime::Handle::try_current()
    .context("Compio direct-H1 service staging requires an active Tokio runtime")?;
  let staged = CompioDirectH1Service::stage(plan, metrics, tokio_handle, runtime_health)
    .context("failed to stage the Compio direct-H1 worker service")?;
  Ok((staged.service(), staged, reservation))
}

fn service_plan(budget: CompioDirectH1Budget, plan_generation: u64) -> CompioDirectH1ServicePlan {
  CompioDirectH1ServicePlan {
    generation: plan_generation,
    worker_count: budget.worker_count,
    queue_capacity_per_worker: budget.queue_capacity_per_worker,
    max_waiters: budget.max_waiters,
    queue_wait_timeout: budget.queue_wait_timeout,
    max_connections_global: budget.max_connections_global,
    max_connections_per_origin: budget.max_connections_per_origin,
  }
}

impl AppSnapshot {
  pub(super) fn restage_compio_direct_h1_service_for_publication(&mut self) -> anyhow::Result<()> {
    if self.effective_direct_h1_io != RuntimeDirectH1IoMode::Compio {
      self.compio_direct_h1_service = None;
      self.staged_compio_direct_h1_service = None;
      self.compio_direct_h1_fleet_reservation = None;
      return Ok(());
    }
    let budget = self
      .compio_direct_h1_budget
      .context("Compio direct-H1 publication is missing its resolved service budget")?;
    let plan = service_plan(budget, self.direct_h1_plan_generation);
    let reusable = self
      .compio_direct_h1_service
      .as_ref()
      .is_some_and(|service| service.plan() == &plan)
      && self
        .compio_direct_h1_fleet_reservation
        .as_ref()
        .is_some_and(|reservation| {
          self
            .compio_direct_h1_service
            .as_ref()
            .is_some_and(|service| reservation.can_publish(service))
        });
    if reusable {
      return Ok(());
    }

    let (service, staged, reservation) = stage_new_service(
      plan,
      Arc::clone(&self.metrics),
      Arc::clone(&self.runtime_health),
      &self.compio_direct_h1_overlap_budget,
    )?;
    self.compio_direct_h1_service = Some(service);
    self.staged_compio_direct_h1_service = Some(staged);
    self.compio_direct_h1_fleet_reservation = Some(reservation);
    Ok(())
  }

  pub(super) fn activate_compio_direct_h1_service(&self) {
    let required = self.effective_direct_h1_io == RuntimeDirectH1IoMode::Compio;
    if let Some(staged) = self.staged_compio_direct_h1_service.as_ref() {
      let activated = staged.activate(self.runtime_generation, required);
      debug_assert!(
        self
          .compio_direct_h1_service
          .as_ref()
          .is_some_and(|service| Arc::ptr_eq(service, &activated)),
        "published Compio direct-H1 service must match its staged fleet"
      );
    } else if let Some(service) = self.compio_direct_h1_service.as_ref() {
      service.activate_generation(
        self.direct_h1_plan_generation,
        self.runtime_generation,
        required,
      );
    }
    if let Some(reservation) = self.compio_direct_h1_fleet_reservation.as_ref() {
      reservation.mark_published();
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn overlap_budget_allows_active_plus_one_replacement() {
    let budget = Arc::new(CompioDirectH1OverlapBudget::default());
    let active = budget.try_reserve().expect("active fleet reservation");
    let replacement = budget.try_reserve().expect("replacement fleet reservation");

    let error = budget
      .try_reserve()
      .expect_err("a third overlapping fleet must be rejected");
    assert!(error.to_string().contains("overlap budget exhausted"));
    assert_eq!(budget.fleets(), 2);

    active.release();
    let next = budget
      .try_reserve()
      .expect("retirement should free one replacement slot");
    assert_eq!(budget.fleets(), 2);

    replacement.release();
    next.release();
    assert_eq!(budget.fleets(), 0);
  }
}
