//! Process-local bounded admission and upstream failure circuits.
//!
//! This layer is intentionally separate from overload sampling: overload reacts
//! to process pressure, while circuit breakers enforce configured request and
//! upstream budgets even when the process is otherwise healthy.

mod circuit;
mod configuration;
mod metrics;
mod priority;
mod queue;
mod resources;
mod runtime;
mod types;

#[cfg(test)]
mod priority_tests;
#[cfg(test)]
mod queue_fairness_tests;
#[cfg(test)]
mod retry_budget_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_budget_tests;

pub(crate) use resources::{CompioDirectH1Budget, compio_direct_h1_budget};
pub use runtime::{
  AdmissionLease, AdmissionRejection, AdmissionRejectionReason, CircuitBreakerRuntime,
  CircuitOutcome, CircuitOutcomeFailure,
};
