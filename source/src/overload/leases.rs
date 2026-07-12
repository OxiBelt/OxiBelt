use std::sync::Arc;
use std::sync::atomic::Ordering;

use http::Version;

use super::{CONTROL_PLANE_COUNT, OverloadBoundary, OverloadRuntime, OverloadState, WorkKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverloadRejection {
  pub boundary: OverloadBoundary,
}

/// A cancellation-safe lease for one sampled unit of active work.
pub struct WorkLease {
  runtime: Option<Arc<OverloadRuntime>>,
  kind: WorkKind,
  amount: u64,
}

impl std::fmt::Debug for WorkLease {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("WorkLease")
      .field("kind", &self.kind)
      .field("amount", &self.amount)
      .finish_non_exhaustive()
  }
}

impl WorkLease {
  pub(super) fn disabled(kind: WorkKind) -> Self {
    Self {
      runtime: None,
      kind,
      amount: 0,
    }
  }
}

impl Drop for WorkLease {
  fn drop(&mut self) {
    if let Some(runtime) = self.runtime.as_ref() {
      runtime.work[self.kind as usize].fetch_sub(self.amount, Ordering::Relaxed);
    }
  }
}

#[derive(Debug)]
pub struct RequestLease {
  _request: WorkLease,
  _stream: Option<WorkLease>,
}

/// Dedicated listener class whose bounded control capacity is independent of public traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlPlane {
  Admin,
  Health,
  Metrics,
}

impl ControlPlane {
  pub(super) const ALL: [Self; CONTROL_PLANE_COUNT] = [Self::Admin, Self::Health, Self::Metrics];

  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Admin => "admin",
      Self::Health => "health",
      Self::Metrics => "metrics",
    }
  }
}

#[derive(Clone, Copy)]
enum ControlSlot {
  Connection,
  Request,
}

pub struct ControlLease {
  runtime: Option<Arc<OverloadRuntime>>,
  plane: ControlPlane,
  slot: ControlSlot,
}

impl ControlLease {
  fn disabled(plane: ControlPlane, slot: ControlSlot) -> Self {
    Self {
      runtime: None,
      plane,
      slot,
    }
  }
}

impl Drop for ControlLease {
  fn drop(&mut self) {
    let Some(runtime) = self.runtime.as_ref() else {
      return;
    };
    let counters = match self.slot {
      ControlSlot::Connection => &runtime.control_connections,
      ControlSlot::Request => &runtime.control_requests,
    };
    counters[self.plane as usize].fetch_sub(1, Ordering::Relaxed);
  }
}

impl OverloadRuntime {
  pub fn lease(self: &Arc<Self>, kind: WorkKind, amount: u64) -> WorkLease {
    if !self.enabled.load(Ordering::Relaxed) || amount == 0 {
      return WorkLease::disabled(kind);
    }
    self.work[kind as usize].fetch_add(amount, Ordering::Relaxed);
    WorkLease {
      runtime: Some(self.clone()),
      kind,
      amount,
    }
  }

  pub fn try_admit_expensive(self: &Arc<Self>, kind: WorkKind) -> Option<WorkLease> {
    if !self.enabled.load(Ordering::Relaxed) {
      return Some(WorkLease::disabled(kind));
    }
    let config = self
      .config
      .read()
      .expect("overload configuration lock poisoned");
    if self.state() == OverloadState::Hard && config.actions.hard.reject_expensive_waf_bodies {
      return None;
    }
    let configured_cap = match kind {
      WorkKind::WafBodyInspectionConcurrency => {
        config.actions.soft.waf_body_inspection_concurrency_cap
      }
      WorkKind::DecompressionJobs => config.actions.soft.decompression_concurrency_cap,
      _ => return Some(self.lease(kind, 1)),
    };
    let capped = self.state() != OverloadState::Normal;
    drop(config);
    if !capped {
      return Some(self.lease(kind, 1));
    }
    let cap = if configured_cap == 0 {
      std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1)
    } else {
      configured_cap
    } as u64;
    let counter = &self.work[kind as usize];
    try_increment(counter, cap).then(|| WorkLease {
      runtime: Some(self.clone()),
      kind,
      amount: 1,
    })
  }

  pub fn try_admit_connection(self: &Arc<Self>) -> Result<WorkLease, OverloadRejection> {
    let config = self
      .config
      .read()
      .expect("overload configuration lock poisoned");
    if self.state() == OverloadState::Hard && config.actions.hard.reject_new_connections {
      self.rejections[OverloadBoundary::Connection as usize].fetch_add(1, Ordering::Relaxed);
      return Err(OverloadRejection {
        boundary: OverloadBoundary::Connection,
      });
    }
    drop(config);
    Ok(self.lease(WorkKind::DownstreamConnections, 1))
  }

  pub fn try_admit_request(
    self: &Arc<Self>,
    version: Version,
  ) -> Result<RequestLease, OverloadRejection> {
    let config = self
      .config
      .read()
      .expect("overload configuration lock poisoned");
    if self.state() == OverloadState::Hard {
      let boundary = match version {
        Version::HTTP_2 | Version::HTTP_3 if config.actions.hard.reject_new_streams => {
          Some(OverloadBoundary::Stream)
        }
        _ if config.actions.hard.reject_new_requests => Some(OverloadBoundary::Request),
        _ => None,
      };
      if let Some(boundary) = boundary {
        self.rejections[boundary as usize].fetch_add(1, Ordering::Relaxed);
        return Err(OverloadRejection { boundary });
      }
    }
    drop(config);
    let stream = match version {
      Version::HTTP_2 => Some(self.lease(WorkKind::H2Streams, 1)),
      Version::HTTP_3 => Some(self.lease(WorkKind::H3Streams, 1)),
      _ => None,
    };
    Ok(RequestLease {
      _request: self.lease(WorkKind::ActiveHttpRequests, 1),
      _stream: stream,
    })
  }

  pub fn try_admit_control_connection(
    self: &Arc<Self>,
    plane: ControlPlane,
  ) -> Option<ControlLease> {
    self.try_admit_control(plane, ControlSlot::Connection)
  }

  pub fn try_admit_control_request(self: &Arc<Self>, plane: ControlPlane) -> Option<ControlLease> {
    self.try_admit_control(plane, ControlSlot::Request)
  }

  fn try_admit_control(
    self: &Arc<Self>,
    plane: ControlPlane,
    slot: ControlSlot,
  ) -> Option<ControlLease> {
    if !self.enabled.load(Ordering::Relaxed) {
      return Some(ControlLease::disabled(plane, slot));
    }
    let config = self
      .config
      .read()
      .expect("overload configuration lock poisoned");
    let capacity = match (plane, slot) {
      (ControlPlane::Admin, ControlSlot::Connection) => config.reserved_capacity.admin_connections,
      (ControlPlane::Admin, ControlSlot::Request) => config.reserved_capacity.admin_requests,
      (ControlPlane::Health, ControlSlot::Connection) => {
        config.reserved_capacity.health_connections
      }
      (ControlPlane::Health, ControlSlot::Request) => config.reserved_capacity.health_requests,
      (ControlPlane::Metrics, ControlSlot::Connection) => {
        config.reserved_capacity.metrics_connections
      }
      (ControlPlane::Metrics, ControlSlot::Request) => config.reserved_capacity.metrics_requests,
    } as u64;
    drop(config);
    let counters = match slot {
      ControlSlot::Connection => &self.control_connections,
      ControlSlot::Request => &self.control_requests,
    };
    try_increment(&counters[plane as usize], capacity).then(|| ControlLease {
      runtime: Some(self.clone()),
      plane,
      slot,
    })
  }
}

fn try_increment(counter: &std::sync::atomic::AtomicU64, limit: u64) -> bool {
  let mut active = counter.load(Ordering::Relaxed);
  loop {
    if active >= limit {
      return false;
    }
    match counter.compare_exchange_weak(active, active + 1, Ordering::Relaxed, Ordering::Relaxed) {
      Ok(_) => return true,
      Err(next) => active = next,
    }
  }
}
