use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::FAILURE_RETRY_SECONDS;

#[derive(Debug, Clone, Serialize)]
pub struct OcspRuntimeStatus {
  pub status: String,
  pub staple_present: bool,
  pub this_update: Option<u64>,
  pub next_update: Option<u64>,
  pub last_fetch_at: Option<u64>,
  pub last_success_at: Option<u64>,
  pub last_error_code: Option<String>,
  pub next_refresh_at: Option<u64>,
  pub failure_policy: &'static str,
}

#[derive(Debug, Clone)]
pub(super) struct OcspStatusState {
  pub(super) status: String,
  pub(super) staple_present: bool,
  pub(super) this_update: Option<SystemTime>,
  pub(super) next_update: Option<SystemTime>,
  pub(super) last_fetch_at: Option<SystemTime>,
  pub(super) last_success_at: Option<SystemTime>,
  pub(super) last_error_code: Option<String>,
  pub(super) next_refresh_at: Option<SystemTime>,
}

impl OcspStatusState {
  pub(super) fn disabled() -> Self {
    Self {
      status: "disabled".to_string(),
      staple_present: false,
      this_update: None,
      next_update: None,
      last_fetch_at: None,
      last_success_at: None,
      last_error_code: None,
      next_refresh_at: None,
    }
  }

  pub(super) fn static_file(staple_present: bool) -> Self {
    Self {
      status: "static_file".to_string(),
      staple_present,
      this_update: None,
      next_update: None,
      last_fetch_at: None,
      last_success_at: None,
      last_error_code: None,
      next_refresh_at: None,
    }
  }

  pub(super) fn live_degraded(error_code: Option<&str>) -> Self {
    Self {
      status: "degraded".to_string(),
      staple_present: false,
      this_update: None,
      next_update: None,
      last_fetch_at: None,
      last_success_at: None,
      last_error_code: error_code.map(str::to_string),
      next_refresh_at: Some(SystemTime::now() + Duration::from_secs(FAILURE_RETRY_SECONDS)),
    }
  }

  pub(super) fn to_public(&self) -> OcspRuntimeStatus {
    OcspRuntimeStatus {
      status: self.status.clone(),
      staple_present: self.staple_present,
      this_update: self.this_update.map(system_time_to_unix),
      next_update: self.next_update.map(system_time_to_unix),
      last_fetch_at: self.last_fetch_at.map(system_time_to_unix),
      last_success_at: self.last_success_at.map(system_time_to_unix),
      last_error_code: self.last_error_code.clone(),
      next_refresh_at: self.next_refresh_at.map(system_time_to_unix),
      failure_policy: "drop_stale",
    }
  }

  pub(super) fn next_refresh_at_unix(&self) -> Option<u64> {
    self.next_refresh_at.map(system_time_to_unix)
  }
}

pub(super) fn system_time_to_unix(time: SystemTime) -> u64 {
  time
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn public_status_uses_drop_stale_policy_and_unix_seconds() {
    let status = OcspStatusState {
      status: "fresh".to_string(),
      staple_present: true,
      this_update: Some(UNIX_EPOCH + Duration::from_secs(10)),
      next_update: Some(UNIX_EPOCH + Duration::from_secs(20)),
      last_fetch_at: Some(UNIX_EPOCH + Duration::from_secs(11)),
      last_success_at: Some(UNIX_EPOCH + Duration::from_secs(12)),
      last_error_code: None,
      next_refresh_at: Some(UNIX_EPOCH + Duration::from_secs(15)),
    }
    .to_public();

    assert_eq!(status.failure_policy, "drop_stale");
    assert!(status.staple_present);
    assert_eq!(status.this_update, Some(10));
    assert_eq!(status.next_update, Some(20));
    assert_eq!(status.last_fetch_at, Some(11));
    assert_eq!(status.last_success_at, Some(12));
    assert_eq!(status.next_refresh_at, Some(15));
  }
}
