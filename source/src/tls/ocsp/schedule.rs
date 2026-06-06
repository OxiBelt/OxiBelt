use std::time::{Duration, SystemTime};

use super::FAILURE_RETRY_SECONDS;
use super::status::system_time_to_unix;

pub(crate) fn next_refresh_time(
  this_update: SystemTime,
  next_update: SystemTime,
  jitter_pct: u8,
) -> SystemTime {
  let lifetime = next_update
    .duration_since(this_update)
    .unwrap_or_else(|_| Duration::from_secs(FAILURE_RETRY_SECONDS));
  let refresh_after = lifetime.mul_f64(0.70);
  let jitter_window = lifetime.mul_f64(f64::from(jitter_pct) / 100.0);
  let jitter = Duration::from_secs(stable_jitter_seconds(&next_update, jitter_window.as_secs()));
  let candidate = this_update + refresh_after + jitter;
  let latest = next_update
    .checked_sub(Duration::from_secs(60))
    .unwrap_or(this_update);
  let refresh = if candidate < latest {
    candidate
  } else {
    latest
  };
  let now = SystemTime::now();
  let soonest = now + Duration::from_secs(1);
  if refresh > soonest || next_update <= soonest {
    refresh
  } else {
    soonest
  }
}

pub(crate) fn failure_retry_time(current_next_update: Option<SystemTime>) -> SystemTime {
  let retry = SystemTime::now() + Duration::from_secs(FAILURE_RETRY_SECONDS);
  if let Some(next_update) = current_next_update
    && next_update < retry
  {
    return next_update;
  }
  retry
}

pub(crate) fn classify_ocsp_error(error: &anyhow::Error) -> &'static str {
  let message = format!("{error:#}");
  for code in [
    "ocsp_stale_response",
    "ocsp_missing_next_update",
    "ocsp_invalid_update_window",
    "ocsp_produced_at_future",
    "ocsp_this_update_future",
    "ocsp_cert_status",
    "ocsp_cert_id_mismatch",
    "ocsp_unauthorized_responder",
    "ocsp_unsupported_signature_algorithm",
    "ocsp_signature",
    "ocsp_http_status",
    "ocsp_fetch",
    "ocsp_parse",
  ] {
    if message.contains(code) {
      return code;
    }
  }
  "ocsp_error"
}

pub(crate) fn unix_now() -> u64 {
  system_time_to_unix(SystemTime::now())
}

fn stable_jitter_seconds(next_update: &SystemTime, window: u64) -> u64 {
  if window == 0 {
    return 0;
  }
  system_time_to_unix(*next_update) % window.saturating_add(1)
}
