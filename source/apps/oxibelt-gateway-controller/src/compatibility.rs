use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use serde_json::Value;

use super::cli::{CompatibilityMode, RunArgs};

pub const EFFECTIVE_VERSION_ANNOTATION: &str = "oxibelt.dev/effective-version";
const MAX_ROLLING_UPGRADE_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompatibilityPolicy {
  pub mode: CompatibilityMode,
  pub current_version: String,
  pub previous_version: Option<String>,
  pub deadline: Option<String>,
  deadline_unix_seconds: Option<i64>,
}

impl CompatibilityPolicy {
  pub fn from_args(args: &RunArgs) -> anyhow::Result<Self> {
    Self::from_args_at(
      args,
      oxibelt_build_identity::current().effective_version,
      unix_seconds_now()?,
    )
  }

  fn from_args_at(
    args: &RunArgs,
    current_version: &str,
    now_unix_seconds: i64,
  ) -> anyhow::Result<Self> {
    oxibelt_build_identity::parse_semver(current_version)
      .map_err(|error| anyhow::anyhow!("controller effective version is not SemVer: {error}"))?;
    match args.compatibility_mode {
      CompatibilityMode::Exact => {
        if args.compatibility_previous_version.is_some() || args.compatibility_deadline.is_some() {
          bail!(
            "compatibility previous version and deadline must be omitted when compatibility mode is exact"
          );
        }
        Ok(Self {
          mode: CompatibilityMode::Exact,
          current_version: current_version.to_string(),
          previous_version: None,
          deadline: None,
          deadline_unix_seconds: None,
        })
      }
      CompatibilityMode::RollingUpgrade => {
        let previous_version = args.compatibility_previous_version.as_deref().context(
          "compatibility previous version is required when compatibility mode is rolling_upgrade",
        )?;
        oxibelt_build_identity::parse_semver(previous_version).map_err(|error| {
          anyhow::anyhow!("compatibility previous version is not SemVer: {error}")
        })?;
        validate_previous_minor(current_version, previous_version)?;
        let deadline = args.compatibility_deadline.as_deref().context(
          "compatibility deadline is required when compatibility mode is rolling_upgrade",
        )?;
        let deadline_unix_seconds = parse_rfc3339_utc(deadline)
          .context("compatibility deadline must be an RFC3339 UTC timestamp")?;
        validate_deadline(now_unix_seconds, deadline_unix_seconds)?;
        Ok(Self {
          mode: CompatibilityMode::RollingUpgrade,
          current_version: current_version.to_string(),
          previous_version: Some(previous_version.to_string()),
          deadline: Some(deadline.to_string()),
          deadline_unix_seconds: Some(deadline_unix_seconds),
        })
      }
    }
  }

  pub fn validate_target_workload(&self, workload: &Value) -> anyhow::Result<()> {
    self.validate_target_workload_at(workload, unix_seconds_now()?)
  }

  fn validate_target_workload_at(
    &self,
    workload: &Value,
    now_unix_seconds: i64,
  ) -> anyhow::Result<()> {
    let observed = workload
      .pointer("/spec/template/metadata/annotations")
      .and_then(Value::as_object)
      .and_then(|annotations| annotations.get(EFFECTIVE_VERSION_ANNOTATION))
      .and_then(Value::as_str)
      .filter(|value| !value.is_empty())
      .with_context(|| {
        format!("target workload pod template must declare {EFFECTIVE_VERSION_ANNOTATION}")
      })?;
    match self.mode {
      CompatibilityMode::Exact => {
        if observed != self.current_version {
          bail!(
            "target workload effective version `{observed}` is incompatible with controller version `{}` in exact mode",
            self.current_version
          );
        }
      }
      CompatibilityMode::RollingUpgrade => {
        let deadline = self
          .deadline_unix_seconds
          .context("rolling-upgrade compatibility deadline is unavailable")?;
        if now_unix_seconds >= deadline {
          bail!("rolling-upgrade compatibility deadline has expired");
        }
        let previous = self
          .previous_version
          .as_deref()
          .context("rolling-upgrade previous version is unavailable")?;
        if observed != self.current_version && observed != previous {
          bail!(
            "target workload effective version `{observed}` is neither controller version `{}` nor permitted previous version `{previous}`",
            self.current_version
          );
        }
      }
    }
    Ok(())
  }
}

fn unix_seconds_now() -> anyhow::Result<i64> {
  let seconds = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system clock is before the Unix epoch")?
    .as_secs();
  i64::try_from(seconds).context("system clock exceeds the supported timestamp range")
}

fn validate_previous_minor(current: &str, previous: &str) -> anyhow::Result<()> {
  let (current_major, current_minor) = semver_major_minor(current)?;
  let (previous_major, previous_minor) = semver_major_minor(previous)?;
  if current_major != previous_major
    || previous_minor
      .checked_add(1)
      .is_none_or(|next| next != current_minor)
  {
    bail!(
      "compatibility previous version `{previous}` must be from the immediately preceding minor of `{current}`"
    );
  }
  Ok(())
}

fn semver_major_minor(value: &str) -> anyhow::Result<(u64, u64)> {
  let core = value.split_once(['-', '+']).map_or(value, |(core, _)| core);
  let mut components = core.split('.');
  let major = components
    .next()
    .context("SemVer major version is missing")?
    .parse::<u64>()
    .context("SemVer major version exceeds the supported range")?;
  let minor = components
    .next()
    .context("SemVer minor version is missing")?
    .parse::<u64>()
    .context("SemVer minor version exceeds the supported range")?;
  Ok((major, minor))
}

fn validate_deadline(now: i64, deadline: i64) -> anyhow::Result<()> {
  if deadline <= now {
    bail!("compatibility deadline must be in the future");
  }
  if deadline - now > MAX_ROLLING_UPGRADE_SECONDS {
    bail!("compatibility deadline must be no more than 24 hours in the future");
  }
  Ok(())
}

fn parse_rfc3339_utc(value: &str) -> anyhow::Result<i64> {
  let bytes = value.as_bytes();
  if bytes.len() != 20
    || bytes[4] != b'-'
    || bytes[7] != b'-'
    || bytes[10] != b'T'
    || bytes[13] != b':'
    || bytes[16] != b':'
    || bytes[19] != b'Z'
  {
    bail!("expected YYYY-MM-DDTHH:MM:SSZ");
  }
  let year = decimal(bytes, 0, 4)?;
  let month = decimal(bytes, 5, 7)?;
  let day = decimal(bytes, 8, 10)?;
  let hour = decimal(bytes, 11, 13)?;
  let minute = decimal(bytes, 14, 16)?;
  let second = decimal(bytes, 17, 19)?;
  if year < 1970
    || !(1..=12).contains(&month)
    || day == 0
    || day > days_in_month(year, month)
    || hour > 23
    || minute > 59
    || second > 59
  {
    bail!("timestamp contains an out-of-range UTC date or time");
  }
  let days = days_from_civil(year, month, day);
  days
    .checked_mul(86_400)
    .and_then(|seconds| seconds.checked_add(hour * 3_600 + minute * 60 + second))
    .context("timestamp exceeds the supported range")
}

fn decimal(bytes: &[u8], start: usize, end: usize) -> anyhow::Result<i64> {
  let mut value = 0_i64;
  for byte in &bytes[start..end] {
    if !byte.is_ascii_digit() {
      bail!("timestamp fields must contain ASCII digits");
    }
    value = value * 10 + i64::from(byte - b'0');
  }
  Ok(value)
}

const fn days_in_month(year: i64, month: i64) -> i64 {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
    4 | 6 | 9 | 11 => 30,
    2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
    2 => 28,
    _ => 0,
  }
}

const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
  let adjusted_year = year - if month <= 2 { 1 } else { 0 };
  let era = adjusted_year.div_euclid(400);
  let year_of_era = adjusted_year - era * 400;
  let adjusted_month = month + if month > 2 { -3 } else { 9 };
  let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
  let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::cli::RolloutTargetKind;
  use serde_json::json;

  fn args(mode: CompatibilityMode) -> RunArgs {
    RunArgs {
      poll_interval_ms: 5_000,
      rollout_target_namespace: "default".to_string(),
      rollout_target_kind: RolloutTargetKind::Deployment,
      rollout_target_name: "oxibelt".to_string(),
      rollout_target_container_name: "oxibelt".to_string(),
      rollout_volume_name: "gateway-config".to_string(),
      rollout_timeout_seconds: 300,
      rollout_config_map_prefix: "oxibelt-gateway-config".to_string(),
      leader_election_namespace: "default".to_string(),
      leader_election_lease_name: "controller".to_string(),
      leader_election_lease_duration_seconds: 15,
      leader_election_renew_deadline_seconds: 10,
      leader_election_retry_period_seconds: 2,
      compatibility_mode: mode,
      compatibility_previous_version: None,
      compatibility_deadline: None,
    }
  }

  fn workload(version: Option<&str>) -> Value {
    let mut value = json!({"spec": {"template": {"metadata": {"annotations": {}}}}});
    if let Some(version) = version {
      value["spec"]["template"]["metadata"]["annotations"][EFFECTIVE_VERSION_ANNOTATION] =
        Value::String(version.to_string());
    }
    value
  }

  #[test]
  fn exact_mode_requires_the_controller_effective_version() {
    let policy =
      CompatibilityPolicy::from_args_at(&args(CompatibilityMode::Exact), "0.7.0", 0).unwrap();
    assert!(
      policy
        .validate_target_workload_at(&workload(Some("0.7.0")), 0)
        .is_ok()
    );
    assert!(
      policy
        .validate_target_workload_at(&workload(Some("0.6.5")), 0)
        .is_err()
    );
    assert!(
      policy
        .validate_target_workload_at(&workload(None), 0)
        .is_err()
    );
  }

  #[test]
  fn exact_mode_rejects_rolling_only_arguments() {
    let mut args = args(CompatibilityMode::Exact);
    args.compatibility_previous_version = Some("0.6.5".to_string());
    assert!(CompatibilityPolicy::from_args_at(&args, "0.7.0", 0).is_err());
  }

  #[test]
  fn rolling_upgrade_is_bounded_and_allows_only_the_adjacent_minor() {
    let now = parse_rfc3339_utc("2026-07-24T00:00:00Z").unwrap();
    let mut args = args(CompatibilityMode::RollingUpgrade);
    args.compatibility_previous_version = Some("0.6.5".to_string());
    args.compatibility_deadline = Some("2026-07-25T00:00:00Z".to_string());
    let policy = CompatibilityPolicy::from_args_at(&args, "0.7.0", now).unwrap();
    assert!(
      policy
        .validate_target_workload_at(&workload(Some("0.7.0")), now)
        .is_ok()
    );
    assert!(
      policy
        .validate_target_workload_at(&workload(Some("0.6.5")), now)
        .is_ok()
    );
    assert!(
      policy
        .validate_target_workload_at(&workload(Some("0.5.9")), now)
        .is_err()
    );
    assert!(
      policy
        .validate_target_workload_at(
          &workload(Some("0.6.5")),
          parse_rfc3339_utc("2026-07-25T00:00:00Z").unwrap()
        )
        .is_err()
    );
    assert!(
      policy
        .validate_target_workload_at(
          &workload(Some("0.6.5")),
          parse_rfc3339_utc("2026-07-25T00:00:01Z").unwrap()
        )
        .is_err()
    );
  }

  #[test]
  fn rolling_upgrade_rejects_invalid_previous_versions_and_deadlines() {
    let now = parse_rfc3339_utc("2026-07-24T00:00:00Z").unwrap();
    let mut args = args(CompatibilityMode::RollingUpgrade);
    args.compatibility_previous_version = Some("0.5.9".to_string());
    args.compatibility_deadline = Some("2026-07-24T01:00:00Z".to_string());
    assert!(CompatibilityPolicy::from_args_at(&args, "0.7.0", now).is_err());

    args.compatibility_previous_version = Some("0.6.5".to_string());
    args.compatibility_deadline = Some("2026-07-25T00:00:01Z".to_string());
    assert!(CompatibilityPolicy::from_args_at(&args, "0.7.0", now).is_err());
    args.compatibility_deadline = Some("2026-02-29T00:00:00Z".to_string());
    assert!(CompatibilityPolicy::from_args_at(&args, "0.7.0", now).is_err());
  }

  #[test]
  fn strict_rfc3339_utc_parser_handles_leap_days() {
    assert!(parse_rfc3339_utc("2024-02-29T23:59:59Z").is_ok());
    assert!(parse_rfc3339_utc("2025-02-29T23:59:59Z").is_err());
    assert!(parse_rfc3339_utc("2026-07-24T00:00:00+00:00").is_err());
  }
}
