//! Bounded process-resource discovery shared by runtime subsystems.
//!
//! The parsers in this module are intentionally side-effect free. Production
//! discovery uses [`crate::platform_fs`] so pseudo-files cannot cause an
//! unbounded allocation after runtime confinement.

const CGROUP_V1_UNLIMITED_MEMORY_SENTINEL: u64 = 1_u64 << 60;
const BYTES_PER_KIBIBYTE: u64 = 1_024;

/// Returns a finite cgroup memory hard limit, when one is exposed by the
/// process environment.
///
/// cgroup v2's `max` value and cgroup v1's very-large unlimited sentinel are
/// treated as no finite limit. A finite v2 value takes precedence over v1;
/// when v2 is unlimited or unavailable, a finite v1 value is considered.
pub(crate) fn finite_cgroup_memory_limit_bytes() -> Option<u64> {
  let v2 = crate::platform_fs::read_to_string("/sys/fs/cgroup/memory.max")
    .ok()
    .and_then(|value| parse_cgroup_v2_memory_limit(&value));
  if v2.is_some() {
    return v2;
  }

  crate::platform_fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    .ok()
    .and_then(|value| parse_cgroup_v1_memory_limit(&value))
}

/// Returns host `MemTotal` from `/proc/meminfo`, when it is valid and finite.
pub(crate) fn host_memory_bytes() -> Option<u64> {
  crate::platform_fs::read_to_string("/proc/meminfo")
    .ok()
    .and_then(|value| parse_memtotal_bytes(&value))
}

fn parse_cgroup_v2_memory_limit(value: &str) -> Option<u64> {
  let value = value.trim();
  if value == "max" {
    return None;
  }
  value.parse::<u64>().ok().filter(|value| *value > 0)
}

fn parse_cgroup_v1_memory_limit(value: &str) -> Option<u64> {
  value
    .trim()
    .parse::<u64>()
    .ok()
    .filter(|value| *value > 0 && *value < CGROUP_V1_UNLIMITED_MEMORY_SENTINEL)
}

fn parse_memtotal_bytes(value: &str) -> Option<u64> {
  value.lines().find_map(|line| {
    let rest = line.strip_prefix("MemTotal:")?;
    let kibibytes = rest.split_whitespace().next()?.parse::<u64>().ok()?;
    (kibibytes > 0)
      .then(|| kibibytes.checked_mul(BYTES_PER_KIBIBYTE))
      .flatten()
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cgroup_v2_parser_accepts_finite_values_and_rejects_unlimited_or_zero() {
    assert_eq!(parse_cgroup_v2_memory_limit(" 123456 \n"), Some(123_456));
    assert_eq!(parse_cgroup_v2_memory_limit("max"), None);
    assert_eq!(parse_cgroup_v2_memory_limit("0"), None);
    assert_eq!(parse_cgroup_v2_memory_limit("not-a-limit"), None);
  }

  #[test]
  fn cgroup_v1_parser_rejects_unlimited_sentinel_and_invalid_values() {
    assert_eq!(parse_cgroup_v1_memory_limit(" 123456 \n"), Some(123_456));
    assert_eq!(
      parse_cgroup_v1_memory_limit(&(CGROUP_V1_UNLIMITED_MEMORY_SENTINEL).to_string()),
      None
    );
    assert_eq!(parse_cgroup_v1_memory_limit("18446744073709551615"), None);
    assert_eq!(parse_cgroup_v1_memory_limit("0"), None);
    assert_eq!(parse_cgroup_v1_memory_limit("not-a-limit"), None);
  }

  #[test]
  fn memtotal_parser_rejects_overflowing_kibibyte_conversion() {
    assert_eq!(
      parse_memtotal_bytes("MemFree: 1 kB\nMemTotal: 2 kB\n"),
      Some(2_048)
    );
    assert_eq!(
      parse_memtotal_bytes("MemTotal: 18446744073709551615 kB\n"),
      None
    );
    assert_eq!(parse_memtotal_bytes("MemTotal: 0 kB\n"), None);
    assert_eq!(parse_memtotal_bytes("MemTotal: malformed kB\n"), None);
  }

  #[test]
  fn finite_v2_value_is_preferred_to_v1_value() {
    let v2 = parse_cgroup_v2_memory_limit("16");
    let v1 = parse_cgroup_v1_memory_limit("32");
    assert_eq!(v2.or(v1), Some(16));
  }

  #[test]
  fn unlimited_v2_can_fall_back_to_finite_v1() {
    let v2 = parse_cgroup_v2_memory_limit("max");
    let v1 = parse_cgroup_v1_memory_limit("32");
    assert_eq!(v2.or(v1), Some(32));
  }
}
