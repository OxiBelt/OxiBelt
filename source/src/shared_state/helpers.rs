//! Shared expiration, identity, and hashing helpers.

use super::*;

#[cfg(test)]
pub(super) fn purge_expired_values(values: &mut HashMap<String, MemoryValue>, now: i64) {
  values.retain(|_, value| value.expires_at_ms.is_none_or(|expires| expires > now));
}

#[cfg(test)]
pub(super) fn purge_expired_counters(counters: &mut HashMap<String, MemoryCounter>, now: i64) {
  counters.retain(|_, value| value.expires_at_ms.is_none_or(|expires| expires > now));
}

pub(super) fn parse_rate_bucket(raw: &[u8]) -> Option<(f64, i64)> {
  let raw = std::str::from_utf8(raw).ok()?;
  let (tokens, last) = raw.split_once(':')?;
  Some((tokens.parse().ok()?, last.parse().ok()?))
}

pub(super) fn ttl_from_expires_ms(expires_at_ms: i64) -> Option<Duration> {
  let now = now_unix_ms();
  (expires_at_ms > now).then_some(Duration::from_millis((expires_at_ms - now) as u64))
}

pub(super) fn rate_bucket_ttl(rate: ParsedRate, burst: u32) -> Duration {
  let seconds = f64::from(burst.max(1)) / rate.per_second();
  let millis = (seconds * 1000.0).ceil().max(1000.0);
  let millis = if millis.is_finite() && millis < i64::MAX as f64 {
    millis as u64
  } else {
    i64::MAX as u64
  };
  Duration::from_millis(millis)
}

pub fn now_unix_ms() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis()
    .min(i64::MAX as u128) as i64
}

pub(super) fn random_hex(bytes: usize) -> anyhow::Result<String> {
  let mut value = vec![0u8; bytes];
  crate::crypto::random_fill(&mut value)
    .map_err(|_| anyhow!("failed to generate shared cache lock token"))?;
  Ok(hex_encode(&value))
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

pub(super) fn config_hash(config: &Config) -> String {
  hex_encode(&crate::crypto::sha256(format!("{config:?}").as_bytes()))
}
