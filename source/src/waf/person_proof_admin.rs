use anyhow::{Context, anyhow, bail};
use serde::Serialize;

use super::person_proof::{PersonProofEngine, now_unix_ms, purge_expired_reuse_tokens};

const MAX_ADMIN_REVOKE_TTL_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, Serialize)]
pub struct PersonProofAdminStatus {
  pub enabled: bool,
  pub store_scope: &'static str,
  pub policies: PersonProofAdminPolicyStatus,
  pub max_reuse_tokens: usize,
  pub active_clearance_count: usize,
  pub challenge_replay_marker_count: usize,
  pub revoked_clearance_count: usize,
  pub legacy_raw_key_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonProofAdminPolicyStatus {
  pub total: usize,
  pub single_use: usize,
  pub multi_use: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonProofAdminClearance {
  pub clearance_hash: String,
  pub expires_at_unix_ms: Option<i64>,
  pub store_scope: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonProofAdminClearancePage {
  pub clearances: Vec<PersonProofAdminClearance>,
  pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonProofAdminRevokeResult {
  pub clearance_hash: String,
  pub revoked: bool,
  pub removed_active: bool,
  pub store_scope: &'static str,
  pub expires_at_unix_ms: i64,
}

impl PersonProofEngine {
  pub(super) fn admin_status(&self) -> anyhow::Result<PersonProofAdminStatus> {
    let policies = PersonProofAdminPolicyStatus {
      total: self.policies.len(),
      single_use: self
        .policies
        .iter()
        .filter(|policy| policy.single_use)
        .count(),
      multi_use: self
        .policies
        .iter()
        .filter(|policy| !policy.single_use)
        .count(),
    };
    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      let status = shared.person_proof_admin_status()?;
      return Ok(PersonProofAdminStatus {
        enabled: !self.policies.is_empty(),
        store_scope: "shared",
        policies,
        max_reuse_tokens: self.max_reuse_tokens,
        active_clearance_count: status.active_clearance_count,
        challenge_replay_marker_count: status.challenge_replay_marker_count,
        revoked_clearance_count: status.revoked_clearance_count,
        legacy_raw_key_count: status.legacy_raw_key_count,
      });
    }

    let now = now_unix_ms()?;
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    let mut revoked = self
      .revoked_clearances
      .lock()
      .map_err(|_| anyhow!("person proof revocation state is unavailable"))?;
    purge_expired_reuse_tokens(&mut revoked, now);
    let mut active_clearance_count = 0;
    let mut challenge_replay_marker_count = 0;
    let mut legacy_raw_key_count = 0;
    for key in active.keys() {
      match classify_reuse_key(key) {
        ReuseKeyKind::ClearanceHash => active_clearance_count += 1,
        ReuseKeyKind::ChallengeHash => challenge_replay_marker_count += 1,
        ReuseKeyKind::LegacyOrUnknown => legacy_raw_key_count += 1,
      }
    }
    Ok(PersonProofAdminStatus {
      enabled: !self.policies.is_empty(),
      store_scope: if self.policies.is_empty() {
        "disabled"
      } else {
        "process_local"
      },
      policies,
      max_reuse_tokens: self.max_reuse_tokens,
      active_clearance_count,
      challenge_replay_marker_count,
      revoked_clearance_count: revoked.len(),
      legacy_raw_key_count,
    })
  }

  pub(super) fn admin_list_clearances(
    &self,
    limit: usize,
    cursor: Option<&str>,
  ) -> anyhow::Result<PersonProofAdminClearancePage> {
    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      let page = shared.person_proof_list_clearances(limit, cursor)?;
      return Ok(PersonProofAdminClearancePage {
        clearances: page
          .clearances
          .into_iter()
          .map(|entry| PersonProofAdminClearance {
            clearance_hash: entry.clearance_hash,
            expires_at_unix_ms: entry.expires_at_unix_ms,
            store_scope: "shared",
          })
          .collect(),
        next_cursor: page.next_cursor,
      });
    }

    let now = now_unix_ms()?;
    let offset = parse_cursor_offset(cursor)?;
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    let mut clearances = active
      .iter()
      .filter_map(|(key, expires_at)| {
        let hash = key.strip_prefix("clearance:")?;
        is_clearance_hash(hash).then(|| PersonProofAdminClearance {
          clearance_hash: format!("clearance:{hash}"),
          expires_at_unix_ms: Some(*expires_at),
          store_scope: "process_local",
        })
      })
      .collect::<Vec<_>>();
    clearances.sort_by(|left, right| left.clearance_hash.cmp(&right.clearance_hash));
    let page = clearances
      .into_iter()
      .skip(offset)
      .take(limit.saturating_add(1))
      .collect::<Vec<_>>();
    let next_cursor = (page.len() > limit).then(|| (offset + limit).to_string());
    Ok(PersonProofAdminClearancePage {
      clearances: page.into_iter().take(limit).collect(),
      next_cursor,
    })
  }

  pub(super) fn admin_revoke_clearance(
    &self,
    hash: &str,
    ttl_seconds: Option<u64>,
  ) -> anyhow::Result<PersonProofAdminRevokeResult> {
    let hash = normalize_clearance_hash(hash)?;
    let ttl_seconds = ttl_seconds.unwrap_or_else(|| self.max_policy_ttl_seconds());
    if ttl_seconds == 0 {
      bail!("person proof clearance revocation ttl_seconds must be greater than 0");
    }
    if ttl_seconds > MAX_ADMIN_REVOKE_TTL_SECONDS {
      bail!(
        "person proof clearance revocation ttl_seconds must be at most {}",
        MAX_ADMIN_REVOKE_TTL_SECONDS
      );
    }
    let now = now_unix_ms()?;
    let expires_at = now
      .checked_add(
        i64::try_from(ttl_seconds)
          .unwrap_or(i64::MAX / 1000)
          .saturating_mul(1000),
      )
      .unwrap_or(i64::MAX);

    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      let removed_active = shared.person_proof_revoke_clearance_hash(&hash, expires_at)?;
      return Ok(PersonProofAdminRevokeResult {
        clearance_hash: format!("clearance:{hash}"),
        revoked: true,
        removed_active,
        store_scope: "shared",
        expires_at_unix_ms: expires_at,
      });
    }

    let key = format!("clearance:{hash}");
    let removed_active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?
      .remove(&key)
      .is_some();
    self
      .revoked_clearances
      .lock()
      .map_err(|_| anyhow!("person proof revocation state is unavailable"))?
      .insert(hash.to_string(), expires_at);
    Ok(PersonProofAdminRevokeResult {
      clearance_hash: format!("clearance:{hash}"),
      revoked: true,
      removed_active,
      store_scope: if self.policies.is_empty() {
        "disabled"
      } else {
        "process_local"
      },
      expires_at_unix_ms: expires_at,
    })
  }

  pub(super) fn normalize_admin_clearance_hash(hash: &str) -> anyhow::Result<String> {
    normalize_clearance_hash(hash)
  }

  fn max_policy_ttl_seconds(&self) -> u64 {
    self
      .policies
      .iter()
      .map(|policy| policy.ttl_seconds)
      .max()
      .unwrap_or(MAX_ADMIN_REVOKE_TTL_SECONDS)
      .max(1)
  }
}

fn normalize_clearance_hash(value: &str) -> anyhow::Result<String> {
  let trimmed = value.trim();
  if trimmed.starts_with("clearance.v") || trimmed.starts_with("session.v") {
    bail!("person proof Admin API accepts only clearance hashes, not raw tokens");
  }
  let hash = trimmed.strip_prefix("clearance:").unwrap_or(trimmed);
  if !is_clearance_hash(hash) {
    bail!("person proof clearance_hash must be clearance:<64 hex> or bare 64 hex");
  }
  Ok(hash.to_ascii_lowercase())
}

fn is_clearance_hash(value: &str) -> bool {
  value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_cursor_offset(cursor: Option<&str>) -> anyhow::Result<usize> {
  let Some(cursor) = cursor else {
    return Ok(0);
  };
  cursor
    .parse::<usize>()
    .context("person proof clearances cursor must be an unsigned offset")
}

enum ReuseKeyKind {
  ClearanceHash,
  ChallengeHash,
  LegacyOrUnknown,
}

fn classify_reuse_key(key: &str) -> ReuseKeyKind {
  if let Some(hash) = key.strip_prefix("clearance:")
    && is_clearance_hash(hash)
  {
    return ReuseKeyKind::ClearanceHash;
  }
  if let Some(hash) = key.strip_prefix("challenge:")
    && is_clearance_hash(hash)
  {
    return ReuseKeyKind::ChallengeHash;
  }
  ReuseKeyKind::LegacyOrUnknown
}
