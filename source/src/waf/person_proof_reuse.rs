use anyhow::{anyhow, bail};

use super::person_proof::{
  PersonProofEngine, challenge_reuse_key, clearance_hash, purge_expired_reuse_tokens, token_hash,
};

const PERSON_PROOF_REUSE_CAPACITY_ERROR: &str = "person proof reuse token capacity exhausted";

pub(super) fn is_reuse_capacity_error(error: &anyhow::Error) -> bool {
  error
    .to_string()
    .contains(PERSON_PROOF_REUSE_CAPACITY_ERROR)
}

impl PersonProofEngine {
  pub(super) async fn remember_reuse_token_async(
    &self,
    key: &str,
    expires: i64,
    now: i64,
  ) -> anyhow::Result<()> {
    if !self.mark_reuse_token_used_async(key, expires, now).await? {
      bail!("person proof token is already active");
    }
    Ok(())
  }

  pub(super) async fn mark_reuse_token_used_async(
    &self,
    key: &str,
    expires: i64,
    now: i64,
  ) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state {
      return shared.person_proof_remember(key, expires).await;
    }
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    if active.contains_key(key) {
      return Ok(false);
    }
    if active.len() >= self.max_reuse_tokens {
      bail!("{PERSON_PROOF_REUSE_CAPACITY_ERROR}");
    }
    active.insert(key.to_string(), expires);
    Ok(true)
  }

  pub(super) async fn consume_reuse_token_async(
    &self,
    key: &str,
    now: i64,
  ) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state {
      return shared.person_proof_consume(key).await;
    }
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    Ok(active.remove(key).is_some())
  }

  pub(super) async fn mark_challenge_token_used_async(
    &self,
    token: &str,
    expires: i64,
    now: i64,
  ) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      return shared
        .person_proof_mark_challenge_used(token, &token_hash(token), expires)
        .await;
    }
    self
      .mark_reuse_token_used_async(&challenge_reuse_key(token), expires, now)
      .await
  }

  pub(super) async fn consume_clearance_token_async(
    &self,
    token: &str,
    now: i64,
  ) -> anyhow::Result<bool> {
    let hash = clearance_hash(token);
    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      return shared.person_proof_consume_clearance(token, &hash).await;
    }
    self
      .consume_reuse_token_async(&format!("clearance:{hash}"), now)
      .await
  }

  pub(super) async fn clearance_revoked_async(&self, hash: &str, now: i64) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      return shared.person_proof_clearance_revoked(hash).await;
    }
    let mut revoked = self
      .revoked_clearances
      .lock()
      .map_err(|_| anyhow!("person proof revocation state is unavailable"))?;
    purge_expired_reuse_tokens(&mut revoked, now);
    Ok(revoked.contains_key(hash))
  }

  pub(super) fn remember_reuse_token(
    &self,
    key: &str,
    expires: i64,
    now: i64,
  ) -> anyhow::Result<()> {
    if !self.mark_reuse_token_used(key, expires, now)? {
      bail!("person proof token is already active");
    }
    Ok(())
  }

  pub(super) fn mark_reuse_token_used(
    &self,
    key: &str,
    expires: i64,
    now: i64,
  ) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state {
      let _ = shared;
      bail!("person proof shared reuse state requires asynchronous evaluation");
    }
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    if active.contains_key(key) {
      return Ok(false);
    }
    if active.len() >= self.max_reuse_tokens {
      bail!("{PERSON_PROOF_REUSE_CAPACITY_ERROR}");
    }
    active.insert(key.to_string(), expires);
    Ok(true)
  }

  pub(super) fn consume_reuse_token(&self, key: &str, now: i64) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state {
      let _ = shared;
      bail!("person proof shared reuse state requires asynchronous evaluation");
    }
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    Ok(active.remove(key).is_some())
  }

  pub(super) fn mark_challenge_token_used(
    &self,
    token: &str,
    expires: i64,
    now: i64,
  ) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      bail!("person proof shared reuse state requires asynchronous evaluation");
    }
    self.mark_reuse_token_used(&challenge_reuse_key(token), expires, now)
  }

  pub(super) fn consume_clearance_token(&self, token: &str, now: i64) -> anyhow::Result<bool> {
    let hash = clearance_hash(token);
    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      bail!("person proof shared reuse state requires asynchronous evaluation");
    }
    self.consume_reuse_token(&format!("clearance:{hash}"), now)
  }

  pub(super) fn clearance_revoked(&self, hash: &str, now: i64) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state
      && shared.person_proof_enabled()
    {
      bail!("person proof shared reuse state requires asynchronous evaluation");
    }
    let mut revoked = self
      .revoked_clearances
      .lock()
      .map_err(|_| anyhow!("person proof revocation state is unavailable"))?;
    purge_expired_reuse_tokens(&mut revoked, now);
    Ok(revoked.contains_key(hash))
  }
}
