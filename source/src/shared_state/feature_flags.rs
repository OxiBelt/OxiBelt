use super::SharedState;

impl SharedState {
  pub fn has_rate_limits(&self) -> bool {
    self.rate_limits.is_some()
  }

  pub fn has_connection_limits(&self) -> bool {
    self.connection_limits.is_some()
  }

  pub fn has_person_proof(&self) -> bool {
    self.person_proof.is_some()
  }

  pub fn has_upstream_health(&self) -> bool {
    self.upstream_health.is_some()
  }

  pub fn has_cache(&self) -> bool {
    self.cache.is_some()
  }
}
