use anyhow::anyhow;

use super::SharedState;

impl SharedState {
  pub fn has_sticky_sessions(&self) -> bool {
    self.sticky_sessions.is_some()
  }

  pub fn sticky_session_secret(&self, pool_name: &str) -> anyhow::Result<Option<[u8; 32]>> {
    let Some(backend) = &self.sticky_sessions else {
      return Ok(None);
    };
    let key = self.key(&format!("sticky-session:secret:{pool_name}:v1"));
    let secret = backend.get_or_init_bytes(&key, 32, None)?;
    let bytes: [u8; 32] = secret
      .as_slice()
      .try_into()
      .map_err(|_| anyhow!("shared sticky session secret has invalid length"))?;
    Ok(Some(bytes))
  }
}
