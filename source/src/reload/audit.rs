//! Restart-only Admin audit authority checks for full hot reloads.

use anyhow::bail;

use crate::config::Config;

pub(super) fn validate_runtime_compatibility(
  active: &Config,
  replacement: &Config,
) -> anyhow::Result<()> {
  if replacement.admin.audit != active.admin.audit {
    bail!(
      "full hot reload rejected because admin.audit persistence, spool, and integrity authority are restart-only"
    );
  }
  if active.admin.audit.enabled
    && (replacement.shared_state.namespace != active.shared_state.namespace
      || replacement.shared_state.instance_id_env != active.shared_state.instance_id_env
      || audit_backend(active) != audit_backend(replacement))
  {
    bail!(
      "full hot reload rejected because Admin audit storage namespace, instance identity, and backend authority are restart-only"
    );
  }
  Ok(())
}

fn audit_backend(config: &Config) -> Option<&crate::config::SharedStateBackendConfig> {
  config.admin.audit.store.backend.as_ref().and_then(|name| {
    config
      .shared_state
      .backends
      .iter()
      .find(|backend| backend.name == *name)
  })
}
