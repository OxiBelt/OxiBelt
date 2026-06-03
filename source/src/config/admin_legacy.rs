//! Legacy admin configuration compatibility checks.
//! Legacy fields are validated separately so migration behavior stays explicit.

use anyhow::bail;
use serde::Deserialize;

use super::Config;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct LegacyAdminRbacConfig {
  #[serde(default)]
  tokens: Vec<toml::Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub(super) struct LegacyAdminTokenStoreConfig {
  #[serde(flatten)]
  settings: toml::map::Map<String, toml::Value>,
}

impl Config {
  pub(super) fn validate_legacy_admin_authorization(&self) -> anyhow::Result<()> {
    if let Some(rbac) = &self.admin.legacy_rbac {
      let _ = rbac.tokens.len();
      bail!(
        "admin.rbac is legacy RBAC syntax; use [ipm], [[ipm.credentials]], [[ipm.policies]], and [[ipm.bindings]]"
      );
    }
    if let Some(token_store) = &self.admin.legacy_token_store {
      let _ = token_store.settings.len();
      bail!("admin.token_store is legacy Admin token syntax; use IPM credentials and policies");
    }
    Ok(())
  }
}
