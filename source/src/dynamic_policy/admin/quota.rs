//! Dynamic policy quota enforcement.
//! Quotas are checked before records are written to the persistent store.

use anyhow::{Context, bail};
use sqlx::{Postgres, Transaction};

#[derive(Debug, Clone, PartialEq)]
enum SourceQuotaScope {
  ExplicitSource(String),
  DefaultBucket(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
struct SourceQuotaCheck {
  quota: usize,
  scope: SourceQuotaScope,
}

fn source_quota_check(
  automation: &crate::config::DynamicPolicyAutomationApiConfig,
  source: &str,
  max_policies: usize,
) -> SourceQuotaCheck {
  if let Some(quota) = automation
    .source_quotas
    .iter()
    .find(|quota| quota.source == source)
  {
    return SourceQuotaCheck {
      quota: quota.max_active_policies,
      scope: SourceQuotaScope::ExplicitSource(quota.source.clone()),
    };
  }

  SourceQuotaCheck {
    quota: automation.default_source_quota.unwrap_or(max_policies),
    scope: SourceQuotaScope::DefaultBucket(
      automation
        .source_quotas
        .iter()
        .map(|quota| quota.source.clone())
        .collect(),
    ),
  }
}

pub(super) async fn enforce_policy_quotas(
  tx: &mut Transaction<'_, Postgres>,
  inner: &super::super::DynamicPolicyInner,
  source: &str,
  exclude_id: Option<i64>,
  enabled: bool,
) -> anyhow::Result<()> {
  if !enabled {
    return Ok(());
  }
  let max_policies = i64::try_from(inner.config.max_policies)
    .context("dynamic_policy.max_policies does not fit in i64")?;
  let total_count: i64 = sqlx::query_scalar(
    "SELECT count(*) FROM oxibelt_dynamic_policies
      WHERE namespace = $1 AND enabled = true
        AND (expires_at IS NULL OR expires_at > now())
        AND ($2::bigint IS NULL OR id <> $2)",
  )
  .bind(inner.namespace.as_ref())
  .bind(exclude_id)
  .fetch_one(&mut **tx)
  .await?;
  if total_count >= max_policies {
    bail!(
      "dynamic policy active policy count exceeds max_policies ({})",
      inner.config.max_policies
    );
  }

  let quota_check = source_quota_check(
    &inner.config.automation_api,
    source,
    inner.config.max_policies,
  );
  let source_count: i64 = match &quota_check.scope {
    SourceQuotaScope::ExplicitSource(source) => {
      sqlx::query_scalar(
        "SELECT count(*) FROM oxibelt_dynamic_policies
        WHERE namespace = $1 AND source = $2 AND enabled = true
          AND (expires_at IS NULL OR expires_at > now())
          AND ($3::bigint IS NULL OR id <> $3)",
      )
      .bind(inner.namespace.as_ref())
      .bind(source)
      .bind(exclude_id)
      .fetch_one(&mut **tx)
      .await?
    }
    SourceQuotaScope::DefaultBucket(explicit_sources) => {
      sqlx::query_scalar(
        "SELECT count(*) FROM oxibelt_dynamic_policies
        WHERE namespace = $1 AND enabled = true
          AND (expires_at IS NULL OR expires_at > now())
          AND ($2::bigint IS NULL OR id <> $2)
          AND (cardinality($3::text[]) = 0 OR source <> ALL($3::text[]))",
      )
      .bind(inner.namespace.as_ref())
      .bind(exclude_id)
      .bind(explicit_sources)
      .fetch_one(&mut **tx)
      .await?
    }
  };
  if source_count >= i64::try_from(quota_check.quota).unwrap_or(i64::MAX) {
    match quota_check.scope {
      SourceQuotaScope::ExplicitSource(source) => {
        bail!(
          "dynamic policy source {source} exceeds active policy quota {}",
          quota_check.quota
        );
      }
      SourceQuotaScope::DefaultBucket(_) => {
        bail!(
          "dynamic policy default source quota exceeds active policy quota {}",
          quota_check.quota
        );
      }
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{DynamicPolicyAutomationApiConfig, DynamicPolicySourceQuotaConfig};

  #[test]
  fn explicit_source_quota_uses_its_own_source_scope() {
    let automation = DynamicPolicyAutomationApiConfig {
      enabled: true,
      require_ttl: true,
      signature_key_env: "OXIBELT_DYNAMIC_POLICY_HMAC_KEY".to_string(),
      default_source_quota: Some(10),
      source_quotas: vec![DynamicPolicySourceQuotaConfig {
        source: "vaultwarden".to_string(),
        max_active_policies: 5,
      }],
    };

    assert_eq!(
      source_quota_check(&automation, "vaultwarden", 100),
      SourceQuotaCheck {
        quota: 5,
        scope: SourceQuotaScope::ExplicitSource("vaultwarden".to_string()),
      }
    );
  }

  #[test]
  fn unknown_sources_share_the_default_quota_bucket() {
    let automation = DynamicPolicyAutomationApiConfig {
      enabled: true,
      require_ttl: true,
      signature_key_env: "OXIBELT_DYNAMIC_POLICY_HMAC_KEY".to_string(),
      default_source_quota: Some(10),
      source_quotas: vec![
        DynamicPolicySourceQuotaConfig {
          source: "vaultwarden".to_string(),
          max_active_policies: 5,
        },
        DynamicPolicySourceQuotaConfig {
          source: "crowdsec".to_string(),
          max_active_policies: 5,
        },
      ],
    };

    let check = source_quota_check(&automation, "attacker-rotated-source", 100);
    assert_eq!(check.quota, 10);
    assert_eq!(
      check.scope,
      SourceQuotaScope::DefaultBucket(vec!["vaultwarden".to_string(), "crowdsec".to_string()])
    );
  }

  #[test]
  fn omitted_default_quota_falls_back_to_the_global_cap_bucket() {
    let automation = DynamicPolicyAutomationApiConfig {
      enabled: true,
      require_ttl: true,
      signature_key_env: "OXIBELT_DYNAMIC_POLICY_HMAC_KEY".to_string(),
      default_source_quota: None,
      source_quotas: Vec::new(),
    };

    assert_eq!(
      source_quota_check(&automation, "any-source", 42),
      SourceQuotaCheck {
        quota: 42,
        scope: SourceQuotaScope::DefaultBucket(Vec::new()),
      }
    );
  }
}
