//! Dynamic policy admin precondition handling.
//! ETags protect concurrent writes from overwriting newer policy state.

use std::fmt;

use serde::Serialize;
use sqlx::{Postgres, Transaction};

use super::store::lock_generation_tx;

#[derive(Debug, Clone, Serialize)]
pub struct DynamicPolicyAdminStatus {
  pub namespace: String,
  pub generation: i64,
  pub etag: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum DynamicPolicyPreconditionMode {
  Required,
  Optional,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DynamicPolicyPreconditionErrorKind {
  Missing,
  Stale,
}

#[derive(Debug, Clone)]
pub struct DynamicPolicyPreconditionError {
  kind: DynamicPolicyPreconditionErrorKind,
  expected: String,
}

impl DynamicPolicyPreconditionError {
  pub fn kind(&self) -> DynamicPolicyPreconditionErrorKind {
    self.kind
  }

  pub fn expected(&self) -> &str {
    &self.expected
  }
}

impl fmt::Display for DynamicPolicyPreconditionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.kind {
      DynamicPolicyPreconditionErrorKind::Missing => write!(formatter, "If-Match is required"),
      DynamicPolicyPreconditionErrorKind::Stale => {
        write!(
          formatter,
          "If-Match does not match the active dynamic policy generation"
        )
      }
    }
  }
}

impl std::error::Error for DynamicPolicyPreconditionError {}

pub(super) async fn check_if_match_tx(
  tx: &mut Transaction<'_, Postgres>,
  namespace: &str,
  if_match: Option<&str>,
  mode: DynamicPolicyPreconditionMode,
) -> anyhow::Result<()> {
  let generation = lock_generation_tx(tx, namespace).await?;
  let expected = dynamic_policy_etag(generation);
  match if_match {
    Some(value) if value == expected => Ok(()),
    Some(_) => Err(
      DynamicPolicyPreconditionError {
        kind: DynamicPolicyPreconditionErrorKind::Stale,
        expected,
      }
      .into(),
    ),
    None if mode == DynamicPolicyPreconditionMode::Required => Err(
      DynamicPolicyPreconditionError {
        kind: DynamicPolicyPreconditionErrorKind::Missing,
        expected,
      }
      .into(),
    ),
    None => Ok(()),
  }
}

pub fn dynamic_policy_etag(generation: i64) -> String {
  format!("\"oxibelt-dynamic-policy-{generation}\"")
}
