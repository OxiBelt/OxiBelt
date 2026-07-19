//! Managed secret material resolved as part of an immutable application snapshot.

use anyhow::Context as _;

use super::AppSnapshot;
use crate::config::Config;
use crate::secret_activation::SecretReferenceRuntime;

pub(super) fn build(
  config: &Config,
  previous: Option<&AppSnapshot>,
) -> anyhow::Result<SecretReferenceRuntime> {
  SecretReferenceRuntime::from_config(config, previous.map(|snapshot| &snapshot.secret_references))
    .context("failed to resolve managed secret references")
}
