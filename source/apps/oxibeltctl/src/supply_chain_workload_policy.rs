//! Bounded, canonical container-image approvals for signed admission bundles.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};

pub(crate) const MAX_AUXILIARY_CONTAINERS: usize = 63;
const MAX_POLICY_BYTES: u64 = 64 * 1024;
const MAX_IMAGE_REFERENCE_BYTES: usize = 256;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AdmissionWorkloadPolicy {
  pub(crate) schema_version: u32,
  pub(crate) auxiliary_containers: Vec<ContainerApproval>,
}

impl Default for AdmissionWorkloadPolicy {
  fn default() -> Self {
    Self {
      schema_version: 1,
      auxiliary_containers: Vec::new(),
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContainerApproval {
  pub(crate) class: ContainerClass,
  pub(crate) name: String,
  pub(crate) image_reference: String,
}

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ContainerClass {
  Regular,
  Init,
  NativeSidecar,
  Ephemeral,
}

pub(crate) fn load_workload_policy(path: Option<&Path>) -> anyhow::Result<AdmissionWorkloadPolicy> {
  let Some(path) = path else {
    return Ok(AdmissionWorkloadPolicy::default());
  };
  let metadata = fs::symlink_metadata(path)
    .with_context(|| format!("failed to inspect workload policy: {}", path.display()))?;
  ensure!(
    metadata.file_type().is_file(),
    "workload policy must be a regular file"
  );
  ensure!(
    metadata.len() <= MAX_POLICY_BYTES,
    "workload policy exceeds its 64 KiB limit"
  );
  let file = fs::File::open(path)
    .with_context(|| format!("failed to open workload policy: {}", path.display()))?;
  let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
  file
    .take(MAX_POLICY_BYTES + 1)
    .read_to_end(&mut bytes)
    .with_context(|| format!("failed to read workload policy: {}", path.display()))?;
  ensure!(
    bytes.len() as u64 <= MAX_POLICY_BYTES,
    "workload policy exceeds its 64 KiB limit"
  );
  let policy = serde_json::from_slice(&bytes).context("workload policy has an invalid shape")?;
  canonicalize_workload_policy(policy)
}

pub(crate) fn canonicalize_workload_policy(
  mut policy: AdmissionWorkloadPolicy,
) -> anyhow::Result<AdmissionWorkloadPolicy> {
  validate_policy_entries(&policy)?;
  policy.auxiliary_containers.sort_by(|left, right| {
    (&left.class, &left.name, &left.image_reference).cmp(&(
      &right.class,
      &right.name,
      &right.image_reference,
    ))
  });
  Ok(policy)
}

pub(crate) fn validate_workload_policy(policy: &AdmissionWorkloadPolicy) -> anyhow::Result<()> {
  validate_policy_entries(policy)?;
  ensure!(
    policy.auxiliary_containers.windows(2).all(|entries| {
      (
        &entries[0].class,
        &entries[0].name,
        &entries[0].image_reference,
      ) < (
        &entries[1].class,
        &entries[1].name,
        &entries[1].image_reference,
      )
    }),
    "workload policy entries are not in canonical order"
  );
  Ok(())
}

fn validate_policy_entries(policy: &AdmissionWorkloadPolicy) -> anyhow::Result<()> {
  ensure!(
    policy.schema_version == 1,
    "workload policy schema must be 1"
  );
  ensure!(
    policy.auxiliary_containers.len() <= MAX_AUXILIARY_CONTAINERS,
    "workload policy exceeds 63 auxiliary containers"
  );
  let mut names = BTreeSet::new();
  for approval in &policy.auxiliary_containers {
    validate_container_name(&approval.name)?;
    ensure!(
      approval.name != "oxibelt",
      "workload policy reserves the oxibelt container name for the primary artifact"
    );
    ensure!(
      names.insert(approval.name.as_str()),
      "workload policy contains a duplicate container name"
    );
    validate_image_reference(&approval.image_reference)?;
  }
  Ok(())
}

pub(crate) fn validate_container_name(name: &str) -> anyhow::Result<()> {
  let bytes = name.as_bytes();
  ensure!(
    (1..=63).contains(&bytes.len())
      && bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
      && bytes
        .last()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
      && bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'),
    "container name must be a lowercase Kubernetes DNS label"
  );
  Ok(())
}

pub(crate) fn validate_image_reference(reference: &str) -> anyhow::Result<()> {
  ensure!(
    !reference.is_empty() && reference.len() <= MAX_IMAGE_REFERENCE_BYTES,
    "container image reference must contain at most 256 bytes"
  );
  let (repository, digest) = reference
    .split_once('@')
    .context("container image reference must contain one sha256 digest")?;
  ensure!(
    !repository.contains('@') && !digest.contains('@'),
    "container image reference must contain one sha256 digest"
  );
  validate_repository(repository)?;
  ensure!(
    digest.len() == 71
      && digest.starts_with("sha256:")
      && digest[7..]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
    "container image digest must be sha256 followed by 64 lowercase hexadecimal characters"
  );
  Ok(())
}

fn validate_repository(repository: &str) -> anyhow::Result<()> {
  ensure!(
    repository.bytes().all(|byte| byte.is_ascii_lowercase()
      || byte.is_ascii_digit()
      || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')),
    "container image repository contains unsupported characters"
  );
  let mut parts = repository.split('/');
  let registry = parts.next().unwrap_or_default();
  let path = parts.collect::<Vec<_>>();
  ensure!(
    !registry.is_empty() && !path.is_empty(),
    "container image repository must include a registry host and path"
  );
  validate_registry(registry)?;
  for component in path {
    let bytes = component.as_bytes();
    ensure!(
      !bytes.is_empty()
        && bytes
          .first()
          .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
          .last()
          .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
          byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }),
      "container image repository path is not canonical"
    );
  }
  Ok(())
}

fn validate_registry(registry: &str) -> anyhow::Result<()> {
  let (host, port) = match registry.rsplit_once(':') {
    Some((host, port)) => (host, Some(port)),
    None => (registry, None),
  };
  if let Some(port) = port {
    ensure!(
      !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|value| value > 0),
      "container image registry port is invalid"
    );
  }
  ensure!(
    host == "localhost" || host.contains('.') || port.is_some(),
    "container image repository must use a fully qualified registry"
  );
  ensure!(
    host.split('.').all(|label| {
      let bytes = label.as_bytes();
      !bytes.is_empty()
        && bytes
          .first()
          .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
          .last()
          .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
          .iter()
          .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    }),
    "container image registry host is invalid"
  );
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn approval(class: ContainerClass, name: &str, digest: char) -> ContainerApproval {
    ContainerApproval {
      class,
      name: name.to_string(),
      image_reference: format!(
        "ghcr.io/example/{name}@sha256:{}",
        digest.to_string().repeat(64)
      ),
    }
  }

  #[test]
  fn canonical_policy_accepts_each_container_class() {
    let policy = canonicalize_workload_policy(AdmissionWorkloadPolicy {
      schema_version: 1,
      auxiliary_containers: vec![
        approval(ContainerClass::Ephemeral, "debugger", 'd'),
        approval(ContainerClass::Regular, "mesh-proxy", 'a'),
        approval(ContainerClass::NativeSidecar, "log-shipper", 'c'),
        approval(ContainerClass::Init, "setup", 'b'),
      ],
    })
    .expect("policy");
    assert_eq!(
      policy
        .auxiliary_containers
        .iter()
        .map(|entry| entry.class)
        .collect::<Vec<_>>(),
      [
        ContainerClass::Regular,
        ContainerClass::Init,
        ContainerClass::NativeSidecar,
        ContainerClass::Ephemeral,
      ]
    );
    validate_workload_policy(&policy).expect("canonical policy");
  }

  #[test]
  fn invalid_names_images_duplicates_and_bounds_fail_closed() {
    let valid = approval(ContainerClass::Regular, "mesh-proxy", 'a');
    let mut cases = Vec::new();
    let mut reserved = valid.clone();
    reserved.name = "oxibelt".to_string();
    cases.push(reserved);
    let mut uppercase = valid.clone();
    uppercase.name = "Mesh".to_string();
    cases.push(uppercase);
    let mut tagged = valid.clone();
    tagged.image_reference = "ghcr.io/example/mesh-proxy:latest".to_string();
    cases.push(tagged);
    let mut uppercase_digest = valid.clone();
    uppercase_digest.image_reference =
      format!("ghcr.io/example/mesh-proxy@sha256:{}", "A".repeat(64));
    cases.push(uppercase_digest);
    let mut unqualified = valid;
    unqualified.image_reference = format!("example/mesh-proxy@sha256:{}", "a".repeat(64));
    cases.push(unqualified);

    for invalid in cases {
      assert!(
        canonicalize_workload_policy(AdmissionWorkloadPolicy {
          schema_version: 1,
          auxiliary_containers: vec![invalid],
        })
        .is_err()
      );
    }

    let duplicate = approval(ContainerClass::Init, "setup", 'a');
    assert!(
      canonicalize_workload_policy(AdmissionWorkloadPolicy {
        schema_version: 1,
        auxiliary_containers: vec![duplicate.clone(), duplicate],
      })
      .is_err()
    );
    assert!(
      canonicalize_workload_policy(AdmissionWorkloadPolicy {
        schema_version: 1,
        auxiliary_containers: (0..=MAX_AUXILIARY_CONTAINERS)
          .map(|index| approval(ContainerClass::Init, &format!("setup-{index}"), 'a'))
          .collect(),
      })
      .is_err()
    );
  }

  #[test]
  fn canonical_validation_rejects_reordered_signed_entries() {
    let policy = AdmissionWorkloadPolicy {
      schema_version: 1,
      auxiliary_containers: vec![
        approval(ContainerClass::Init, "setup", 'b'),
        approval(ContainerClass::Regular, "mesh-proxy", 'a'),
      ],
    };
    assert!(validate_workload_policy(&policy).is_err());
  }

  #[test]
  fn policy_file_is_bounded_strict_and_canonicalized() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("workload-policy.json");
    fs::write(
      &path,
      serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "auxiliaryContainers": [
          approval(ContainerClass::Ephemeral, "debugger", 'b'),
          approval(ContainerClass::Regular, "mesh-proxy", 'a')
        ]
      }))
      .expect("policy JSON"),
    )
    .expect("write policy");
    let policy = load_workload_policy(Some(&path)).expect("load policy");
    assert_eq!(
      policy.auxiliary_containers[0].class,
      ContainerClass::Regular
    );

    fs::write(
      &path,
      br#"{"schemaVersion":1,"auxiliaryContainers":[],"unknown":true}"#,
    )
    .expect("write unknown field");
    assert!(load_workload_policy(Some(&path)).is_err());

    fs::write(
      &path,
      vec![b' '; usize::try_from(MAX_POLICY_BYTES + 1).expect("size")],
    )
    .expect("write oversized policy");
    assert!(load_workload_policy(Some(&path)).is_err());
  }
}
