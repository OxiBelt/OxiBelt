use std::path::{Component, Path};
use std::time::Duration;

use anyhow::{Context, bail};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::cli::{RolloutTargetKind, RunArgs};
use super::model::KubernetesObject;
use super::rollout_patch::json_pointer_escape;

pub use super::rollout_patch::build_workload_patch;

#[path = "rollout/pod_ownership.rs"]
mod pod_ownership;
pub(crate) use pod_ownership::{WorkloadPodOwnership, pod_is_selected};

pub const IMMUTABLE_ROLLOUT_ANNOTATION: &str = "oxibelt.dev/immutable-config-rollout";
pub const CONFIG_REVISION_ANNOTATION: &str = "oxibelt.dev/config-revision";
pub const CONFIG_DIGEST_ANNOTATION: &str = "oxibelt.dev/config-digest";
pub const ARTIFACT_DIGEST_ANNOTATION: &str = "oxibelt.dev/gateway-config-artifact-digest";
pub const MANAGED_PATH_ANNOTATION: &str = "oxibelt.dev/gateway-config-managed-path";
pub const ROLLOUT_PHASE_ANNOTATION: &str = "oxibelt.dev/gateway-config-phase";
pub const DESIRED_REVISION_ANNOTATION: &str = "oxibelt.dev/gateway-config-desired";
pub const COMMITTED_REVISION_ANNOTATION: &str = "oxibelt.dev/gateway-config-committed";
pub const COMMITTED_DIGEST_ANNOTATION: &str = "oxibelt.dev/gateway-config-committed-digest";
pub const STARTED_AT_ANNOTATION: &str = "oxibelt.dev/gateway-config-started-at-unix";
pub const FAILURE_ANNOTATION: &str = "oxibelt.dev/gateway-config-failure";
pub const FAILED_REVISION_ANNOTATION: &str = "oxibelt.dev/gateway-config-failed-revision";
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const ROLLOUT_TARGET_LABEL: &str = "oxibelt.dev/rollout-target";
pub const ROLLOUT_TARGET_KIND_LABEL: &str = "oxibelt.dev/rollout-target-kind";

const CONTROLLER_NAME: &str = "oxibelt-gateway-controller";
const DIGEST_DOMAIN: &[u8] = b"oxibelt-gateway-config-v1\0";
const MAX_CONFIG_MAP_DATA_BYTES: usize = 900 * 1024;
const GENERATED_CONFIG_KEYS: &[&str] =
  &["external_auth", "routes", "sni_forward", "upstream_pools"];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WorkloadKind {
  Deployment,
  DaemonSet,
}

impl WorkloadKind {
  pub fn resource(self) -> &'static str {
    match self {
      Self::Deployment => "deployments",
      Self::DaemonSet => "daemonsets",
    }
  }

  pub fn api_prefix(self) -> &'static str {
    "/apis/apps/v1"
  }

  pub fn label_value(self) -> &'static str {
    match self {
      Self::Deployment => "deployment",
      Self::DaemonSet => "daemonset",
    }
  }

  pub fn from_cli(kind: RolloutTargetKind) -> Self {
    match kind {
      RolloutTargetKind::Deployment => Self::Deployment,
      RolloutTargetKind::DaemonSet => Self::DaemonSet,
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RolloutTarget {
  pub namespace: String,
  pub kind: WorkloadKind,
  pub name: String,
  pub container_name: String,
  pub volume_name: String,
  pub timeout: Duration,
  pub config_map_prefix: String,
}

impl RolloutTarget {
  pub fn from_args(args: &RunArgs) -> anyhow::Result<Self> {
    validate_dns_label("rollout target namespace", &args.rollout_target_namespace)?;
    validate_dns_label("rollout target name", &args.rollout_target_name)?;
    validate_dns_label(
      "rollout target container name",
      &args.rollout_target_container_name,
    )?;
    validate_dns_label("rollout volume name", &args.rollout_volume_name)?;
    validate_dns_label("rollout ConfigMap prefix", &args.rollout_config_map_prefix)?;
    if args.rollout_timeout_seconds == 0 {
      bail!("rollout timeout must be greater than zero seconds");
    }
    Ok(Self {
      namespace: args.rollout_target_namespace.clone(),
      kind: WorkloadKind::from_cli(args.rollout_target_kind),
      name: args.rollout_target_name.clone(),
      container_name: args.rollout_target_container_name.clone(),
      volume_name: args.rollout_volume_name.clone(),
      timeout: Duration::from_secs(args.rollout_timeout_seconds),
      config_map_prefix: args.rollout_config_map_prefix.clone(),
    })
  }

  pub fn workload_path(&self) -> String {
    format!(
      "{}/namespaces/{}/{}/{}",
      self.kind.api_prefix(),
      self.namespace,
      self.kind.resource(),
      self.name
    )
  }

  pub fn config_map_name(&self, artifact_digest: &str) -> String {
    format!(
      "{}-{}-{}-{artifact_digest}",
      self.config_map_prefix,
      self.kind.label_value(),
      self.name
    )
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigArtifact {
  pub name: String,
  pub artifact_digest: String,
  pub content_digest: String,
  pub managed_path: String,
  pub data_key: String,
  pub toml: String,
}

impl ConfigArtifact {
  pub fn new(target: &RolloutTarget, managed_path: &str, toml: String) -> anyhow::Result<Self> {
    let data_key = validate_managed_config_path(managed_path)?;
    validate_generated_toml(&toml)?;
    if toml.len() > MAX_CONFIG_MAP_DATA_BYTES {
      bail!(
        "generated configuration is {} bytes, exceeding the {} byte immutable ConfigMap safety limit",
        toml.len(),
        MAX_CONFIG_MAP_DATA_BYTES
      );
    }
    let artifact_digest = digest_artifact(managed_path, toml.as_bytes());
    let content_digest = digest_content(toml.as_bytes());
    let name = target.config_map_name(&artifact_digest);
    if name.len() > 253 {
      bail!("immutable ConfigMap name exceeds Kubernetes 253-character limit");
    }
    Ok(Self {
      name,
      artifact_digest,
      content_digest,
      managed_path: managed_path.to_string(),
      data_key,
      toml,
    })
  }

  pub fn manifest(&self, target: &RolloutTarget) -> Value {
    let mut labels = Map::new();
    labels.insert(
      MANAGED_BY_LABEL.to_string(),
      Value::String(CONTROLLER_NAME.to_string()),
    );
    labels.insert(
      ROLLOUT_TARGET_LABEL.to_string(),
      Value::String(target.name.clone()),
    );
    labels.insert(
      ROLLOUT_TARGET_KIND_LABEL.to_string(),
      Value::String(target.kind.label_value().to_string()),
    );
    let mut annotations = Map::new();
    annotations.insert(
      ARTIFACT_DIGEST_ANNOTATION.to_string(),
      Value::String(self.artifact_digest.clone()),
    );
    annotations.insert(
      CONFIG_DIGEST_ANNOTATION.to_string(),
      Value::String(self.content_digest.clone()),
    );
    annotations.insert(
      MANAGED_PATH_ANNOTATION.to_string(),
      Value::String(self.managed_path.clone()),
    );
    let mut data = Map::new();
    data.insert(self.data_key.clone(), Value::String(self.toml.clone()));
    json!({
      "apiVersion": "v1",
      "kind": "ConfigMap",
      "metadata": {
        "name": self.name,
        "namespace": target.namespace,
        "labels": labels,
        "annotations": annotations,
      },
      "immutable": true,
      "data": data,
    })
  }

  pub fn matches_existing(&self, target: &RolloutTarget, existing: &Value) -> bool {
    existing.pointer("/metadata/name").and_then(Value::as_str) == Some(self.name.as_str())
      && existing
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        == Some(target.namespace.as_str())
      && label(existing, MANAGED_BY_LABEL) == Some(CONTROLLER_NAME)
      && label(existing, ROLLOUT_TARGET_LABEL) == Some(target.name.as_str())
      && label(existing, ROLLOUT_TARGET_KIND_LABEL) == Some(target.kind.label_value())
      && existing.get("immutable").and_then(Value::as_bool) == Some(true)
      && existing
        .pointer(&format!("/data/{}", json_pointer_escape(&self.data_key)))
        .and_then(Value::as_str)
        == Some(self.toml.as_str())
      && annotation(existing, ARTIFACT_DIGEST_ANNOTATION) == Some(self.artifact_digest.as_str())
      && annotation(existing, CONFIG_DIGEST_ANNOTATION) == Some(self.content_digest.as_str())
      && annotation(existing, MANAGED_PATH_ANNOTATION) == Some(self.managed_path.as_str())
  }

  pub fn from_existing(target: &RolloutTarget, existing: &Value) -> anyhow::Result<Self> {
    let name = existing
      .pointer("/metadata/name")
      .and_then(Value::as_str)
      .context("immutable ConfigMap metadata.name is required")?;
    let managed_path = annotation(existing, MANAGED_PATH_ANNOTATION)
      .context("immutable ConfigMap managed path annotation is required")?;
    let data_key = validate_managed_config_path(managed_path)?;
    let toml = existing
      .pointer(&format!("/data/{}", json_pointer_escape(&data_key)))
      .and_then(Value::as_str)
      .context("immutable ConfigMap generated configuration data is required")?
      .to_string();
    let artifact = Self::new(target, managed_path, toml)?;
    if artifact.name != name || !artifact.matches_existing(target, existing) {
      bail!("immutable ConfigMap does not match its deterministic rollout identity");
    }
    Ok(artifact)
  }
}

pub fn canonicalize_objects(objects: &[KubernetesObject]) -> Vec<KubernetesObject> {
  let mut canonical = objects.to_vec();
  canonical.sort_by(|left, right| {
    (
      left.api_version.as_str(),
      left.kind.as_str(),
      left.namespace(),
      left.name(),
      left.spec.to_string(),
    )
      .cmp(&(
        right.api_version.as_str(),
        right.kind.as_str(),
        right.namespace(),
        right.name(),
        right.spec.to_string(),
      ))
  });
  canonical
}

pub fn digest_artifact(managed_path: &str, content: &[u8]) -> String {
  let mut digest = Sha256::new();
  digest.update(DIGEST_DOMAIN);
  digest.update(managed_path.as_bytes());
  digest.update(b"\0");
  digest.update(content);
  hex_digest(&digest.finalize())
}

pub fn digest_content(content: &[u8]) -> String {
  hex_digest(&Sha256::digest(content))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RolloutPhase {
  Generated,
  Validated,
  CanaryApplying,
  CanaryHealthy,
  Expanding,
  FullyApplied,
  Committed,
  RollbackRequested,
  RolledBack,
  Failed,
}

impl RolloutPhase {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Generated => "Generated",
      Self::Validated => "Validated",
      Self::CanaryApplying => "CanaryApplying",
      Self::CanaryHealthy => "CanaryHealthy",
      Self::Expanding => "Expanding",
      Self::FullyApplied => "FullyApplied",
      Self::Committed => "Committed",
      Self::RollbackRequested => "RollbackRequested",
      Self::RolledBack => "RolledBack",
      Self::Failed => "Failed",
    }
  }

  pub fn from_annotation(value: Option<&str>) -> Self {
    match value {
      Some("Generated") => Self::Generated,
      Some("Validated") => Self::Validated,
      Some("CanaryApplying") => Self::CanaryApplying,
      Some("CanaryHealthy") => Self::CanaryHealthy,
      Some("Expanding") => Self::Expanding,
      Some("FullyApplied") => Self::FullyApplied,
      Some("Committed") => Self::Committed,
      Some("RollbackRequested") => Self::RollbackRequested,
      Some("RolledBack") => Self::RolledBack,
      Some("Failed") => Self::Failed,
      _ => Self::Generated,
    }
  }

  pub fn is_committed(self) -> bool {
    self == Self::Committed
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RolloutState {
  pub phase: RolloutPhase,
  pub desired_revision: Option<String>,
  pub desired_artifact_digest: Option<String>,
  pub desired_content_digest: Option<String>,
  pub committed_revision: Option<String>,
  pub committed_content_digest: Option<String>,
  pub failed_revision: Option<String>,
  pub started_at_unix: Option<u64>,
  pub failure: Option<String>,
}

impl RolloutState {
  pub fn from_workload(workload: &Value) -> Self {
    let annotations = workload
      .pointer("/metadata/annotations")
      .and_then(Value::as_object);
    let get = |key| {
      annotations
        .and_then(|values| values.get(key))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    };
    Self {
      phase: RolloutPhase::from_annotation(get(ROLLOUT_PHASE_ANNOTATION)),
      desired_revision: get(DESIRED_REVISION_ANNOTATION).map(str::to_string),
      desired_artifact_digest: get(ARTIFACT_DIGEST_ANNOTATION).map(str::to_string),
      desired_content_digest: get(CONFIG_DIGEST_ANNOTATION).map(str::to_string),
      committed_revision: get(COMMITTED_REVISION_ANNOTATION).map(str::to_string),
      committed_content_digest: get(COMMITTED_DIGEST_ANNOTATION).map(str::to_string),
      failed_revision: get(FAILED_REVISION_ANNOTATION).map(str::to_string),
      started_at_unix: get(STARTED_AT_ANNOTATION).and_then(|value| value.parse().ok()),
      failure: get(FAILURE_ANNOTATION)
        .filter(|value| !value.is_empty())
        .map(str::to_string),
    }
  }

  pub fn new_attempt(artifact: &ConfigArtifact, previous: &Self, now_unix: u64) -> Self {
    Self {
      phase: RolloutPhase::CanaryApplying,
      desired_revision: Some(artifact.name.clone()),
      desired_artifact_digest: Some(artifact.artifact_digest.clone()),
      desired_content_digest: Some(artifact.content_digest.clone()),
      committed_revision: previous.committed_revision.clone(),
      committed_content_digest: previous.committed_content_digest.clone(),
      failed_revision: None,
      started_at_unix: Some(now_unix),
      failure: None,
    }
  }

  pub fn annotations(&self) -> Map<String, Value> {
    let mut annotations = Map::new();
    annotations.insert(
      ROLLOUT_PHASE_ANNOTATION.to_string(),
      Value::String(self.phase.as_str().to_string()),
    );
    insert_optional(
      &mut annotations,
      DESIRED_REVISION_ANNOTATION,
      self.desired_revision.as_deref(),
    );
    insert_optional(
      &mut annotations,
      ARTIFACT_DIGEST_ANNOTATION,
      self.desired_artifact_digest.as_deref(),
    );
    insert_optional(
      &mut annotations,
      CONFIG_DIGEST_ANNOTATION,
      self.desired_content_digest.as_deref(),
    );
    insert_optional(
      &mut annotations,
      COMMITTED_REVISION_ANNOTATION,
      self.committed_revision.as_deref(),
    );
    insert_optional(
      &mut annotations,
      COMMITTED_DIGEST_ANNOTATION,
      self.committed_content_digest.as_deref(),
    );
    insert_optional(
      &mut annotations,
      FAILED_REVISION_ANNOTATION,
      self.failed_revision.as_deref(),
    );
    insert_optional(
      &mut annotations,
      STARTED_AT_ANNOTATION,
      self
        .started_at_unix
        .map(|value| value.to_string())
        .as_deref(),
    );
    insert_optional(
      &mut annotations,
      FAILURE_ANNOTATION,
      self.failure.as_deref(),
    );
    annotations
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PodConvergence {
  pub selected: usize,
  pub ready: usize,
  pub desired_ready: usize,
  pub stale_ready: usize,
}

impl PodConvergence {
  pub fn fully_converged(&self) -> bool {
    self.ready == self.desired_ready && self.stale_ready == 0
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WorkloadConvergence {
  pub observed_generation: bool,
  pub expected_replicas: u32,
  pub updated_replicas: u32,
  pub ready_replicas: u32,
  pub available_replicas: u32,
  pub pods: PodConvergence,
}

impl WorkloadConvergence {
  pub fn all_replicas_converged(&self) -> bool {
    self.observed_generation
      && self.updated_replicas >= self.expected_replicas
      && self.ready_replicas >= self.expected_replicas
      && self.available_replicas >= self.expected_replicas
      && self.pods.fully_converged()
      && self.pods.desired_ready >= self.expected_replicas as usize
  }
}

pub fn evaluate_convergence(
  target: &RolloutTarget,
  workload: &Value,
  ownership: &WorkloadPodOwnership,
  pods: &[Value],
  revision: &str,
  content_digest: &str,
) -> WorkloadConvergence {
  let expected_replicas = match target.kind {
    WorkloadKind::Deployment => value_u32(workload, "/spec/replicas").unwrap_or(1),
    WorkloadKind::DaemonSet => value_u32(workload, "/status/desiredNumberScheduled").unwrap_or(0),
  };
  let observed_generation = value_i64(workload, "/status/observedGeneration")
    .zip(value_i64(workload, "/metadata/generation"))
    .is_some_and(|(observed, generation)| observed >= generation);
  let updated_replicas = match target.kind {
    WorkloadKind::Deployment => value_u32(workload, "/status/updatedReplicas").unwrap_or(0),
    WorkloadKind::DaemonSet => value_u32(workload, "/status/updatedNumberScheduled").unwrap_or(0),
  };
  let ready_replicas = match target.kind {
    WorkloadKind::Deployment => value_u32(workload, "/status/readyReplicas").unwrap_or(0),
    WorkloadKind::DaemonSet => value_u32(workload, "/status/numberReady").unwrap_or(0),
  };
  let available_replicas = match target.kind {
    WorkloadKind::Deployment => value_u32(workload, "/status/availableReplicas").unwrap_or(0),
    WorkloadKind::DaemonSet => value_u32(workload, "/status/numberAvailable").unwrap_or(0),
  };
  let mut selected = 0;
  let mut ready = 0;
  let mut desired_ready = 0;
  let mut stale_ready = 0;
  for pod in pods
    .iter()
    .filter(|pod| pod_is_selected(workload, ownership, pod))
  {
    if pod
      .pointer("/metadata/deletionTimestamp")
      .is_some_and(|value| !value.is_null())
    {
      continue;
    }
    selected += 1;
    if !pod_ready(pod) {
      continue;
    }
    ready += 1;
    if annotation(pod, CONFIG_REVISION_ANNOTATION) == Some(revision)
      && annotation(pod, CONFIG_DIGEST_ANNOTATION) == Some(content_digest)
    {
      desired_ready += 1;
    } else {
      stale_ready += 1;
    }
  }
  WorkloadConvergence {
    observed_generation,
    expected_replicas,
    updated_replicas,
    ready_replicas,
    available_replicas,
    pods: PodConvergence {
      selected,
      ready,
      desired_ready,
      stale_ready,
    },
  }
}

pub fn now_unix_seconds() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|duration| duration.as_secs())
    .unwrap_or_default()
}

fn validate_dns_label(name: &str, value: &str) -> anyhow::Result<()> {
  let valid = !value.is_empty()
    && value.len() <= 63
    && value
      .bytes()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    && !value.starts_with('-')
    && !value.ends_with('-');
  if !valid {
    bail!("{name} must be a lowercase Kubernetes DNS label");
  }
  Ok(())
}

fn validate_managed_config_path(path: &str) -> anyhow::Result<String> {
  let parsed = Path::new(path);
  if path.is_empty() || parsed.is_absolute() || path.contains('\\') {
    bail!("managed config path must be a non-empty relative POSIX path");
  }
  let mut normal = 0;
  for component in parsed.components() {
    match component {
      Component::Normal(_) => normal += 1,
      _ => bail!("managed config path must not contain traversal or empty components"),
    }
  }
  if normal == 0 {
    bail!("managed config path must name a regular file");
  }
  parsed
    .parent()
    .and_then(Path::to_str)
    .filter(|parent| !parent.is_empty() && *parent != ".")
    .context("managed config path must be nested below a configuration directory")?;
  let file_name = parsed
    .file_name()
    .and_then(|value| value.to_str())
    .context("managed config filename must be UTF-8")?;
  if file_name.is_empty()
    || !file_name
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
  {
    bail!("managed config filename cannot be represented as a ConfigMap data key");
  }
  Ok(file_name.to_string())
}

fn validate_generated_toml(toml: &str) -> anyhow::Result<()> {
  let value: toml::Value =
    toml::from_str(toml).context("generated configuration is not valid TOML")?;
  let table = value
    .as_table()
    .context("generated configuration must be a TOML table")?;
  for key in table.keys() {
    if !GENERATED_CONFIG_KEYS.contains(&key.as_str()) {
      bail!("generated configuration contains unsupported top-level key `{key}`");
    }
  }
  Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
  let mut value = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    use std::fmt::Write as _;
    let _ = write!(&mut value, "{byte:02x}");
  }
  value
}

fn insert_optional(map: &mut Map<String, Value>, key: &str, value: Option<&str>) {
  map.insert(
    key.to_string(),
    Value::String(value.unwrap_or_default().to_string()),
  );
}

pub(crate) fn annotation<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
  value
    .pointer("/metadata/annotations")
    .and_then(Value::as_object)
    .and_then(|annotations| annotations.get(key))
    .and_then(Value::as_str)
}

fn label<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
  value
    .pointer("/metadata/labels")
    .and_then(Value::as_object)
    .and_then(|labels| labels.get(key))
    .and_then(Value::as_str)
}

fn value_u32(value: &Value, pointer: &str) -> Option<u32> {
  value.pointer(pointer)?.as_u64()?.try_into().ok()
}

fn value_i64(value: &Value, pointer: &str) -> Option<i64> {
  value.pointer(pointer)?.as_i64()
}

fn pod_ready(pod: &Value) -> bool {
  pod
    .pointer("/status/conditions")
    .and_then(Value::as_array)
    .into_iter()
    .flatten()
    .any(|condition| {
      condition.get("type").and_then(Value::as_str) == Some("Ready")
        && condition.get("status").and_then(Value::as_str) == Some("True")
    })
}

#[cfg(test)]
#[path = "rollout/tests.rs"]
mod tests;
