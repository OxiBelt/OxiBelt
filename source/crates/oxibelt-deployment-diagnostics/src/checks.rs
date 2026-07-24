//! Kubernetes workload relationship checks.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, bail};
use serde_json::Value;

use oxibelt::diagnostics::{DiagnosticReport, DiagnosticSeverity};

use super::Manifest;

const IMMUTABLE_ROLLOUT: &str = "oxibelt.dev/immutable-config-rollout";
const CONFIG_REVISION: &str = "oxibelt.dev/config-revision";
const CONFIG_DIGEST: &str = "oxibelt.dev/config-digest";
const EFFECTIVE_VERSION: &str = "oxibelt.dev/effective-version";

#[derive(Debug, Clone)]
struct ControllerTarget {
  namespace: String,
  kind: String,
  name: String,
  container_name: String,
  volume_name: String,
  controller_version: String,
  compatibility_mode: String,
  previous_version: Option<String>,
  deadline: Option<String>,
}

pub(super) fn diagnose_manifests(manifests: Vec<Manifest>) -> DiagnosticReport {
  let mut report = DiagnosticReport::new();
  let workloads = manifests
    .iter()
    .filter(|manifest| is_workload(manifest))
    .collect::<Vec<_>>();
  let mut targets = Vec::new();

  for workload in &workloads {
    for container in pod_containers(&workload.value) {
      if !is_gateway_controller(container) {
        continue;
      }
      match controller_target(&workload.value, container) {
        Ok(target) => targets.push(target),
        Err(error) => report.push(
          DiagnosticSeverity::Error,
          "kubernetes.controller_rollout_wiring",
          "kubernetes",
          workload_target(workload),
          format!("Gateway Controller rollout wiring is incomplete: {error}"),
          "Configure every required --rollout-target-* argument and point it at an immutable OxiBelt workload.",
        ),
      }
    }
  }

  let target_keys = targets
    .iter()
    .map(ControllerTarget::key)
    .collect::<HashSet<_>>();
  let target_containers = targets.iter().fold(
    HashMap::<String, Vec<String>>::new(),
    |mut result, target| {
      result
        .entry(target.key())
        .or_default()
        .push(target.container_name.clone());
      result
    },
  );

  for target in &targets {
    let Some(workload) = workloads
      .iter()
      .copied()
      .find(|workload| target.matches(workload))
    else {
      // Separate chart renders cannot prove a target is missing. A present
      // target, however, is checked completely and deterministically.
      continue;
    };
    if let Err(reason) = verify_controller_target(workload, target) {
      report.push(
        DiagnosticSeverity::Error,
        "kubernetes.controller_rollout_wiring",
        "kubernetes",
        workload_target(workload),
        format!("Gateway Controller target wiring is unsafe: {reason}"),
        "Use immutable rollout opt-in, a read-only base ConfigMap mount, or the controller-owned projected rollout volume for the target configuration root.",
      );
    }
    if let Err(reason) = verify_version_compatibility(workload, target) {
      report.push(
        DiagnosticSeverity::Error,
        "kubernetes.component_version_skew",
        "kubernetes",
        workload_target(workload),
        format!("Gateway Controller/data-plane compatibility is unsafe: {reason}"),
        "Set matching oxibelt.dev/effective-version pod-template annotations, or use a bounded rolling_upgrade window for the immediately preceding minor.",
      );
    }
  }

  for workload in &workloads {
    if !is_oxibelt_workload(workload) && !is_gateway_controller_workload(workload) {
      continue;
    }
    diagnose_mutable_images(&mut report, workload);

    let key = workload_key(workload);
    let rollout_scoped = has_immutable_rollout_opt_in(workload) || target_keys.contains(&key);
    if !rollout_scoped || !is_multi_instance(workload, &manifests) {
      continue;
    }
    let expected_containers = target_containers
      .get(&key)
      .cloned()
      .unwrap_or_else(|| oxibelt_container_names(workload));
    if let Err(reason) = verify_cluster_acknowledgement(workload, &expected_containers) {
      report.push(
        DiagnosticSeverity::Error,
        "kubernetes.multi_instance_missing_revision",
        "kubernetes",
        workload_target(workload),
        format!("multiple replicas lack cluster-wide configuration acknowledgement: {reason}"),
        "Add immutable rollout revision and digest annotations, Downward API environment variables, an instance ID, revision-file wiring, and a readiness probe before scaling out.",
      );
    }
  }

  report.finish()
}

impl ControllerTarget {
  fn key(&self) -> String {
    format!("{}/{}/{}", self.kind, self.namespace, self.name)
  }

  fn matches(&self, manifest: &Manifest) -> bool {
    self.kind
      == workload_kind(manifest)
        .unwrap_or_default()
        .to_ascii_lowercase()
      && self.namespace == manifest_namespace(manifest)
      && self.name == metadata_name(&manifest.value).unwrap_or_default()
  }
}

fn controller_target(workload: &Value, container: &Value) -> anyhow::Result<ControllerTarget> {
  let args = string_array(container.get("args"));
  let namespace = required_option(&args, "--rollout-target-namespace")?;
  let kind = required_option(&args, "--rollout-target-kind")?.to_ascii_lowercase();
  if !matches!(kind.as_str(), "deployment" | "daemonset") {
    bail!("--rollout-target-kind must be deployment or daemonset");
  }
  let compatibility_mode = option_value(&args, "--compatibility-mode")
    .unwrap_or("exact")
    .to_string();
  let previous_version = option_value(&args, "--compatibility-previous-version")
    .filter(|value| !value.is_empty())
    .map(str::to_string);
  let deadline = option_value(&args, "--compatibility-deadline")
    .filter(|value| !value.is_empty())
    .map(str::to_string);
  match compatibility_mode.as_str() {
    "exact" if previous_version.is_some() || deadline.is_some() => {
      bail!("exact compatibility mode must not set previous version or deadline");
    }
    "exact" => {}
    "rolling_upgrade" if previous_version.is_none() || deadline.is_none() => {
      bail!("rolling_upgrade compatibility mode requires previous version and deadline");
    }
    "rolling_upgrade" => {}
    _ => bail!("--compatibility-mode must be exact or rolling_upgrade"),
  }
  let controller_version = annotation(
    workload,
    "/spec/template/metadata/annotations",
    EFFECTIVE_VERSION,
  )
  .filter(|value| !value.is_empty())
  .context("controller pod template is missing oxibelt.dev/effective-version")?
  .to_string();
  Ok(ControllerTarget {
    namespace,
    kind,
    name: required_option(&args, "--rollout-target-name")?,
    container_name: option_value(&args, "--rollout-target-container-name")
      .unwrap_or("oxibelt")
      .to_string(),
    volume_name: option_value(&args, "--rollout-volume-name")
      .unwrap_or("gateway-config")
      .to_string(),
    controller_version,
    compatibility_mode,
    previous_version,
    deadline,
  })
}

fn verify_version_compatibility(
  workload: &Manifest,
  target: &ControllerTarget,
) -> anyhow::Result<()> {
  let observed = annotation(
    &workload.value,
    "/spec/template/metadata/annotations",
    EFFECTIVE_VERSION,
  )
  .filter(|value| !value.is_empty())
  .context("target pod template is missing oxibelt.dev/effective-version")?;
  match target.compatibility_mode.as_str() {
    "exact" if observed == target.controller_version => Ok(()),
    "exact" => bail!(
      "target version `{observed}` does not match controller version `{}` in exact mode",
      target.controller_version
    ),
    "rolling_upgrade"
      if observed == target.controller_version
        || target.previous_version.as_deref() == Some(observed) =>
    {
      let deadline = target
        .deadline
        .as_deref()
        .context("rolling_upgrade deadline is missing")?;
      if !looks_like_rfc3339_utc(deadline) {
        bail!("rolling_upgrade deadline is not an RFC3339 UTC timestamp");
      }
      Ok(())
    }
    "rolling_upgrade" => bail!(
      "target version `{observed}` is neither controller version `{}` nor permitted previous version",
      target.controller_version
    ),
    _ => bail!("unsupported compatibility mode"),
  }
}

fn looks_like_rfc3339_utc(value: &str) -> bool {
  let bytes = value.as_bytes();
  bytes.len() == 20
    && bytes[4] == b'-'
    && bytes[7] == b'-'
    && bytes[10] == b'T'
    && bytes[13] == b':'
    && bytes[16] == b':'
    && bytes[19] == b'Z'
    && bytes
      .iter()
      .enumerate()
      .all(|(index, byte)| matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit())
}

fn required_option(args: &[String], option: &str) -> anyhow::Result<String> {
  option_value(args, option)
    .filter(|value| !value.is_empty())
    .map(str::to_string)
    .ok_or_else(|| anyhow::anyhow!("missing {option}"))
}

fn option_value<'a>(args: &'a [String], option: &str) -> Option<&'a str> {
  let prefix = format!("{option}=");
  for (index, value) in args.iter().enumerate() {
    if let Some(value) = value.strip_prefix(&prefix) {
      return Some(value);
    }
    if value == option {
      return args.get(index + 1).map(String::as_str);
    }
  }
  None
}

fn verify_controller_target(workload: &Manifest, target: &ControllerTarget) -> anyhow::Result<()> {
  if !has_immutable_rollout_opt_in(workload) {
    bail!(
      "{} is not opted into immutable configuration rollout",
      workload_target(workload)
    );
  }
  let container = pod_containers(&workload.value)
    .into_iter()
    .find(|container| {
      container.get("name").and_then(Value::as_str) == Some(target.container_name.as_str())
    })
    .ok_or_else(|| anyhow::anyhow!("target container {} is absent", target.container_name))?;
  let args = string_array(container.get("args"));
  let config_path = option_value(&args, "--config")
    .filter(|path| Path::new(path).is_absolute())
    .ok_or_else(|| anyhow::anyhow!("target container has no absolute --config path"))?;
  let config_root = Path::new(config_path)
    .parent()
    .and_then(Path::to_str)
    .ok_or_else(|| anyhow::anyhow!("target --config path has no UTF-8 parent directory"))?;
  let mounts = container
    .get("volumeMounts")
    .and_then(Value::as_array)
    .ok_or_else(|| anyhow::anyhow!("target container has no volumeMounts"))?;
  let mounts = mounts
    .iter()
    .filter(|mount| mount.get("mountPath").and_then(Value::as_str) == Some(config_root))
    .collect::<Vec<_>>();
  if mounts.len() != 1 {
    bail!("target configuration root must have exactly one volume mount");
  }
  let mount = mounts[0];
  if mount.get("readOnly").and_then(Value::as_bool) != Some(true) {
    bail!("target configuration root mount must be read-only");
  }
  if mount.get("subPath").is_some() || mount.get("subPathExpr").is_some() {
    bail!("target configuration root mount must not use subPath");
  }
  let volume_name = mount
    .get("name")
    .and_then(Value::as_str)
    .ok_or_else(|| anyhow::anyhow!("target configuration root mount has no volume name"))?;
  let volume = pod_spec(&workload.value)
    .and_then(|spec| spec.get("volumes"))
    .and_then(Value::as_array)
    .and_then(|volumes| {
      volumes
        .iter()
        .find(|volume| volume.get("name").and_then(Value::as_str) == Some(volume_name))
    })
    .ok_or_else(|| anyhow::anyhow!("target configuration root volume is absent"))?;
  if volume.get("configMap").and_then(Value::as_object).is_some() {
    return Ok(());
  }
  if volume_name == target.volume_name
    && volume.get("projected").and_then(Value::as_object).is_some()
  {
    return Ok(());
  }
  bail!(
    "target configuration root is neither a base ConfigMap nor the controller-owned projected rollout volume"
  )
}

fn verify_cluster_acknowledgement(
  workload: &Manifest,
  expected_containers: &[String],
) -> anyhow::Result<()> {
  let annotations = template_annotations(workload)
    .ok_or_else(|| anyhow::anyhow!("pod template has no annotations"))?;
  for annotation in [CONFIG_REVISION, CONFIG_DIGEST] {
    if annotations
      .get(annotation)
      .and_then(Value::as_str)
      .is_none_or(str::is_empty)
    {
      bail!("pod template is missing {annotation}");
    }
  }
  if expected_containers.is_empty() {
    bail!("no OxiBelt target container could be identified");
  }
  for name in expected_containers {
    let container = pod_containers(&workload.value)
      .into_iter()
      .find(|container| container.get("name").and_then(Value::as_str) == Some(name.as_str()))
      .ok_or_else(|| anyhow::anyhow!("target container {name} is absent"))?;
    if !env_has_value(
      container,
      "OXIBELT_CONFIG_ROLLOUT_MODE",
      "kubernetes_immutable",
    ) {
      bail!("target container {name} lacks OXIBELT_CONFIG_ROLLOUT_MODE=kubernetes_immutable");
    }
    if !env_has_field_ref(
      container,
      "OXIBELT_CONFIG_REVISION",
      "metadata.annotations['oxibelt.dev/config-revision']",
    ) {
      bail!("target container {name} lacks a Downward API configuration revision");
    }
    if !env_has_field_ref(
      container,
      "OXIBELT_CONFIG_DIGEST",
      "metadata.annotations['oxibelt.dev/config-digest']",
    ) {
      bail!("target container {name} lacks a Downward API configuration digest");
    }
    if !env_has_nonempty_value(container, "OXIBELT_CONFIG_REVISION_FILE") {
      bail!("target container {name} lacks OXIBELT_CONFIG_REVISION_FILE");
    }
    if !env_has_field_ref(container, "OXIBELT_INSTANCE_ID", "metadata.uid") {
      bail!("target container {name} lacks a Downward API instance ID");
    }
    if container
      .get("readinessProbe")
      .and_then(Value::as_object)
      .is_none()
    {
      bail!("target container {name} has no readiness probe");
    }
  }
  Ok(())
}

fn diagnose_mutable_images(report: &mut DiagnosticReport, workload: &Manifest) {
  for container in pod_containers(&workload.value)
    .into_iter()
    .chain(pod_init_containers(&workload.value))
  {
    let image = container
      .get("image")
      .and_then(Value::as_str)
      .unwrap_or_default();
    if is_digest_pinned(image) {
      continue;
    }
    let name = container
      .get("name")
      .and_then(Value::as_str)
      .unwrap_or("unnamed");
    report.push(
      DiagnosticSeverity::Warning,
      "release.image_not_digest_pinned",
      "release",
      format!("{}/containers/{name}", workload_target(workload)),
      "container image is referenced without a SHA-256 digest",
      "Pin the OxiBelt or Gateway Controller image as repository@sha256:<64 lowercase hex characters>.",
    );
  }
}

pub(super) fn is_digest_pinned(image: &str) -> bool {
  let Some((_, digest)) = image.rsplit_once("@sha256:") else {
    return false;
  };
  digest.len() == 64
    && digest
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit()))
}

fn is_multi_instance(workload: &Manifest, manifests: &[Manifest]) -> bool {
  if workload_kind(workload) == Some("DaemonSet") {
    return true;
  }
  workload
    .value
    .pointer("/spec/replicas")
    .and_then(Value::as_u64)
    .unwrap_or(1)
    > 1
    || manifests
      .iter()
      .any(|candidate| hpa_scales_workload(candidate, workload))
}

fn hpa_scales_workload(candidate: &Manifest, workload: &Manifest) -> bool {
  if manifest_kind(candidate) != Some("HorizontalPodAutoscaler")
    || manifest_namespace(candidate) != manifest_namespace(workload)
  {
    return false;
  }
  let Some(target) = candidate.value.pointer("/spec/scaleTargetRef") else {
    return false;
  };
  target
    .get("kind")
    .and_then(Value::as_str)
    .is_some_and(|kind| kind.eq_ignore_ascii_case(workload_kind(workload).unwrap_or_default()))
    && target.get("name").and_then(Value::as_str) == metadata_name(&workload.value)
    && candidate
      .value
      .pointer("/spec/maxReplicas")
      .and_then(Value::as_u64)
      .is_some_and(|replicas| replicas > 1)
}

fn has_immutable_rollout_opt_in(workload: &Manifest) -> bool {
  annotation(&workload.value, "/metadata/annotations", IMMUTABLE_ROLLOUT) == Some("true")
    && annotation(
      &workload.value,
      "/spec/template/metadata/annotations",
      IMMUTABLE_ROLLOUT,
    ) == Some("true")
}

fn annotation<'a>(value: &'a Value, path: &str, key: &str) -> Option<&'a str> {
  value.pointer(path)?.get(key)?.as_str()
}

fn template_annotations(workload: &Manifest) -> Option<&serde_json::Map<String, Value>> {
  workload
    .value
    .pointer("/spec/template/metadata/annotations")
    .and_then(Value::as_object)
}

fn env_has_value(container: &Value, name: &str, expected: &str) -> bool {
  env_entry(container, name)
    .and_then(|entry| entry.get("value"))
    .and_then(Value::as_str)
    == Some(expected)
}

fn env_has_nonempty_value(container: &Value, name: &str) -> bool {
  env_entry(container, name)
    .and_then(|entry| entry.get("value"))
    .and_then(Value::as_str)
    .is_some_and(|value| !value.is_empty())
}

fn env_has_field_ref(container: &Value, name: &str, expected: &str) -> bool {
  env_entry(container, name)
    .and_then(|entry| entry.pointer("/valueFrom/fieldRef/fieldPath"))
    .and_then(Value::as_str)
    == Some(expected)
}

fn env_entry<'a>(container: &'a Value, name: &str) -> Option<&'a Value> {
  container
    .get("env")
    .and_then(Value::as_array)?
    .iter()
    .find(|entry| entry.get("name").and_then(Value::as_str) == Some(name))
}

fn pod_spec(value: &Value) -> Option<&Value> {
  value.pointer("/spec/template/spec")
}

fn pod_containers(value: &Value) -> Vec<&Value> {
  pod_spec(value)
    .and_then(|spec| spec.get("containers"))
    .and_then(Value::as_array)
    .map_or_else(Vec::new, |containers| containers.iter().collect())
}

fn pod_init_containers(value: &Value) -> Vec<&Value> {
  pod_spec(value)
    .and_then(|spec| spec.get("initContainers"))
    .and_then(Value::as_array)
    .map_or_else(Vec::new, |containers| containers.iter().collect())
}

fn string_array(value: Option<&Value>) -> Vec<String> {
  value
    .and_then(Value::as_array)
    .map_or_else(Vec::new, |values| {
      values
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
    })
}

fn is_gateway_controller(container: &Value) -> bool {
  command_contains(container, "/usr/local/bin/oxibelt-gateway-controller")
}

fn is_gateway_controller_workload(workload: &Manifest) -> bool {
  pod_containers(&workload.value)
    .into_iter()
    .any(is_gateway_controller)
}

fn is_oxibelt_workload(workload: &Manifest) -> bool {
  pod_containers(&workload.value)
    .into_iter()
    .any(|container| command_contains(container, "/usr/local/bin/oxibelt"))
}

fn oxibelt_container_names(workload: &Manifest) -> Vec<String> {
  pod_containers(&workload.value)
    .into_iter()
    .filter(|container| command_contains(container, "/usr/local/bin/oxibelt"))
    .filter_map(|container| container.get("name").and_then(Value::as_str))
    .map(str::to_string)
    .collect()
}

fn command_contains(container: &Value, expected: &str) -> bool {
  container
    .get("command")
    .and_then(Value::as_array)
    .is_some_and(|command| {
      command
        .iter()
        .filter_map(Value::as_str)
        .any(|value| value == expected)
    })
}

fn is_workload(manifest: &Manifest) -> bool {
  matches!(manifest_kind(manifest), Some("Deployment" | "DaemonSet"))
}

fn workload_kind(manifest: &Manifest) -> Option<&str> {
  manifest_kind(manifest).filter(|kind| matches!(*kind, "Deployment" | "DaemonSet"))
}

fn manifest_kind(manifest: &Manifest) -> Option<&str> {
  manifest.value.get("kind").and_then(Value::as_str)
}

fn workload_key(workload: &Manifest) -> String {
  format!(
    "{}/{}/{}",
    workload_kind(workload)
      .unwrap_or_default()
      .to_ascii_lowercase(),
    manifest_namespace(workload),
    metadata_name(&workload.value).unwrap_or_default()
  )
}

fn workload_target(workload: &Manifest) -> String {
  format!(
    "{} {}/{} ({}, document {})",
    workload_kind(workload).unwrap_or("Workload"),
    manifest_namespace(workload),
    metadata_name(&workload.value).unwrap_or("unnamed"),
    workload.source,
    workload.document,
  )
}

fn manifest_namespace(manifest: &Manifest) -> &str {
  metadata_namespace(&manifest.value).unwrap_or(&manifest.default_namespace)
}

fn metadata_name(value: &Value) -> Option<&str> {
  value.pointer("/metadata/name").and_then(Value::as_str)
}

fn metadata_namespace(value: &Value) -> Option<&str> {
  value.pointer("/metadata/namespace").and_then(Value::as_str)
}
