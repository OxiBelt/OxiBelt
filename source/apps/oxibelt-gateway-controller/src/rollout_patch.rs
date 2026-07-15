use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, bail};
use serde_json::{Map, Value, json};

use super::rollout::{
  ARTIFACT_DIGEST_ANNOTATION, CONFIG_DIGEST_ANNOTATION, CONFIG_REVISION_ANNOTATION, ConfigArtifact,
  IMMUTABLE_ROLLOUT_ANNOTATION, MANAGED_PATH_ANNOTATION, RolloutState, RolloutTarget, annotation,
};

#[path = "rollout_patch/volume.rs"]
mod volume;
use volume::patch_projected_volume;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WorkloadPatch {
  pub operations: Vec<Value>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BaseConfigReference {
  pub config_map_name: String,
  pub data_key: String,
  pub placeholder_key: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum BaseConfigLayoutKind {
  Bootstrap,
  Projected { volume_index: usize },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct BaseConfigLayout {
  pub(super) reference: BaseConfigReference,
  pub(super) kind: BaseConfigLayoutKind,
  pub(super) container_index: usize,
  pub(super) mount_index: usize,
  pub(super) config_root: String,
  pub(super) projected_source: Value,
  pub(super) default_mode: Option<Value>,
}

pub fn base_config_reference(
  workload: &Value,
  target: &RolloutTarget,
  managed_path: &str,
) -> anyhow::Result<BaseConfigReference> {
  Ok(base_config_layout(workload, target, managed_path)?.reference)
}

fn base_config_layout(
  workload: &Value,
  target: &RolloutTarget,
  managed_path: &str,
) -> anyhow::Result<BaseConfigLayout> {
  let container_index = target_container_index(workload, &target.container_name)?;
  let container = workload
    .pointer(&format!("/spec/template/spec/containers/{container_index}"))
    .context("target container disappeared while validating base configuration")?;
  let empty_args = Vec::new();
  let args = container
    .get("args")
    .and_then(Value::as_array)
    .unwrap_or(&empty_args);
  let config_path =
    config_argument(args).context("target container must pass an absolute --config path")?;
  let config_file = Path::new(config_path)
    .file_name()
    .and_then(|value| value.to_str())
    .context("target --config path must name a UTF-8 file")?;
  let config_root = Path::new(config_path)
    .parent()
    .and_then(Path::to_str)
    .filter(|path| path.starts_with('/'))
    .context("target --config path must have an absolute parent directory")?;
  let mounts = container
    .get("volumeMounts")
    .and_then(Value::as_array)
    .context("target --config root must be mounted from a read-only ConfigMap volume")?;
  let root_mounts = mounts
    .iter()
    .enumerate()
    .filter(|(_, mount)| mount.get("mountPath").and_then(Value::as_str) == Some(config_root))
    .collect::<Vec<_>>();
  if root_mounts.len() != 1 {
    bail!("target --config root must have exactly one volume mount");
  }
  let (mount_index, mount) = root_mounts[0];
  let mount = mount
    .as_object()
    .context("target --config root must be mounted from a read-only ConfigMap volume")?;
  if mount.get("readOnly").and_then(Value::as_bool) != Some(true) {
    bail!("target base configuration mount must be read-only");
  }
  if mount.contains_key("subPath") || mount.contains_key("subPathExpr") {
    bail!("target base configuration root mount must not use subPath or subPathExpr");
  }
  let volume_name = mount
    .get("name")
    .and_then(Value::as_str)
    .context("target base configuration mount has no volume name")?;
  let volumes = workload
    .pointer("/spec/template/spec/volumes")
    .and_then(Value::as_array)
    .context("target workload spec.template.spec.volumes is required")?;
  let matching_volumes = volumes
    .iter()
    .enumerate()
    .filter(|(_, volume)| volume.get("name").and_then(Value::as_str) == Some(volume_name))
    .collect::<Vec<_>>();
  if matching_volumes.len() != 1 {
    bail!("target base configuration mount must reference exactly one volume");
  }
  let (volume_index, volume) = matching_volumes[0];
  if let Some(config_map) = volume.get("configMap") {
    if volume_name == target.volume_name {
      bail!(
        "target workload volume `{}` collides with the reserved immutable rollout volume",
        target.volume_name
      );
    }
    validate_volume_shape(volume, &["name", "configMap"], "base ConfigMap volume")?;
    let (reference, projected_source, default_mode) =
      parse_base_config_map(config_map, config_file, managed_path, true, true)?;
    return Ok(BaseConfigLayout {
      reference,
      kind: BaseConfigLayoutKind::Bootstrap,
      container_index,
      mount_index,
      config_root: config_root.to_string(),
      projected_source,
      default_mode,
    });
  }

  if volume_name != target.volume_name {
    bail!("target base configuration volume must be a ConfigMap or controller-owned projection");
  }
  validate_volume_shape(
    volume,
    &["name", "projected"],
    "immutable rollout projected volume",
  )?;
  let projected = volume
    .get("projected")
    .and_then(Value::as_object)
    .context("immutable rollout projected volume definition must be an object")?;
  validate_object_keys(
    projected,
    &["sources", "defaultMode"],
    "immutable rollout projected volume",
  )?;
  let default_mode = projected
    .get("defaultMode")
    .map(|mode| validate_mode(mode, "immutable rollout projected defaultMode"))
    .transpose()?
    .cloned();
  let sources = projected
    .get("sources")
    .and_then(Value::as_array)
    .context("immutable rollout projected volume sources must be an array")?;
  if sources.len() != 2 {
    bail!("immutable rollout projected volume must contain exactly two ConfigMap sources");
  }
  let base_source = exact_config_map_source(&sources[0], "base")?;
  let (reference, projected_source, source_default_mode) =
    parse_base_config_map(base_source, config_file, managed_path, false, false)?;
  if source_default_mode.is_some() {
    bail!("projected base ConfigMap source must not define defaultMode");
  }
  validate_generated_source(
    &sources[1],
    managed_path,
    RolloutState::from_workload(workload)
      .desired_revision
      .as_deref()
      .context("projected immutable rollout volume has no recorded desired revision")?,
  )?;
  Ok(BaseConfigLayout {
    reference,
    kind: BaseConfigLayoutKind::Projected { volume_index },
    container_index,
    mount_index,
    config_root: config_root.to_string(),
    projected_source,
    default_mode,
  })
}

fn validate_volume_shape(
  volume: &Value,
  allowed: &[&str],
  description: &str,
) -> anyhow::Result<()> {
  let object = volume
    .as_object()
    .with_context(|| format!("{description} must be an object"))?;
  validate_object_keys(object, allowed, description)
}

fn validate_object_keys(
  object: &Map<String, Value>,
  allowed: &[&str],
  description: &str,
) -> anyhow::Result<()> {
  if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
    bail!("{description} contains unsupported field `{key}`");
  }
  Ok(())
}

fn validate_mode<'a>(mode: &'a Value, description: &str) -> anyhow::Result<&'a Value> {
  if mode.as_u64().is_none_or(|mode| mode > 0o777) {
    bail!("{description} must be an integer between 0 and 0777");
  }
  Ok(mode)
}

fn exact_config_map_source<'a>(source: &'a Value, description: &str) -> anyhow::Result<&'a Value> {
  let source = source
    .as_object()
    .with_context(|| format!("immutable rollout {description} source must be an object"))?;
  validate_object_keys(
    source,
    &["configMap"],
    &format!("immutable rollout {description} source"),
  )?;
  source
    .get("configMap")
    .with_context(|| format!("immutable rollout {description} source must be a ConfigMap"))
}

fn parse_base_config_map(
  config_map: &Value,
  config_file: &str,
  managed_path: &str,
  require_placeholder: bool,
  allow_default_mode: bool,
) -> anyhow::Result<(BaseConfigReference, Value, Option<Value>)> {
  let config_map = config_map
    .as_object()
    .context("target base configuration ConfigMap reference must be an object")?;
  let allowed = if allow_default_mode {
    &["name", "items", "defaultMode", "optional"][..]
  } else {
    &["name", "items", "optional"][..]
  };
  validate_object_keys(
    config_map,
    allowed,
    "target base configuration ConfigMap reference",
  )?;
  let config_map_name = config_map
    .get("name")
    .and_then(Value::as_str)
    .filter(|name| !name.is_empty())
    .context("target base configuration ConfigMap name is required")?;
  if config_map
    .get("optional")
    .is_some_and(|optional| !optional.is_boolean())
  {
    bail!("target base configuration ConfigMap optional field must be a boolean");
  }
  let default_mode = config_map
    .get("defaultMode")
    .map(|mode| validate_mode(mode, "target base configuration defaultMode"))
    .transpose()?
    .cloned();
  let items = config_map
    .get("items")
    .and_then(Value::as_array)
    .context("target base configuration ConfigMap must use explicit item mappings")?;
  let managed_directory = Path::new(managed_path)
    .parent()
    .and_then(Path::to_str)
    .filter(|directory| !directory.is_empty() && *directory != ".")
    .context("managed configuration must be below an existing configuration directory")?;
  let directory_placeholder = format!("{managed_directory}/.keep");
  let mut paths = HashSet::new();
  let mut data_key = None;
  let mut directory_key = None;
  let mut placeholder_key = None;
  let mut projected_items = Vec::with_capacity(items.len());

  for item in items {
    let object = item
      .as_object()
      .context("target base configuration ConfigMap item must be an object")?;
    validate_object_keys(
      object,
      &["key", "path", "mode"],
      "target base configuration ConfigMap item",
    )?;
    let key = object
      .get("key")
      .and_then(Value::as_str)
      .filter(|key| !key.is_empty())
      .context("target base configuration ConfigMap item key is required")?;
    let path = object
      .get("path")
      .and_then(Value::as_str)
      .filter(|path| !path.is_empty())
      .context("target base configuration ConfigMap item path is required")?;
    if !paths.insert(path.to_string()) {
      bail!("target base configuration ConfigMap contains duplicate item path `{path}`");
    }
    if let Some(mode) = object.get("mode") {
      validate_mode(mode, "target base configuration ConfigMap item mode")?;
    }
    if path == config_file {
      data_key = Some(key.to_string());
    }
    if path == directory_placeholder {
      directory_key = Some(key.to_string());
    }
    if path == managed_path {
      placeholder_key = Some(key.to_string());
      if require_placeholder {
        continue;
      }
      bail!(
        "projected base ConfigMap source must not override the controller-managed configuration path"
      );
    }
    projected_items.push(item.clone());
  }

  let data_key = data_key.context(
    "target base configuration ConfigMap must explicitly project the configured entry file",
  )?;
  let directory_key = directory_key.context(
    "target base ConfigMap must project a .keep entry for the managed configuration directory",
  )?;
  let placeholder_key = if require_placeholder {
    let placeholder_key = placeholder_key.context(
      "target base ConfigMap must project an empty placeholder at the managed configuration path",
    )?;
    if placeholder_key != directory_key {
      bail!(
        "target base ConfigMap managed path and directory placeholders must use the same sentinel key"
      );
    }
    placeholder_key
  } else {
    directory_key
  };

  let mut projected_source = config_map.clone();
  projected_source.remove("defaultMode");
  projected_source.insert("items".to_string(), Value::Array(projected_items));
  Ok((
    BaseConfigReference {
      config_map_name: config_map_name.to_string(),
      data_key,
      placeholder_key,
    },
    Value::Object(projected_source),
    default_mode,
  ))
}

fn validate_generated_source(
  source: &Value,
  managed_path: &str,
  expected_revision: &str,
) -> anyhow::Result<()> {
  let config_map = exact_config_map_source(source, "generated")?
    .as_object()
    .context("immutable rollout generated ConfigMap source must be an object")?;
  validate_object_keys(
    config_map,
    &["name", "items"],
    "immutable rollout generated ConfigMap source",
  )?;
  if config_map.get("name").and_then(Value::as_str) != Some(expected_revision) {
    bail!(
      "immutable rollout generated ConfigMap source is not owned by the recorded desired revision"
    );
  }
  let data_key = Path::new(managed_path)
    .file_name()
    .and_then(|value| value.to_str())
    .context("managed configuration path must name a UTF-8 file")?;
  let items = config_map
    .get("items")
    .and_then(Value::as_array)
    .context("immutable rollout generated ConfigMap source items must be an array")?;
  if items.len() != 1 {
    bail!("immutable rollout generated ConfigMap source must contain exactly one item");
  }
  let item = items[0]
    .as_object()
    .context("immutable rollout generated ConfigMap source item must be an object")?;
  validate_object_keys(
    item,
    &["key", "path"],
    "immutable rollout generated ConfigMap source item",
  )?;
  if item.get("key").and_then(Value::as_str) != Some(data_key)
    || item.get("path").and_then(Value::as_str) != Some(managed_path)
  {
    bail!("immutable rollout generated ConfigMap source item does not match the managed path");
  }
  Ok(())
}

pub fn validate_immutable_base_config(
  config_map: &Value,
  base: &BaseConfigReference,
  managed_path: &str,
) -> anyhow::Result<()> {
  if config_map.get("immutable").and_then(Value::as_bool) != Some(true) {
    bail!("target base configuration ConfigMap must set immutable: true");
  }
  let config = config_map
    .pointer(&format!("/data/{}", json_pointer_escape(&base.data_key)))
    .and_then(Value::as_str)
    .context("target base configuration ConfigMap does not contain the configured entry file")?;
  let placeholder = config_map
    .pointer(&format!(
      "/data/{}",
      json_pointer_escape(&base.placeholder_key)
    ))
    .and_then(Value::as_str)
    .context(
      "target base configuration ConfigMap does not contain the managed configuration placeholder",
    )?;
  if !placeholder.is_empty() {
    bail!("target base configuration ConfigMap managed configuration placeholder must be empty");
  }
  let parsed: toml::Value =
    toml::from_str(config).context("target base configuration entry file is not valid TOML")?;
  let includes = parsed
    .get("include")
    .and_then(toml::Value::as_array)
    .context("target base configuration must include the controller-managed configuration path")?;
  let includes_managed_path = includes
    .iter()
    .filter_map(toml::Value::as_str)
    .any(|pattern| {
      glob::Pattern::new(pattern).is_ok_and(|pattern| pattern.matches_path(Path::new(managed_path)))
    });
  if !includes_managed_path {
    bail!("target base configuration does not include `{managed_path}`");
  }
  Ok(())
}

impl WorkloadPatch {
  pub fn json(&self) -> Value {
    Value::Array(self.operations.clone())
  }
}

pub fn build_workload_patch(
  workload: &Value,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  state: &RolloutState,
) -> anyhow::Result<WorkloadPatch> {
  validate_rollout_opt_in(workload)?;
  let resource_version = workload
    .pointer("/metadata/resourceVersion")
    .and_then(Value::as_str)
    .context("target workload metadata.resourceVersion is required")?;
  let layout = base_config_layout(workload, target, &artifact.managed_path)?;
  let prior_state = RolloutState::from_workload(workload);
  let mut operations = vec![json!({
    "op": "test",
    "path": "/metadata/resourceVersion",
    "value": resource_version,
  })];
  patch_annotations(&mut operations, workload, "/metadata", state.annotations())?;
  let mut pod_annotations = Map::new();
  pod_annotations.insert(
    CONFIG_REVISION_ANNOTATION.to_string(),
    Value::String(artifact.name.clone()),
  );
  pod_annotations.insert(
    CONFIG_DIGEST_ANNOTATION.to_string(),
    Value::String(artifact.content_digest.clone()),
  );
  pod_annotations.insert(
    ARTIFACT_DIGEST_ANNOTATION.to_string(),
    Value::String(artifact.artifact_digest.clone()),
  );
  pod_annotations.insert(
    MANAGED_PATH_ANNOTATION.to_string(),
    Value::String(artifact.managed_path.clone()),
  );
  patch_annotations(
    &mut operations,
    workload,
    "/spec/template/metadata",
    pod_annotations,
  )?;
  patch_projected_volume(
    &mut operations,
    workload,
    target,
    artifact,
    &prior_state,
    &layout,
  )?;
  Ok(WorkloadPatch { operations })
}

pub fn validate_rollout_opt_in(workload: &Value) -> anyhow::Result<()> {
  if annotation(workload, IMMUTABLE_ROLLOUT_ANNOTATION) != Some("true") {
    bail!(
      "target workload must opt in with metadata.annotations.{IMMUTABLE_ROLLOUT_ANNOTATION}=true"
    );
  }
  Ok(())
}

fn target_container_index(workload: &Value, name: &str) -> anyhow::Result<usize> {
  workload
    .pointer("/spec/template/spec/containers")
    .and_then(Value::as_array)
    .context("target workload spec.template.spec.containers is required")?
    .iter()
    .position(|container| container.get("name").and_then(Value::as_str) == Some(name))
    .with_context(|| format!("target container `{name}` was not found"))
}

fn config_argument(args: &[Value]) -> Option<&str> {
  for (index, argument) in args.iter().enumerate() {
    let Some(argument) = argument.as_str() else {
      continue;
    };
    if argument == "--config" {
      return args.get(index + 1).and_then(Value::as_str);
    }
    if let Some(path) = argument.strip_prefix("--config=") {
      return Some(path);
    }
  }
  None
}

fn patch_annotations(
  operations: &mut Vec<Value>,
  workload: &Value,
  object_path: &str,
  annotations: Map<String, Value>,
) -> anyhow::Result<()> {
  let pointer = format!("{object_path}/annotations");
  match workload.pointer(&pointer) {
    Some(Value::Object(_)) => {
      for (key, value) in annotations {
        operations.push(json!({
          "op": "add",
          "path": format!("{pointer}/{}", json_pointer_escape(&key)),
          "value": value,
        }));
      }
    }
    Some(_) => bail!("target workload {pointer} must be an object when present"),
    None => operations.push(json!({
      "op": "add",
      "path": pointer,
      "value": Value::Object(annotations),
    })),
  }
  Ok(())
}

pub fn json_pointer_escape(value: &str) -> String {
  value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use serde_json::json;

  use super::*;
  use crate::rollout::WorkloadKind;

  const MANAGED_PATH: &str = "conf.d/gateway-api.generated.toml";

  fn target() -> RolloutTarget {
    RolloutTarget {
      namespace: "default".to_string(),
      kind: WorkloadKind::Deployment,
      name: "edge".to_string(),
      container_name: "oxibelt".to_string(),
      volume_name: "gateway-config".to_string(),
      timeout: Duration::from_secs(300),
      config_map_prefix: "oxibelt-gateway-config".to_string(),
    }
  }

  fn workload(placeholder_path: &str) -> Value {
    json!({
      "spec": {
        "template": {
          "spec": {
            "containers": [{
              "name": "oxibelt",
              "args": ["--config", "/etc/oxibelt/config/oxibelt.toml"],
              "volumeMounts": [{
                "name": "config",
                "mountPath": "/etc/oxibelt/config",
                "readOnly": true,
              }],
            }],
            "volumes": [{
              "name": "config",
              "configMap": {
                "name": "base-config",
                "items": [
                  {"key": "oxibelt.toml", "path": "oxibelt.toml"},
                  {"key": "gateway-config-directory", "path": "conf.d/.keep"},
                  {"key": "gateway-config-directory", "path": placeholder_path},
                ],
              },
            }],
          },
        },
      },
    })
  }

  fn base_config() -> Value {
    json!({
      "immutable": true,
      "data": {
        "oxibelt.toml": "include = [\"conf.d/*.toml\"]\n",
        "gateway-config-directory": "",
      },
    })
  }

  #[test]
  fn immutable_base_config_requires_an_empty_exact_path_placeholder() {
    let target = target();
    let reference = base_config_reference(&workload(MANAGED_PATH), &target, MANAGED_PATH)
      .expect("exact managed placeholder should be discovered");
    assert_eq!(reference.placeholder_key, "gateway-config-directory");
    validate_immutable_base_config(&base_config(), &reference, MANAGED_PATH)
      .expect("empty exact managed placeholder should be accepted");

    let mut nonempty_placeholder = base_config();
    nonempty_placeholder["data"]["gateway-config-directory"] =
      Value::String("[admin]\n".to_string());
    assert!(
      validate_immutable_base_config(&nonempty_placeholder, &reference, MANAGED_PATH).is_err()
    );

    assert!(base_config_reference(&workload("conf.d/.keep"), &target, MANAGED_PATH).is_err());
  }
}
