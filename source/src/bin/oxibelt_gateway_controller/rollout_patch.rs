use std::path::Path;

use anyhow::{Context, bail};
use serde_json::{Map, Value, json};

use super::rollout::{
  ARTIFACT_DIGEST_ANNOTATION, CONFIG_DIGEST_ANNOTATION, CONFIG_REVISION_ANNOTATION, ConfigArtifact,
  IMMUTABLE_ROLLOUT_ANNOTATION, MANAGED_PATH_ANNOTATION, RolloutState, RolloutTarget, annotation,
};

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

pub fn base_config_reference(
  workload: &Value,
  target: &RolloutTarget,
  managed_path: &str,
) -> anyhow::Result<BaseConfigReference> {
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
  let mount = container
    .get("volumeMounts")
    .and_then(Value::as_array)
    .and_then(|mounts| {
      mounts
        .iter()
        .find(|mount| mount.get("mountPath").and_then(Value::as_str) == Some(config_root))
    })
    .context("target --config root must be mounted from a read-only ConfigMap volume")?;
  if mount.get("readOnly").and_then(Value::as_bool) != Some(true) {
    bail!("target base configuration mount must be read-only");
  }
  let volume_name = mount
    .get("name")
    .and_then(Value::as_str)
    .context("target base configuration mount has no volume name")?;
  let config_map = workload
    .pointer("/spec/template/spec/volumes")
    .and_then(Value::as_array)
    .and_then(|volumes| {
      volumes
        .iter()
        .find(|volume| volume.get("name").and_then(Value::as_str) == Some(volume_name))
    })
    .and_then(|volume| volume.get("configMap"))
    .context("target base configuration volume must be a ConfigMap")?;
  let config_map_name = config_map
    .get("name")
    .and_then(Value::as_str)
    .context("target base configuration ConfigMap name is required")?;
  let data_key = config_map
    .get("items")
    .and_then(Value::as_array)
    .and_then(|items| {
      items.iter().find_map(|item| {
        (item.get("path").and_then(Value::as_str) == Some(config_file))
          .then(|| item.get("key").and_then(Value::as_str))
          .flatten()
      })
    })
    .unwrap_or(config_file);
  let placeholder_key = config_map
    .get("items")
    .and_then(Value::as_array)
    .and_then(|items| {
      items.iter().find_map(|item| {
        (item.get("path").and_then(Value::as_str) == Some(managed_path))
          .then(|| item.get("key").and_then(Value::as_str))
          .flatten()
      })
    })
    .context(
      "target base ConfigMap must project an empty placeholder at the managed configuration path",
    )?;
  Ok(BaseConfigReference {
    config_map_name: config_map_name.to_string(),
    data_key: data_key.to_string(),
    placeholder_key: placeholder_key.to_string(),
  })
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
  let container_index = target_container_index(workload, &target.container_name)?;
  let mount_path = managed_mount_path(workload, container_index, &artifact.managed_path)?;
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
  patch_volume(&mut operations, workload, target, artifact, &prior_state)?;
  patch_volume_mount(
    &mut operations,
    workload,
    container_index,
    target,
    artifact,
    &mount_path,
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

fn managed_mount_path(
  workload: &Value,
  container_index: usize,
  managed_path: &str,
) -> anyhow::Result<String> {
  let container = workload
    .pointer(&format!("/spec/template/spec/containers/{container_index}"))
    .context("target container disappeared while building rollout patch")?;
  let empty_args = Vec::new();
  let args = container
    .get("args")
    .and_then(Value::as_array)
    .unwrap_or(&empty_args);
  let config_path =
    config_argument(args).context("target container must pass an absolute --config path")?;
  let config_root = Path::new(config_path)
    .parent()
    .and_then(Path::to_str)
    .filter(|path| path.starts_with('/'))
    .context("target --config path must have an absolute parent directory")?;
  Ok(format!(
    "{}/{managed_path}",
    config_root.trim_end_matches('/')
  ))
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

fn patch_volume(
  operations: &mut Vec<Value>,
  workload: &Value,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  prior_state: &RolloutState,
) -> anyhow::Result<()> {
  let path = "/spec/template/spec/volumes";
  let desired = json!({
    "name": target.volume_name,
    "configMap": {
      "name": artifact.name,
      "items": [{ "key": artifact.data_key, "path": artifact.data_key }],
    },
  });
  match workload.pointer(path) {
    Some(Value::Array(volumes)) => {
      if let Some(index) = volumes.iter().position(|volume| {
        volume.get("name").and_then(Value::as_str) == Some(target.volume_name.as_str())
      }) {
        if volumes[index].get("configMap").is_none() {
          bail!(
            "target workload volume `{}` is not controller-owned ConfigMap volume",
            target.volume_name
          );
        }
        if volumes[index]
          .pointer("/configMap/name")
          .and_then(Value::as_str)
          != prior_state.desired_revision.as_deref()
        {
          bail!(
            "target workload volume `{}` is not owned by the recorded immutable rollout revision",
            target.volume_name
          );
        }
        operations.push(json!({
          "op": "replace",
          "path": format!("{path}/{index}/configMap"),
          "value": desired["configMap"].clone(),
        }));
      } else {
        operations.push(json!({ "op": "add", "path": format!("{path}/-"), "value": desired }));
      }
    }
    Some(_) => bail!("target workload {path} must be an array when present"),
    None => operations.push(json!({ "op": "add", "path": path, "value": [desired] })),
  }
  Ok(())
}

fn patch_volume_mount(
  operations: &mut Vec<Value>,
  workload: &Value,
  container_index: usize,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  mount_path: &str,
) -> anyhow::Result<()> {
  let path = format!("/spec/template/spec/containers/{container_index}/volumeMounts");
  let desired = json!({
    "name": target.volume_name,
    "mountPath": mount_path,
    "subPath": artifact.data_key,
    "readOnly": true,
  });
  match workload.pointer(&path) {
    Some(Value::Array(mounts)) => {
      if let Some(index) = mounts.iter().position(|mount| {
        mount.get("name").and_then(Value::as_str) == Some(target.volume_name.as_str())
      }) {
        if mounts[index].get("mountPath").and_then(Value::as_str) != Some(mount_path)
          || mounts[index].get("subPath").and_then(Value::as_str)
            != Some(artifact.data_key.as_str())
          || mounts[index].get("readOnly").and_then(Value::as_bool) != Some(true)
        {
          bail!(
            "target workload volume mount `{}` conflicts with immutable rollout mount",
            target.volume_name
          );
        }
      } else {
        operations.push(json!({ "op": "add", "path": format!("{path}/-"), "value": desired }));
      }
    }
    Some(_) => bail!("target workload {path} must be an array when present"),
    None => operations.push(json!({ "op": "add", "path": path, "value": [desired] })),
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
