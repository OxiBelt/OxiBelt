use std::path::Path;

use anyhow::{Context, bail};
use serde_json::{Map, Value, json};

use super::{
  BaseConfigLayout, BaseConfigLayoutKind, ConfigArtifact, RolloutState, RolloutTarget,
  validate_object_keys, validate_volume_shape,
};

pub(super) fn patch_projected_volume(
  operations: &mut Vec<Value>,
  workload: &Value,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  prior_state: &RolloutState,
  layout: &BaseConfigLayout,
) -> anyhow::Result<()> {
  let legacy_migration = patch_volume(operations, workload, target, artifact, prior_state, layout)?;
  patch_volume_mount(
    operations,
    workload,
    target,
    artifact,
    layout,
    legacy_migration,
  )
}

fn patch_volume(
  operations: &mut Vec<Value>,
  workload: &Value,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  prior_state: &RolloutState,
  layout: &BaseConfigLayout,
) -> anyhow::Result<bool> {
  let path = "/spec/template/spec/volumes";
  let volumes = workload
    .pointer(path)
    .and_then(Value::as_array)
    .context("target workload spec.template.spec.volumes is required")?;
  let desired = desired_projected_volume(target, artifact, layout);
  if let BaseConfigLayoutKind::Projected { volume_index } = layout.kind {
    operations.push(json!({
      "op": "replace",
      "path": format!("{path}/{volume_index}/projected/sources/1/configMap"),
      "value": desired["projected"]["sources"][1]["configMap"].clone(),
    }));
    return Ok(false);
  }

  let matching = volumes
    .iter()
    .enumerate()
    .filter(|(_, volume)| {
      volume.get("name").and_then(Value::as_str) == Some(target.volume_name.as_str())
    })
    .collect::<Vec<_>>();
  if matching.len() > 1 {
    bail!(
      "target workload contains duplicate immutable rollout volume `{}`",
      target.volume_name
    );
  }
  let Some((index, volume)) = matching.first().copied() else {
    operations.push(json!({ "op": "add", "path": format!("{path}/-"), "value": desired }));
    return Ok(false);
  };
  validate_legacy_volume(volume, target, artifact, prior_state)?;
  operations.push(json!({
    "op": "replace",
    "path": format!("{path}/{index}"),
    "value": desired,
  }));
  Ok(true)
}

fn patch_volume_mount(
  operations: &mut Vec<Value>,
  workload: &Value,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  layout: &BaseConfigLayout,
  legacy_migration: bool,
) -> anyhow::Result<()> {
  validate_reserved_mounts_in_other_containers(workload, target, layout.container_index)?;
  let path = format!(
    "/spec/template/spec/containers/{}/volumeMounts",
    layout.container_index
  );
  let mounts = workload
    .pointer(&path)
    .and_then(Value::as_array)
    .context("target container volumeMounts must be an array")?;
  let managed_mount_path = format!(
    "{}/{}",
    layout.config_root.trim_end_matches('/'),
    artifact.managed_path
  );
  let target_mounts = mounts
    .iter()
    .enumerate()
    .filter(|(_, mount)| {
      mount.get("name").and_then(Value::as_str) == Some(target.volume_name.as_str())
    })
    .collect::<Vec<_>>();
  let overlapping_mounts = mounts
    .iter()
    .enumerate()
    .filter(|(index, mount)| {
      *index != layout.mount_index
        && mount
          .get("mountPath")
          .and_then(Value::as_str)
          .is_some_and(|path| mount_paths_overlap(path, &layout.config_root))
    })
    .collect::<Vec<_>>();

  match layout.kind {
    BaseConfigLayoutKind::Projected { .. } => {
      if !target_mounts
        .iter()
        .any(|(index, _)| *index == layout.mount_index)
      {
        bail!(
          "target workload volume mount `{}` conflicts with immutable rollout root mount",
          target.volume_name
        );
      }
      if !overlapping_mounts.is_empty() {
        bail!("target workload contains a mount overlapping the managed configuration root");
      }
      return patch_ca_asset_mount(operations, mounts, &path, target, artifact, layout);
    }
    BaseConfigLayoutKind::Bootstrap => {}
  }

  let legacy_mount_index = if legacy_migration {
    if target_mounts.len() != 1 {
      bail!("legacy immutable rollout volume must have exactly one controller-owned mount");
    }
    let (index, mount) = target_mounts[0];
    validate_legacy_mount(mount, target, artifact, &managed_mount_path)?;
    if overlapping_mounts.len() != 1 || overlapping_mounts[0].0 != index {
      bail!("legacy immutable rollout mount collides with another configuration-root mount");
    }
    Some(index)
  } else {
    if !target_mounts.is_empty() {
      bail!(
        "target workload volume mount `{}` collides with the reserved immutable rollout mount",
        target.volume_name
      );
    }
    if !overlapping_mounts.is_empty() {
      bail!("target workload contains a mount overlapping the managed configuration root");
    }
    None
  };

  operations.push(json!({
    "op": "replace",
    "path": format!("{path}/{}/name", layout.mount_index),
    "value": target.volume_name,
  }));
  if let Some(index) = legacy_mount_index {
    operations.push(json!({
      "op": "remove",
      "path": format!("{path}/{index}"),
    }));
  }
  if artifact.assets.is_empty() {
    Ok(())
  } else {
    let mount = desired_ca_asset_mount(target, layout)?;
    operations.push(json!({ "op": "add", "path": format!("{path}/-"), "value": mount }));
    Ok(())
  }
}

fn patch_ca_asset_mount(
  operations: &mut Vec<Value>,
  mounts: &[Value],
  mounts_path: &str,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  layout: &BaseConfigLayout,
) -> anyhow::Result<()> {
  let desired = desired_ca_asset_mount(target, layout)?;
  let desired_path = desired
    .get("mountPath")
    .and_then(Value::as_str)
    .context("internal CA asset mount path is missing")?;
  let asset_mounts = mounts
    .iter()
    .enumerate()
    .filter(|(index, mount)| {
      *index != layout.mount_index
        && mount.get("name").and_then(Value::as_str) == Some(target.volume_name.as_str())
    })
    .collect::<Vec<_>>();
  if asset_mounts.len() > 1 {
    bail!("immutable rollout volume has duplicate controller-owned CA mounts");
  }
  for (index, mount) in mounts.iter().enumerate() {
    if index == layout.mount_index || asset_mounts.first().is_some_and(|entry| entry.0 == index) {
      continue;
    }
    if mount
      .get("mountPath")
      .and_then(Value::as_str)
      .is_some_and(|path| Path::new(path).starts_with(desired_path))
    {
      bail!("target workload contains a mount overlapping the generated Gateway API CA directory");
    }
  }
  match (artifact.assets.is_empty(), asset_mounts.first()) {
    (true, Some((index, mount))) => {
      validate_ca_asset_mount(mount, &desired)?;
      operations.push(json!({ "op": "remove", "path": format!("{mounts_path}/{index}") }));
    }
    (true, None) | (false, Some(_)) => {
      if let Some((_, mount)) = asset_mounts.first() {
        validate_ca_asset_mount(mount, &desired)?;
      }
    }
    (false, None) => operations.push(json!({
      "op": "add",
      "path": format!("{mounts_path}/-"),
      "value": desired,
    })),
  }
  Ok(())
}

fn desired_ca_asset_mount(
  target: &RolloutTarget,
  layout: &BaseConfigLayout,
) -> anyhow::Result<Value> {
  let root = Path::new(&layout.config_root)
    .parent()
    .and_then(Path::to_str)
    .context("configuration root must have a UTF-8 parent for generated CA projection")?;
  Ok(json!({
    "name": target.volume_name,
    "mountPath": format!("{root}/cert/gateway-api-ca"),
    "subPath": "gateway-api-ca",
    "readOnly": true,
  }))
}

fn validate_ca_asset_mount(actual: &Value, expected: &Value) -> anyhow::Result<()> {
  let actual = actual
    .as_object()
    .context("generated Gateway API CA mount must be an object")?;
  validate_object_keys(
    actual,
    &["name", "mountPath", "subPath", "readOnly"],
    "generated Gateway API CA mount",
  )?;
  if Value::Object(actual.clone()) != *expected {
    bail!("generated Gateway API CA mount is not controller-owned");
  }
  Ok(())
}

fn validate_reserved_mounts_in_other_containers(
  workload: &Value,
  target: &RolloutTarget,
  target_container_index: usize,
) -> anyhow::Result<()> {
  let pod_spec = workload
    .pointer("/spec/template/spec")
    .and_then(Value::as_object)
    .context("target workload spec.template.spec must be an object")?;
  for field in ["containers", "initContainers", "ephemeralContainers"] {
    let Some(value) = pod_spec.get(field) else {
      continue;
    };
    let containers = value
      .as_array()
      .with_context(|| format!("target workload {field} must be an array"))?;
    for (index, container) in containers.iter().enumerate() {
      if field == "containers" && index == target_container_index {
        continue;
      }
      let Some(mounts) = container.get("volumeMounts") else {
        continue;
      };
      let mounts = mounts.as_array().with_context(|| {
        format!("target workload {field}[{index}].volumeMounts must be an array")
      })?;
      if mounts
        .iter()
        .any(|mount| mount.get("name").and_then(Value::as_str) == Some(target.volume_name.as_str()))
      {
        bail!(
          "immutable rollout volume `{}` must not be mounted by non-target containers",
          target.volume_name
        );
      }
    }
  }
  Ok(())
}

fn mount_paths_overlap(left: &str, right: &str) -> bool {
  let left = Path::new(left);
  let right = Path::new(right);
  left.starts_with(right) || right.starts_with(left)
}

fn desired_projected_volume(
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  layout: &BaseConfigLayout,
) -> Value {
  let mut projected = Map::new();
  if let Some(default_mode) = &layout.default_mode {
    projected.insert("defaultMode".to_string(), default_mode.clone());
  }
  projected.insert(
    "sources".to_string(),
    json!([
      { "configMap": layout.projected_source.clone() },
      { "configMap": desired_generated_config_map(artifact) },
    ]),
  );
  json!({
    "name": target.volume_name,
    "projected": projected,
  })
}

fn desired_generated_config_map(artifact: &ConfigArtifact) -> Value {
  let mut items = vec![json!({ "key": artifact.data_key, "path": artifact.managed_path })];
  items.extend(
    artifact
      .assets
      .iter()
      .map(|asset| json!({ "key": asset.data_key, "path": asset.managed_path })),
  );
  json!({
    "name": artifact.name,
    "items": items,
  })
}

fn validate_legacy_volume(
  volume: &Value,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  prior_state: &RolloutState,
) -> anyhow::Result<()> {
  validate_volume_shape(
    volume,
    &["name", "configMap"],
    "legacy immutable rollout volume",
  )?;
  let config_map = volume
    .get("configMap")
    .and_then(Value::as_object)
    .context("legacy immutable rollout volume must be a ConfigMap")?;
  validate_object_keys(
    config_map,
    &["name", "items", "defaultMode"],
    "legacy immutable rollout ConfigMap reference",
  )?;
  if config_map
    .get("defaultMode")
    .is_some_and(|mode| mode.as_u64() != Some(0o644))
  {
    bail!("legacy immutable rollout ConfigMap defaultMode is not the Kubernetes server default");
  }
  if config_map.get("name").and_then(Value::as_str) != prior_state.desired_revision.as_deref() {
    bail!(
      "target workload volume `{}` is not owned by the recorded immutable rollout revision",
      target.volume_name
    );
  }
  let items = config_map
    .get("items")
    .and_then(Value::as_array)
    .context("legacy immutable rollout ConfigMap items must be an array")?;
  let expected = json!([{
    "key": artifact.data_key,
    "path": artifact.data_key,
  }]);
  if items
    != expected
      .as_array()
      .context("internal legacy item shape is invalid")?
  {
    bail!("legacy immutable rollout ConfigMap item mapping is not controller-owned");
  }
  Ok(())
}

fn validate_legacy_mount(
  mount: &Value,
  target: &RolloutTarget,
  artifact: &ConfigArtifact,
  managed_mount_path: &str,
) -> anyhow::Result<()> {
  let mount = mount
    .as_object()
    .context("legacy immutable rollout volume mount must be an object")?;
  validate_object_keys(
    mount,
    &["name", "mountPath", "subPath", "readOnly"],
    "legacy immutable rollout volume mount",
  )?;
  if mount.get("name").and_then(Value::as_str) != Some(target.volume_name.as_str())
    || mount.get("mountPath").and_then(Value::as_str) != Some(managed_mount_path)
    || mount.get("subPath").and_then(Value::as_str) != Some(artifact.data_key.as_str())
    || mount.get("readOnly").and_then(Value::as_bool) != Some(true)
  {
    bail!("legacy immutable rollout volume mount is not controller-owned");
  }
  Ok(())
}
