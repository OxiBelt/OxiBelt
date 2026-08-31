use anyhow::{Context, bail};
use serde_json::{Value, json};

use super::{ConfigArtifact, RolloutTarget};
use crate::upstream_client_tls::{
  CERTIFICATE_DATA_KEY, CLIENT_IDENTITY_MOUNT_DIRECTORY, DERIVED_SECRET_PREFIX,
  PRIVATE_KEY_DATA_KEY,
};

const VOLUME_PREFIX: &str = "gateway-mtls-";
const CERT_ROOT: &str = "/etc/oxibelt/cert";
const FILE_MODE: u64 = 0o440;

pub(super) fn patch_client_identity_secrets(
  operations: &mut Vec<Value>,
  workload: &Value,
  _target: &RolloutTarget,
  artifact: &ConfigArtifact,
  target_container_index: usize,
) -> anyhow::Result<()> {
  let desired = artifact
    .client_identity_secret_names
    .iter()
    .map(|secret| (volume_name(secret), secret))
    .collect::<Vec<_>>();
  patch_volumes(operations, workload, &desired)?;
  patch_mounts(operations, workload, target_container_index, &desired)
}

fn patch_volumes(
  operations: &mut Vec<Value>,
  workload: &Value,
  desired: &[(String, &String)],
) -> anyhow::Result<()> {
  let path = "/spec/template/spec/volumes";
  let volumes = workload
    .pointer(path)
    .and_then(Value::as_array)
    .context("target workload spec.template.spec.volumes is required")?;
  let mut next = Vec::with_capacity(volumes.len() + desired.len());
  for volume in volumes {
    let name = volume.get("name").and_then(Value::as_str).unwrap_or("");
    if name.starts_with(VOLUME_PREFIX) {
      validate_managed_volume(volume)?;
    } else {
      next.push(volume.clone());
    }
  }
  next.extend(
    desired
      .iter()
      .map(|(volume, secret)| desired_volume(volume, secret)),
  );
  if next != *volumes {
    operations.push(json!({ "op": "replace", "path": path, "value": next }));
  }
  Ok(())
}

fn patch_mounts(
  operations: &mut Vec<Value>,
  workload: &Value,
  target_container_index: usize,
  desired: &[(String, &String)],
) -> anyhow::Result<()> {
  let containers = workload
    .pointer("/spec/template/spec/containers")
    .and_then(Value::as_array)
    .context("target workload spec.template.spec.containers is required")?;
  for (index, container) in containers.iter().enumerate() {
    let mounts = container
      .get("volumeMounts")
      .and_then(Value::as_array)
      .context("workload containers must use an explicit volumeMounts array")?;
    if index != target_container_index
      && mounts.iter().any(|mount| {
        mount
          .get("name")
          .and_then(Value::as_str)
          .is_some_and(|name| name.starts_with(VOLUME_PREFIX))
      })
    {
      bail!("derived upstream client Secret volume must not be mounted by another container");
    }
  }
  let path = format!("/spec/template/spec/containers/{target_container_index}/volumeMounts");
  let mounts = workload
    .pointer(&path)
    .and_then(Value::as_array)
    .context("target container volumeMounts must be an array")?;
  let desired_paths = desired
    .iter()
    .map(|(_, secret)| mount_path(secret))
    .collect::<std::collections::HashSet<_>>();
  let mut next = Vec::with_capacity(mounts.len() + desired.len());
  for mount in mounts {
    let name = mount.get("name").and_then(Value::as_str).unwrap_or("");
    if name.starts_with(VOLUME_PREFIX) {
      validate_managed_mount(mount)?;
    } else {
      if mount
        .get("mountPath")
        .and_then(Value::as_str)
        .is_some_and(|path| desired_paths.contains(path))
      {
        bail!("target workload already mounts a volume at a derived client identity path");
      }
      next.push(mount.clone());
    }
  }
  next.extend(
    desired
      .iter()
      .map(|(volume, secret)| desired_mount(volume, secret)),
  );
  if next != *mounts {
    operations.push(json!({ "op": "replace", "path": path, "value": next }));
  }
  Ok(())
}

fn desired_volume(volume_name: &str, secret_name: &str) -> Value {
  json!({
    "name": volume_name,
    "secret": {
      "secretName": secret_name,
      "defaultMode": FILE_MODE,
      "items": [
        { "key": CERTIFICATE_DATA_KEY, "path": CERTIFICATE_DATA_KEY, "mode": FILE_MODE },
        { "key": PRIVATE_KEY_DATA_KEY, "path": PRIVATE_KEY_DATA_KEY, "mode": FILE_MODE },
      ],
    },
  })
}

fn desired_mount(volume_name: &str, secret_name: &str) -> Value {
  json!({
    "name": volume_name,
    "mountPath": mount_path(secret_name),
    "readOnly": true,
  })
}

fn validate_managed_volume(volume: &Value) -> anyhow::Result<()> {
  let name = volume
    .get("name")
    .and_then(Value::as_str)
    .context("managed upstream client volume name is required")?;
  let secret = volume
    .get("secret")
    .context("managed upstream client volume must be a Secret volume")?;
  let secret_name = secret
    .get("secretName")
    .and_then(Value::as_str)
    .filter(|name| name.starts_with(DERIVED_SECRET_PREFIX))
    .context("managed upstream client volume must reference a controller-derived Secret")?;
  if name != volume_name(secret_name) || *volume != desired_volume(name, secret_name) {
    bail!("managed upstream client Secret volume has been modified outside the controller");
  }
  Ok(())
}

fn validate_managed_mount(mount: &Value) -> anyhow::Result<()> {
  let name = mount
    .get("name")
    .and_then(Value::as_str)
    .context("managed upstream client volume mount name is required")?;
  let path = mount
    .get("mountPath")
    .and_then(Value::as_str)
    .context("managed upstream client volume mount path is required")?;
  let secret_name = path
    .strip_prefix(&format!("{CERT_ROOT}/{CLIENT_IDENTITY_MOUNT_DIRECTORY}/"))
    .filter(|name| name.starts_with(DERIVED_SECRET_PREFIX))
    .context("managed upstream client volume mount path is invalid")?;
  if name != volume_name(secret_name) || *mount != desired_mount(name, secret_name) {
    bail!("managed upstream client Secret mount has been modified outside the controller");
  }
  Ok(())
}

fn volume_name(secret_name: &str) -> String {
  let suffix = secret_name
    .strip_prefix(DERIVED_SECRET_PREFIX)
    .unwrap_or(secret_name);
  format!("{VOLUME_PREFIX}{suffix}")
}

fn mount_path(secret_name: &str) -> String {
  format!("{CERT_ROOT}/{CLIENT_IDENTITY_MOUNT_DIRECTORY}/{secret_name}")
}
