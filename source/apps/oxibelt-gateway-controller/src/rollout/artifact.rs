use super::*;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigArtifact {
  pub name: String,
  pub artifact_digest: String,
  pub content_digest: String,
  pub managed_path: String,
  pub data_key: String,
  pub toml: String,
  pub assets: Vec<ConfigArtifactAsset>,
  pub client_identity_secret_names: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigArtifactAsset {
  pub data_key: String,
  pub managed_path: String,
  pub content: String,
}

impl ConfigArtifact {
  #[cfg_attr(not(test), allow(dead_code))]
  pub fn new(target: &RolloutTarget, managed_path: &str, toml: String) -> anyhow::Result<Self> {
    Self::new_with_assets(target, managed_path, toml, Vec::new())
  }

  pub fn new_with_assets(
    target: &RolloutTarget,
    managed_path: &str,
    toml: String,
    assets: Vec<ConfigArtifactAsset>,
  ) -> anyhow::Result<Self> {
    Self::new_with_assets_and_client_identities(target, managed_path, toml, assets, Vec::new())
  }

  pub fn new_with_assets_and_client_identities(
    target: &RolloutTarget,
    managed_path: &str,
    toml: String,
    mut assets: Vec<ConfigArtifactAsset>,
    mut client_identity_secret_names: Vec<String>,
  ) -> anyhow::Result<Self> {
    validate_artifact_context(target.artifact_context.as_deref())?;
    let data_key = validate_managed_config_path(managed_path)?;
    validate_generated_toml(&toml)?;
    assets.sort_by(|left, right| left.managed_path.cmp(&right.managed_path));
    let mut asset_paths = std::collections::HashSet::new();
    let mut asset_keys = std::collections::HashSet::new();
    for asset in &assets {
      validate_ca_asset(asset)?;
      if !asset_paths.insert(asset.managed_path.clone())
        || !asset_keys.insert(asset.data_key.clone())
      {
        bail!("generated CA artifact paths and data keys must be unique");
      }
    }
    client_identity_secret_names.sort();
    client_identity_secret_names.dedup();
    if client_identity_secret_names.iter().any(|name| {
      !name.starts_with(super::super::upstream_client_tls::DERIVED_SECRET_PREFIX)
        || validate_kubernetes_dns_label("derived upstream client Secret", name).is_err()
    }) {
      bail!("derived upstream client Secret names must be controller-owned Kubernetes DNS labels");
    }
    let aggregate_bytes = toml.len()
      + assets
        .iter()
        .map(|asset| asset.content.len())
        .sum::<usize>();
    if aggregate_bytes > MAX_CONFIG_MAP_DATA_BYTES {
      bail!(
        "generated configuration bundle is {} bytes, exceeding the {} byte immutable ConfigMap safety limit",
        aggregate_bytes,
        MAX_CONFIG_MAP_DATA_BYTES
      );
    }
    let artifact_digest = digest_artifact_bundle_with_client_identities(
      managed_path,
      toml.as_bytes(),
      &assets,
      &client_identity_secret_names,
    );
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
      assets,
      client_identity_secret_names,
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
      CLIENT_IDENTITY_SECRETS_ANNOTATION.to_string(),
      Value::String(self.client_identity_secret_names.join(",")),
    );
    annotations.insert(
      CONFIG_DIGEST_ANNOTATION.to_string(),
      Value::String(self.content_digest.clone()),
    );
    annotations.insert(
      MANAGED_PATH_ANNOTATION.to_string(),
      Value::String(self.managed_path.clone()),
    );
    if let Some(context) = &target.artifact_context {
      annotations.insert(
        TARGET_CONTEXT_ANNOTATION.to_string(),
        Value::String(context.clone()),
      );
    }
    let mut data = Map::new();
    data.insert(self.data_key.clone(), Value::String(self.toml.clone()));
    for asset in &self.assets {
      data.insert(asset.data_key.clone(), Value::String(asset.content.clone()));
    }
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
      && existing
        .get("data")
        .and_then(Value::as_object)
        .is_some_and(|data| {
          data.len() == self.assets.len() + 1
            && self.assets.iter().all(|asset| {
              data.get(&asset.data_key).and_then(Value::as_str) == Some(asset.content.as_str())
            })
        })
      && annotation(existing, ARTIFACT_DIGEST_ANNOTATION) == Some(self.artifact_digest.as_str())
      && annotation(existing, CONFIG_DIGEST_ANNOTATION) == Some(self.content_digest.as_str())
      && annotation(existing, MANAGED_PATH_ANNOTATION) == Some(self.managed_path.as_str())
      && annotation(existing, CLIENT_IDENTITY_SECRETS_ANNOTATION)
        == Some(self.client_identity_secret_names.join(",").as_str())
      && annotation(existing, TARGET_CONTEXT_ANNOTATION) == target.artifact_context.as_deref()
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
    let mut assets = Vec::new();
    for (key, value) in existing
      .get("data")
      .and_then(Value::as_object)
      .context("immutable ConfigMap data is required")?
    {
      if key == &data_key {
        continue;
      }
      let digest = key
        .strip_prefix("gateway-api-ca-")
        .and_then(|value| value.strip_suffix(".pem"))
        .context("immutable ConfigMap contains an unknown generated data key")?;
      assets.push(ConfigArtifactAsset {
        data_key: key.clone(),
        managed_path: format!("gateway-api-ca/{digest}.pem"),
        content: value
          .as_str()
          .context("immutable ConfigMap generated CA value must be text")?
          .to_string(),
      });
    }
    let client_identity_secret_names = annotation(existing, CLIENT_IDENTITY_SECRETS_ANNOTATION)
      .unwrap_or("")
      .split(',')
      .filter(|name| !name.is_empty())
      .map(str::to_string)
      .collect();
    let artifact = Self::new_with_assets_and_client_identities(
      target,
      managed_path,
      toml,
      assets,
      client_identity_secret_names,
    )?;
    if artifact.name != name || !artifact.matches_existing(target, existing) {
      bail!("immutable ConfigMap does not match its deterministic rollout identity");
    }
    Ok(artifact)
  }
}

fn validate_artifact_context(context: Option<&str>) -> anyhow::Result<()> {
  if context.is_some_and(|context| {
    context.len() != 64
      || !context
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  }) {
    bail!("rollout target artifact context must be a lowercase SHA-256 digest");
  }
  Ok(())
}

pub(crate) fn digest_artifact_bundle(
  managed_path: &str,
  content: &[u8],
  assets: &[ConfigArtifactAsset],
) -> String {
  if assets.is_empty() {
    return digest_artifact(managed_path, content);
  }
  let mut digest = Sha256::new();
  digest.update(DIGEST_DOMAIN);
  digest.update(managed_path.as_bytes());
  digest.update(b"\0");
  digest.update(content);
  for asset in assets {
    digest.update(b"\0asset\0");
    digest.update(asset.managed_path.as_bytes());
    digest.update(b"\0");
    digest.update(asset.content.as_bytes());
  }
  hex_digest(&digest.finalize())
}

fn digest_artifact_bundle_with_client_identities(
  managed_path: &str,
  content: &[u8],
  assets: &[ConfigArtifactAsset],
  client_identity_secret_names: &[String],
) -> String {
  let bundle_digest = digest_artifact_bundle(managed_path, content, assets);
  if client_identity_secret_names.is_empty() {
    return bundle_digest;
  }
  let mut digest = Sha256::new();
  digest.update(DIGEST_DOMAIN);
  digest.update(b"client-identities\0");
  digest.update(bundle_digest.as_bytes());
  for name in client_identity_secret_names {
    digest.update(b"\0");
    digest.update(name.as_bytes());
  }
  hex_digest(&digest.finalize())
}

fn validate_ca_asset(asset: &ConfigArtifactAsset) -> anyhow::Result<()> {
  let digest = digest_content(asset.content.as_bytes());
  if asset.data_key != format!("gateway-api-ca-{digest}.pem")
    || asset.managed_path != format!("gateway-api-ca/{digest}.pem")
  {
    bail!("generated CA artifact key/path must be content-addressed by its SHA-256 digest");
  }
  if asset.content.is_empty() || asset.content.len() > 256 * 1024 {
    bail!("generated CA artifact must be between 1 and 262144 bytes");
  }
  Ok(())
}
