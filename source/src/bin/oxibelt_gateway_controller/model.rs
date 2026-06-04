use std::collections::BTreeMap;

use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize, Eq, PartialEq)]
pub struct ObjectMeta {
  pub name: String,
  #[serde(default)]
  pub namespace: Option<String>,
  #[serde(default)]
  pub annotations: BTreeMap<String, String>,
  #[serde(default)]
  pub generation: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KubernetesObject {
  #[serde(rename = "apiVersion")]
  pub api_version: String,
  pub kind: String,
  pub metadata: ObjectMeta,
  #[serde(default)]
  pub spec: Value,
  #[serde(default)]
  pub status: Value,
}

impl KubernetesObject {
  pub fn namespace(&self) -> &str {
    self.metadata.namespace.as_deref().unwrap_or("default")
  }

  pub fn name(&self) -> &str {
    &self.metadata.name
  }

  pub fn key(&self) -> ObjectKey {
    ObjectKey {
      namespace: self.namespace().to_string(),
      name: self.name().to_string(),
    }
  }

  pub fn from_value(value: Value) -> anyhow::Result<Vec<Self>> {
    if value.is_null() {
      return Ok(Vec::new());
    }
    if value.get("kind").and_then(Value::as_str) == Some("List") {
      let mut objects = Vec::new();
      for item in value
        .get("items")
        .and_then(Value::as_array)
        .context("List object must contain items array")?
      {
        objects.extend(Self::from_value(item.clone())?);
      }
      return Ok(objects);
    }
    let object: Self =
      serde_json::from_value(value).context("failed to parse Kubernetes object")?;
    if object.api_version.is_empty() || object.kind.is_empty() || object.metadata.name.is_empty() {
      bail!("Kubernetes object must set apiVersion, kind, and metadata.name");
    }
    Ok(vec![object])
  }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectKey {
  pub namespace: String,
  pub name: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DiagnosticSeverity {
  Warning,
  Error,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Diagnostic {
  pub severity: DiagnosticSeverity,
  pub object: String,
  pub message: String,
}

impl Diagnostic {
  pub fn warning(object: impl Into<String>, message: impl Into<String>) -> Self {
    Self {
      severity: DiagnosticSeverity::Warning,
      object: object.into(),
      message: message.into(),
    }
  }

  pub fn error(object: impl Into<String>, message: impl Into<String>) -> Self {
    Self {
      severity: DiagnosticSeverity::Error,
      object: object.into(),
      message: message.into(),
    }
  }
}

pub fn object_ref(object: &KubernetesObject) -> String {
  format!("{}/{}/{}", object.kind, object.namespace(), object.name())
}
