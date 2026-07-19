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
  pub labels: BTreeMap<String, String>,
  #[serde(default)]
  pub generation: Option<i64>,
  #[serde(default, rename = "resourceVersion")]
  pub resource_version: Option<String>,
  #[serde(default, rename = "creationTimestamp")]
  pub creation_timestamp: Option<String>,
  #[serde(default)]
  pub uid: Option<String>,
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
  #[serde(default)]
  pub data: BTreeMap<String, String>,
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
    let list_kind = value
      .get("kind")
      .and_then(Value::as_str)
      .filter(|kind| {
        *kind == "List"
          || (kind.ends_with("List")
            && value
              .pointer("/metadata/name")
              .and_then(Value::as_str)
              .is_none_or(str::is_empty))
      })
      .map(str::to_owned);
    if let Some(list_kind) = list_kind {
      let typed_item = if list_kind == "List" {
        None
      } else {
        let api_version = value
          .get("apiVersion")
          .and_then(Value::as_str)
          .filter(|api_version| !api_version.is_empty())
          .context("Kubernetes typed list object must set a non-empty apiVersion")?;
        let item_kind = list_kind
          .strip_suffix("List")
          .filter(|item_kind| !item_kind.is_empty())
          .context("Kubernetes typed list object must identify an item kind")?;
        Some((api_version.to_owned(), item_kind.to_owned()))
      };
      let items = match value {
        Value::Object(mut object) => match object.remove("items") {
          Some(Value::Array(items)) => items,
          _ => bail!("Kubernetes list object must contain an items array"),
        },
        _ => bail!("Kubernetes list object must contain an items array"),
      };
      let mut objects = Vec::with_capacity(items.len());
      for mut item in items {
        if let Some((api_version, item_kind)) = &typed_item {
          let Value::Object(item) = &mut item else {
            bail!("Kubernetes typed list items must be objects");
          };
          inherit_typed_list_field(item, "apiVersion", api_version)?;
          inherit_typed_list_field(item, "kind", item_kind)?;
        }
        objects.extend(Self::from_value(item)?);
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

fn inherit_typed_list_field(
  item: &mut serde_json::Map<String, Value>,
  field: &str,
  expected: &str,
) -> anyhow::Result<()> {
  match item.get(field) {
    None => {
      item.insert(field.to_owned(), Value::String(expected.to_owned()));
    }
    Some(Value::String(value)) if value == expected => {}
    Some(_) => bail!("Kubernetes typed list item {field} must match its list envelope"),
  }
  Ok(())
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
