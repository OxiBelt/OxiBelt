use std::collections::BTreeMap;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Deserialize, PartialEq)]
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
  #[serde(default, rename = "type")]
  pub resource_type: Option<String>,
}

impl std::fmt::Debug for KubernetesObject {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut debug = formatter.debug_struct("KubernetesObject");
    debug
      .field("api_version", &self.api_version)
      .field("kind", &self.kind)
      .field("metadata", &self.metadata)
      .field("spec", &self.spec)
      .field("status", &self.status);
    if self.kind == "Secret" {
      debug.field("data", &"[redacted]");
    } else {
      debug.field("data", &self.data);
    }
    debug.field("resource_type", &self.resource_type).finish()
  }
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
  Warning,
  Error,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
pub enum DiagnosticCode {
  Conflicted,
  ExceedsOperatorLimit,
  IncompatibleFilters,
  InvalidResource,
  InvalidClientCertificateRef,
  NotProgrammed,
  RefNotPermitted,
  RequiresExactDataPlane,
  UnsupportedValue,
}

impl DiagnosticCode {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Conflicted => "Conflicted",
      Self::ExceedsOperatorLimit => "ExceedsOperatorLimit",
      Self::IncompatibleFilters => "IncompatibleFilters",
      Self::InvalidResource => "InvalidResource",
      Self::InvalidClientCertificateRef => "InvalidClientCertificateRef",
      Self::NotProgrammed => "NotProgrammed",
      Self::RefNotPermitted => "RefNotPermitted",
      Self::RequiresExactDataPlane => "RequiresExactDataPlane",
      Self::UnsupportedValue => "UnsupportedValue",
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Diagnostic {
  pub severity: DiagnosticSeverity,
  pub code: DiagnosticCode,
  pub object: String,
  pub message: String,
}

impl Diagnostic {
  pub fn warning(object: impl Into<String>, message: impl Into<String>) -> Self {
    let message = message.into();
    Self {
      severity: DiagnosticSeverity::Warning,
      code: diagnostic_code(&message),
      object: object.into(),
      message,
    }
  }

  pub fn error(object: impl Into<String>, message: impl Into<String>) -> Self {
    let message = message.into();
    Self {
      severity: DiagnosticSeverity::Error,
      code: diagnostic_code(&message),
      object: object.into(),
      message,
    }
  }
}

fn diagnostic_code(message: &str) -> DiagnosticCode {
  if message.contains("operator source Secret allowlist")
    || message.contains("ReferenceGrant")
    || message.contains("was not found")
    || message.contains("does not expose")
  {
    DiagnosticCode::RefNotPermitted
  } else if message.contains("client certificate Secret")
    || message.contains("clientCertificateRef") && message.contains("invalid")
  {
    DiagnosticCode::InvalidClientCertificateRef
  } else if message.contains("operator cap") {
    DiagnosticCode::ExceedsOperatorLimit
  } else if message.contains("filter") || message.contains("cannot be combined") {
    DiagnosticCode::IncompatibleFilters
  } else if message.contains("Conflicted") || message.contains("conflict") {
    DiagnosticCode::Conflicted
  } else if message.contains("requires compatibility mode `exact`") {
    DiagnosticCode::RequiresExactDataPlane
  } else if message.contains("unsupported") || message.contains("outside the supported") {
    DiagnosticCode::UnsupportedValue
  } else if message.contains("not Programmed") {
    DiagnosticCode::NotProgrammed
  } else {
    DiagnosticCode::InvalidResource
  }
}

pub fn object_ref(object: &KubernetesObject) -> String {
  format!("{}/{}/{}", object.kind, object.namespace(), object.name())
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;

  #[test]
  fn secret_debug_output_redacts_data() {
    let secret = KubernetesObject::from_value(json!({
      "apiVersion": "v1",
      "kind": "Secret",
      "metadata": {"name": "client", "namespace": "credentials"},
      "type": "kubernetes.io/tls",
      "data": {"tls.key": "sensitive-private-key"},
    }))
    .unwrap()
    .pop()
    .unwrap();
    let output = format!("{secret:?}");
    assert!(!output.contains("sensitive-private-key"));
    assert!(output.contains("[redacted]"));
    assert!(output.contains("credentials"));
  }
}
