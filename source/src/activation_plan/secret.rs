use std::collections::BTreeMap;
use std::sync::Arc;

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::config::{NativeConfigSecretClass, native_config_field_metadata};

const SECRET_EQUALITY_DOMAIN: &[u8] = b"oxibelt.activation-plan.secret-equality.v1\0";
const REDACTED_VALUE: &str = "<redacted>";

/// Process-local key used only to compare redacted secret leaves for equality.
///
/// The key deliberately implements neither `Debug` nor `Serialize`.
pub struct ConfigComparisonKey {
  material: Arc<ConfigComparisonKeyMaterial>,
}

struct ConfigComparisonKeyMaterial {
  bytes: Zeroizing<[u8; 32]>,
}

impl ConfigComparisonKey {
  pub fn generate() -> anyhow::Result<Self> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    crate::crypto::random_fill(bytes.as_mut())
      .map_err(|_| anyhow::anyhow!("failed to generate configuration comparison key"))?;
    Ok(Self {
      material: Arc::new(ConfigComparisonKeyMaterial { bytes }),
    })
  }

  #[cfg(test)]
  pub(super) fn for_test(bytes: [u8; 32]) -> Self {
    Self {
      material: Arc::new(ConfigComparisonKeyMaterial {
        bytes: Zeroizing::new(bytes),
      }),
    }
  }
}

impl Clone for ConfigComparisonKey {
  fn clone(&self) -> Self {
    Self {
      material: Arc::clone(&self.material),
    }
  }
}

struct SecretEqualityTag(Zeroizing<[u8; 32]>);

impl SecretEqualityTag {
  fn matches(&self, other: &Self) -> bool {
    bool::from(self.0.as_ref().ct_eq(other.0.as_ref()))
  }
}

impl Clone for SecretEqualityTag {
  fn clone(&self) -> Self {
    Self(Zeroizing::new(*self.0))
  }
}

/// Redacted configuration plus opaque secret-equality tags.
///
/// This projection deliberately implements neither `Debug` nor `Serialize`.
/// It may be retained with runtime state so a later candidate can reveal that
/// a secret changed without retaining or returning the secret itself.
pub struct ConfigComparisonProjection {
  redacted: toml::Value,
  secret_tags: BTreeMap<String, SecretEqualityTag>,
}

impl Clone for ConfigComparisonProjection {
  fn clone(&self) -> Self {
    Self {
      redacted: self.redacted.clone(),
      secret_tags: self.secret_tags.clone(),
    }
  }
}

impl ConfigComparisonProjection {
  pub fn from_value(value: &toml::Value, key: &ConfigComparisonKey) -> Self {
    let mut secret_tags = BTreeMap::new();
    let redacted = project_value("", value, key, &mut secret_tags);
    Self {
      redacted,
      secret_tags,
    }
  }

  pub(crate) fn redacted_value(&self) -> &toml::Value {
    &self.redacted
  }

  pub(crate) fn secret_matches(
    &self,
    path: &str,
    other: &ConfigComparisonProjection,
  ) -> Option<bool> {
    match (self.secret_tags.get(path), other.secret_tags.get(path)) {
      (Some(left), Some(right)) => Some(left.matches(right)),
      (None, None) => None,
      _ => Some(false),
    }
  }
}

fn project_value(
  path: &str,
  value: &toml::Value,
  key: &ConfigComparisonKey,
  secret_tags: &mut BTreeMap<String, SecretEqualityTag>,
) -> toml::Value {
  let metadata = native_config_field_metadata(path);
  if !path.is_empty() && metadata.secret_class != NativeConfigSecretClass::None {
    let tag = secret_equality_tag(path, value, key);
    secret_tags.insert(path.to_string(), SecretEqualityTag(Zeroizing::new(tag)));
    return toml::Value::String(REDACTED_VALUE.to_string());
  }

  match value {
    toml::Value::Table(table) => toml::Value::Table(
      table
        .iter()
        .map(|(name, child)| {
          let child_path = child_field_path(path, name);
          (
            name.clone(),
            project_value(&child_path, child, key, secret_tags),
          )
        })
        .collect(),
    ),
    toml::Value::Array(values) => toml::Value::Array(
      values
        .iter()
        .enumerate()
        .map(|(index, child)| {
          let child_path = format!("{path}[{index}]");
          project_value(&child_path, child, key, secret_tags)
        })
        .collect(),
    ),
    _ => value.clone(),
  }
}

fn secret_equality_tag(path: &str, value: &toml::Value, key: &ConfigComparisonKey) -> [u8; 32] {
  let rendered = Zeroizing::new(value.to_string());
  let mut transcript = Zeroizing::new(Vec::with_capacity(
    SECRET_EQUALITY_DOMAIN.len() + path.len() + rendered.len() + 2,
  ));
  transcript.extend_from_slice(SECRET_EQUALITY_DOMAIN);
  transcript.extend_from_slice(path.as_bytes());
  transcript.push(0);
  transcript.extend_from_slice(rendered.as_bytes());
  crate::crypto::hmac_sha256(key.material.bytes.as_ref(), transcript.as_ref())
}

fn child_field_path(path: &str, name: &str) -> String {
  if path.is_empty() {
    name.to_string()
  } else {
    format!("{path}.{name}")
  }
}
