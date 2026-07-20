//! Redacted effective-configuration projection.

use super::*;

const REDACTED_TOML_VALUE: &str = "<redacted>";
pub(super) fn redact_effective_toml(value: &mut toml::Value) {
  redact_toml_path(value, &["database", "access_log", "connection_url"]);
  redact_toml_path(value, &["database", "mitigation", "connection_url"]);
  redact_toml_path(
    value,
    &["logging", "access_log", "database", "connection_url"],
  );
  if let Some(backends) = value
    .get_mut("shared_state")
    .and_then(|shared_state| shared_state.get_mut("backends"))
    .and_then(toml::Value::as_array_mut)
  {
    for backend in backends {
      redact_toml_path(backend, &["connection_url"]);
    }
  }
  if let Some(credentials) = value
    .get_mut("ipm")
    .and_then(|ipm| ipm.get_mut("credentials"))
    .and_then(toml::Value::as_array_mut)
  {
    for credential in credentials {
      redact_toml_path(credential, &["break_glass_access_token_hash"]);
    }
  }
  if let Some(listeners) = value
    .get_mut("webrtc_turn_listeners")
    .and_then(toml::Value::as_array_mut)
  {
    for listener in listeners {
      redact_toml_path(listener, &["auth", "rest_shared_secret"]);
      if let Some(static_credentials) = listener
        .get_mut("auth")
        .and_then(|auth| auth.get_mut("static_credentials"))
        .and_then(toml::Value::as_array_mut)
      {
        for credential in static_credentials {
          redact_toml_path(credential, &["password"]);
        }
      }
    }
  }
  redact_toml_url_sensitive_parts(value, &["tls", "ocsp", "responder_url"]);
  if let Some(upstreams) = value
    .get_mut("upstreams")
    .and_then(toml::Value::as_array_mut)
  {
    for upstream in upstreams {
      redact_toml_url_sensitive_parts(upstream, &["origin"]);
    }
  }
  if let Some(pools) = value
    .get_mut("upstream_pools")
    .and_then(toml::Value::as_array_mut)
  {
    for pool in pools {
      if let Some(servers) = pool.get_mut("servers").and_then(toml::Value::as_array_mut) {
        for server in servers {
          redact_toml_url_sensitive_parts(server, &["origin"]);
        }
      }
    }
  }
  if let Some(pools) = value
    .get_mut("stream_upstream_pools")
    .and_then(toml::Value::as_array_mut)
  {
    for pool in pools {
      if let Some(servers) = pool.get_mut("servers").and_then(toml::Value::as_array_mut) {
        for server in servers {
          redact_toml_url_sensitive_parts(server, &["origin"]);
        }
      }
    }
  }
}

pub(super) fn redact_toml_path(value: &mut toml::Value, path: &[&str]) {
  let Some((last, parents)) = path.split_last() else {
    return;
  };
  let mut current = value;
  for key in parents {
    let Some(next) = current.get_mut(*key) else {
      return;
    };
    current = next;
  }
  if let Some(secret) = current.get_mut(*last) {
    *secret = toml::Value::String(REDACTED_TOML_VALUE.to_string());
  }
}

pub(super) fn redact_toml_url_sensitive_parts(value: &mut toml::Value, path: &[&str]) {
  let Some((last, parents)) = path.split_last() else {
    return;
  };
  let mut current = value;
  for key in parents {
    let Some(next) = current.get_mut(*key) else {
      return;
    };
    current = next;
  }
  let Some(origin) = current.get_mut(*last) else {
    return;
  };
  let Some(redacted) = origin.as_str().and_then(redact_url_sensitive_parts) else {
    return;
  };
  *origin = toml::Value::String(redacted);
}

pub(super) fn redact_url_sensitive_parts(raw: &str) -> Option<String> {
  let Ok(mut url) = Url::parse(raw) else {
    return None;
  };
  if url.username().is_empty()
    && url.password().is_none()
    && url.query().is_none()
    && url.fragment().is_none()
  {
    return None;
  }
  let _ = url.set_username("");
  let _ = url.set_password(None);
  url.set_query(None);
  url.set_fragment(None);
  Some(url.to_string())
}

pub(super) fn set_toml_integer_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: usize,
) -> anyhow::Result<()> {
  let resolved = i64::try_from(resolved).context("resolved worker count is too large")?;
  set_toml_value_path(value, path, toml::Value::Integer(resolved))
}

pub(super) fn set_toml_float_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: f64,
) -> anyhow::Result<()> {
  set_toml_value_path(value, path, toml::Value::Float(resolved))
}

pub(super) fn set_toml_value_path(
  value: &mut toml::Value,
  path: &[&str],
  resolved: toml::Value,
) -> anyhow::Result<()> {
  let Some((leaf, parents)) = path.split_last() else {
    return Ok(());
  };
  let mut current = value
    .as_table_mut()
    .ok_or_else(|| anyhow!("effective TOML root must be a table"))?;
  for key in parents {
    let entry = current
      .entry((*key).to_string())
      .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    current = entry
      .as_table_mut()
      .ok_or_else(|| anyhow!("effective TOML path {} must be a table", parents.join(".")))?;
  }
  current.insert((*leaf).to_string(), resolved);
  Ok(())
}
