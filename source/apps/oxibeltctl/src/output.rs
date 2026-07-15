use anyhow::Context;
use oxibelt::admin_client::{AdminResponse, BREAK_GLASS_TOKEN_ENV};
use serde_json::Value;

use super::cli::OutputFormat;
use super::plan::{PermissionHint, ResponseFilter};

pub(crate) fn print_response(
  response: &AdminResponse,
  format: OutputFormat,
  filter: &ResponseFilter,
) -> anyhow::Result<()> {
  let body = filtered_body(response, filter)?;
  if body.is_empty() {
    return Ok(());
  }
  match serde_json::from_slice::<Value>(&body) {
    Ok(value) => match format {
      OutputFormat::PrettyJson => println!("{}", serde_json::to_string_pretty(&value)?),
      OutputFormat::Json => println!("{}", serde_json::to_string(&value)?),
    },
    Err(_) => println!("{}", String::from_utf8_lossy(&body)),
  }
  Ok(())
}

pub(crate) fn print_permission_hint(permission: &PermissionHint) {
  for line in permission_hint_lines(permission) {
    eprintln!("{line}");
  }
}

fn permission_hint_lines(permission: &PermissionHint) -> Vec<String> {
  let mut lines = vec![
    "permission denied by Admin IPM".to_string(),
    format!("required action: {}", permission.action),
  ];
  if permission.resources.len() == 1 {
    let resource = &permission.resources[0];
    lines.push(format!("required resource: {resource}"));
    lines.push(format!(
      "check with: oxibeltctl auth check --action {} --resource {resource}",
      permission.action
    ));
  } else {
    lines.push("required resources:".to_string());
    for resource in &permission.resources {
      lines.push(format!("  - {resource}"));
    }
    lines.push("check each resource with:".to_string());
    for resource in &permission.resources {
      lines.push(format!(
        "  oxibeltctl auth check --action {} --resource {resource}",
        permission.action
      ));
    }
  }
  lines.push(format!(
    "break-glass access credential: set {BREAK_GLASS_TOKEN_ENV} and rerun with --break-glass-access"
  ));
  lines
}

fn filtered_body(response: &AdminResponse, filter: &ResponseFilter) -> anyhow::Result<Vec<u8>> {
  match filter {
    ResponseFilter::None => Ok(response.body.to_vec()),
    ResponseFilter::TopRules(top) => {
      let mut value = serde_json::from_slice::<Value>(&response.body)
        .context("WAF telemetry response was not JSON")?;
      if let Some(rules) = value.get_mut("rules").and_then(Value::as_array_mut) {
        rules.truncate(*top);
      }
      serde_json::to_vec(&value).map_err(Into::into)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn permission_hint_includes_auth_check_and_break_glass() {
    let lines = permission_hint_lines(&PermissionHint {
      action: "config:GetStatus".to_string(),
      resources: vec!["*".to_string()],
    });
    assert!(lines.iter().any(|line| line.contains("permission denied")));
    assert!(lines.iter().any(|line| line.contains("auth check")));
    assert!(
      lines
        .iter()
        .any(|line| line.contains(BREAK_GLASS_TOKEN_ENV))
    );
  }

  #[test]
  fn permission_hint_lists_multiple_resources() {
    let lines = permission_hint_lines(&PermissionHint {
      action: "cache:PurgeObject".to_string(),
      resources: vec!["policy/default".to_string(), "host/example.com".to_string()],
    });
    assert!(lines.iter().any(|line| line == "required resources:"));
    assert!(
      lines
        .iter()
        .any(|line| line.contains("--resource policy/default"))
    );
    assert!(
      lines
        .iter()
        .any(|line| line.contains("--resource host/example.com"))
    );
  }
}
