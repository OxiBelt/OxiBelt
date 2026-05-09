use regex::Regex;

use super::model::CrsTransaction;

#[derive(Clone)]
pub(super) enum CrsAction {
  SetVar {
    name: String,
    operation: SetVarOperation,
  },
}

impl CrsAction {
  pub(super) fn apply(&self, tx: &mut CrsTransaction<'_>) -> anyhow::Result<()> {
    match self {
      Self::SetVar { name, operation } => {
        let current = tx.get_i64(name);
        match operation {
          SetVarOperation::Assign(raw) => {
            let expanded = expand_macros(raw, tx);
            tx.set_value(name, expanded);
          }
          SetVarOperation::Add(raw) => {
            let value = expand_macros(raw, tx).parse::<i64>().unwrap_or(0);
            tx.set_value(name, current.saturating_add(value).to_string());
          }
          SetVarOperation::Subtract(raw) => {
            let value = expand_macros(raw, tx).parse::<i64>().unwrap_or(0);
            tx.set_value(name, current.saturating_sub(value).to_string());
          }
        }
      }
    }
    Ok(())
  }
}

#[derive(Clone)]
pub(super) enum SetVarOperation {
  Assign(String),
  Add(String),
  Subtract(String),
}

pub(super) fn parse_setvar(raw: &str) -> anyhow::Result<Option<CrsAction>> {
  let Some(rest) = raw.strip_prefix("tx.") else {
    return Ok(None);
  };
  let Some((name, value)) = rest.split_once('=') else {
    anyhow::bail!("setvar action must contain '='");
  };
  let operation = if let Some(value) = value.strip_prefix('+') {
    SetVarOperation::Add(value.to_string())
  } else if let Some(value) = value.strip_prefix('-') {
    SetVarOperation::Subtract(value.to_string())
  } else {
    SetVarOperation::Assign(value.to_string())
  };
  Ok(Some(CrsAction::SetVar {
    name: name.to_ascii_lowercase(),
    operation,
  }))
}

pub(super) fn expand_macros(value: &str, tx: &CrsTransaction<'_>) -> String {
  let Ok(regex) = Regex::new(r"%\{tx\.([A-Za-z0-9_.-]+)\}") else {
    return value.to_string();
  };
  regex
    .replace_all(value, |captures: &regex::Captures<'_>| {
      tx.tx
        .get(&captures[1].to_ascii_lowercase())
        .cloned()
        .unwrap_or_default()
    })
    .to_string()
}
