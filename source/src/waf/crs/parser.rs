use std::path::Path;

use anyhow::{Context, anyhow, bail};

use super::actions::parse_setvar;
use super::model::{CrsEntry, CrsRule};
use super::operators::CrsOperator;
use super::syntax::{logical_lines, parse_quoted_sections, split_actions, strip_comment, unquote};
use super::transforms::CrsTransform;
use super::variables::CrsVariable;

pub(super) struct CrsParser {
  pub(super) entries: Vec<CrsEntry>,
}

impl CrsParser {
  pub(super) fn new() -> Self {
    Self {
      entries: Vec::new(),
    }
  }

  pub(super) fn load_file(&mut self, path: &Path) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(path)
      .with_context(|| format!("failed to read CRS file {}", path.display()))?;
    for (line_number, directive) in logical_lines(&raw).into_iter().enumerate() {
      let directive = strip_comment(&directive);
      if directive.trim().is_empty() {
        continue;
      }
      self
        .parse_directive(&directive)
        .with_context(|| format!("failed to parse CRS {}:{}", path.display(), line_number + 1))?;
    }
    Ok(())
  }

  fn parse_directive(&mut self, raw: &str) -> anyhow::Result<()> {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix("SecMarker") {
      self
        .entries
        .push(CrsEntry::Marker(unquote(rest.trim()).to_string()));
      return Ok(());
    }
    if let Some(rest) = raw.strip_prefix("SecAction") {
      let actions = parse_quoted_sections(rest);
      let actions = actions
        .first()
        .ok_or_else(|| anyhow!("SecAction requires an action list"))?;
      let mut rule = CrsRule::from_parts(Vec::new(), CrsOperator::UnconditionalMatch, actions)?;
      rule.variables = vec![CrsVariable::RequestUri];
      self.entries.push(CrsEntry::Rule(Box::new(rule)));
      return Ok(());
    }
    if let Some(rest) = raw.strip_prefix("SecRule") {
      let mut sections = parse_quoted_sections(rest);
      if sections.len() < 2 {
        bail!("SecRule requires variables and operator");
      }
      let variables = sections.remove(0);
      let operator = sections.remove(0);
      let actions = sections.first().cloned().unwrap_or_default();
      let rule = CrsRule::from_parts(
        variables
          .split('|')
          .map(CrsVariable::parse)
          .collect::<anyhow::Result<Vec<_>>>()?,
        CrsOperator::parse(&operator)?,
        &actions,
      )?;
      if let Some(CrsEntry::Rule(previous)) = self.entries.last_mut()
        && previous.expects_chain
      {
        previous.chain.push(rule);
        previous.expects_chain = previous
          .chain
          .last()
          .map(|rule| rule.expects_chain)
          .unwrap_or(false);
        return Ok(());
      }
      self.entries.push(CrsEntry::Rule(Box::new(rule)));
      return Ok(());
    }
    if raw.starts_with("SecRuleUpdate")
      || raw.starts_with("SecRuleRemove")
      || raw.starts_with("SecDefaultAction")
      || raw.starts_with("SecComponentSignature")
    {
      return Ok(());
    }
    bail!("unsupported CRS directive {raw}");
  }
}

impl CrsRule {
  pub(super) fn from_parts(
    variables: Vec<CrsVariable>,
    operator: CrsOperator,
    actions_raw: &str,
  ) -> anyhow::Result<Self> {
    let tokens = split_actions(actions_raw);
    let mut id = String::new();
    let mut phase = 2u8;
    let mut actions = Vec::new();
    let mut transforms = Vec::new();
    let mut tags = Vec::new();
    let mut msg = None;
    let mut skip_after = None;
    let mut chain = false;
    for token in tokens {
      if let Some((key, value)) = token.split_once(':') {
        match key {
          "id" => id = unquote(value).to_string(),
          "phase" => phase = unquote(value).parse::<u8>()?,
          "msg" => msg = Some(unquote(value).to_string()),
          "tag" => tags.push(unquote(value).to_string()),
          "skipAfter" => skip_after = Some(unquote(value).to_string()),
          "setvar" => {
            if let Some(action) = parse_setvar(unquote(value))? {
              actions.push(action);
            }
          }
          "t" => {
            let transform = unquote(value);
            if transform == "none" {
              transforms.clear();
            } else if let Some(transform) = CrsTransform::parse(transform)? {
              transforms.push(transform);
            }
          }
          "severity" | "ver" | "rev" | "status" | "logdata" | "accuracy" | "maturity" | "ctl"
          | "expirevar" | "initcol" | "setuid" | "sanitiseArg" => {}
          _ => bail!("unsupported CRS action {key}"),
        }
      } else {
        match token.as_str() {
          "chain" => chain = true,
          "pass" | "deny" | "block" | "log" | "nolog" | "auditlog" | "noauditlog" | "capture"
          | "multiMatch" | "append" | "prepend" => {}
          "" => {}
          _ => bail!("unsupported CRS action {token}"),
        }
      }
    }
    if id.is_empty() {
      id = format!("generated-{}", crate::waf::new_access_log_id());
    }
    Ok(Self {
      id,
      phase,
      variables,
      operator,
      transforms,
      actions,
      tags,
      msg,
      skip_after,
      chain: Vec::new(),
      expects_chain: chain,
      hit_key: None,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::super::operators::CrsOperator;
  use super::super::variables::CrsVariable;
  use super::*;

  #[test]
  fn parses_secrule_and_scores_with_setvar() {
    let rule = CrsRule::from_parts(
      vec![CrsVariable::RequestUri],
      CrsOperator::parse("@contains union select").unwrap(),
      "id:942100,phase:2,t:lowercase,tag:'paranoia-level/1',severity:'CRITICAL',setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'",
    )
    .unwrap();

    assert_eq!(rule.id, "942100");
    assert_eq!(rule.phase, 2);
    assert_eq!(rule.actions.len(), 1);
  }
}
