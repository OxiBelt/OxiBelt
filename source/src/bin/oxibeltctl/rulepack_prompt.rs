use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};

use anyhow::{Context, bail};
use oxibelt::admin_client::AdminClient;
use oxibelt::identity::Cidr;
use oxibelt::waf::{RulepackBinding, RulepackInputMetadata, RulepackVariable};

use crate::cli::{RulepackModeArg, RulepackSourceArgs};
use crate::rulepack::LoadedRulepackSource;
use crate::rulepack_fit::{RulepackFitEvaluation, RulepackFitReport};

pub(crate) async fn complete_interactive_apply(
  client: &AdminClient,
  loaded: &LoadedRulepackSource,
  source_args: &RulepackSourceArgs,
  vars: &mut BTreeMap<String, String>,
  binds: &mut BTreeMap<String, String>,
  mode: RulepackModeArg,
  force_mode: bool,
) -> anyhow::Result<()> {
  let evaluation = crate::rulepack_fit::evaluate_fit(
    client,
    loaded,
    source_args,
    crate::rulepack_fit::RulepackFitOptions {
      vars,
      binds,
      command_vars: vars,
      command_binds: binds,
      values_file: None,
      profile_arg: None,
      mode: Some(mode),
      force_mode,
    },
  )
  .await?;
  let mut prompt = StdioPrompt;
  complete_interactive_from_evaluation(&evaluation, vars, binds, mode, &mut prompt)
}

pub(crate) trait InteractivePrompt {
  fn is_terminal(&self) -> bool;
  fn write_line(&mut self, line: &str) -> anyhow::Result<()>;
  fn prompt(&mut self, message: &str) -> anyhow::Result<String>;
}

pub(crate) struct StdioPrompt;

impl InteractivePrompt for StdioPrompt {
  fn is_terminal(&self) -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
  }

  fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
    writeln!(io::stderr(), "{line}").context("failed to write interactive prompt")
  }

  fn prompt(&mut self, message: &str) -> anyhow::Result<String> {
    eprint!("{message} ");
    io::stderr()
      .flush()
      .context("failed to flush interactive prompt")?;
    let mut line = String::new();
    io::stdin()
      .read_line(&mut line)
      .context("failed to read interactive input")?;
    Ok(line.trim().to_string())
  }
}

pub(crate) fn complete_interactive_from_evaluation(
  evaluation: &RulepackFitEvaluation,
  vars: &mut BTreeMap<String, String>,
  binds: &mut BTreeMap<String, String>,
  mode: RulepackModeArg,
  prompt: &mut impl InteractivePrompt,
) -> anyhow::Result<()> {
  if !prompt.is_terminal() {
    bail!("rulepack apply --interactive requires an interactive terminal");
  }
  collect_missing_bindings(&evaluation.inputs, &evaluation.report, vars, binds, prompt)?;
  collect_missing_variables(&evaluation.inputs, vars, binds, prompt)?;
  print_confirmation(&evaluation.inputs, vars, binds, mode, prompt)?;
  let answer = prompt.prompt("Apply rulepack now? [y/N]")?;
  if !matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes") {
    bail!("rulepack apply cancelled");
  }
  Ok(())
}

fn collect_missing_bindings(
  inputs: &RulepackInputMetadata,
  report: &RulepackFitReport,
  vars: &BTreeMap<String, String>,
  binds: &mut BTreeMap<String, String>,
  prompt: &mut impl InteractivePrompt,
) -> anyhow::Result<()> {
  for binding_name in crate::rulepack_fit::missing_required_bindings(inputs, vars, binds) {
    let binding = inputs
      .bindings
      .iter()
      .find(|binding| binding.name == binding_name)
      .with_context(|| format!("unknown binding {binding_name}"))?;
    let candidates = report
      .route_candidates
      .iter()
      .find(|set| set.binding == binding.name)
      .map(|set| set.candidates.as_slice())
      .unwrap_or_default();
    if !candidates.is_empty() {
      prompt.write_line(&format!("Route candidates for binding {}:", binding.name))?;
      for (index, candidate) in candidates.iter().enumerate() {
        prompt.write_line(&format!(
          "  {}. {} (score {}, {})",
          index + 1,
          candidate.name,
          candidate.score,
          candidate.reason.join("; ")
        ))?;
      }
    }
    let value = prompt_for_route(binding, candidates, prompt)?;
    binds.insert(binding.name.clone(), value);
  }
  Ok(())
}

fn prompt_for_route(
  binding: &RulepackBinding,
  candidates: &[crate::rulepack_fit::RouteCandidate],
  prompt: &mut impl InteractivePrompt,
) -> anyhow::Result<String> {
  let message = binding
    .prompt
    .as_deref()
    .unwrap_or("Select the route for this binding.");
  loop {
    let answer = prompt.prompt(&format!("{message} Enter number or route name:"))?;
    if answer.is_empty() {
      prompt.write_line("route selection must not be empty")?;
      continue;
    }
    if let Ok(index) = answer.parse::<usize>() {
      if index > 0
        && let Some(candidate) = candidates.get(index - 1)
      {
        return Ok(candidate.name.clone());
      }
      prompt.write_line("candidate number is out of range")?;
      continue;
    }
    return Ok(answer);
  }
}

fn collect_missing_variables(
  inputs: &RulepackInputMetadata,
  vars: &mut BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
  prompt: &mut impl InteractivePrompt,
) -> anyhow::Result<()> {
  for variable_name in crate::rulepack_fit::missing_required_variables(inputs, vars, binds) {
    let variable = inputs
      .variables
      .iter()
      .find(|variable| variable.name == variable_name)
      .with_context(|| format!("unknown variable {variable_name}"))?;
    let value = prompt_for_variable(variable, prompt)?;
    vars.insert(variable.name.clone(), value);
  }
  Ok(())
}

fn prompt_for_variable(
  variable: &RulepackVariable,
  prompt: &mut impl InteractivePrompt,
) -> anyhow::Result<String> {
  let message = variable
    .prompt
    .as_deref()
    .or(variable.description.as_deref())
    .unwrap_or("Enter required value.");
  loop {
    let answer = prompt.prompt(&format!("{message} ({})", variable.name))?;
    if answer.is_empty() {
      prompt.write_line("value must not be empty")?;
      continue;
    }
    if variable.value_type.as_deref() == Some("cidr") && Cidr::parse(&answer).is_err() {
      prompt.write_line("value must be a valid CIDR")?;
      continue;
    }
    if variable.value_type.as_deref() == Some("rate")
      && oxibelt::limits::parse_rate(&answer).is_err()
    {
      prompt.write_line("value must be a valid rate, such as 10r/s or 600r/m")?;
      continue;
    }
    return Ok(answer);
  }
}

fn print_confirmation(
  inputs: &RulepackInputMetadata,
  vars: &BTreeMap<String, String>,
  binds: &BTreeMap<String, String>,
  mode: RulepackModeArg,
  prompt: &mut impl InteractivePrompt,
) -> anyhow::Result<()> {
  prompt.write_line(&format!("Rulepack: {}", inputs.summary.name))?;
  prompt.write_line(&format!("Mode: {}", mode_name(mode)))?;
  if !binds.is_empty() {
    prompt.write_line("Bindings:")?;
    for (name, value) in binds {
      prompt.write_line(&format!("  {name}={value}"))?;
    }
  }
  let variable_count = vars
    .keys()
    .filter(|name| {
      !inputs
        .bindings
        .iter()
        .any(|binding| binding.bind_as == **name)
    })
    .count();
  if variable_count > 0 {
    prompt.write_line(&format!("Variables provided: {variable_count}"))?;
  }
  Ok(())
}

fn mode_name(mode: RulepackModeArg) -> &'static str {
  match mode {
    RulepackModeArg::Monitor => "monitor",
    RulepackModeArg::Enforcing => "enforcing",
  }
}

#[cfg(test)]
#[path = "rulepack_prompt_tests.rs"]
mod tests;
