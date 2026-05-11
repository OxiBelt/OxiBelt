use std::collections::{HashMap, HashSet};

use anyhow::{Context, anyhow, bail};
use serde::Deserialize;

use super::{Expr, Parser};

pub(super) type FunctionMap = HashMap<String, CompiledFunction>;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct WafFunctionConfig {
  pub name: String,
  #[serde(default)]
  pub params: Vec<String>,
  pub expression: String,
}

#[derive(Clone)]
pub(super) struct CompiledFunction {
  pub(super) name: String,
  pub(super) params: Vec<String>,
  pub(super) expression: Expr,
  pub(super) origin: FunctionOrigin,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub(super) enum FunctionOrigin {
  Global,
  Route,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(super) struct FunctionKey {
  origin: FunctionOrigin,
  name: String,
}

impl From<&CompiledFunction> for FunctionKey {
  fn from(function: &CompiledFunction) -> Self {
    Self {
      origin: function.origin,
      name: function.name.clone(),
    }
  }
}

#[derive(Clone, Copy)]
pub(super) struct FunctionCallRef<'a> {
  pub(super) name: &'a str,
  pub(super) args: &'a [Expr],
}

pub(super) fn compile_global_functions(
  configs: &[WafFunctionConfig],
) -> anyhow::Result<FunctionMap> {
  let functions = compile_function_scope("global WAF", configs, FunctionOrigin::Global)?;
  validate_function_graph("global WAF", &functions, None)?;
  Ok(functions)
}

pub(super) fn compile_route_functions(
  scope: &str,
  configs: &[WafFunctionConfig],
  global_functions: &FunctionMap,
) -> anyhow::Result<FunctionMap> {
  let functions = compile_function_scope(scope, configs, FunctionOrigin::Route)?;
  validate_function_graph(scope, global_functions, Some(&functions))?;
  Ok(functions)
}

fn compile_function_scope(
  scope: &str,
  configs: &[WafFunctionConfig],
  origin: FunctionOrigin,
) -> anyhow::Result<FunctionMap> {
  let mut names = HashSet::new();
  let mut functions = FunctionMap::new();
  for config in configs {
    validate_oxirule_identifier(
      &config.name,
      &format!("{scope} function name {}", config.name),
    )?;
    if !names.insert(config.name.as_str()) {
      bail!(
        "{scope} contains duplicate OxiRule function {}",
        config.name
      );
    }

    let mut params = HashSet::new();
    for param in &config.params {
      validate_oxirule_identifier(
        param,
        &format!("{scope} function {} parameter {param}", config.name),
      )?;
      if !params.insert(param.as_str()) {
        bail!(
          "{scope} function {} contains duplicate parameter {param}",
          config.name
        );
      }
    }

    let expression = Parser::new(&config.expression)
      .parse()
      .with_context(|| format!("failed to parse {scope} function {}", config.name))?;
    functions.insert(
      config.name.clone(),
      CompiledFunction {
        name: config.name.clone(),
        params: config.params.clone(),
        expression,
        origin,
      },
    );
  }
  Ok(functions)
}

fn validate_function_graph(
  scope: &str,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<()> {
  let mut permanent = HashSet::new();
  let mut temporary = HashSet::new();
  let roots = route_functions.unwrap_or(global_functions);
  for function in roots.values() {
    validate_function_node(
      scope,
      function,
      global_functions,
      route_functions,
      &mut permanent,
      &mut temporary,
    )?;
  }
  Ok(())
}

fn validate_function_node(
  scope: &str,
  function: &CompiledFunction,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
  permanent: &mut HashSet<FunctionKey>,
  temporary: &mut HashSet<FunctionKey>,
) -> anyhow::Result<()> {
  let key = FunctionKey::from(function);
  if permanent.contains(&key) {
    return Ok(());
  }
  if !temporary.insert(key.clone()) {
    bail!(
      "{scope} contains recursive OxiRule function {}",
      function.name
    );
  }

  let body_route_functions = function_body_route_functions(function, route_functions);
  for call in function.expression.function_calls() {
    let callee =
      resolve_function(call.name, global_functions, body_route_functions).ok_or_else(|| {
        anyhow!(
          "{scope} function {} calls unknown OxiRule function {}",
          function.name,
          call.name
        )
      })?;
    validate_function_arity(callee, call.args.len())
      .with_context(|| format!("{scope} function {} calls {}", function.name, call.name))?;
    validate_function_node(
      scope,
      callee,
      global_functions,
      body_route_functions,
      permanent,
      temporary,
    )?;
  }

  temporary.remove(&key);
  permanent.insert(key);
  Ok(())
}

pub(super) fn resolve_function<'a>(
  name: &str,
  global_functions: &'a FunctionMap,
  route_functions: Option<&'a FunctionMap>,
) -> Option<&'a CompiledFunction> {
  route_functions
    .and_then(|functions| functions.get(name))
    .or_else(|| global_functions.get(name))
}

pub(super) fn function_body_route_functions<'a>(
  function: &CompiledFunction,
  route_functions: Option<&'a FunctionMap>,
) -> Option<&'a FunctionMap> {
  match function.origin {
    FunctionOrigin::Global => None,
    FunctionOrigin::Route => route_functions,
  }
}

pub(super) fn validate_function_arity(
  function: &CompiledFunction,
  args_len: usize,
) -> anyhow::Result<()> {
  if function.params.len() != args_len {
    bail!(
      "OxiRule function {} expects {} arguments but got {args_len}",
      function.name,
      function.params.len()
    );
  }
  Ok(())
}

fn validate_oxirule_identifier(identifier: &str, label: &str) -> anyhow::Result<()> {
  let mut chars = identifier.chars();
  let Some(first) = chars.next() else {
    bail!("{label} must be a valid OxiRule identifier");
  };
  if !(first.is_ascii_alphabetic() || first == '_')
    || !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    || is_reserved_oxirule_identifier(identifier)
    || is_top_level_oxirule_object(identifier)
  {
    bail!("{label} must be a valid OxiRule identifier");
  }
  Ok(())
}

fn is_reserved_oxirule_identifier(identifier: &str) -> bool {
  matches!(
    identifier,
    "if"
      | "else"
      | "for"
      | "while"
      | "do"
      | "switch"
      | "let"
      | "const"
      | "function"
      | "import"
      | "export"
      | "new"
      | "try"
      | "catch"
      | "throw"
      | "await"
      | "return"
      | "true"
      | "false"
      | "null"
  )
}

fn is_top_level_oxirule_object(identifier: &str) -> bool {
  matches!(
    identifier,
    "Context" | "Request" | "DynamicPolicy" | "Response" | "Stream"
  )
}
