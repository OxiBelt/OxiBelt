//! OxiRule expression facade backed by `online-dsl-forge`.
//! The facade keeps OxiBelt's WAF-specific runtime semantics behind one boundary.

use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use online_dsl_forge::{
  Analyzer, AstExpression, BodyNeedSummary, DiagnosticReport, ExpressionDialect,
  ExpressionFunctionMode, Phase, RuntimeSchema, SecurityProfile, VerifiedExprKindRef,
  VerifiedExpression, VerifiedProgram, parse_expression,
};

use super::WafPhase;
use super::functions::FunctionMap;

#[derive(Clone, Debug)]
pub(super) struct Expr {
  ast: AstExpression,
  verified: Option<Arc<VerifiedProgram>>,
}

#[derive(Clone, Copy)]
pub(super) struct FunctionCallRef<'a> {
  pub(super) name: &'a str,
  pub(super) arity: usize,
}

pub(super) struct Parser<'a> {
  input: &'a str,
}

impl<'a> Parser<'a> {
  pub(super) fn new(input: &'a str) -> Self {
    Self { input }
  }

  pub(super) fn parse(self) -> anyhow::Result<Expr> {
    Expr::parse(self.input)
  }
}

impl Expr {
  pub(super) fn parse(input: &str) -> anyhow::Result<Self> {
    validate_strict_source(input)?;
    let ast = parse_expression(input).map_err(diagnostic_report_error)?;
    Ok(Self {
      ast,
      verified: None,
    })
  }

  pub(super) fn ast(&self) -> &AstExpression {
    &self.ast
  }

  pub(super) fn verified_program(&self) -> anyhow::Result<&VerifiedProgram> {
    self
      .verified
      .as_deref()
      .ok_or_else(|| anyhow!("OxiRule expression was not analyzed before evaluation"))
  }

  pub(super) fn verified_root(&self) -> anyhow::Result<&VerifiedExpression> {
    Ok(self.verified_program()?.root())
  }

  pub(super) fn analyze_for_phase_with_functions(
    &self,
    phase: WafPhase,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> anyhow::Result<Self> {
    self.analyze_with_profile(
      security_profile_for_phase(phase),
      global_functions,
      route_functions,
    )
  }

  pub(super) fn validate_for_phase_with_functions(
    &self,
    phase: WafPhase,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> anyhow::Result<()> {
    self
      .analyze_for_phase_with_functions(phase, global_functions, route_functions)
      .map(|_| ())
  }

  pub(super) fn analyze_for_mitigation_field(
    &self,
    phase: WafPhase,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> anyhow::Result<Self> {
    self.analyze_with_profile(
      SecurityProfile::mitigation_field(forge_phase(phase)),
      global_functions,
      route_functions,
    )
  }

  pub(super) fn body_need(&self) -> anyhow::Result<BodyNeedSummary> {
    Ok(self.verified_program()?.body_need())
  }

  pub(super) fn function_calls(&self) -> Vec<FunctionCallRef<'_>> {
    let mut calls = Vec::new();
    collect_function_calls(&self.ast, &mut calls);
    calls
  }

  fn analyze_with_profile(
    &self,
    profile: SecurityProfile,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> anyhow::Result<Self> {
    let schema = schema_with_functions(global_functions, route_functions);
    let verified = Analyzer::new(profile)
      .with_dialect(ExpressionDialect::OxiRuleV1)
      .with_expression_function_mode(ExpressionFunctionMode::CallFrame)
      .analyze(&self.ast, &schema)
      .map_err(diagnostic_report_error)?;
    Ok(Self {
      ast: self.ast.clone(),
      verified: Some(Arc::new(verified)),
    })
  }
}

fn schema_with_functions(
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> RuntimeSchema {
  let mut schema = RuntimeSchema::oxirule_waf();
  for function in global_functions.values() {
    schema.add_expression_function(
      function.name.clone(),
      function.params.clone(),
      function.expression.ast().clone(),
    );
  }
  if let Some(route_functions) = route_functions {
    for function in route_functions.values() {
      schema.add_local_expression_function(
        function.name.clone(),
        function.params.clone(),
        function.expression.ast().clone(),
      );
    }
  }
  schema
}

fn collect_function_calls<'a>(expression: &'a AstExpression, calls: &mut Vec<FunctionCallRef<'a>>) {
  match &expression.kind {
    online_dsl_forge::ExprKind::FunctionCall { name, args } => {
      calls.push(FunctionCallRef {
        name,
        arity: args.len(),
      });
      for arg in args {
        collect_function_calls(arg, calls);
      }
    }
    online_dsl_forge::ExprKind::Array { items } => {
      for item in items {
        collect_function_calls(item, calls);
      }
    }
    online_dsl_forge::ExprKind::Member { receiver, .. }
    | online_dsl_forge::ExprKind::Unary { expr: receiver, .. } => {
      collect_function_calls(receiver, calls);
    }
    online_dsl_forge::ExprKind::MethodCall { receiver, args, .. } => {
      collect_function_calls(receiver, calls);
      for arg in args {
        collect_function_calls(arg, calls);
      }
    }
    online_dsl_forge::ExprKind::Binary { left, right, .. } => {
      collect_function_calls(left, calls);
      collect_function_calls(right, calls);
    }
    online_dsl_forge::ExprKind::Null
    | online_dsl_forge::ExprKind::Bool { .. }
    | online_dsl_forge::ExprKind::Int { .. }
    | online_dsl_forge::ExprKind::Float { .. }
    | online_dsl_forge::ExprKind::String { .. }
    | online_dsl_forge::ExprKind::Identifier { .. } => {}
  }
}

pub(super) fn verified_string_literal(expression: &VerifiedExpression) -> Option<&str> {
  match expression.kind() {
    VerifiedExprKindRef::String(value) => Some(value),
    _ => None,
  }
}

fn security_profile_for_phase(phase: WafPhase) -> SecurityProfile {
  match phase {
    WafPhase::Request => SecurityProfile::oxirule_waf_request(),
    WafPhase::Response => SecurityProfile::oxirule_waf_response(),
    WafPhase::Stream => SecurityProfile::oxirule_waf_stream(),
  }
}

fn forge_phase(phase: WafPhase) -> Phase {
  match phase {
    WafPhase::Request => Phase::Request,
    WafPhase::Response => Phase::Response,
    WafPhase::Stream => Phase::Stream,
  }
}

fn diagnostic_report_error(report: DiagnosticReport) -> anyhow::Error {
  anyhow!(report.to_string())
}

fn validate_strict_source(input: &str) -> anyhow::Result<()> {
  let mut chars = input.char_indices().peekable();
  while let Some((index, ch)) = chars.next() {
    match ch {
      '\'' => consume_single_quoted_string(input, &mut chars)
        .with_context(|| format!("invalid OxiRule string literal at byte {index}"))?,
      '"' => bail!("OxiRule V1 supports single-quoted string literals only"),
      '[' | ']' => bail!("OxiRule V1 does not support array literals"),
      '-' => bail!("OxiRule V1 does not support unary numeric negation or operator -"),
      '*' => bail!("OxiRule V1 does not support operator *"),
      '%' => bail!("OxiRule V1 does not support operator %"),
      '/' if chars.peek().is_some_and(|(_, next)| *next == '/') => {
        bail!("OxiRule V1 does not support comments")
      }
      '/' => bail!("OxiRule V1 does not support operator /"),
      '0'..='9' => {
        consume_number_tail(input, &mut chars)?;
      }
      _ => {}
    }
  }
  Ok(())
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_and_analyze(input: &[u8]) {
  const MAX_EXPRESSION_BYTES: usize = 8 * 1024;
  let input = &input[..input.len().min(MAX_EXPRESSION_BYTES)];
  let Ok(input) = std::str::from_utf8(input) else {
    return;
  };
  let Ok(expression) = Parser::new(input).parse() else {
    return;
  };
  let functions = FunctionMap::new();
  for phase in [WafPhase::Request, WafPhase::Response, WafPhase::Stream] {
    if let Ok(analyzed) = expression.analyze_for_phase_with_functions(phase, &functions, None) {
      let _ = analyzed.verified_root();
      let _ = analyzed.body_need();
      let _ = analyzed.function_calls();
    }
  }
}

fn consume_single_quoted_string(
  input: &str,
  chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> anyhow::Result<()> {
  while let Some((_, ch)) = chars.next() {
    match ch {
      '\\' => {
        chars.next();
      }
      '\'' => return Ok(()),
      _ => {}
    }
  }
  bail!(
    "unterminated OxiRule string literal in {} bytes",
    input.len()
  )
}

fn consume_number_tail(
  input: &str,
  chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
) -> anyhow::Result<()> {
  while chars.peek().is_some_and(|(_, next)| next.is_ascii_digit()) {
    chars.next();
  }
  if let Some((dot_index, '.')) = chars.peek().copied() {
    let mut lookahead = chars.clone();
    lookahead.next();
    if lookahead
      .peek()
      .is_some_and(|(_, next)| next.is_ascii_digit())
    {
      bail!(
        "OxiRule V1 does not support float literal near byte {dot_index} in expression of {} bytes",
        input.len()
      );
    }
  }
  Ok(())
}
