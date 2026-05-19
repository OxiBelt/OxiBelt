use anyhow::{Context, bail};

use super::super::{
  AccessLogFieldConfig, Expr, FunctionKey, FunctionMap, Parser, WafPhase,
  function_body_route_functions, resolve_function, validate_function_arity,
};

pub(super) fn validate_mitigation_fields(
  label: &str,
  fields: &[AccessLogFieldConfig],
  phase: WafPhase,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<()> {
  let mut names = std::collections::HashSet::new();
  for field in fields {
    super::super::validate_access_log_field_name(label, &field.name)?;
    if !names.insert(field.name.as_str()) {
      bail!("{label} contains duplicate field {}", field.name);
    }
    validate_mitigation_expression(
      &format!("{label} field {}", field.name),
      &field.value,
      phase,
      global_functions,
      route_functions,
    )?;
  }
  Ok(())
}

pub(super) fn validate_mitigation_expression(
  label: &str,
  expression: &str,
  phase: WafPhase,
  global_functions: &FunctionMap,
  route_functions: Option<&FunctionMap>,
) -> anyhow::Result<()> {
  let expression = Parser::new(expression)
    .parse()
    .with_context(|| format!("failed to parse {label}"))?;
  expression
    .validate_for_phase_with_functions(phase, global_functions, route_functions)
    .with_context(|| format!("invalid {label}"))?;
  if expression.references_mitigation_payload_with_functions(
    global_functions,
    route_functions,
    &mut Default::default(),
  )? {
    bail!("{label} cannot read request, response, or stream body bytes");
  }
  Ok(())
}

trait MitigationExpressionExt {
  fn references_mitigation_payload_with_functions(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    active: &mut std::collections::HashSet<FunctionKey>,
  ) -> anyhow::Result<bool>;

  fn references_response_body_object(&self) -> bool;

  fn references_stream_payload_object(&self) -> bool;
}

impl MitigationExpressionExt for Expr {
  fn references_mitigation_payload_with_functions(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    active: &mut std::collections::HashSet<FunctionKey>,
  ) -> anyhow::Result<bool> {
    if self.references_request_body_object()
      || self.references_response_body_object()
      || self.references_stream_payload_object()
    {
      return Ok(true);
    }
    for call in self.function_calls() {
      let Some(function) = resolve_function(call.name, global_functions, route_functions) else {
        continue;
      };
      validate_function_arity(function, call.args.len())?;
      let key = FunctionKey::from(function);
      if !active.insert(key.clone()) {
        continue;
      }
      let body_route_functions = function_body_route_functions(function, route_functions);
      if function
        .expression
        .references_mitigation_payload_with_functions(
          global_functions,
          body_route_functions,
          active,
        )?
      {
        active.remove(&key);
        return Ok(true);
      }
      active.remove(&key);
    }
    Ok(false)
  }

  fn references_response_body_object(&self) -> bool {
    match self {
      Self::Member(receiver, field) => {
        (field == "Body" && (receiver.is_response_expr() || receiver.is_response_http_expr()))
          || receiver.references_response_body_object()
      }
      Self::Call(receiver, _, args) => {
        receiver.references_response_body_object()
          || args.iter().any(Self::references_response_body_object)
      }
      Self::FunctionCall(_, args) => args.iter().any(Self::references_response_body_object),
      Self::UnaryNot(expr) => expr.references_response_body_object(),
      Self::Binary(left, _, right) => {
        left.references_response_body_object() || right.references_response_body_object()
      }
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => false,
    }
  }

  fn references_stream_payload_object(&self) -> bool {
    match self {
      Self::Member(receiver, field) => {
        (field == "Payload" && receiver.is_stream_expr())
          || receiver.references_stream_payload_object()
      }
      Self::Call(receiver, _, args) => {
        receiver.references_stream_payload_object()
          || args.iter().any(Self::references_stream_payload_object)
      }
      Self::FunctionCall(_, args) => args.iter().any(Self::references_stream_payload_object),
      Self::UnaryNot(expr) => expr.references_stream_payload_object(),
      Self::Binary(left, _, right) => {
        left.references_stream_payload_object() || right.references_stream_payload_object()
      }
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => false,
    }
  }
}

trait StreamExprExt {
  fn is_stream_expr(&self) -> bool;
}

impl StreamExprExt for Expr {
  fn is_stream_expr(&self) -> bool {
    matches!(self, Self::Ident(name) if name == "Stream")
  }
}
