use std::collections::{HashMap, HashSet};

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
    &Default::default(),
    &mut Default::default(),
  )? {
    bail!("{label} cannot read request, response, or stream body bytes");
  }
  Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MitigationObjectOrigin {
  Request,
  RequestHttp,
  RequestBody,
  Response,
  ResponseHttp,
  ResponseBody,
  Stream,
  StreamPayload,
}

trait MitigationExpressionExt {
  fn references_mitigation_payload_with_functions(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    locals: &HashMap<&str, MitigationObjectOrigin>,
    active: &mut HashSet<FunctionKey>,
  ) -> anyhow::Result<bool>;

  fn mitigation_object_origin(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    locals: &HashMap<&str, MitigationObjectOrigin>,
    active: &mut HashSet<FunctionKey>,
  ) -> anyhow::Result<Option<MitigationObjectOrigin>>;

  fn function_call_locals<'a>(
    function_params: &'a [String],
    args: &'a [Expr],
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    locals: &HashMap<&str, MitigationObjectOrigin>,
    active: &mut HashSet<FunctionKey>,
  ) -> anyhow::Result<HashMap<&'a str, MitigationObjectOrigin>>;
}

impl MitigationExpressionExt for Expr {
  fn references_mitigation_payload_with_functions(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    locals: &HashMap<&str, MitigationObjectOrigin>,
    active: &mut HashSet<FunctionKey>,
  ) -> anyhow::Result<bool> {
    match self {
      Self::Member(receiver, field) => {
        if receiver.references_mitigation_payload_with_functions(
          global_functions,
          route_functions,
          locals,
          active,
        )? {
          return Ok(true);
        }
        let receiver_origin =
          receiver.mitigation_object_origin(global_functions, route_functions, locals, active)?;
        Ok(matches!(
          (receiver_origin, field.as_str()),
          (
            Some(MitigationObjectOrigin::Request | MitigationObjectOrigin::RequestHttp),
            "Body",
          ) | (
            Some(MitigationObjectOrigin::Response | MitigationObjectOrigin::ResponseHttp),
            "Body",
          ) | (Some(MitigationObjectOrigin::Stream), "Payload")
        ))
      }
      Self::Call(receiver, _, args) => {
        if receiver.references_mitigation_payload_with_functions(
          global_functions,
          route_functions,
          locals,
          active,
        )? {
          return Ok(true);
        }
        for arg in args {
          if arg.references_mitigation_payload_with_functions(
            global_functions,
            route_functions,
            locals,
            active,
          )? {
            return Ok(true);
          }
        }
        Ok(false)
      }
      Self::FunctionCall(name, args) => {
        for arg in args {
          if arg.references_mitigation_payload_with_functions(
            global_functions,
            route_functions,
            locals,
            active,
          )? {
            return Ok(true);
          }
        }
        let Some(function) = resolve_function(name, global_functions, route_functions) else {
          return Ok(false);
        };
        validate_function_arity(function, args.len())?;
        let body_locals = Self::function_call_locals(
          &function.params,
          args,
          global_functions,
          route_functions,
          locals,
          active,
        )?;
        let key = FunctionKey::from(function);
        if !active.insert(key.clone()) {
          return Ok(false);
        }
        let body_route_functions = function_body_route_functions(function, route_functions);
        let result = function
          .expression
          .references_mitigation_payload_with_functions(
            global_functions,
            body_route_functions,
            &body_locals,
            active,
          );
        active.remove(&key);
        result
      }
      Self::UnaryNot(expr) => expr.references_mitigation_payload_with_functions(
        global_functions,
        route_functions,
        locals,
        active,
      ),
      Self::Binary(left, _, right) => Ok(
        left.references_mitigation_payload_with_functions(
          global_functions,
          route_functions,
          locals,
          active,
        )? || right.references_mitigation_payload_with_functions(
          global_functions,
          route_functions,
          locals,
          active,
        )?,
      ),
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => Ok(false),
    }
  }

  fn mitigation_object_origin(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    locals: &HashMap<&str, MitigationObjectOrigin>,
    active: &mut HashSet<FunctionKey>,
  ) -> anyhow::Result<Option<MitigationObjectOrigin>> {
    match self {
      Self::Ident(name) => Ok(match name.as_str() {
        "Request" => Some(MitigationObjectOrigin::Request),
        "Response" => Some(MitigationObjectOrigin::Response),
        "Stream" => Some(MitigationObjectOrigin::Stream),
        _ => locals.get(name.as_str()).copied(),
      }),
      Self::Member(receiver, field) => match (
        receiver.mitigation_object_origin(global_functions, route_functions, locals, active)?,
        field.as_str(),
      ) {
        (Some(MitigationObjectOrigin::Request), "Http") => {
          Ok(Some(MitigationObjectOrigin::RequestHttp))
        }
        (Some(MitigationObjectOrigin::Request | MitigationObjectOrigin::RequestHttp), "Body") => {
          Ok(Some(MitigationObjectOrigin::RequestBody))
        }
        (Some(MitigationObjectOrigin::Response), "Http") => {
          Ok(Some(MitigationObjectOrigin::ResponseHttp))
        }
        (Some(MitigationObjectOrigin::Response | MitigationObjectOrigin::ResponseHttp), "Body") => {
          Ok(Some(MitigationObjectOrigin::ResponseBody))
        }
        (Some(MitigationObjectOrigin::Stream), "Payload") => {
          Ok(Some(MitigationObjectOrigin::StreamPayload))
        }
        _ => Ok(None),
      },
      Self::FunctionCall(name, args) => {
        let Some(function) = resolve_function(name, global_functions, route_functions) else {
          return Ok(None);
        };
        validate_function_arity(function, args.len())?;
        let body_locals = Self::function_call_locals(
          &function.params,
          args,
          global_functions,
          route_functions,
          locals,
          active,
        )?;
        let key = FunctionKey::from(function);
        if !active.insert(key.clone()) {
          return Ok(None);
        }
        let body_route_functions = function_body_route_functions(function, route_functions);
        let result = function.expression.mitigation_object_origin(
          global_functions,
          body_route_functions,
          &body_locals,
          active,
        );
        active.remove(&key);
        result
      }
      Self::Bool(_)
      | Self::Null
      | Self::Int(_)
      | Self::String(_)
      | Self::Call(_, _, _)
      | Self::UnaryNot(_)
      | Self::Binary(_, _, _) => Ok(None),
    }
  }

  fn function_call_locals<'a>(
    function_params: &'a [String],
    args: &'a [Expr],
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    locals: &HashMap<&str, MitigationObjectOrigin>,
    active: &mut HashSet<FunctionKey>,
  ) -> anyhow::Result<HashMap<&'a str, MitigationObjectOrigin>> {
    let mut body_locals = HashMap::new();
    for (param, arg) in function_params.iter().zip(args.iter()) {
      if let Some(origin) =
        arg.mitigation_object_origin(global_functions, route_functions, locals, active)?
      {
        body_locals.insert(param.as_str(), origin);
      }
    }
    Ok(body_locals)
  }
}
