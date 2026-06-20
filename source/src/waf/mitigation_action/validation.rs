//! Validation helpers for WAF mitigation actions.
//! Validation ensures response and stream actions are safe before compilation.

use std::collections::HashMap;

use anyhow::{Context, bail};
use online_dsl_forge::{VerifiedExprKindRef, VerifiedExpression};

use super::super::{AccessLogFieldConfig, FunctionMap, Parser, WafPhase};

const MITIGATION_PAYLOAD_ERROR: &str = "cannot read request, response, or stream body bytes";

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
  let expression =
    match expression.analyze_for_mitigation_field(phase, global_functions, route_functions) {
      Ok(expression) => expression,
      Err(error) if format!("{error:#}").contains(MITIGATION_PAYLOAD_ERROR) => {
        bail!("{label} {MITIGATION_PAYLOAD_ERROR}");
      }
      Err(error) => return Err(error).with_context(|| format!("invalid {label}")),
    };
  if references_mitigation_payload(expression.verified_root()?, &HashMap::new()) {
    bail!("{label} {MITIGATION_PAYLOAD_ERROR}");
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

fn references_mitigation_payload(
  expression: &VerifiedExpression,
  locals: &HashMap<&str, MitigationObjectOrigin>,
) -> bool {
  match expression.kind() {
    VerifiedExprKindRef::Member { receiver, name } => {
      references_mitigation_payload(receiver, locals)
        || matches!(
          (mitigation_object_origin(receiver, locals), name),
          (
            Some(MitigationObjectOrigin::Request | MitigationObjectOrigin::RequestHttp),
            "Body",
          ) | (
            Some(MitigationObjectOrigin::Response | MitigationObjectOrigin::ResponseHttp),
            "Body",
          ) | (Some(MitigationObjectOrigin::Stream), "Payload")
        )
    }
    VerifiedExprKindRef::ExpressionFunctionCall {
      params, args, body, ..
    } => {
      if args
        .iter()
        .any(|arg| references_mitigation_payload(arg, locals))
      {
        return true;
      }
      let body_locals = function_body_locals(params, args, locals);
      references_mitigation_payload(body, &body_locals)
    }
    VerifiedExprKindRef::FunctionCall { args, .. } | VerifiedExprKindRef::Array(args) => args
      .iter()
      .any(|arg| references_mitigation_payload(arg, locals)),
    VerifiedExprKindRef::MethodCall { receiver, args, .. } => {
      references_mitigation_payload(receiver, locals)
        || args
          .iter()
          .any(|arg| references_mitigation_payload(arg, locals))
    }
    VerifiedExprKindRef::Unary { expr, .. } => references_mitigation_payload(expr, locals),
    VerifiedExprKindRef::Binary { left, right, .. } => {
      references_mitigation_payload(left, locals) || references_mitigation_payload(right, locals)
    }
    VerifiedExprKindRef::Null
    | VerifiedExprKindRef::Bool(_)
    | VerifiedExprKindRef::Int(_)
    | VerifiedExprKindRef::Float(_)
    | VerifiedExprKindRef::String(_)
    | VerifiedExprKindRef::Identifier(_) => false,
  }
}

fn mitigation_object_origin(
  expression: &VerifiedExpression,
  locals: &HashMap<&str, MitigationObjectOrigin>,
) -> Option<MitigationObjectOrigin> {
  match expression.kind() {
    VerifiedExprKindRef::Identifier(name) => match name {
      "Request" => Some(MitigationObjectOrigin::Request),
      "Response" => Some(MitigationObjectOrigin::Response),
      "Stream" => Some(MitigationObjectOrigin::Stream),
      _ => locals.get(name).copied(),
    },
    VerifiedExprKindRef::Member { receiver, name } => {
      match (mitigation_object_origin(receiver, locals), name) {
        (Some(MitigationObjectOrigin::Request), "Http") => {
          Some(MitigationObjectOrigin::RequestHttp)
        }
        (Some(MitigationObjectOrigin::Request | MitigationObjectOrigin::RequestHttp), "Body") => {
          Some(MitigationObjectOrigin::RequestBody)
        }
        (Some(MitigationObjectOrigin::Response), "Http") => {
          Some(MitigationObjectOrigin::ResponseHttp)
        }
        (Some(MitigationObjectOrigin::Response | MitigationObjectOrigin::ResponseHttp), "Body") => {
          Some(MitigationObjectOrigin::ResponseBody)
        }
        (Some(MitigationObjectOrigin::Stream), "Payload") => {
          Some(MitigationObjectOrigin::StreamPayload)
        }
        _ => None,
      }
    }
    VerifiedExprKindRef::ExpressionFunctionCall {
      params, args, body, ..
    } => {
      let body_locals = function_body_locals(params, args, locals);
      mitigation_object_origin(body, &body_locals)
    }
    VerifiedExprKindRef::Null
    | VerifiedExprKindRef::Bool(_)
    | VerifiedExprKindRef::Int(_)
    | VerifiedExprKindRef::Float(_)
    | VerifiedExprKindRef::String(_)
    | VerifiedExprKindRef::Array(_)
    | VerifiedExprKindRef::FunctionCall { .. }
    | VerifiedExprKindRef::MethodCall { .. }
    | VerifiedExprKindRef::Unary { .. }
    | VerifiedExprKindRef::Binary { .. } => None,
  }
}

fn function_body_locals<'a>(
  params: &'a [String],
  args: &'a [VerifiedExpression],
  locals: &HashMap<&str, MitigationObjectOrigin>,
) -> HashMap<&'a str, MitigationObjectOrigin> {
  params
    .iter()
    .zip(args.iter())
    .filter_map(|(param, arg)| {
      mitigation_object_origin(arg, locals).map(|origin| (param.as_str(), origin))
    })
    .collect()
}
