//! Per-route WAF execution planning.
//! Plans make body-inspection needs explicit before proxy fast paths are chosen.

use std::sync::Arc;

use std::collections::HashMap;

use online_dsl_forge::{BodyAccess, BodyTarget, VerifiedExprKindRef, VerifiedExpression};

use super::{CompiledAction, CompiledRule, Expr, FunctionMap, WafActionConfig, WafPhase};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum BodyNeed {
  #[default]
  None,
  SizeOnly,
  PrefixBytes,
}

impl BodyNeed {
  pub fn merge(self, other: Self) -> Self {
    self.max(other)
  }

  pub fn requires_prefix(self) -> bool {
    self == Self::PrefixBytes
  }
}

#[derive(Clone)]
pub struct WafPhasePlan {
  enabled: bool,
  body_need: BodyNeed,
  rules: Arc<[CompiledRule]>,
}

impl WafPhasePlan {
  pub(super) fn new(enabled: bool, body_need: BodyNeed, rules: Arc<[CompiledRule]>) -> Self {
    Self {
      enabled,
      body_need,
      rules,
    }
  }

  pub fn enabled(&self) -> bool {
    self.enabled
  }

  pub fn body_need(&self) -> BodyNeed {
    self.body_need
  }

  pub(super) fn rules(&self) -> &[CompiledRule] {
    &self.rules
  }
}

#[derive(Clone)]
pub struct WafRoutePlan {
  request: WafPhasePlan,
  response: WafPhasePlan,
  stream: WafPhasePlan,
  request_body_need: BodyNeed,
}

impl WafRoutePlan {
  pub(super) fn new(request: WafPhasePlan, response: WafPhasePlan, stream: WafPhasePlan) -> Self {
    let request_body_need =
      request
        .body_need()
        .merge(response.rules().iter().fold(BodyNeed::None, |need, rule| {
          need.merge(rule.request_body_need)
        }));
    Self {
      request,
      response,
      stream,
      request_body_need,
    }
  }

  pub fn request(&self) -> &WafPhasePlan {
    &self.request
  }

  pub fn response(&self) -> &WafPhasePlan {
    &self.response
  }

  pub fn stream(&self) -> &WafPhasePlan {
    &self.stream
  }

  pub fn request_body_need(&self) -> BodyNeed {
    self.request_body_need
  }

  pub(crate) fn plain_proxy_fast_path_safe(&self) -> bool {
    self.request_body_need == BodyNeed::None
      && self.response.body_need() == BodyNeed::None
      && !self.stream.enabled()
      && !self.request_has_upstream_selection_actions()
  }

  pub(crate) fn static_sendfile_fast_path_safe(&self) -> bool {
    self.request_body_need <= BodyNeed::SizeOnly
      && self.response.body_need() <= BodyNeed::SizeOnly
      && !self.stream.enabled()
  }

  pub(super) fn disabled() -> Self {
    Self::new(
      WafPhasePlan::new(false, BodyNeed::None, Arc::from([])),
      WafPhasePlan::new(false, BodyNeed::None, Arc::from([])),
      WafPhasePlan::new(false, BodyNeed::None, Arc::from([])),
    )
  }

  fn request_has_upstream_selection_actions(&self) -> bool {
    self
      .request
      .rules()
      .iter()
      .any(|rule| rule.actions.iter().any(action_selects_upstream))
  }
}

fn action_selects_upstream(action: &CompiledAction) -> bool {
  matches!(
    action,
    CompiledAction::Config(
      WafActionConfig::RouteToPool { .. }
        | WafActionConfig::RouteToUpstream { .. }
        | WafActionConfig::SetLoadBalancingPolicy { .. }
    )
  )
}

pub(super) fn phase_plan(
  global_rules: &[CompiledRule],
  route_rules: &[CompiledRule],
  phase: WafPhase,
  crs_enabled: bool,
  crs_body_need: BodyNeed,
) -> WafPhasePlan {
  let mut rules = global_rules
    .iter()
    .chain(route_rules.iter())
    .filter(|rule| rule.phase == phase)
    .cloned()
    .collect::<Vec<_>>();
  rules.sort_by(|left, right| {
    left
      .priority
      .cmp(&right.priority)
      .then_with(|| left.name.cmp(&right.name))
  });
  let body_need = rules.iter().fold(crs_body_need, |need, rule| match phase {
    WafPhase::Request => need.merge(rule.request_body_need),
    WafPhase::Response => need.merge(rule.response_body_need),
    WafPhase::Stream => need,
  });
  WafPhasePlan::new(
    crs_enabled || !rules.is_empty(),
    body_need,
    Arc::from(rules),
  )
}

impl Expr {
  pub(super) fn request_body_need_with_functions(
    &self,
    _global_functions: &FunctionMap,
    _route_functions: Option<&FunctionMap>,
  ) -> BodyNeed {
    self
      .body_need()
      .map(|need| {
        body_need_for_target(need, BodyTarget::Request)
          .merge(self.compat_body_need_for_target(BodyTarget::Request))
      })
      .unwrap_or(BodyNeed::None)
  }

  pub(super) fn response_body_need_with_functions(
    &self,
    _global_functions: &FunctionMap,
    _route_functions: Option<&FunctionMap>,
  ) -> BodyNeed {
    self
      .body_need()
      .map(|need| {
        body_need_for_target(need, BodyTarget::Response)
          .merge(self.compat_body_need_for_target(BodyTarget::Response))
      })
      .unwrap_or(BodyNeed::None)
  }

  fn compat_body_need_for_target(&self, target: BodyTarget) -> BodyNeed {
    self
      .verified_root()
      .map(|expression| body_need_for_verified_target(expression, target, &HashMap::new()))
      .unwrap_or(BodyNeed::None)
  }
}

fn body_need_for_target(need: online_dsl_forge::BodyNeedSummary, target: BodyTarget) -> BodyNeed {
  let access = match target {
    BodyTarget::Request => need.request,
    BodyTarget::Response => need.response,
    BodyTarget::Stream => need.stream,
  };
  match access {
    BodyAccess::None => BodyNeed::None,
    BodyAccess::SizeOnly => BodyNeed::SizeOnly,
    BodyAccess::PrefixBytes => BodyNeed::PrefixBytes,
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyObjectOrigin {
  Request,
  RequestHttp,
  RequestBody,
  RequestBodyBytes,
  Response,
  ResponseHttp,
  ResponseBody,
  ResponseBodyBytes,
  Stream,
  StreamPayload,
}

fn body_need_for_verified_target(
  expression: &VerifiedExpression,
  target: BodyTarget,
  locals: &HashMap<&str, BodyObjectOrigin>,
) -> BodyNeed {
  match expression.kind() {
    VerifiedExprKindRef::Member { receiver, name } => {
      let need = body_need_for_verified_target(receiver, target, locals);
      let member_need = match (body_object_origin(receiver, locals), name, target) {
        (Some(BodyObjectOrigin::RequestBody), "Size", BodyTarget::Request)
        | (Some(BodyObjectOrigin::ResponseBody), "Size", BodyTarget::Response) => {
          BodyNeed::SizeOnly
        }
        (
          Some(BodyObjectOrigin::RequestBody),
          "Bytes" | "Text" | "IsTruncated",
          BodyTarget::Request,
        )
        | (
          Some(BodyObjectOrigin::ResponseBody),
          "Bytes" | "Text" | "IsTruncated",
          BodyTarget::Response,
        ) => BodyNeed::PrefixBytes,
        _ => BodyNeed::None,
      };
      need.merge(member_need)
    }
    VerifiedExprKindRef::MethodCall {
      receiver,
      name,
      args,
    } => {
      let need = args.iter().fold(
        body_need_for_verified_target(receiver, target, locals),
        |need, arg| need.merge(body_need_for_verified_target(arg, target, locals)),
      );
      let method_need = match (body_object_origin(receiver, locals), target) {
        (Some(BodyObjectOrigin::RequestBody), BodyTarget::Request) if body_content_method(name) => {
          BodyNeed::PrefixBytes
        }
        (Some(BodyObjectOrigin::ResponseBody), BodyTarget::Response)
          if body_content_method(name) =>
        {
          BodyNeed::PrefixBytes
        }
        (Some(BodyObjectOrigin::RequestBodyBytes), BodyTarget::Request)
          if bytes_content_method(name) =>
        {
          BodyNeed::PrefixBytes
        }
        (Some(BodyObjectOrigin::ResponseBodyBytes), BodyTarget::Response)
          if bytes_content_method(name) =>
        {
          BodyNeed::PrefixBytes
        }
        _ => BodyNeed::None,
      };
      need.merge(method_need)
    }
    VerifiedExprKindRef::ExpressionFunctionCall {
      params, args, body, ..
    } => {
      let args_need = args.iter().fold(BodyNeed::None, |need, arg| {
        need.merge(body_need_for_verified_target(arg, target, locals))
      });
      let body_locals = body_function_locals(params, args, locals);
      args_need.merge(body_need_for_verified_target(body, target, &body_locals))
    }
    VerifiedExprKindRef::FunctionCall { args, .. } | VerifiedExprKindRef::Array(args) => {
      args.iter().fold(BodyNeed::None, |need, arg| {
        need.merge(body_need_for_verified_target(arg, target, locals))
      })
    }
    VerifiedExprKindRef::Unary { expr, .. } => body_need_for_verified_target(expr, target, locals),
    VerifiedExprKindRef::Binary { left, right, .. } => {
      body_need_for_verified_target(left, target, locals)
        .merge(body_need_for_verified_target(right, target, locals))
    }
    VerifiedExprKindRef::Null
    | VerifiedExprKindRef::Bool(_)
    | VerifiedExprKindRef::Int(_)
    | VerifiedExprKindRef::Float(_)
    | VerifiedExprKindRef::String(_)
    | VerifiedExprKindRef::Identifier(_) => BodyNeed::None,
  }
}

fn body_object_origin(
  expression: &VerifiedExpression,
  locals: &HashMap<&str, BodyObjectOrigin>,
) -> Option<BodyObjectOrigin> {
  match expression.kind() {
    VerifiedExprKindRef::Identifier(name) => match name {
      "Request" => Some(BodyObjectOrigin::Request),
      "Response" => Some(BodyObjectOrigin::Response),
      "Stream" => Some(BodyObjectOrigin::Stream),
      _ => locals.get(name).copied(),
    },
    VerifiedExprKindRef::Member { receiver, name } => {
      match (body_object_origin(receiver, locals), name) {
        (Some(BodyObjectOrigin::Request), "Http") => Some(BodyObjectOrigin::RequestHttp),
        (Some(BodyObjectOrigin::Request | BodyObjectOrigin::RequestHttp), "Body") => {
          Some(BodyObjectOrigin::RequestBody)
        }
        (Some(BodyObjectOrigin::RequestBody), "Bytes") => Some(BodyObjectOrigin::RequestBodyBytes),
        (Some(BodyObjectOrigin::Response), "Http") => Some(BodyObjectOrigin::ResponseHttp),
        (Some(BodyObjectOrigin::Response | BodyObjectOrigin::ResponseHttp), "Body") => {
          Some(BodyObjectOrigin::ResponseBody)
        }
        (Some(BodyObjectOrigin::ResponseBody), "Bytes") => {
          Some(BodyObjectOrigin::ResponseBodyBytes)
        }
        (Some(BodyObjectOrigin::Stream), "Payload") => Some(BodyObjectOrigin::StreamPayload),
        _ => None,
      }
    }
    VerifiedExprKindRef::ExpressionFunctionCall {
      params, args, body, ..
    } => {
      let body_locals = body_function_locals(params, args, locals);
      body_object_origin(body, &body_locals)
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

fn body_function_locals<'a>(
  params: &'a [String],
  args: &'a [VerifiedExpression],
  locals: &HashMap<&str, BodyObjectOrigin>,
) -> HashMap<&'a str, BodyObjectOrigin> {
  params
    .iter()
    .zip(args.iter())
    .filter_map(|(param, arg)| {
      body_object_origin(arg, locals).map(|origin| (param.as_str(), origin))
    })
    .collect()
}

fn body_content_method(method: &str) -> bool {
  matches!(
    method,
    "isFormat"
      | "isBinaryFormat"
      | "matchesFormat"
      | "contains"
      | "matches"
      | "containsAny"
      | "matchesAny"
      | "scan"
      | "anomalyScore"
      | "malformedScore"
      | "promptInjectionScore"
  )
}

fn bytes_content_method(method: &str) -> bool {
  matches!(
    method,
    "isFormat" | "isBinaryFormat" | "matchesFormat" | "size"
  )
}
