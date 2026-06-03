//! Per-route WAF execution planning.
//! Plans make body-inspection needs explicit before proxy fast paths are chosen.

use std::collections::HashSet;
use std::sync::Arc;

use super::functions::CompiledFunction;
use super::{
  CompiledAction, CompiledRule, Expr, FunctionKey, FunctionMap, WafActionConfig, WafPhase,
  body_content_method, bytes_content_method, function_body_route_functions, resolve_function,
};

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

#[derive(Default)]
struct BodyBindings(Vec<String>, Vec<String>);

impl BodyBindings {
  fn bind(function: &CompiledFunction, args: &[Expr], caller: &Self) -> Self {
    let mut bindings = Self::default();
    for (param, arg) in function.params.iter().zip(args) {
      if arg.is_request_body_expr_with_bindings(caller) {
        bindings.0.push(param.clone());
      }
      if arg.is_response_body_expr_with_bindings(caller) {
        bindings.1.push(param.clone());
      }
    }
    bindings
  }
}

impl Expr {
  fn request_body_need_with_bindings(&self, bindings: &BodyBindings) -> BodyNeed {
    match self {
      Self::Member(receiver, field) => {
        let need = receiver.request_body_need_with_bindings(bindings);
        if receiver.is_request_body_expr_with_bindings(bindings) {
          need.merge(match field.as_str() {
            "Size" => BodyNeed::SizeOnly,
            "Bytes" | "Text" | "IsTruncated" => BodyNeed::PrefixBytes,
            _ => BodyNeed::None,
          })
        } else {
          need
        }
      }
      Self::Call(receiver, method, args) => {
        let need = args.iter().fold(
          receiver.request_body_need_with_bindings(bindings),
          |need, arg| need.merge(arg.request_body_need_with_bindings(bindings)),
        );
        if (receiver.is_request_body_expr_with_bindings(bindings) && body_content_method(method))
          || (receiver.is_request_body_bytes_expr_with_bindings(bindings)
            && bytes_content_method(method))
        {
          need.merge(BodyNeed::PrefixBytes)
        } else {
          need
        }
      }
      Self::FunctionCall(_, args) => args.iter().fold(BodyNeed::None, |need, arg| {
        need.merge(arg.request_body_need_with_bindings(bindings))
      }),
      Self::UnaryNot(expr) => expr.request_body_need_with_bindings(bindings),
      Self::Binary(left, _, right) => left
        .request_body_need_with_bindings(bindings)
        .merge(right.request_body_need_with_bindings(bindings)),
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => {
        BodyNeed::None
      }
    }
  }

  fn response_body_need_with_bindings(&self, bindings: &BodyBindings) -> BodyNeed {
    match self {
      Self::Member(receiver, field) => {
        let need = receiver.response_body_need_with_bindings(bindings);
        if receiver.is_response_body_expr_with_bindings(bindings) {
          need.merge(match field.as_str() {
            "Size" => BodyNeed::SizeOnly,
            "Bytes" | "Text" | "IsTruncated" => BodyNeed::PrefixBytes,
            _ => BodyNeed::None,
          })
        } else {
          need
        }
      }
      Self::Call(receiver, method, args) => {
        let need = args.iter().fold(
          receiver.response_body_need_with_bindings(bindings),
          |need, arg| need.merge(arg.response_body_need_with_bindings(bindings)),
        );
        if (receiver.is_response_body_expr_with_bindings(bindings) && body_content_method(method))
          || (receiver.is_response_body_bytes_expr_with_bindings(bindings)
            && bytes_content_method(method))
        {
          need.merge(BodyNeed::PrefixBytes)
        } else {
          need
        }
      }
      Self::FunctionCall(_, args) => args.iter().fold(BodyNeed::None, |need, arg| {
        need.merge(arg.response_body_need_with_bindings(bindings))
      }),
      Self::UnaryNot(expr) => expr.response_body_need_with_bindings(bindings),
      Self::Binary(left, _, right) => left
        .response_body_need_with_bindings(bindings)
        .merge(right.response_body_need_with_bindings(bindings)),
      Self::Bool(_) | Self::Null | Self::Int(_) | Self::String(_) | Self::Ident(_) => {
        BodyNeed::None
      }
    }
  }

  fn is_request_body_expr(&self) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Body" && (receiver.is_request_expr() || receiver.is_request_http_expr()))
  }

  fn is_request_body_expr_with_bindings(&self, bindings: &BodyBindings) -> bool {
    self.is_request_body_expr()
      || matches!(self, Self::Ident(name) if bindings.0.iter().any(|param| param == name))
  }

  fn is_request_body_bytes_expr_with_bindings(&self, bindings: &BodyBindings) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Bytes" && receiver.is_request_body_expr_with_bindings(bindings))
  }

  fn is_response_body_expr(&self) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Body" && (receiver.is_response_expr() || receiver.is_response_http_expr()))
  }

  fn is_response_body_expr_with_bindings(&self, bindings: &BodyBindings) -> bool {
    self.is_response_body_expr()
      || matches!(self, Self::Ident(name) if bindings.1.iter().any(|param| param == name))
  }

  fn is_response_body_bytes_expr_with_bindings(&self, bindings: &BodyBindings) -> bool {
    matches!(self, Self::Member(receiver, field) if field == "Bytes" && receiver.is_response_body_expr_with_bindings(bindings))
  }

  pub(super) fn request_body_need_with_functions(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> BodyNeed {
    self.request_body_need_with_functions_inner(
      global_functions,
      route_functions,
      &mut HashSet::new(),
      &BodyBindings::default(),
    )
  }

  fn request_body_need_with_functions_inner(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    active: &mut HashSet<FunctionKey>,
    bindings: &BodyBindings,
  ) -> BodyNeed {
    self.function_calls().into_iter().fold(
      self.request_body_need_with_bindings(bindings),
      |need, call| {
        let Some(function) = resolve_function(call.name, global_functions, route_functions) else {
          return need;
        };
        let key = FunctionKey::from(function);
        if !active.insert(key.clone()) {
          return need;
        }
        let body_route_functions = function_body_route_functions(function, route_functions);
        let body_bindings = BodyBindings::bind(function, call.args, bindings);
        let result = function.expression.request_body_need_with_functions_inner(
          global_functions,
          body_route_functions,
          active,
          &body_bindings,
        );
        active.remove(&key);
        need.merge(result)
      },
    )
  }

  pub(super) fn response_body_need_with_functions(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
  ) -> BodyNeed {
    self.response_body_need_with_functions_inner(
      global_functions,
      route_functions,
      &mut HashSet::new(),
      &BodyBindings::default(),
    )
  }

  fn response_body_need_with_functions_inner(
    &self,
    global_functions: &FunctionMap,
    route_functions: Option<&FunctionMap>,
    active: &mut HashSet<FunctionKey>,
    bindings: &BodyBindings,
  ) -> BodyNeed {
    self.function_calls().into_iter().fold(
      self.response_body_need_with_bindings(bindings),
      |need, call| {
        let Some(function) = resolve_function(call.name, global_functions, route_functions) else {
          return need;
        };
        let key = FunctionKey::from(function);
        if !active.insert(key.clone()) {
          return need;
        }
        let body_route_functions = function_body_route_functions(function, route_functions);
        let body_bindings = BodyBindings::bind(function, call.args, bindings);
        let result = function.expression.response_body_need_with_functions_inner(
          global_functions,
          body_route_functions,
          active,
          &body_bindings,
        );
        active.remove(&key);
        need.merge(result)
      },
    )
  }
}
