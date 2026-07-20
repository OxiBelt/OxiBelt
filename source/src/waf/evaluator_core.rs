//! Expression evaluation context and transaction budgets.

use super::*;

pub(super) struct TransactionBudget<'a> {
  limits: &'a WafLimits,
  started_at: Instant,
  rule_started_at: Instant,
  steps: usize,
  mutations: usize,
}

impl<'a> TransactionBudget<'a> {
  pub(super) fn new(limits: &'a WafLimits) -> Self {
    let now = Instant::now();
    Self {
      limits,
      started_at: now,
      rule_started_at: now,
      steps: 0,
      mutations: 0,
    }
  }

  pub(super) fn start_rule(&mut self) {
    self.rule_started_at = Instant::now();
    self.steps = 0;
  }

  pub(super) fn step(&mut self) -> anyhow::Result<()> {
    self.steps += 1;
    if self.steps > self.limits.max_expression_steps {
      bail!("WAF expression step budget exceeded");
    }
    self.check_total()?;
    if self.rule_started_at.elapsed() > Duration::from_millis(self.limits.max_rule_runtime_ms) {
      bail!("WAF rule runtime budget exceeded");
    }
    Ok(())
  }

  pub(super) fn check_total(&self) -> anyhow::Result<()> {
    if self.started_at.elapsed() > Duration::from_millis(self.limits.max_total_waf_runtime_ms) {
      bail!("WAF total runtime budget exceeded");
    }
    Ok(())
  }

  pub(super) fn count_mutation(&mut self) -> anyhow::Result<()> {
    self.mutations += 1;
    if self.mutations > self.limits.max_mutations {
      bail!("WAF mutation budget exceeded");
    }
    Ok(())
  }
}

#[derive(Clone, Copy)]
pub(super) struct EvalContext<'a> {
  pub(super) phase: WafPhase,
  pub(super) mode: WafMode,
  pub(super) rule_name: &'a str,
  pub(super) rule_id: Option<&'a str>,
  pub(super) rule_tags: &'a [String],
  pub(super) request: WafRequestInput<'a>,
  pub(super) response: Option<WafResponseInput<'a>>,
  pub(super) stream: Option<WafStreamInput<'a>>,
  pub(super) person_proof: &'a PersonProofRequestStatus,
  pub(super) pattern_sets: &'a HashMap<String, CompiledPatternSet>,
  pub(super) regex_cache: Option<&'a CompiledRegexCache>,
  pub(super) locals: &'a [(&'a str, &'a Value)],
  pub(super) limits: &'a WafLimits,
  pub(super) duplicate_metadata_policy: WafDuplicateMetadataPolicy,
  pub(super) body_text_caches: &'a BodyTextCaches,
}

impl Expr {
  pub(super) fn eval(
    &self,
    ctx: &EvalContext<'_>,
    tx: &mut TransactionBudget,
  ) -> anyhow::Result<Value> {
    self.eval_verified(self.verified_root()?, ctx, tx)
  }

  pub(super) fn eval_verified(
    &self,
    expression: &VerifiedExpression,
    ctx: &EvalContext<'_>,
    tx: &mut TransactionBudget,
  ) -> anyhow::Result<Value> {
    tx.step()?;
    match expression.kind() {
      VerifiedExprKindRef::Null => Ok(Value::Null),
      VerifiedExprKindRef::Bool(value) => Ok(Value::Bool(value)),
      VerifiedExprKindRef::Int(value) => Ok(Value::Int(value)),
      VerifiedExprKindRef::Float(_) => bail!("OxiRule V1 does not support float values"),
      VerifiedExprKindRef::String(value) => Ok(Value::String(value.to_string())),
      VerifiedExprKindRef::Array(_) => bail!("OxiRule V1 does not support array values"),
      VerifiedExprKindRef::Identifier(name) => eval_ident(name, ctx),
      VerifiedExprKindRef::Member { receiver, name } => {
        let value = self.eval_verified(receiver, ctx, tx)?;
        eval_member(value, name, ctx)
      }
      VerifiedExprKindRef::FunctionCall { name, .. } => {
        bail!("unknown OxiRule function {name}")
      }
      VerifiedExprKindRef::ExpressionFunctionCall {
        params, args, body, ..
      } => {
        let values = args
          .iter()
          .map(|arg| self.eval_verified(arg, ctx, tx))
          .collect::<anyhow::Result<Vec<_>>>()?;
        let locals = params
          .iter()
          .zip(values.iter())
          .map(|(param, value)| (param.as_str(), value))
          .collect::<Vec<_>>();
        let child_ctx = EvalContext {
          locals: &locals,
          ..*ctx
        };
        self.eval_verified(body, &child_ctx, tx)
      }
      VerifiedExprKindRef::MethodCall {
        receiver,
        name,
        args,
      } => {
        let value = self.eval_verified(receiver, ctx, tx)?;
        let regex_args = CachedRegexArgs::for_verified_args(args, ctx.regex_cache);
        let values = args
          .iter()
          .map(|arg| self.eval_verified(arg, ctx, tx))
          .collect::<anyhow::Result<Vec<_>>>()?;
        eval_call(value, name, &values, ctx, tx, regex_args)
      }
      VerifiedExprKindRef::Unary { op, expr } => match op {
        ForgeUnaryOp::Not => Ok(Value::Bool(!self.eval_verified(expr, ctx, tx)?.as_bool()?)),
        ForgeUnaryOp::Neg => bail!("OxiRule V1 does not support unary numeric negation"),
      },
      VerifiedExprKindRef::Binary { left, op, right } => {
        eval_verified_binary(self, left, op, right, ctx, tx)
      }
    }
  }
}

pub(super) fn eval_verified_binary(
  owner: &Expr,
  left: &VerifiedExpression,
  op: ForgeBinaryOp,
  right: &VerifiedExpression,
  ctx: &EvalContext<'_>,
  tx: &mut TransactionBudget,
) -> anyhow::Result<Value> {
  match op {
    ForgeBinaryOp::And => {
      let left_value = owner.eval_verified(left, ctx, tx)?.as_bool()?;
      if !left_value {
        return Ok(Value::Bool(false));
      }
      Ok(Value::Bool(owner.eval_verified(right, ctx, tx)?.as_bool()?))
    }
    ForgeBinaryOp::Or => {
      let left_value = owner.eval_verified(left, ctx, tx)?.as_bool()?;
      if left_value {
        return Ok(Value::Bool(true));
      }
      Ok(Value::Bool(owner.eval_verified(right, ctx, tx)?.as_bool()?))
    }
    ForgeBinaryOp::Add => {
      let left_value = owner.eval_verified(left, ctx, tx)?;
      let right_value = owner.eval_verified(right, ctx, tx)?;
      Ok(Value::String(format!(
        "{}{}",
        left_value.as_string()?,
        right_value.as_string()?
      )))
    }
    ForgeBinaryOp::Eq | ForgeBinaryOp::Ne => {
      let left_value = owner.eval_verified(left, ctx, tx)?;
      let right_value = owner.eval_verified(right, ctx, tx)?;
      let equal = values_equal(&left_value, &right_value)?;
      Ok(Value::Bool(matches!(op, ForgeBinaryOp::Eq) == equal))
    }
    ForgeBinaryOp::Lt | ForgeBinaryOp::Le | ForgeBinaryOp::Gt | ForgeBinaryOp::Ge => {
      let left_value = owner.eval_verified(left, ctx, tx)?;
      let right_value = owner.eval_verified(right, ctx, tx)?;
      let result = match (&left_value, &right_value) {
        (Value::Int(left), Value::Int(right)) => match op {
          ForgeBinaryOp::Lt => left < right,
          ForgeBinaryOp::Le => left <= right,
          ForgeBinaryOp::Gt => left > right,
          ForgeBinaryOp::Ge => left >= right,
          _ => unreachable!(),
        },
        (Value::String(left), Value::String(right)) => match op {
          ForgeBinaryOp::Lt => left < right,
          ForgeBinaryOp::Le => left <= right,
          ForgeBinaryOp::Gt => left > right,
          ForgeBinaryOp::Ge => left >= right,
          _ => unreachable!(),
        },
        _ => bail!("ordered comparison requires matching Int or String values"),
      };
      Ok(Value::Bool(result))
    }
    ForgeBinaryOp::Sub | ForgeBinaryOp::Mul | ForgeBinaryOp::Div | ForgeBinaryOp::Rem => {
      bail!("OxiRule V1 does not support operator {}", op.as_str())
    }
  }
}
