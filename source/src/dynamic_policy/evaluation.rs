//! Request-time dynamic-policy evaluation.

use tracing::info;

use crate::config::DynamicPolicyConfig;
use crate::limits::LimitState;
use crate::metrics::Metrics;

use super::{
  DynamicPolicyAction, DynamicPolicyMode, DynamicPolicyOutcome, DynamicPolicyRequest,
  DynamicPolicyRuntime, DynamicPolicySnapshot, DynamicPolicyTerminal,
};

impl DynamicPolicyRuntime {
  pub fn evaluate(
    &self,
    request: DynamicPolicyRequest<'_>,
    limits: &LimitState,
  ) -> DynamicPolicyOutcome {
    let Some(inner) = &self.inner else {
      return DynamicPolicyOutcome::default();
    };
    let snapshot = inner.snapshot();
    evaluate_snapshot(
      &inner.config,
      inner.metrics.as_ref(),
      snapshot.as_ref(),
      request,
      limits,
    )
  }

  /// Evaluates a dynamic policy without synchronously touching shared state.
  ///
  /// The rate-limit action may use the configured shared-state backend, so
  /// request handlers must use this variant. The synchronous variant is kept
  /// for local-only callers and tests, where it fails closed if a shared rate
  /// limiter is configured.
  pub async fn evaluate_async(
    &self,
    request: DynamicPolicyRequest<'_>,
    limits: &LimitState,
  ) -> DynamicPolicyOutcome {
    let Some(inner) = &self.inner else {
      return DynamicPolicyOutcome::default();
    };
    let snapshot = inner.snapshot();
    evaluate_snapshot_async(
      &inner.config,
      inner.metrics.as_ref(),
      snapshot.as_ref(),
      request,
      limits,
    )
    .await
  }
}

pub(super) fn evaluate_snapshot(
  config: &DynamicPolicyConfig,
  metrics: &Metrics,
  snapshot: &DynamicPolicySnapshot,
  request: DynamicPolicyRequest<'_>,
  limits: &LimitState,
) -> DynamicPolicyOutcome {
  let request_path = if config.matching.normalize_path {
    crate::waf::normalization::normalize_path(request.path)
  } else {
    request.path.to_string()
  };

  let mut dry_run_context = None;
  let mut selected = None;
  for policy in snapshot.policies.iter() {
    if !policy.matches(config, &request, &request_path) {
      continue;
    }
    metrics.record_dynamic_policy_match();
    if policy.mode == DynamicPolicyMode::DryRun {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = policy.action.as_str(),
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy dry-run matched request"
      );
      dry_run_context.get_or_insert_with(|| policy.context());
      continue;
    }
    if selected.is_none_or(|current| policy.precedes(current)) {
      selected = Some(policy);
    }
  }

  let Some(policy) = selected else {
    return dry_run_context
      .map(|context| DynamicPolicyOutcome {
        context,
        terminal: None,
      })
      .unwrap_or_default();
  };
  let context = policy.context();
  match policy.action {
    DynamicPolicyAction::Allow => {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "allow",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy allowed request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: None,
      }
    }
    DynamicPolicyAction::Challenge => {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "challenge",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy challenged request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::Challenge {
          status: policy.status,
        }),
      }
    }
    DynamicPolicyAction::Reject => {
      metrics.record_dynamic_policy_reject();
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "reject",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy rejected request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::Text {
          status: policy.status,
          body: policy.body.clone(),
        }),
      }
    }
    DynamicPolicyAction::SilentClose => {
      metrics.record_dynamic_policy_reject();
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "silent_close",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy silently closed request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::SilentClose),
      }
    }
    DynamicPolicyAction::RateLimit => {
      let bucket = policy.bucket_name(request.route_name);
      let status = limits.check_direct_rate_limit_local(
        &bucket,
        policy.rate.as_deref().unwrap_or("1r/s"),
        policy.burst.unwrap_or(1),
        policy.status.as_u16(),
      );
      rate_limit_outcome(policy, request, metrics, context, status)
    }
  }
}

async fn evaluate_snapshot_async(
  config: &DynamicPolicyConfig,
  metrics: &Metrics,
  snapshot: &DynamicPolicySnapshot,
  request: DynamicPolicyRequest<'_>,
  limits: &LimitState,
) -> DynamicPolicyOutcome {
  let request_path = if config.matching.normalize_path {
    crate::waf::normalization::normalize_path(request.path)
  } else {
    request.path.to_string()
  };

  let mut dry_run_context = None;
  let mut selected = None;
  for policy in snapshot.policies.iter() {
    if !policy.matches(config, &request, &request_path) {
      continue;
    }
    metrics.record_dynamic_policy_match();
    if policy.mode == DynamicPolicyMode::DryRun {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = policy.action.as_str(),
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy dry-run matched request"
      );
      dry_run_context.get_or_insert_with(|| policy.context());
      continue;
    }
    if selected.is_none_or(|current| policy.precedes(current)) {
      selected = Some(policy);
    }
  }

  let Some(policy) = selected else {
    return dry_run_context
      .map(|context| DynamicPolicyOutcome {
        context,
        terminal: None,
      })
      .unwrap_or_default();
  };
  let context = policy.context();
  match policy.action {
    DynamicPolicyAction::Allow => {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "allow",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy allowed request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: None,
      }
    }
    DynamicPolicyAction::Challenge => {
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "challenge",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy challenged request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::Challenge {
          status: policy.status,
        }),
      }
    }
    DynamicPolicyAction::Reject => {
      metrics.record_dynamic_policy_reject();
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "reject",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy rejected request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::Text {
          status: policy.status,
          body: policy.body.clone(),
        }),
      }
    }
    DynamicPolicyAction::SilentClose => {
      metrics.record_dynamic_policy_reject();
      info!(
        policy_id = policy.id,
        policy_name = %policy.name,
        action = "silent_close",
        route = request.route_name,
        client_ip = %request.client_ip,
        "dynamic policy silently closed request"
      );
      DynamicPolicyOutcome {
        context,
        terminal: Some(DynamicPolicyTerminal::SilentClose),
      }
    }
    DynamicPolicyAction::RateLimit => {
      let bucket = policy.bucket_name(request.route_name);
      let status = limits
        .check_direct_rate_limit_async(
          &bucket,
          policy.rate.as_deref().unwrap_or("1r/s"),
          policy.burst.unwrap_or(1),
          policy.status.as_u16(),
        )
        .await;
      rate_limit_outcome(policy, request, metrics, context, status)
    }
  }
}

fn rate_limit_outcome(
  policy: &super::DynamicPolicy,
  request: DynamicPolicyRequest<'_>,
  metrics: &Metrics,
  context: super::DynamicPolicyContext,
  status: Option<http::StatusCode>,
) -> DynamicPolicyOutcome {
  if let Some(status) = status {
    metrics.record_dynamic_policy_rate_limit_denied();
    info!(
      policy_id = policy.id,
      policy_name = %policy.name,
      action = "rate_limit",
      route = request.route_name,
      client_ip = %request.client_ip,
      "dynamic policy rate limit denied request"
    );
    return DynamicPolicyOutcome {
      context,
      terminal: Some(DynamicPolicyTerminal::Text {
        status,
        body: policy.body.clone(),
      }),
    };
  }
  DynamicPolicyOutcome {
    context,
    terminal: None,
  }
}
