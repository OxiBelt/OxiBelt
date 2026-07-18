use ::http::{Response, StatusCode};
use hyper::body::Incoming;

use crate::admin_audit::AdminAuditHandle;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppSnapshot;

use crate::server::admin_body::{collect_admin_json, collect_admin_json_with_limit};
use crate::server::{admin, admin_auth::AdminAuthorization, admin_operations};

pub(in crate::server) const OXIRULE_REPLAY_BODY_LIMIT: usize = 4 * 1024 * 1024;

pub(in crate::server) async fn admin_waf_devtools_response(
  request: hyper::Request<Incoming>,
  snapshot: &AppSnapshot,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  match (method, path) {
    (&::http::Method::POST, "/admin/v1/waf/oxirule/check") => {
      let body = match collect_admin_json::<crate::waf::OxiRuleDevtoolsCheckRequest>(request).await
      {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if let Some(response) = authorize_oxirule_check(authorization, &body) {
        return Some(response);
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::check_oxirule(&snapshot.config, body),
      ))
    }
    (&::http::Method::POST, "/admin/v1/waf/oxirule/cost") => {
      let body = match collect_admin_json::<crate::waf::OxiRuleDevtoolsCheckRequest>(request).await
      {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorization.is_allowed(
        "waf:EstimateOxiRuleCost",
        oxirule_check_resource(&body).as_str(),
      ) {
        return Some(super::permission_denied(
          authorization.actor,
          "waf:EstimateOxiRuleCost",
        ));
      }
      if let Some(response) = authorize_oxirule_active_context(
        authorization,
        body.include_active_rules,
        "waf:EstimateOxiRuleCost",
        "oxirule/*",
      ) {
        return Some(response);
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::cost_oxirule(&snapshot.config, body),
      ))
    }
    (&::http::Method::POST, "/admin/v1/waf/oxirule/test") => {
      let body = match collect_admin_json::<crate::waf::OxiRuleDevtoolsEvalRequest>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      let resource = crate::waf::oxirule_rule_resource_name(&body.rule);
      if !authorization.is_allowed("waf:TestOxiRule", &resource) {
        return Some(super::permission_denied(
          authorization.actor,
          "waf:TestOxiRule",
        ));
      }
      if let Some(response) = authorize_oxirule_active_context(
        authorization,
        body.include_active_rules,
        "waf:TestOxiRule",
        "oxirule/*",
      ) {
        return Some(response);
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::test_oxirule(&snapshot.config, body),
      ))
    }
    (&::http::Method::POST, "/admin/v1/waf/oxirule/explain") => {
      let body = match collect_admin_json::<crate::waf::OxiRuleDevtoolsEvalRequest>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      let resource = crate::waf::oxirule_rule_resource_name(&body.rule);
      if !authorization.is_allowed("waf:ExplainOxiRule", &resource) {
        return Some(super::permission_denied(
          authorization.actor,
          "waf:ExplainOxiRule",
        ));
      }
      if let Some(response) = authorize_oxirule_active_context(
        authorization,
        body.include_active_rules,
        "waf:ExplainOxiRule",
        "oxirule/*",
      ) {
        return Some(response);
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::explain_oxirule(&snapshot.config, body),
      ))
    }
    (&::http::Method::POST, "/admin/v1/waf/oxirule/replay") => {
      let respond_async = admin_operations::prefer_respond_async(&request);
      let idempotency_key = if respond_async {
        match admin_operations::idempotency_key(&request) {
          Ok(key) => key,
          Err(response) => return Some(*response),
        }
      } else {
        None
      };
      let request_id = AdminAuditHandle::from_request(&request)
        .map(|audit| audit.request_id())
        .unwrap_or_else(|| "unknown".to_string());
      let body = match collect_admin_json_with_limit::<crate::waf::OxiRuleDevtoolsReplayRequest>(
        request,
        OXIRULE_REPLAY_BODY_LIMIT,
      )
      .await
      {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if let Some(response) = authorize_replay(authorization, &body) {
        return Some(response);
      }
      if respond_async {
        return Some(
          enqueue_replay(
            body,
            snapshot,
            operations,
            authorization,
            request_id,
            idempotency_key,
          )
          .await,
        );
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::replay_oxirule(&snapshot.config, body),
      ))
    }
    (&::http::Method::POST, "/admin/v1/waf/oxirule/analyze") => {
      let body = match collect_admin_json::<crate::waf::OxiRuleAnalyzeRequest>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorization.is_allowed("waf:AnalyzeOxiRuleRisk", "analyze/inline") {
        return Some(super::permission_denied(
          authorization.actor,
          "waf:AnalyzeOxiRuleRisk",
        ));
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::analyze_oxirule(&snapshot.config, body),
      ))
    }
    (&::http::Method::POST, "/admin/v1/waf/oxirule/hardening-plan") => {
      let body = match collect_admin_json::<crate::waf::OxiRuleHardeningPlanRequest>(request).await
      {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorization.is_allowed("waf:PlanOxiRuleHardening", "hardening-plan/inline") {
        return Some(super::permission_denied(
          authorization.actor,
          "waf:PlanOxiRuleHardening",
        ));
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::plan_oxirule_hardening(body),
      ))
    }
    (&::http::Method::GET, "/admin/v1/waf/oxirule/templates") => {
      if !authorization.is_allowed("waf:ListOxiRuleTemplates", "template/*") {
        return Some(super::permission_denied(
          authorization.actor,
          "waf:ListOxiRuleTemplates",
        ));
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::list_oxirule_templates(),
      ))
    }
    (&::http::Method::POST, "/admin/v1/waf/oxirule/templates/render") => {
      let body = match collect_admin_json::<crate::waf::OxiRuleTemplateRenderRequest>(request).await
      {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      let resource = format!("template/{}", body.name);
      if !authorization.is_allowed("waf:RenderOxiRuleTemplate", &resource) {
        return Some(super::permission_denied(
          authorization.actor,
          "waf:RenderOxiRuleTemplate",
        ));
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::render_oxirule_template(body),
      ))
    }
    (&::http::Method::POST, "/admin/v1/waf/oxirule/false-positive") => {
      let body = match collect_admin_json::<crate::waf::OxiRuleFalsePositiveRequest>(request).await
      {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if !authorization.is_allowed("waf:PlanOxiRuleFalsePositive", "false-positive/inline") {
        return Some(super::permission_denied(
          authorization.actor,
          "waf:PlanOxiRuleFalsePositive",
        ));
      }
      Some(admin::json_response(
        StatusCode::OK,
        &crate::waf::plan_false_positive(body),
      ))
    }
    (_, path) if path.starts_with("/admin/v1/waf/oxirule/") => Some(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "method not allowed",
    )),
    _ => None,
  }
}

pub(in crate::server) async fn enqueue_oxirule_replay_operation(
  request: serde_json::Value,
  snapshot: &AppSnapshot,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
  idempotency_key: Option<String>,
) -> Response<ProxyBody> {
  let body = match serde_json::from_value::<crate::waf::OxiRuleDevtoolsReplayRequest>(request) {
    Ok(body) => body,
    Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid oxirule_replay request"),
  };
  if let Some(response) = authorize_replay(authorization, &body) {
    return response;
  }
  enqueue_replay(
    body,
    snapshot,
    operations,
    authorization,
    request_id,
    idempotency_key,
  )
  .await
}

async fn enqueue_replay(
  body: crate::waf::OxiRuleDevtoolsReplayRequest,
  snapshot: &AppSnapshot,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
  idempotency_key: Option<String>,
) -> Response<ProxyBody> {
  let config = snapshot.config.clone();
  let command = serde_json::to_value(&body).unwrap_or(serde_json::Value::Null);
  let resource = crate::waf::oxirule_rule_resource_name(&body.rule).replace("oxirule/", "replay/");
  let submission = durable_submission(command, idempotency_key, resource);
  match operations
    .enqueue_with_submission(
      submission,
      authorization.actor,
      request_id,
      move |context| async move {
        context.ensure_not_cancelled()?;
        let total = body
          .input
          .lines()
          .filter(|line| !line.trim().is_empty())
          .count();
        context
          .progress("replaying", Some(0), Some(total as u64))
          .await;
        context.ensure_not_cancelled()?;
        let report = crate::waf::replay_oxirule(&config, body);
        context.ensure_not_cancelled()?;
        context
          .progress("replaying", Some(total as u64), Some(total as u64))
          .await;
        admin_operations::value_result(report)
      },
    )
    .await
  {
    Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
    Err(error) => admin_operations::enqueue_error_response(error),
  }
}

fn durable_submission(
  command: serde_json::Value,
  idempotency_key: Option<String>,
  resource: String,
) -> admin_operations::AdminOperationSubmission {
  let submission = admin_operations::AdminOperationSubmission::new(
    admin_operations::AdminOperationKind::OxiRuleReplay,
    "waf:ReplayOxiRule",
    Some(resource),
    admin_operations::AdminOperationRecoveryClass::Resumable,
  )
  .with_command(command);
  match idempotency_key {
    Some(key) => submission.with_idempotency_key(key),
    None => submission,
  }
}

pub(in crate::server) fn authorize_oxirule_check(
  authorization: &AdminAuthorization<'_>,
  body: &crate::waf::OxiRuleDevtoolsCheckRequest,
) -> Option<Response<ProxyBody>> {
  if let Some(rule) = &body.rule {
    let resource = crate::waf::oxirule_rule_resource_name(rule);
    if !authorization.is_allowed("waf:CheckOxiRule", &resource) {
      return Some(super::permission_denied(
        authorization.actor,
        "waf:CheckOxiRule",
      ));
    }
  }
  for resource in crate::waf::oxirule_group_resource_names(&body.groups) {
    if !authorization.is_allowed("waf:CheckOxiRuleGroup", &resource) {
      return Some(super::permission_denied(
        authorization.actor,
        "waf:CheckOxiRuleGroup",
      ));
    }
  }
  authorize_oxirule_active_context(
    authorization,
    body.include_active_rules,
    "waf:CheckOxiRule",
    "oxirule/*",
  )
}

fn authorize_replay(
  authorization: &AdminAuthorization<'_>,
  body: &crate::waf::OxiRuleDevtoolsReplayRequest,
) -> Option<Response<ProxyBody>> {
  let resource = crate::waf::oxirule_rule_resource_name(&body.rule).replace("oxirule/", "replay/");
  if !authorization.is_allowed("waf:ReplayOxiRule", &resource) {
    return Some(super::permission_denied(
      authorization.actor,
      "waf:ReplayOxiRule",
    ));
  }
  authorize_oxirule_active_context(
    authorization,
    body.include_active_rules,
    "waf:ReplayOxiRule",
    "replay/*",
  )
}

pub(in crate::server) fn authorize_oxirule_active_context(
  authorization: &AdminAuthorization<'_>,
  include_active_rules: bool,
  action: &str,
  resource: &str,
) -> Option<Response<ProxyBody>> {
  if include_active_rules && !authorization.is_allowed(action, resource) {
    return Some(super::permission_denied(authorization.actor, action));
  }
  None
}

fn oxirule_check_resource(body: &crate::waf::OxiRuleDevtoolsCheckRequest) -> String {
  body
    .rule
    .as_ref()
    .map(crate::waf::oxirule_rule_resource_name)
    .unwrap_or_else(|| "oxirule/inline".to_string())
}
