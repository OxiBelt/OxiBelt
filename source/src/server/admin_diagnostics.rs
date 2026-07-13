//! Admin diagnostics endpoints.
//! Diagnostics are scoped and redacted before leaving the control plane.

use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;

use crate::admin_audit::AdminAuditHandle;
use crate::diagnostics::{DoctorOptions, ExternalProbeKind};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_json;
use super::admin_control::AdminControlHandle;
use super::admin_operations;

#[derive(Debug, Clone, Deserialize)]
struct AdminPreflightRequest {
  #[serde(default = "default_config_format")]
  format: String,
  config: String,
  #[serde(default)]
  external_probes: Vec<ExternalProbeKind>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminSupportBundleRequest {
  #[serde(default)]
  redact: bool,
  #[serde(default)]
  external_probes: Vec<ExternalProbeKind>,
}

pub(super) async fn admin_diagnostics_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if !matches!(
    path,
    "/admin/v1/diagnostics/preflight"
      | "/admin/v1/diagnostics/support-bundle"
      | "/admin/v1/runtime/snapshot"
      | "/admin/v1/runtime/introspection"
  ) {
    return None;
  }

  match (method, path) {
    (&::http::Method::GET, "/admin/v1/diagnostics/preflight") => {
      let respond_async = admin_operations::prefer_respond_async(&request);
      let request_id = AdminAuditHandle::from_request(&request)
        .map(|audit| audit.request_id())
        .unwrap_or_else(|| "unknown".to_string());
      if !authorization.is_allowed("diagnostics:ReadPreflight", "preflight/current") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let options = match preflight_options(&request) {
        Ok(options) => options,
        Err(response) => return Some(*response),
      }
      .with_secret_env_probes();
      if let Some(response) = ensure_probe_permissions(authorization, &options) {
        return Some(response);
      }
      let config = state.snapshot().config.clone();
      if let Some(response) = ensure_probe_target_permissions(authorization, &config, &options) {
        return Some(response);
      }
      if respond_async {
        return Some(
          match operations
            .enqueue(
              admin_operations::AdminOperationKind::DiagnosticsPreflight,
              authorization.actor,
              request_id,
              move |context| async move {
                context.ensure_not_cancelled()?;
                context.progress("diagnosing", None, None).await;
                let report = crate::diagnostics::diagnose_config(config, &options).await;
                context.ensure_not_cancelled()?;
                admin_operations::value_result(report)
              },
            )
            .await
          {
            Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
            Err(error) => admin_operations::enqueue_error_response(error),
          },
        );
      }
      let report = crate::diagnostics::diagnose_config(config, &options).await;
      Some(json_response(StatusCode::OK, &report))
    }
    (&::http::Method::POST, "/admin/v1/diagnostics/preflight") => {
      let respond_async = admin_operations::prefer_respond_async(&request);
      let request_id = AdminAuditHandle::from_request(&request)
        .map(|audit| audit.request_id())
        .unwrap_or_else(|| "unknown".to_string());
      if !authorization.is_allowed("diagnostics:RunPreflight", "preflight/candidate") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let body = match collect_admin_json::<AdminPreflightRequest>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      if body.format != "toml" {
        return Some(text_response(
          StatusCode::BAD_REQUEST,
          "unsupported config format",
        ));
      }
      let options = DoctorOptions {
        external_probes: body.external_probes,
        allow_secret_env_probes: false,
      };
      if let Some(response) = ensure_probe_permissions(authorization, &options) {
        return Some(response);
      }
      let active = state.snapshot();
      let config = match crate::diagnostics::load_admin_inline_config(&body.config, &active.config)
      {
        Ok(config) => config,
        Err(report) => return Some(json_response(StatusCode::OK, &report)),
      };
      if let Err(report) = crate::diagnostics::validate_config_for_diagnostics(&config) {
        return Some(json_response(StatusCode::OK, &report));
      }
      if let Some(response) = ensure_probe_target_permissions(authorization, &config, &options) {
        return Some(response);
      }
      if respond_async {
        return Some(
          match operations
            .enqueue(
              admin_operations::AdminOperationKind::DiagnosticsPreflight,
              authorization.actor,
              request_id,
              move |context| async move {
                context.ensure_not_cancelled()?;
                context.progress("diagnosing", None, None).await;
                let report = crate::diagnostics::diagnose_config(config, &options).await;
                context.ensure_not_cancelled()?;
                admin_operations::value_result(report)
              },
            )
            .await
          {
            Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
            Err(error) => admin_operations::enqueue_error_response(error),
          },
        );
      }
      let report = crate::diagnostics::diagnose_config(config, &options).await;
      Some(json_response(StatusCode::OK, &report))
    }
    (&::http::Method::GET, "/admin/v1/diagnostics/support-bundle") => {
      let respond_async = admin_operations::prefer_respond_async(&request);
      let request_id = AdminAuditHandle::from_request(&request)
        .map(|audit| audit.request_id())
        .unwrap_or_else(|| "unknown".to_string());
      if !authorization.is_allowed("diagnostics:ReadSupportBundle", "support-bundle/current") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let options = match support_bundle_options(&request) {
        Ok(options) => options,
        Err(response) => return Some(*response),
      }
      .with_secret_env_probes();
      if let Some(response) = ensure_probe_permissions(authorization, &options) {
        return Some(response);
      }
      let active = state.snapshot();
      if let Some(response) =
        ensure_probe_target_permissions(authorization, &active.config, &options)
      {
        return Some(response);
      }
      if respond_async {
        return Some(
          match operations
            .enqueue(
              admin_operations::AdminOperationKind::SupportBundle,
              authorization.actor,
              request_id,
              move |context| async move {
                context.ensure_not_cancelled()?;
                context.progress("collecting", None, None).await;
                let status =
                  append_operational_profile_status(admin_control.status().await, &active.config);
                let effective = admin_control
                  .effective_config()
                  .await
                  .map(|(_, _, config)| config);
                let bundle = crate::diagnostics::build_support_bundle(
                  active.as_ref(),
                  status,
                  effective,
                  &options,
                )
                .await;
                context.ensure_not_cancelled()?;
                admin_operations::value_result(bundle)
              },
            )
            .await
          {
            Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
            Err(error) => admin_operations::enqueue_error_response(error),
          },
        );
      }
      let status = append_operational_profile_status(admin_control.status().await, &active.config);
      let effective = admin_control
        .effective_config()
        .await
        .map(|(_, _, config)| config);
      let bundle =
        crate::diagnostics::build_support_bundle(active.as_ref(), status, effective, &options)
          .await;
      Some(json_response(StatusCode::OK, &bundle))
    }
    (&::http::Method::GET, "/admin/v1/runtime/snapshot") => {
      if !authorization.is_allowed("runtime:ReadSnapshot", "snapshot/current") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      if let Err(response) = require_redact(&request) {
        return Some(*response);
      }
      let active = state.snapshot();
      let snapshot = crate::diagnostics::build_runtime_snapshot(active.as_ref());
      Some(json_response(StatusCode::OK, &snapshot))
    }
    (&::http::Method::GET, "/admin/v1/runtime/introspection") => {
      if !authorization.is_allowed("runtime:ReadIntrospection", "introspection/current") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      if let Err(response) = require_redact(&request) {
        return Some(*response);
      }
      let active = state.snapshot();
      let introspection =
        crate::runtime_introspection::build_runtime_introspection(active.as_ref());
      Some(json_response(StatusCode::OK, &introspection))
    }
    _ => Some(text_response(
      StatusCode::METHOD_NOT_ALLOWED,
      "method not allowed",
    )),
  }
}

pub(in crate::server) async fn enqueue_diagnostics_operation(
  kind: admin_operations::AdminOperationKind,
  request: serde_json::Value,
  state: AppHandle,
  admin_control: AdminControlHandle,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
) -> Response<ProxyBody> {
  match kind {
    admin_operations::AdminOperationKind::DiagnosticsPreflight => {
      enqueue_preflight_operation(request, state, operations, authorization, request_id).await
    }
    admin_operations::AdminOperationKind::SupportBundle => {
      enqueue_support_bundle_operation(
        request,
        state,
        admin_control,
        operations,
        authorization,
        request_id,
      )
      .await
    }
    _ => text_response(
      StatusCode::BAD_REQUEST,
      "unsupported diagnostics operation kind",
    ),
  }
}

async fn enqueue_preflight_operation(
  request: serde_json::Value,
  state: AppHandle,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
) -> Response<ProxyBody> {
  let body = match serde_json::from_value::<AdminPreflightRequest>(request) {
    Ok(body) => body,
    Err(_) => {
      return text_response(
        StatusCode::BAD_REQUEST,
        "invalid diagnostics_preflight request",
      );
    }
  };
  if !authorization.is_allowed("diagnostics:RunPreflight", "preflight/candidate") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if body.format != "toml" {
    return text_response(StatusCode::BAD_REQUEST, "unsupported config format");
  }
  let options = DoctorOptions {
    external_probes: body.external_probes,
    allow_secret_env_probes: false,
  };
  if let Some(response) = ensure_probe_permissions(authorization, &options) {
    return response;
  }
  let active = state.snapshot();
  let config = match crate::diagnostics::load_admin_inline_config(&body.config, &active.config) {
    Ok(config) => config,
    Err(report) => {
      return enqueue_completed_report(
        operations,
        admin_operations::AdminOperationKind::DiagnosticsPreflight,
        authorization,
        request_id,
        report,
      )
      .await;
    }
  };
  if let Err(report) = crate::diagnostics::validate_config_for_diagnostics(&config) {
    return enqueue_completed_report(
      operations,
      admin_operations::AdminOperationKind::DiagnosticsPreflight,
      authorization,
      request_id,
      report,
    )
    .await;
  }
  if let Some(response) = ensure_probe_target_permissions(authorization, &config, &options) {
    return response;
  }
  match operations
    .enqueue(
      admin_operations::AdminOperationKind::DiagnosticsPreflight,
      authorization.actor,
      request_id,
      move |context| async move {
        context.ensure_not_cancelled()?;
        context.progress("diagnosing", None, None).await;
        let report = crate::diagnostics::diagnose_config(config, &options).await;
        context.ensure_not_cancelled()?;
        admin_operations::value_result(report)
      },
    )
    .await
  {
    Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
    Err(error) => admin_operations::enqueue_error_response(error),
  }
}

async fn enqueue_support_bundle_operation(
  request: serde_json::Value,
  state: AppHandle,
  admin_control: AdminControlHandle,
  operations: admin_operations::AdminOperationRuntime,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
) -> Response<ProxyBody> {
  let body = if request.is_null() {
    AdminSupportBundleRequest::default()
  } else {
    match serde_json::from_value::<AdminSupportBundleRequest>(request) {
      Ok(body) => body,
      Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid support_bundle request"),
    }
  };
  if !body.redact {
    return text_response(StatusCode::BAD_REQUEST, "redact=true is required");
  }
  if !authorization.is_allowed("diagnostics:ReadSupportBundle", "support-bundle/current") {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  let options = DoctorOptions {
    external_probes: body.external_probes,
    allow_secret_env_probes: true,
  };
  if let Some(response) = ensure_probe_permissions(authorization, &options) {
    return response;
  }
  let active = state.snapshot();
  if let Some(response) = ensure_probe_target_permissions(authorization, &active.config, &options) {
    return response;
  }
  match operations
    .enqueue(
      admin_operations::AdminOperationKind::SupportBundle,
      authorization.actor,
      request_id,
      move |context| async move {
        context.ensure_not_cancelled()?;
        context.progress("collecting", None, None).await;
        let status =
          append_operational_profile_status(admin_control.status().await, &active.config);
        let effective = admin_control
          .effective_config()
          .await
          .map(|(_, _, config)| config);
        let bundle =
          crate::diagnostics::build_support_bundle(active.as_ref(), status, effective, &options)
            .await;
        context.ensure_not_cancelled()?;
        admin_operations::value_result(bundle)
      },
    )
    .await
  {
    Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
    Err(error) => admin_operations::enqueue_error_response(error),
  }
}

fn append_operational_profile_status(
  mut status: serde_json::Value,
  config: &crate::config::Config,
) -> serde_json::Value {
  let Some(profile) = config.operational_profile.as_ref() else {
    return status;
  };
  if let Some(status) = status.as_object_mut() {
    status.insert(
      "operational_profile".to_string(),
      json!({ "name": profile.name(), "version": profile.version() }),
    );
  }
  status
}

async fn enqueue_completed_report<T>(
  operations: admin_operations::AdminOperationRuntime,
  kind: admin_operations::AdminOperationKind,
  authorization: &AdminAuthorization<'_>,
  request_id: String,
  report: T,
) -> Response<ProxyBody>
where
  T: serde::Serialize + Send + 'static,
{
  match operations
    .enqueue(kind, authorization.actor, request_id, move |_| async move {
      admin_operations::value_result(report)
    })
    .await
  {
    Ok(snapshot) => admin_operations::accepted_operation_response(&snapshot),
    Err(error) => admin_operations::enqueue_error_response(error),
  }
}

fn ensure_probe_permissions(
  authorization: &AdminAuthorization<'_>,
  options: &DoctorOptions,
) -> Option<Response<ProxyBody>> {
  for probe in options.expanded_external_probes() {
    let resource = format!("probe/{}", probe.as_str());
    if !authorization.is_allowed("diagnostics:RunProbe", &resource) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
  }
  None
}

fn ensure_probe_target_permissions(
  authorization: &AdminAuthorization<'_>,
  config: &crate::config::Config,
  options: &DoctorOptions,
) -> Option<Response<ProxyBody>> {
  for resource in crate::diagnostics::external_probe_target_resources(config, options) {
    if !authorization.is_allowed("diagnostics:RunProbe", &resource) {
      return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
    }
  }
  None
}

fn support_bundle_options(
  request: &hyper::Request<Incoming>,
) -> Result<DoctorOptions, Box<Response<ProxyBody>>> {
  require_redact(request)?;
  external_probe_options(request)
}

fn preflight_options(
  request: &hyper::Request<Incoming>,
) -> Result<DoctorOptions, Box<Response<ProxyBody>>> {
  external_probe_options(request)
}

fn external_probe_options(
  request: &hyper::Request<Incoming>,
) -> Result<DoctorOptions, Box<Response<ProxyBody>>> {
  let mut external_probes = Vec::new();
  for (key, value) in query_pairs(request) {
    if key == "external_probe" {
      match value.parse::<ExternalProbeKind>() {
        Ok(probe) => external_probes.push(probe),
        Err(error) => {
          return Err(Box::new(text_response(
            StatusCode::BAD_REQUEST,
            &error.to_string(),
          )));
        }
      }
    }
  }
  Ok(DoctorOptions {
    external_probes,
    allow_secret_env_probes: false,
  })
}

fn require_redact(request: &hyper::Request<Incoming>) -> Result<(), Box<Response<ProxyBody>>> {
  let redact = query_pairs(request)
    .into_iter()
    .filter(|(key, _)| key == "redact")
    .map(|(_, value)| value)
    .next_back();
  match redact.as_deref() {
    Some("true") => Ok(()),
    _ => Err(Box::new(text_response(
      StatusCode::BAD_REQUEST,
      "redact=true is required",
    ))),
  }
}

fn query_pairs(request: &hyper::Request<Incoming>) -> Vec<(String, String)> {
  url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
    .into_owned()
    .collect()
}

fn default_config_format() -> String {
  "toml".to_string()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::{IpmPolicyConfig, IpmPolicyEffect, IpmPolicyStatementConfig};
  use crate::ipm::{IpmActor, IpmRequestContext, IpmRuntime};
  use crate::server::admin_auth::AdminAuthorization;

  fn authorization(actions: &[&str], resources: &[&str]) -> (IpmActor, IpmRuntime) {
    let actor = IpmActor {
      name: "diagnostics-token".to_string(),
      principal: "diagnostics".to_string(),
      subject: "diagnostics@example.com".to_string(),
      groups: Vec::new(),
    };
    let policy = IpmPolicyConfig {
      name: "diagnostics".to_string(),
      version: "2026-05-23".to_string(),
      statements: vec![IpmPolicyStatementConfig {
        effect: IpmPolicyEffect::Allow,
        actions: actions.iter().map(|value| (*value).to_string()).collect(),
        resources: resources.iter().map(|value| (*value).to_string()).collect(),
        conditions: Vec::new(),
      }],
    };
    let ipm = IpmRuntime::test_with_actor_policy("oxibelt", actor.clone(), policy);
    (actor, ipm)
  }

  #[test]
  fn external_probe_requires_run_probe_permission() {
    let (actor, ipm) = authorization(
      &["diagnostics:RunPreflight"],
      &["oxibelt:oxibelt:diagnostics:*"],
    );
    let context = IpmRequestContext::default();
    let auth = AdminAuthorization::new(&actor, &ipm, &context);
    let options = DoctorOptions {
      external_probes: vec![ExternalProbeKind::SharedState],
      allow_secret_env_probes: false,
    };

    assert!(ensure_probe_permissions(&auth, &options).is_some());

    let (actor, ipm) = authorization(
      &["diagnostics:RunProbe"],
      &["oxibelt:oxibelt:diagnostics:probe/shared_state"],
    );
    let auth = AdminAuthorization::new(&actor, &ipm, &context);
    assert!(ensure_probe_permissions(&auth, &options).is_none());
  }

  #[test]
  fn all_external_probes_require_each_coarse_permission() {
    let context = IpmRequestContext::default();
    let options = DoctorOptions {
      external_probes: vec![ExternalProbeKind::All],
      allow_secret_env_probes: false,
    };

    let (actor, ipm) = authorization(
      &["diagnostics:RunProbe"],
      &["oxibelt:oxibelt:diagnostics:probe/shared_state"],
    );
    let auth = AdminAuthorization::new(&actor, &ipm, &context);
    assert!(ensure_probe_permissions(&auth, &options).is_some());

    let (actor, ipm) = authorization(
      &["diagnostics:RunProbe"],
      &[
        "oxibelt:oxibelt:diagnostics:probe/shared_state",
        "oxibelt:oxibelt:diagnostics:probe/ipm_store",
        "oxibelt:oxibelt:diagnostics:probe/remote_signer",
        "oxibelt:oxibelt:diagnostics:probe/upstream",
      ],
    );
    let auth = AdminAuthorization::new(&actor, &ipm, &context);
    assert!(ensure_probe_permissions(&auth, &options).is_none());
  }
}
