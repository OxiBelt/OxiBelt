use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;

use crate::diagnostics::{DoctorOptions, ExternalProbeKind};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppHandle;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_json;
use super::admin_control::AdminControlHandle;

#[derive(Debug, Deserialize)]
struct AdminPreflightRequest {
  #[serde(default = "default_config_format")]
  format: String,
  config: String,
  #[serde(default)]
  external_probes: Vec<ExternalProbeKind>,
}

pub(super) async fn admin_diagnostics_response(
  request: hyper::Request<Incoming>,
  state: AppHandle,
  admin_control: AdminControlHandle,
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
      if !authorization.is_allowed("diagnostics:ReadPreflight", "preflight/current") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let config = state.snapshot().config.clone();
      let report = crate::diagnostics::diagnose_config(config, &DoctorOptions::default()).await;
      Some(json_response(StatusCode::OK, &report))
    }
    (&::http::Method::POST, "/admin/v1/diagnostics/preflight") => {
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
      let report = crate::diagnostics::diagnose_config(config, &options).await;
      Some(json_response(StatusCode::OK, &report))
    }
    (&::http::Method::GET, "/admin/v1/diagnostics/support-bundle") => {
      if !authorization.is_allowed("diagnostics:ReadSupportBundle", "support-bundle/current") {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let options = match support_bundle_options(&request) {
        Ok(options) => options,
        Err(response) => return Some(*response),
      };
      if let Some(response) = ensure_probe_permissions(authorization, &options) {
        return Some(response);
      }
      let active = state.snapshot();
      if let Some(response) =
        ensure_probe_target_permissions(authorization, &active.config, &options)
      {
        return Some(response);
      }
      let status = admin_control.status().await;
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
  Ok(DoctorOptions { external_probes })
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
