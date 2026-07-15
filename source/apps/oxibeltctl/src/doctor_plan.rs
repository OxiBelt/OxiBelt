use std::path::Path;

use anyhow::{Context, bail};
use http::Method;
use serde_json::json;

use crate::cli::DoctorArgs;
use crate::plan::{PermissionHint, RequestPlan, ResponseFilter};

pub(crate) fn plan_doctor(args: &DoctorArgs) -> anyhow::Result<RequestPlan> {
  if args.has_local_source() {
    bail!("local doctor must be handled before building an Admin client");
  }
  match &args.candidate {
    Some(path) => Ok(RequestPlan {
      method: Method::POST,
      endpoint: "/admin/v1/diagnostics/preflight".to_string(),
      body: Some(json!({
        "format": "toml",
        "config": read_text_file(path)?,
        "external_probes": args.external_probes,
      })),
      if_match: None,
      permission: permission("diagnostics:RunPreflight", "preflight/candidate"),
      filter: ResponseFilter::None,
    }),
    None => Ok(RequestPlan {
      method: Method::GET,
      endpoint: preflight_endpoint(&args.external_probes),
      body: None,
      if_match: None,
      permission: permission("diagnostics:ReadPreflight", "preflight/current"),
      filter: ResponseFilter::None,
    }),
  }
}

fn preflight_endpoint(external_probes: &[oxibelt::diagnostics::ExternalProbeKind]) -> String {
  if external_probes.is_empty() {
    return "/admin/v1/diagnostics/preflight".to_string();
  }
  let mut serializer = url::form_urlencoded::Serializer::new(String::new());
  for probe in external_probes {
    serializer.append_pair("external_probe", probe.as_str());
  }
  format!("/admin/v1/diagnostics/preflight?{}", serializer.finish())
}

fn permission(action: &str, resource: &str) -> PermissionHint {
  PermissionHint::new(action, resource)
}

fn read_text_file(path: &Path) -> anyhow::Result<String> {
  std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}
