//! Query parsing for Admin diagnostics and redacted runtime views.

use ::http::{Response, StatusCode};
use hyper::body::Incoming;

use crate::diagnostics::{DoctorOptions, ExternalProbeKind};
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;

pub(super) fn support_bundle_options(
  request: &hyper::Request<Incoming>,
) -> Result<DoctorOptions, Box<Response<ProxyBody>>> {
  require_redact(request)?;
  external_probe_options(request)
}

pub(super) fn preflight_options(
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

pub(super) fn require_redact(
  request: &hyper::Request<Incoming>,
) -> Result<(), Box<Response<ProxyBody>>> {
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
