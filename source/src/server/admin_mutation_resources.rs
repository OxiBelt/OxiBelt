//! Typed high-risk Admin mutation resources.
//!
//! Replay admission happens before this module is called. This boundary still
//! enforces resource authorization, `If-Match`, strict request shapes, and
//! reference pinning before it asks a runtime subsystem to apply a change.

use ::http::{HeaderMap, Method, Response, StatusCode, header};
use bytes::Bytes;
use hyper::body::Body;
use serde::Deserialize;
use serde_json::json;

use crate::config::IpmBreakGlassAccessMode;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::secret_activation::{SecretReferenceField, SecretReferenceUpdateRequest};
use crate::state::AppHandle;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::{
  collect_admin_json_body_with_limit, collect_admin_request_bytes, decode_admin_json,
};
use super::admin_control::AdminControlHandle;
use super::{admin_error, admin_resource};

mod validation;
use validation::*;
#[cfg(test)]
mod tests;

const MUTATION_RESOURCE_BODY_LIMIT: usize = 16 * 1024;
const BREAK_GLASS_SCOPE: &str = "admin";

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum KeyRotationTarget {
  DownstreamTlsDefault,
  DownstreamTlsSni,
}

impl KeyRotationTarget {
  const fn as_str(self) -> &'static str {
    match self {
      Self::DownstreamTlsDefault => "downstream_tls_default",
      Self::DownstreamTlsSni => "downstream_tls_sni",
    }
  }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRotationRequest {
  target: KeyRotationTarget,
  #[serde(default)]
  name: Option<String>,
  reference: String,
  sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BreakGlassActivationRequest {
  ttl_seconds: u64,
  #[serde(default)]
  reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

pub(super) fn handles(method: &Method, path: &str) -> bool {
  matches!(
    (method, path),
    (&Method::POST, "/admin/v1/keys/rotate")
      | (&Method::POST, "/admin/v1/config/secret-references/update")
      | (&Method::GET, "/admin/v1/break-glass/activations/self")
      | (&Method::POST, "/admin/v1/break-glass/activations")
  ) || (*method == Method::POST && break_glass_revoke_id(path).is_some())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn response<B>(
  request: hyper::Request<B>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  authorization: &AdminAuthorization<'_>,
  method: &Method,
  path: &str,
  mutation_request_id: Option<&str>,
  mutation_logical_revision: Option<&str>,
  authenticated_with_break_glass: bool,
) -> Option<Response<ProxyBody>>
where
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  match (method, path) {
    (&Method::POST, "/admin/v1/keys/rotate") => {
      Some(rotate_key_response(request, state, admin_control, authorization).await)
    }
    (&Method::POST, "/admin/v1/config/secret-references/update") => Some(
      update_secret_reference_response(
        request,
        admin_control,
        authorization,
        mutation_request_id,
        mutation_logical_revision,
      )
      .await,
    ),
    (&Method::GET, "/admin/v1/break-glass/activations/self") => {
      Some(break_glass_self_response(state, authorization, authenticated_with_break_glass).await)
    }
    (&Method::POST, "/admin/v1/break-glass/activations") => Some(
      create_break_glass_response(
        request,
        state,
        authorization,
        required_mutation_request_id(mutation_request_id),
        authenticated_with_break_glass,
      )
      .await,
    ),
    (&Method::POST, _) => {
      let activation_id = break_glass_revoke_id(path)?;
      Some(
        revoke_break_glass_response(
          request,
          state,
          authorization,
          activation_id,
          authenticated_with_break_glass,
        )
        .await,
      )
    }
    _ => None,
  }
}

async fn rotate_key_response<B>(
  request: hyper::Request<B>,
  state: AppHandle,
  admin_control: AdminControlHandle,
  authorization: &AdminAuthorization<'_>,
) -> Response<ProxyBody>
where
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  let if_match = match required_if_match(request.headers()) {
    Ok(value) => value,
    Err(response) => return response,
  };
  let body = match collect_admin_json_body_with_limit::<KeyRotationRequest, _>(
    request,
    MUTATION_RESOURCE_BODY_LIMIT,
  )
  .await
  {
    Ok(body) => body,
    Err(response) => return response,
  };
  if let Err(message) = validate_key_rotation(&body) {
    return text_response(StatusCode::BAD_REQUEST, message);
  }
  let resource = format!(
    "key/{}/{}",
    body.target.as_str(),
    admin_resource::component(body.name.as_deref().unwrap_or("default"))
  );
  if !authorization.is_allowed("config:RotateKey", &resource) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if let Some(response) = check_config_if_match(&admin_control, &if_match).await {
    return response;
  }

  let snapshot = state.snapshot();
  let key_path = match active_key_path(snapshot.as_ref(), &body) {
    Ok(path) => path,
    Err((status, message)) => return text_response(status, message),
  };
  if let Err(message) = verify_file_digest(&key_path, &body.sha256) {
    return text_response(StatusCode::CONFLICT, &message);
  }
  admin_control
    .reload_downstream_tls(authorization.actor.name.clone(), Some(if_match.to_string()))
    .await
    .into_http()
}

async fn update_secret_reference_response<B>(
  request: hyper::Request<B>,
  admin_control: AdminControlHandle,
  authorization: &AdminAuthorization<'_>,
  mutation_request_id: Option<&str>,
  mutation_logical_revision: Option<&str>,
) -> Response<ProxyBody>
where
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  let mutation_request_id = match mutation_request_id {
    Some(request_id) => request_id.to_string(),
    None => match crate::secret_activation::new_local_request_id() {
      Ok(request_id) => request_id,
      Err(error) => {
        return json_response(
          StatusCode::SERVICE_UNAVAILABLE,
          &json!({
            "error": "secret reference activation failed",
            "code": error.code(),
          }),
        );
      }
    },
  };
  let if_match = match required_if_match(request.headers()) {
    Ok(value) => value,
    Err(response) => return response,
  };
  let body = match collect_admin_json_body_with_limit::<SecretReferenceUpdateRequest, _>(
    request,
    MUTATION_RESOURCE_BODY_LIMIT,
  )
  .await
  {
    Ok(body) => body,
    Err(response) => return response,
  };
  let field = match validate_secret_reference(&body) {
    Ok(field) => field,
    Err(message) => return text_response(StatusCode::BAD_REQUEST, message),
  };
  let resource = format!(
    "secret-reference/{}",
    admin_resource::component(&body.field)
  );
  if !authorization.is_allowed("config:UpdateSecretReference", &resource) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if matches!(field, SecretReferenceField::IpmCredentialBearerTokenEnv(_))
    && !authorization.is_allowed("ipm:UpdateConfig", "config")
  {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if let Some(response) = check_config_if_match(&admin_control, &if_match).await {
    return response;
  }

  admin_control
    .activate_secret_reference(
      authorization.actor.name.clone(),
      Some(if_match),
      mutation_request_id,
      mutation_logical_revision.map(str::to_string),
      None,
      body,
    )
    .await
    .into_http()
}

async fn break_glass_self_response(
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  authenticated_with_break_glass: bool,
) -> Response<ProxyBody> {
  if let Some(response) = require_break_glass_identity(
    state.snapshot().config.ipm.break_glass.access_mode,
    authenticated_with_break_glass,
  ) {
    return response;
  }
  let resource = break_glass_principal_resource(&authorization.actor.principal);
  if !authorization.is_allowed("ipm:GetBreakGlassActivation", &resource) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  let snapshot = state.snapshot();
  let active = match snapshot
    .admin_mutations
    .active_break_glass_activation(&authorization.actor.principal)
    .await
  {
    Ok(active) => active,
    Err(_) => return store_unavailable_response(),
  };
  json_response(
    StatusCode::OK,
    &json!({
      "principal": authorization.actor.principal,
      "active": active.is_some(),
      "activation": active,
      "revision": snapshot.ipm.admin_status().etag,
    }),
  )
}

async fn create_break_glass_response<B>(
  request: hyper::Request<B>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  mutation_request_id: Result<&str, Response<ProxyBody>>,
  authenticated_with_break_glass: bool,
) -> Response<ProxyBody>
where
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  let mutation_request_id = match mutation_request_id {
    Ok(value) => value,
    Err(response) => return response,
  };
  if let Some(response) = require_break_glass_identity(
    state.snapshot().config.ipm.break_glass.access_mode,
    authenticated_with_break_glass,
  ) {
    return response;
  }
  let if_match = match required_if_match(request.headers()) {
    Ok(value) => value,
    Err(response) => return response,
  };
  let body = match collect_admin_json_body_with_limit::<BreakGlassActivationRequest, _>(
    request,
    MUTATION_RESOURCE_BODY_LIMIT,
  )
  .await
  {
    Ok(body) => body,
    Err(response) => return response,
  };
  let maximum_ttl = state
    .snapshot()
    .config
    .ipm
    .break_glass
    .max_activation_seconds;
  if let Err(message) = validate_break_glass_activation(&body, maximum_ttl) {
    return text_response(StatusCode::BAD_REQUEST, message);
  }
  let resource = break_glass_principal_resource(&authorization.actor.principal);
  if !authorization.is_allowed("ipm:ActivateBreakGlass", &resource) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if let Some(response) = check_ipm_if_match(&state, &if_match) {
    return response;
  }

  let snapshot = state.snapshot();
  match snapshot
    .admin_mutations
    .active_break_glass_activation(&authorization.actor.principal)
    .await
  {
    Ok(Some(_)) => {
      return text_response(
        StatusCode::CONFLICT,
        "an active break-glass activation already exists",
      );
    }
    Ok(None) => {}
    Err(_) => return store_unavailable_response(),
  }
  let scopes = [BREAK_GLASS_SCOPE.to_string()];
  let activation = match snapshot
    .admin_mutations
    .create_break_glass_activation(
      mutation_request_id,
      mutation_request_id,
      &authorization.actor.principal,
      &scopes,
      body.ttl_seconds,
      maximum_ttl,
    )
    .await
  {
    Ok(activation) => activation,
    Err(_) => return store_unavailable_response(),
  };
  json_response(
    StatusCode::CREATED,
    &json!({ "ok": true, "activation": activation }),
  )
}

async fn revoke_break_glass_response<B>(
  request: hyper::Request<B>,
  state: AppHandle,
  authorization: &AdminAuthorization<'_>,
  activation_id: &str,
  authenticated_with_break_glass: bool,
) -> Response<ProxyBody>
where
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  if let Some(response) = require_break_glass_identity(
    state.snapshot().config.ipm.break_glass.access_mode,
    authenticated_with_break_glass,
  ) {
    return response;
  }
  if !is_canonical_uuid(activation_id) {
    return text_response(StatusCode::BAD_REQUEST, "invalid activation ID");
  }
  let if_match = match required_if_match(request.headers()) {
    Ok(value) => value,
    Err(response) => return response,
  };
  if let Err(response) = collect_optional_empty_json(request).await {
    return response;
  }
  let resource = format!(
    "break-glass/activation/{}",
    admin_resource::component(activation_id)
  );
  if !authorization.is_allowed("ipm:RevokeBreakGlass", &resource) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if let Some(response) = check_ipm_if_match(&state, &if_match) {
    return response;
  }
  match state
    .snapshot()
    .admin_mutations
    .revoke_break_glass_activation(activation_id, &authorization.actor.principal)
    .await
  {
    Ok(true) => json_response(
      StatusCode::OK,
      &json!({ "ok": true, "activation_id": activation_id }),
    ),
    Ok(false) => text_response(StatusCode::NOT_FOUND, "activation not found"),
    Err(_) => store_unavailable_response(),
  }
}

async fn collect_optional_empty_json<B>(
  request: hyper::Request<B>,
) -> Result<(), Response<ProxyBody>>
where
  B: Body<Data = Bytes>,
  B::Error: std::error::Error + Send + Sync + 'static,
{
  let (parts, bytes) = collect_admin_request_bytes(request, MUTATION_RESOURCE_BODY_LIMIT).await?;
  if bytes.is_empty() {
    return Ok(());
  }
  decode_admin_json::<EmptyRequest>(&parts, &bytes).map(|_| ())
}

#[allow(clippy::result_large_err)]
fn required_if_match(headers: &HeaderMap) -> Result<String, Response<ProxyBody>> {
  let values = headers.get_all(header::IF_MATCH).iter().collect::<Vec<_>>();
  if values.is_empty() {
    return Err(admin_error::error_response_with_details(
      StatusCode::PRECONDITION_REQUIRED,
      "If-Match is required",
      Some(json!({ "header": "If-Match" })),
    ));
  }
  if values.len() != 1 {
    return Err(text_response(
      StatusCode::BAD_REQUEST,
      "If-Match must be supplied exactly once",
    ));
  }
  let value = values[0]
    .to_str()
    .map_err(|_| text_response(StatusCode::BAD_REQUEST, "If-Match is invalid"))?;
  if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
    return Err(text_response(
      StatusCode::BAD_REQUEST,
      "If-Match is invalid",
    ));
  }
  Ok(value.to_string())
}

async fn check_config_if_match(
  control: &AdminControlHandle,
  supplied: &str,
) -> Option<Response<ProxyBody>> {
  let expected = control
    .status()
    .await
    .get("etag")
    .and_then(serde_json::Value::as_str)
    .unwrap_or("")
    .to_string();
  (!constant_time_ascii_eq(supplied.as_bytes(), expected.as_bytes())).then(|| {
    admin_error::error_response_with_details(
      StatusCode::PRECONDITION_FAILED,
      "If-Match does not match the active config revision",
      Some(json!({ "header": "If-Match", "expected": expected })),
    )
  })
}

fn check_ipm_if_match(state: &AppHandle, supplied: &str) -> Option<Response<ProxyBody>> {
  let expected = state.snapshot().ipm.admin_status().etag;
  (!constant_time_ascii_eq(supplied.as_bytes(), expected.as_bytes())).then(|| {
    admin_error::error_response_with_details(
      StatusCode::PRECONDITION_FAILED,
      "If-Match does not match the active IPM generation",
      Some(json!({ "header": "If-Match", "expected": expected })),
    )
  })
}

fn require_break_glass_identity(
  mode: IpmBreakGlassAccessMode,
  authenticated_with_break_glass: bool,
) -> Option<Response<ProxyBody>> {
  if mode != IpmBreakGlassAccessMode::TwoFactorActivation {
    return Some(text_response(
      StatusCode::CONFLICT,
      "two-factor break-glass activation is not configured",
    ));
  }
  (!authenticated_with_break_glass)
    .then(|| text_response(StatusCode::FORBIDDEN, "break-glass credential is required"))
}

#[allow(clippy::result_large_err)]
fn required_mutation_request_id(request_id: Option<&str>) -> Result<&str, Response<ProxyBody>> {
  request_id.ok_or_else(|| {
    text_response(
      StatusCode::INTERNAL_SERVER_ERROR,
      "mutation admission context is unavailable",
    )
  })
}

fn store_unavailable_response() -> Response<ProxyBody> {
  json_response(
    StatusCode::SERVICE_UNAVAILABLE,
    &json!({
      "error": "break-glass activation store is unavailable",
      "code": "mutation_store_unavailable",
    }),
  )
}

fn break_glass_principal_resource(principal: &str) -> String {
  format!(
    "break-glass/principal/{}",
    admin_resource::component(principal)
  )
}

fn break_glass_revoke_id(path: &str) -> Option<&str> {
  path
    .strip_prefix("/admin/v1/break-glass/activations/")?
    .strip_suffix("/revoke")
    .filter(|value| !value.is_empty() && !value.contains('/'))
}

fn is_canonical_uuid(raw: &str) -> bool {
  if raw.len() != 36
    || raw.as_bytes().get(8) != Some(&b'-')
    || raw.as_bytes().get(13) != Some(&b'-')
    || raw.as_bytes().get(18) != Some(&b'-')
    || raw.as_bytes().get(23) != Some(&b'-')
  {
    return false;
  }
  let compact = raw.bytes().filter(|byte| *byte != b'-').collect::<Vec<_>>();
  if compact.len() != 32
    || compact
      .iter()
      .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(byte))
  {
    return false;
  }
  let mut bytes = [0_u8; 16];
  for (index, pair) in compact.chunks_exact(2).enumerate() {
    bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
  }
  let version = bytes[6] >> 4;
  (1..=8).contains(&version) && bytes[8] & 0b1100_0000 == 0b1000_0000 && bytes != [0; 16]
}

const fn hex_nibble(byte: u8) -> u8 {
  match byte {
    b'0'..=b'9' => byte - b'0',
    b'a'..=b'f' => byte - b'a' + 10,
    _ => 0,
  }
}

fn constant_time_ascii_eq(left: &[u8], right: &[u8]) -> bool {
  let mut difference = left.len() ^ right.len();
  let length = left.len().max(right.len());
  for index in 0..length {
    let lhs = left.get(index).copied().unwrap_or(0);
    let rhs = right.get(index).copied().unwrap_or(0);
    difference |= usize::from(lhs ^ rhs);
  }
  difference == 0
}
