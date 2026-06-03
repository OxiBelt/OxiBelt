//! Person proof HTTP API handling.
//! Challenge and clearance responses are routed before generic upstream proxying.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Body;
use ring::digest;
use serde_json::{Map, Value};
use tracing::warn;

use crate::control_http::{full_body as control_full_body, uri_from_url};
use crate::dynamic_policy::DynamicPolicyContext;
use crate::state::AppSnapshot;
use crate::waf::{
  PersonProofApiPathRole, PersonProofMode, PersonProofProviderChallenge,
  PersonProofProviderFailPolicy, PersonProofThirdPartyProvider, WafProtocol, WafRequestInput,
  WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork, apply_header_mutations,
};

use super::body::{self, BodyTimeoutKind, ProxyBody, error_is_body_length_limit, error_is_timeout};
use super::full_body;
use super::response::text_response;

const PERSON_PROOF_VERIFY_BODY_LIMIT: usize = 16_384;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_person_proof_api<B>(
  request: Request<B>,
  state: &AppSnapshot,
  request_method: Method,
  request_uri: http::Uri,
  client_body_timeout: Duration,
  request_version: http::Version,
  client_addr: std::net::SocketAddr,
  host: &str,
  downstream_scheme: &str,
  route_name: &str,
  tcp_max_hop: Option<u8>,
  tls: &WafTlsMetadata,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
  transport_metadata: WafTransportMetadataInput<'_>,
  tags: &HashMap<String, String>,
  dynamic_policy: &DynamicPolicyContext,
  request_id: String,
  transaction_id: String,
  received_at_unix_ms: u64,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  let Some(role) = state.waf.person_proof_api_path_role(request_uri.path()) else {
    return text_response(StatusCode::NOT_FOUND, "person proof API path not found");
  };
  let content_type = request
    .headers()
    .get(http::header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string);
  let (parts, body) = request.into_parts();
  let input = WafRequestInput {
    request_id: &request_id,
    transaction_id: &transaction_id,
    received_at_unix_ms,
    method: &request_method,
    uri: &request_uri,
    version: request_version,
    headers: &parts.headers,
    body: None,
    peer_addr: client_addr,
    downstream_host: host,
    downstream_scheme,
    route_name,
    tcp_max_hop,
    tls,
    protocol,
    transport_network,
    transport_metadata,
    tags,
    dynamic_policy,
  };

  match role {
    PersonProofApiPathRole::OpenApi => {
      if request_method != Method::GET {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
      }
      let Some(document) = state.waf.person_proof_openapi_document(request_uri.path()) else {
        return text_response(
          StatusCode::NOT_FOUND,
          "person proof OpenAPI document not found",
        );
      };
      json_bytes_response(StatusCode::OK, bytes::Bytes::from(document))
    }
    PersonProofApiPathRole::Session => {
      if request_method != Method::GET {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
      }
      let Some(session) = query_field(&request_uri, "session") else {
        return text_response(StatusCode::FORBIDDEN, "person proof session is required");
      };
      match state
        .waf
        .person_proof_session_document(input, request_uri.path(), &session)
      {
        Ok(Some(document)) => json_response(StatusCode::OK, &document),
        Ok(None) => text_response(StatusCode::FORBIDDEN, "person proof session is invalid"),
        Err(error) if error.to_string().contains("expired") => {
          text_response(StatusCode::GONE, "person proof session expired")
        }
        Err(error) => {
          warn!(error = %error, "invalid person proof session");
          text_response(StatusCode::FORBIDDEN, "person proof session is invalid")
        }
      }
    }
    PersonProofApiPathRole::Verify => {
      if request_method != Method::POST {
        return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
      }
      handle_person_proof_verify(
        body,
        state,
        input,
        request_uri.path(),
        content_type.as_deref(),
        client_body_timeout,
        client_addr.ip(),
      )
      .await
    }
  }
}

async fn handle_person_proof_verify<B>(
  body: B,
  state: &AppSnapshot,
  input: WafRequestInput<'_>,
  verify_path: &str,
  content_type: Option<&str>,
  client_body_timeout: Duration,
  client_ip: std::net::IpAddr,
) -> Response<ProxyBody>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + 'static,
{
  let body = body::with_read_timeout(
    Limited::new(body, PERSON_PROOF_VERIFY_BODY_LIMIT),
    client_body_timeout,
    BodyTimeoutKind::DownstreamRequestRead,
  );
  let body = match body.collect().await {
    Ok(collected) => collected.to_bytes(),
    Err(error) if error_is_body_length_limit(&error) => {
      return text_response(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large");
    }
    Err(error) => {
      warn!(error = %error, "failed to read person proof verify body");
      if error_is_timeout(&error, BodyTimeoutKind::DownstreamRequestRead) {
        return text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out");
      }
      return text_response(StatusCode::BAD_REQUEST, "failed to read request body");
    }
  };
  let payload = match parse_person_proof_verify_payload(&body, content_type) {
    Ok(payload) => payload,
    Err(error) => {
      warn!(error = %error, "invalid person proof verify payload");
      return text_response(
        StatusCode::BAD_REQUEST,
        "invalid person proof verify payload",
      );
    }
  };

  let challenge =
    match state
      .waf
      .begin_person_proof_provider_challenge(input, verify_path, &payload.session)
    {
      Ok(Some(challenge)) => challenge,
      Ok(None) => return text_response(StatusCode::FORBIDDEN, "person proof session is invalid"),
      Err(error) if error.to_string().contains("expired") => {
        return text_response(StatusCode::GONE, "person proof session expired");
      }
      Err(error) => {
        warn!(error = %error, "invalid person proof session");
        return text_response(StatusCode::FORBIDDEN, "person proof session is invalid");
      }
    };
  if let Err(error) = state
    .waf
    .consume_person_proof_provider_challenge_attempt(&challenge)
  {
    if error.to_string().contains("expired") {
      return text_response(StatusCode::GONE, "person proof session expired");
    }
    if is_person_proof_reuse_capacity_error(&error) {
      return person_proof_rate_limited_response();
    }
    warn!(error = %error, "invalid person proof session");
    return text_response(StatusCode::FORBIDDEN, "person proof session is invalid");
  }

  match verify_person_proof_response(state, &challenge, &payload.response, client_ip).await {
    Ok(true) => complete_person_proof_verify(state, input, challenge),
    Ok(false) => text_response(StatusCode::FORBIDDEN, "person proof verification failed"),
    Err(error) if challenge.provider_fail_policy == PersonProofProviderFailPolicy::Open => {
      warn!(error = %error, "person proof provider failed open");
      complete_person_proof_verify(state, input, challenge)
    }
    Err(error) => {
      warn!(error = %error, "person proof provider failed closed");
      text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "person proof provider verification failed",
      )
    }
  }
}

struct PersonProofVerifyPayload {
  session: String,
  response: PersonProofClientResponse,
}

struct PersonProofClientResponse {
  token: String,
  fields: Map<String, Value>,
}

fn parse_person_proof_verify_payload(
  body: &[u8],
  content_type: Option<&str>,
) -> anyhow::Result<PersonProofVerifyPayload> {
  let is_json = content_type.map(|value| value.split(';').next().unwrap_or_default().trim())
    == Some("application/json");
  if !is_json {
    anyhow::bail!("person proof verify payload must use application/json");
  }
  let (session, response) = parse_json_payload(body)?;
  let session = session
    .filter(|value| !value.trim().is_empty())
    .context("person proof verify payload is missing session")?;
  if response.token.trim().is_empty() {
    anyhow::bail!("person proof verify payload is missing response token");
  }
  Ok(PersonProofVerifyPayload { session, response })
}

fn parse_json_payload(body: &[u8]) -> anyhow::Result<(Option<String>, PersonProofClientResponse)> {
  let value: Value = serde_json::from_slice(body)?;
  let session = json_string_field(&value, "session");
  let response_value = value.get("response").and_then(Value::as_object);
  let token = response_value
    .and_then(|response| response.get("token"))
    .and_then(Value::as_str)
    .map(str::to_string)
    .unwrap_or_default();
  let fields = response_value
    .and_then(|response| response.get("fields"))
    .and_then(Value::as_object)
    .cloned()
    .unwrap_or_default();
  Ok((session, PersonProofClientResponse { token, fields }))
}

fn json_string_field(value: &Value, field: &str) -> Option<String> {
  value.get(field).and_then(Value::as_str).map(str::to_string)
}

async fn verify_person_proof_response(
  state: &AppSnapshot,
  challenge: &PersonProofProviderChallenge,
  response: &PersonProofClientResponse,
  remote_ip: std::net::IpAddr,
) -> anyhow::Result<bool> {
  match challenge.mode {
    PersonProofMode::BuiltIn | PersonProofMode::OpenApi => Ok(pow_response_is_valid(
      &challenge.session,
      &response.token,
      challenge.difficulty,
    )),
    PersonProofMode::ThirdPartyProvider | PersonProofMode::CustomProvider => {
      verify_person_proof_provider(state, challenge, response, remote_ip).await
    }
  }
}

async fn verify_person_proof_provider(
  state: &AppSnapshot,
  challenge: &PersonProofProviderChallenge,
  response: &PersonProofClientResponse,
  remote_ip: std::net::IpAddr,
) -> anyhow::Result<bool> {
  let endpoint = challenge
    .endpoint
    .as_ref()
    .context("person proof provider challenge requires provider endpoint")?;
  let mut builder = Request::builder()
    .method(Method::POST)
    .uri(uri_from_url(endpoint)?)
    .header(http::header::ACCEPT, "application/json");
  let body = match challenge.mode {
    PersonProofMode::BuiltIn | PersonProofMode::OpenApi => {
      anyhow::bail!("pow person proof does not use provider verification");
    }
    PersonProofMode::ThirdPartyProvider => match challenge.third_party_provider {
      Some(PersonProofThirdPartyProvider::Turnstile)
      | Some(PersonProofThirdPartyProvider::HCaptcha) => {
        let secret = provider_secret(challenge)?;
        builder = builder.header(
          http::header::CONTENT_TYPE,
          "application/x-www-form-urlencoded",
        );
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("secret", &secret);
        form.append_pair("response", &response.token);
        if challenge.third_party_provider == Some(PersonProofThirdPartyProvider::HCaptcha) {
          form.append_pair("sitekey", provider_site_key(challenge)?);
        }
        if challenge.send_remote_ip {
          form.append_pair("remoteip", &remote_ip.to_string());
        }
        bytes::Bytes::from(form.finish())
      }
      Some(PersonProofThirdPartyProvider::FriendlyCaptchaV2) => {
        let secret = provider_secret(challenge)?;
        builder = builder
          .header(http::header::CONTENT_TYPE, "application/json")
          .header("x-api-key", secret);
        bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({
          "response": response.token,
          "sitekey": provider_site_key(challenge)?,
        }))?)
      }
      None => anyhow::bail!("third_party_provider mode requires a provider"),
    },
    PersonProofMode::CustomProvider => {
      builder = builder.header(http::header::CONTENT_TYPE, "application/json");
      bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({
        "session": challenge.session.clone(),
        "person_proof_mode": challenge.mode.as_str(),
        "provider": challenge.provider.clone(),
        "response": {
          "token": response.token.clone(),
          "fields": response.fields.clone(),
        },
        "remote_ip": challenge.send_remote_ip.then(|| remote_ip.to_string()),
        "site_key": challenge.site_key.clone(),
        "metadata": challenge.metadata.clone(),
      }))?)
    }
  };
  let request = builder
    .body(control_full_body(body))
    .context("failed to build person proof provider request")?;
  let provider_response = state
    .control_http
    .request(
      request,
      Duration::from_millis(challenge.provider_timeout_ms),
      challenge.provider_max_response_body_bytes,
    )
    .await?;
  if !provider_response.status.is_success() {
    anyhow::bail!(
      "person proof provider returned {}",
      provider_response.status
    );
  }
  parse_provider_success(&provider_response.body)
}

fn provider_secret(challenge: &PersonProofProviderChallenge) -> anyhow::Result<String> {
  let secret_env = challenge
    .secret_env
    .as_deref()
    .context("person proof provider challenge requires secret_env")?;
  let secret = std::env::var(secret_env)
    .with_context(|| format!("failed to read person proof secret_env {secret_env}"))?;
  if secret.is_empty() {
    anyhow::bail!("person proof secret_env {secret_env} resolved to an empty value");
  }
  Ok(secret)
}

fn provider_site_key(challenge: &PersonProofProviderChallenge) -> anyhow::Result<&str> {
  challenge
    .site_key
    .as_deref()
    .context("person proof provider challenge requires site_key")
}

fn parse_provider_success(body: &[u8]) -> anyhow::Result<bool> {
  let document: Value =
    serde_json::from_slice(body).context("person proof provider response is not JSON")?;
  document
    .get("success")
    .and_then(Value::as_bool)
    .context("person proof provider response is missing success")
}

fn complete_person_proof_verify(
  state: &AppSnapshot,
  input: WafRequestInput<'_>,
  challenge: PersonProofProviderChallenge,
) -> Response<ProxyBody> {
  let return_path = challenge.return_path.clone();
  let clearance = match state
    .waf
    .complete_person_proof_provider_challenge(input, challenge)
  {
    Ok(clearance) => clearance,
    Err(error) => {
      if is_person_proof_reuse_capacity_error(&error) {
        return person_proof_rate_limited_response();
      }
      warn!(error = %error, "failed to complete person proof challenge");
      return text_response(StatusCode::FORBIDDEN, "person proof session is invalid");
    }
  };
  let mut response = json_response(
    StatusCode::OK,
    &serde_json::json!({
      "ok": true,
      "return_path": return_path,
      "clearance": clearance.metadata.clone(),
    }),
  );
  if let Some(mutation) = clearance.response_header {
    apply_header_mutations(response.headers_mut(), &[mutation]);
  }
  response
}

fn is_person_proof_reuse_capacity_error(error: &anyhow::Error) -> bool {
  error
    .to_string()
    .contains("person proof reuse token capacity exhausted")
}

fn person_proof_rate_limited_response() -> Response<ProxyBody> {
  text_response(
    StatusCode::TOO_MANY_REQUESTS,
    "person proof token capacity exhausted",
  )
}

fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response<ProxyBody> {
  let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
  json_bytes_response(status, bytes::Bytes::from(bytes))
}

fn json_bytes_response(status: StatusCode, body: bytes::Bytes) -> Response<ProxyBody> {
  Response::builder()
    .status(status)
    .header(http::header::CONTENT_TYPE, "application/json")
    .header(http::header::CACHE_CONTROL, "no-store")
    .body(full_body(body))
    .expect("person proof JSON response should build")
}

fn query_field(uri: &http::Uri, name: &str) -> Option<String> {
  url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
    .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

fn pow_response_is_valid(session: &str, nonce: &str, difficulty: u8) -> bool {
  if nonce.is_empty() || nonce.len() > 20 || !nonce.bytes().all(|byte| byte.is_ascii_digit()) {
    return false;
  }
  let input = format!("{session}.{nonce}");
  let digest = digest::digest(&digest::SHA256, input.as_bytes());
  leading_zero_bits(digest.as_ref()) >= u32::from(difficulty)
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
  let mut total = 0u32;
  for byte in bytes {
    if *byte == 0 {
      total += 8;
    } else {
      total += byte.leading_zeros();
      break;
    }
  }
  total
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_verify_payload_accepts_json_session_response() {
    let json = br#"{
      "session": "session.v1.test",
      "response": {
        "token": "provider-token",
        "fields": { "tenant": "a" }
      }
    }"#;
    let payload = parse_person_proof_verify_payload(json, Some("application/json; charset=utf-8"))
      .expect("JSON payload should parse");

    assert_eq!(payload.session, "session.v1.test");
    assert_eq!(payload.response.token, "provider-token");
    assert_eq!(
      payload
        .response
        .fields
        .get("tenant")
        .and_then(Value::as_str),
      Some("a")
    );
  }

  #[test]
  fn parse_verify_payload_rejects_legacy_json_and_form_fields() {
    let json = br#"{
      "challenge": "session.v1.test",
      "cf-turnstile-response": "provider-token"
    }"#;
    assert!(parse_person_proof_verify_payload(json, Some("application/json")).is_err());

    let body = b"challenge=session.v1.test&h-captcha-response=provider-token&tenant=a";
    assert!(
      parse_person_proof_verify_payload(body, Some("application/x-www-form-urlencoded")).is_err()
    );
  }

  #[test]
  fn parse_provider_success_requires_json_success_boolean() {
    assert!(parse_provider_success(br#"{"success":true}"#).unwrap());
    assert!(!parse_provider_success(br#"{"success":false}"#).unwrap());
    assert!(parse_provider_success(b"not-json").is_err());
    assert!(parse_provider_success(br#"{"ok":true}"#).is_err());
  }

  #[test]
  fn pow_response_requires_numeric_nonce() {
    assert!(!pow_response_is_valid("session.v1.test", "abc", 1));
    assert!(!pow_response_is_valid("session.v1.test", "", 1));
  }
}
