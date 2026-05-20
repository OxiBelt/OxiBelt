use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Body;
use tracing::warn;

use crate::control_http::{full_body as control_full_body, uri_from_url};
use crate::dynamic_policy::DynamicPolicyContext;
use crate::state::AppSnapshot;
use crate::waf::{
  PersonProofAlgorithm, PersonProofProviderChallenge, PersonProofProviderFailPolicy, WafProtocol,
  WafRequestInput, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork,
  apply_header_mutations,
};

use super::body::{self, BodyTimeoutKind, ProxyBody, error_is_body_length_limit, error_is_timeout};
use super::full_body;
use super::response::text_response;

const PERSON_PROOF_VERIFY_BODY_LIMIT: usize = 16_384;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_person_proof_verify<B>(
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
  if request_method != Method::POST {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }

  let content_type = request
    .headers()
    .get(http::header::CONTENT_TYPE)
    .and_then(|value| value.to_str().ok())
    .map(str::to_string);
  let (parts, body) = request.into_parts();
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
  let payload = match parse_person_proof_verify_payload(&body, content_type.as_deref()) {
    Ok(payload) => payload,
    Err(error) => {
      warn!(error = %error, "invalid person proof verify payload");
      return text_response(
        StatusCode::BAD_REQUEST,
        "invalid person proof verify payload",
      );
    }
  };

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
  let challenge = match state.waf.begin_person_proof_provider_challenge(
    input,
    request_uri.path(),
    &payload.challenge,
  ) {
    Ok(Some(challenge)) => challenge,
    Ok(None) => return text_response(StatusCode::NOT_FOUND, "person proof verifier not found"),
    Err(error) => {
      warn!(error = %error, "invalid person proof provider challenge");
      return text_response(StatusCode::FORBIDDEN, "person proof challenge is invalid");
    }
  };

  match verify_person_proof_provider(
    state,
    &challenge,
    &payload.provider_response,
    client_addr.ip(),
  )
  .await
  {
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
  challenge: String,
  provider_response: String,
}

fn parse_person_proof_verify_payload(
  body: &[u8],
  content_type: Option<&str>,
) -> anyhow::Result<PersonProofVerifyPayload> {
  let is_json = content_type.map(|value| value.split(';').next().unwrap_or_default().trim())
    == Some("application/json");
  let (challenge, provider_response) = if is_json {
    let value: serde_json::Value = serde_json::from_slice(body)?;
    (
      json_string_field(&value, "challenge"),
      json_string_field(&value, "provider_response")
        .or_else(|| json_string_field(&value, "cf-turnstile-response"))
        .or_else(|| json_string_field(&value, "h-captcha-response"))
        .or_else(|| json_string_field(&value, "frc-captcha-response")),
    )
  } else {
    let fields = url::form_urlencoded::parse(body)
      .into_owned()
      .collect::<HashMap<_, _>>();
    (
      fields.get("challenge").cloned(),
      fields
        .get("provider_response")
        .or_else(|| fields.get("cf-turnstile-response"))
        .or_else(|| fields.get("h-captcha-response"))
        .or_else(|| fields.get("frc-captcha-response"))
        .cloned(),
    )
  };
  let challenge = challenge
    .filter(|value| !value.trim().is_empty())
    .context("person proof verify payload is missing challenge")?;
  let provider_response = provider_response
    .filter(|value| !value.trim().is_empty())
    .context("person proof verify payload is missing provider_response")?;
  Ok(PersonProofVerifyPayload {
    challenge,
    provider_response,
  })
}

fn json_string_field(value: &serde_json::Value, field: &str) -> Option<String> {
  value
    .get(field)
    .and_then(serde_json::Value::as_str)
    .map(str::to_string)
}

async fn verify_person_proof_provider(
  state: &AppSnapshot,
  challenge: &PersonProofProviderChallenge,
  provider_response: &str,
  remote_ip: std::net::IpAddr,
) -> anyhow::Result<bool> {
  let secret = std::env::var(&challenge.secret_env).with_context(|| {
    format!(
      "failed to read person proof secret_env {}",
      challenge.secret_env
    )
  })?;
  if secret.is_empty() {
    anyhow::bail!(
      "person proof secret_env {} resolved to an empty value",
      challenge.secret_env
    );
  }
  let mut builder = Request::builder()
    .method(Method::POST)
    .uri(uri_from_url(&challenge.endpoint)?)
    .header(http::header::ACCEPT, "application/json");
  let body = match challenge.method {
    PersonProofAlgorithm::PowSha256V1 => {
      anyhow::bail!("pow person proof does not use provider verification");
    }
    PersonProofAlgorithm::Turnstile | PersonProofAlgorithm::HCaptcha => {
      builder = builder.header(
        http::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded",
      );
      let mut form = url::form_urlencoded::Serializer::new(String::new());
      form.append_pair("secret", &secret);
      form.append_pair("response", provider_response);
      if challenge.method == PersonProofAlgorithm::HCaptcha {
        form.append_pair("sitekey", &challenge.site_key);
      }
      if challenge.send_remote_ip {
        form.append_pair("remoteip", &remote_ip.to_string());
      }
      bytes::Bytes::from(form.finish())
    }
    PersonProofAlgorithm::FriendlyCaptchaV2 => {
      builder = builder
        .header(http::header::CONTENT_TYPE, "application/json")
        .header("x-api-key", secret);
      bytes::Bytes::from(serde_json::to_vec(&serde_json::json!({
        "response": provider_response,
        "sitekey": challenge.site_key,
      }))?)
    }
  };
  let request = builder
    .body(control_full_body(body))
    .context("failed to build person proof provider request")?;
  let response = state
    .control_http
    .request(
      request,
      Duration::from_millis(challenge.provider_timeout_ms),
      challenge.provider_max_response_body_bytes,
    )
    .await?;
  if !response.status.is_success() {
    anyhow::bail!("person proof provider returned {}", response.status);
  }
  parse_provider_success(&response.body)
}

fn parse_provider_success(body: &[u8]) -> anyhow::Result<bool> {
  let document: serde_json::Value =
    serde_json::from_slice(body).context("person proof provider response is not JSON")?;
  document
    .get("success")
    .and_then(serde_json::Value::as_bool)
    .context("person proof provider response is missing success")
}

fn complete_person_proof_verify(
  state: &AppSnapshot,
  input: WafRequestInput<'_>,
  challenge: PersonProofProviderChallenge,
) -> Response<ProxyBody> {
  let mutation = match state
    .waf
    .complete_person_proof_provider_challenge(input, challenge)
  {
    Ok(mutation) => mutation,
    Err(error) => {
      warn!(error = %error, "failed to complete person proof provider challenge");
      return text_response(StatusCode::FORBIDDEN, "person proof challenge is invalid");
    }
  };
  let mut response = Response::builder()
    .status(StatusCode::NO_CONTENT)
    .body(full_body(bytes::Bytes::new()))
    .expect("empty person proof response should build");
  apply_header_mutations(response.headers_mut(), &[mutation]);
  response
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parse_verify_payload_accepts_json_and_provider_field_names() {
    let json = br#"{
      "challenge": "challenge.v2.test",
      "cf-turnstile-response": "provider-token"
    }"#;
    let payload = parse_person_proof_verify_payload(json, Some("application/json; charset=utf-8"))
      .expect("JSON payload should parse");

    assert_eq!(payload.challenge, "challenge.v2.test");
    assert_eq!(payload.provider_response, "provider-token");
  }

  #[test]
  fn parse_verify_payload_accepts_form_payloads() {
    let body = b"challenge=challenge.v2.test&h-captcha-response=provider-token";
    let payload =
      parse_person_proof_verify_payload(body, Some("application/x-www-form-urlencoded"))
        .expect("form payload should parse");

    assert_eq!(payload.challenge, "challenge.v2.test");
    assert_eq!(payload.provider_response, "provider-token");
  }

  #[test]
  fn parse_provider_success_requires_json_success_boolean() {
    assert!(parse_provider_success(br#"{"success":true}"#).unwrap());
    assert!(!parse_provider_success(br#"{"success":false}"#).unwrap());
    assert!(parse_provider_success(b"not-json").is_err());
    assert!(parse_provider_success(br#"{"ok":true}"#).is_err());
  }
}
