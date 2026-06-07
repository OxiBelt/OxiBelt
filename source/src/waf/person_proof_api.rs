use anyhow::{Context, anyhow, bail};
use ring::{digest, hmac};
use serde::Serialize;

use super::person_proof::{
  PersonProofEngine, PersonProofPolicy, hex_decode, hex_encode, now_unix_ms,
  token_binding_payload_for_route,
};
use super::person_proof_v2::{PersonProofProviderChallenge, ProviderChallengeState};
use super::{PersonProofMode, PersonProofThirdPartyProvider, WafRequestInput};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PersonProofApiPathRole {
  Session,
  Verify,
  OpenApi,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersonProofSessionDocument {
  pub session: String,
  pub person_proof_mode: &'static str,
  pub provider: String,
  pub expires_unix_ms: i64,
  pub return_path: String,
  pub verify_path: String,
  pub clearance: serde_json::Value,
  pub challenge: serde_json::Value,
}

struct SessionFields {
  issued: i64,
  expires: i64,
  mode: String,
  provider: String,
  method: String,
  route: String,
  return_path: String,
  binding_hash: String,
  random: String,
  mac: String,
}

pub(super) fn api_path_role(
  engine: &PersonProofEngine,
  path: &str,
) -> Option<PersonProofApiPathRole> {
  engine.policies.iter().find_map(|policy| {
    if policy.provider.session_path == path {
      Some(PersonProofApiPathRole::Session)
    } else if policy.provider.verify_path == path {
      Some(PersonProofApiPathRole::Verify)
    } else if policy.provider.openapi_path == path {
      Some(PersonProofApiPathRole::OpenApi)
    } else {
      None
    }
  })
}

pub(super) fn session_document(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  session_path: &str,
  session: &str,
) -> anyhow::Result<Option<PersonProofSessionDocument>> {
  let Some((policy, fields)) = validate_session_for_path(
    engine,
    input,
    session_path,
    session,
    PersonProofApiPathRole::Session,
  )?
  else {
    return Ok(None);
  };
  let challenge = match policy.mode {
    PersonProofMode::BuiltIn | PersonProofMode::OpenApi => serde_json::json!({
      "kind": "pow_sha256_v1",
      "difficulty": policy.difficulty,
      "token": session,
    }),
    PersonProofMode::ThirdPartyProvider => serde_json::json!({
      "kind": "third_party_provider",
      "third_party_provider": policy.third_party_provider.map(PersonProofThirdPartyProvider::as_str),
      "site_key": policy.provider.site_key,
      "metadata": provider_metadata(&policy),
    }),
    PersonProofMode::CustomProvider => serde_json::json!({
      "kind": custom_provider_challenge_kind(&policy),
      "proof_kind": custom_provider_proof_kind(&policy),
      "provider": provider_name(&policy),
      "label": custom_provider_proof_label(&policy),
      "metadata": provider_metadata(&policy),
    }),
  };
  Ok(Some(PersonProofSessionDocument {
    session: session.to_string(),
    person_proof_mode: policy.mode.as_str(),
    provider: provider_name(&policy),
    expires_unix_ms: fields.expires,
    return_path: fields.return_path,
    verify_path: policy.provider.verify_path,
    clearance: policy.clearance.session_metadata(),
    challenge,
  }))
}

pub(super) fn begin_session_challenge(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  verify_path: &str,
  session: &str,
) -> anyhow::Result<Option<PersonProofProviderChallenge>> {
  let Some((policy, fields)) = validate_session_for_path(
    engine,
    input,
    verify_path,
    session,
    PersonProofApiPathRole::Verify,
  )?
  else {
    return Ok(None);
  };
  Ok(Some(PersonProofProviderChallenge {
    mode: policy.mode,
    third_party_provider: policy.third_party_provider,
    endpoint: if policy.mode.uses_pow() {
      None
    } else {
      Some(provider_endpoint(&policy)?)
    },
    site_key: policy.provider.site_key.clone(),
    secret_env: policy.provider.secret_env.clone(),
    provider: provider_name(&policy),
    metadata: provider_metadata(&policy),
    proof_kind: (policy.mode == PersonProofMode::CustomProvider)
      .then(|| custom_provider_proof_kind(&policy).to_string()),
    proof_challenge_kind: (policy.mode == PersonProofMode::CustomProvider)
      .then(|| custom_provider_challenge_kind(&policy).to_string()),
    proof_label: custom_provider_proof_label(&policy).map(str::to_string),
    session: session.to_string(),
    return_path: fields.return_path.clone(),
    difficulty: policy.difficulty,
    provider_timeout_ms: policy.provider.provider_timeout_ms,
    provider_fail_policy: policy.provider.provider_fail_policy,
    provider_max_response_body_bytes: policy.provider.provider_max_response_body_bytes,
    send_remote_ip: policy.provider.send_remote_ip,
    state: ProviderChallengeState {
      policy,
      token: session.to_string(),
      issued: fields.issued,
      expires: fields.expires,
      mode: fields.mode,
      provider: fields.provider,
      method: fields.method,
      route_name: fields.route,
      binding_hash: fields.binding_hash,
      random: fields.random,
    },
  }))
}

pub(super) fn sign_session_token(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  issued: i64,
  expires: i64,
  return_path: &str,
  random: &str,
) -> String {
  let binding_hash = token_binding_hash(input, policy, input.route_name);
  let payload = session_payload(
    input.downstream_host,
    policy,
    &provider_identity(policy),
    input.method.as_str(),
    input.route_name,
    return_path,
    &binding_hash,
    issued,
    expires,
    random,
  );
  let mac = hmac::sign(
    &hmac::Key::new(hmac::HMAC_SHA256, &engine.secret),
    payload.as_bytes(),
  );
  format!(
    "session.v1.{issued}.{expires}.{}.{}.{}.{}.{}.{}.{}.{}",
    policy.mode.as_str(),
    hex_encode(provider_identity(policy).as_bytes()),
    hex_encode(input.method.as_str().as_bytes()),
    hex_encode(input.route_name.as_bytes()),
    hex_encode(return_path.as_bytes()),
    binding_hash,
    random,
    hex_encode(mac.as_ref())
  )
}

pub(super) fn openapi_document(engine: &PersonProofEngine, openapi_path: &str) -> Option<String> {
  let policy = engine
    .policies
    .iter()
    .find(|policy| policy.provider.openapi_path == openapi_path)?;
  let document = serde_json::json!({
    "openapi": "3.1.0",
    "info": {
      "title": "OxiBelt Person-Proof API",
      "version": "1.0.0"
    },
    "paths": {
      policy.provider.session_path.clone(): {
        "get": {
          "operationId": "getPersonProofSession",
          "parameters": [{
            "name": "session",
            "in": "query",
            "required": true,
            "schema": { "type": "string" }
          }],
          "responses": {
            "200": {
              "description": "Person-proof session",
              "content": {
                "application/json": {
                  "schema": { "$ref": "#/components/schemas/SessionDocument" }
                }
              }
            }
          }
        }
      },
      policy.provider.verify_path.clone(): {
        "post": {
          "operationId": "verifyPersonProofSession",
          "requestBody": {
            "required": true,
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/VerifyRequest" }
              }
            }
          },
          "responses": {
            "200": {
              "description": "Verification result with clearance metadata and token",
              "content": {
                "application/json": {
                  "schema": { "$ref": "#/components/schemas/VerifyResponse" }
                }
              }
            }
          }
        }
      },
      policy.provider.openapi_path.clone(): {
        "get": {
          "operationId": "getPersonProofOpenApi",
          "responses": { "200": { "description": "OpenAPI document" } }
        }
      }
    },
    "components": {
      "schemas": {
        "SessionDocument": {
          "type": "object",
          "required": [
            "session",
            "person_proof_mode",
            "provider",
            "expires_unix_ms",
            "return_path",
            "verify_path",
            "clearance",
            "challenge"
          ],
          "properties": {
            "session": { "type": "string" },
            "person_proof_mode": {
              "type": "string",
              "enum": [
                "built_in",
                "openapi",
                "third_party_provider",
                "custom_provider"
              ]
            },
            "provider": { "type": "string" },
            "expires_unix_ms": { "type": "integer", "format": "int64" },
            "return_path": { "type": "string" },
            "verify_path": { "type": "string" },
            "clearance": { "$ref": "#/components/schemas/ClearanceMetadata" },
            "challenge": {
              "type": "object",
              "description": "Mode-specific challenge payload. built_in and openapi use kind pow_sha256_v1. third_party_provider uses kind third_party_provider. custom_provider may use a configured proof_challenge_kind, defaults to custom_provider for compatibility, and adds proof_kind, provider, label, and metadata.",
              "additionalProperties": true,
              "properties": {
                "kind": {
                  "type": "string",
                  "description": "Frontend challenge kind. custom_provider can configure this with proof_challenge_kind."
                },
                "proof_kind": {
                  "type": "string",
                  "description": "Operator-facing custom_provider proof category such as work, knowledge, or possession."
                },
                "provider": { "type": "string" },
                "label": { "type": ["string", "null"] },
                "metadata": {
                  "type": "object",
                  "additionalProperties": true
                },
                "difficulty": { "type": "integer" },
                "token": { "type": "string" },
                "third_party_provider": {
                  "type": "string",
                  "enum": ["turnstile", "hcaptcha", "friendly_captcha_v2"]
                },
                "site_key": { "type": ["string", "null"] }
              }
            }
          }
        },
        "VerifyRequest": {
          "type": "object",
          "required": ["session", "response"],
          "properties": {
            "session": { "type": "string" },
            "response": {
              "type": "object",
              "required": ["token"],
              "properties": {
                "token": { "type": "string" },
                "fields": {
                  "type": "object",
                  "additionalProperties": true
                }
              }
            }
          }
        },
        "VerifyResponse": {
          "type": "object",
          "required": ["ok", "return_path", "clearance"],
          "properties": {
            "ok": { "type": "boolean" },
            "return_path": { "type": "string" },
            "clearance": { "$ref": "#/components/schemas/ClearanceMetadata" }
          }
        },
        "ClearanceMetadata": {
          "type": "object",
          "required": ["issue_to", "cookie", "local_storage", "sources"],
          "properties": {
            "issue_to": {
              "type": "string",
              "enum": ["cookie", "local_storage", "response_json"]
            },
            "token": { "type": "string" },
            "expires_unix_ms": { "type": "integer", "format": "int64" },
            "max_age_seconds": { "type": "integer", "format": "int64" },
            "cookie": {
              "type": "object",
              "required": ["key", "path", "same_site", "secure", "http_only"],
              "properties": {
                "key": { "type": "string" },
                "path": { "type": "string" },
                "same_site": { "type": "string", "enum": ["Strict", "Lax", "None"] },
                "secure": { "type": "boolean" },
                "http_only": { "type": "boolean" }
              }
            },
            "local_storage": {
              "type": "object",
              "required": ["key", "request_header"],
              "properties": {
                "key": { "type": "string" },
                "request_header": { "type": "string" }
              }
            },
            "sources": {
              "type": "array",
              "items": {
                "type": "object",
                "required": ["type"],
                "properties": {
                  "type": {
                    "type": "string",
                    "enum": ["cookie", "authorization_bearer", "header"]
                  },
                  "key": { "type": "string" }
                }
              }
            }
          }
        }
      }
    }
  });
  serde_json::to_string_pretty(&document).ok()
}

pub(super) fn provider_endpoint(policy: &PersonProofPolicy) -> anyhow::Result<url::Url> {
  if let Some(endpoint) = policy.provider.provider_endpoint.clone() {
    return Ok(endpoint);
  }
  let endpoint = match policy.mode {
    PersonProofMode::BuiltIn | PersonProofMode::OpenApi | PersonProofMode::CustomProvider => {
      bail!(
        "person proof provider_endpoint is required for {}",
        policy.mode.as_str()
      );
    }
    PersonProofMode::ThirdPartyProvider => match policy.third_party_provider {
      Some(PersonProofThirdPartyProvider::Turnstile) => {
        "https://challenges.cloudflare.com/turnstile/v0/siteverify"
      }
      Some(PersonProofThirdPartyProvider::HCaptcha) => "https://api.hcaptcha.com/siteverify",
      Some(PersonProofThirdPartyProvider::FriendlyCaptchaV2) => {
        "https://global.frcapi.com/api/v2/captcha/siteverify"
      }
      None => bail!("person proof third_party_provider is required"),
    },
  };
  url::Url::parse(endpoint).context("built-in provider endpoint must be valid")
}

pub(super) fn provider_identity(policy: &PersonProofPolicy) -> String {
  match policy.mode {
    PersonProofMode::BuiltIn | PersonProofMode::OpenApi => "oxibelt-pow".to_string(),
    PersonProofMode::ThirdPartyProvider => policy
      .third_party_provider
      .map(PersonProofThirdPartyProvider::as_str)
      .unwrap_or("unknown-third-party-provider")
      .to_string(),
    PersonProofMode::CustomProvider => provider_name(policy),
  }
}

pub(super) fn provider_name(policy: &PersonProofPolicy) -> String {
  if let Some(provider) = policy.provider.provider.as_deref() {
    return provider.to_string();
  }
  match policy.mode {
    PersonProofMode::BuiltIn | PersonProofMode::OpenApi => "oxibelt-pow",
    PersonProofMode::ThirdPartyProvider => match policy.third_party_provider {
      Some(PersonProofThirdPartyProvider::Turnstile) => "cloudflare-turnstile",
      Some(PersonProofThirdPartyProvider::HCaptcha) => "hcaptcha",
      Some(PersonProofThirdPartyProvider::FriendlyCaptchaV2) => "friendly-captcha",
      None => "unknown-third-party-provider",
    },
    PersonProofMode::CustomProvider => "custom-provider",
  }
  .to_string()
}

pub(super) fn provider_metadata(policy: &PersonProofPolicy) -> serde_json::Value {
  if policy.provider.provider_metadata.is_null() {
    serde_json::json!({})
  } else {
    policy.provider.provider_metadata.clone()
  }
}

pub(super) fn custom_provider_proof_kind(policy: &PersonProofPolicy) -> &str {
  policy.provider.proof_kind.as_deref().unwrap_or("custom")
}

pub(super) fn custom_provider_challenge_kind(policy: &PersonProofPolicy) -> &str {
  policy
    .provider
    .proof_challenge_kind
    .as_deref()
    .unwrap_or("custom_provider")
}

pub(super) fn custom_provider_proof_label(policy: &PersonProofPolicy) -> Option<&str> {
  policy.provider.proof_label.as_deref()
}

fn validate_session_for_path(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  path: &str,
  session: &str,
  role: PersonProofApiPathRole,
) -> anyhow::Result<Option<(PersonProofPolicy, SessionFields)>> {
  let fields = parse_session_token(session)?;
  let now = now_unix_ms()?;
  if now > fields.expires {
    bail!("person proof session token expired");
  }
  if fields.issued > now.saturating_add(60_000) {
    bail!("person proof session token was issued in the future");
  }
  for policy in &engine.policies {
    if fields.mode != policy.mode.as_str()
      || fields.provider != provider_identity(policy)
      || !path_matches_role(policy, path, role)
    {
      continue;
    }
    if verify_session_mac(engine, input, policy, &fields).is_err() {
      continue;
    }
    let current_binding_hash = token_binding_hash(input, policy, &fields.route);
    if current_binding_hash != fields.binding_hash {
      bail!("person proof session token bindings do not match request");
    }
    return Ok(Some((policy.clone(), fields)));
  }
  Ok(None)
}

fn path_matches_role(policy: &PersonProofPolicy, path: &str, role: PersonProofApiPathRole) -> bool {
  match role {
    PersonProofApiPathRole::Session => policy.provider.session_path == path,
    PersonProofApiPathRole::Verify => policy.provider.verify_path == path,
    PersonProofApiPathRole::OpenApi => policy.provider.openapi_path == path,
  }
}

fn verify_session_mac(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  fields: &SessionFields,
) -> anyhow::Result<()> {
  let payload = session_payload(
    input.downstream_host,
    policy,
    &fields.provider,
    &fields.method,
    &fields.route,
    &fields.return_path,
    &fields.binding_hash,
    fields.issued,
    fields.expires,
    &fields.random,
  );
  verify_mac(engine, &payload, &fields.mac)
}

#[allow(clippy::too_many_arguments)]
fn session_payload(
  host: &str,
  policy: &PersonProofPolicy,
  provider: &str,
  method: &str,
  route: &str,
  return_path: &str,
  binding_hash: &str,
  issued: i64,
  expires: i64,
  random: &str,
) -> String {
  format!(
    "session.v1\n{}\n{}\n{}\n{}\n{host}\n{method}\n{route}\n{}\n{}\n{}\n{return_path}\n{binding_hash}\n{issued}\n{expires}\n{random}",
    policy.mode.as_str(),
    provider,
    policy.key,
    policy.clearance.signing_id(),
    policy.provider.session_path,
    policy.provider.verify_path,
    policy.provider.openapi_path
  )
}

fn verify_mac(engine: &PersonProofEngine, payload: &str, mac: &str) -> anyhow::Result<()> {
  let mac = hex_decode(mac)?;
  hmac::verify(
    &hmac::Key::new(hmac::HMAC_SHA256, &engine.secret),
    payload.as_bytes(),
    &mac,
  )
  .map_err(|_| anyhow!("person proof session token signature is invalid"))
}

fn parse_session_token(token: &str) -> anyhow::Result<SessionFields> {
  let parts = token.split('.').collect::<Vec<_>>();
  if parts.len() != 12 || parts[0] != "session" || parts[1] != "v1" {
    bail!("person proof session token has invalid shape");
  }
  Ok(SessionFields {
    issued: parts[2]
      .parse()
      .context("invalid session issued timestamp")?,
    expires: parts[3]
      .parse()
      .context("invalid session expiration timestamp")?,
    mode: parts[4].to_string(),
    provider: decode_hex_string(parts[5])?,
    method: decode_hex_string(parts[6])?,
    route: decode_hex_string(parts[7])?,
    return_path: decode_hex_string(parts[8])?,
    binding_hash: validate_hex_field(parts[9], "session binding hash", 64)?,
    random: validate_hex_field(parts[10], "session random", 32)?,
    mac: parts[11].to_string(),
  })
}

fn validate_hex_field(value: &str, label: &str, expected_len: usize) -> anyhow::Result<String> {
  if value.len() != expected_len || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    bail!("person proof {label} is invalid");
  }
  Ok(value.to_string())
}

fn decode_hex_string(value: &str) -> anyhow::Result<String> {
  String::from_utf8(hex_decode(value)?).context("person proof token field is not UTF-8")
}

fn token_binding_hash(
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  route_name: &str,
) -> String {
  let payload = token_binding_payload_for_route(input, policy, route_name);
  hex_encode(digest::digest(&digest::SHA256, payload.as_bytes()).as_ref())
}
