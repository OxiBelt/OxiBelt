//! Person proof provider challenge state.
//! Provider responses are validated before they can issue local clearance material.

use anyhow::{Context, anyhow, bail};
use http::header::{CACHE_CONTROL, LOCATION};
use http::{HeaderName, HeaderValue, StatusCode};
use ring::{digest, hmac};
use url::form_urlencoded;

use super::person_proof::{
  PersonProofEngine, PersonProofIssuedClearance, PersonProofPolicy, PersonProofRequestStatus,
  PersonProofState, clearance_hash, clearance_reuse_key, hex_decode, hex_encode, now_unix_ms,
  random_hex, remaining_seconds, token_binding_payload_for_route,
};
use super::person_proof_api::{
  begin_session_challenge, custom_provider_challenge_kind, custom_provider_proof_kind,
  custom_provider_proof_label, provider_endpoint, provider_identity, provider_metadata,
  provider_name, sign_session_token,
};
use super::{
  HeaderMutation, PersonProofMode, PersonProofProviderFailPolicy, PersonProofThirdPartyProvider,
  WafRequestInput, WafTerminalResponse,
};

#[derive(Debug, Clone)]
pub(super) struct PersonProofProviderConfig {
  pub custom_frontend_url: Option<String>,
  pub challenge_redirect_status: u16,
  pub session_path: String,
  pub verify_path: String,
  pub openapi_path: String,
  pub provider: Option<String>,
  pub provider_metadata: serde_json::Value,
  pub proof_kind: Option<Box<str>>,
  pub proof_challenge_kind: Option<Box<str>>,
  pub proof_label: Option<Box<str>>,
  pub site_key: Option<String>,
  pub secret_env: Option<String>,
  pub provider_endpoint: Option<url::Url>,
  pub provider_timeout_ms: u64,
  pub provider_fail_policy: PersonProofProviderFailPolicy,
  pub provider_max_response_body_bytes: usize,
  pub send_remote_ip: bool,
}

#[derive(Debug, Clone)]
pub struct PersonProofProviderChallenge {
  pub mode: PersonProofMode,
  pub third_party_provider: Option<PersonProofThirdPartyProvider>,
  pub endpoint: Option<url::Url>,
  pub site_key: Option<String>,
  pub secret_env: Option<String>,
  pub provider: String,
  pub metadata: serde_json::Value,
  pub proof_kind: Option<String>,
  pub proof_challenge_kind: Option<String>,
  pub proof_label: Option<String>,
  pub session: String,
  pub return_path: String,
  pub difficulty: u8,
  pub provider_timeout_ms: u64,
  pub provider_fail_policy: PersonProofProviderFailPolicy,
  pub provider_max_response_body_bytes: usize,
  pub send_remote_ip: bool,
  pub(super) state: ProviderChallengeState,
}

#[derive(Debug, Clone)]
pub(super) struct ProviderChallengeState {
  pub(super) policy: PersonProofPolicy,
  pub(super) token: String,
  pub(super) issued: i64,
  pub(super) expires: i64,
  pub(super) mode: String,
  pub(super) provider: String,
  pub(super) method: String,
  pub(super) route_name: String,
  pub(super) binding_hash: String,
  pub(super) random: String,
}

struct ChallengeFields {
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

struct ClearanceFields {
  issued: i64,
  expires: i64,
  mode: String,
  provider: String,
  method: String,
  route: String,
  binding_hash: String,
  random: String,
  mac: String,
}

pub(super) fn redirect_challenge(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
) -> anyhow::Result<WafTerminalResponse> {
  let now = now_unix_ms()?;
  let expires = now
    .checked_add(
      i64::try_from(policy.ttl_seconds)
        .context("person proof ttl does not fit in i64")?
        .saturating_mul(1000),
    )
    .context("person proof expiration overflow")?;
  let random = random_hex(16)?;
  let return_path = request_return_path(input);
  let session = sign_session_token(engine, input, policy, now, expires, &return_path, &random);

  let expires_string = expires.to_string();
  let pairs = vec![
    ("session", session.as_str()),
    ("session_path", policy.provider.session_path.as_str()),
    ("verify_path", policy.provider.verify_path.as_str()),
    ("openapi_path", policy.provider.openapi_path.as_str()),
    ("return_path", return_path.as_str()),
    ("expires_unix_ms", expires_string.as_str()),
  ];

  let location = append_query(
    policy
      .provider
      .custom_frontend_url
      .as_deref()
      .context("person proof redirect requires custom_frontend_url")?,
    pairs,
  );
  let mut response = WafTerminalResponse::new(
    StatusCode::from_u16(policy.provider.challenge_redirect_status)?,
    "person proof challenge required".to_string(),
  );
  response.headers.push(HeaderMutation::Set {
    name: LOCATION,
    value: HeaderValue::from_str(&location).context("invalid person proof challenge Location")?,
  });
  response.headers.push(HeaderMutation::Set {
    name: CACHE_CONTROL,
    value: HeaderValue::from_static("no-store"),
  });
  response.headers.push(HeaderMutation::Set {
    name: HeaderName::from_static("x-robots-tag"),
    value: HeaderValue::from_static("noindex, nofollow"),
  });
  response.headers.push(HeaderMutation::Set {
    name: HeaderName::from_static("x-oxibelt-person-proof"),
    value: HeaderValue::from_str(policy.mode.as_str())
      .context("invalid person proof mode header")?,
  });
  Ok(response)
}

pub(super) fn begin_provider_challenge(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  verify_path: &str,
  challenge: &str,
) -> anyhow::Result<Option<PersonProofProviderChallenge>> {
  if challenge.starts_with("session.v1.") {
    return begin_session_challenge(engine, input, verify_path, challenge);
  }
  let Some(policy) = engine
    .policies
    .iter()
    .find(|policy| policy.provider.verify_path == verify_path && policy.mode.uses_provider())
    .cloned()
  else {
    return Ok(None);
  };

  let fields = parse_challenge_token(challenge)?;
  let expected_provider = provider_identity(&policy);
  if fields.mode != policy.mode.as_str() {
    bail!("person proof challenge mode does not match policy");
  }
  if fields.provider != expected_provider {
    bail!("person proof challenge provider does not match policy");
  }
  verify_challenge_mac(engine, input, &policy, &fields, verify_path)?;
  let now = now_unix_ms()?;
  if now > fields.expires {
    bail!("person proof challenge token expired");
  }
  if fields.issued > now.saturating_add(60_000) {
    bail!("person proof challenge token was issued in the future");
  }
  let current_binding_hash = token_binding_hash(input, &policy, &fields.route);
  if current_binding_hash != fields.binding_hash {
    bail!("person proof challenge token bindings do not match request");
  }

  Ok(Some(PersonProofProviderChallenge {
    mode: policy.mode,
    third_party_provider: policy.third_party_provider,
    endpoint: Some(provider_endpoint(&policy)?),
    site_key: policy.provider.site_key.clone(),
    secret_env: policy.provider.secret_env.clone(),
    provider: provider_name(&policy),
    metadata: provider_metadata(&policy),
    proof_kind: (policy.mode == PersonProofMode::CustomProvider)
      .then(|| custom_provider_proof_kind(&policy).to_string()),
    proof_challenge_kind: (policy.mode == PersonProofMode::CustomProvider)
      .then(|| custom_provider_challenge_kind(&policy).to_string()),
    proof_label: custom_provider_proof_label(&policy).map(str::to_string),
    session: challenge.to_string(),
    return_path: fields.return_path.clone(),
    difficulty: policy.difficulty,
    provider_timeout_ms: policy.provider.provider_timeout_ms,
    provider_fail_policy: policy.provider.provider_fail_policy,
    provider_max_response_body_bytes: policy.provider.provider_max_response_body_bytes,
    send_remote_ip: policy.provider.send_remote_ip,
    state: ProviderChallengeState {
      policy,
      token: challenge.to_string(),
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

pub(super) fn complete_provider_challenge(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  challenge: PersonProofProviderChallenge,
) -> anyhow::Result<PersonProofIssuedClearance> {
  let now = now_unix_ms()?;
  if now > challenge.state.expires {
    bail!("person proof challenge token expired");
  }
  issue_clearance(engine, input, &challenge.state, now)
}

pub(super) fn consume_provider_challenge_attempt(
  engine: &PersonProofEngine,
  challenge: &PersonProofProviderChallenge,
) -> anyhow::Result<()> {
  let now = now_unix_ms()?;
  if now > challenge.state.expires {
    bail!("person proof challenge token expired");
  }
  if challenge.state.policy.single_use
    && !engine.mark_challenge_token_used(&challenge.state.token, challenge.state.expires, now)?
  {
    bail!("person proof challenge token was already used");
  }
  Ok(())
}

impl super::WafEngine {
  pub fn consume_person_proof_provider_challenge_attempt(
    &self,
    challenge: &PersonProofProviderChallenge,
  ) -> anyhow::Result<()> {
    consume_provider_challenge_attempt(&self.person_proof, challenge)
  }
}

pub(super) fn verify_clearance(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  proof: &str,
) -> anyhow::Result<PersonProofRequestStatus> {
  let fields = parse_clearance_token(proof)?;
  if fields.mode != policy.mode.as_str() {
    bail!("person proof clearance mode does not match policy");
  }
  if fields.provider != provider_identity(policy) {
    bail!("person proof clearance provider does not match policy");
  }
  if fields.method != input.method.as_str() || fields.route != input.route_name {
    bail!("person proof clearance request context does not match");
  }
  let current_binding_hash = token_binding_hash(input, policy, input.route_name);
  if current_binding_hash != fields.binding_hash {
    bail!("person proof clearance token bindings do not match request");
  }
  verify_clearance_mac(engine, input, policy, &fields)?;

  let now = now_unix_ms()?;
  let mut status = PersonProofRequestStatus {
    state: if now > fields.expires {
      PersonProofState::Expired
    } else {
      PersonProofState::Valid
    },
    mode: Some(policy.mode.as_str()),
    difficulty: None,
    issued_at_unix_ms: Some(fields.issued),
    expires_at_unix_ms: Some(fields.expires),
    policy_key: Some(policy.key.clone()),
    rate_limited: false,
    weight: 0,
    allowed: false,
    clearance_hash: None,
    clearance: None,
  };
  if status.state != PersonProofState::Valid {
    return Ok(status);
  }
  let hash = clearance_hash(proof);
  status.clearance_hash = Some(hash.clone());
  if engine.clearance_revoked(&hash, now)? {
    bail!("person proof clearance token was revoked");
  }
  if policy.single_use {
    if !engine.consume_clearance_token(proof, now)? {
      bail!("person proof clearance token was already used");
    }
    let state = ProviderChallengeState {
      policy: policy.clone(),
      token: proof.to_string(),
      issued: now,
      expires: fields.expires,
      mode: fields.mode,
      provider: fields.provider,
      method: fields.method,
      route_name: fields.route,
      binding_hash: fields.binding_hash,
      random: random_hex(16)?,
    };
    let value = sign_clearance_token(engine, input, &state);
    engine.remember_reuse_token(&clearance_reuse_key(&value), fields.expires, now)?;
    status.clearance = Some(policy.clearance.issue(
      value,
      fields.expires,
      remaining_seconds(now, fields.expires),
    )?);
  }
  Ok(status)
}

fn issue_clearance(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  state: &ProviderChallengeState,
  now: i64,
) -> anyhow::Result<PersonProofIssuedClearance> {
  let value = sign_clearance_token(engine, input, state);
  if state.policy.single_use {
    engine.remember_reuse_token(&clearance_reuse_key(&value), state.expires, now)?;
  }
  state
    .policy
    .clearance
    .issue(value, state.expires, remaining_seconds(now, state.expires))
}

fn sign_clearance_token(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  state: &ProviderChallengeState,
) -> String {
  let payload = clearance_payload(
    input.downstream_host,
    &state.policy,
    &state.provider,
    &state.method,
    &state.route_name,
    &state.binding_hash,
    state.issued,
    state.expires,
    &state.random,
  );
  let mac = hmac::sign(
    &hmac::Key::new(hmac::HMAC_SHA256, &engine.secret),
    payload.as_bytes(),
  );
  format!(
    "clearance.v2.{}.{}.{}.{}.{}.{}.{}.{}.{}",
    state.issued,
    state.expires,
    state.mode,
    hex_encode(state.provider.as_bytes()),
    hex_encode(state.method.as_bytes()),
    hex_encode(state.route_name.as_bytes()),
    state.binding_hash,
    state.random,
    hex_encode(mac.as_ref())
  )
}

fn verify_challenge_mac(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  fields: &ChallengeFields,
  verify_path: &str,
) -> anyhow::Result<()> {
  let payload = challenge_payload(
    input.downstream_host,
    policy,
    &fields.provider,
    &fields.method,
    &fields.route,
    verify_path,
    &fields.return_path,
    &fields.binding_hash,
    fields.issued,
    fields.expires,
    &fields.random,
  );
  verify_mac(engine, &payload, &fields.mac)
}

fn verify_clearance_mac(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  fields: &ClearanceFields,
) -> anyhow::Result<()> {
  let payload = clearance_payload(
    input.downstream_host,
    policy,
    &fields.provider,
    &fields.method,
    &fields.route,
    &fields.binding_hash,
    fields.issued,
    fields.expires,
    &fields.random,
  );
  verify_mac(engine, &payload, &fields.mac)
}

#[allow(clippy::too_many_arguments)]
fn challenge_payload(
  host: &str,
  policy: &PersonProofPolicy,
  provider: &str,
  method: &str,
  route: &str,
  verify_path: &str,
  return_path: &str,
  binding_hash: &str,
  issued: i64,
  expires: i64,
  random: &str,
) -> String {
  format!(
    "challenge.v2\n{}\n{}\n{}\n{}\n{host}\n{method}\n{route}\n{verify_path}\n{return_path}\n{binding_hash}\n{issued}\n{expires}\n{random}",
    policy.mode.as_str(),
    provider,
    policy.key,
    policy.clearance.signing_id()
  )
}

#[allow(clippy::too_many_arguments)]
fn clearance_payload(
  host: &str,
  policy: &PersonProofPolicy,
  provider: &str,
  method: &str,
  route: &str,
  binding_hash: &str,
  issued: i64,
  expires: i64,
  random: &str,
) -> String {
  format!(
    "clearance.v2\n{}\n{}\n{}\n{}\n{host}\n{method}\n{route}\n{binding_hash}\n{issued}\n{expires}\n{random}",
    policy.mode.as_str(),
    provider,
    policy.key,
    policy.clearance.signing_id()
  )
}

fn verify_mac(engine: &PersonProofEngine, payload: &str, mac: &str) -> anyhow::Result<()> {
  let mac = hex_decode(mac)?;
  hmac::verify(
    &hmac::Key::new(hmac::HMAC_SHA256, &engine.secret),
    payload.as_bytes(),
    &mac,
  )
  .map_err(|_| anyhow!("person proof v2 token signature is invalid"))
}

fn parse_challenge_token(token: &str) -> anyhow::Result<ChallengeFields> {
  let parts = token.split('.').collect::<Vec<_>>();
  if parts.len() != 12 || parts[0] != "challenge" || parts[1] != "v2" {
    bail!("person proof challenge token has invalid shape");
  }
  Ok(ChallengeFields {
    issued: parts[2]
      .parse()
      .context("invalid challenge issued timestamp")?,
    expires: parts[3]
      .parse()
      .context("invalid challenge expiration timestamp")?,
    mode: parts[4].to_string(),
    provider: decode_hex_string(parts[5])?,
    method: decode_hex_string(parts[6])?,
    route: decode_hex_string(parts[7])?,
    return_path: decode_hex_string(parts[8])?,
    binding_hash: validate_hex_field(parts[9], "challenge binding hash", 64)?,
    random: validate_hex_field(parts[10], "challenge random", 32)?,
    mac: parts[11].to_string(),
  })
}

fn parse_clearance_token(token: &str) -> anyhow::Result<ClearanceFields> {
  let parts = token.split('.').collect::<Vec<_>>();
  if parts.len() != 11 || parts[0] != "clearance" || parts[1] != "v2" {
    bail!("person proof clearance token has invalid shape");
  }
  Ok(ClearanceFields {
    issued: parts[2]
      .parse()
      .context("invalid clearance issued timestamp")?,
    expires: parts[3]
      .parse()
      .context("invalid clearance expiration timestamp")?,
    mode: parts[4].to_string(),
    provider: decode_hex_string(parts[5])?,
    method: decode_hex_string(parts[6])?,
    route: decode_hex_string(parts[7])?,
    binding_hash: validate_hex_field(parts[8], "clearance binding hash", 64)?,
    random: validate_hex_field(parts[9], "clearance random", 32)?,
    mac: parts[10].to_string(),
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

fn append_query(base: &str, pairs: Vec<(&str, &str)>) -> String {
  let query = form_urlencoded::Serializer::new(String::new())
    .extend_pairs(pairs)
    .finish();
  let separator = if base.contains('?') {
    if base.ends_with('?') || base.ends_with('&') {
      ""
    } else {
      "&"
    }
  } else {
    "?"
  };
  format!("{base}{separator}{query}")
}

pub(super) fn request_return_path(input: WafRequestInput<'_>) -> String {
  input
    .uri
    .path_and_query()
    .map(|path| path.as_str().to_string())
    .filter(|path| path.starts_with('/'))
    .unwrap_or_else(|| "/".to_string())
}
