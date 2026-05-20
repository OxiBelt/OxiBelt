use anyhow::{Context, anyhow, bail};
use http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use http::{HeaderName, HeaderValue, StatusCode};
use ring::{digest, hmac};
use url::form_urlencoded;

use super::person_proof::{
  PersonProofEngine, PersonProofPolicy, PersonProofRequestStatus, PersonProofState,
  challenge_reuse_key, clearance_reuse_key, hex_decode, hex_encode, now_unix_ms, random_hex,
  remaining_seconds, token_binding_payload_for_route,
};
use super::{
  HeaderMutation, PersonProofAlgorithm, PersonProofProviderFailPolicy, WafRequestInput,
  WafTerminalResponse,
};

#[derive(Debug, Clone)]
pub(super) struct PersonProofProviderConfig {
  pub challenge_url: Option<String>,
  pub challenge_redirect_status: u16,
  pub verify_path: Option<String>,
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
  pub method: PersonProofAlgorithm,
  pub endpoint: url::Url,
  pub site_key: String,
  pub secret_env: String,
  pub provider_timeout_ms: u64,
  pub provider_fail_policy: PersonProofProviderFailPolicy,
  pub provider_max_response_body_bytes: usize,
  pub send_remote_ip: bool,
  state: ProviderChallengeState,
}

#[derive(Debug, Clone)]
struct ProviderChallengeState {
  policy: PersonProofPolicy,
  token: String,
  issued: i64,
  expires: i64,
  method: String,
  route_name: String,
  binding_hash: String,
  random: String,
}

struct ChallengeFields {
  issued: i64,
  expires: i64,
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
  let challenge = if policy.method == PersonProofAlgorithm::PowSha256V1 {
    engine.sign_token(input, policy, now, expires, &random)
  } else {
    sign_challenge_token(engine, input, policy, now, expires, &return_path, &random)
  };

  if policy.single_use
    && let Err(error) = engine.remember_reuse_token(&challenge_reuse_key(&challenge), expires, now)
  {
    if error
      .to_string()
      .contains("person proof reuse token capacity exhausted")
    {
      return Ok(WafTerminalResponse::new(
        StatusCode::TOO_MANY_REQUESTS,
        "person proof token capacity exhausted".to_string(),
      ));
    }
    return Err(error);
  }

  let expires_string = expires.to_string();
  let difficulty_string = policy.difficulty.to_string();
  let mut pairs = vec![
    ("challenge", challenge.as_str()),
    ("return_path", return_path.as_str()),
    ("method", policy.method.as_str()),
    ("expires_unix_ms", expires_string.as_str()),
  ];
  if let Some(verify_path) = policy.provider.verify_path.as_deref() {
    pairs.push(("verify_path", verify_path));
  }
  if let Some(site_key) = policy.provider.site_key.as_deref() {
    pairs.push(("site_key", site_key));
  }
  if policy.method == PersonProofAlgorithm::PowSha256V1 {
    pairs.push(("cookie", policy.cookie.as_str()));
    pairs.push(("difficulty", difficulty_string.as_str()));
  }

  let location = append_query(
    policy
      .provider
      .challenge_url
      .as_deref()
      .context("person proof redirect requires challenge_url")?,
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
    value: HeaderValue::from_str(policy.method.as_str())
      .context("invalid person proof method header")?,
  });
  Ok(response)
}

pub(super) fn begin_provider_challenge(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  verify_path: &str,
  challenge: &str,
) -> anyhow::Result<Option<PersonProofProviderChallenge>> {
  let Some(policy) = engine
    .policies
    .iter()
    .find(|policy| {
      policy.provider.verify_path.as_deref() == Some(verify_path) && policy.method.is_provider()
    })
    .cloned()
  else {
    return Ok(None);
  };

  let fields = parse_challenge_token(challenge)?;
  if fields.provider != policy.method.as_str() {
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
    method: policy.method,
    endpoint: provider_endpoint(&policy),
    site_key: policy
      .provider
      .site_key
      .clone()
      .context("person proof provider challenge requires site_key")?,
    secret_env: policy
      .provider
      .secret_env
      .clone()
      .context("person proof provider challenge requires secret_env")?,
    provider_timeout_ms: policy.provider.provider_timeout_ms,
    provider_fail_policy: policy.provider.provider_fail_policy,
    provider_max_response_body_bytes: policy.provider.provider_max_response_body_bytes,
    send_remote_ip: policy.provider.send_remote_ip,
    state: ProviderChallengeState {
      policy,
      token: challenge.to_string(),
      issued: fields.issued,
      expires: fields.expires,
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
) -> anyhow::Result<HeaderMutation> {
  let now = now_unix_ms()?;
  if now > challenge.state.expires {
    bail!("person proof challenge token expired");
  }
  if challenge.state.policy.single_use
    && !engine.consume_reuse_token(&challenge_reuse_key(&challenge.state.token), now)?
  {
    bail!("person proof challenge token was already used");
  }
  issue_clearance(engine, input, &challenge.state, now)
}

pub(super) fn verify_clearance(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  proof: &str,
) -> anyhow::Result<PersonProofRequestStatus> {
  let fields = parse_clearance_token(proof)?;
  if fields.provider != policy.method.as_str() {
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
    method: Some(policy.method.as_str()),
    difficulty: None,
    issued_at_unix_ms: Some(fields.issued),
    expires_at_unix_ms: Some(fields.expires),
    policy_key: Some(policy.key.clone()),
    rate_limited: false,
    clearance: None,
  };
  if status.state != PersonProofState::Valid {
    return Ok(status);
  }
  if policy.single_use {
    if !engine.consume_reuse_token(&clearance_reuse_key(proof), now)? {
      bail!("person proof clearance token was already used");
    }
    let state = ProviderChallengeState {
      policy: policy.clone(),
      token: proof.to_string(),
      issued: now,
      expires: fields.expires,
      method: fields.method,
      route_name: fields.route,
      binding_hash: fields.binding_hash,
      random: random_hex(16)?,
    };
    status.clearance = Some(super::person_proof::PersonProofClearance {
      cookie: policy.cookie.clone(),
      value: sign_clearance_token(engine, input, &state),
      max_age_seconds: remaining_seconds(now, fields.expires),
    });
  }
  Ok(status)
}

fn issue_clearance(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  state: &ProviderChallengeState,
  now: i64,
) -> anyhow::Result<HeaderMutation> {
  let value = sign_clearance_token(engine, input, state);
  if state.policy.single_use {
    engine.remember_reuse_token(&clearance_reuse_key(&value), state.expires, now)?;
  }
  let cookie = format!(
    "{}={}; Max-Age={}; Path=/; SameSite=Lax; Secure; HttpOnly",
    state.policy.cookie,
    value,
    remaining_seconds(now, state.expires)
  );
  Ok(HeaderMutation::Append {
    name: SET_COOKIE,
    value: HeaderValue::from_str(&cookie).context("invalid person proof clearance cookie")?,
  })
}

fn sign_challenge_token(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  issued: i64,
  expires: i64,
  return_path: &str,
  random: &str,
) -> String {
  let binding_hash = token_binding_hash(input, policy, input.route_name);
  let payload = challenge_payload(
    input.downstream_host,
    policy,
    input.method.as_str(),
    input.route_name,
    policy.provider.verify_path.as_deref().unwrap_or_default(),
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
    "challenge.v2.{issued}.{expires}.{}.{}.{}.{}.{}.{}.{}",
    policy.method.as_str(),
    hex_encode(input.method.as_str().as_bytes()),
    hex_encode(input.route_name.as_bytes()),
    hex_encode(return_path.as_bytes()),
    binding_hash,
    random,
    hex_encode(mac.as_ref())
  )
}

fn sign_clearance_token(
  engine: &PersonProofEngine,
  input: WafRequestInput<'_>,
  state: &ProviderChallengeState,
) -> String {
  let payload = clearance_payload(
    input.downstream_host,
    &state.policy,
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
    "clearance.v2.{}.{}.{}.{}.{}.{}.{}.{}",
    state.issued,
    state.expires,
    state.policy.method.as_str(),
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
    "challenge.v2\n{}\n{}\n{}\n{host}\n{method}\n{route}\n{verify_path}\n{return_path}\n{binding_hash}\n{issued}\n{expires}\n{random}",
    policy.method.as_str(),
    policy.key,
    policy.cookie
  )
}

#[allow(clippy::too_many_arguments)]
fn clearance_payload(
  host: &str,
  policy: &PersonProofPolicy,
  method: &str,
  route: &str,
  binding_hash: &str,
  issued: i64,
  expires: i64,
  random: &str,
) -> String {
  format!(
    "clearance.v2\n{}\n{}\n{}\n{host}\n{method}\n{route}\n{binding_hash}\n{issued}\n{expires}\n{random}",
    policy.method.as_str(),
    policy.key,
    policy.cookie
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
  if parts.len() != 11 || parts[0] != "challenge" || parts[1] != "v2" {
    bail!("person proof challenge token has invalid shape");
  }
  Ok(ChallengeFields {
    issued: parts[2]
      .parse()
      .context("invalid challenge issued timestamp")?,
    expires: parts[3]
      .parse()
      .context("invalid challenge expiration timestamp")?,
    provider: parts[4].to_string(),
    method: decode_hex_string(parts[5])?,
    route: decode_hex_string(parts[6])?,
    return_path: decode_hex_string(parts[7])?,
    binding_hash: validate_hex_field(parts[8], "challenge binding hash", 64)?,
    random: validate_hex_field(parts[9], "challenge random", 32)?,
    mac: parts[10].to_string(),
  })
}

fn parse_clearance_token(token: &str) -> anyhow::Result<ClearanceFields> {
  let parts = token.split('.').collect::<Vec<_>>();
  if parts.len() != 10 || parts[0] != "clearance" || parts[1] != "v2" {
    bail!("person proof clearance token has invalid shape");
  }
  Ok(ClearanceFields {
    issued: parts[2]
      .parse()
      .context("invalid clearance issued timestamp")?,
    expires: parts[3]
      .parse()
      .context("invalid clearance expiration timestamp")?,
    provider: parts[4].to_string(),
    method: decode_hex_string(parts[5])?,
    route: decode_hex_string(parts[6])?,
    binding_hash: validate_hex_field(parts[7], "clearance binding hash", 64)?,
    random: validate_hex_field(parts[8], "clearance random", 32)?,
    mac: parts[9].to_string(),
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

fn request_return_path(input: WafRequestInput<'_>) -> String {
  input
    .uri
    .path_and_query()
    .map(|path| path.as_str().to_string())
    .filter(|path| path.starts_with('/'))
    .unwrap_or_else(|| "/".to_string())
}

fn provider_endpoint(policy: &PersonProofPolicy) -> url::Url {
  policy
    .provider
    .provider_endpoint
    .clone()
    .unwrap_or_else(|| {
      url::Url::parse(match policy.method {
        PersonProofAlgorithm::PowSha256V1 => "https://invalid.example/",
        PersonProofAlgorithm::Turnstile => {
          "https://challenges.cloudflare.com/turnstile/v0/siteverify"
        }
        PersonProofAlgorithm::HCaptcha => "https://api.hcaptcha.com/siteverify",
        PersonProofAlgorithm::FriendlyCaptchaV2 => {
          "https://global.frcapi.com/api/v2/captcha/siteverify"
        }
      })
      .expect("built-in provider endpoint must be valid")
    })
}
