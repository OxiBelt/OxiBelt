use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use http::header::{CACHE_CONTROL, CONTENT_TYPE, SET_COOKIE, VARY};
use http::{HeaderName, HeaderValue, StatusCode};
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use crate::config::Config;

use super::{
  HeaderMutation, PersonProofAlgorithm, WafActionConfig, WafRequestInput, WafTerminalResponse,
};

#[derive(Clone)]
pub(super) struct PersonProofEngine {
  secret: [u8; 32],
  policies: Vec<PersonProofPolicy>,
}

#[derive(Debug, Clone)]
pub(super) struct PersonProofPolicy {
  pub algorithm: PersonProofAlgorithm,
  pub difficulty: u8,
  pub ttl_seconds: u64,
  pub cookie: String,
  pub success_tag: Option<String>,
  pub status: u16,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum PersonProofState {
  Absent,
  Valid,
  Failed,
  Expired,
}

impl PersonProofState {
  pub(super) fn as_str(self) -> &'static str {
    match self {
      Self::Absent => "absent",
      Self::Valid => "valid",
      Self::Failed => "failed",
      Self::Expired => "expired",
    }
  }
}

#[derive(Debug, Clone)]
pub(super) struct PersonProofRequestStatus {
  pub state: PersonProofState,
  pub method: Option<&'static str>,
  pub difficulty: Option<u8>,
  pub issued_at_unix_ms: Option<i64>,
  pub expires_at_unix_ms: Option<i64>,
  cookie: Option<String>,
  clearance: Option<PersonProofClearance>,
}

#[derive(Debug, Clone)]
struct PersonProofClearance {
  cookie: String,
  value: String,
  max_age_seconds: u64,
}

struct TokenFields<'a> {
  issued: i64,
  expires: i64,
  difficulty: u8,
  random: &'a str,
  mac: &'a str,
}

impl Default for PersonProofRequestStatus {
  fn default() -> Self {
    Self {
      state: PersonProofState::Absent,
      method: None,
      difficulty: None,
      issued_at_unix_ms: None,
      expires_at_unix_ms: None,
      cookie: None,
      clearance: None,
    }
  }
}

impl PersonProofEngine {
  pub(super) fn from_config(config: &Config) -> anyhow::Result<Self> {
    let mut secret = [0u8; 32];
    SystemRandom::new()
      .fill(&mut secret)
      .map_err(|_| anyhow!("failed to generate WAF person proof secret"))?;

    let mut policies = Vec::new();
    collect_policies(&config.waf.rules, &mut policies);
    for route in &config.routes {
      collect_policies(&route.waf.rules, &mut policies);
    }

    Ok(Self { secret, policies })
  }

  pub(super) fn evaluate_request(&self, input: WafRequestInput<'_>) -> PersonProofRequestStatus {
    let mut failed = None;
    let mut expired = None;

    for policy in &self.policies {
      let Some(cookie_value) = find_cookie(input.headers, &policy.cookie) else {
        continue;
      };
      match self.verify_proof(input, policy, cookie_value) {
        Ok(status) if status.state == PersonProofState::Valid => return status,
        Ok(status) if status.state == PersonProofState::Expired => expired = Some(status),
        Ok(status) => failed = Some(status),
        Err(_) => {
          failed = Some(PersonProofRequestStatus {
            state: PersonProofState::Failed,
            method: Some(policy.algorithm.as_str()),
            difficulty: Some(policy.difficulty),
            issued_at_unix_ms: None,
            expires_at_unix_ms: None,
            cookie: Some(policy.cookie.clone()),
            clearance: None,
          });
        }
      }
    }

    failed.or(expired).unwrap_or_default()
  }

  pub(super) fn success_tag_for<'a>(
    &'a self,
    status: &PersonProofRequestStatus,
  ) -> Option<&'a str> {
    if status.state != PersonProofState::Valid {
      return None;
    }
    let cookie = status.cookie.as_ref()?;
    self
      .policies
      .iter()
      .find(|policy| &policy.cookie == cookie)
      .and_then(|policy| policy.success_tag.as_deref())
  }

  pub(super) fn clearance_cookie_mutation(
    &self,
    status: &PersonProofRequestStatus,
  ) -> anyhow::Result<Option<HeaderMutation>> {
    let Some(clearance) = status.clearance.as_ref() else {
      return Ok(None);
    };
    let cookie = format!(
      "{}={}; Max-Age={}; Path=/; SameSite=Lax; Secure; HttpOnly",
      clearance.cookie, clearance.value, clearance.max_age_seconds
    );
    Ok(Some(HeaderMutation::Append {
      name: SET_COOKIE,
      value: HeaderValue::from_str(&cookie).context("invalid person proof clearance cookie")?,
    }))
  }

  pub(super) fn issue_challenge(
    &self,
    input: WafRequestInput<'_>,
    policy: PersonProofPolicy,
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
    let token = self.sign_token(input, &policy, now, expires, &random);
    let csp_nonce = random_hex(16)?;
    let body = challenge_html(&policy, &token, expires, &csp_nonce);
    let mut response = WafTerminalResponse {
      status: StatusCode::from_u16(policy.status)?,
      body,
      headers: Vec::new(),
    };
    response.headers.push(HeaderMutation::Set {
      name: CONTENT_TYPE,
      value: HeaderValue::from_static("text/html; charset=utf-8"),
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
      value: HeaderValue::from_static("pow_sha256_v1"),
    });
    response
      .headers
      .extend(challenge_security_headers(input, &csp_nonce)?);
    Ok(response)
  }

  fn verify_proof(
    &self,
    input: WafRequestInput<'_>,
    policy: &PersonProofPolicy,
    proof: &str,
  ) -> anyhow::Result<PersonProofRequestStatus> {
    if proof.starts_with("clearance.") {
      return self.verify_clearance(input, policy, proof);
    }

    let (token, nonce) = proof
      .rsplit_once('.')
      .ok_or_else(|| anyhow!("person proof is missing nonce"))?;
    if nonce.is_empty() || nonce.len() > 20 || !nonce.bytes().all(|byte| byte.is_ascii_digit()) {
      bail!("person proof nonce is invalid");
    }

    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 6 {
      bail!("person proof token has invalid shape");
    }
    if parts[0] != "v1" {
      bail!("person proof token has unsupported version");
    }

    let fields = TokenFields {
      issued: parts[1]
        .parse::<i64>()
        .context("invalid issued timestamp")?,
      expires: parts[2]
        .parse::<i64>()
        .context("invalid expiration timestamp")?,
      difficulty: parts[3].parse::<u8>().context("invalid difficulty")?,
      random: parts[4],
      mac: parts[5],
    };

    if fields.difficulty != policy.difficulty {
      bail!("person proof difficulty does not match policy");
    }
    if fields.random.len() != 32 || !fields.random.bytes().all(|byte| byte.is_ascii_hexdigit()) {
      bail!("person proof random field is invalid");
    }

    self.verify_token_mac(input, policy, &fields)?;

    let now = now_unix_ms()?;
    let mut status = PersonProofRequestStatus {
      state: PersonProofState::Failed,
      method: Some(policy.algorithm.as_str()),
      difficulty: Some(fields.difficulty),
      issued_at_unix_ms: Some(fields.issued),
      expires_at_unix_ms: Some(fields.expires),
      cookie: Some(policy.cookie.clone()),
      clearance: None,
    };

    if now > fields.expires {
      status.state = PersonProofState::Expired;
      return Ok(status);
    }
    if fields.issued > now.saturating_add(60_000) {
      bail!("person proof token was issued in the future");
    }

    if hash_meets_difficulty(format!("{token}.{nonce}").as_bytes(), fields.difficulty) {
      status.state = PersonProofState::Valid;
      status.clearance = Some(PersonProofClearance {
        cookie: policy.cookie.clone(),
        value: self.sign_clearance_token(input, policy, &fields),
        max_age_seconds: remaining_seconds(now, fields.expires),
      });
    }
    Ok(status)
  }

  fn sign_token(
    &self,
    input: WafRequestInput<'_>,
    policy: &PersonProofPolicy,
    issued: i64,
    expires: i64,
    random: &str,
  ) -> String {
    let payload = token_payload(input, policy, issued, expires, policy.difficulty, random);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
    let mac = hmac::sign(&key, payload.as_bytes());
    format!(
      "v1.{issued}.{expires}.{}.{}.{}",
      policy.difficulty,
      random,
      hex_encode(mac.as_ref())
    )
  }

  fn verify_token_mac(
    &self,
    input: WafRequestInput<'_>,
    policy: &PersonProofPolicy,
    fields: &TokenFields<'_>,
  ) -> anyhow::Result<()> {
    let mac = hex_decode(fields.mac)?;
    let payload = token_payload(
      input,
      policy,
      fields.issued,
      fields.expires,
      fields.difficulty,
      fields.random,
    );
    let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
    hmac::verify(&key, payload.as_bytes(), &mac)
      .map_err(|_| anyhow!("person proof token signature is invalid"))
  }

  fn sign_clearance_token(
    &self,
    input: WafRequestInput<'_>,
    policy: &PersonProofPolicy,
    fields: &TokenFields<'_>,
  ) -> String {
    let payload = clearance_payload(input, policy, fields);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
    let mac = hmac::sign(&key, payload.as_bytes());
    format!(
      "clearance.v1.{}.{}.{}.{}.{}",
      fields.issued,
      fields.expires,
      fields.difficulty,
      fields.random,
      hex_encode(mac.as_ref())
    )
  }

  fn verify_clearance(
    &self,
    input: WafRequestInput<'_>,
    policy: &PersonProofPolicy,
    proof: &str,
  ) -> anyhow::Result<PersonProofRequestStatus> {
    let parts = proof.split('.').collect::<Vec<_>>();
    if parts.len() != 7 || parts[0] != "clearance" || parts[1] != "v1" {
      bail!("person proof clearance token has invalid shape");
    }

    let fields = TokenFields {
      issued: parts[2]
        .parse::<i64>()
        .context("invalid clearance issued timestamp")?,
      expires: parts[3]
        .parse::<i64>()
        .context("invalid clearance expiration timestamp")?,
      difficulty: parts[4]
        .parse::<u8>()
        .context("invalid clearance difficulty")?,
      random: parts[5],
      mac: parts[6],
    };

    if fields.difficulty != policy.difficulty {
      bail!("person proof clearance difficulty does not match policy");
    }
    if fields.random.len() != 32 || !fields.random.bytes().all(|byte| byte.is_ascii_hexdigit()) {
      bail!("person proof clearance random field is invalid");
    }

    let mac = hex_decode(fields.mac)?;
    let payload = clearance_payload(input, policy, &fields);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
    hmac::verify(&key, payload.as_bytes(), &mac)
      .map_err(|_| anyhow!("person proof clearance signature is invalid"))?;

    let now = now_unix_ms()?;
    let state = if now > fields.expires {
      PersonProofState::Expired
    } else {
      PersonProofState::Valid
    };

    Ok(PersonProofRequestStatus {
      state,
      method: Some(policy.algorithm.as_str()),
      difficulty: Some(fields.difficulty),
      issued_at_unix_ms: Some(fields.issued),
      expires_at_unix_ms: Some(fields.expires),
      cookie: Some(policy.cookie.clone()),
      clearance: None,
    })
  }
}

fn collect_policies(rules: &[super::WafRuleConfig], policies: &mut Vec<PersonProofPolicy>) {
  for rule in rules {
    for action in &rule.actions {
      if let WafActionConfig::RequirePersonProof {
        algorithm,
        difficulty,
        ttl_seconds,
        cookie,
        success_tag,
        status,
      } = action
      {
        policies.push(PersonProofPolicy {
          algorithm: *algorithm,
          difficulty: *difficulty,
          ttl_seconds: *ttl_seconds,
          cookie: cookie.clone(),
          success_tag: success_tag.clone(),
          status: *status,
        });
      }
    }
  }
}

fn token_payload(
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  issued: i64,
  expires: i64,
  difficulty: u8,
  random: &str,
) -> String {
  let user_agent = input
    .headers
    .get(http::header::USER_AGENT)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  format!(
    "v1\n{}\n{issued}\n{expires}\n{difficulty}\n{}\n{}\n{}\n{}\n{}\n{random}",
    policy.algorithm.as_str(),
    policy.cookie,
    input.route_name,
    input.downstream_host,
    input.method.as_str(),
    user_agent
  )
}

fn clearance_payload(
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  fields: &TokenFields<'_>,
) -> String {
  let user_agent = input
    .headers
    .get(http::header::USER_AGENT)
    .and_then(|value| value.to_str().ok())
    .unwrap_or_default();
  format!(
    "clearance\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
    policy.algorithm.as_str(),
    policy.cookie,
    input.route_name,
    input.downstream_host,
    user_agent,
    fields.issued,
    fields.expires,
    fields.difficulty,
    fields.random
  )
}

fn find_cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
  headers
    .get_all(http::header::COOKIE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(';'))
    .filter_map(|part| part.trim().split_once('='))
    .find_map(|(cookie_name, cookie_value)| {
      (cookie_name.trim() == name).then(|| cookie_value.trim())
    })
}

fn challenge_html(
  policy: &PersonProofPolicy,
  token: &str,
  expires: i64,
  csp_nonce: &str,
) -> String {
  let token_js = js_escape(token);
  let cookie_js = js_escape(&policy.cookie);
  let algorithm = html_escape(policy.algorithm.as_str());
  let token_html = html_escape(token);
  let cookie_html = html_escape(&policy.cookie);
  let csp_nonce_html = html_escape(csp_nonce);
  include_str!("../../assets/person-proof-challenge.html")
    .replace("__TOKEN_HTML__", &token_html)
    .replace("__TOKEN_JS__", &token_js)
    .replace("__COOKIE_HTML__", &cookie_html)
    .replace("__COOKIE_JS__", &cookie_js)
    .replace("__ALGORITHM__", &algorithm)
    .replace("__DIFFICULTY__", &policy.difficulty.to_string())
    .replace("__TTL_SECONDS__", &policy.ttl_seconds.to_string())
    .replace("__EXPIRES_UNIX_MS__", &expires.to_string())
    .replace("__CSP_NONCE__", &csp_nonce_html)
}

fn challenge_security_headers(
  input: WafRequestInput<'_>,
  csp_nonce: &str,
) -> anyhow::Result<Vec<HeaderMutation>> {
  let protected_origin = format!("https://{}", input.downstream_host);
  let csp = format!(
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'none'; connect-src 'none'; script-src 'nonce-{csp_nonce}'; style-src 'nonce-{csp_nonce}' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; upgrade-insecure-requests"
  );

  Ok(vec![
    header_set("access-control-allow-origin", &protected_origin)?,
    header_set("access-control-allow-credentials", "true")?,
    header_set("access-control-allow-methods", "GET, HEAD, OPTIONS")?,
    header_set(
      "access-control-allow-headers",
      "accept, accept-language, content-type, cookie, user-agent",
    )?,
    header_set("access-control-max-age", "600")?,
    HeaderMutation::Append {
      name: VARY,
      value: HeaderValue::from_static("Origin"),
    },
    header_set("cross-origin-resource-policy", "same-origin")?,
    header_set("content-security-policy", &csp)?,
  ])
}

fn header_set(name: &'static str, value: &str) -> anyhow::Result<HeaderMutation> {
  Ok(HeaderMutation::Set {
    name: HeaderName::from_static(name),
    value: HeaderValue::from_str(value).with_context(|| format!("invalid {name} header value"))?,
  })
}

fn hash_meets_difficulty(input: &[u8], difficulty: u8) -> bool {
  let digest = digest::digest(&digest::SHA256, input);
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

fn random_hex(bytes: usize) -> anyhow::Result<String> {
  let mut value = vec![0u8; bytes];
  SystemRandom::new()
    .fill(&mut value)
    .map_err(|_| anyhow!("failed to generate person proof challenge random data"))?;
  Ok(hex_encode(&value))
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

fn hex_decode(value: &str) -> anyhow::Result<Vec<u8>> {
  if !value.len().is_multiple_of(2) {
    bail!("hex value has odd length");
  }
  value
    .as_bytes()
    .chunks_exact(2)
    .map(|pair| {
      let high = hex_nibble(pair[0])?;
      let low = hex_nibble(pair[1])?;
      Ok((high << 4) | low)
    })
    .collect()
}

fn hex_nibble(byte: u8) -> anyhow::Result<u8> {
  match byte {
    b'0'..=b'9' => Ok(byte - b'0'),
    b'a'..=b'f' => Ok(byte - b'a' + 10),
    b'A'..=b'F' => Ok(byte - b'A' + 10),
    _ => bail!("invalid hex digit"),
  }
}

fn html_escape(value: &str) -> String {
  value
    .replace('&', "&amp;")
    .replace('<', "&lt;")
    .replace('>', "&gt;")
    .replace('"', "&quot;")
    .replace('\'', "&#39;")
}

fn js_escape(value: &str) -> String {
  value
    .replace('\\', "\\\\")
    .replace('"', "\\\"")
    .replace('\'', "\\'")
    .replace('<', "\\u003c")
    .replace('\n', "\\n")
    .replace('\r', "\\r")
}

fn now_unix_ms() -> anyhow::Result<i64> {
  let duration = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system clock is before Unix epoch")?;
  i64::try_from(duration.as_millis()).context("Unix timestamp does not fit in i64")
}

fn remaining_seconds(now_unix_ms: i64, expires_unix_ms: i64) -> u64 {
  expires_unix_ms
    .saturating_sub(now_unix_ms)
    .try_into()
    .map(|millis: u64| millis.div_ceil(1000))
    .unwrap_or(0)
}
