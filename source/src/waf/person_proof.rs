use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use http::header::{CACHE_CONTROL, CONTENT_TYPE, SET_COOKIE, VARY};
use http::{HeaderName, HeaderValue, StatusCode};
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use super::{
  HeaderMutation, PersonProofAlgorithm, PersonProofTokenBinding, WafRequestInput,
  WafTerminalResponse,
};
use crate::shared_state::SharedState;

#[derive(Clone)]
pub(super) struct PersonProofEngine {
  secret: [u8; 32],
  policies: Vec<PersonProofPolicy>,
  active_reuse_tokens: Arc<Mutex<HashMap<String, i64>>>,
  max_reuse_tokens: usize,
  shared_state: Option<Arc<SharedState>>,
}

#[derive(Debug, Clone)]
pub(super) struct PersonProofPolicy {
  pub key: String,
  pub algorithm: PersonProofAlgorithm,
  pub difficulty: u8,
  pub ttl_seconds: u64,
  pub cookie: String,
  pub token_bindings: Vec<PersonProofTokenBinding>,
  pub direct_peer_ipv4_prefix_bits: u8,
  pub direct_peer_ipv6_prefix_bits: u8,
  pub tcp_max_hop: Option<u8>,
  pub single_use: bool,
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
  pub policy_key: Option<String>,
  pub rate_limited: bool,
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
      policy_key: None,
      rate_limited: false,
      clearance: None,
    }
  }
}

impl PersonProofEngine {
  pub(super) fn from_policies_with_previous(
    policies: Vec<PersonProofPolicy>,
    max_reuse_tokens: usize,
    previous: Option<&Self>,
    shared_state: Option<Arc<SharedState>>,
  ) -> anyhow::Result<Self> {
    let mut secret = [0u8; 32];
    let active_reuse_tokens = if let Some(previous) = previous {
      secret = previous.secret;
      previous.active_reuse_tokens.clone()
    } else {
      SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| anyhow!("failed to generate WAF person proof secret"))?;
      Arc::new(Mutex::new(HashMap::new()))
    };
    if let Some(shared) = &shared_state
      && let Some(shared_secret) = shared.person_proof_secret()?
    {
      secret = shared_secret;
    }

    Ok(Self {
      secret,
      policies,
      active_reuse_tokens,
      max_reuse_tokens,
      shared_state,
    })
  }

  pub(super) fn tcp_max_hop(&self) -> Option<u8> {
    self
      .policies
      .iter()
      .filter_map(|policy| policy.tcp_max_hop)
      .min()
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
        Err(error) => {
          failed = Some(PersonProofRequestStatus {
            state: PersonProofState::Failed,
            method: Some(policy.algorithm.as_str()),
            difficulty: Some(policy.difficulty),
            issued_at_unix_ms: None,
            expires_at_unix_ms: None,
            policy_key: Some(policy.key.clone()),
            rate_limited: is_reuse_capacity_error(&error),
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
    let policy_key = status.policy_key.as_ref()?;
    self
      .policies
      .iter()
      .find(|policy| &policy.key == policy_key)
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
    if policy.single_use
      && let Err(error) = self.remember_reuse_token(&challenge_reuse_key(&token), expires, now)
    {
      if is_reuse_capacity_error(&error) {
        return Ok(person_proof_rate_limited_response());
      }
      return Err(error);
    }
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
      policy_key: Some(policy.key.clone()),
      rate_limited: false,
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
      if policy.single_use && !self.consume_reuse_token(&challenge_reuse_key(token), now)? {
        bail!("person proof challenge token was already used");
      }
      status.state = PersonProofState::Valid;
      status.clearance = Some(self.issue_clearance(input, policy, &fields, now)?);
    }
    Ok(status)
  }

  fn issue_clearance(
    &self,
    input: WafRequestInput<'_>,
    policy: &PersonProofPolicy,
    fields: &TokenFields<'_>,
    now: i64,
  ) -> anyhow::Result<PersonProofClearance> {
    let value = self.sign_clearance_token(input, policy, fields);

    if policy.single_use {
      self.remember_reuse_token(&clearance_reuse_key(&value), fields.expires, now)?;
    }

    Ok(PersonProofClearance {
      cookie: policy.cookie.clone(),
      value,
      max_age_seconds: remaining_seconds(now, fields.expires),
    })
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
    let mut status = PersonProofRequestStatus {
      state: if now > fields.expires {
        PersonProofState::Expired
      } else {
        PersonProofState::Valid
      },
      method: Some(policy.algorithm.as_str()),
      difficulty: Some(fields.difficulty),
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
      if !self.consume_reuse_token(&clearance_reuse_key(proof), now)? {
        bail!("person proof clearance token was already used");
      }

      let random = random_hex(16)?;
      let rotated_fields = TokenFields {
        issued: now,
        expires: fields.expires,
        difficulty: fields.difficulty,
        random: &random,
        mac: "",
      };
      status.clearance = Some(self.issue_clearance(input, policy, &rotated_fields, now)?);
    }

    Ok(status)
  }

  fn remember_reuse_token(&self, key: &str, expires: i64, now: i64) -> anyhow::Result<()> {
    if let Some(shared) = &self.shared_state {
      if !shared.person_proof_remember(key, expires)? {
        bail!("person proof token is already active");
      }
      return Ok(());
    }
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    if !active.contains_key(key) && active.len() >= self.max_reuse_tokens {
      bail!("{PERSON_PROOF_REUSE_CAPACITY_ERROR}");
    }
    active.insert(key.to_string(), expires);
    Ok(())
  }

  fn consume_reuse_token(&self, key: &str, now: i64) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state {
      return shared.person_proof_consume(key);
    }
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    Ok(active.remove(key).is_some())
  }
}

const PERSON_PROOF_REUSE_CAPACITY_ERROR: &str = "person proof reuse token capacity exhausted";

fn is_reuse_capacity_error(error: &anyhow::Error) -> bool {
  error
    .to_string()
    .contains(PERSON_PROOF_REUSE_CAPACITY_ERROR)
}

fn person_proof_rate_limited_response() -> WafTerminalResponse {
  WafTerminalResponse::new(
    StatusCode::TOO_MANY_REQUESTS,
    "person proof token capacity exhausted".to_string(),
  )
}

fn token_payload(
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  issued: i64,
  expires: i64,
  difficulty: u8,
  random: &str,
) -> String {
  let token_bindings = token_binding_payload(input, policy);
  format!(
    "v1\n{}\n{}\n{issued}\n{expires}\n{difficulty}\n{}\n{}\n{}\n{token_bindings}\n{random}",
    policy.algorithm.as_str(),
    policy.key,
    policy.cookie,
    input.downstream_host,
    input.method.as_str()
  )
}

fn clearance_payload(
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  fields: &TokenFields<'_>,
) -> String {
  let token_bindings = token_binding_payload(input, policy);
  format!(
    "clearance\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{token_bindings}\n{}",
    policy.algorithm.as_str(),
    policy.key,
    policy.cookie,
    input.downstream_host,
    input.method.as_str(),
    fields.issued,
    fields.expires,
    fields.difficulty,
    fields.random
  )
}

fn token_binding_payload(input: WafRequestInput<'_>, policy: &PersonProofPolicy) -> String {
  policy
    .token_bindings
    .iter()
    .map(|binding| {
      format!(
        "{}={}",
        binding.as_str(),
        token_binding_value(input, policy, *binding)
      )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn token_binding_value(
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  binding: PersonProofTokenBinding,
) -> String {
  match binding {
    PersonProofTokenBinding::UserAgent => input
      .headers
      .get(http::header::USER_AGENT)
      .and_then(|value| value.to_str().ok())
      .unwrap_or_default()
      .to_string(),
    PersonProofTokenBinding::TlsFingerprint => input
      .tls
      .fingerprint
      .as_deref()
      .unwrap_or("unavailable")
      .to_string(),
    PersonProofTokenBinding::Route => input.route_name.to_string(),
    PersonProofTokenBinding::DirectPeerIpNetworkPrefix => direct_peer_ip_network_prefix(
      input.peer_addr.ip(),
      policy.direct_peer_ipv4_prefix_bits,
      policy.direct_peer_ipv6_prefix_bits,
    ),
    PersonProofTokenBinding::TcpMaxHop => {
      tcp_max_hop_binding_value(policy.tcp_max_hop, input.tcp_max_hop)
    }
  }
}

pub(super) fn direct_peer_ip_network_prefix(
  ip: IpAddr,
  ipv4_prefix_bits: u8,
  ipv6_prefix_bits: u8,
) -> String {
  match ip {
    IpAddr::V4(addr) => {
      let bits = ipv4_prefix_bits.min(32);
      let value = u32::from(addr);
      let mask = if bits == 0 {
        0
      } else {
        u32::MAX << (32 - bits)
      };
      format!("ipv4:{}/{}", std::net::Ipv4Addr::from(value & mask), bits)
    }
    IpAddr::V6(addr) => {
      let bits = ipv6_prefix_bits.min(128);
      let value = u128::from(addr);
      let mask = if bits == 0 {
        0
      } else {
        u128::MAX << (128 - bits)
      };
      format!("ipv6:{}/{}", Ipv6Addr::from(value & mask), bits)
    }
  }
}

pub(super) fn tcp_max_hop_binding_value(configured: Option<u8>, applied: Option<u8>) -> String {
  format!(
    "configured={};applied={}",
    configured
      .map(|value| value.to_string())
      .unwrap_or_else(|| "unconfigured".to_string()),
    applied
      .map(|value| value.to_string())
      .unwrap_or_else(|| "unavailable".to_string())
  )
}

fn challenge_reuse_key(token: &str) -> String {
  format!("challenge:{token}")
}

fn clearance_reuse_key(token: &str) -> String {
  format!("clearance:{token}")
}

fn purge_expired_reuse_tokens(active: &mut HashMap<String, i64>, now: i64) {
  active.retain(|_, expires| *expires >= now);
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn shared_state_shares_secret_and_single_use_replay_state() {
    let shared = SharedState::test_memory("person-proof-test");
    let first =
      PersonProofEngine::from_policies_with_previous(Vec::new(), 16, None, Some(shared.clone()))
        .unwrap();
    let second =
      PersonProofEngine::from_policies_with_previous(Vec::new(), 16, None, Some(shared)).unwrap();

    assert_eq!(first.secret, second.secret);

    let now = now_unix_ms().unwrap();
    first
      .remember_reuse_token("challenge:test-token", now + 60_000, now)
      .unwrap();
    assert!(
      second
        .consume_reuse_token("challenge:test-token", now)
        .unwrap()
    );
    assert!(
      !first
        .consume_reuse_token("challenge:test-token", now)
        .unwrap()
    );
  }
}
