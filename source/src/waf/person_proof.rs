use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, SET_COOKIE, VARY};
use http::{HeaderName, HeaderValue, StatusCode};
use ring::rand::{SecureRandom, SystemRandom};

use super::{
  HeaderMutation, PersonProofAlgorithm, PersonProofClearanceConfig,
  PersonProofClearanceIssueTarget, PersonProofClearanceSameSite, PersonProofClearanceSourceConfig,
  PersonProofTokenBinding, WafRequestInput, WafTerminalResponse,
};
use crate::shared_state::SharedState;

#[derive(Clone)]
pub(super) struct PersonProofEngine {
  pub(super) secret: [u8; 32],
  pub(super) policies: Vec<PersonProofPolicy>,
  active_reuse_tokens: Arc<Mutex<HashMap<String, i64>>>,
  max_reuse_tokens: usize,
  shared_state: Option<Arc<SharedState>>,
}

#[derive(Debug, Clone)]
pub(super) struct PersonProofPolicy {
  pub key: String,
  pub method: PersonProofAlgorithm,
  pub difficulty: u8,
  pub ttl_seconds: u64,
  pub clearance: PersonProofClearancePolicy,
  pub token_bindings: Vec<PersonProofTokenBinding>,
  pub direct_peer_ipv4_prefix_bits: u8,
  pub direct_peer_ipv6_prefix_bits: u8,
  pub tcp_max_hop: Option<u8>,
  pub single_use: bool,
  pub success_tag: Option<String>,
  pub status: u16,
  pub provider: super::person_proof_v2::PersonProofProviderConfig,
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
  pub weight: i64,
  pub allowed: bool,
  pub(super) clearance: Option<PersonProofIssuedClearance>,
}

#[derive(Debug, Clone)]
pub struct PersonProofIssuedClearance {
  pub token: String,
  pub expires_unix_ms: i64,
  pub max_age_seconds: u64,
  pub response_header: Option<HeaderMutation>,
  pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub(super) struct PersonProofClearancePolicy {
  pub(super) issue_to: PersonProofClearanceIssueTarget,
  pub(super) sources: Vec<PersonProofClearanceSource>,
  pub(super) cookie: PersonProofCookieClearance,
  pub(super) local_storage: PersonProofLocalStorageClearance,
}

#[derive(Debug, Clone)]
pub(super) enum PersonProofClearanceSource {
  Cookie { key: String },
  AuthorizationBearer,
  Header { key: String, name: HeaderName },
}

#[derive(Debug, Clone)]
pub(super) struct PersonProofCookieClearance {
  pub(super) key: String,
  pub(super) path: String,
  pub(super) same_site: PersonProofClearanceSameSite,
  pub(super) secure: bool,
  pub(super) http_only: bool,
}

#[derive(Debug, Clone)]
pub(super) struct PersonProofLocalStorageClearance {
  pub(super) key: String,
  pub(super) request_header: String,
  pub(super) request_header_name: HeaderName,
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
      weight: 0,
      allowed: false,
      clearance: None,
    }
  }
}

impl PersonProofClearancePolicy {
  pub(super) fn from_config(config: &PersonProofClearanceConfig) -> Self {
    let cookie = PersonProofCookieClearance {
      key: config.cookie.key.clone(),
      path: config.cookie.path.clone(),
      same_site: config.cookie.same_site,
      secure: config.cookie.secure,
      http_only: config.cookie.http_only,
    };
    let local_storage = PersonProofLocalStorageClearance {
      key: config.local_storage.key.clone(),
      request_header: config.local_storage.request_header.clone(),
      request_header_name: header_name(&config.local_storage.request_header),
    };
    let sources = if config.sources.is_empty() {
      match config.issue_to {
        PersonProofClearanceIssueTarget::Cookie => vec![PersonProofClearanceSource::Cookie {
          key: cookie.key.clone(),
        }],
        PersonProofClearanceIssueTarget::LocalStorage => {
          vec![PersonProofClearanceSource::Header {
            key: local_storage.request_header.clone(),
            name: local_storage.request_header_name.clone(),
          }]
        }
        PersonProofClearanceIssueTarget::ResponseJson => Vec::new(),
      }
    } else {
      config
        .sources
        .iter()
        .map(PersonProofClearanceSource::from_config)
        .collect()
    };
    Self {
      issue_to: config.issue_to,
      sources,
      cookie,
      local_storage,
    }
  }

  pub(super) fn extract_token<'a>(&self, headers: &'a http::HeaderMap) -> Option<&'a str> {
    self
      .sources
      .iter()
      .find_map(|source| source.extract_token(headers))
  }

  pub(super) fn signing_id(&self) -> String {
    let sources = self
      .sources
      .iter()
      .map(PersonProofClearanceSource::signing_id)
      .collect::<Vec<_>>()
      .join(",");
    format!(
      "issue_to={};cookie={}:{}:{}:{}:{};local_storage={}:{};sources={sources}",
      self.issue_to.as_str(),
      self.cookie.key,
      self.cookie.path,
      self.cookie.same_site.as_str(),
      self.cookie.secure,
      self.cookie.http_only,
      self.local_storage.key,
      self.local_storage.request_header,
    )
  }

  pub(super) fn session_metadata(&self) -> serde_json::Value {
    serde_json::json!({
      "issue_to": self.issue_to.as_str(),
      "cookie": {
        "key": self.cookie.key,
        "path": self.cookie.path,
        "same_site": self.cookie.same_site.as_str(),
        "secure": self.cookie.secure,
        "http_only": self.cookie.http_only,
      },
      "local_storage": {
        "key": self.local_storage.key,
        "request_header": self.local_storage.request_header,
      },
      "sources": self.sources.iter().map(PersonProofClearanceSource::metadata).collect::<Vec<_>>(),
    })
  }

  pub(super) fn storage_label(&self) -> String {
    match self.issue_to {
      PersonProofClearanceIssueTarget::Cookie => format!("cookie:{}", self.cookie.key),
      PersonProofClearanceIssueTarget::LocalStorage => {
        format!(
          "localStorage:{} via {}",
          self.local_storage.key, self.local_storage.request_header
        )
      }
      PersonProofClearanceIssueTarget::ResponseJson => "response_json".to_string(),
    }
  }

  pub(super) fn issue(
    &self,
    token: String,
    expires_unix_ms: i64,
    max_age_seconds: u64,
  ) -> anyhow::Result<PersonProofIssuedClearance> {
    let response_header = self.response_header(&token, max_age_seconds)?;
    Ok(PersonProofIssuedClearance {
      metadata: self.issued_metadata(&token, expires_unix_ms, max_age_seconds),
      token,
      expires_unix_ms,
      max_age_seconds,
      response_header,
    })
  }

  fn response_header(
    &self,
    token: &str,
    max_age_seconds: u64,
  ) -> anyhow::Result<Option<HeaderMutation>> {
    match self.issue_to {
      PersonProofClearanceIssueTarget::Cookie => {
        let mut cookie = format!(
          "{}={token}; Max-Age={max_age_seconds}; Path={}; SameSite={}",
          self.cookie.key,
          self.cookie.path,
          self.cookie.same_site.as_str()
        );
        if self.cookie.secure {
          cookie.push_str("; Secure");
        }
        if self.cookie.http_only {
          cookie.push_str("; HttpOnly");
        }
        Ok(Some(HeaderMutation::Append {
          name: SET_COOKIE,
          value: HeaderValue::from_str(&cookie).context("invalid person proof clearance cookie")?,
        }))
      }
      PersonProofClearanceIssueTarget::LocalStorage => Ok(Some(HeaderMutation::Set {
        name: self.local_storage.request_header_name.clone(),
        value: HeaderValue::from_str(token).context("invalid person proof clearance header")?,
      })),
      PersonProofClearanceIssueTarget::ResponseJson => Ok(None),
    }
  }

  fn issued_metadata(
    &self,
    token: &str,
    expires_unix_ms: i64,
    max_age_seconds: u64,
  ) -> serde_json::Value {
    let mut metadata = self.session_metadata();
    if let serde_json::Value::Object(object) = &mut metadata {
      if self.issue_to != PersonProofClearanceIssueTarget::Cookie {
        object.insert(
          "token".to_string(),
          serde_json::Value::String(token.to_string()),
        );
      }
      object.insert(
        "expires_unix_ms".to_string(),
        serde_json::Value::Number(expires_unix_ms.into()),
      );
      object.insert(
        "max_age_seconds".to_string(),
        serde_json::Value::Number(max_age_seconds.into()),
      );
    }
    metadata
  }
}

impl PersonProofClearanceSource {
  fn from_config(config: &PersonProofClearanceSourceConfig) -> Self {
    match config {
      PersonProofClearanceSourceConfig::Cookie { key } => Self::Cookie { key: key.clone() },
      PersonProofClearanceSourceConfig::AuthorizationBearer => Self::AuthorizationBearer,
      PersonProofClearanceSourceConfig::Header { key } => Self::Header {
        key: key.clone(),
        name: header_name(key),
      },
    }
  }

  fn extract_token<'a>(&self, headers: &'a http::HeaderMap) -> Option<&'a str> {
    match self {
      Self::Cookie { key } => find_cookie(headers, key),
      Self::AuthorizationBearer => headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token),
      Self::Header { name, .. } => headers.get(name).and_then(|value| value.to_str().ok()),
    }
  }

  fn signing_id(&self) -> String {
    match self {
      Self::Cookie { key } => format!("cookie:{key}"),
      Self::AuthorizationBearer => "authorization_bearer".to_string(),
      Self::Header { key, .. } => format!("header:{key}"),
    }
  }

  fn metadata(&self) -> serde_json::Value {
    match self {
      Self::Cookie { key } => serde_json::json!({ "type": "cookie", "key": key }),
      Self::AuthorizationBearer => serde_json::json!({ "type": "authorization_bearer" }),
      Self::Header { key, .. } => serde_json::json!({ "type": "header", "key": key }),
    }
  }
}

fn header_name(value: &str) -> HeaderName {
  HeaderName::from_bytes(value.as_bytes()).expect("person proof header name should be validated")
}

fn bearer_token(value: &str) -> Option<&str> {
  let (scheme, token) = value.trim().split_once(' ')?;
  if scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty() {
    Some(token.trim())
  } else {
    None
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
      let Some(proof) = policy.clearance.extract_token(input.headers) else {
        continue;
      };
      match self.verify_proof(input, policy, proof) {
        Ok(status) if status.state == PersonProofState::Valid => return status,
        Ok(status) if status.state == PersonProofState::Expired => expired = Some(status),
        Ok(status) => failed = Some(status),
        Err(error) => {
          failed = Some(PersonProofRequestStatus {
            state: PersonProofState::Failed,
            method: Some(policy.method.as_str()),
            difficulty: Some(policy.difficulty),
            issued_at_unix_ms: None,
            expires_at_unix_ms: None,
            policy_key: Some(policy.key.clone()),
            rate_limited: is_reuse_capacity_error(&error),
            weight: 0,
            allowed: false,
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

  pub(super) fn clearance_response_mutation(
    &self,
    status: &PersonProofRequestStatus,
  ) -> anyhow::Result<Option<HeaderMutation>> {
    let Some(clearance) = status.clearance.as_ref() else {
      return Ok(None);
    };
    Ok(clearance.response_header.clone())
  }

  pub(super) fn issue_challenge(
    &self,
    input: WafRequestInput<'_>,
    policy: PersonProofPolicy,
  ) -> anyhow::Result<WafTerminalResponse> {
    if policy.provider.challenge_url.is_some() {
      return super::person_proof_v2::redirect_challenge(self, input, &policy);
    }

    let now = now_unix_ms()?;
    let expires = now
      .checked_add(
        i64::try_from(policy.ttl_seconds)
          .context("person proof ttl does not fit in i64")?
          .saturating_mul(1000),
      )
      .context("person proof expiration overflow")?;
    let random = random_hex(16)?;
    let return_path = super::person_proof_v2::request_return_path(input);
    let session = super::person_proof_api::sign_session_token(
      self,
      input,
      &policy,
      now,
      expires,
      &return_path,
      &random,
    );
    let csp_nonce = random_hex(16)?;
    let body = challenge_html(&policy, &session, &return_path, expires, &csp_nonce);
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
    if proof.starts_with("clearance.v2.") {
      return super::person_proof_v2::verify_clearance(self, input, policy, proof);
    }
    if proof.starts_with("clearance.") {
      bail!("person proof clearance token has unsupported version");
    }
    bail!("person proof credential must contain an API-issued clearance token")
  }

  pub(super) fn remember_reuse_token(
    &self,
    key: &str,
    expires: i64,
    now: i64,
  ) -> anyhow::Result<()> {
    if !self.mark_reuse_token_used(key, expires, now)? {
      bail!("person proof token is already active");
    }
    Ok(())
  }

  pub(super) fn mark_reuse_token_used(
    &self,
    key: &str,
    expires: i64,
    now: i64,
  ) -> anyhow::Result<bool> {
    if let Some(shared) = &self.shared_state {
      return shared.person_proof_remember(key, expires);
    }
    let mut active = self
      .active_reuse_tokens
      .lock()
      .map_err(|_| anyhow!("person proof reuse token state is unavailable"))?;
    purge_expired_reuse_tokens(&mut active, now);
    if active.contains_key(key) {
      return Ok(false);
    }
    if active.len() >= self.max_reuse_tokens {
      bail!("{PERSON_PROOF_REUSE_CAPACITY_ERROR}");
    }
    active.insert(key.to_string(), expires);
    Ok(true)
  }

  pub(super) fn consume_reuse_token(&self, key: &str, now: i64) -> anyhow::Result<bool> {
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

pub(super) fn token_binding_payload_for_route(
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  route_name: &str,
) -> String {
  policy
    .token_bindings
    .iter()
    .map(|binding| {
      format!(
        "{}={}",
        binding.as_str(),
        token_binding_value(input, policy, *binding, route_name)
      )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn token_binding_value(
  input: WafRequestInput<'_>,
  policy: &PersonProofPolicy,
  binding: PersonProofTokenBinding,
  route_name: &str,
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
    PersonProofTokenBinding::Route => route_name.to_string(),
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

pub(super) fn challenge_reuse_key(token: &str) -> String {
  format!("challenge:{token}")
}

pub(super) fn clearance_reuse_key(token: &str) -> String {
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
  session: &str,
  return_path: &str,
  expires: i64,
  csp_nonce: &str,
) -> String {
  let session_js = js_escape(session);
  let session_path_js = js_escape(&policy.provider.session_path);
  let verify_path_js = js_escape(&policy.provider.verify_path);
  let return_path_js = js_escape(return_path);
  let clearance_label = policy.clearance.storage_label();
  let algorithm = html_escape(policy.method.as_str());
  let session_html = html_escape(session);
  let session_path_html = html_escape(&policy.provider.session_path);
  let verify_path_html = html_escape(&policy.provider.verify_path);
  let clearance_html = html_escape(&clearance_label);
  let csp_nonce_html = html_escape(csp_nonce);
  include_str!("../../assets/person-proof-challenge.html")
    .replace("__SESSION_HTML__", &session_html)
    .replace("__SESSION_JS__", &session_js)
    .replace("__SESSION_PATH_HTML__", &session_path_html)
    .replace("__SESSION_PATH_JS__", &session_path_js)
    .replace("__VERIFY_PATH_HTML__", &verify_path_html)
    .replace("__VERIFY_PATH_JS__", &verify_path_js)
    .replace("__RETURN_PATH_JS__", &return_path_js)
    .replace("__CLEARANCE_STORAGE_HTML__", &clearance_html)
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
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'none'; connect-src 'self'; worker-src blob:; script-src 'nonce-{csp_nonce}'; style-src 'nonce-{csp_nonce}' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; upgrade-insecure-requests"
  );

  Ok(vec![
    header_set("access-control-allow-origin", &protected_origin)?,
    header_set("access-control-allow-credentials", "true")?,
    header_set("access-control-allow-methods", "GET, HEAD, OPTIONS, POST")?,
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

pub(super) fn random_hex(bytes: usize) -> anyhow::Result<String> {
  let mut value = vec![0u8; bytes];
  SystemRandom::new()
    .fill(&mut value)
    .map_err(|_| anyhow!("failed to generate person proof challenge random data"))?;
  Ok(hex_encode(&value))
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

pub(super) fn hex_decode(value: &str) -> anyhow::Result<Vec<u8>> {
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

pub(super) fn now_unix_ms() -> anyhow::Result<i64> {
  let duration = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system clock is before Unix epoch")?;
  i64::try_from(duration.as_millis()).context("Unix timestamp does not fit in i64")
}

pub(super) fn remaining_seconds(now_unix_ms: i64, expires_unix_ms: i64) -> u64 {
  expires_unix_ms
    .saturating_sub(now_unix_ms)
    .try_into()
    .map(|millis: u64| millis.div_ceil(1000))
    .unwrap_or(0)
}

#[cfg(test)]
mod tests;
