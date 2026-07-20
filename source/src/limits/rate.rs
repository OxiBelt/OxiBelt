//! Rate parsing, bucket identity, and local token-bucket mechanics.

use super::*;

#[derive(Debug, Clone, Copy)]
pub struct ParsedRate {
  pub(super) per_second: f64,
}

pub fn parse_rate(raw: &str) -> anyhow::Result<ParsedRate> {
  let Some((amount, unit)) = raw.split_once("r/") else {
    bail!("rate must use format like 10r/s or 600r/m");
  };
  let amount: f64 = amount
    .parse()
    .with_context(|| format!("invalid rate amount {raw}"))?;
  if amount <= 0.0 {
    bail!("rate amount must be greater than 0");
  }
  let divisor = match unit {
    "s" => 1.0,
    "m" => 60.0,
    "h" => 3600.0,
    _ => bail!("rate unit must be s, m, or h"),
  };
  Ok(ParsedRate {
    per_second: amount / divisor,
  })
}

impl ParsedRate {
  pub fn per_second(self) -> f64 {
    self.per_second
  }
}

pub(super) fn rate_limit_applies_before_route(limit: &RateLimitConfig) -> bool {
  matches!(limit.key, RateLimitKey::ClientIp | RateLimitKey::Global) && limit.routes.is_empty()
}

pub(super) fn rate_limit_applies_after_route(limit: &RateLimitConfig, route_name: &str) -> bool {
  if rate_limit_applies_before_route(limit) {
    return false;
  }
  limit.routes.is_empty() || limit.routes.iter().any(|route| route == route_name)
}

pub(super) fn take_local_rate_token(
  bucket: &mut TokenBucket,
  now: Instant,
  rate: ParsedRate,
  burst: f64,
  mode: LimitMode,
  status: u16,
) -> Option<StatusCode> {
  let elapsed = now.duration_since(bucket.last).as_secs_f64();
  bucket.tokens = (bucket.tokens + elapsed * rate.per_second).min(burst);
  bucket.last = now;
  if bucket.tokens < 1.0 && mode == LimitMode::Enforcing {
    return Some(rate_limit_status(status));
  }
  bucket.tokens -= 1.0;
  None
}

pub(super) fn prune_refilled_rate_buckets(
  buckets: &mut HashMap<(String, String), TokenBucket>,
  limit_name: &str,
  now: Instant,
  rate_per_second: f64,
  burst: f64,
) {
  buckets.retain(|(bucket_limit_name, _), bucket| {
    bucket_limit_name != limit_name || !bucket_refills_to_burst(bucket, now, rate_per_second, burst)
  });
}

pub(super) fn bucket_refills_to_burst(
  bucket: &TokenBucket,
  now: Instant,
  rate_per_second: f64,
  burst: f64,
) -> bool {
  if bucket.tokens >= burst {
    return true;
  }
  let elapsed = now.duration_since(bucket.last).as_secs_f64();
  bucket.tokens + elapsed * rate_per_second >= burst
}

pub(super) fn rate_limit_bucket_count(
  buckets: &HashMap<(String, String), TokenBucket>,
  limit_name: &str,
) -> usize {
  buckets
    .keys()
    .filter(|(bucket_limit_name, _)| bucket_limit_name == limit_name)
    .count()
}

pub(super) fn rate_limit_status(status: u16) -> StatusCode {
  StatusCode::from_u16(status).unwrap_or(StatusCode::TOO_MANY_REQUESTS)
}

pub(super) fn rate_limit_key(context: RateLimitContext<'_>, check: &RateLimitCheck<'_>) -> String {
  let route = context.route_name.unwrap_or_default();
  let path = context.path.unwrap_or_default();
  let identity_context = SybilIdentityContext::from(context);
  let identity_spec = SybilIdentitySpec::from(check);
  match check.key {
    RateLimitKey::Global => String::new(),
    RateLimitKey::Route => format!("route:{route}"),
    RateLimitKey::ClientIp => format!("client_ip:{}", context.ip),
    RateLimitKey::ClientIpRoute => format!("client_ip_route:{}:{route}", context.ip),
    RateLimitKey::ClientIpPath => format!("client_ip_path:{}:{path}", context.ip),
    RateLimitKey::AccessToken => {
      format!(
        "access_token:{}",
        access_token_bucket_identity(context, check.access_token_source, check.token_header)
      )
    }
    RateLimitKey::AccessTokenRoute => format!(
      "access_token_route:{}:{route}",
      access_token_bucket_identity(context, check.access_token_source, check.token_header)
    ),
    RateLimitKey::AccessTokenPath => format!(
      "access_token_path:{}:{path}",
      access_token_bucket_identity(context, check.access_token_source, check.token_header)
    ),
    RateLimitKey::ClientIpPrefix => format!(
      "client_ip_prefix:{}",
      sybil_identity::client_ip_prefix_identity(identity_context, identity_spec)
    ),
    RateLimitKey::ClientIpPrefixRoute => format!(
      "client_ip_prefix_route:{}:{route}",
      sybil_identity::client_ip_prefix_identity(identity_context, identity_spec)
    ),
    RateLimitKey::ClientIpPrefixPath => format!(
      "client_ip_prefix_path:{}:{path}",
      sybil_identity::client_ip_prefix_identity(identity_context, identity_spec)
    ),
    RateLimitKey::TlsFingerprint => format!(
      "tls_fingerprint:{}",
      sybil_identity::tls_fingerprint_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::TlsFingerprintRoute => format!(
      "tls_fingerprint_route:{}:{route}",
      sybil_identity::tls_fingerprint_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::TokenBindingHash => format!(
      "token_binding_hash:{}",
      sybil_identity::token_binding_hash_identity(identity_context, identity_spec)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::TokenBindingHashRoute => format!(
      "token_binding_hash_route:{}:{route}",
      sybil_identity::token_binding_hash_identity(identity_context, identity_spec)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::PersonProofClearance => format!(
      "person_proof_clearance:{}",
      sybil_identity::person_proof_clearance_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::PersonProofClearanceRoute => format!(
      "person_proof_clearance_route:{}:{route}",
      sybil_identity::person_proof_clearance_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::CompositeClient => format!(
      "composite_client:{}",
      sybil_identity::composite_client_rate_limit_identity(identity_context, identity_spec)
    ),
    RateLimitKey::CompositeClientRoute => format!(
      "composite_client_route:{}:{route}",
      sybil_identity::composite_client_rate_limit_identity(identity_context, identity_spec)
    ),
    RateLimitKey::Asn => format!(
      "asn:{}",
      sybil_identity::asn_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
    RateLimitKey::AsnRoute => format!(
      "asn_route:{}:{route}",
      sybil_identity::asn_identity(identity_context)
        .unwrap_or_else(|| sybil_identity::fallback_ip_identity(identity_context))
    ),
  }
}

pub(super) fn access_token_bucket_identity(
  context: RateLimitContext<'_>,
  access_token_source: Option<AccessTokenRateLimitSource>,
  token_header: Option<&str>,
) -> String {
  context
    .headers
    .and_then(|headers| access_token(headers, access_token_source, token_header))
    .map(|token| format!("token:{}", sybil_identity::sha256_hex(token.as_bytes())))
    .unwrap_or_else(|| format!("fallback_ip:{}", context.ip))
}

pub(super) fn access_token(
  headers: &HeaderMap,
  access_token_source: Option<AccessTokenRateLimitSource>,
  token_header: Option<&str>,
) -> Option<String> {
  match access_token_source {
    Some(AccessTokenRateLimitSource::TrustedAuthorizationBearer) => bearer_token(headers),
    Some(AccessTokenRateLimitSource::TrustedHeader) => {
      token_header.and_then(|name| named_header_token(headers, name))
    }
    None => None,
  }
}

pub(super) fn bearer_token(headers: &HeaderMap) -> Option<String> {
  let raw = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
  let mut parts = raw.splitn(2, char::is_whitespace);
  let scheme = parts.next()?;
  let token = parts.next()?.trim();
  if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
    return None;
  }
  Some(token.to_string())
}

pub(super) fn named_header_token(headers: &HeaderMap, name: &str) -> Option<String> {
  let name = HeaderName::from_bytes(name.as_bytes()).ok()?;
  let value = headers.get(name)?.to_str().ok()?.trim();
  if value.is_empty() {
    return None;
  }
  Some(value.to_string())
}

impl<'a> From<RateLimitContext<'a>> for SybilIdentityContext<'a> {
  fn from(context: RateLimitContext<'a>) -> Self {
    Self {
      ip: context.ip,
      route_name: context.route_name,
      headers: context.headers,
      tls_fingerprint: context.tls_fingerprint,
      client_asn: context.client_asn,
      tcp_max_hop: context.tcp_max_hop,
      person_proof_clearance_hash: context.person_proof_clearance_hash,
    }
  }
}

impl<'a> From<&'a RateLimitCheck<'a>> for SybilIdentitySpec<'a> {
  fn from(check: &'a RateLimitCheck<'a>) -> Self {
    Self {
      ipv4_prefix_bits: check.ipv4_prefix_bits,
      ipv6_prefix_bits: check.ipv6_prefix_bits,
      identity_parts: check.identity_parts,
      token_bindings: check.token_bindings,
    }
  }
}
