//! Canonical request identity strings for Sybil-oriented limits and policy.
//! Helpers return prefixed hashes for sensitive values so callers never persist raw credentials.

use std::net::IpAddr;

use http::HeaderMap;

use crate::config::RateLimitIdentityPart;
use crate::waf::PersonProofTokenBinding;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SybilIdentityContext<'a> {
  pub(crate) ip: IpAddr,
  pub(crate) route_name: Option<&'a str>,
  pub(crate) headers: Option<&'a HeaderMap>,
  pub(crate) tls_fingerprint: Option<&'a str>,
  pub(crate) client_asn: Option<u32>,
  pub(crate) tcp_max_hop: Option<u8>,
  pub(crate) person_proof_clearance_hash: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SybilIdentitySpec<'a> {
  pub(crate) ipv4_prefix_bits: u8,
  pub(crate) ipv6_prefix_bits: u8,
  pub(crate) identity_parts: &'a [RateLimitIdentityPart],
  pub(crate) token_bindings: &'a [PersonProofTokenBinding],
}

pub(crate) fn fallback_ip_identity(context: SybilIdentityContext<'_>) -> String {
  format!("fallback_ip:{}", context.ip)
}

pub(crate) fn client_ip_prefix_identity(
  context: SybilIdentityContext<'_>,
  spec: SybilIdentitySpec<'_>,
) -> String {
  client_ip_network_prefix(context.ip, spec.ipv4_prefix_bits, spec.ipv6_prefix_bits)
}

pub(crate) fn tls_fingerprint_identity(context: SybilIdentityContext<'_>) -> Option<String> {
  context
    .tls_fingerprint
    .filter(|value| !value.is_empty())
    .map(|value| format!("fingerprint:{}", sha256_hex(value.as_bytes())))
}

pub(crate) fn token_binding_hash_identity(
  context: SybilIdentityContext<'_>,
  spec: SybilIdentitySpec<'_>,
) -> Option<String> {
  if spec.token_bindings.is_empty() {
    return None;
  }
  let payload = spec
    .token_bindings
    .iter()
    .map(|binding| {
      format!(
        "{}={}",
        binding.as_str(),
        token_binding_value(context, spec, *binding)
      )
    })
    .collect::<Vec<_>>()
    .join("\n");
  Some(format!("binding:{}", sha256_hex(payload.as_bytes())))
}

pub(crate) fn person_proof_clearance_identity(context: SybilIdentityContext<'_>) -> Option<String> {
  context
    .person_proof_clearance_hash
    .filter(|value| !value.is_empty())
    .map(|value| format!("clearance:{value}"))
}

pub(crate) fn composite_client_identity(
  context: SybilIdentityContext<'_>,
  spec: SybilIdentitySpec<'_>,
) -> Option<String> {
  if spec.identity_parts.is_empty() {
    return None;
  }
  let mut parts = Vec::with_capacity(spec.identity_parts.len());
  for part in spec.identity_parts {
    let value = match part {
      RateLimitIdentityPart::ClientIpPrefix => client_ip_prefix_identity(context, spec),
      RateLimitIdentityPart::UserAgent => {
        let value = user_agent_value(context)?;
        format!("ua:{}", sha256_hex(value.as_bytes()))
      }
      RateLimitIdentityPart::TlsFingerprint => tls_fingerprint_identity(context)?,
      RateLimitIdentityPart::Asn => asn_identity(context)?,
    };
    parts.push(format!("{part:?}={value}"));
  }
  Some(format!("hash:{}", sha256_hex(parts.join("\n").as_bytes())))
}

pub(crate) fn composite_client_rate_limit_identity(
  context: SybilIdentityContext<'_>,
  spec: SybilIdentitySpec<'_>,
) -> String {
  if spec.identity_parts.is_empty() {
    return fallback_ip_identity(context);
  }
  let payload = spec
    .identity_parts
    .iter()
    .map(|part| {
      let value = match part {
        RateLimitIdentityPart::ClientIpPrefix => client_ip_prefix_identity(context, spec),
        RateLimitIdentityPart::UserAgent => user_agent_value(context)
          .map(|value| format!("ua:{}", sha256_hex(value.as_bytes())))
          .unwrap_or_else(|| fallback_ip_identity(context)),
        RateLimitIdentityPart::TlsFingerprint => {
          tls_fingerprint_identity(context).unwrap_or_else(|| fallback_ip_identity(context))
        }
        RateLimitIdentityPart::Asn => {
          asn_identity(context).unwrap_or_else(|| fallback_ip_identity(context))
        }
      };
      format!("{part:?}={value}")
    })
    .collect::<Vec<_>>()
    .join("\n");
  format!("hash:{}", sha256_hex(payload.as_bytes()))
}

pub(crate) fn asn_identity(context: SybilIdentityContext<'_>) -> Option<String> {
  context.client_asn.map(|asn| format!("AS{asn}"))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
  let digest = crate::crypto::sha256(bytes);
  let mut output = String::with_capacity(digest.len() * 2);
  for byte in digest {
    use std::fmt::Write as _;
    let _ = write!(&mut output, "{byte:02x}");
  }
  output
}

fn token_binding_value(
  context: SybilIdentityContext<'_>,
  spec: SybilIdentitySpec<'_>,
  binding: PersonProofTokenBinding,
) -> String {
  match binding {
    PersonProofTokenBinding::UserAgent => user_agent_value(context).unwrap_or_default(),
    PersonProofTokenBinding::TlsFingerprint => context
      .tls_fingerprint
      .filter(|value| !value.is_empty())
      .unwrap_or("unavailable")
      .to_string(),
    PersonProofTokenBinding::Route => context.route_name.unwrap_or_default().to_string(),
    PersonProofTokenBinding::DirectPeerIpNetworkPrefix => {
      client_ip_network_prefix(context.ip, spec.ipv4_prefix_bits, spec.ipv6_prefix_bits)
    }
    PersonProofTokenBinding::TcpMaxHop => format!(
      "configured=unconfigured;applied={}",
      context
        .tcp_max_hop
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_string())
    ),
  }
}

fn user_agent_value(context: SybilIdentityContext<'_>) -> Option<String> {
  context
    .headers?
    .get(http::header::USER_AGENT)?
    .to_str()
    .ok()
    .map(str::to_string)
}

fn client_ip_network_prefix(ip: IpAddr, ipv4_prefix_bits: u8, ipv6_prefix_bits: u8) -> String {
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
      format!("ipv6:{}/{}", std::net::Ipv6Addr::from(value & mask), bits)
    }
  }
}
