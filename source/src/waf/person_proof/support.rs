//! Challenge rendering plus token encoding and time helpers.

use super::*;

pub(super) fn challenge_html(
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
  let mode = html_escape(policy.mode.as_str());
  let session_html = html_escape(session);
  let session_path_html = html_escape(&policy.provider.session_path);
  let verify_path_html = html_escape(&policy.provider.verify_path);
  let clearance_html = html_escape(&clearance_label);
  let csp_nonce_html = html_escape(csp_nonce);
  include_str!(concat!(env!("OUT_DIR"), "/person-proof-challenge.html"))
    .replace("__SESSION_HTML__", &session_html)
    .replace("__SESSION_JS__", &session_js)
    .replace("__SESSION_PATH_HTML__", &session_path_html)
    .replace("__SESSION_PATH_JS__", &session_path_js)
    .replace("__VERIFY_PATH_HTML__", &verify_path_html)
    .replace("__VERIFY_PATH_JS__", &verify_path_js)
    .replace("__RETURN_PATH_JS__", &return_path_js)
    .replace("__CLEARANCE_STORAGE_HTML__", &clearance_html)
    .replace("__MODE__", &mode)
    .replace("__DIFFICULTY__", &policy.difficulty.to_string())
    .replace("__EXPIRES_UNIX_MS__", &expires.to_string())
    .replace("__CSP_NONCE__", &csp_nonce_html)
}

pub(super) fn challenge_security_headers(
  input: WafRequestInput<'_>,
  csp_nonce: &str,
) -> anyhow::Result<Vec<HeaderMutation>> {
  let protected_origin = format!("https://{}", input.downstream_host);
  let csp = format!(
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'none'; connect-src 'self'; worker-src blob:; script-src 'nonce-{csp_nonce}'; style-src 'nonce-{csp_nonce}'; font-src 'none'; upgrade-insecure-requests"
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

pub(in crate::waf) fn random_hex(bytes: usize) -> anyhow::Result<String> {
  let mut value = vec![0u8; bytes];
  crate::crypto::random_fill(&mut value)
    .map_err(|_| anyhow!("failed to generate person proof challenge random data"))?;
  Ok(hex_encode(&value))
}

pub(in crate::waf) fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

pub(in crate::waf) fn hex_decode(value: &str) -> anyhow::Result<Vec<u8>> {
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

pub(in crate::waf) fn now_unix_ms() -> anyhow::Result<i64> {
  let duration = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .context("system clock is before Unix epoch")?;
  i64::try_from(duration.as_millis()).context("Unix timestamp does not fit in i64")
}

pub(in crate::waf) fn remaining_seconds(now_unix_ms: i64, expires_unix_ms: i64) -> u64 {
  u64::try_from(expires_unix_ms.saturating_sub(now_unix_ms))
    .map(|millis: u64| millis.div_ceil(1000))
    .unwrap_or(0)
}
