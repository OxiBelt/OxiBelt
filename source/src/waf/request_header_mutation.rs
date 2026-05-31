use anyhow::{Context, bail};
use http::header::{HeaderName, HeaderValue};

pub(super) fn validate(
  rule_name: &str,
  action: &str,
  name: &str,
  value: Option<&str>,
) -> anyhow::Result<()> {
  let name = HeaderName::from_bytes(name.as_bytes()).context("invalid WAF header name")?;
  ensure_allowed(rule_name, action, &name)?;
  if let Some(value) = value {
    HeaderValue::from_str(value).context("invalid WAF header value")?;
  }
  Ok(())
}

pub(super) fn ensure_allowed(
  rule_name: &str,
  action: &str,
  name: &HeaderName,
) -> anyhow::Result<()> {
  if is_forbidden(name) {
    bail!(
      "WAF rule {rule_name} {action} cannot mutate request header {} because it controls HTTP message framing or connection state",
      name.as_str()
    );
  }
  Ok(())
}

fn is_forbidden(name: &HeaderName) -> bool {
  [
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
  ]
  .iter()
  .any(|forbidden| name.as_str().eq_ignore_ascii_case(forbidden))
}
