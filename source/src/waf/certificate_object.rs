//! Explicit certificate projections use the same budgets as other bounded name lists.

use super::*;

pub(super) fn eval_certificate_member(
  object: ObjectRef,
  field: &str,
  ctx: &EvalContext<'_>,
) -> anyhow::Result<Value> {
  let certificate = match object {
    ObjectRef::ClientCertificate => ctx.request.tls.client_certificate_details.as_deref(),
    ObjectRef::ResponseServerCertificate => {
      ctx.response.and_then(|value| value.upstream_certificate)
    }
    ObjectRef::StreamServerCertificate => ctx.stream.and_then(|value| value.upstream_certificate),
    _ => None,
  }
  .context("missing peer certificate metadata")?;
  let names = match field {
    "FingerprintSha256" => return Ok(Value::String(certificate.fingerprint_sha256.clone())),
    "ParseStatus" => {
      return Ok(Value::String(
        if certificate.parse_complete {
          "complete"
        } else {
          "incomplete"
        }
        .to_string(),
      ));
    }
    "SubjectCommonNames" => &certificate.subject_common_names,
    "SanDnsNames" => &certificate.san_dns_names,
    "SanIpAddresses" => &certificate.san_ip_addresses,
    "SanUriNames" => &certificate.san_uri_names,
    "SanEmailAddresses" => &certificate.san_email_addresses,
    _ => bail!("unknown certificate property {field}"),
  };
  let mut list = bounded_string_list(names.values.iter().cloned(), ctx.limits);
  list.is_truncated |= names.is_truncated;
  Ok(Value::StringList(list))
}
