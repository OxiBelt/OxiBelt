//! TLS diagnostic checks.
//! Certificate parsing reports validity problems without changing live TLS configuration.

use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use rustls::pki_types::{CertificateDer, pem::PemObject};

use crate::config::{Config, OcspMode, TlsKeyExchangeGroup, TlsVersion};

use super::{DiagnosticReport, DiagnosticSeverity};

pub(super) fn diagnose_tls(config: &Config, report: &mut DiagnosticReport) {
  diagnose_downstream_tls(config, report);
  diagnose_admin_tls(config, report);
  diagnose_turn_tls(config, report);
  diagnose_client_auth_roots(config, report);
  diagnose_pqc_tls_version(config, report);
}

fn diagnose_downstream_tls(config: &Config, report: &mut DiagnosticReport) {
  check_certificate_file(report, "tls.cert_chain", &config.tls.cert_chain, &[]);
  if !config.tls.remote_signer.enabled {
    if let Err(error) = crate::tls::build_server_config(&config.tls, &config.listeners) {
      report.push(
        DiagnosticSeverity::Error,
        "tls.downstream_invalid",
        "tls",
        "tls",
        format!("downstream TLS certificate/key configuration is invalid: {error:#}"),
        "Fix tls.cert_chain, tls.private_key, client auth roots, or static OCSP before serving traffic.",
      );
    }
  } else if let Err(error) = read_first_cert(&config.tls.cert_chain) {
    report.push(
      DiagnosticSeverity::Error,
      "tls.cert_parse_failed",
      "tls",
      "tls.cert_chain",
      format!("downstream certificate chain could not be parsed: {error:#}"),
      "Replace tls.cert_chain with a readable PEM certificate chain.",
    );
  }
  check_ocsp_file(config, report);
}

fn diagnose_admin_tls(config: &Config, report: &mut DiagnosticReport) {
  if !config.admin.enabled || !config.admin.tls.enabled {
    return;
  }
  if let Err(error) = crate::tls::build_admin_server_config(&config.admin.tls) {
    report.push(
      DiagnosticSeverity::Error,
      "tls.admin_invalid",
      "tls",
      "admin.tls",
      format!("admin TLS certificate/key configuration is invalid: {error:#}"),
      "Fix admin.tls certificate, key, SNI, or client auth settings before exposing the Admin listener.",
    );
  }
  for certificate in &config.admin.tls.certificates {
    check_certificate_file(
      report,
      "admin.tls.certificates.cert_chain",
      &certificate.cert_chain,
      &certificate.server_names,
    );
  }
}

fn diagnose_turn_tls(config: &Config, report: &mut DiagnosticReport) {
  for listener in &config.webrtc_turn_listeners {
    if listener.bind_tls.is_none() {
      continue;
    }
    let cert_chain = listener
      .tls
      .cert_chain
      .as_ref()
      .unwrap_or(&config.tls.cert_chain);
    check_certificate_file(
      report,
      &format!("webrtc_turn_listeners.{}.tls.cert_chain", listener.name),
      cert_chain,
      &[],
    );
    if config.tls.remote_signer.enabled && listener.tls.private_key.is_none() {
      continue;
    }
    if let Err(error) = crate::tls::build_turn_server_config(&listener.tls, &config.tls) {
      report.push(
        DiagnosticSeverity::Error,
        "tls.turn_invalid",
        "tls",
        format!("webrtc_turn_listeners.{}.tls", listener.name),
        format!("TURN TLS certificate/key configuration is invalid: {error:#}"),
        "Fix the TURN TLS override or default downstream TLS key material before enabling TURN TLS.",
      );
    }
  }
}

fn diagnose_client_auth_roots(config: &Config, report: &mut DiagnosticReport) {
  for path in &config.tls.client_auth.ca_certs {
    check_ca_file(report, "tls.client_auth.ca_certs", path);
  }
  for path in &config.admin.tls.client_auth.ca_certs {
    check_ca_file(report, "admin.tls.client_auth.ca_certs", path);
  }
}

fn check_ca_file(report: &mut DiagnosticReport, target: &str, path: &Path) {
  match read_certs(path) {
    Ok(certs) if !certs.is_empty() => {}
    Ok(_) => report.push(
      DiagnosticSeverity::Error,
      "tls.ca_empty",
      "tls",
      target,
      format!("CA file {} did not contain certificates", path.display()),
      "Replace the CA file with a PEM bundle containing at least one certificate.",
    ),
    Err(error) => report.push(
      DiagnosticSeverity::Error,
      "tls.ca_unreadable",
      "tls",
      target,
      format!("CA file {} could not be read: {error:#}", path.display()),
      "Mount a readable CA bundle or disable client certificate authentication for this listener.",
    ),
  }
}

fn diagnose_pqc_tls_version(config: &Config, report: &mut DiagnosticReport) {
  if config
    .tls
    .key_exchange_groups
    .contains(&TlsKeyExchangeGroup::X25519MlKem768)
    && config.tls.max_version < TlsVersion::Tls13
  {
    report.push(
      DiagnosticSeverity::Error,
      "tls.pqc_without_tls13",
      "tls",
      "tls.key_exchange_groups",
      "post-quantum key exchange is configured but TLS 1.3 is disabled",
      "Enable TLS 1.3 or remove x25519mlkem768 from tls.key_exchange_groups.",
    );
  }
}

fn check_certificate_file(
  report: &mut DiagnosticReport,
  target: &str,
  path: &Path,
  server_names: &[String],
) {
  match read_first_cert(path).and_then(|cert| parse_certificate_info(&cert)) {
    Ok(info) => {
      check_validity(report, target, path, &info);
      for name in server_names {
        if !name_covered_by_cert(name, &info) {
          report.push(
            DiagnosticSeverity::Warning,
            "tls.admin_sni_not_covered",
            "tls",
            target,
            format!(
              "admin TLS server_name {name} is not covered by certificate {}",
              path.display()
            ),
            "Use a certificate whose SAN covers every configured admin.tls.certificates.server_names value.",
          );
        }
      }
    }
    Err(error) => report.push(
      DiagnosticSeverity::Error,
      "tls.cert_parse_failed",
      "tls",
      target,
      format!(
        "certificate {} could not be parsed: {error:#}",
        path.display()
      ),
      "Replace the certificate file with a readable PEM certificate chain.",
    ),
  }
}

fn check_validity(report: &mut DiagnosticReport, target: &str, path: &Path, info: &CertInfo) {
  let now = now_unix_seconds();
  if now < info.not_before {
    report.push(
      DiagnosticSeverity::Error,
      "tls.cert_not_yet_valid",
      "tls",
      target,
      format!("certificate {} is not valid yet", path.display()),
      "Install a certificate whose notBefore is in the past for this deployment clock.",
    );
  }
  if now > info.not_after {
    report.push(
      DiagnosticSeverity::Error,
      "tls.cert_expired",
      "tls",
      target,
      format!("certificate {} has expired", path.display()),
      "Renew the certificate before serving traffic.",
    );
  } else if info.not_after.saturating_sub(now) < 14 * 24 * 60 * 60 {
    report.push(
      DiagnosticSeverity::Warning,
      "tls.cert_expires_soon",
      "tls",
      target,
      format!(
        "certificate {} expires in less than 14 days",
        path.display()
      ),
      "Renew the certificate or verify automated renewal and downstream TLS reload are working.",
    );
  }
}

fn check_ocsp_file(config: &Config, report: &mut DiagnosticReport) {
  if config.tls.ocsp.mode != OcspMode::StaticFile {
    return;
  }
  let Some(path) = &config.tls.ocsp.response_file else {
    return;
  };
  match std::fs::read(path).context("failed to read OCSP response") {
    Ok(bytes) => match earliest_future_der_time(&bytes) {
      Some(next_update) if next_update > now_unix_seconds() => {}
      Some(_) | None => report.push(
        DiagnosticSeverity::Error,
        "tls.ocsp_expired",
        "tls",
        "tls.ocsp.response_file",
        format!(
          "static OCSP response {} appears expired or has no future nextUpdate",
          path.display()
        ),
        "Refresh the static OCSP staple before enabling tls.ocsp.mode = \"static_file\".",
      ),
    },
    Err(error) => report.push(
      DiagnosticSeverity::Error,
      "tls.ocsp_unreadable",
      "tls",
      "tls.ocsp.response_file",
      format!(
        "static OCSP response {} could not be read: {error:#}",
        path.display()
      ),
      "Mount a readable static OCSP response file or disable OCSP stapling.",
    ),
  }
}

fn read_first_cert(path: &Path) -> anyhow::Result<Vec<u8>> {
  read_certs(path)?
    .into_iter()
    .next()
    .ok_or_else(|| anyhow!("certificate file contained no certificates"))
}

fn read_certs(path: &Path) -> anyhow::Result<Vec<Vec<u8>>> {
  let bytes = std::fs::read(path)
    .with_context(|| format!("failed to read certificate {}", path.display()))?;
  CertificateDer::pem_slice_iter(&bytes)
    .map(|cert| cert.map(|cert| cert.as_ref().to_vec()))
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))
}

#[derive(Debug)]
struct CertInfo {
  not_before: i64,
  not_after: i64,
  dns_names: Vec<String>,
  ip_addresses: Vec<IpAddr>,
}

fn parse_certificate_info(der: &[u8]) -> anyhow::Result<CertInfo> {
  let cert = DerReader::single(der, 0x30)?;
  let tbs = DerReader::single(cert, 0x30)?;
  let mut reader = DerReader::new(tbs);
  if reader.peek_tag() == Some(0xa0) {
    reader.read_any()?;
  }
  reader.read_any()?; // serialNumber
  reader.read_any()?; // signature
  reader.read_any()?; // issuer
  let validity = reader.read(0x30)?;
  let mut validity_reader = DerReader::new(validity);
  let not_before = parse_der_time(validity_reader.read_any()?.1)?;
  let not_after = parse_der_time(validity_reader.read_any()?.1)?;
  reader.read_any()?; // subject
  reader.read_any()?; // subjectPublicKeyInfo

  let mut info = CertInfo {
    not_before,
    not_after,
    dns_names: Vec::new(),
    ip_addresses: Vec::new(),
  };
  while !reader.is_empty() {
    let (tag, value) = reader.read_any()?;
    if tag == 0xa3 {
      parse_extensions(value, &mut info)?;
    }
  }
  Ok(info)
}

fn parse_extensions(value: &[u8], info: &mut CertInfo) -> anyhow::Result<()> {
  let extensions = DerReader::single(value, 0x30)?;
  let mut reader = DerReader::new(extensions);
  while !reader.is_empty() {
    let extension = reader.read(0x30)?;
    let mut extension_reader = DerReader::new(extension);
    let oid = extension_reader.read(0x06)?;
    if extension_reader.peek_tag() == Some(0x01) {
      extension_reader.read_any()?;
    }
    let extn_value = extension_reader.read(0x04)?;
    if oid == [0x55, 0x1d, 0x11] {
      parse_subject_alt_names(extn_value, info)?;
    }
  }
  Ok(())
}

fn parse_subject_alt_names(value: &[u8], info: &mut CertInfo) -> anyhow::Result<()> {
  let names = DerReader::single(value, 0x30)?;
  let mut reader = DerReader::new(names);
  while !reader.is_empty() {
    let (tag, value) = reader.read_any()?;
    match tag {
      0x82 => {
        if let Ok(name) = std::str::from_utf8(value) {
          info.dns_names.push(name.to_ascii_lowercase());
        }
      }
      0x87 => match value {
        [a, b, c, d] => info.ip_addresses.push(IpAddr::from([*a, *b, *c, *d])),
        bytes if bytes.len() == 16 => {
          let mut octets = [0_u8; 16];
          octets.copy_from_slice(bytes);
          info.ip_addresses.push(IpAddr::from(octets));
        }
        _ => {}
      },
      _ => {}
    }
  }
  Ok(())
}

fn name_covered_by_cert(name: &str, info: &CertInfo) -> bool {
  if let Ok(ip) = name.parse::<IpAddr>() {
    return info.ip_addresses.contains(&ip);
  }
  let name = name.to_ascii_lowercase();
  info.dns_names.iter().any(|candidate| {
    candidate == &name
      || candidate
        .strip_prefix("*.")
        .is_some_and(|suffix| wildcard_matches(&name, suffix))
  })
}

fn wildcard_matches(name: &str, suffix: &str) -> bool {
  let Some(prefix) = name.strip_suffix(suffix) else {
    return false;
  };
  prefix.ends_with('.') && !prefix.trim_end_matches('.').contains('.')
}

fn earliest_future_der_time(der: &[u8]) -> Option<i64> {
  let now = now_unix_seconds();
  let mut times = Vec::new();
  collect_der_times(der, &mut times);
  times.into_iter().filter(|time| *time > now).min()
}

fn collect_der_times(input: &[u8], times: &mut Vec<i64>) {
  let mut reader = DerReader::new(input);
  while let Ok((tag, value)) = reader.read_any() {
    if matches!(tag, 0x17 | 0x18)
      && let Ok(time) = parse_der_time_for_tag(tag, value)
    {
      times.push(time);
    }
    if matches!(tag, 0x30 | 0x31 | 0xa0..=0xbf) {
      collect_der_times(value, times);
    }
  }
}

fn parse_der_time(value: &[u8]) -> anyhow::Result<i64> {
  let text = std::str::from_utf8(value).context("time was not ASCII")?;
  match text.len() {
    13 => parse_utc_time(text),
    15 => parse_generalized_time(text),
    _ => bail!("unsupported DER time length"),
  }
}

fn parse_der_time_for_tag(tag: u8, value: &[u8]) -> anyhow::Result<i64> {
  match tag {
    0x17 => parse_utc_time(std::str::from_utf8(value)?),
    0x18 => parse_generalized_time(std::str::from_utf8(value)?),
    _ => bail!("not a DER time"),
  }
}

fn parse_utc_time(value: &str) -> anyhow::Result<i64> {
  if !value.ends_with('Z') || value.len() != 13 {
    bail!("unsupported UTCTime format");
  }
  let year = parse_decimal(&value[0..2])?;
  let year = if year >= 50 { 1900 + year } else { 2000 + year };
  parse_time_parts(year, &value[2..])
}

fn parse_generalized_time(value: &str) -> anyhow::Result<i64> {
  if !value.ends_with('Z') || value.len() != 15 {
    bail!("unsupported GeneralizedTime format");
  }
  parse_time_parts(parse_decimal(&value[0..4])?, &value[4..])
}

fn parse_time_parts(year: i32, rest: &str) -> anyhow::Result<i64> {
  let month = parse_decimal(&rest[0..2])?;
  let day = parse_decimal(&rest[2..4])?;
  let hour = parse_decimal(&rest[4..6])?;
  let minute = parse_decimal(&rest[6..8])?;
  let second = parse_decimal(&rest[8..10])?;
  let days = days_from_civil(year, month, day);
  Ok(days * 86_400 + i64::from(hour * 3_600 + minute * 60 + second))
}

fn parse_decimal(value: &str) -> anyhow::Result<i32> {
  value.parse::<i32>().context("invalid decimal time field")
}

fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
  let year = year - if month <= 2 { 1 } else { 0 };
  let era = if year >= 0 { year } else { year - 399 } / 400;
  let yoe = year - era * 400;
  let mp = month + if month > 2 { -3 } else { 9 };
  let doy = (153 * mp + 2) / 5 + day - 1;
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  i64::from(era * 146_097 + doe - 719_468)
}

fn now_unix_seconds() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs() as i64)
    .unwrap_or_default()
}

struct DerReader<'a> {
  input: &'a [u8],
  offset: usize,
}

impl<'a> DerReader<'a> {
  fn new(input: &'a [u8]) -> Self {
    Self { input, offset: 0 }
  }

  fn single(input: &'a [u8], expected_tag: u8) -> anyhow::Result<&'a [u8]> {
    let mut reader = Self::new(input);
    let value = reader.read(expected_tag)?;
    if !reader.is_empty() {
      bail!("DER value has trailing data");
    }
    Ok(value)
  }

  fn is_empty(&self) -> bool {
    self.offset >= self.input.len()
  }

  fn peek_tag(&self) -> Option<u8> {
    self.input.get(self.offset).copied()
  }

  fn read(&mut self, expected_tag: u8) -> anyhow::Result<&'a [u8]> {
    let (tag, value) = self.read_any()?;
    if tag != expected_tag {
      bail!("unexpected DER tag 0x{tag:02x}, expected 0x{expected_tag:02x}");
    }
    Ok(value)
  }

  fn read_any(&mut self) -> anyhow::Result<(u8, &'a [u8])> {
    if self.offset + 2 > self.input.len() {
      bail!("truncated DER value");
    }
    let tag = self.input[self.offset];
    self.offset += 1;
    let first_len = self.input[self.offset];
    self.offset += 1;
    let len = if first_len & 0x80 == 0 {
      usize::from(first_len)
    } else {
      let bytes = usize::from(first_len & 0x7f);
      if bytes == 0
        || bytes > std::mem::size_of::<usize>()
        || self.offset + bytes > self.input.len()
      {
        bail!("invalid DER length");
      }
      let mut len = 0_usize;
      for byte in &self.input[self.offset..self.offset + bytes] {
        len = (len << 8) | usize::from(*byte);
      }
      self.offset += bytes;
      len
    };
    if self.offset + len > self.input.len() {
      bail!("truncated DER content");
    }
    let value = &self.input[self.offset..self.offset + len];
    self.offset += len;
    Ok((tag, value))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn generalized_time_converts_to_unix_timestamp() {
    assert_eq!(
      parse_generalized_time("19700101000000Z").expect("epoch should parse"),
      0
    );
  }

  #[test]
  fn wildcard_matches_single_label_only() {
    assert!(wildcard_matches("admin.example.test", "example.test"));
    assert!(!wildcard_matches("deep.admin.example.test", "example.test"));
  }
}
