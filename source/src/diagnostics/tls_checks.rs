//! TLS diagnostic checks.
//! Certificate parsing reports validity problems without changing live TLS configuration.

use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use rustls::pki_types::{CertificateDer, pem::PemObject};

use crate::config::{Config, OcspMode, TlsKeyExchangeGroup, TlsVersion};
use crate::tls::ParsedCertificateMetadata;

use super::{DiagnosticReport, DiagnosticSeverity};

pub(super) fn diagnose_tls(config: &Config, report: &mut DiagnosticReport) {
  diagnose_quic_host_key(config, report);
  diagnose_downstream_tls(config, report);
  #[cfg(feature = "admin-runtime")]
  diagnose_admin_tls(config, report);
  diagnose_turn_tls(config, report);
  diagnose_client_auth_roots(config, report);
  diagnose_pqc_tls_version(config, report);
}

fn diagnose_quic_host_key(config: &Config, report: &mut DiagnosticReport) {
  if (config.listeners.http3 || (config.admin.enabled && config.admin.http3.enabled))
    && config.quic.host_key_file.is_none()
  {
    report.push(
      DiagnosticSeverity::Warning,
      "tls.http3_host_key_missing",
      "tls",
      "quic.host_key_file",
      "HTTP/3 is enabled but the QUIC host key is generated ephemerally",
      "Set quic.host_key_file to a persistent, access-restricted path so retry and address-validation state survives restart.",
    );
  }
}

fn diagnose_downstream_tls(config: &Config, report: &mut DiagnosticReport) {
  check_certificate_file(
    report,
    "tls.cert_chain",
    &config.tls.cert_chain,
    &config.tls.server_names,
  );
  for (index, certificate) in config.tls.certificates.iter().enumerate() {
    check_certificate_file(
      report,
      &format!("tls.certificates[{index}].cert_chain"),
      &certificate.cert_chain,
      &certificate.server_names,
    );
  }
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
  } else {
    if let Err(error) = read_first_cert(&config.tls.cert_chain) {
      report.push(
        DiagnosticSeverity::Error,
        "tls.cert_parse_failed",
        "tls",
        "tls.cert_chain",
        format!("downstream certificate chain could not be parsed: {error:#}"),
        "Replace tls.cert_chain with a readable PEM certificate chain.",
      );
    }
    for (index, certificate) in config.tls.certificates.iter().enumerate() {
      if let Err(error) = read_first_cert(&certificate.cert_chain) {
        report.push(
          DiagnosticSeverity::Error,
          "tls.cert_parse_failed",
          "tls",
          format!("tls.certificates[{index}].cert_chain"),
          format!("downstream certificate chain could not be parsed: {error:#}"),
          "Replace the certificate chain with a readable PEM certificate chain.",
        );
      }
    }
  }
  check_ocsp_file(config, report);
}

#[cfg(feature = "admin-runtime")]
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
    if listener.tls_binds().next().is_none() {
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
    .tls13
    .key_exchange_groups
    .contains(&TlsKeyExchangeGroup::X25519MlKem768)
    && config.tls.max_version < TlsVersion::Tls13
  {
    report.push(
      DiagnosticSeverity::Error,
      "tls.pqc_without_tls13",
      "tls",
      "tls.1_3.key_exchange_groups",
      "post-quantum key exchange is configured but TLS 1.3 is disabled",
      "Enable TLS 1.3 or remove x25519mlkem768 from tls.1_3.key_exchange_groups.",
    );
  }
}

fn check_certificate_file(
  report: &mut DiagnosticReport,
  target: &str,
  path: &Path,
  server_names: &[String],
) {
  match read_first_cert(path).and_then(|cert| crate::tls::parse_certificate_metadata(&cert)) {
    Ok(info) => {
      check_validity(report, target, path, &info);
      for name in server_names {
        if !name_covered_by_cert(name, &info) {
          report.push(
            DiagnosticSeverity::Warning,
            "tls.sni_not_covered",
            "tls",
            target,
            format!(
              "TLS server_name {name} is not covered by certificate {}",
              path.display()
            ),
            "Use a certificate whose SAN covers every configured TLS server name value.",
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

fn check_validity(
  report: &mut DiagnosticReport,
  target: &str,
  path: &Path,
  info: &ParsedCertificateMetadata,
) {
  let now = now_unix_seconds();
  if now < info.not_before_unix_seconds {
    report.push(
      DiagnosticSeverity::Error,
      "tls.cert_not_yet_valid",
      "tls",
      target,
      format!("certificate {} is not valid yet", path.display()),
      "Install a certificate whose notBefore is in the past for this deployment clock.",
    );
  }
  if now > info.not_after_unix_seconds {
    report.push(
      DiagnosticSeverity::Error,
      "tls.cert_expired",
      "tls",
      target,
      format!("certificate {} has expired", path.display()),
      "Renew the certificate before serving traffic.",
    );
  } else if info.not_after_unix_seconds.saturating_sub(now) < 14 * 24 * 60 * 60 {
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
  if config.tls.ocsp.mode == OcspMode::StaticFile
    && let Some(path) = &config.tls.ocsp.response_file
  {
    check_ocsp_response_file(report, "tls.ocsp.response_file", path);
  }
  for (index, certificate) in config.tls.certificates.iter().enumerate() {
    if certificate.ocsp.mode == OcspMode::StaticFile
      && let Some(path) = &certificate.ocsp.response_file
    {
      check_ocsp_response_file(
        report,
        &format!("tls.certificates[{index}].ocsp.response_file"),
        path,
      );
    }
  }
}

fn check_ocsp_response_file(report: &mut DiagnosticReport, target: &str, path: &Path) {
  match std::fs::read(path).context("failed to read OCSP response") {
    Ok(bytes) => match earliest_future_der_time(&bytes) {
      Some(next_update) if next_update > now_unix_seconds() => {}
      Some(_) | None => report.push(
        DiagnosticSeverity::Error,
        "tls.ocsp_expired",
        "tls",
        target,
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
      target,
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

fn name_covered_by_cert(name: &str, info: &ParsedCertificateMetadata) -> bool {
  if let Ok(ip) = name.parse::<IpAddr>() {
    return info.san_ip_addresses.contains(&ip);
  }
  let name = name.to_ascii_lowercase();
  info.san_dns_names.iter().any(|candidate| {
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
  use std::fs;
  use std::path::Path;

  use super::*;

  #[allow(dead_code)]
  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  #[test]
  fn certbot_and_lego_certificate_outputs_do_not_report_parse_failure() {
    let temp_dir = common::TempDir::new("tls-acme-bundles");
    let (ca_cert, ca_key) =
      common::create_self_signed_cert(temp_dir.path(), "acme-ca.example.test");
    let (leaf_cert, _leaf_key) =
      common::create_ca_signed_server_cert(temp_dir.path(), "example.com", &ca_cert, &ca_key);
    let fullchain = temp_dir.path().join("fullchain.pem");
    let chain = temp_dir.path().join("chain.pem");
    let lego_leaf = temp_dir.path().join("example.com.crt");
    let lego_issuer = temp_dir.path().join("example.com.issuer.crt");
    let lego_concat = temp_dir.path().join("example.com.chain.crt");

    write_pem_bundle(&fullchain, &[leaf_cert.as_path(), ca_cert.as_path()]);
    write_pem_bundle(&chain, &[ca_cert.as_path()]);
    write_pem_bundle(&lego_leaf, &[leaf_cert.as_path()]);
    write_pem_bundle(&lego_issuer, &[ca_cert.as_path()]);
    write_pem_bundle(&lego_concat, &[leaf_cert.as_path(), ca_cert.as_path()]);

    for path in [&fullchain, &chain, &lego_leaf, &lego_issuer, &lego_concat] {
      let mut report = DiagnosticReport::new();
      check_certificate_file(&mut report, "tls.cert_chain", path, &[]);
      assert!(
        !has_finding(&report, "tls.cert_parse_failed"),
        "{} should not report tls.cert_parse_failed: {:?}",
        path.display(),
        report.findings
      );
    }
  }

  #[test]
  fn fullchain_san_check_uses_leaf_certificate() {
    let temp_dir = common::TempDir::new("tls-fullchain-san");
    let (ca_cert, ca_key) =
      common::create_self_signed_cert(temp_dir.path(), "acme-ca.example.test");
    let (leaf_cert, _leaf_key) =
      common::create_ca_signed_server_cert(temp_dir.path(), "example.com", &ca_cert, &ca_key);
    let fullchain = temp_dir.path().join("fullchain.pem");
    write_pem_bundle(&fullchain, &[leaf_cert.as_path(), ca_cert.as_path()]);

    let mut covered_report = DiagnosticReport::new();
    check_certificate_file(
      &mut covered_report,
      "tls.cert_chain",
      &fullchain,
      &["example.com".to_string()],
    );
    assert!(!has_finding(&covered_report, "tls.cert_parse_failed"));
    assert!(!has_finding(&covered_report, "tls.sni_not_covered"));

    let mut missing_report = DiagnosticReport::new();
    check_certificate_file(
      &mut missing_report,
      "tls.cert_chain",
      &fullchain,
      &["missing.example.com".to_string()],
    );
    assert!(!has_finding(&missing_report, "tls.cert_parse_failed"));
    assert!(has_finding(&missing_report, "tls.sni_not_covered"));
  }

  #[test]
  fn malformed_certificate_still_reports_parse_failure() {
    let temp_dir = common::TempDir::new("tls-malformed-cert");
    let path = temp_dir.path().join("fullchain.pem");
    fs::write(&path, b"not a certificate\n").expect("failed to write malformed certificate");

    let mut report = DiagnosticReport::new();
    check_certificate_file(&mut report, "tls.cert_chain", &path, &[]);

    assert!(has_finding(&report, "tls.cert_parse_failed"));
  }

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

  fn has_finding(report: &DiagnosticReport, id: &str) -> bool {
    report.findings.iter().any(|finding| finding.id == id)
  }

  fn write_pem_bundle(path: &Path, parts: &[&Path]) {
    let mut bundle = Vec::new();
    for part in parts {
      let bytes = fs::read(part).unwrap_or_else(|error| {
        panic!(
          "failed to read certificate fixture {}: {error}",
          part.display()
        )
      });
      bundle.extend_from_slice(&bytes);
      if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
      }
    }
    fs::write(path, bundle)
      .unwrap_or_else(|error| panic!("failed to write PEM bundle {}: {error}", path.display()));
  }
}
