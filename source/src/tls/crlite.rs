use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow, bail};
use clubcard_crlite::{CRLiteClubcard, CRLiteKey, CRLiteStatus, IssuerSpkiHash, LogId, Timestamp};
use x509_cert::Certificate;
use x509_cert::der::{
  Decode, Encode,
  asn1::{ObjectIdentifier, OctetString},
};

use crate::config::{CrliteConfig, CrliteCoveragePolicy, CrliteFailurePolicy, TlsConfig};

use super::certificate_io::load_certs;

const CT_PRECERT_SCTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

type Serial = Vec<u8>;
type SctEntries = Vec<(LogId, Timestamp)>;

pub(super) struct CrliteQueryMaterial {
  issuer_spki_hash: IssuerSpkiHash,
  serial: Serial,
  scts: SctEntries,
}

pub(super) struct CrliteCheckOutcome {
  pub(super) status: &'static str,
  pub(super) result: Option<&'static str>,
  pub(super) filter_loaded: bool,
  pub(super) filter_stale: bool,
  pub(super) error_code: Option<&'static str>,
  pub(super) certificate_rejected: bool,
}

pub(super) fn check_crlite(tls: &TlsConfig) -> anyhow::Result<CrliteCheckOutcome> {
  let filter_path = tls
    .crlite
    .filter_file
    .as_deref()
    .ok_or_else(|| anyhow!("crlite_missing_filter_file"))?;
  let (filter, stale) = load_filter(&tls.crlite, filter_path)?;
  let materials = crlite_query_materials(tls)?;
  check_crlite_filter_for_materials(&tls.crlite, &materials, &filter, stale)
}

pub(super) fn check_crlite_filter_bytes(
  tls: &TlsConfig,
  bytes: &[u8],
  stale: bool,
) -> anyhow::Result<CrliteCheckOutcome> {
  let materials = crlite_query_materials(tls)?;
  check_crlite_filter_bytes_for_materials(&tls.crlite, &materials, bytes, stale)
}

pub(super) fn check_crlite_config(
  config: &CrliteConfig,
  material: &CrliteQueryMaterial,
) -> anyhow::Result<CrliteCheckOutcome> {
  let filter_path = config
    .filter_file
    .as_deref()
    .ok_or_else(|| anyhow!("crlite_missing_filter_file"))?;
  let (filter, stale) = load_filter(config, filter_path)?;
  check_crlite_filter(config, material, &filter, stale)
}

pub(super) fn check_crlite_filter_bytes_for_material(
  config: &CrliteConfig,
  material: &CrliteQueryMaterial,
  bytes: &[u8],
  stale: bool,
) -> anyhow::Result<CrliteCheckOutcome> {
  check_crlite_filter_bytes_for_materials(config, std::slice::from_ref(material), bytes, stale)
}

fn check_crlite_filter_bytes_for_materials(
  config: &CrliteConfig,
  materials: &[CrliteQueryMaterial],
  bytes: &[u8],
  stale: bool,
) -> anyhow::Result<CrliteCheckOutcome> {
  if bytes.len() > config.max_filter_bytes {
    bail!("crlite_filter_too_large");
  }
  let filter = CRLiteClubcard::from_bytes(bytes).map_err(|_| anyhow!("crlite_filter_parse"))?;
  check_crlite_filter_for_materials(config, materials, &filter, stale)
}

fn check_crlite_filter_for_materials(
  config: &CrliteConfig,
  materials: &[CrliteQueryMaterial],
  filter: &CRLiteClubcard,
  stale: bool,
) -> anyhow::Result<CrliteCheckOutcome> {
  let mut degraded = None;
  for material in materials {
    let outcome = check_crlite_filter(config, material, filter, stale)?;
    if outcome.certificate_rejected {
      return Ok(outcome);
    }
    if outcome.error_code.is_some() {
      degraded = Some(outcome);
    }
  }
  Ok(degraded.unwrap_or(CrliteCheckOutcome {
    status: if stale { "degraded" } else { "fresh" },
    result: None,
    filter_loaded: true,
    filter_stale: stale,
    error_code: stale.then_some("crlite_filter_stale"),
    certificate_rejected: false,
  }))
}

fn check_crlite_filter(
  config: &CrliteConfig,
  material: &CrliteQueryMaterial,
  filter: &CRLiteClubcard,
  stale: bool,
) -> anyhow::Result<CrliteCheckOutcome> {
  let key = CRLiteKey::new(&material.issuer_spki_hash, &material.serial);
  let status = filter.contains(
    &key,
    material
      .scts
      .iter()
      .map(|(log_id, timestamp)| (*log_id, *timestamp)),
  );
  let result = crlite_result_name(&status);
  if status == CRLiteStatus::Revoked {
    return Ok(CrliteCheckOutcome {
      status: "revoked",
      result: Some(result),
      filter_loaded: true,
      filter_stale: stale,
      error_code: None,
      certificate_rejected: true,
    });
  }
  if config.coverage_policy == CrliteCoveragePolicy::RequireGood && status != CRLiteStatus::Good {
    return Ok(CrliteCheckOutcome {
      status: "degraded",
      result: Some(result),
      filter_loaded: true,
      filter_stale: stale,
      error_code: Some(crlite_coverage_error_code(&status)),
      certificate_rejected: true,
    });
  }
  Ok(CrliteCheckOutcome {
    status: if stale { "degraded" } else { "fresh" },
    result: Some(result),
    filter_loaded: true,
    filter_stale: stale,
    error_code: stale.then_some("crlite_filter_stale"),
    certificate_rejected: false,
  })
}

fn load_filter(config: &CrliteConfig, path: &Path) -> anyhow::Result<(CRLiteClubcard, bool)> {
  let metadata = fs::metadata(path).context("crlite_filter_metadata")?;
  if metadata.len() > config.max_filter_bytes as u64 {
    bail!("crlite_filter_too_large");
  }
  let stale = filter_is_stale(&metadata, config.max_filter_age_seconds)?;
  let bytes = fs::read(path).context("crlite_filter_read")?;
  if let Some(expected) = config.filter_sha256.as_deref() {
    verify_sha256(expected, &bytes)?;
  }
  let filter = CRLiteClubcard::from_bytes(&bytes).map_err(|_| anyhow!("crlite_filter_parse"))?;
  Ok((filter, stale))
}

fn crlite_result_name(status: &CRLiteStatus) -> &'static str {
  match status {
    CRLiteStatus::Good => "good",
    CRLiteStatus::Revoked => "revoked",
    CRLiteStatus::NotCovered => "not_covered",
    CRLiteStatus::NotEnrolled => "not_enrolled",
  }
}

fn crlite_coverage_error_code(status: &CRLiteStatus) -> &'static str {
  match status {
    CRLiteStatus::NotCovered => "crlite_not_covered",
    CRLiteStatus::NotEnrolled => "crlite_not_enrolled",
    CRLiteStatus::Good | CRLiteStatus::Revoked => "crlite_error",
  }
}

fn filter_is_stale(metadata: &fs::Metadata, max_age_seconds: u64) -> anyhow::Result<bool> {
  let modified = metadata.modified().context("crlite_filter_modified_time")?;
  Ok(match modified.elapsed() {
    Ok(age) => filter_age_is_stale(age, max_age_seconds),
    Err(_) => true,
  })
}

fn filter_age_is_stale(age: Duration, max_age_seconds: u64) -> bool {
  age.gt(&Duration::from_secs(max_age_seconds))
}

fn verify_sha256(expected: &str, bytes: &[u8]) -> anyhow::Result<()> {
  let actual = hex_digest(&crate::crypto::sha256(bytes));
  if !actual.eq_ignore_ascii_case(expected) {
    bail!("crlite_filter_sha256_mismatch");
  }
  Ok(())
}

fn crlite_query_materials(tls: &TlsConfig) -> anyhow::Result<Vec<CrliteQueryMaterial>> {
  let mut materials = vec![crlite_query_material_from_cert_chain(&tls.cert_chain)?];
  for certificate in &tls.certificates {
    materials.push(crlite_query_material_from_cert_chain(
      &certificate.cert_chain,
    )?);
  }
  Ok(materials)
}

fn crlite_query_material_from_cert_chain(
  cert_chain: &std::path::Path,
) -> anyhow::Result<CrliteQueryMaterial> {
  let certs = load_certs(cert_chain).context("crlite_cert_chain_read")?;
  let leaf_der = certs
    .first()
    .ok_or_else(|| anyhow!("crlite_missing_leaf_certificate"))?
    .as_ref();
  let issuer_der = certs
    .get(1)
    .ok_or_else(|| anyhow!("crlite_missing_issuer_certificate"))?
    .as_ref();
  crlite_query_material_from_der(leaf_der, issuer_der)
}

pub(super) fn crlite_query_material_from_der(
  leaf_der: &[u8],
  issuer_der: &[u8],
) -> anyhow::Result<CrliteQueryMaterial> {
  let leaf = Certificate::from_der(leaf_der).context("crlite_leaf_parse")?;
  let issuer = Certificate::from_der(issuer_der).context("crlite_issuer_parse")?;
  let issuer_spki_der = issuer
    .tbs_certificate
    .subject_public_key_info
    .to_der()
    .context("crlite_issuer_spki_encode")?;
  let mut issuer_spki_hash = [0_u8; 32];
  issuer_spki_hash.copy_from_slice(&crate::crypto::sha256(&issuer_spki_der));
  let serial = leaf.tbs_certificate.serial_number.as_bytes().to_vec();
  let scts = embedded_scts(&leaf)?;
  Ok(CrliteQueryMaterial {
    issuer_spki_hash: IssuerSpkiHash(issuer_spki_hash),
    serial,
    scts,
  })
}

fn embedded_scts(leaf: &Certificate) -> anyhow::Result<SctEntries> {
  let Some(extensions) = leaf.tbs_certificate.extensions.as_deref() else {
    return Ok(Vec::new());
  };
  let Some(extension) = extensions
    .iter()
    .find(|extension| extension.extn_id == CT_PRECERT_SCTS)
  else {
    return Ok(Vec::new());
  };
  let sct_list =
    OctetString::from_der(extension.extn_value.as_bytes()).context("crlite_sct_extension_parse")?;
  parse_sct_list(sct_list.as_bytes())
}

fn parse_sct_list(mut bytes: &[u8]) -> anyhow::Result<SctEntries> {
  let list_len = read_u16(&mut bytes)? as usize;
  if bytes.len() != list_len {
    bail!("crlite_sct_list_length");
  }
  let mut scts = Vec::new();
  while !bytes.is_empty() {
    let sct_len = read_u16(&mut bytes)? as usize;
    if bytes.len() < sct_len {
      bail!("crlite_sct_length");
    }
    let (sct, rest) = bytes.split_at(sct_len);
    bytes = rest;
    if sct.len() < 41 {
      bail!("crlite_sct_short");
    }
    if sct[0] != 0 {
      continue;
    }
    let mut log_id = [0_u8; 32];
    log_id.copy_from_slice(&sct[1..33]);
    let mut timestamp = [0_u8; 8];
    timestamp.copy_from_slice(&sct[33..41]);
    scts.push((LogId(log_id), Timestamp(u64::from_be_bytes(timestamp))));
  }
  Ok(scts)
}

fn read_u16(bytes: &mut &[u8]) -> anyhow::Result<u16> {
  if bytes.len() < 2 {
    bail!("crlite_tls_vector_short");
  }
  let value = u16::from_be_bytes([bytes[0], bytes[1]]);
  *bytes = &bytes[2..];
  Ok(value)
}

pub(super) fn classify_crlite_error(error: &anyhow::Error) -> &'static str {
  let message = format!("{error:#}");
  for code in [
    "crlite_filter_stale",
    "crlite_filter_sha256_mismatch",
    "crlite_filter_too_large",
    "crlite_filter_parse",
    "crlite_filter_read",
    "crlite_filter_metadata",
    "crlite_missing_filter_file",
    "crlite_missing_issuer_certificate",
    "crlite_missing_leaf_certificate",
    "crlite_cert_chain_read",
    "crlite_leaf_parse",
    "crlite_issuer_parse",
    "crlite_issuer_spki_encode",
    "crlite_sct_extension_parse",
    "crlite_sct_list_length",
    "crlite_sct_length",
    "crlite_sct_short",
    "crlite_tls_vector_short",
    "crlite_managed_attachment_base_url",
    "crlite_managed_attachment_base_url_scheme",
    "crlite_managed_attachment_fetch",
    "crlite_managed_attachment_hash",
    "crlite_managed_attachment_http_status",
    "crlite_managed_attachment_size_mismatch",
    "crlite_managed_attachment_too_large",
    "crlite_managed_attachment_url",
    "crlite_managed_attachment_url_scheme",
    "crlite_managed_cache_filter_read",
    "crlite_managed_cache_filter_write",
    "crlite_managed_cache_hash_mismatch",
    "crlite_managed_cache_metadata_encode",
    "crlite_managed_cache_metadata_parse",
    "crlite_managed_cache_metadata_read",
    "crlite_managed_cache_metadata_write",
    "crlite_managed_cache_size_mismatch",
    "crlite_managed_cache_too_large",
    "crlite_managed_http",
    "crlite_managed_http_status",
    "crlite_managed_json_parse",
    "crlite_managed_missing_attachment",
    "crlite_managed_missing_attachment_base_url",
    "crlite_managed_no_filter_record",
    "crlite_managed_records_fetch",
    "crlite_managed_request_build",
    "crlite_managed_root_fetch",
    "crlite_managed_sha256_mismatch",
  ] {
    if message.contains(code) {
      return code;
    }
  }
  "crlite_error"
}

pub(super) fn failure_policy_name(policy: CrliteFailurePolicy) -> &'static str {
  match policy {
    CrliteFailurePolicy::FailClosed => "fail_closed",
    CrliteFailurePolicy::DegradedAllow => "degraded_allow",
  }
}

pub(super) fn coverage_policy_name(policy: CrliteCoveragePolicy) -> &'static str {
  match policy {
    CrliteCoveragePolicy::AllowUnknown => "allow_unknown",
    CrliteCoveragePolicy::RequireGood => "require_good",
  }
}

fn hex_digest(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

pub(super) fn unix_now() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

#[cfg(test)]
mod tests {
  use super::super::crlite_runtime::CrliteRuntime;
  use super::*;
  use crate::config::{CrliteConfig, CrliteCoveragePolicy, CrliteFailurePolicy, CrliteMode};
  use crate::metrics::Metrics;
  use base64::Engine;
  use clubcard::builder::{ApproximateRibbon, ClubcardBuilder, ExactRibbon};
  use clubcard_crlite::builder::CRLiteBuilderItem;
  use clubcard_crlite::{CRLiteCoverage, CRLiteQuery, Encoding};

  #[test]
  fn valid_filter_bytes_round_trip_and_query() {
    let issuer = IssuerSpkiHash([5_u8; 32]);
    let other_issuer = IssuerSpkiHash([6_u8; 32]);
    let log_id = LogId([9_u8; 32]);
    let revoked_serial = vec![1_u8];
    let good_serial = vec![2_u8];
    let filter = test_crlite_filter(issuer, log_id, &revoked_serial, &good_serial);
    let bytes = filter
      .to_bytes(Encoding::V4)
      .expect("filter should serialize");

    let parsed = CRLiteClubcard::from_bytes(&bytes).expect("filter should parse");
    let revoked_key = CRLiteKey::new(&issuer, &revoked_serial);
    let good_key = CRLiteKey::new(&issuer, &good_serial);
    let not_enrolled_key = CRLiteKey::new(&other_issuer, &revoked_serial);
    let covered_sct = std::iter::once((log_id, Timestamp(100)));
    let uncovered_log = LogId([8_u8; 32]);

    assert_eq!(
      parsed.contains(&revoked_key, covered_sct),
      CRLiteStatus::Revoked
    );
    assert_eq!(
      parsed.contains(&good_key, std::iter::once((log_id, Timestamp(100)))),
      CRLiteStatus::Good
    );
    assert_eq!(
      parsed.contains(
        &revoked_key,
        std::iter::once((uncovered_log, Timestamp(100)))
      ),
      CRLiteStatus::NotCovered
    );
    assert_eq!(
      parsed.contains(&not_enrolled_key, std::iter::once((log_id, Timestamp(100)))),
      CRLiteStatus::NotEnrolled
    );
  }

  #[tokio::test]
  async fn invalid_filter_bytes_return_parse_error() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let filter = temp_dir.path().join("crlite.filter");
    fs::write(&filter, b"not a crlite clubcard").expect("write filter");
    let mut tls = test_tls_config(filter);
    tls.crlite.failure_policy = CrliteFailurePolicy::FailClosed;

    let error = CrliteRuntime::new(&tls, Metrics::new())
      .await
      .expect_err("invalid filter should fail");

    assert!(error.to_string().contains("crlite_filter_parse"));
  }

  #[tokio::test]
  async fn degraded_allow_keeps_bounded_status_for_invalid_filter() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let filter = temp_dir.path().join("crlite.filter");
    fs::write(&filter, b"not a crlite clubcard").expect("write filter");
    let mut tls = test_tls_config(filter);
    tls.crlite.failure_policy = CrliteFailurePolicy::DegradedAllow;

    let runtime = CrliteRuntime::new(&tls, Metrics::new())
      .await
      .expect("degraded allow should load");
    let status = runtime.status();

    assert_eq!(status.status, "degraded");
    assert_eq!(
      status.last_error_code.as_deref(),
      Some("crlite_filter_parse")
    );
    assert!(!status.filter_loaded);
  }

  #[tokio::test]
  async fn missing_filter_file_returns_bounded_error_code() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let mut tls = test_tls_config(temp_dir.path().join("missing.filter"));
    tls.crlite.failure_policy = CrliteFailurePolicy::DegradedAllow;

    let runtime = CrliteRuntime::new(&tls, Metrics::new())
      .await
      .expect("degraded allow should load");
    let status = runtime.status();

    assert_eq!(status.status, "degraded");
    assert_eq!(
      status.last_error_code.as_deref(),
      Some("crlite_filter_metadata")
    );
    assert!(!status.filter_loaded);
  }

  #[tokio::test]
  async fn oversized_filter_is_rejected_before_parse() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let filter = temp_dir.path().join("crlite.filter");
    fs::write(&filter, b"too large").expect("write filter");
    let mut tls = test_tls_config(filter);
    tls.crlite.max_filter_bytes = 1;
    tls.crlite.failure_policy = CrliteFailurePolicy::FailClosed;

    let error = CrliteRuntime::new(&tls, Metrics::new())
      .await
      .expect_err("oversized filter should fail");

    assert!(error.to_string().contains("crlite_filter_too_large"));
  }

  #[tokio::test]
  async fn filter_sha256_mismatch_is_rejected_before_parse() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let filter = temp_dir.path().join("crlite.filter");
    fs::write(&filter, b"filter bytes").expect("write filter");
    let mut tls = test_tls_config(filter);
    tls.crlite.filter_sha256 =
      Some("0000000000000000000000000000000000000000000000000000000000000000".to_string());
    tls.crlite.failure_policy = CrliteFailurePolicy::FailClosed;

    let error = CrliteRuntime::new(&tls, Metrics::new())
      .await
      .expect_err("hash mismatch should fail");

    assert!(error.to_string().contains("crlite_filter_sha256_mismatch"));
  }

  #[test]
  fn filter_age_policy_marks_old_filters_stale() {
    assert!(!filter_age_is_stale(Duration::from_secs(60), 60));
    assert!(filter_age_is_stale(Duration::from_secs(61), 60));
  }

  #[test]
  fn future_filter_mtime_is_stale() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let filter = temp_dir.path().join("crlite.filter");
    fs::write(&filter, b"filter bytes").expect("write filter");
    let future = SystemTime::now() + Duration::from_secs(60);
    let times = fs::FileTimes::new().set_modified(future);
    fs::File::open(&filter)
      .expect("open filter")
      .set_times(times)
      .expect("set future filter mtime");
    let metadata = fs::metadata(&filter).expect("filter metadata");

    assert!(filter_is_stale(&metadata, 60).expect("stale check"));
  }

  #[test]
  fn coverage_policy_requires_good_for_unknown_results() {
    let outcome = CRLiteStatus::NotCovered;
    assert_eq!(
      coverage_error(CrliteCoveragePolicy::RequireGood, &outcome),
      Some("crlite_not_covered")
    );
    assert_eq!(
      coverage_error(CrliteCoveragePolicy::AllowUnknown, &outcome),
      None
    );
  }

  #[test]
  fn sct_parser_extracts_log_id_and_timestamp() {
    let log_id = [7_u8; 32];
    let timestamp = 1_700_000_000_000_u64;
    let mut sct = Vec::new();
    sct.push(0);
    sct.extend_from_slice(&log_id);
    sct.extend_from_slice(&timestamp.to_be_bytes());
    sct.extend_from_slice(&[0, 0, 0, 0]);
    let mut list = Vec::new();
    list.extend_from_slice(&((sct.len() + 2) as u16).to_be_bytes());
    list.extend_from_slice(&(sct.len() as u16).to_be_bytes());
    list.extend_from_slice(&sct);

    let parsed = parse_sct_list(&list).expect("SCT list should parse");

    assert_eq!(parsed, vec![(LogId(log_id), Timestamp(timestamp))]);
  }

  fn coverage_error(policy: CrliteCoveragePolicy, status: &CRLiteStatus) -> Option<&'static str> {
    if policy != CrliteCoveragePolicy::RequireGood || status == &CRLiteStatus::Good {
      return None;
    }
    Some(crlite_coverage_error_code(status))
  }

  fn test_tls_config(filter_file: std::path::PathBuf) -> TlsConfig {
    TlsConfig {
      server_names: Vec::new(),
      cert_chain: std::path::PathBuf::from("cert.pem"),
      private_key: Some(std::path::PathBuf::from("key.pem")),
      remote_signer: crate::config::TlsRemoteSignerConfig::default(),
      require_sni: false,
      reject_unknown_sni: false,
      ssl_early_data: None,
      certificates: Vec::new(),
      min_version: crate::config::TlsVersion::Tls13,
      max_version: crate::config::TlsVersion::Tls13,
      tls12: crate::config::Tls12NegotiationConfig {
        groups: Vec::new(),
        key_exchange_groups: Vec::new(),
      },
      tls13: crate::config::Tls13NegotiationConfig {
        key_exchange_groups: Vec::new(),
        ciphers: Vec::new(),
      },
      key_exchange_groups: Vec::new(),
      session_tickets: true,
      session_ticket_rotation_seconds: 86_400,
      resumption: crate::config::TlsServerResumptionConfig::default(),
      client_auth: crate::config::TlsClientAuthConfig::default(),
      ocsp: crate::config::OcspConfig::default(),
      crlite: CrliteConfig {
        mode: CrliteMode::Enforce,
        filter_file: Some(filter_file),
        ..CrliteConfig::default()
      },
    }
  }

  fn test_crlite_filter(
    issuer: IssuerSpkiHash,
    log_id: LogId,
    revoked_serial: &[u8],
    good_serial: &[u8],
  ) -> CRLiteClubcard {
    let mut builder = ClubcardBuilder::new();
    let mut approx_builder = builder.new_approx_builder(&issuer.0);
    approx_builder.insert(CRLiteBuilderItem::revoked(issuer, revoked_serial.to_vec()));
    approx_builder.set_universe_size(2);
    builder.collect_approx_ribbons(vec![ApproximateRibbon::from(approx_builder)]);

    let mut exact_builder = builder.new_exact_builder(&issuer.0);
    exact_builder.insert(CRLiteBuilderItem::revoked(issuer, revoked_serial.to_vec()));
    exact_builder.insert(CRLiteBuilderItem::not_revoked(issuer, good_serial.to_vec()));
    builder.collect_exact_ribbons(vec![ExactRibbon::from(exact_builder)]);

    let ct_logs = format!(
      r#"[{{"LogID":"{}","MaxTimestamp":1000,"MinTimestamp":0,"MMD":0,"MinEntry":0}}]"#,
      base64::engine::general_purpose::STANDARD.encode(log_id.0)
    );
    builder
      .build::<CRLiteQuery>(
        CRLiteCoverage::from_mozilla_ct_logs_json(ct_logs.as_bytes()),
        (),
      )
      .into()
  }
}
