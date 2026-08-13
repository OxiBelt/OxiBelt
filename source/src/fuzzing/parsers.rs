use rustls::pki_types::CertificateDer;

pub fn exercise_native_config(data: &[u8]) {
  crate::config::fuzz_native_config(data);
}

pub fn exercise_oxirule_expression(data: &[u8]) {
  crate::waf::fuzz_expression(data);
}

pub fn exercise_waf_request_normalization(data: &[u8]) {
  crate::waf::fuzz_request_normalization(data);
}

pub fn exercise_http_body_coding(data: &[u8]) {
  crate::proxy::http::waf_body_coding::fuzz_body_coding(data);
}

pub fn exercise_cache_metadata_key(data: &[u8]) {
  crate::cache::fuzz_metadata_and_key(data);
}

pub fn exercise_tls_certificate_metadata(data: &[u8]) {
  const MAX_TOTAL_BYTES: usize = 128 * 1024;
  const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
  const MAX_CERTIFICATES: usize = 4;
  let data = &data[..data.len().min(MAX_TOTAL_BYTES)];
  let mut certificates = Vec::new();
  let mut remaining = data;
  while !remaining.is_empty() && certificates.len() < MAX_CERTIFICATES {
    let requested = remaining
      .first()
      .copied()
      .map(usize::from)
      .unwrap_or_default()
      .saturating_mul(257)
      .min(MAX_CERTIFICATE_BYTES);
    remaining = remaining.get(1..).unwrap_or_default();
    let length = requested.min(remaining.len());
    let (certificate, rest) = remaining.split_at(length);
    certificates.push(CertificateDer::from(certificate.to_vec()));
    remaining = rest;
  }
  if certificates.is_empty() {
    certificates.push(CertificateDer::from(data.to_vec()));
  }
  let _ = crate::tls::client_certificate_metadata(&certificates);
  #[cfg(feature = "admin-runtime")]
  let _ = crate::tls::verified_client_certificate(&certificates);
  for certificate in &certificates {
    let _ = crate::tls::parse_certificate_metadata(certificate.as_ref());
  }
}
