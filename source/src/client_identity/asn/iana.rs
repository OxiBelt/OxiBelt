use std::time::Duration;

use anyhow::{Context, bail};
use http::header::ACCEPT;
use url::Url;

use crate::config::ClientIdentityAsnConfig;
use crate::control_http::{ControlHttpClient, empty_body, uri_from_url};

const IANA_REGISTRY_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct AsnRegistry {
  ranges: Vec<(u32, u32)>,
}

impl AsnRegistry {
  pub(super) fn validate(&self, asn: u32) -> anyhow::Result<()> {
    if self
      .ranges
      .iter()
      .any(|(start, end)| *start <= asn && asn <= *end)
    {
      return Ok(());
    }
    bail!("asn_not_in_iana_registry")
  }
}

pub(super) async fn load_registry(
  config: &ClientIdentityAsnConfig,
  control_http: &ControlHttpClient,
) -> anyhow::Result<Option<AsnRegistry>> {
  if !config.iana_registry.enabled {
    return Ok(None);
  }
  let mut ranges = Vec::new();
  for raw_url in &config.iana_registry.source_urls {
    let url = Url::parse(raw_url).context("asn_iana_registry_source_url")?;
    if url.scheme() != "https" {
      bail!("asn_iana_registry_source_url_scheme");
    }
    let request = http::Request::builder()
      .method(http::Method::GET)
      .uri(uri_from_url(&url)?)
      .header(ACCEPT, "text/csv,text/plain,*/*")
      .body(empty_body())
      .context("asn_iana_registry_request_build")?;
    let response = control_http
      .request(
        request,
        Duration::from_millis(config.managed.request_timeout_ms),
        IANA_REGISTRY_MAX_BYTES,
      )
      .await
      .context("asn_iana_registry_http")?;
    if response.status != http::StatusCode::OK {
      bail!("asn_iana_registry_http_status");
    }
    let text = std::str::from_utf8(&response.body).context("asn_iana_registry_utf8")?;
    ranges.extend(parse_registry_csv(text)?);
  }
  if ranges.is_empty() {
    bail!("asn_iana_registry_empty");
  }
  Ok(Some(AsnRegistry { ranges }))
}

fn parse_registry_csv(text: &str) -> anyhow::Result<Vec<(u32, u32)>> {
  let mut ranges = Vec::new();
  for (index, line) in text.lines().enumerate() {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
      continue;
    }
    let Some((number, _rest)) = line.split_once(',') else {
      bail!("asn_iana_registry_line_{}_invalid_shape", index + 1);
    };
    let number = number.trim().trim_matches('"');
    if number.eq_ignore_ascii_case("number") {
      continue;
    }
    let (start, end) = parse_iana_asn_range(number)
      .with_context(|| format!("asn_iana_registry_line_{}_invalid_range", index + 1))?;
    ranges.push((start, end));
  }
  Ok(ranges)
}

fn parse_iana_asn_range(raw: &str) -> anyhow::Result<(u32, u32)> {
  if let Some((start, end)) = raw.split_once('-') {
    let start = super::parse_asn(start.trim())?;
    let end = super::parse_asn(end.trim())?;
    if start > end {
      bail!("invalid ASN range");
    }
    return Ok((start, end));
  }
  let asn = super::parse_asn(raw.trim())?;
  Ok((asn, asn))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn iana_registry_csv_parses_ranges_and_validates_database_asns() {
    let ranges = parse_registry_csv(
      r#"
Number,Name,WHOIS,RDAP,Reference
64496-64511,Documentation,,
64512,Private Use,,
"#,
    )
    .unwrap();
    let registry = AsnRegistry { ranges };
    assert!(
      super::super::parse_prefix_asn_csv("203.0.113.0/24,AS64500\n", 16, Some(&registry),).is_ok()
    );
    assert!(
      super::super::parse_prefix_asn_csv("203.0.113.0/24,AS64520\n", 16, Some(&registry),).is_err()
    );
  }
}
