use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use oxibelt::waf::{RULEPACK_FILE_SUFFIX, RulepackSourceProvenance};
use serde::Serialize;

use crate::cli::RulepackModeArg;

pub(crate) const RULEPACK_INSTALL_FILE_SUFFIX: &str = ".install.toml";

#[derive(Debug)]
pub(crate) struct RulepackInstallLockInput<'a> {
  pub(crate) name: &'a str,
  pub(crate) version: &'a str,
  pub(crate) source: &'a str,
  pub(crate) source_commit: Option<&'a str>,
  pub(crate) source_provenance: Option<&'a RulepackSourceProvenance>,
  pub(crate) selected_profile: Option<&'a str>,
  pub(crate) effective_mode: RulepackModeArg,
  pub(crate) force_mode: bool,
  pub(crate) bindings: &'a BTreeMap<String, String>,
  pub(crate) values: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct RulepackInstallLock<'a> {
  install: RulepackInstallSection<'a>,
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  bindings: &'a BTreeMap<String, String>,
  #[serde(skip_serializing_if = "BTreeMap::is_empty")]
  values: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct RulepackInstallSection<'a> {
  name: &'a str,
  version: &'a str,
  source: &'a str,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_commit: Option<&'a str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_url: Option<&'a str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_sha256: Option<&'a str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_openpgp_signature_url: Option<&'a str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  source_openpgp_signer_fingerprint: Option<&'a str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  profile: Option<&'a str>,
  effective_mode: &'static str,
  force_mode: bool,
  installed_at: String,
}

pub(crate) fn installed_rulepack_path(name: &str) -> anyhow::Result<String> {
  ensure_install_name(name)?;
  Ok(format!("rulepacks/{name}{RULEPACK_FILE_SUFFIX}"))
}

pub(crate) fn installed_rulepack_lock_path(name: &str) -> anyhow::Result<String> {
  ensure_install_name(name)?;
  Ok(format!("rulepacks/{name}{RULEPACK_INSTALL_FILE_SUFFIX}"))
}

pub(crate) fn render_install_lock(input: RulepackInstallLockInput<'_>) -> anyhow::Result<String> {
  ensure_install_name(input.name)?;
  let provenance = input.source_provenance;
  let lock = RulepackInstallLock {
    install: RulepackInstallSection {
      name: input.name,
      version: input.version,
      source: input.source,
      source_commit: input.source_commit,
      source_url: provenance.map(|value| value.source_url.as_str()),
      source_sha256: provenance.map(|value| value.source_sha256.as_str()),
      source_openpgp_signature_url: provenance
        .and_then(|value| value.source_openpgp_signature_url.as_deref()),
      source_openpgp_signer_fingerprint: provenance
        .and_then(|value| value.source_openpgp_signer_fingerprint.as_deref()),
      profile: input.selected_profile,
      effective_mode: mode_name(input.effective_mode),
      force_mode: input.force_mode,
      installed_at: rfc3339_now(),
    },
    bindings: input.bindings,
    values: input.values,
  };
  toml::to_string_pretty(&lock).context("failed to render rulepack install lock")
}

fn ensure_install_name(name: &str) -> anyhow::Result<()> {
  if name.trim().is_empty()
    || name
      .chars()
      .any(|character| matches!(character, '/' | '\\' | '?' | '#'))
  {
    bail!("rulepack name is not valid for an install path");
  }
  Ok(())
}

fn mode_name(mode: RulepackModeArg) -> &'static str {
  match mode {
    RulepackModeArg::Monitor => "monitor",
    RulepackModeArg::Enforcing => "enforcing",
  }
}

fn rfc3339_now() -> String {
  let seconds = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs() as i64)
    .unwrap_or_default();
  let days = seconds.div_euclid(86_400);
  let seconds_of_day = seconds.rem_euclid(86_400);
  let (year, month, day) = civil_from_days(days);
  let hour = seconds_of_day / 3_600;
  let minute = seconds_of_day % 3_600 / 60;
  let second = seconds_of_day % 60;
  format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
  let days = days_since_epoch + 719_468;
  let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
  let day_of_era = days - era * 146_097;
  let year_of_era =
    (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
  let mut year = year_of_era + era * 400;
  let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  let month_prime = (5 * day_of_year + 2) / 153;
  let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
  let month = month_prime + if month_prime < 10 { 3 } else { -9 };
  year += i64::from(month <= 2);
  (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn install_paths_reject_path_separators() {
    assert!(installed_rulepack_path("vaultwarden").is_ok());
    assert!(installed_rulepack_lock_path("vaultwarden").is_ok());
    assert!(installed_rulepack_path("../bad").is_err());
    assert!(installed_rulepack_lock_path("bad/name").is_err());
  }

  #[test]
  fn install_lock_records_selected_values() {
    let rendered = render_install_lock(RulepackInstallLockInput {
      name: "vaultwarden",
      version: "0.1.0",
      source: "file vaultwarden.oxirule-rulepack.toml",
      source_commit: None,
      source_provenance: None,
      selected_profile: Some("public-production"),
      effective_mode: RulepackModeArg::Enforcing,
      force_mode: true,
      bindings: &BTreeMap::from([("app_route".to_string(), "mmsecretvault".to_string())]),
      values: &BTreeMap::from([("admin_cidr".to_string(), "10.10.0.0/16".to_string())]),
    })
    .expect("install lock");

    assert!(rendered.contains("[install]"));
    assert!(rendered.contains("profile = \"public-production\""));
    assert!(rendered.contains("effective_mode = \"enforcing\""));
    assert!(rendered.contains("[bindings]"));
    assert!(rendered.contains("app_route = \"mmsecretvault\""));
    assert!(rendered.contains("[values]"));
    assert!(rendered.contains("admin_cidr = \"10.10.0.0/16\""));
  }
}
