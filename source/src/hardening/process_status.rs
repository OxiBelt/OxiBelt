//! Safe parsing and injection boundary for Linux process-hardening evidence.

use std::fmt;
use std::fs;
use std::io;

use serde::{Deserialize, Serialize};

const SECCOMP_FIELD: &str = "Seccomp";
const SECCOMP_FILTERS_FIELD: &str = "Seccomp_filters";
const NO_NEW_PRIVS_FIELD: &str = "NoNewPrivs";

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedSeccompMode {
  Disabled,
  Strict,
  Filter,
  Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedNoNewPrivileges {
  Disabled,
  Enabled,
  Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProcessHardeningEvidence {
  pub seccomp_mode: ObservedSeccompMode,
  pub no_new_privs: ObservedNoNewPrivileges,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub seccomp_filters: Option<u32>,
}

pub trait ProcessStatusSource {
  fn read_process_status(&self) -> io::Result<String>;
}

#[derive(Debug, Default)]
pub struct ProcSelfStatusSource;

impl ProcessStatusSource for ProcSelfStatusSource {
  fn read_process_status(&self) -> io::Result<String> {
    fs::read_to_string("/proc/self/status")
  }
}

#[derive(Debug)]
pub enum ProcessStatusObservationError {
  Read(io::Error),
  Parse(ProcessStatusParseError),
}

impl ProcessStatusObservationError {
  pub const fn is_read_error(&self) -> bool {
    matches!(self, Self::Read(_))
  }
}

impl fmt::Display for ProcessStatusObservationError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Read(error) => write!(formatter, "failed to read process status: {error}"),
      Self::Parse(error) => write!(formatter, "failed to parse process status: {error}"),
    }
  }
}

impl std::error::Error for ProcessStatusObservationError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::Read(error) => Some(error),
      Self::Parse(error) => Some(error),
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProcessStatusParseError {
  DuplicateField(&'static str),
  MissingField(&'static str),
  InvalidValue(&'static str),
}

impl fmt::Display for ProcessStatusParseError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DuplicateField(field) => write!(formatter, "duplicate {field} field"),
      Self::MissingField(field) => write!(formatter, "missing {field} field"),
      Self::InvalidValue(field) => write!(formatter, "invalid {field} value"),
    }
  }
}

impl std::error::Error for ProcessStatusParseError {}

pub fn observe_process_hardening(
  source: &dyn ProcessStatusSource,
) -> Result<ProcessHardeningEvidence, ProcessStatusObservationError> {
  let raw = source
    .read_process_status()
    .map_err(ProcessStatusObservationError::Read)?;
  parse_process_status(&raw).map_err(ProcessStatusObservationError::Parse)
}

pub fn parse_process_status(
  raw: &str,
) -> Result<ProcessHardeningEvidence, ProcessStatusParseError> {
  let mut seccomp = None;
  let mut no_new_privs = None;
  let mut seccomp_filters = None;
  let mut saw_seccomp_filters = false;

  for line in raw.lines() {
    let Some((field, value)) = line.split_once(':') else {
      continue;
    };
    match field.trim() {
      SECCOMP_FIELD => set_once(
        &mut seccomp,
        SECCOMP_FIELD,
        parse_u32(value, SECCOMP_FIELD)?,
      )?,
      NO_NEW_PRIVS_FIELD => set_once(
        &mut no_new_privs,
        NO_NEW_PRIVS_FIELD,
        parse_u32(value, NO_NEW_PRIVS_FIELD)?,
      )?,
      SECCOMP_FILTERS_FIELD => {
        if saw_seccomp_filters {
          return Err(ProcessStatusParseError::DuplicateField(
            SECCOMP_FILTERS_FIELD,
          ));
        }
        saw_seccomp_filters = true;
        seccomp_filters = Some(parse_u32(value, SECCOMP_FILTERS_FIELD)?);
      }
      _ => {}
    }
  }

  let seccomp = seccomp.ok_or(ProcessStatusParseError::MissingField(SECCOMP_FIELD))?;
  let no_new_privs =
    no_new_privs.ok_or(ProcessStatusParseError::MissingField(NO_NEW_PRIVS_FIELD))?;
  Ok(ProcessHardeningEvidence {
    seccomp_mode: match seccomp {
      0 => ObservedSeccompMode::Disabled,
      1 => ObservedSeccompMode::Strict,
      2 => ObservedSeccompMode::Filter,
      _ => ObservedSeccompMode::Unknown,
    },
    no_new_privs: match no_new_privs {
      0 => ObservedNoNewPrivileges::Disabled,
      1 => ObservedNoNewPrivileges::Enabled,
      _ => ObservedNoNewPrivileges::Unknown,
    },
    seccomp_filters,
  })
}

fn set_once(
  slot: &mut Option<u32>,
  field: &'static str,
  value: u32,
) -> Result<(), ProcessStatusParseError> {
  if slot.replace(value).is_some() {
    return Err(ProcessStatusParseError::DuplicateField(field));
  }
  Ok(())
}

fn parse_u32(value: &str, field: &'static str) -> Result<u32, ProcessStatusParseError> {
  value
    .trim()
    .parse()
    .map_err(|_| ProcessStatusParseError::InvalidValue(field))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_filter_and_no_new_privs_independent_of_field_order() {
    let evidence = parse_process_status(
      "Name:\toxibelt\nNoNewPrivs:\t1\nThreads:\t1\nSeccomp_filters:\t3\nSeccomp:\t2\n",
    )
    .expect("process status should parse");
    assert_eq!(evidence.seccomp_mode, ObservedSeccompMode::Filter);
    assert_eq!(evidence.no_new_privs, ObservedNoNewPrivileges::Enabled);
    assert_eq!(evidence.seccomp_filters, Some(3));
  }

  #[test]
  fn preserves_unknown_kernel_values_without_claiming_enforcement() {
    let evidence = parse_process_status("Seccomp: 7\nNoNewPrivs: 9\n")
      .expect("numeric future values should remain observable");
    assert_eq!(evidence.seccomp_mode, ObservedSeccompMode::Unknown);
    assert_eq!(evidence.no_new_privs, ObservedNoNewPrivileges::Unknown);
  }

  #[test]
  fn rejects_missing_duplicate_and_malformed_required_fields() {
    assert_eq!(
      parse_process_status("NoNewPrivs: 1\n"),
      Err(ProcessStatusParseError::MissingField(SECCOMP_FIELD))
    );
    assert_eq!(
      parse_process_status("Seccomp: 2\nSeccomp: 2\nNoNewPrivs: 1\n"),
      Err(ProcessStatusParseError::DuplicateField(SECCOMP_FIELD))
    );
    assert_eq!(
      parse_process_status("Seccomp: filter\nNoNewPrivs: 1\n"),
      Err(ProcessStatusParseError::InvalidValue(SECCOMP_FIELD))
    );
  }

  #[test]
  fn rejects_duplicate_optional_filter_counts() {
    assert_eq!(
      parse_process_status("Seccomp: 2\nNoNewPrivs: 1\nSeccomp_filters: 1\nSeccomp_filters: 2\n"),
      Err(ProcessStatusParseError::DuplicateField(
        SECCOMP_FILTERS_FIELD
      ))
    );
  }
}
