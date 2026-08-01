//! Integrity-boundary input for orchestrator-supplied seccomp profile metadata.

use std::env;
use std::fmt;

pub const SECCOMP_PROFILE_IDENTITY_ENV: &str = "OXIBELT_SECCOMP_PROFILE_IDENTITY";
pub const SECCOMP_PROFILE_DIGEST_ENV: &str = "OXIBELT_SECCOMP_PROFILE_DIGEST";
const MAX_PROFILE_IDENTITY_LEN: usize = 128;

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ExternalProfileAssertions {
  pub profile_identity: Option<String>,
  pub profile_digest: Option<String>,
}

pub trait ProfileAssertionSource {
  fn read_profile_assertions(&self) -> Result<ExternalProfileAssertions, ProfileAssertionError>;
}

#[derive(Debug, Default)]
pub struct EnvironmentProfileAssertionSource;

impl ProfileAssertionSource for EnvironmentProfileAssertionSource {
  fn read_profile_assertions(&self) -> Result<ExternalProfileAssertions, ProfileAssertionError> {
    let assertions = ExternalProfileAssertions {
      profile_identity: read_optional_env(SECCOMP_PROFILE_IDENTITY_ENV)?,
      profile_digest: read_optional_env(SECCOMP_PROFILE_DIGEST_ENV)?,
    };
    assertions.validate()?;
    Ok(assertions)
  }
}

impl ExternalProfileAssertions {
  pub fn validate(&self) -> Result<(), ProfileAssertionError> {
    if let Some(identity) = self.profile_identity.as_deref()
      && !valid_profile_identity(identity)
    {
      return Err(ProfileAssertionError::InvalidIdentity);
    }
    if let Some(digest) = self.profile_digest.as_deref()
      && !valid_sha256_digest(digest)
    {
      return Err(ProfileAssertionError::InvalidDigest);
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProfileAssertionError {
  NonUnicodeEnvironment,
  InvalidIdentity,
  InvalidDigest,
}

impl fmt::Display for ProfileAssertionError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(match self {
      Self::NonUnicodeEnvironment => "seccomp profile assertion environment is not Unicode",
      Self::InvalidIdentity => "seccomp profile identity assertion is invalid",
      Self::InvalidDigest => "seccomp profile digest assertion is invalid",
    })
  }
}

impl std::error::Error for ProfileAssertionError {}

fn read_optional_env(name: &'static str) -> Result<Option<String>, ProfileAssertionError> {
  match env::var(name) {
    Ok(value) => Ok(Some(value)),
    Err(env::VarError::NotPresent) => Ok(None),
    Err(env::VarError::NotUnicode(_)) => Err(ProfileAssertionError::NonUnicodeEnvironment),
  }
}

fn valid_profile_identity(identity: &str) -> bool {
  !identity.is_empty()
    && identity.len() <= MAX_PROFILE_IDENTITY_LEN
    && identity.bytes().all(|byte| {
      byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@' | b'+')
    })
}

fn valid_sha256_digest(value: &str) -> bool {
  value.strip_prefix("sha256:").is_some_and(|encoded| {
    encoded.len() == 64
      && encoded
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn validates_bounded_assertions_without_exposing_values_in_errors() {
    ExternalProfileAssertions {
      profile_identity: Some("kubernetes/runtime-default".to_string()),
      profile_digest: Some(format!("sha256:{}", "a".repeat(64))),
    }
    .validate()
    .expect("bounded profile assertions should validate");

    assert_eq!(
      ExternalProfileAssertions {
        profile_identity: Some("contains whitespace".to_string()),
        profile_digest: None,
      }
      .validate(),
      Err(ProfileAssertionError::InvalidIdentity)
    );
  }
}
