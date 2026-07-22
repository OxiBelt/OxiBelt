use std::cmp::Ordering;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemVer<'a> {
  major: &'a str,
  minor: &'a str,
  patch: &'a str,
  prerelease: Vec<&'a str>,
}

impl Ord for SemVer<'_> {
  fn cmp(&self, other: &Self) -> Ordering {
    compare_numeric(self.major, other.major)
      .then_with(|| compare_numeric(self.minor, other.minor))
      .then_with(|| compare_numeric(self.patch, other.patch))
      .then_with(|| compare_prerelease(&self.prerelease, &other.prerelease))
  }
}

impl PartialOrd for SemVer<'_> {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

pub fn parse_semver(value: &str) -> Result<SemVer<'_>, &'static str> {
  if value.is_empty() || !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
    return Err("version must be non-empty ASCII without whitespace");
  }

  let mut build_parts = value.split('+');
  let without_build = build_parts.next().expect("non-empty version");
  let build = build_parts.next();
  if build_parts.next().is_some() {
    return Err("version must contain at most one build separator");
  }
  if let Some(build) = build {
    validate_identifiers(build, false)?;
  }
  let (core, prerelease) = match without_build.split_once('-') {
    Some((core, prerelease)) => (core, Some(prerelease)),
    None => (without_build, None),
  };
  let mut components = core.split('.');
  let major = components
    .next()
    .ok_or("version must contain major.minor.patch")?;
  let minor = components
    .next()
    .ok_or("version must contain major.minor.patch")?;
  let patch = components
    .next()
    .ok_or("version must contain major.minor.patch")?;
  if components.next().is_some() {
    return Err("version core must contain exactly three components");
  }
  for component in [major, minor, patch] {
    validate_numeric(component)?;
  }

  let prerelease = match prerelease {
    Some(value) => {
      validate_identifiers(value, true)?;
      value.split('.').collect()
    }
    None => Vec::new(),
  };
  Ok(SemVer {
    major,
    minor,
    patch,
    prerelease,
  })
}

pub fn compare_semver(left: &str, right: &str) -> Result<Ordering, &'static str> {
  Ok(parse_semver(left)?.cmp(&parse_semver(right)?))
}

pub fn is_release_version(value: &str) -> bool {
  if parse_semver(value).is_err() {
    return false;
  }
  if value.contains('+') {
    return false;
  }
  let Some((_, prerelease)) = value.split_once('-') else {
    return true;
  };
  let mut components = prerelease.split('.');
  let valid_kind = match components.next() {
    Some("beta") => components
      .next()
      .is_some_and(is_numeric_without_leading_zero),
    Some("build") => components.next().is_some_and(|revision| {
      revision.len() == 8
        && revision
          .bytes()
          .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }),
    _ => false,
  };
  valid_kind && components.next().is_none()
}

#[allow(dead_code)] // Shared with build.rs, where the release resolver consumes it.
pub fn release_build_revision(value: &str) -> Option<&str> {
  let (_, build) = value.split_once("-build.")?;
  (build.len() == 8).then_some(build)
}

fn validate_numeric(value: &str) -> Result<(), &'static str> {
  if is_numeric_without_leading_zero(value) {
    Ok(())
  } else {
    Err("numeric identifiers must contain digits without leading zeroes")
  }
}

fn is_numeric_without_leading_zero(value: &str) -> bool {
  !value.is_empty()
    && value.bytes().all(|byte| byte.is_ascii_digit())
    && (value == "0" || !value.starts_with('0'))
}

fn validate_identifiers(value: &str, enforce_numeric_zero_rule: bool) -> Result<(), &'static str> {
  if value.is_empty() {
    return Err("identifier list must not be empty");
  }
  for identifier in value.split('.') {
    if identifier.is_empty()
      || !identifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
      return Err("identifiers must contain only ASCII alphanumerics and hyphens");
    }
    if enforce_numeric_zero_rule
      && identifier.bytes().all(|byte| byte.is_ascii_digit())
      && !is_numeric_without_leading_zero(identifier)
    {
      return Err("numeric prerelease identifiers must not contain leading zeroes");
    }
  }
  Ok(())
}

fn compare_numeric(left: &str, right: &str) -> Ordering {
  left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn compare_prerelease(left: &[&str], right: &[&str]) -> Ordering {
  match (left.is_empty(), right.is_empty()) {
    (true, true) => return Ordering::Equal,
    (true, false) => return Ordering::Greater,
    (false, true) => return Ordering::Less,
    (false, false) => {}
  }
  for (left, right) in left.iter().zip(right) {
    let left_numeric = left.bytes().all(|byte| byte.is_ascii_digit());
    let right_numeric = right.bytes().all(|byte| byte.is_ascii_digit());
    let ordering = match (left_numeric, right_numeric) {
      (true, true) => compare_numeric(left, right),
      (true, false) => Ordering::Less,
      (false, true) => Ordering::Greater,
      (false, false) => left.cmp(right),
    };
    if ordering != Ordering::Equal {
      return ordering;
    }
  }
  left.len().cmp(&right.len())
}

#[cfg(test)]
mod tests {
  use super::{compare_semver, is_release_version, parse_semver};
  use std::cmp::Ordering;

  #[test]
  fn accepts_semver_two_and_rejects_invalid_forms() {
    for valid in [
      "0.0.0",
      "1.2.3-beta.1",
      "1.2.3-alpha-beta.1+linux-x86-64",
      "1.2.3+build.abcdef01",
      "184467440737095516160.0.0",
    ] {
      assert!(parse_semver(valid).is_ok(), "{valid}");
    }
    for invalid in ["", "1.2", "01.2.3", "1.2.3-01", "1.2.3+", "1.2.3+a..b"] {
      assert!(parse_semver(invalid).is_err(), "{invalid}");
    }
  }

  #[test]
  fn compares_semver_precedence_without_integer_overflow() {
    assert_eq!(
      compare_semver("1.0.0", "1.0.0-beta.9"),
      Ok(Ordering::Greater)
    );
    assert_eq!(
      compare_semver("1.0.0-beta.10", "1.0.0-beta.9"),
      Ok(Ordering::Greater)
    );
    assert_eq!(
      compare_semver("1.0.0+one", "1.0.0+two"),
      Ok(Ordering::Equal)
    );
  }

  #[test]
  fn restricts_repository_release_grammar() {
    for valid in ["1.2.3", "1.2.3-beta.1", "1.2.3-build.abcdef01"] {
      assert!(is_release_version(valid), "{valid}");
    }
    for invalid in [
      "1.2.3-rc.1",
      "1.2.3-beta.01",
      "1.2.3-build.ABCDEF01",
      "1.2.3-other.abcdef01",
    ] {
      assert!(!is_release_version(invalid), "{invalid}");
    }
  }
}
