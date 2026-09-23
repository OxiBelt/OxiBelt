//! Response fields for explicitly advertised top-level HTTP rate limits.

use std::fmt;
use std::time::Instant;

use http::header::{CACHE_CONTROL, RETRY_AFTER};
use http::{HeaderMap, HeaderValue, Response, StatusCode};
use sfv::visitor::{
  EntryVisitor, Ignored, InnerListVisitor, ItemVisitor, ListVisitor, ParameterVisitor,
};
use sfv::{BareItemFromInput, KeyRef, Parser};

use crate::config::{RateLimitConfig, RateLimitKey};
use crate::limits::{RateLimitEvaluation, RateLimitOutcome};

use super::cache_status::StandardCacheStatus;

const MAX_ORIGIN_FIELD_BYTES: usize = 4096;
const MAX_ORIGIN_MEMBERS: usize = 16;
const MAX_ORIGIN_PARAMETERS: usize = 16;

#[derive(Debug, Clone)]
struct PolicySnapshot {
  pub id: String,
  pub quota: u32,
  pub remaining: Option<u32>,
  pub next_token_at: Option<Instant>,
  pub client_specific: bool,
}

#[derive(Default)]
pub(crate) struct Report {
  snapshots: Vec<PolicySnapshot>,
  quota_denied: bool,
  suppress_all: bool,
}

impl Report {
  pub(super) fn absorb(&mut self, evaluation: RateLimitEvaluation, limits: &[RateLimitConfig]) {
    self.suppress_all |= evaluation.suppress_all;
    if evaluation.status.is_some()
      && evaluation.checked.last().is_some_and(|snapshot| {
        matches!(
          snapshot.outcome,
          RateLimitOutcome::RateLimited | RateLimitOutcome::BucketCapExceeded
        )
      })
    {
      self.quota_denied = true;
    }
    for snapshot in evaluation.checked {
      let Some(limit) = limits.iter().find(|limit| limit.name == snapshot.name) else {
        continue;
      };
      let Some(id) = &limit.policy_id else {
        continue;
      };
      self.snapshots.push(PolicySnapshot {
        id: id.clone(),
        quota: snapshot.burst,
        remaining: snapshot.remaining,
        next_token_at: snapshot.next_token_at,
        client_specific: !matches!(limit.key, RateLimitKey::Global | RateLimitKey::Route),
      });
    }
  }
}

pub(super) fn apply<B>(response: &mut Response<B>, report: &Report) {
  if report.suppress_all || report.snapshots.is_empty() {
    return;
  }
  let status = response.status();
  if !(status.is_success()
    || status.is_redirection()
    || status == StatusCode::SWITCHING_PROTOCOLS
    || report.quota_denied)
  {
    return;
  }
  // A refreshed cached representation is still a cache response, even when
  // its Cache-Status facts describe a forwarded 304 rather than a hit.
  if response
    .extensions()
    .get::<StandardCacheStatus>()
    .is_some_and(|facts| facts.hit || facts.forwarded_status == Some(304))
  {
    return;
  }
  if !valid_origin(
    response.headers(),
    "ratelimit-policy",
    "q",
    &report.snapshots,
  ) || !valid_origin(response.headers(), "ratelimit", "r", &report.snapshots)
  {
    return;
  }

  let mut policies = String::new();
  let mut limits = String::new();
  let mut client_specific_balance = false;
  for snapshot in &report.snapshots {
    if !policies.is_empty() {
      policies.push_str(", ");
    }
    policies.push('"');
    policies.push_str("oxibelt/");
    policies.push_str(&snapshot.id);
    policies.push_str("\";q=");
    policies.push_str(&snapshot.quota.to_string());
    let Some(remaining) = snapshot.remaining else {
      continue;
    };
    if !limits.is_empty() {
      limits.push_str(", ");
    }
    limits.push('"');
    limits.push_str("oxibelt/");
    limits.push_str(&snapshot.id);
    limits.push_str("\";r=");
    limits.push_str(&remaining.to_string());
    if remaining == 0
      && !response.headers().contains_key(RETRY_AFTER)
      && let Some(duration) = snapshot
        .next_token_at
        .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
    {
      let seconds = duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0));
      if seconds <= 999_999_999_999_999 {
        limits.push_str(";t=");
        limits.push_str(&seconds.to_string());
      }
    }
    client_specific_balance |= snapshot.client_specific;
  }
  // Validation bounds policy identifiers and their count. Keep a defensive
  // check here in case future callers construct reports without config.
  if policies.len() > MAX_ORIGIN_FIELD_BYTES || limits.len() > MAX_ORIGIN_FIELD_BYTES {
    return;
  }
  let Ok(policy_value) = HeaderValue::from_str(&policies) else {
    return;
  };
  let limit_value = if limits.is_empty() {
    None
  } else {
    let Ok(value) = HeaderValue::from_str(&limits) else {
      return;
    };
    Some(value)
  };
  response
    .headers_mut()
    .append("ratelimit-policy", policy_value);
  if let Some(value) = limit_value {
    response.headers_mut().append("ratelimit", value);
  }
  if client_specific_balance {
    // This changes only the outgoing response. The internal cache object was
    // already selected or stored before this finalization step.
    response
      .headers_mut()
      .append(CACHE_CONTROL, HeaderValue::from_static("private"));
  }
}

fn valid_origin(
  headers: &HeaderMap,
  name: &'static str,
  required: &'static str,
  local: &[PolicySnapshot],
) -> bool {
  let mut joined = Vec::new();
  for value in headers.get_all(name) {
    if !joined.is_empty() {
      joined.extend_from_slice(b", ");
    }
    if joined.len().saturating_add(value.len()) > MAX_ORIGIN_FIELD_BYTES {
      return false;
    }
    joined.extend_from_slice(value.as_bytes());
  }
  if joined.is_empty() {
    return true;
  }
  Parser::new(&joined)
    .with_version(sfv::Version::Rfc9651)
    .parse_list_with_visitor(CheckList {
      required,
      members: 0,
      local,
    })
    .is_ok()
}

#[derive(Debug)]
struct InvalidField;

impl fmt::Display for InvalidField {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("invalid rate limit field")
  }
}

impl std::error::Error for InvalidField {}

struct CheckList<'a> {
  required: &'static str,
  members: usize,
  local: &'a [PolicySnapshot],
}

impl<'de> ListVisitor<'de> for CheckList<'_> {
  type Out = ();
  type Error = InvalidField;

  fn entry(&mut self) -> Result<impl EntryVisitor<'de>, Self::Error> {
    self.members += 1;
    if self.members > MAX_ORIGIN_MEMBERS {
      return Err(InvalidField);
    }
    Ok(CheckItem {
      required: self.required,
      local: self.local,
    })
  }

  fn finish(self) -> Result<Self::Out, Self::Error> {
    if self.members == 0 {
      return Err(InvalidField);
    }
    Ok(())
  }
}

struct CheckItem<'a> {
  required: &'static str,
  local: &'a [PolicySnapshot],
}

impl<'de> EntryVisitor<'de> for CheckItem<'_> {
  type Error = InvalidField;

  fn item(self) -> Result<impl ItemVisitor<'de>, Self::Error> {
    Ok(self)
  }

  fn inner_list(self) -> Result<impl InnerListVisitor<'de>, Self::Error> {
    Err::<Ignored, _>(InvalidField)
  }
}

impl<'de> ItemVisitor<'de> for CheckItem<'_> {
  type Out = ();
  type Error = InvalidField;

  fn bare_item(
    self,
    item: BareItemFromInput<'de>,
  ) -> Result<impl ParameterVisitor<'de, Out = ()>, Self::Error> {
    let BareItemFromInput::String(id) = item else {
      return Err(InvalidField);
    };
    if id
      .as_str()
      .strip_prefix("oxibelt/")
      .is_some_and(|id| self.local.iter().any(|snapshot| snapshot.id == id))
    {
      return Err(InvalidField);
    }
    Ok(CheckParameters {
      required: self.required,
      seen_required: false,
      count: 0,
    })
  }
}

struct CheckParameters {
  required: &'static str,
  seen_required: bool,
  count: usize,
}

impl<'de> ParameterVisitor<'de> for CheckParameters {
  type Out = ();
  type Error = InvalidField;

  fn parameter(
    &mut self,
    key: &'de KeyRef,
    value: BareItemFromInput<'de>,
  ) -> Result<(), Self::Error> {
    self.count += 1;
    if self.count > MAX_ORIGIN_PARAMETERS {
      return Err(InvalidField);
    }
    match key.as_str() {
      required if required == self.required => {
        let BareItemFromInput::Integer(integer) = value else {
          return Err(InvalidField);
        };
        if i64::from(integer) < 0 || self.seen_required {
          return Err(InvalidField);
        }
        self.seen_required = true;
      }
      "w" if self.required == "q" => {
        if !matches!(value, BareItemFromInput::Integer(integer) if i64::from(integer) > 0) {
          return Err(InvalidField);
        }
      }
      "t" if self.required == "r" => {
        if !matches!(value, BareItemFromInput::Integer(integer) if i64::from(integer) >= 0) {
          return Err(InvalidField);
        }
      }
      "qu" if self.required == "q" => {
        if !matches!(value, BareItemFromInput::String(_)) {
          return Err(InvalidField);
        }
      }
      "pk" if !matches!(value, BareItemFromInput::ByteSequence(_)) => return Err(InvalidField),
      _ => {}
    }
    Ok(())
  }

  fn finish(self) -> Result<(), Self::Error> {
    if !self.seen_required {
      return Err(InvalidField);
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn make_response() -> Response<()> {
    Response::new(())
  }

  fn report() -> Report {
    Report {
      snapshots: vec![PolicySnapshot {
        id: "public-api".to_string(),
        quota: 50,
        remaining: Some(0),
        next_token_at: Instant::now().checked_add(std::time::Duration::from_secs(2)),
        client_specific: true,
      }],
      ..Report::default()
    }
  }

  #[test]
  fn emits_structured_fields_and_private_response() {
    let mut response = make_response();
    apply(&mut response, &report());
    assert_eq!(
      response.headers()["ratelimit-policy"],
      "\"oxibelt/public-api\";q=50"
    );
    assert_eq!(
      response.headers()["ratelimit"],
      "\"oxibelt/public-api\";r=0;t=2"
    );
    assert_eq!(response.headers()[CACHE_CONTROL], "private");
    assert!(valid_origin(
      response.headers(),
      "ratelimit-policy",
      "q",
      &[]
    ));
    assert!(valid_origin(response.headers(), "ratelimit", "r", &[]));
  }

  #[test]
  fn preserves_valid_origin_and_skips_malformed_origin() {
    let mut response = make_response();
    response
      .headers_mut()
      .insert("ratelimit", HeaderValue::from_static("\"origin\";r=4"));
    apply(&mut response, &report());
    assert_eq!(response.headers().get_all("ratelimit").iter().count(), 2);

    let mut malformed = make_response();
    malformed
      .headers_mut()
      .insert("ratelimit", HeaderValue::from_static("not-a-string;r=4"));
    apply(&mut malformed, &report());
    assert!(!malformed.headers().contains_key("ratelimit-policy"));
    assert_eq!(malformed.headers()["ratelimit"], "not-a-string;r=4");

    for (name, value) in [
      ("ratelimit", "\"origin\";r=4;t=\"later\""),
      ("ratelimit-policy", "\"origin\";q=4;w=0"),
      ("ratelimit-policy", "\"origin\";q=4;qu=wrong"),
      ("ratelimit", "\"origin\";r=4;pk=\"client\""),
    ] {
      let mut malformed = make_response();
      malformed
        .headers_mut()
        .insert(name, HeaderValue::from_str(value).unwrap());
      apply(&mut malformed, &report());
      assert!(!malformed.headers().contains_key(if name == "ratelimit" {
        "ratelimit-policy"
      } else {
        "ratelimit"
      }));
      assert_eq!(malformed.headers()[name], value);
    }
  }

  #[test]
  fn omits_on_cached_or_unrelated_error_responses() {
    let mut cached = make_response();
    cached.extensions_mut().insert(StandardCacheStatus {
      hit: true,
      ..Default::default()
    });
    apply(&mut cached, &report());
    assert!(!cached.headers().contains_key("ratelimit"));

    let mut error = make_response();
    *error.status_mut() = StatusCode::UNAUTHORIZED;
    apply(&mut error, &report());
    assert!(!error.headers().contains_key("ratelimit"));
  }

  #[test]
  fn retry_after_suppresses_only_the_optional_window() {
    let mut response = make_response();
    response
      .headers_mut()
      .insert(RETRY_AFTER, HeaderValue::from_static("5"));
    apply(&mut response, &report());
    assert_eq!(
      response.headers()["ratelimit"],
      "\"oxibelt/public-api\";r=0"
    );
    assert_eq!(response.headers()[RETRY_AFTER], "5");
  }

  #[test]
  fn expired_refill_deadline_omits_stale_window() {
    let mut report = report();
    report.snapshots[0].next_token_at =
      Instant::now().checked_sub(std::time::Duration::from_secs(1));
    let mut response = make_response();
    apply(&mut response, &report);
    assert_eq!(
      response.headers()["ratelimit"],
      "\"oxibelt/public-api\";r=0"
    );
  }

  #[test]
  fn bucket_cap_reports_policy_without_invented_balance() {
    let mut report = report();
    report.quota_denied = true;
    report.snapshots[0].remaining = None;
    let mut response = make_response();
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    apply(&mut response, &report);
    assert_eq!(
      response.headers()["ratelimit-policy"],
      "\"oxibelt/public-api\";q=50"
    );
    assert!(!response.headers().contains_key("ratelimit"));
    assert!(!response.headers().contains_key(CACHE_CONTROL));
  }

  #[test]
  fn upstream_policy_id_collision_preserves_origin_without_appending_local() {
    let mut response = make_response();
    response.headers_mut().insert(
      "ratelimit",
      HeaderValue::from_static("\"oxibelt/public-api\";r=100"),
    );
    apply(&mut response, &report());
    assert_eq!(
      response.headers()["ratelimit"],
      "\"oxibelt/public-api\";r=100"
    );
    assert!(!response.headers().contains_key("ratelimit-policy"));

    let mut policy_collision = make_response();
    policy_collision.headers_mut().insert(
      "ratelimit-policy",
      HeaderValue::from_static("\"oxibelt/public-api\";q=100"),
    );
    apply(&mut policy_collision, &report());
    assert_eq!(
      policy_collision.headers()["ratelimit-policy"],
      "\"oxibelt/public-api\";q=100"
    );
    assert!(!policy_collision.headers().contains_key("ratelimit"));
  }
}
