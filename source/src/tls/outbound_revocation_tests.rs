use super::*;

fn outcome(
  result: &'static str,
  error_code: Option<&'static str>,
  certificate_rejected: bool,
) -> crlite::CrliteCheckOutcome {
  crlite::CrliteCheckOutcome {
    status: if certificate_rejected {
      "rejected"
    } else {
      "fresh"
    },
    result: Some(result),
    filter_loaded: true,
    filter_stale: false,
    error_code,
    certificate_rejected,
  }
}

#[test]
fn good_crlite_outcome_is_allowed_under_both_failure_policies() {
  let outcome = outcome("good", None, false);

  for failure_policy in [
    CrliteFailurePolicy::FailClosed,
    CrliteFailurePolicy::DegradedAllow,
  ] {
    enforce_crlite_outcome(&outcome, failure_policy).expect("good certificate should be allowed");
  }
}

#[test]
fn crlite_health_error_follows_failure_policy() {
  let outcome = outcome("good", Some("crlite_filter_stale"), false);

  let error = enforce_crlite_outcome(&outcome, CrliteFailurePolicy::FailClosed)
    .expect_err("fail-closed policy should reject a CRLite health error");
  assert_eq!(error.to_string(), "crlite_filter_stale");
  enforce_crlite_outcome(&outcome, CrliteFailurePolicy::DegradedAllow)
    .expect("degraded-allow policy should permit a CRLite health error");
}

#[test]
fn certificate_rejections_are_terminal_under_both_failure_policies() {
  for (result, error_code, expected) in [
    ("revoked", None, "upstream_crlite_revoked_certificate"),
    (
      "not_covered",
      Some("crlite_not_covered"),
      "crlite_not_covered",
    ),
    (
      "not_enrolled",
      Some("crlite_not_enrolled"),
      "crlite_not_enrolled",
    ),
  ] {
    let outcome = outcome(result, error_code, true);
    for failure_policy in [
      CrliteFailurePolicy::FailClosed,
      CrliteFailurePolicy::DegradedAllow,
    ] {
      let error = enforce_crlite_outcome(&outcome, failure_policy)
        .expect_err("a certificate rejection must be terminal");
      assert_eq!(error.to_string(), expected);
    }
  }
}
