use crate::config::HttpVersion;
use crate::waf::BodyNeed;

use super::super::fast_path_small_request_body_candidate;

#[test]
fn small_request_body_candidate_allows_h1_without_body_waf() {
  assert!(fast_path_small_request_body_candidate(
    HttpVersion::H1,
    BodyNeed::None
  ));
}

#[test]
fn small_request_body_candidate_rejects_non_h1_and_body_waf() {
  assert!(!fast_path_small_request_body_candidate(
    HttpVersion::H2,
    BodyNeed::None
  ));
  assert!(!fast_path_small_request_body_candidate(
    HttpVersion::H3,
    BodyNeed::None
  ));

  for body_need in [BodyNeed::SizeOnly, BodyNeed::PrefixBytes] {
    assert!(!fast_path_small_request_body_candidate(
      HttpVersion::H1,
      body_need
    ));
  }
}
