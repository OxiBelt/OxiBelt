use super::super::CacheLookupContext;
use super::super::no_vary_search::{NoVarySearchParse, parse_no_vary_search};
use super::digest_hex;
use http::HeaderMap;
use serde::Serialize;

/// Non-sensitive No-Vary-Search diagnostics for authenticated key explanation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CacheNvsExplain {
  pub eligibility: String,
  pub blockers: Vec<String>,
  pub received_query_digest: Option<String>,
  pub forwarded_query_digest: Option<String>,
}

pub(crate) fn explain(
  enabled: bool,
  ctx: &CacheLookupContext<'_>,
  response_headers: Option<&HeaderMap>,
) -> CacheNvsExplain {
  if !enabled {
    return result(
      "disabled",
      vec!["cache.no_vary_search is disabled"],
      None,
      None,
    );
  }

  let parsed = response_headers
    .map(parse_no_vary_search)
    .unwrap_or(NoVarySearchParse::Absent);
  let rule = match parsed {
    NoVarySearchParse::Valid(rule) => rule,
    NoVarySearchParse::Absent => {
      return result(
        "absent",
        vec!["response has no No-Vary-Search field"],
        None,
        None,
      );
    }
    NoVarySearchParse::Default => {
      return result(
        "default",
        vec!["response rule preserves exact query matching"],
        None,
        None,
      );
    }
    NoVarySearchParse::Invalid => {
      return result(
        "invalid",
        vec!["response No-Vary-Search field is invalid"],
        None,
        None,
      );
    }
    NoVarySearchParse::Bounded => {
      return result(
        "bounded",
        vec!["response No-Vary-Search field exceeds its bound"],
        None,
        None,
      );
    }
  };

  let received = rule.canonical_query(ctx.uri);
  let Some(received) = received else {
    return result(
      "bounded",
      vec!["received query exceeds the No-Vary-Search comparison bound"],
      None,
      None,
    );
  };
  let received_digest = Some(digest_hex(received.as_bytes()));
  let Some(request) = ctx.no_vary_search else {
    return result(
      "missing_context",
      vec!["forwarding context is unavailable to compare the effective query"],
      received_digest,
      None,
    );
  };
  let Some(forwarded) = rule.canonical_query(&request.effective_uri) else {
    return result(
      "bounded",
      vec!["effective query exceeds the No-Vary-Search comparison bound"],
      received_digest,
      None,
    );
  };
  result(
    "eligible",
    Vec::new(),
    received_digest,
    Some(digest_hex(forwarded.as_bytes())),
  )
}

fn result(
  eligibility: &str,
  blockers: Vec<&str>,
  received_query_digest: Option<String>,
  forwarded_query_digest: Option<String>,
) -> CacheNvsExplain {
  CacheNvsExplain {
    eligibility: eligibility.to_string(),
    blockers: blockers.into_iter().map(str::to_string).collect(),
    received_query_digest,
    forwarded_query_digest,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use http::{HeaderValue, Method, Uri};

  fn context<'a>(
    method: &'a Method,
    uri: &'a Uri,
    request_headers: &'a HeaderMap,
    no_vary_search: Option<&'a super::super::CacheNvsRequest>,
  ) -> CacheLookupContext<'a> {
    CacheLookupContext {
      group_request: None,
      no_vary_search,
      proxy_protocol_identity: None,
      certificate_identity: None,
      dictionary_identity: None,
      origin_vary_headers: None,
      policy_name: Some("default"),
      scheme: "https",
      host: "example.test",
      method,
      uri,
      request_headers,
      query_identity: None,
    }
  }

  #[test]
  fn reports_parser_state_without_exposing_query_values() {
    let method = Method::GET;
    let uri = Uri::from_static("/search?noise=one&keep=stable");
    let request_headers = HeaderMap::new();
    let missing = explain(true, &context(&method, &uri, &request_headers, None), None);
    assert_eq!(missing.eligibility, "absent");
    assert!(missing.received_query_digest.is_none());

    let mut headers = HeaderMap::new();
    headers.insert(
      "no-vary-search",
      HeaderValue::from_static("params=(\"noise\"), except=(\"keep\")"),
    );
    let invalid = explain(
      true,
      &context(&method, &uri, &request_headers, None),
      Some(&headers),
    );
    assert_eq!(invalid.eligibility, "invalid");
    assert!(
      serde_json::to_string(&invalid)
        .unwrap()
        .contains("received_query_digest")
    );
    assert!(!serde_json::to_string(&invalid).unwrap().contains("stable"));
  }

  #[test]
  fn reports_missing_context_and_canonical_comparison_digests() {
    let method = Method::GET;
    let uri = Uri::from_static("/search?noise=one&keep=stable");
    let request_headers = HeaderMap::new();
    let mut headers = HeaderMap::new();
    headers.insert(
      "no-vary-search",
      HeaderValue::from_static("params=(\"noise\")"),
    );
    let request = super::super::CacheNvsRequest::new(
      Uri::from_static("https://origin.test/search?noise=two&keep=stable"),
      b"diagnostic-context",
    )
    .unwrap();
    let missing = explain(
      true,
      &context(&method, &uri, &request_headers, None),
      Some(&headers),
    );
    assert_eq!(missing.eligibility, "missing_context");
    assert!(missing.received_query_digest.is_some());
    assert!(missing.forwarded_query_digest.is_none());

    let eligible = explain(
      true,
      &context(&method, &uri, &request_headers, Some(&request)),
      Some(&headers),
    );
    assert_eq!(eligible.eligibility, "eligible");
    assert!(eligible.blockers.is_empty());
    assert_eq!(
      eligible.received_query_digest,
      eligible.forwarded_query_digest
    );
  }
}
