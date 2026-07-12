//! Admin Person proof operational endpoints.
//! Responses expose only hash-derived identifiers and aggregate state.

use ::http::{HeaderMap, Response, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::shared_state::PersonProofIdempotencyConflict;
use crate::state::AppSnapshot;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_json;
use super::admin_resource;

const DEFAULT_CLEARANCE_LIST_LIMIT: usize = 100;
const MAX_CLEARANCE_LIST_LIMIT: usize = 1000;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

#[derive(Debug, Deserialize)]
struct RevokeClearanceRequest {
  clearance_hash: String,
  ttl_seconds: Option<u64>,
}

pub(super) async fn admin_person_proof_response(
  request: hyper::Request<Incoming>,
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  method: &::http::Method,
  path: &str,
) -> Option<Response<ProxyBody>> {
  if !path.starts_with("/admin/v1/waf/person-proof") {
    return None;
  }

  match (method, path) {
    (&::http::Method::GET, "/admin/v1/waf/person-proof/status") => {
      if !authorization.is_allowed(
        "waf:GetPersonProofStatus",
        admin_resource::person_proof_status(),
      ) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      Some(match snapshot.waf.person_proof_admin_status_async().await {
        Ok(status) => json_response(StatusCode::OK, &status),
        Err(error) => {
          warn!(error = %error, "person proof shared status enumeration did not complete");
          text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "person proof shared state unavailable",
          )
        }
      })
    }
    (&::http::Method::GET, "/admin/v1/waf/person-proof/clearances") => {
      if !authorization.is_allowed(
        "waf:ListPersonProofClearances",
        admin_resource::person_proof_clearance_wildcard(),
      ) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let query = match clearance_list_query(request.uri().query()) {
        Ok(query) => query,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      Some(
        match snapshot
          .waf
          .person_proof_admin_clearances_async(query.limit, query.cursor.as_deref())
          .await
        {
          Ok(page) => json_response(
            StatusCode::OK,
            &json!({
              "clearances": page.clearances,
              "pagination": { "next_cursor": page.next_cursor },
            }),
          ),
          Err(error) => {
            let message = error.to_string();
            if matches!(
              message.as_str(),
              "person proof clearance cursor is invalid"
                | "person proof clearances cursor must be an unsigned offset"
            ) {
              text_response(StatusCode::BAD_REQUEST, &message)
            } else {
              warn!(error = %message, "person proof shared clearance enumeration did not complete");
              text_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "person proof shared state unavailable",
              )
            }
          }
        },
      )
    }
    (&::http::Method::POST, "/admin/v1/waf/person-proof/clearances/revoke") => {
      let idempotency_key = revocation_idempotency_key(request.headers());
      let body = match collect_admin_json::<RevokeClearanceRequest>(request).await {
        Ok(body) => body,
        Err(response) => return Some(response),
      };
      let hash = match crate::waf::WafEngine::normalize_person_proof_admin_clearance_hash(
        &body.clearance_hash,
      ) {
        Ok(hash) => hash,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      let resource = admin_resource::person_proof_clearance(&hash);
      if !authorization.is_allowed("waf:RevokePersonProofClearance", &resource) {
        return Some(text_response(StatusCode::FORBIDDEN, "forbidden"));
      }
      let idempotency_key = match idempotency_key {
        Ok(key) => key,
        Err(error) => return Some(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
      };
      Some(
        match snapshot
          .waf
          .person_proof_admin_revoke_clearance_with_idempotency_async(
            &hash,
            body.ttl_seconds,
            idempotency_key.as_deref(),
          )
          .await
        {
          Ok(result) => json_response(StatusCode::OK, &result),
          Err(error)
            if error
              .downcast_ref::<PersonProofIdempotencyConflict>()
              .is_some() =>
          {
            text_response(
              StatusCode::CONFLICT,
              "person proof idempotency key was reused with a different request",
            )
          }
          Err(error)
            if error
              .to_string()
              .starts_with("person proof clearance revocation ttl_seconds") =>
          {
            text_response(StatusCode::BAD_REQUEST, &error.to_string())
          }
          Err(error) => {
            warn!(error = %error, "person proof clearance revocation did not complete");
            text_response(
              StatusCode::SERVICE_UNAVAILABLE,
              "person proof shared state unavailable",
            )
          }
        },
      )
    }
    _ if matches!(
      path,
      "/admin/v1/waf/person-proof/status"
        | "/admin/v1/waf/person-proof/clearances"
        | "/admin/v1/waf/person-proof/clearances/revoke"
    ) =>
    {
      Some(text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed",
      ))
    }
    _ => Some(text_response(StatusCode::NOT_FOUND, "not found")),
  }
}

fn revocation_idempotency_key(headers: &HeaderMap) -> anyhow::Result<Option<String>> {
  let values = headers.get_all("idempotency-key");
  let mut values = values.iter();
  let Some(value) = values.next() else {
    return Ok(None);
  };
  if values.next().is_some() {
    anyhow::bail!("Idempotency-Key must be supplied at most once");
  }
  let value = value
    .to_str()
    .map_err(|_| anyhow::anyhow!("Idempotency-Key must contain visible ASCII characters"))?;
  if value.is_empty()
    || value.len() > MAX_IDEMPOTENCY_KEY_BYTES
    || !value.bytes().all(|byte| byte.is_ascii_graphic())
  {
    anyhow::bail!(
      "Idempotency-Key must contain 1 to {} visible ASCII characters",
      MAX_IDEMPOTENCY_KEY_BYTES
    );
  }
  Ok(Some(value.to_string()))
}

struct ClearanceListQuery {
  limit: usize,
  cursor: Option<String>,
}

fn clearance_list_query(query: Option<&str>) -> anyhow::Result<ClearanceListQuery> {
  let mut limit = DEFAULT_CLEARANCE_LIST_LIMIT;
  let mut cursor = None;
  if let Some(query) = query {
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
      match key.as_ref() {
        "limit" => {
          limit = value.parse::<usize>()?;
          if limit == 0 || limit > MAX_CLEARANCE_LIST_LIMIT {
            anyhow::bail!("limit must be between 1 and {}", MAX_CLEARANCE_LIST_LIMIT);
          }
        }
        "cursor" => cursor = Some(value.into_owned()),
        other => anyhow::bail!("unsupported person proof clearances query parameter {other}"),
      }
    }
  }
  Ok(ClearanceListQuery { limit, cursor })
}

#[cfg(test)]
mod tests {
  use ::http::{HeaderMap, HeaderValue};

  use super::revocation_idempotency_key;

  #[test]
  fn revocation_idempotency_key_accepts_one_visible_ascii_value() {
    let mut headers = HeaderMap::new();
    headers.insert("Idempotency-Key", HeaderValue::from_static("retry-key_01"));
    assert_eq!(
      revocation_idempotency_key(&headers).unwrap().as_deref(),
      Some("retry-key_01")
    );
  }

  #[test]
  fn revocation_idempotency_key_rejects_duplicate_or_non_visible_values() {
    let mut duplicate = HeaderMap::new();
    duplicate.append("Idempotency-Key", HeaderValue::from_static("first"));
    duplicate.append("Idempotency-Key", HeaderValue::from_static("second"));
    assert!(revocation_idempotency_key(&duplicate).is_err());

    let mut whitespace = HeaderMap::new();
    whitespace.insert(
      "Idempotency-Key",
      HeaderValue::from_static("contains space"),
    );
    assert!(revocation_idempotency_key(&whitespace).is_err());
  }
}
