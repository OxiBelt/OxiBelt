//! Admin Person proof operational endpoints.
//! Responses expose only hash-derived identifiers and aggregate state.

use ::http::{Response, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;
use serde_json::json;

use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::text_response;
use crate::state::AppSnapshot;

use super::admin::json_response;
use super::admin_auth::AdminAuthorization;
use super::admin_body::collect_admin_json;
use super::admin_resource;

const DEFAULT_CLEARANCE_LIST_LIMIT: usize = 100;
const MAX_CLEARANCE_LIST_LIMIT: usize = 1000;

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
        Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
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
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
        },
      )
    }
    (&::http::Method::POST, "/admin/v1/waf/person-proof/clearances/revoke") => {
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
      Some(
        match snapshot
          .waf
          .person_proof_admin_revoke_clearance_async(&hash, body.ttl_seconds)
          .await
        {
          Ok(result) => json_response(StatusCode::OK, &result),
          Err(error) => text_response(StatusCode::BAD_REQUEST, &error.to_string()),
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
