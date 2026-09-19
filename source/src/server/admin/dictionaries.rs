//! Profile-scoped dictionary inventory and generation-fenced purge.
use super::super::AdminAuthorization;
use super::{collect_admin_json, json_response};
use crate::{
  proxy::http::{body::ProxyBody, response::text_response},
  state::AppSnapshot,
};
use http::{Method, Response, StatusCode};
use hyper::{Request, body::Incoming};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Purge {
  profile: String,
  origin: Option<url::Url>,
}

pub(in crate::server) async fn response(
  request: Request<Incoming>,
  snapshot: &AppSnapshot,
  authorization: &AdminAuthorization<'_>,
  purge: bool,
) -> Response<ProxyBody> {
  if purge {
    if request.method() != Method::POST {
      return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let body = match collect_admin_json::<Purge>(request).await {
      Ok(body) => body,
      Err(response) => return response,
    };
    let resource = format!("compression-dictionary-profile/{}", body.profile);
    if !authorization.is_allowed("compression-dictionary:Purge", &resource) {
      return text_response(StatusCode::FORBIDDEN, "forbidden");
    }
    if snapshot
      .compression_dictionary
      .profile(&body.profile)
      .is_none()
    {
      return text_response(StatusCode::NOT_FOUND, "profile not found");
    }
    if body
      .origin
      .as_ref()
      .is_some_and(|origin| !valid_origin(origin))
    {
      return text_response(StatusCode::BAD_REQUEST, "origin must be an HTTPS origin");
    }
    return match snapshot
      .compression_dictionary
      .purge(&body.profile, None, body.origin.as_ref(), None)
      .await
    {
      Ok(count) => json_response(
        StatusCode::OK,
        &json!({"profile":body.profile,"purged":count}),
      ),
      Err(_) => text_response(StatusCode::SERVICE_UNAVAILABLE, "dictionary purge failed"),
    };
  }
  if request.method() != Method::GET {
    return text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
  }
  let mut profile = None;
  for (key, value) in
    url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
  {
    if key != "profile" || profile.is_some() || value.len() > 256 {
      return text_response(StatusCode::BAD_REQUEST, "exactly one profile is required");
    }
    profile = Some(value.into_owned());
  }
  let Some(profile) = profile else {
    return text_response(StatusCode::BAD_REQUEST, "profile is required");
  };
  if !authorization.is_allowed(
    "compression-dictionary:List",
    &format!("compression-dictionary-profile/{profile}"),
  ) {
    return text_response(StatusCode::FORBIDDEN, "forbidden");
  }
  if snapshot.compression_dictionary.profile(&profile).is_none() {
    return text_response(StatusCode::NOT_FOUND, "profile not found");
  }
  match snapshot.compression_dictionary.inventory(&profile).await {
    Ok(inventory) => json_response(
      StatusCode::OK,
      &json!({"profile":profile,"entries":inventory.entries,"bytes":inventory.bytes,"pending_bytes":inventory.pending_bytes,"active_jobs":inventory.active_jobs}),
    ),
    Err(_) => text_response(
      StatusCode::SERVICE_UNAVAILABLE,
      "dictionary inventory failed",
    ),
  }
}

fn valid_origin(origin: &url::Url) -> bool {
  origin.scheme() == "https"
    && origin.host_str().is_some()
    && origin.username().is_empty()
    && origin.password().is_none()
    && origin.path() == "/"
    && origin.query().is_none()
    && origin.fragment().is_none()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn purge_origin_must_be_a_hosted_https_origin() {
    for value in [
      "https://example.test",
      "https://example.test/",
      "https://example.test:8443/",
    ] {
      assert!(valid_origin(&url::Url::parse(value).unwrap()), "{value}");
    }
    for value in [
      "http://example.test/",
      "https://user@example.test/",
      "https://example.test/path",
      "https://example.test/?query",
      "https://example.test/#fragment",
    ] {
      assert!(!valid_origin(&url::Url::parse(value).unwrap()), "{value}");
    }
  }
}
