use ::http::{Response, header};
use std::time::Duration;

use tokio::time::{Instant, sleep};

use crate::admin_mutation::{AdminMutationRuntime, MutationAdmissionError, MutationRecord};
use crate::proxy::http::body::ProxyBody;

pub(super) fn attach_in_progress_headers(response: &mut Response<ProxyBody>, request_id: &str) {
  let location = format!("/admin/v1/mutations/{request_id}");
  if let Ok(value) = header::HeaderValue::from_str(&location) {
    response.headers_mut().insert(header::LOCATION, value);
  }
  response
    .headers_mut()
    .insert(header::RETRY_AFTER, header::HeaderValue::from_static("1"));
}

pub(super) async fn wait_for_terminal(
  runtime: &AdminMutationRuntime,
  request_id: &str,
  timeout: Duration,
) -> Result<Option<MutationRecord>, MutationAdmissionError> {
  let deadline = Instant::now() + timeout;
  loop {
    let record = runtime
      .load_mutation(request_id)
      .await?
      .ok_or_else(|| anyhow::anyhow!("claimed cluster mutation disappeared"))?;
    if record.state.is_terminal() {
      return Ok(Some(record));
    }
    if Instant::now() >= deadline {
      return Ok(None);
    }
    sleep(Duration::from_millis(50)).await;
  }
}

#[cfg(test)]
mod tests {
  use ::http::{StatusCode, header};
  use http_body_util::BodyExt;

  #[tokio::test]
  async fn nonterminal_cluster_outcome_is_never_an_early_success() {
    let response = super::super::in_progress_response_for_execution("request-1", "revision-2");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
      response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok()),
      Some("/admin/v1/mutations/request-1")
    );
    assert_eq!(
      response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok()),
      Some("1")
    );
    let body = response
      .into_body()
      .collect()
      .await
      .expect("collect in-progress response")
      .to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&body).expect("in-progress JSON");
    assert_eq!(payload["code"], "mutation_in_progress");
  }
}
