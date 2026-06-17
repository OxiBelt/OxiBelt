use ::http::HeaderMap;
use ::http::header::CONTENT_LENGTH;

use crate::proxy::http::static_files::StaticBodyPlan;

pub(super) fn static_fast_path_request_has_body(headers: &HeaderMap) -> bool {
  let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
  let Some(value) = content_lengths.next() else {
    return false;
  };
  if content_lengths.next().is_some() {
    return true;
  }
  value
    .to_str()
    .map(|value| value.trim() != "0")
    .unwrap_or(true)
}

pub(super) fn static_body_source_label(body: &StaticBodyPlan) -> &'static str {
  match body {
    StaticBodyPlan::Empty => "empty",
    StaticBodyPlan::Text(_) => "text",
    StaticBodyPlan::Bytes { source, .. } => source.metric_label(),
    StaticBodyPlan::File(_) => "sendfile",
  }
}
