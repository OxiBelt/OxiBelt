use http::{HeaderValue, Response};

pub const MUTATION_REQUEST_ID_HEADER: &str = "x-oxibelt-mutation-request-id";
pub const MUTATION_REVISION_HEADER: &str = "x-oxibelt-mutation-revision";
pub const IDEMPOTENT_REPLAY_HEADER: &str = "x-oxibelt-idempotent-replay";

#[derive(Clone, Copy, Debug)]
pub struct MutationResponseMetadata<'a> {
  pub request_id: &'a str,
  pub revision: &'a str,
  pub replayed: bool,
}

pub fn attach_mutation_response_headers<B>(
  response: &mut Response<B>,
  metadata: MutationResponseMetadata<'_>,
) {
  if let Ok(value) = HeaderValue::from_str(metadata.request_id) {
    response
      .headers_mut()
      .insert(MUTATION_REQUEST_ID_HEADER, value);
  }
  if let Ok(value) = HeaderValue::from_str(metadata.revision) {
    response
      .headers_mut()
      .insert(MUTATION_REVISION_HEADER, value);
  }
  response.headers_mut().insert(
    IDEMPOTENT_REPLAY_HEADER,
    HeaderValue::from_static(if metadata.replayed { "true" } else { "false" }),
  );
}
