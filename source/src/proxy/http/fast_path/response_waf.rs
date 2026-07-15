//! Response-WAF evaluation for the plain-proxy fast path.

use http::response::Parts;

use crate::config::UpstreamConfig;
use crate::pools::PoolSelection;
use crate::proxy::http::SystemAccessLogContext;
use crate::state::AppSnapshot;
use crate::waf::{ResponseWafDecision, WafRequestInput, WafResponseInput};

pub(super) fn evaluate_response_waf(
  state: &AppSnapshot,
  access_log: &SystemAccessLogContext<'_>,
  request: WafRequestInput<'_>,
  parts: &Parts,
  upstream: &UpstreamConfig,
  pool_selection: Option<&PoolSelection>,
) -> ResponseWafDecision {
  #[allow(
    clippy::expect_used,
    reason = "the caller validates the request-scoped Person proof snapshot before evaluation"
  )]
  let person_proof = access_log
    .person_proof_snapshot()
    .expect("fast-path response WAF should have a request-scoped Person proof snapshot");
  state.waf.evaluate_response_with_person_proof_snapshot(
    WafResponseInput {
      request,
      response_id: access_log.response_id(),
      received_at_unix_ms: access_log.response_received_at_unix_ms,
      version: parts.version,
      status: parts.status,
      headers: &parts.headers,
      body: None,
      upstream_name: &upstream.name,
      upstream_pool: pool_selection.map(|selection| selection.pool_name.as_str()),
      upstream_scheme: upstream.origin.scheme(),
      upstream_connect_time_ms: access_log.upstream_connect_time_ms,
      upstream_first_byte_time_ms: access_log.upstream_first_byte_time_ms,
      upstream_error: None,
    },
    person_proof,
  )
}
