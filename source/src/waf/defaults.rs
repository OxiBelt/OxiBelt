use super::{AccessLogFieldConfig, PersonProofTokenBinding};

pub(super) fn default_access_log_field_configs() -> Vec<AccessLogFieldConfig> {
  [
    ("request_id", "Request.Id"),
    ("response_id", "Response.Id"),
    ("transaction_id", "Context.TransactionId"),
    ("method", "Request.Http.Method"),
    ("uri", "Request.Http.Uri"),
    ("path", "Request.Http.Path"),
    ("query", "Request.Http.Query"),
    ("request_version", "Request.Http.Version"),
    ("host", "Request.Http.Host"),
    ("user_agent", "Request.Headers.getAll('User-Agent')"),
    ("client_ip", "Request.Client.Ip"),
    ("client_port", "Request.Client.Port"),
    ("protocol", "Request.Protocol"),
    ("transport", "Request.Transport.Network"),
    ("tls", "Request.Tls.Enabled"),
    ("route", "Context.RouteName"),
    ("status", "Response.Http.Status"),
    ("reason", "Response.Http.Reason"),
    ("response_body_bytes", "Response.Body.Size"),
    ("upstream", "Response.Upstream.Name"),
    ("upstream_pool", "Response.Upstream.Pool"),
    ("upstream_scheme", "Response.Upstream.Scheme"),
    (
      "upstream_connect_time_ms",
      "Response.Upstream.ConnectTimeMs",
    ),
    (
      "upstream_first_byte_time_ms",
      "Response.Upstream.FirstByteTimeMs",
    ),
    ("waf_rule", "Context.RuleName"),
    ("waf_rule_id", "Context.RuleId"),
    ("request_received_at_unix_ms", "Request.ReceivedAtUnixMs"),
    ("response_received_at_unix_ms", "Response.ReceivedAtUnixMs"),
  ]
  .into_iter()
  .map(|(name, value)| AccessLogFieldConfig {
    name: name.to_string(),
    value: value.to_string(),
  })
  .collect()
}

pub(super) fn default_waf_rate_limit_status() -> u16 {
  429
}

pub(super) fn default_mitigation_fail_status() -> u16 {
  503
}

pub(super) fn default_websocket_close_code() -> u16 {
  1008
}

pub(super) fn default_webtransport_close_code() -> u32 {
  1
}

pub(super) fn default_stream_close_reason() -> String {
  "policy violation".to_string()
}

pub(super) fn default_max_rule_runtime_ms() -> u64 {
  5
}

pub(super) fn default_max_total_waf_runtime_ms() -> u64 {
  20
}

pub(super) fn default_max_expression_steps() -> usize {
  2_000
}

pub(super) fn default_max_memory_bytes() -> usize {
  262_144
}

pub(super) fn default_max_string_bytes() -> usize {
  8_192
}

pub(super) fn default_max_body_inspection_bytes() -> usize {
  1_048_576
}

pub(super) fn default_max_header_count() -> usize {
  128
}

pub(super) fn default_max_header_value_bytes() -> usize {
  8_192
}

pub(super) fn default_max_mutations() -> usize {
  32
}

pub(super) fn default_max_regex_runtime_ms() -> u64 {
  2
}

pub(super) fn default_max_helper_items() -> usize {
  128
}

pub(super) fn default_max_helper_pattern_count() -> usize {
  32
}

pub(super) fn default_max_helper_result_bytes() -> usize {
  8_192
}

pub(super) fn default_max_person_proof_reuse_tokens() -> usize {
  4_096
}

pub(super) fn default_person_proof_difficulty() -> u8 {
  18
}

pub(super) fn default_person_proof_token_validity_seconds() -> u64 {
  300
}

pub(super) fn default_person_proof_cookie() -> String {
  "__oxibelt_person_proof".to_string()
}

pub(super) fn default_person_proof_token_bindings() -> Vec<PersonProofTokenBinding> {
  vec![
    PersonProofTokenBinding::UserAgent,
    PersonProofTokenBinding::Route,
    PersonProofTokenBinding::DirectPeerIpNetworkPrefix,
  ]
}

pub(super) fn default_person_proof_direct_peer_ipv4_prefix_bits() -> u8 {
  24
}

pub(super) fn default_person_proof_direct_peer_ipv6_prefix_bits() -> u8 {
  56
}

pub(super) fn default_person_proof_single_use() -> bool {
  true
}

pub(super) fn default_person_proof_status() -> u16 {
  403
}

pub(super) fn default_person_proof_challenge_redirect_status() -> u16 {
  303
}

pub(super) fn default_person_proof_session_path() -> String {
  "/.oxibelt/person-proof/session".to_string()
}

pub(super) fn default_person_proof_verify_path() -> String {
  "/.oxibelt/person-proof/verify".to_string()
}

pub(super) fn default_person_proof_openapi_path() -> String {
  "/.oxibelt/person-proof/openapi.json".to_string()
}

pub(super) fn default_person_proof_provider_timeout_ms() -> u64 {
  3_000
}

pub(super) fn default_person_proof_provider_max_response_body_bytes() -> usize {
  16_384
}

pub(super) fn default_true() -> bool {
  true
}
