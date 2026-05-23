use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::super::{WafMode, WafPhase};

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleDevtoolsCheckRequest {
  #[serde(default)]
  pub rule: Option<OxiRuleCandidate>,
  #[serde(default)]
  pub groups: Vec<OxiRuleGroupCandidate>,
  #[serde(default)]
  pub include_active_rules: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleDevtoolsEvalRequest {
  pub rule: OxiRuleCandidate,
  #[serde(default)]
  pub groups: Vec<OxiRuleGroupCandidate>,
  #[serde(default)]
  pub include_active_rules: bool,
  #[serde(default)]
  pub fixture: OxiRuleFixture,
  #[serde(default)]
  pub expected: Option<OxiRuleExpectedOutcome>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleDevtoolsReplayRequest {
  pub rule: OxiRuleCandidate,
  #[serde(default)]
  pub groups: Vec<OxiRuleGroupCandidate>,
  #[serde(default)]
  pub include_active_rules: bool,
  pub input: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleCandidate {
  pub content: String,
  #[serde(default)]
  pub name: Option<String>,
  #[serde(default)]
  pub id: Option<String>,
  #[serde(default)]
  pub tags: Vec<String>,
  #[serde(default)]
  pub mode: Option<WafMode>,
  #[serde(default)]
  pub phase: Option<WafPhase>,
  #[serde(default)]
  pub priority: Option<i64>,
  #[serde(default)]
  pub route: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleGroupCandidate {
  pub content: String,
  #[serde(default)]
  pub route: Option<String>,
  #[serde(default)]
  pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OxiRuleFixture {
  #[serde(default)]
  pub phase: Option<WafPhase>,
  #[serde(default)]
  pub route: Option<String>,
  #[serde(default)]
  pub request: OxiRuleRequestFixture,
  #[serde(default)]
  pub response: Option<OxiRuleResponseFixture>,
  #[serde(default)]
  pub stream: Option<OxiRuleStreamFixture>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleRequestFixture {
  #[serde(default = "default_method")]
  pub method: String,
  #[serde(default = "default_uri")]
  pub uri: String,
  #[serde(default = "default_http_version")]
  pub version: String,
  #[serde(default)]
  pub headers: BTreeMap<String, HeaderInput>,
  #[serde(default)]
  pub body: Option<String>,
  #[serde(default)]
  pub body_base64: Option<String>,
  #[serde(default)]
  pub body_truncated: bool,
  #[serde(default = "default_peer_addr")]
  pub peer_addr: String,
  #[serde(default)]
  pub downstream_host: Option<String>,
  #[serde(default = "default_scheme")]
  pub downstream_scheme: String,
  #[serde(default)]
  pub tcp_max_hop: Option<u8>,
  #[serde(default)]
  pub tls: OxiRuleTlsFixture,
  #[serde(default = "default_protocol")]
  pub protocol: String,
  #[serde(default = "default_transport_network")]
  pub transport_network: String,
  #[serde(default)]
  pub transport: OxiRuleTransportFixture,
  #[serde(default)]
  pub tags: HashMap<String, String>,
  #[serde(default)]
  pub dynamic_policy: OxiRuleDynamicPolicyFixture,
}

impl Default for OxiRuleRequestFixture {
  fn default() -> Self {
    Self {
      method: default_method(),
      uri: default_uri(),
      version: default_http_version(),
      headers: BTreeMap::new(),
      body: None,
      body_base64: None,
      body_truncated: false,
      peer_addr: default_peer_addr(),
      downstream_host: None,
      downstream_scheme: default_scheme(),
      tcp_max_hop: None,
      tls: OxiRuleTlsFixture::default(),
      protocol: default_protocol(),
      transport_network: default_transport_network(),
      transport: OxiRuleTransportFixture::default(),
      tags: HashMap::new(),
      dynamic_policy: OxiRuleDynamicPolicyFixture::default(),
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleResponseFixture {
  #[serde(default = "default_response_id")]
  pub response_id: String,
  #[serde(default = "default_http_version")]
  pub version: String,
  #[serde(default = "default_status")]
  pub status: u16,
  #[serde(default)]
  pub headers: BTreeMap<String, HeaderInput>,
  #[serde(default)]
  pub body: Option<String>,
  #[serde(default)]
  pub body_base64: Option<String>,
  #[serde(default)]
  pub body_truncated: bool,
  #[serde(default = "default_upstream_name")]
  pub upstream_name: String,
  #[serde(default)]
  pub upstream_pool: Option<String>,
  #[serde(default = "default_scheme")]
  pub upstream_scheme: String,
  #[serde(default)]
  pub upstream_connect_time_ms: Option<u64>,
  #[serde(default)]
  pub upstream_first_byte_time_ms: Option<u64>,
  #[serde(default)]
  pub upstream_error: Option<OxiRuleUpstreamErrorFixture>,
}

impl Default for OxiRuleResponseFixture {
  fn default() -> Self {
    Self {
      response_id: default_response_id(),
      version: default_http_version(),
      status: default_status(),
      headers: BTreeMap::new(),
      body: None,
      body_base64: None,
      body_truncated: false,
      upstream_name: default_upstream_name(),
      upstream_pool: None,
      upstream_scheme: default_scheme(),
      upstream_connect_time_ms: None,
      upstream_first_byte_time_ms: None,
      upstream_error: None,
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleStreamFixture {
  #[serde(default = "default_stream_protocol")]
  pub protocol: String,
  #[serde(default = "default_stream_direction")]
  pub direction: String,
  #[serde(default = "default_stream_unit")]
  pub unit: String,
  #[serde(default)]
  pub payload: Option<String>,
  #[serde(default)]
  pub payload_base64: Option<String>,
  #[serde(default)]
  pub payload_truncated: bool,
  #[serde(default)]
  pub websocket: Option<OxiRuleWebSocketFixture>,
  #[serde(default)]
  pub webtransport: Option<OxiRuleWebTransportFixture>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OxiRuleTlsFixture {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub version: Option<String>,
  #[serde(default)]
  pub cipher_suite: Option<String>,
  #[serde(default)]
  pub sni: Option<String>,
  #[serde(default)]
  pub alpn: Option<String>,
  #[serde(default)]
  pub fingerprint: Option<String>,
  #[serde(default)]
  pub fingerprint_scheme: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OxiRuleTransportFixture {
  #[serde(default)]
  pub tcp_mss: Option<u32>,
  #[serde(default)]
  pub tcp_rtt_ms: Option<u64>,
  #[serde(default)]
  pub udp_datagram_size: Option<usize>,
  #[serde(default)]
  pub udp_connection_id: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OxiRuleDynamicPolicyFixture {
  #[serde(default)]
  pub matched: bool,
  #[serde(default)]
  pub action: Option<String>,
  #[serde(default)]
  pub name: Option<String>,
  #[serde(default)]
  pub reason: Option<String>,
  #[serde(default)]
  pub code: Option<String>,
  #[serde(default)]
  pub mode: Option<String>,
  #[serde(default)]
  pub source: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleUpstreamErrorFixture {
  pub code: String,
  pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleWebSocketFixture {
  #[serde(default = "default_ws_opcode")]
  pub opcode: String,
  #[serde(default = "default_true")]
  pub fin: bool,
  #[serde(default)]
  pub is_control: bool,
  #[serde(default)]
  pub message_opcode: Option<String>,
  #[serde(default)]
  pub frame_payload_size: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OxiRuleWebTransportFixture {
  #[serde(default)]
  pub stream_kind: Option<String>,
  #[serde(default)]
  pub stream_id: Option<u64>,
  #[serde(default)]
  pub datagram_size: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HeaderInput {
  One(String),
  Many(Vec<String>),
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OxiRuleExpectedOutcome {
  #[serde(default)]
  pub matched_rules: Vec<String>,
  #[serde(default)]
  pub terminal_status: Option<u16>,
  #[serde(default)]
  pub stream_close: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleTemplateRenderRequest {
  pub name: String,
  #[serde(default)]
  pub variables: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OxiRuleFalsePositiveRequest {
  #[serde(default)]
  pub finding: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleDevtoolsReport {
  pub ok: bool,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub diagnostics: Vec<OxiRuleDiagnostic>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub matched_rules: Vec<OxiRuleMatchedRule>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub actions: Vec<OxiRuleActionSummary>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub terminal: Option<OxiRuleTerminalSummary>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub mutations: Vec<OxiRuleMutationSummary>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<OxiRuleTagSummary>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub stream_close: Option<OxiRuleStreamCloseSummary>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub body_need: Option<OxiRuleBodyNeedSummary>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub cost_warnings: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub explain_steps: Vec<OxiRuleExplainStep>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub replay_results: Vec<OxiRuleReplayResult>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub templates: Vec<OxiRuleTemplateSummary>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub rendered: Option<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub suggestions: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub toml_patch: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleDiagnostic {
  pub severity: &'static str,
  pub code: &'static str,
  pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleMatchedRule {
  pub scope: String,
  pub route: Option<String>,
  pub phase: String,
  pub name: String,
  pub id: Option<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub tags: Vec<String>,
  pub effective_mode: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleActionSummary {
  pub action: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleTerminalSummary {
  pub status: u16,
  pub body: String,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub headers: Vec<OxiRuleMutationSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleMutationSummary {
  pub op: String,
  pub name: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleTagSummary {
  pub key: String,
  pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleStreamCloseSummary {
  pub websocket_code: u16,
  pub webtransport_code: u32,
  pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleBodyNeedSummary {
  pub phase: String,
  pub request_body: String,
  pub response_body: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleExplainStep {
  pub phase: String,
  pub rule: String,
  pub matched: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleReplayResult {
  pub line: usize,
  pub ok: bool,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub matched_rules: Vec<OxiRuleMatchedRule>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub terminal: Option<OxiRuleTerminalSummary>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub stream_close: Option<OxiRuleStreamCloseSummary>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub diagnostics: Vec<OxiRuleDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OxiRuleTemplateSummary {
  pub name: &'static str,
  pub description: &'static str,
  pub variables: &'static [&'static str],
}

impl OxiRuleDevtoolsReport {
  pub(super) fn ok() -> Self {
    Self {
      ok: true,
      diagnostics: Vec::new(),
      matched_rules: Vec::new(),
      actions: Vec::new(),
      terminal: None,
      mutations: Vec::new(),
      tags: Vec::new(),
      stream_close: None,
      body_need: None,
      cost_warnings: Vec::new(),
      explain_steps: Vec::new(),
      replay_results: Vec::new(),
      templates: Vec::new(),
      rendered: None,
      suggestions: Vec::new(),
      toml_patch: None,
    }
  }

  pub(super) fn error(code: &'static str, error: impl Into<String>) -> Self {
    let mut report = Self::ok();
    report.push_error(code, error);
    report
  }

  pub(super) fn push_error(&mut self, code: &'static str, error: impl Into<String>) {
    self.ok = false;
    self.diagnostics.push(OxiRuleDiagnostic {
      severity: "error",
      code,
      message: error.into(),
    });
  }

  pub(super) fn push_warning(&mut self, code: &'static str, warning: impl Into<String>) {
    self.diagnostics.push(OxiRuleDiagnostic {
      severity: "warning",
      code,
      message: warning.into(),
    });
  }
}

pub(super) fn default_method() -> String {
  "GET".to_string()
}

pub(super) fn default_uri() -> String {
  "/".to_string()
}

pub(super) fn default_http_version() -> String {
  "HTTP/1.1".to_string()
}

fn default_peer_addr() -> String {
  "127.0.0.1:12345".to_string()
}

fn default_scheme() -> String {
  "http".to_string()
}

fn default_protocol() -> String {
  "http".to_string()
}

fn default_transport_network() -> String {
  "tcp".to_string()
}

fn default_response_id() -> String {
  "response-fixture".to_string()
}

pub(super) fn default_status() -> u16 {
  200
}

fn default_upstream_name() -> String {
  "app".to_string()
}

pub(super) fn default_stream_protocol() -> String {
  "websocket".to_string()
}

pub(super) fn default_stream_direction() -> String {
  "downstream_to_upstream".to_string()
}

pub(super) fn default_stream_unit() -> String {
  "websocket_message".to_string()
}

pub(super) fn default_ws_opcode() -> String {
  "text".to_string()
}

pub(super) fn default_true() -> bool {
  true
}
