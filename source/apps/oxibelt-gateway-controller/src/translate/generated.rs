#[derive(Debug, Clone)]
pub(super) struct GeneratedRoute {
  pub(super) source: String,
  pub(super) name: String,
  pub(super) hosts: Vec<String>,
  pub(super) path_prefix: String,
  pub(super) path_exact: Option<String>,
  pub(super) methods: Vec<String>,
  pub(super) headers: Vec<NamedExactMatch>,
  pub(super) queries: Vec<NamedExactMatch>,
  pub(super) priority: i32,
  pub(super) upstream_pool: Option<String>,
  pub(super) direct_response_status: Option<u16>,
  pub(super) rewrite: Option<RewriteAction>,
  pub(super) redirect: Option<RedirectAction>,
  pub(super) request_headers: HeaderModifierAction,
  pub(super) response_headers: HeaderModifierAction,
  pub(super) cors: Option<CorsAction>,
  pub(super) request_mirrors: Vec<RequestMirrorAction>,
  pub(super) external_auth: Option<String>,
  pub(super) policy_source: Option<String>,
  pub(super) waf_request_rule_groups: Vec<String>,
  pub(super) max_request_body_bytes: Option<u64>,
  pub(super) upstream_request_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedPool {
  pub(super) source: String,
  pub(super) name: String,
  pub(super) servers: Vec<GeneratedServer>,
  pub(super) discoveries: Vec<GeneratedKubernetesDiscovery>,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedServer {
  pub(super) id: String,
  pub(super) origin: String,
  pub(super) weight: u32,
  pub(super) tls: Option<GeneratedBackendTls>,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedKubernetesDiscovery {
  pub(super) id: String,
  pub(super) weight_multiplier: u32,
  pub(super) endpoint: String,
  pub(super) namespace: String,
  pub(super) service: String,
  pub(super) scheme: String,
  pub(super) port: GeneratedKubernetesDiscoveryPort,
  pub(super) tls: Option<GeneratedBackendTls>,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedBackendTls {
  pub(super) server_name: String,
  pub(super) subject_alt_names: Vec<GeneratedBackendTlsSubjectAltName>,
  pub(super) trust: String,
  pub(super) trusted_ca_certs: Vec<String>,
  pub(super) trusted_ca_sha256: Vec<String>,
  pub(super) client_identity: Option<GeneratedClientIdentity>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct GeneratedClientIdentity {
  pub(super) derived_secret_name: String,
  pub(super) cert_chain: String,
  pub(super) private_key: String,
}

#[derive(Debug, Clone)]
pub(super) enum GeneratedBackendTlsSubjectAltName {
  Dns(String),
  Uri(String),
}

#[derive(Debug, Clone)]
pub(super) enum BackendTlsDecision {
  Valid(GeneratedBackendTls),
  Invalid { covered_diagnostics: Vec<usize> },
}

#[derive(Debug, Clone)]
pub(super) enum GeneratedKubernetesDiscoveryPort {
  Number(u16),
  Name(String),
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedSniRule {
  pub(super) source: String,
  pub(super) name: String,
  pub(super) server_names: Vec<String>,
  pub(super) target: String,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedStreamListener {
  pub(super) source: String,
  pub(super) name: String,
  pub(super) network: String,
  pub(super) bind: String,
  pub(super) upstream_pool: String,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedStreamPool {
  pub(super) source: String,
  pub(super) name: String,
  pub(super) servers: Vec<GeneratedStreamServer>,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedStreamServer {
  pub(super) id: String,
  pub(super) origin: String,
  pub(super) weight: u32,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedExternalAuth {
  pub(super) source: String,
  pub(super) name: String,
  pub(super) endpoint: String,
  pub(super) forward_headers: Vec<String>,
  pub(super) identity_headers: Vec<String>,
  pub(super) terminal_response_headers: Vec<String>,
  pub(super) max_request_body_bytes: usize,
  pub(super) allowed_content_types: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct NamedExactMatch {
  pub(super) name: String,
  pub(super) value: String,
}

impl GeneratedRoute {
  pub(super) fn has_same_fail_closed_tombstone_match(&self, other: &Self) -> bool {
    route_source_identity(&self.source) == route_source_identity(&other.source)
      && self.name == other.name
      && self.path_prefix == other.path_prefix
      && self.path_exact == other.path_exact
      && self.methods == other.methods
      && self.headers == other.headers
      && self.queries == other.queries
      && self.priority == other.priority
  }
}

fn route_source_identity(source: &str) -> &str {
  source
    .split_once(" via Gateway/")
    .map_or(source, |(identity, _)| identity)
}

#[derive(Debug, Clone)]
pub(super) struct RewriteAction {
  pub(super) authority: Option<String>,
  pub(super) path: Option<String>,
  pub(super) query: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct RedirectAction {
  pub(super) status: u16,
  pub(super) scheme: Option<String>,
  pub(super) hostname: Option<String>,
  pub(super) port: Option<u16>,
  pub(super) path: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct HeaderModifierAction {
  pub(super) set: Vec<HeaderValueAction>,
  pub(super) add: Vec<HeaderValueAction>,
  pub(super) remove: Vec<String>,
}

impl HeaderModifierAction {
  pub(super) fn is_empty(&self) -> bool {
    self.set.is_empty() && self.add.is_empty() && self.remove.is_empty()
  }
}

#[derive(Debug, Clone)]
pub(super) struct HeaderValueAction {
  pub(super) name: String,
  pub(super) value: String,
}

#[derive(Debug, Clone)]
pub(super) struct CorsAction {
  pub(super) allow_origins: Vec<String>,
  pub(super) allow_methods: Vec<String>,
  pub(super) allow_headers: Vec<String>,
  pub(super) expose_headers: Vec<String>,
  pub(super) allow_credentials: bool,
  pub(super) max_age_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct RequestMirrorAction {
  pub(super) upstream_pool: String,
  pub(super) sample_percent: Option<f64>,
  pub(super) max_body_bytes: usize,
}
