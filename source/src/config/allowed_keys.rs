//! Known configuration-key lists used for typo detection.
//! Keeping keys centralized avoids accepting misspelled settings silently.

pub(super) const ROOT_CONFIG_KEYS: &[&str] = &[
  "admin",
  "cache",
  "client_identity",
  "compression",
  "config",
  "connection_limits",
  "database",
  "dynamic_policy",
  "external_auth",
  "health",
  "ipm",
  "limits",
  "listeners",
  "logging",
  "metrics",
  "proxy",
  "quic",
  "rate_limits",
  "routes",
  "runtime",
  "security",
  "shared_state",
  "sni_forward",
  "stream_upstream_pools",
  "stream_listeners",
  "telemetry",
  "tls",
  "turn_upstream_pools",
  "upstream_pools",
  "upstreams",
  "waf",
  "webrtc_turn_listeners",
];

pub(super) const TLS_CONFIG_KEYS: &[&str] = &[
  "cert_chain",
  "certificates",
  "client_auth",
  "crlite",
  "1_2",
  "1_3",
  "key_exchange_groups",
  "max_version",
  "min_version",
  "ocsp",
  "private_key",
  "reject_unknown_sni",
  "remote_signer",
  "require_sni",
  "resumption",
  "server_names",
  "session_ticket_rotation_seconds",
  "session_tickets",
];

pub(super) const TLS12_NEGOTIATION_CONFIG_KEYS: &[&str] = &["groups"];

pub(super) const TLS13_NEGOTIATION_CONFIG_KEYS: &[&str] = &["ciphers", "key_exchange_groups"];

pub(super) const TLS_RESUMPTION_CONFIG_KEYS: &[&str] = &[
  "mode",
  "rotation_seconds",
  "session_cache_size",
  "tls13_ticket_count",
];

pub(super) const TLS_REMOTE_SIGNER_CONFIG_KEYS: &[&str] = &[
  "allow_tls12_unstructured_signing",
  "connect_timeout_ms",
  "enabled",
  "key_id",
  "pool_max_idle_connections",
  "sign_timeout_ms",
  "socket_path",
  "token_env",
  "token_file",
  "token_reload_interval_ms",
];

pub(super) const TLS_CLIENT_AUTH_CONFIG_KEYS: &[&str] = &["ca_certs", "mode", "verify_depth"];
