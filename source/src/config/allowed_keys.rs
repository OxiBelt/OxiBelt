//! Known configuration-key lists used for typo detection.
//! Keeping keys centralized avoids accepting misspelled settings silently.

pub(super) const ROOT_CONFIG_KEYS: &[&str] = &[
  "admin",
  "access_log",
  "cache",
  "circuit_breakers",
  "client_identity",
  "compression",
  "config",
  "connection_limits",
  "crypto",
  "database",
  "dynamic_policy",
  "external_auth",
  "health",
  "ipm",
  "limits",
  "listeners",
  "logging",
  "metrics",
  "overload",
  "profile",
  "profile_version",
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
  "ssl_early_data",
];

pub(super) const TLS12_NEGOTIATION_CONFIG_KEYS: &[&str] = &["groups"];

pub(super) const TLS13_NEGOTIATION_CONFIG_KEYS: &[&str] = &["ciphers", "key_exchange_groups"];

pub(super) const TLS_RESUMPTION_CONFIG_KEYS: &[&str] = &[
  "multi_certificate",
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

pub(super) const ADMIN_CONFIG_KEYS: &[&str] = &[
  "allow_insecure_plaintext",
  "audit",
  "bearer_token_env",
  "bind",
  "cache_purge_signing",
  "enabled",
  "http3",
  "mutations",
  "operations",
  "plaintext_allowed_source_cidrs",
  "rbac",
  "tls",
  "token_store",
  "transport",
  "workload_identity",
];

pub(super) const ADMIN_AUDIT_CONFIG_KEYS: &[&str] = &[
  "acknowledgement",
  "anchor",
  "backend",
  "enabled",
  "export",
  "integrity",
  "mode",
  "queue_capacity",
  "required_actions",
  "spool",
  "store",
];

pub(super) const ADMIN_AUDIT_SPOOL_CONFIG_KEYS: &[&str] = &[
  "directory",
  "enabled",
  "max_bytes",
  "max_event_bytes",
  "max_events",
];

pub(super) const ADMIN_AUDIT_INTEGRITY_CONFIG_KEYS: &[&str] = &["hmac_key_env", "hmac_key_id"];

pub(super) const ADMIN_AUDIT_ANCHOR_CONFIG_KEYS: &[&str] = &[
  "deployment_epoch_env",
  "enabled",
  "max_pending_bytes",
  "max_pending_checkpoints",
  "record_interval",
  "signer",
  "sink",
  "time_interval_ms",
];

pub(super) const ADMIN_AUDIT_ANCHOR_SINK_CONFIG_KEYS: &[&str] =
  &["authority_id", "backend", "kind", "submit_timeout_ms"];

pub(super) const ADMIN_AUDIT_ANCHOR_SIGNER_CONFIG_KEYS: &[&str] = &[
  "connect_timeout_ms",
  "key_id",
  "kind",
  "public_key_file",
  "sign_timeout_ms",
  "socket_path",
  "token_env",
  "token_file",
  "token_reload_interval_ms",
];

pub(super) const ADMIN_WORKLOAD_IDENTITY_CONFIG_KEYS: &[&str] = &[
  "bearer_mode",
  "enabled",
  "revoked_certificate_fingerprints_sha256",
];

pub(super) const ADMIN_MUTATIONS_CONFIG_KEYS: &[&str] = &[
  "artifact_key_env",
  "backend",
  "max_clock_skew_seconds",
  "max_response_bytes",
  "max_validity_seconds",
  "mode",
  "retention_seconds",
  "rollout",
  "signers",
];

pub(super) const ADMIN_MUTATION_ROLLOUT_CONFIG_KEYS: &[&str] = &[
  "canary_observation_seconds",
  "cluster_id",
  "heartbeat_interval_seconds",
  "instance_id_env",
  "members",
  "mode",
  "phase_timeout_seconds",
  "rollback_timeout_seconds",
  "stale_after_seconds",
];

pub(super) const ADMIN_MUTATION_SIGNER_CONFIG_KEYS: &[&str] = &[
  "ed25519_public_key_file",
  "id",
  "ml_dsa_44_public_key_file",
  "principal",
  "suite",
];

pub(super) const IPM_BREAK_GLASS_CONFIG_KEYS: &[&str] = &[
  "access_mode",
  "argon2id_memory_mib",
  "max_activation_seconds",
];
