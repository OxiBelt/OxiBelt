//! Configuration parsing and validation for every runtime boundary.
//! This module keeps defaults explicit before listeners, proxying, WAF, and admin code consume them.

use std::collections::HashMap;
use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::waf::WafConfig;

mod access_log;
mod admin_audit;
mod admin_audit_anchor;
mod admin_legacy;
mod admin_mutations;
mod admin_operations;
mod admin_runtime;
mod admin_workload_identity;
mod allowed_keys;
mod assembly;
mod cache_external;
mod cache_sections;
mod circuit_breakers;
mod client_identity;
mod compression;
mod crlite;
mod crypto;
mod database;
mod defaults;
mod dynamic_policy;
mod external_auth;
mod http2;
mod http3;
mod ipm;
mod lb_policy_compat;
mod limits;
mod listener;
mod loader;
mod logging;
mod model;
mod native_config;
mod native_schema;
mod operational_profile;
mod outbound_revocation;
mod overload;
mod path_helpers;
mod path_resolution;
mod provenance;
mod quic;
mod quic_workers;
mod rate_limit;
mod redaction;
mod retry;
mod rollout_identity;
mod route;
mod route_actions;
mod route_header_policy;
mod route_static_files;
mod route_tls_policy;
mod runtime_hardening;
mod schema_cache;
mod schema_runtime;
mod schema_services;
mod security_headers;
mod shape;
mod shared_state;
mod sni_forward;
mod source_paths;
mod static_files;
mod stream;
mod telemetry;
mod tls;
mod turn;
mod turn_queue;
mod upstream_pool;
mod upstream_tls;
#[cfg(test)]
mod upstream_tls_tests;
mod validation_core;
mod validation_helpers;
mod validation_limits;
mod validation_proxy;
mod validation_services;
mod workers;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_native_config(input: &[u8]) {
  loader::fuzz_virtual_toml_documents(input);
}
use admin_legacy::{LegacyAdminRbacConfig, LegacyAdminTokenStoreConfig};
pub use admin_workload_identity::*;
pub use cache_external::{
  ExternalCacheHandlerConfig, ExternalCacheHandlerFailPolicy, ExternalCacheHandlerKind,
};
pub use cache_sections::{
  CacheAdmissionConfig, CachePolicyRuleConfig, CacheStaleIfErrorConfig, CacheSurrogateConfig,
};
pub use circuit_breakers::*;
pub use client_identity::*;
pub use compression::*;
pub use crlite::*;
pub use crypto::*;
pub use database::*;
pub(crate) use defaults::default_cache_tmpfs_dir;
use defaults::*;
pub use dynamic_policy::*;
pub use external_auth::*;
pub use http2::*;
pub use http3::*;
pub use ipm::*;
pub use lb_policy_compat::*;
use limits::{
  default_max_connections, default_max_connections_per_ip, default_max_requests_per_connection,
  default_max_webtransport_sessions_per_connection,
};
pub use listener::{HttpListenerMode, ListenerConfig, ProxyProtocolConfig, ProxyProtocolVersion};
use listener::{RawListenerConfig, validate_bind_list, validate_bind_lists_do_not_overlap};
use loader::load_toml_with_includes_and_overrides;
use loader::{absolute_config_path, load_toml_with_includes};
pub use logging::*;
pub use model::*;
pub use native_config::*;
pub use native_schema::*;
pub use operational_profile::OperationalProfile;
pub use outbound_revocation::*;
pub use overload::*;
use path_helpers::{ConfigPathRoots, config_path_roots};
pub(crate) use path_helpers::{
  canonicalize_existing_file, canonicalize_local_config_file_target,
  quote_postgres_identifier_path, resolve_existing_local_config_file_path_with_logical,
  resolve_local_config_file_path,
};
use path_helpers::{
  validate_optional_non_empty, validate_postgres_identifier_path, validate_relative_path,
};
pub use provenance::{ConfigOriginIndex, ConfigOriginKind, ConfigValueOrigin};
pub(crate) use quic::RawQuicTransportConfig;
pub use quic::*;
pub use quic_workers::*;
pub use rate_limit::*;
use redaction::{
  redact_effective_toml, set_toml_float_path, set_toml_integer_path, set_toml_value_path,
};
pub use retry::*;
pub use rollout_identity::{
  ConfigRolloutApplyState, ConfigRolloutIdentity, ConfigRolloutMode, KubernetesRolloutTarget,
  KubernetesRolloutTargetKind,
};
pub use route::*;
pub use route_actions::*;
pub use route_header_policy::*;
pub use route_static_files::*;
pub use runtime_hardening::*;
pub use schema_cache::*;
pub use schema_runtime::*;
pub use schema_services::*;
pub use security_headers::*;
use shape::{
  allowed_config_keys, normalize_merged_lb_policy_compat,
  normalize_merged_upstream_resolution_compat, reject_removed_access_log_config,
  validate_merged_toml_shape,
};
pub use shared_state::{
  BackendFailureMode, RedisAuthConfig, RedisPlaintextPolicy, RedisPoolConfig, RedisTlsConfig,
  RedisTrustStore, SharedStateBackendConfig, SharedStateBackendKind, SharedStateConfig,
  SharedStateFailurePolicies,
};
pub(crate) use shared_state::{
  RedisPoolSettings, default_shared_state_namespace, validate_redis_connection_url,
};
pub use sni_forward::*;
pub use source_paths::{ConfigSourcePaths, DownstreamTlsCertificateSourcePaths};
pub use static_files::*;
pub use stream::*;
pub use telemetry::*;
pub use tls::*;
use turn::RawWebRtcTurnListenerConfig;
pub use turn::*;
pub use upstream_pool::*;
pub use upstream_tls::*;
use validation_helpers::*;
pub(crate) use validation_helpers::{
  turn_upstream_pool_server_id, upstream_pool_server_id, validate_runtime_identifier,
};
pub use workers::*;
pub use {
  access_log::*, admin_audit::*, admin_audit_anchor::*, admin_mutations::*, admin_operations::*,
};
