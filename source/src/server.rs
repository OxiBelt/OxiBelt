//! Listener supervision and control-plane orchestration for the running proxy.
//! This module binds transports together without owning protocol-specific policy.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ::http::{Response, StatusCode};
use anyhow::{Context, bail};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{info, warn};

#[cfg(feature = "admin-runtime")]
use crate::admin_audit::AdminAuditHandle;
use crate::config::ConnectionLimitIdentityMode;
#[cfg(feature = "admin-runtime")]
use crate::config::{AdminTransportMode, IpmBreakGlassAccessMode};
#[cfg(feature = "admin-runtime")]
use crate::identity::Cidr;
use crate::lifecycle::{ConnectionDrain, TaskRegistry};
use crate::limits::{ConnectionLimitContext, ConnectionPermit};
use crate::listener_socket::{TcpListenOptions, bind_tcp_listeners};
#[cfg(feature = "admin-runtime")]
use crate::overload::ControlPlane;
use crate::proxy::http::body::ProxyBody;
use crate::proxy::http::response::{SilentClose, is_silent_close_response, text_response};
use crate::proxy::{http, http3};
use crate::proxy_protocol;
use crate::runtime_health::RuntimeTaskKind;
use crate::runtime_introspection::RuntimeIntrospectionCounter as RuntimeCounter;
use crate::state::{AppHandle, AppSnapshot};
use crate::stream::{BoundStreamListener, StreamListenerTask};
use crate::tcp_hop;
use crate::telemetry::TelemetryRuntime;
use crate::turn::{BoundTurnListener, TurnListenerTask};
use crate::waf::{WafTlsMetadata, WafTransportMetadataInput};
#[cfg(feature = "admin-runtime")]
mod admin;
#[cfg(feature = "admin-runtime")]
mod admin_audit_endpoint;
#[cfg(feature = "admin-runtime")]
mod admin_audit_gate;
#[cfg(feature = "admin-runtime")]
mod admin_auth;
#[cfg(feature = "admin-runtime")]
mod admin_body;
#[cfg(feature = "admin-runtime")]
mod admin_cluster_executor;
#[cfg(feature = "admin-runtime")]
mod admin_cluster_runtime;
#[cfg(feature = "admin-runtime")]
mod admin_config_diff;
#[cfg(feature = "admin-runtime")]
mod admin_config_introspection;
#[cfg(all(test, feature = "admin-runtime"))]
mod admin_config_introspection_tests;
#[cfg(feature = "admin-runtime")]
mod admin_control;
#[cfg(feature = "admin-runtime")]
mod admin_diagnostics;
#[cfg(feature = "admin-runtime")]
mod admin_dispatch;
#[cfg(feature = "admin-runtime")]
mod admin_error;
#[cfg(feature = "admin-runtime")]
mod admin_h3;
#[cfg(feature = "admin-runtime")]
mod admin_ipm;
#[cfg(feature = "admin-runtime")]
mod admin_ipm_list;
#[cfg(feature = "admin-runtime")]
mod admin_ipm_simulation;
#[cfg(all(test, feature = "admin-runtime"))]
mod admin_ipm_simulation_security_tests;
#[cfg(feature = "admin-runtime")]
mod admin_listener;
#[cfg(feature = "admin-runtime")]
mod admin_metadata;
#[cfg(feature = "admin-runtime")]
mod admin_mutation_resources;
#[cfg(feature = "admin-runtime")]
mod admin_mutations;
#[cfg(feature = "admin-runtime")]
mod admin_operations;
#[cfg(all(test, feature = "admin-runtime"))]
mod admin_operations_tests;
#[cfg(feature = "admin-runtime")]
mod admin_ops;
#[cfg(feature = "admin-runtime")]
mod admin_person_proof;
#[cfg(all(test, feature = "admin-runtime"))]
mod admin_person_proof_scope_tests;
#[cfg(feature = "admin-runtime")]
mod admin_resource;
#[cfg(all(test, feature = "admin-runtime"))]
mod admin_resource_scope_tests;
#[cfg(feature = "admin-runtime")]
mod admin_rulepacks;
#[cfg(feature = "admin-runtime")]
mod admin_runtime;
#[cfg(all(test, feature = "admin-runtime"))]
mod admin_stream_pool_scope_tests;
#[cfg(feature = "admin-runtime")]
mod admin_stream_pools;
#[cfg(feature = "admin-runtime")]
mod admin_upstream_pools;
mod connection_errors;
#[cfg(feature = "admin-runtime")]
mod file_sync_path;
mod h1_fast_proxy;
mod http_io;
mod listener_sets;
mod listener_supervisor;
mod listener_tasks;
mod listeners;
mod ops;
mod plain_http;
#[cfg(test)]
mod pod_lifecycle_tests;
mod prefixed_io;
mod process_signals;

#[cfg(all(feature = "admin-runtime", feature = "fuzzing"))]
pub(crate) fn fuzz_admin_json_mutation(input: &[u8]) {
  const MAX_ADMIN_JSON_BYTES: usize = 32 * 1024;
  let Some((&selector, body)) = input
    .get(..input.len().min(MAX_ADMIN_JSON_BYTES))
    .and_then(|bounded| bounded.split_first())
  else {
    return;
  };
  if matches!(selector, b'{' | b'[') {
    admin_control::fuzz_decode_mutation_body(0, input);
    admin_control::fuzz_decode_mutation_body(1, input);
    for resource_selector in 0..4 {
      admin_mutation_resources::fuzz_decode_mutation_body(resource_selector, input);
    }
    for ipm_selector in 0..9 {
      admin_ipm::fuzz_decode_mutation_body(ipm_selector, input);
    }
    for policy_selector in 0..3 {
      admin::fuzz_decode_dynamic_policy_mutation(policy_selector, input);
    }
  }
  match selector % 4 {
    0 => admin_control::fuzz_decode_mutation_body(selector / 4, body),
    1 => admin_mutation_resources::fuzz_decode_mutation_body(selector / 4, body),
    2 => admin_ipm::fuzz_decode_mutation_body(selector / 4, body),
    _ => admin::fuzz_decode_dynamic_policy_mutation(selector / 4, body),
  }
}
mod public_dispatch;
#[cfg(test)]
mod reload_tests;
mod rollout_identity;
#[cfg(not(feature = "admin-runtime"))]
mod strict_runtime;
mod tls_metadata;
#[cfg(feature = "admin-runtime")]
use admin_auth::{
  AdminActor, AdminAuthentication, AdminAuthorization, admin_authentication, admin_request_context,
};
#[cfg(feature = "admin-runtime")]
use admin_control::AdminControlHandle;
#[cfg(feature = "admin-runtime")]
use admin_dispatch::*;
#[cfg(feature = "admin-runtime")]
use admin_operations::AdminOperationRuntime;
#[cfg(feature = "admin-runtime")]
pub use admin_runtime::serve;
#[cfg(feature = "admin-runtime")]
use admin_stream_pools::admin_stream_pools_response;
#[cfg(feature = "admin-runtime")]
use admin_upstream_pools::admin_upstream_pools_response;
pub(crate) use listener_supervisor::ListenerSupervisor;
use listener_supervisor::*;
use listener_tasks::*;
use listeners::*;
pub(crate) use public_dispatch::downstream_quic_tls_metadata;
use public_dispatch::*;
#[cfg(not(feature = "admin-runtime"))]
pub use strict_runtime::serve;
use tls_metadata::*;
#[cfg(feature = "admin-runtime")]
pub const ADMIN_CAPABILITY_FEATURE_KEYS: &[&str] = &[
  "config_load",
  "file_sync",
  "dynamic_policy",
  "ipm_store",
  "waf_devtools",
  "runtime_introspection",
  "cache_admin",
  "person_proof_admin",
  "upstream_pool_runtime_control",
  "stream_pool_runtime_control",
  "admin_operations",
  "admin_http3",
  "admin_operation_webtransport",
  "admin_audit",
  "admin_audit_anchoring",
  "admin_mutation_replay",
  "atomic_secret_reference_activation",
];
#[cfg(feature = "admin-runtime")]
pub const ADMIN_ERROR_CODE_VALUES: &[&str] = &[
  "invalid_request",
  "unauthorized",
  "permission_denied",
  "not_found",
  "method_not_allowed",
  "conflict",
  "etag_mismatch",
  "payload_too_large",
  "precondition_required",
  "control_plane_unavailable",
  "internal_error",
  "mutation_required",
  "mutation_digest_mismatch",
  "mutation_expired",
  "mutation_not_yet_valid",
  "mutation_indeterminate",
  "mutation_failed",
  "mutation_store_unavailable",
  "invalid_mutation_signature",
  "invalid_mutation_envelope",
  "mutation_request_id_conflict",
  "mutation_revision_conflict",
  "mutation_in_progress",
  "mutation_target_conflict",
  "immutable_rollout_conflict",
  "secret_reference_version_unsupported",
  "secret_reference_field_not_allowlisted",
  "secret_reference_invalid",
  "secret_reference_target_not_found",
  "secret_reference_target_ambiguous",
  "secret_reference_missing",
  "secret_reference_unauthorized",
  "secret_reference_provider_unavailable",
  "secret_reference_type_mismatch",
  "secret_reference_size_exceeded",
  "secret_reference_digest_mismatch",
  "secret_material_invalid_format",
  "secret_certificate_key_mismatch",
  "secret_certificate_expired",
  "secret_certificate_not_yet_valid",
  "secret_ca_bundle_invalid",
  "secret_upstream_tls_preflight_failed",
  "secret_hostname_validation_failed",
  "secret_client_identity_unusable",
  "secret_activation_snapshot_conflict",
  "secret_activation_validation_evidence_mismatch",
  "secret_activation_rollback_failed",
  "secret_activation_entropy_unavailable",
];
#[cfg(feature = "admin-runtime")]
pub const ADMIN_OPERATION_KIND_WIRE_VALUES: &[&str] = &[
  "cache_warm",
  "oxirule_replay",
  "diagnostics_preflight",
  "support_bundle",
  "dynamic_policy_import",
  "webtransport_snapshot",
  "webtransport_drain",
];
#[cfg(feature = "admin-runtime")]
pub const ADMIN_OPERATION_STATE_WIRE_VALUES: &[&str] = &[
  "accepted",
  "queued",
  "claimed",
  "running",
  "cancellation_requested",
  "compensating",
  "succeeded",
  "failed",
  "cancelled",
  "indeterminate",
  "expired",
];

const TCP_TLS_FINGERPRINT_SCHEME: &str = "rustls-tcp-negotiated-v2";
const QUIC_TLS_FINGERPRINT_SCHEME: &str = "quinn-rustls-quic-v2";
#[cfg(feature = "admin-runtime")]
#[cfg(all(test, feature = "admin-runtime"))]
mod admin_audit_tests;

#[cfg(all(test, feature = "admin-runtime"))]
mod admin_diagnostics_tests;

#[cfg(all(test, feature = "admin-runtime"))]
mod admin_diagnostics_async_tests;

#[cfg(all(test, feature = "admin-runtime"))]
mod admin_diagnostics_probe_tests;

#[cfg(all(test, feature = "admin-runtime"))]
mod admin_json_tests;

#[cfg(all(test, feature = "admin-runtime"))]
mod admin_metadata_assertions;

#[cfg(all(test, feature = "admin-runtime"))]
mod admin_runtime_introspection_tests;

#[cfg(all(test, feature = "admin-runtime"))]
#[path = "server/inline_tests.rs"]
mod tests;
