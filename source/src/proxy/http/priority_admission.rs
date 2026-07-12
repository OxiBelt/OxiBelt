//! Trusted pre-admission classification for global priority capacity.

use std::collections::HashMap;
use std::net::SocketAddr;

use http::Request;

use crate::config::PriorityClass;
use crate::ipm::{IpmDecision, IpmRequestContext, resource as ipm_resource};
use crate::routes::{RouteMatchContext, RouteRequestProtocol};
use crate::state::AppSnapshot;
use crate::waf::{WafProtocol, WafTlsMetadata, WafTransportNetwork};

use super::headers::{extract_host_snapshot, validate_authority_host_consistency};
use super::uri::validate_downstream_path;

#[derive(Clone, Copy, Debug)]
pub(super) struct PriorityAdmission {
  pub(super) class: PriorityClass,
  pub(super) reservation_eligible: bool,
}

impl Default for PriorityAdmission {
  fn default() -> Self {
    Self {
      class: PriorityClass::Default,
      reservation_eligible: false,
    }
  }
}

/// Resolve only the trusted data required by the global capacity boundary.
///
/// The regular request path repeats route resolution after rate and connection limits so its
/// established response ordering remains intact. This preflight has no side effects and never
/// grants a reserve when normalization or identity validation fails.
pub(super) fn classify<B>(
  request: &Request<B>,
  peer_addr: SocketAddr,
  tls: &WafTlsMetadata,
  state: &AppSnapshot,
  protocol: WafProtocol,
  transport_network: WafTransportNetwork,
) -> PriorityAdmission {
  if validate_authority_host_consistency(request).is_err() {
    return PriorityAdmission::default();
  }
  let path = request.uri().path();
  if validate_downstream_path(path).is_err() {
    return PriorityAdmission::default();
  }
  let Ok(client_addr) =
    crate::identity::resolve_client_addr(request.headers(), peer_addr, &state.config.proxy.real_ip)
  else {
    return PriorityAdmission::default();
  };
  let host_snapshot = extract_host_snapshot(request);
  let host = host_snapshot.as_str();
  let request_version = request.version();
  let resolved = state
    .route_table
    .try_resolve_simple_exact_host(host, path, &state.upstreams)
    .or_else(|| {
      state.route_table.resolve_normalized_host_with_context(
        host,
        RouteMatchContext {
          path,
          method: Some(request.method()),
          headers: Some(request.headers()),
          query: request.uri().query(),
          source_ip: Some(client_addr.ip()),
          protocol: Some(RouteRequestProtocol::from_http(request_version, protocol)),
          tls: Some(tls),
        },
        &state.upstreams,
      )
    });
  let Some(resolved) = resolved else {
    return PriorityAdmission::default();
  };
  // Quinn does not expose verified peer-certificate metadata. Keep UDP fail-closed even if a
  // future caller accidentally supplies descriptive certificate fields.
  let mtls = transport_network == WafTransportNetwork::Tcp
    && matched_verified_client_certificate(resolved.route, tls);
  let ipm = ipm_authorized(
    request,
    state,
    &resolved.route.name,
    resolved.route,
    resolved.execution_plan.features.ipm,
    client_addr,
    host,
    path,
  );
  PriorityAdmission {
    class: resolved.route.priority_class,
    reservation_eligible: mtls || ipm,
  }
}

fn matched_verified_client_certificate(
  route: &crate::config::RouteConfig,
  tls: &WafTlsMetadata,
) -> bool {
  let matcher = &route.r#match.tls.client_cert;
  tls.client_certificate.is_some()
    && (matcher.present == Some(true)
      || matcher.fingerprint_sha256.has_conditions()
      || matcher.subject_cn.has_conditions()
      || matcher.san_dns.has_conditions()
      || matcher.san_ip.has_conditions())
}

#[allow(clippy::too_many_arguments)]
fn ipm_authorized<B>(
  request: &Request<B>,
  state: &AppSnapshot,
  route_name: &str,
  route: &crate::config::RouteConfig,
  enabled: bool,
  client_addr: SocketAddr,
  host: &str,
  path: &str,
) -> bool {
  if !enabled {
    return false;
  }
  let Some(actor) = state.ipm.actor_from_headers(request.headers()) else {
    return false;
  };
  let action = route.ipm.action.as_deref().unwrap_or("route:Invoke");
  let resource = ipm_resource(state.ipm.namespace(), "route", route_name);
  let context = IpmRequestContext {
    source_ip: Some(client_addr.ip()),
    method: Some(request.method().as_str().to_string()),
    host: Some(host.to_string()),
    path: Some(path.to_string()),
    route: Some(route_name.to_string()),
    protocol: Some(format!("{:?}", request.version())),
    claims: HashMap::new(),
  };
  state.ipm.authorize(&actor, action, &resource, &context) == IpmDecision::Allow
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::config::Config;
  use crate::state::AppSnapshot;
  use crate::waf::metadata::WafClientCertificateMetadata;

  mod common {
    include!(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/../tests/rust/common/mod.rs"
    ));
  }

  async fn state(extra_route_config: &str) -> (AppSnapshot, common::TempDir) {
    let temp_dir = common::TempDir::new("priority-admission");
    let (cert_path, key_path) =
      common::create_self_signed_cert(temp_dir.path(), "priority-admission");
    let raw = common::minimal_config_toml(&cert_path, &key_path).replace(
      "upstream = \"app\"",
      &format!("upstream = \"app\"\npriority_class = \"security_callback\"{extra_route_config}"),
    );
    let config: Config = toml::from_str(&raw).expect("config should parse");
    config.validate().expect("config should validate");
    (
      AppSnapshot::new(config)
        .await
        .expect("snapshot should initialize"),
      temp_dir,
    )
  }

  fn request(version: http::Version) -> Request<()> {
    Request::builder()
      .method(http::Method::GET)
      .uri("/")
      .version(version)
      .header(http::header::HOST, "example.com")
      .header("priority", "u=0")
      .body(())
      .expect("request should build")
  }

  #[tokio::test]
  async fn client_priority_header_never_claims_a_reservation() {
    let (state, _temp_dir) = state("").await;
    let admission = classify(
      &request(http::Version::HTTP_11),
      "203.0.113.10:443".parse().unwrap(),
      &WafTlsMetadata::default(),
      &state,
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
    );

    assert_eq!(admission.class, PriorityClass::SecurityCallback);
    assert!(!admission.reservation_eligible);
  }

  #[tokio::test]
  async fn verified_tcp_mtls_can_claim_a_reservation_but_udp_fails_closed() {
    let (state, _temp_dir) = state(
      r#"

[routes.match.tls.client_cert]
present = true
"#,
    )
    .await;
    let tls = WafTlsMetadata {
      enabled: true,
      client_certificate: Some(WafClientCertificateMetadata {
        fingerprint_sha256: "00".to_string(),
        ..WafClientCertificateMetadata::default()
      }),
      ..WafTlsMetadata::default()
    };
    let peer = "203.0.113.10:443".parse().unwrap();

    let tcp = classify(
      &request(http::Version::HTTP_11),
      peer,
      &tls,
      &state,
      WafProtocol::Http,
      WafTransportNetwork::Tcp,
    );
    assert_eq!(tcp.class, PriorityClass::SecurityCallback);
    assert!(tcp.reservation_eligible);

    let udp = classify(
      &request(http::Version::HTTP_3),
      peer,
      &tls,
      &state,
      WafProtocol::Http,
      WafTransportNetwork::Udp,
    );
    assert_eq!(udp.class, PriorityClass::SecurityCallback);
    assert!(!udp.reservation_eligible);
  }
}
