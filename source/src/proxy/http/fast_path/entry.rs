//! Plain-proxy fast-path entry point.
//! This wrapper keeps decision telemetry and WAF preparation outside the hot handler module.

use std::net::SocketAddr;
use std::sync::Arc;

use http::{Request, Response};
use hyper::body::Body;

use crate::proxy::http::SystemAccessLogContext;
use crate::proxy::http::body::{self, ProxyBody};
use crate::proxy::http::headers::ForwardedHeaderCache;
use crate::routes::ResolvedRoute;
use crate::state::AppSnapshot;
use crate::telemetry::TraceContext;
use crate::waf::{WafProtocol, WafTlsMetadata, WafTransportMetadataInput, WafTransportNetwork};

use super::PlainProxyFastPath;
use super::decision::{plain_proxy_fast_path_decision, record_plain_proxy_fast_path_decision};
use super::stage_timing as timing;
use super::waf::{PlainFastPathWaf, plain_fast_path_waf_required, prepare_plain_fast_path_waf};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_handle_plain_proxy<B>(
  request: Request<B>,
  state: &Arc<AppSnapshot>,
  resolved: &ResolvedRoute<'_>,
  forwarded_client_addr: SocketAddr,
  forwarded_header_cache: Option<&ForwardedHeaderCache>,
  client_addr: SocketAddr,
  host: &str,
  downstream_port: u16,
  tcp_max_hop: Option<u8>,
  tls: &WafTlsMetadata,
  protocol: WafProtocol,
  downstream_scheme: &'static str,
  request_version: http::Version,
  transport_network: WafTransportNetwork,
  transport_metadata: WafTransportMetadataInput<'_>,
  access_log: &mut SystemAccessLogContext<'_>,
  trace_context: Option<TraceContext>,
) -> Result<Response<ProxyBody>, Request<B>>
where
  B: Body<Data = bytes::Bytes> + Send + Sync + Unpin + 'static,
  B::Error: Into<body::BoxError> + Send + Sync + Unpin + 'static,
{
  let eligibility_started = timing::start(state.request_path_features.stage_timing_metrics);
  let metric_protocol = timing::protocol(request_version);
  match plain_proxy_fast_path_decision(&request, state.as_ref(), resolved) {
    Ok(()) => {
      timing::record_fast_path_eligibility(
        state.as_ref(),
        metric_protocol,
        true,
        eligibility_started,
      );
      record_plain_proxy_fast_path_decision(state.as_ref(), request_version, None);
    }
    Err(reason) => {
      timing::record_fast_path_eligibility(
        state.as_ref(),
        metric_protocol,
        false,
        eligibility_started,
      );
      record_plain_proxy_fast_path_decision(state.as_ref(), request_version, Some(reason));
      return Err(request);
    }
  }
  let fast_path_waf = if plain_fast_path_waf_required(resolved) {
    match prepare_plain_fast_path_waf(
      &request,
      state.as_ref(),
      resolved,
      client_addr,
      host,
      tcp_max_hop,
      tls,
      protocol,
      transport_network,
      transport_metadata,
      downstream_scheme,
      access_log,
    ) {
      Ok(waf) => waf,
      Err(response) => return Ok(*response),
    }
  } else {
    PlainFastPathWaf::disabled()
  };
  Ok(
    PlainProxyFastPath::handle(
      request,
      state,
      resolved,
      forwarded_client_addr,
      forwarded_header_cache,
      client_addr,
      host,
      downstream_port,
      tcp_max_hop,
      tls,
      protocol,
      downstream_scheme,
      request_version,
      transport_network,
      transport_metadata,
      fast_path_waf.request,
      fast_path_waf.request_headers,
      fast_path_waf.tags,
      state
        .compiled_fast_path_actions(resolved.route_index)
        .filter(|actions| actions.action_for_version(request_version).is_some()),
      access_log,
      trace_context,
    )
    .await,
  )
}
