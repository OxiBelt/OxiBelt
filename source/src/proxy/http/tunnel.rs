//! CONNECT, upgrade, WebSocket, and idle-aware bidirectional tunneling.

use super::*;

use crate::bandwidth::{BandwidthDirection, RouteBandwidthLimiter};

#[path = "tunnel/websocket_wire.rs"]
mod websocket_wire;

pub(super) struct TunnelConnectionLimitHold {
  _request_permit: Option<ConnectionPermit>,
  _first_request_context: Option<ConnectionLimitContext>,
}
impl TunnelConnectionLimitHold {
  pub(super) fn capture(
    request_permit: &mut Option<ConnectionPermit>,
    first_request_context: Option<&ConnectionLimitContext>,
  ) -> Self {
    Self {
      _request_permit: request_permit.take(),
      _first_request_context: first_request_context.cloned(),
    }
  }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_connect_request(
  mut request: Request<ProxyBody>,
  state: &Arc<AppSnapshot>,
  resolved: &crate::routes::ResolvedRoute<'_>,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  request_waf: &crate::waf::RequestWafDecision,
  request_version: http::Version,
  connection_limit_context: Option<&ConnectionLimitContext>,
  request_connection_permit: &mut Option<ConnectionPermit>,
  drain: ConnectionDrain,
  access_log: &mut SystemAccessLogContext<'_>,
  _trace_context: Option<TraceContext>,
) -> Response<ProxyBody> {
  let route_security = RouteSecurityHeaders::new(&state.config.security, resolved.route);
  if !state.config.proxy.upgrades.connect_tunneling || !resolved.route.connect_tunneling {
    return route_security.text(
      StatusCode::METHOD_NOT_ALLOWED,
      "CONNECT tunneling is disabled for this route",
    );
  }

  let selected = match select_request_upstream(
    state.as_ref(),
    resolved,
    client_addr,
    downstream_host,
    request.uri(),
    request.headers().get(http::header::COOKIE),
    request_waf,
  )
  .await
  {
    Ok(selected) => selected,
    Err(error) => {
      return route_security.apply(upstream_selection_error_response(error));
    }
  };
  let upstream = selected.upstream.clone();
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, &upstream);
  access_log.set_upstream(&upstream.name, upstream.origin.scheme());
  let selected_pool_name = selected.pool_name().map(Arc::<str>::from);
  if let Some(pool_name) = selected_pool_name.as_deref() {
    access_log.set_upstream_pool(pool_name);
  }
  let connection_admission = crate::upstream_resolution::ConnectionAdmissionContext::new(
    state.circuit_breakers.clone(),
    selected_pool_name,
  );
  let sticky_cookie = selected.sticky_cookie();
  let pool_report = state.pools.clone();
  let pool_selection = selected.into_pool_selection();
  let upstream_resolution = state.config.proxy.upstream_resolution.clone();
  if request_version == http::Version::HTTP_11 || request_version == http::Version::HTTP_10 {
    let downstream_upgrade = hyper::upgrade::on(&mut request);
    let connection_limit_hold =
      TunnelConnectionLimitHold::capture(request_connection_permit, connection_limit_context);
    let bandwidth = resolved.bandwidth.clone();
    let bandwidth_metrics = state.metrics.clone();
    tokio::spawn(async move {
      let _connection_limit_hold = connection_limit_hold;
      let result = async {
        let downstream = downstream_upgrade.await?;
        let downstream = TokioIo::new(downstream);
        let upstream_stream = dial_tunnel_upstream(
          &upstream,
          &upstream_resolution,
          client_addr,
          timeouts,
          connection_admission,
        )
        .await?;
        copy_bidirectional_with_idle_and_bandwidth(
          downstream,
          upstream_stream,
          timeouts.websocket_idle,
          drain,
          Some(bandwidth),
          Some(bandwidth_metrics),
          crate::metrics::BandwidthTrafficClass::Tunnel,
          TunnelProtocol::Opaque,
        )
        .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
      }
      .await;
      if result.is_ok() {
        pool_report.report_success_async(&upstream.name).await;
      } else {
        pool_report.report_failure_async(&upstream.name).await;
      }
      drop(pool_selection);
    });
    let mut response = Response::new(full_body(bytes::Bytes::new()));
    *response.status_mut() = StatusCode::OK;
    apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
    return response;
  }

  match dial_tunnel_upstream(
    &upstream,
    &upstream_resolution,
    client_addr,
    timeouts,
    connection_admission,
  )
  .await
  {
    Ok(upstream_stream) => {
      let body = bridge_connect_body(request.into_body(), upstream_stream, timeouts, drain);
      drop(pool_selection);
      let mut response = Response::new(body);
      *response.status_mut() = StatusCode::OK;
      apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
      response
    }
    Err(error) => {
      pool_report.report_failure_async(&upstream.name).await;
      warn!(upstream = %upstream.name, error = %error, "failed to establish CONNECT tunnel");
      access_log.record_upstream_error("connect_error", &error.to_string());
      route_security.text(
        StatusCode::BAD_GATEWAY,
        "failed to establish CONNECT tunnel",
      )
    }
  }
}
pub(super) fn bridge_connect_body<U>(
  mut downstream_body: ProxyBody,
  upstream: U,
  timeouts: EffectiveTimeouts,
  mut drain: ConnectionDrain,
) -> ProxyBody
where
  U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (body_sender, body) = body::channel_body(1);
  let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
  let mut downstream_to_upstream = tokio::spawn(async move {
    while let Some(frame) = downstream_body.frame().await {
      let frame = match frame {
        Ok(frame) => frame,
        Err(_) => break,
      };
      if let Ok(data) = frame.into_data() {
        let write_result =
          tokio::time::timeout(timeouts.upstream_send, upstream_writer.write_all(&data)).await;
        if !matches!(write_result, Ok(Ok(()))) {
          break;
        }
      }
    }
    let _ = upstream_writer.shutdown().await;
  });
  let mut upstream_to_downstream = tokio::spawn(async move {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
      match tokio::time::timeout(timeouts.upstream_read, upstream_reader.read(&mut buffer)).await {
        Err(_) => {
          let _ = body_sender
            .send(Err(boxed_error(std::io::Error::new(
              std::io::ErrorKind::TimedOut,
              "CONNECT upstream read timed out",
            ))))
            .await;
          break;
        }
        Ok(Ok(0)) => break,
        Ok(Ok(read)) => {
          let frame = Ok(hyper::body::Frame::data(bytes::Bytes::copy_from_slice(
            &buffer[..read],
          )));
          let sent = body_sender.send(frame).await.is_ok();
          if !sent {
            break;
          }
        }
        Ok(Err(error)) => {
          let _ = body_sender
            .send(Err(boxed_error(std::io::Error::other(format!(
              "failed to read CONNECT upstream: {error}"
            )))))
            .await;
          break;
        }
      }
    }
  });

  tokio::spawn(async move {
    let drain_close = drain.close_delay_elapsed();
    tokio::pin!(drain_close);
    let mut downstream_done = false;
    let mut upstream_done = false;

    loop {
      tokio::select! {
        _ = &mut drain_close => {
          if !downstream_done {
            downstream_to_upstream.abort();
          }
          if !upstream_done {
            upstream_to_downstream.abort();
          }
          return;
        }
        _ = &mut downstream_to_upstream, if !downstream_done => {
          downstream_done = true;
          if upstream_done {
            return;
          }
        }
        _ = &mut upstream_to_downstream, if !upstream_done => {
          upstream_done = true;
          if downstream_done {
            return;
          }
        }
      }
    }
  });

  body
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn copy_bidirectional_with_idle_and_bandwidth<D, U>(
  downstream: D,
  upstream: U,
  idle_timeout: Duration,
  mut drain: ConnectionDrain,
  bandwidth: Option<Arc<RouteBandwidthLimiter>>,
  metrics: Option<Arc<crate::metrics::Metrics>>,
  traffic_class: crate::metrics::BandwidthTrafficClass,
  protocol: TunnelProtocol,
) -> anyhow::Result<()>
where
  D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (downstream_read, downstream_write) = tokio::io::split(downstream);
  let (upstream_read, upstream_write) = tokio::io::split(upstream);
  let (activity_tx, mut activity_rx) = mpsc::channel(16);
  let upload = bandwidth
    .as_ref()
    .map(|limiter| limiter.flow(BandwidthDirection::Upload));
  let download = bandwidth
    .as_ref()
    .map(|limiter| limiter.flow(BandwidthDirection::Download));
  let mut downstream_to_upstream = spawn_copy_task(
    downstream_read,
    upstream_write,
    activity_tx.clone(),
    upload,
    metrics.clone(),
    traffic_class,
    protocol,
  );
  let mut upstream_to_downstream = spawn_copy_task(
    upstream_read,
    downstream_write,
    activity_tx,
    download,
    metrics,
    traffic_class,
    protocol,
  );
  let idle = tokio::time::sleep(idle_timeout);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);
  let mut bandwidth_waiters = 0usize;

  loop {
    tokio::select! {
      biased;
      result = &mut downstream_to_upstream => {
        upstream_to_downstream.abort();
        return result.context("upgrade copy task panicked")?;
      }
      result = &mut upstream_to_downstream => {
        downstream_to_upstream.abort();
        return result.context("upgrade copy task panicked")?;
      }
      activity = activity_rx.recv() => {
        let Some(activity) = activity else {
          return Ok(());
        };
        match activity {
          TunnelActivity::Network => {
            if bandwidth_waiters == 0 {
              idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
          }
          TunnelActivity::BandwidthWaitStarted => {
            bandwidth_waiters = bandwidth_waiters.saturating_add(1);
          }
          TunnelActivity::BandwidthWaitEnded => {
            bandwidth_waiters = bandwidth_waiters.saturating_sub(1);
            if bandwidth_waiters == 0 {
              idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
          }
        }
      }
      _ = &mut idle, if bandwidth_waiters == 0 => {
        downstream_to_upstream.abort();
        upstream_to_downstream.abort();
        return Err(anyhow::anyhow!("upgrade tunnel idle timeout elapsed"));
      }
      _ = &mut drain_close => {
        downstream_to_upstream.abort();
        upstream_to_downstream.abort();
        return Ok(());
      }
    }
  }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum TunnelActivity {
  Network,
  BandwidthWaitStarted,
  BandwidthWaitEnded,
}

#[derive(Clone, Copy)]
pub(super) enum TunnelProtocol {
  Opaque,
  WebSocket,
}

#[allow(clippy::too_many_arguments)]
fn spawn_copy_task<R, W>(
  reader: R,
  writer: W,
  activity: mpsc::Sender<TunnelActivity>,
  bandwidth: Option<crate::bandwidth::BandwidthFlow>,
  metrics: Option<Arc<crate::metrics::Metrics>>,
  traffic_class: crate::metrics::BandwidthTrafficClass,
  protocol: TunnelProtocol,
) -> tokio::task::JoinHandle<anyhow::Result<()>>
where
  R: AsyncRead + Unpin + Send + 'static,
  W: AsyncWrite + Unpin + Send + 'static,
{
  match protocol {
    TunnelProtocol::Opaque => tokio::spawn(copy_one_way_shaped(
      reader,
      writer,
      activity,
      bandwidth,
      metrics,
      traffic_class,
    )),
    TunnelProtocol::WebSocket => tokio::spawn(websocket_wire::copy_one_way(
      reader, writer, activity, bandwidth, metrics,
    )),
  }
}

async fn copy_one_way_shaped<R, W>(
  mut reader: R,
  mut writer: W,
  activity: mpsc::Sender<TunnelActivity>,
  mut bandwidth: Option<crate::bandwidth::BandwidthFlow>,
  metrics: Option<Arc<crate::metrics::Metrics>>,
  traffic_class: crate::metrics::BandwidthTrafficClass,
) -> anyhow::Result<()>
where
  R: AsyncRead + Unpin,
  W: AsyncWrite + Unpin,
{
  let mut buffer = vec![0u8; 16 * 1024];
  loop {
    let read = reader.read(&mut buffer).await?;
    if read == 0 {
      writer.shutdown().await?;
      return Ok(());
    }
    if let Some(flow) = bandwidth.as_mut() {
      let mut offset = 0;
      while offset < read {
        let limited = flow.is_limited()?;
        let (granted, waited) = if limited {
          let _ = activity.send(TunnelActivity::BandwidthWaitStarted).await;
          let acquisition = flow.acquire(read - offset).await;
          let _ = activity.send(TunnelActivity::BandwidthWaitEnded).await;
          let grant = acquisition?;
          (grant.bytes(), grant.waited())
        } else {
          (read - offset, Duration::ZERO)
        };
        writer.write_all(&buffer[offset..offset + granted]).await?;
        if limited && let Some(metrics) = metrics.as_ref() {
          metrics.record_bandwidth_shaped_bytes(flow.direction(), traffic_class, granted as u64);
          if !waited.is_zero() {
            metrics.record_bandwidth_wait(flow.direction(), traffic_class, waited);
          }
        }
        offset += granted;
      }
    } else {
      writer.write_all(&buffer[..read]).await?;
    }
    let _ = activity.send(TunnelActivity::Network).await;
  }
}

pub(super) async fn dial_tunnel_upstream(
  upstream: &UpstreamConfig,
  resolution_config: &crate::config::UpstreamResolutionConfig,
  client_addr: std::net::SocketAddr,
  timeouts: EffectiveTimeouts,
  admission: crate::upstream_resolution::ConnectionAdmissionContext,
) -> anyhow::Result<crate::upstream_resolution::ConnectionAdmitted<TcpStream>> {
  let (mut stream, remote_addr, connect_deadline) =
    connect_upstream_tcp(upstream, resolution_config, timeouts, admission).await?;
  crate::tcp_socket::enable_tcp_nodelay(stream.get_ref(), remote_addr, "upstream tunnel");
  tokio::time::timeout_at(
    connect_deadline,
    crate::proxy_protocol_egress::write_header(
      &mut stream,
      upstream.proxy_protocol_egress,
      client_addr,
      remote_addr,
    ),
  )
  .await
  .context("upstream tunnel PROXY protocol egress header timed out")?
  .context("failed to write upstream PROXY protocol egress header")?;
  Ok(stream)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_upgrade_request(
  mut request: Request<ProxyBody>,
  state: &Arc<AppSnapshot>,
  resolved: &crate::routes::ResolvedRoute<'_>,
  forwarded_client_addr: std::net::SocketAddr,
  client_addr: std::net::SocketAddr,
  downstream_host: &str,
  downstream_scheme: &str,
  downstream_port: u16,
  request_waf: &crate::waf::RequestWafDecision,
  stream_waf: Option<StreamWafRequestContext>,
  connection_limit_context: Option<&ConnectionLimitContext>,
  request_connection_permit: &mut Option<ConnectionPermit>,
  drain: ConnectionDrain,
  access_log: &mut SystemAccessLogContext<'_>,
  trace_context: Option<TraceContext>,
) -> Option<Response<ProxyBody>> {
  let route_security = RouteSecurityHeaders::new(&state.config.security, resolved.route);
  if request.version() != http::Version::HTTP_11 {
    return Some(route_security.text(
      StatusCode::NOT_IMPLEMENTED,
      "HTTP upgrade tunneling requires HTTP/1.1 downstream",
    ));
  }

  let websocket_upgrade = is_websocket_upgrade(&request);
  let websocket_framed_bridge = websocket_upgrade && stream_waf.is_some();
  let generic_upgrade = !websocket_upgrade
    && state.config.proxy.upgrades.generic_http_upgrade
    && resolved.route.generic_http_upgrade;
  if websocket_upgrade && !state.config.proxy.upgrades.websocket {
    return None;
  }
  if !websocket_upgrade && !generic_upgrade {
    return None;
  }

  let selected = match select_request_upstream(
    state.as_ref(),
    resolved,
    client_addr,
    downstream_host,
    request.uri(),
    request.headers().get(http::header::COOKIE),
    request_waf,
  )
  .await
  {
    Ok(selected) => selected,
    Err(error) => {
      return Some(route_security.apply(upstream_selection_error_response(error)));
    }
  };
  let upstream = selected.upstream;
  if let Some(pool_name) = selected.pool_name() {
    access_log.set_upstream_pool(pool_name);
  }
  let sticky_cookie = selected.sticky_cookie();
  let pool_selection = selected.into_pool_selection();
  access_log.set_upstream(&upstream.name, upstream.origin.scheme());
  let timeouts = EffectiveTimeouts::new(&state.config, resolved.route, upstream);

  if websocket_upgrade && !upstream.websocket {
    return Some(route_security.text(
      StatusCode::BAD_GATEWAY,
      "selected upstream does not allow WebSocket",
    ));
  }
  let Some(upstream_uri) = state.upstream_uri_parts.get(&upstream.name) else {
    warn!(upstream = %upstream.name, "missing precomputed upstream URI parts");
    return Some(route_security.text(StatusCode::BAD_GATEWAY, "upstream URI is not configured"));
  };
  let target_uri = match route_actions::build_resolved_upstream_uri(
    upstream_uri,
    resolved,
    downstream_scheme,
    downstream_host,
    request.uri(),
  ) {
    Ok(uri) => uri,
    Err(_) => {
      return Some(route_security.text(StatusCode::BAD_REQUEST, "invalid upstream URI rewrite"));
    }
  };
  let downstream_upgrade = hyper::upgrade::on(&mut request);
  let verified_early_data = early_data::is_verified(&request);
  let (mut parts, body) = request.into_parts();
  parts.uri = target_uri;
  parts.version = http::Version::HTTP_11;
  if upstream.preserve_host {
    set_effective_host_header(&mut parts.headers, downstream_host);
  } else {
    parts.headers.remove(http::header::HOST);
  }
  add_forwarded_headers(
    &mut parts.headers,
    forwarded_client_addr,
    downstream_host,
    downstream_scheme,
    downstream_port,
    state.config.proxy.forwarded_headers.mode,
    None,
  );
  apply_header_mutations(&mut parts.headers, &request_waf.request_header_mutations);
  if websocket_framed_bridge {
    remove_websocket_extensions(&mut parts.headers);
  }
  if let Some(authority) = resolved
    .route
    .actions
    .rewrite
    .as_ref()
    .and_then(|rewrite| rewrite.authority.as_deref())
  {
    set_effective_host_header(&mut parts.headers, authority);
  }
  early_data::apply_verified_upstream_header(&mut parts.headers, verified_early_data);
  state
    .telemetry
    .inject_trace_context(&mut parts.headers, trace_context);
  let outbound = Request::from_parts(parts, body);
  let outbound = outbound.map(|body| {
    body::with_backpressure_send_timeout(
      body,
      timeouts.upstream_send,
      BodyTimeoutKind::UpstreamRequestSend,
    )
  });
  let Some(client) =
    state
      .clients
      .for_upstream_version(&upstream.name, upstream.origin.scheme(), HttpVersion::H1)
  else {
    return Some(route_security.text(StatusCode::BAD_GATEWAY, "upstream client is not configured"));
  };
  let upstream_started_at = Instant::now();
  let mut upstream_response =
    match tokio::time::timeout(timeouts.upstream_first_byte, client.request(outbound)).await {
      Ok(Ok(response)) => {
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        response
      }
      Ok(Err(error)) => {
        state.pools.report_failure_async(&upstream.name).await;
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        access_log.record_upstream_error("connect_error", &error.to_string());
        return Some(route_security.text(
          StatusCode::BAD_GATEWAY,
          &format!("upstream upgrade request failed: {error}"),
        ));
      }
      Err(_) => {
        state.pools.report_failure_async(&upstream.name).await;
        access_log.upstream_first_byte_time_ms = Some(elapsed_ms(upstream_started_at));
        access_log.record_upstream_error("read_timeout", "upstream upgrade request timed out");
        return Some(route_security.text(
          StatusCode::BAD_GATEWAY,
          "upstream upgrade request timed out",
        ));
      }
    };

  if upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS {
    let response = upstream_response.map(|body| body.map_err(boxed_error).boxed());
    return Some(route_security.apply(response));
  }
  if websocket_framed_bridge {
    remove_websocket_extensions(upstream_response.headers_mut());
  }
  let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
  let pool_report = state.pools.clone();
  let upstream_name = upstream.name.clone();
  let route_name = resolved.route.name.clone();
  let stream_waf_state = state.clone();
  let websocket_metrics_state = state.clone();
  let websocket_started_at = TelemetryRuntime::start();
  if websocket_upgrade {
    state.metrics.record_websocket_session_start(
      &state.config.metrics,
      &route_name,
      &upstream_name,
    );
  }
  let websocket_stream_waf = if websocket_upgrade { stream_waf } else { None };
  let bandwidth = resolved.bandwidth.clone();
  let connection_limit_hold =
    TunnelConnectionLimitHold::capture(request_connection_permit, connection_limit_context);
  let websocket_guard = websocket_upgrade.then(|| {
    state
      .runtime_introspection
      .guard(RuntimeCounter::WebSocketTunnel)
  });
  tokio::spawn(async move {
    let _websocket_guard = websocket_guard;
    let _connection_limit_hold = connection_limit_hold;
    let result = async {
      let downstream = downstream_upgrade.await?;
      let upstream = upstream_upgrade.await?;
      if websocket_framed_bridge {
        crate::proxy::stream_waf::bridge_websocket(
          TokioIo::new(downstream),
          TokioIo::new(upstream),
          stream_waf_state,
          websocket_stream_waf,
          Some(bandwidth),
          timeouts.websocket_idle,
          drain,
        )
        .await?;
      } else {
        let traffic_class = if websocket_upgrade {
          crate::metrics::BandwidthTrafficClass::WebSocket
        } else {
          crate::metrics::BandwidthTrafficClass::Tunnel
        };
        let protocol = if websocket_upgrade {
          TunnelProtocol::WebSocket
        } else {
          TunnelProtocol::Opaque
        };
        copy_bidirectional_with_idle_and_bandwidth(
          TokioIo::new(downstream),
          TokioIo::new(upstream),
          timeouts.websocket_idle,
          drain,
          Some(bandwidth),
          Some(websocket_metrics_state.metrics.clone()),
          traffic_class,
          protocol,
        )
        .await?;
      }
      Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    if result.is_ok() {
      pool_report.report_success_async(&upstream_name).await;
    } else {
      pool_report.report_failure_async(&upstream_name).await;
    }
    if websocket_upgrade {
      record_websocket_session_end(
        &websocket_metrics_state,
        &route_name,
        &upstream_name,
        trace_context,
        websocket_started_at,
        if result.is_ok() { "closed" } else { "error" },
      );
    }
  });
  drop(pool_selection);
  let mut response = upstream_response.map(|body| body.map_err(boxed_error).boxed());
  apply_sticky_cookie(&mut response, sticky_cookie.as_ref());
  Some(response)
}

pub(super) fn is_websocket_upgrade<B>(request: &Request<B>) -> bool {
  request
    .headers()
    .get_all(http::header::UPGRADE)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .any(|value| value.trim().eq_ignore_ascii_case("websocket"))
}

fn remove_websocket_extensions(headers: &mut HeaderMap) {
  headers.remove("sec-websocket-extensions");
}

#[cfg(test)]
#[path = "tunnel/bandwidth_tests.rs"]
mod bandwidth_tests;
