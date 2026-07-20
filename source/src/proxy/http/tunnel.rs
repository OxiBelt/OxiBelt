//! CONNECT, upgrade, WebSocket, and idle-aware bidirectional tunneling.

use super::*;

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
  if let Some(pool_name) = selected.pool_name() {
    access_log.set_upstream_pool(pool_name);
  }
  let sticky_cookie = selected.sticky_cookie();
  let pool_report = state.pools.clone();
  let pool_selection = selected.into_pool_selection();
  if request_version == http::Version::HTTP_11 || request_version == http::Version::HTTP_10 {
    let downstream_upgrade = hyper::upgrade::on(&mut request);
    let connection_limit_hold =
      TunnelConnectionLimitHold::capture(request_connection_permit, connection_limit_context);
    tokio::spawn(async move {
      let _connection_limit_hold = connection_limit_hold;
      let result = async {
        let downstream = downstream_upgrade.await?;
        let downstream = TokioIo::new(downstream);
        let upstream_stream = dial_tunnel_upstream(&upstream, client_addr, timeouts).await?;
        copy_bidirectional_with_idle(downstream, upstream_stream, timeouts.websocket_idle, drain)
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

  match dial_tunnel_upstream(&upstream, client_addr, timeouts).await {
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
pub(super) fn bridge_connect_body(
  mut downstream_body: ProxyBody,
  upstream: TcpStream,
  timeouts: EffectiveTimeouts,
  mut drain: ConnectionDrain,
) -> ProxyBody {
  let (body_sender, body) = body::channel_body(16);
  let (mut upstream_reader, mut upstream_writer) = upstream.into_split();
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
          let send_result =
            tokio::time::timeout(timeouts.response_send, body_sender.send(frame)).await;
          if !matches!(send_result, Ok(Ok(()))) {
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

pub(super) async fn copy_bidirectional_with_idle<D, U>(
  downstream: D,
  upstream: U,
  idle_timeout: Duration,
  mut drain: ConnectionDrain,
) -> anyhow::Result<()>
where
  D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
  U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
  let (downstream_read, downstream_write) = tokio::io::split(downstream);
  let (upstream_read, upstream_write) = tokio::io::split(upstream);
  let (activity_tx, mut activity_rx) = mpsc::channel(16);
  let mut downstream_to_upstream = tokio::spawn(copy_one_way_with_activity(
    downstream_read,
    upstream_write,
    activity_tx.clone(),
  ));
  let mut upstream_to_downstream = tokio::spawn(copy_one_way_with_activity(
    upstream_read,
    downstream_write,
    activity_tx,
  ));
  let idle = tokio::time::sleep(idle_timeout);
  tokio::pin!(idle);
  let drain_close = drain.close_delay_elapsed();
  tokio::pin!(drain_close);

  loop {
    tokio::select! {
      result = &mut downstream_to_upstream => {
        upstream_to_downstream.abort();
        return result.context("upgrade copy task panicked")?;
      }
      result = &mut upstream_to_downstream => {
        downstream_to_upstream.abort();
        return result.context("upgrade copy task panicked")?;
      }
      activity = activity_rx.recv() => {
        if activity.is_none() {
          return Ok(());
        }
        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
      }
      _ = &mut idle => {
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

pub(super) async fn copy_one_way_with_activity<R, W>(
  mut reader: R,
  mut writer: W,
  activity: mpsc::Sender<()>,
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
    writer.write_all(&buffer[..read]).await?;
    let _ = activity.try_send(());
  }
}

pub(super) async fn dial_tunnel_upstream(
  upstream: &UpstreamConfig,
  client_addr: std::net::SocketAddr,
  timeouts: EffectiveTimeouts,
) -> anyhow::Result<TcpStream> {
  let remote_addr = resolve_upstream_tcp_addr(&upstream.origin).await?;
  let mut stream = tokio::time::timeout(timeouts.upstream_connect, TcpStream::connect(remote_addr))
    .await
    .context("upstream tunnel connect timed out")??;
  crate::tcp_socket::enable_tcp_nodelay(&stream, remote_addr, "upstream tunnel");
  crate::proxy_protocol_egress::write_header(
    &mut stream,
    upstream.proxy_protocol_egress,
    client_addr,
    remote_addr,
  )
  .await
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
      if let Some(stream_waf) = websocket_stream_waf {
        crate::proxy::stream_waf::bridge_websocket(
          TokioIo::new(downstream),
          TokioIo::new(upstream),
          stream_waf_state,
          stream_waf,
          timeouts.websocket_idle,
          drain,
        )
        .await?;
      } else {
        copy_bidirectional_with_idle(
          TokioIo::new(downstream),
          TokioIo::new(upstream),
          timeouts.websocket_idle,
          drain,
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
    .get(http::header::UPGRADE)
    .and_then(|value| value.to_str().ok())
    .map(|value| value.eq_ignore_ascii_case("websocket"))
    .unwrap_or(false)
}
