use super::*;

#[test]
fn typed_transport_errors_drive_direct_h1_miss_classification() {
  let connect_error = DirectH1TransportError::connect(anyhow::anyhow!("synthetic connect failure"));
  assert_eq!(
    direct_h1_transport_miss_reason(&connect_error),
    FastPathTransportMissReason::ConnectError
  );

  let send_error = DirectH1TransportError::send(anyhow::anyhow!("synthetic send failure"));
  assert_eq!(
    direct_h1_transport_miss_reason(&send_error),
    FastPathTransportMissReason::SendError
  );

  let protocol_error =
    DirectH1TransportError::response_protocol(anyhow::anyhow!("invalid response framing"));
  assert_eq!(
    direct_h1_transport_miss_reason(&protocol_error),
    FastPathTransportMissReason::ResponseError
  );
  assert_eq!(
    direct_h1_upstream_error_kind(&protocol_error),
    Some(DirectH1UpstreamErrorKind::Protocol)
  );

  let timeout_error = DirectH1TransportError::read_timeout(anyhow::anyhow!("idle timeout"));
  assert_eq!(
    direct_h1_transport_miss_reason(&timeout_error),
    FastPathTransportMissReason::ResponseError
  );
  assert_eq!(
    direct_h1_upstream_error_kind(&timeout_error),
    Some(DirectH1UpstreamErrorKind::ReadTimeout)
  );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn compio_connect_backoff_routes_h2_to_hyper_direct_h1() -> anyhow::Result<()> {
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let origin = format!("http://{}", listener.local_addr()?);
  let accepted_connections = Arc::new(AtomicUsize::new(0));
  let server = tokio::spawn(serve_keepalive_listener(
    listener,
    accepted_connections.clone(),
  ));

  let mut upstream = upstream(&origin);
  upstream.connect_timeout_ms = 1_000;
  upstream.first_byte_timeout_ms = 1_000;
  let pool = Arc::new(DirectH1Pool::new(&upstream).expect("loopback origin should be eligible"));
  pool.note_compio_connect_error();
  let metrics = Metrics::new();
  let request = Request::builder()
    .method(Method::GET)
    .version(http::Version::HTTP_2)
    .uri("/compio-backoff")
    .body(empty_body())
    .expect("test request should be valid");
  let prepared = PreparedDirectH1Request::from_request(request, &pool.origin)?;

  let mut response = send_prepared_request(
    pool,
    &metrics,
    FastPathMetricProtocol::H2,
    prepared,
    direct_h1_test_timeouts(),
    DirectH1RuntimeBackend::Compio,
    true,
    None,
    crate::config::EarlyHintsMode::Drop,
    DirectH1SendMetricOptions {
      hot_path_metrics: true,
      diagnostic_metrics: true,
      timing_enabled: false,
    },
  )
  .await?;
  let lease = response
    .take_lease()
    .expect("Hyper direct-H1 fallback should retain a recyclable lease");
  response
    .response
    .into_body()
    .collect()
    .await
    .map_err(|error| anyhow::anyhow!("{error}"))?;
  lease.recycle_if_reusable(true);

  let body = metrics_prometheus(&metrics);
  assert!(
    body.contains(
      "oxibelt_http_direct_h1_io_backend_total{backend=\"compio\",protocol=\"h2\",outcome=\"fallback\"} 1"
    ),
    "Compio backoff should record fallback evidence:\n{body}"
  );
  assert!(
    body.contains(
      "oxibelt_http_direct_h1_io_backend_total{backend=\"tokio_hyper\",protocol=\"h2\",outcome=\"selected\"} 1"
    ),
    "Hyper fallback should record selected evidence:\n{body}"
  );
  assert_eq!(
    accepted_connections.load(Ordering::SeqCst),
    1,
    "fallback should use one Hyper direct-H1 upstream connection"
  );
  server.abort();
  Ok(())
}
