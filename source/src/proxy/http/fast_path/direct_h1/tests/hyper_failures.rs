use super::*;

/// Disabling reconnect must keep a reused-connection failure terminal even
/// when the request body could otherwise be reconstructed for a retry.
#[tokio::test]
async fn reused_connection_failure_does_not_replay_when_reconnect_is_disabled() -> anyhow::Result<()>
{
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let origin = format!("http://{}", listener.local_addr()?);
  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await?;
    let first = read_request_head(&mut stream).await?;
    anyhow::ensure!(first.starts_with(b"GET /prime HTTP/1.1\r\n"));
    stream
      .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
      .await?;
    let second = read_request_head(&mut stream).await?;
    anyhow::ensure!(second.starts_with(b"GET /dispatched HTTP/1.1\r\n"));
    drop(stream);
    // An implicit reconnect would establish a second TCP connection here.
    match tokio::time::timeout(Duration::from_millis(150), listener.accept()).await {
      Err(_) => Ok(()),
      Ok(result) => anyhow::bail!("dispatched request was replayed: {result:?}"),
    }
  });

  let mut upstream = upstream(&origin);
  upstream.connect_timeout_ms = 1_000;
  let pool = Arc::new(DirectH1Pool::new(&upstream).expect("loopback origin should be eligible"));
  let metrics = Metrics::new();
  let client = async {
    send_and_recycle_direct_get(
      pool.clone(),
      &metrics,
      "/prime",
      direct_h1_test_timeouts(),
      false,
    )
    .await?;
    assert_eq!(pool.idle_count.load(Ordering::Acquire), 1);
    let request = Request::builder().uri("/dispatched").body(empty_body())?;
    let prepared = PreparedDirectH1Request::from_request(request, &pool.origin)?;
    let result = send_prepared_request(
      pool.clone(),
      &metrics,
      FastPathMetricProtocol::H1,
      prepared,
      direct_h1_test_timeouts(),
      false,
      None,
      DirectH1SendMetricOptions {
        hot_path_metrics: true,
        diagnostic_metrics: false,
        timing_enabled: false,
      },
    )
    .await;
    let error = match result {
      Err(error) => error,
      Ok(_) => anyhow::bail!("upstream EOF must fail when reconnect is disabled"),
    };
    assert!(error.downcast_ref::<hyper::Error>().is_some());
    assert_eq!(pool.idle_count.load(Ordering::Acquire), 0);
    Ok::<_, anyhow::Error>(())
  };
  let (client, server) = tokio::join!(client, server);
  client?;
  server??;
  Ok(())
}

#[tokio::test]
async fn malformed_hyper_response_head_discards_connection() -> anyhow::Result<()> {
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let origin = format!("http://{}", listener.local_addr()?);
  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await?;
    read_request_head(&mut stream).await?;
    stream
      .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok")
      .await?;
    Ok::<_, anyhow::Error>(())
  });
  let pool = Arc::new(DirectH1Pool::new(&upstream(&origin)).expect("loopback origin is eligible"));
  let metrics = Metrics::new();
  let result = send_and_recycle_direct_get(
    pool.clone(),
    &metrics,
    "/ambiguous-response",
    direct_h1_test_timeouts(),
    false,
  )
  .await;
  assert!(result.is_err(), "conflicting response framing must fail");
  assert_eq!(pool.idle_count.load(Ordering::Acquire), 0);
  server.await??;
  Ok(())
}

#[tokio::test]
async fn direct_h1_records_only_tokio_hyper_backend() -> anyhow::Result<()> {
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let origin = format!("http://{}", listener.local_addr()?);
  let accepted_connections = Arc::new(AtomicUsize::new(0));
  let server = tokio::spawn(serve_keepalive_listener(
    listener,
    accepted_connections.clone(),
  ));
  let pool = Arc::new(DirectH1Pool::new(&upstream(&origin)).expect("loopback origin is eligible"));
  let metrics = Metrics::new();
  for protocol in [
    FastPathMetricProtocol::H1,
    FastPathMetricProtocol::H2,
    FastPathMetricProtocol::H3,
  ] {
    let request = Request::builder().uri("/backend").body(empty_body())?;
    let prepared = PreparedDirectH1Request::from_request(request, &pool.origin)?;
    let mut direct = send_prepared_request(
      pool.clone(),
      &metrics,
      protocol,
      prepared,
      direct_h1_test_timeouts(),
      true,
      None,
      DirectH1SendMetricOptions {
        hot_path_metrics: true,
        diagnostic_metrics: true,
        timing_enabled: false,
      },
    )
    .await?;
    let lease = direct
      .take_lease()
      .expect("Hyper response should retain its lease");
    direct
      .response
      .into_body()
      .collect()
      .await
      .map_err(|error| anyhow::anyhow!("{error}"))?;
    lease.recycle_if_reusable(true);
  }
  let body = metrics_prometheus(&metrics);
  for protocol in ["h1", "h2", "h3"] {
    assert!(body.contains(&format!(
      "oxibelt_http_direct_h1_io_backend_total{{backend=\"tokio_hyper\",protocol=\"{protocol}\",outcome=\"selected\"}} 1"
    )));
  }
  assert_eq!(accepted_connections.load(Ordering::SeqCst), 1);
  server.abort();
  Ok(())
}

async fn read_request_head(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
  tokio::time::timeout(Duration::from_secs(2), async {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
      anyhow::ensure!(head.len() < 16 * 1024, "test request head exceeded bound");
      head.push(stream.read_u8().await?);
    }
    Ok(head)
  })
  .await?
}

#[tokio::test]
async fn reused_connection_failure_preserves_enabled_single_reconnect() -> anyhow::Result<()> {
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let origin = format!("http://{}", listener.local_addr()?);
  let server = tokio::spawn(async move {
    let (mut stream, _) = listener.accept().await?;
    read_request_head(&mut stream).await?;
    stream
      .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
      .await?;
    let failed = read_request_head(&mut stream).await?;
    anyhow::ensure!(failed.starts_with(b"GET /retry HTTP/1.1\r\n"));
    drop(stream);
    let (mut replacement, _) =
      tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
    let retried = read_request_head(&mut replacement).await?;
    anyhow::ensure!(
      retried == failed,
      "reconnect must preserve the empty request"
    );
    replacement
      .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
      .await?;
    Ok::<_, anyhow::Error>(())
  });
  let pool = Arc::new(DirectH1Pool::new(&upstream(&origin)).expect("loopback origin is eligible"));
  let metrics = Metrics::new();
  for path in ["/prime", "/retry"] {
    send_and_recycle_direct_get(
      pool.clone(),
      &metrics,
      path,
      direct_h1_test_timeouts(),
      false,
    )
    .await?;
  }
  server.await??;
  Ok(())
}
