//! Bounded raw HTTP/2 WebTransport draft-15 oracle.
//! It deliberately avoids Hyper and h2 so it remains an independent wire check.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use http::header::{HeaderName, HeaderValue};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod admin;
mod scenarios;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_FRAME: usize = 64 * 1024;
const MAX_HEADER_BLOCK: usize = 64 * 1024;
const MAX_CAPSULE: usize = 1024 * 1024;
const SESSION_CREDIT: u32 = 1024 * 1024;
const STREAM_CREDIT: u32 = 64 * 1024;
const STREAM_COUNT: u32 = 8;

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;
const ACK: u8 = 0x1;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;

const ENABLE_CONNECT: u16 = 8;
const WT_ENABLED: u16 = 0x2b60;
const WT_INITIAL_MAX_DATA: u16 = 0x2b61;
const WT_INITIAL_MAX_STREAM_DATA_UNI: u16 = 0x2b62;
const WT_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u16 = 0x2b63;
const WT_INITIAL_MAX_STREAMS_UNI: u16 = 0x2b64;
const WT_INITIAL_MAX_STREAMS_BIDI: u16 = 0x2b65;
const WT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u16 = 0x2b66;

const WT_RESET_STREAM: u64 = 0x190b4d39;
const WT_STOP_SENDING: u64 = 0x190b4d3a;
const WT_STREAM_FIN: u64 = 0x190b4d3b;
const WT_STREAM: u64 = 0x190b4d3c;
const WT_MAX_DATA: u64 = 0x190b4d3d;
const WT_MAX_STREAM_DATA: u64 = 0x190b4d3e;
const WT_MAX_STREAMS_BIDI: u64 = 0x190b4d3f;
const WT_MAX_STREAMS_UNI: u64 = 0x190b4d40;
const WT_DATA_BLOCKED: u64 = 0x190b4d41;
const WT_STREAM_DATA_BLOCKED: u64 = 0x190b4d42;
const WT_STREAMS_BLOCKED_BIDI: u64 = 0x190b4d43;
const WT_STREAMS_BLOCKED_UNI: u64 = 0x190b4d44;
const WT_DATAGRAM: u64 = 0;
const WT_CLOSE_SESSION: u64 = 0x2843;
const WT_DRAIN_SESSION: u64 = 0x78ae;

const BIDI_PAYLOAD: &[u8] = b"h2-webtransport-bidi-echo";
const UNI_PAYLOAD: &[u8] = b"h2-webtransport-uni-echo";
const DATAGRAM_PAYLOAD: &[u8] = b"h2-webtransport-datagram-echo";
const RESET_PREFIX: &[u8] = b"h2-reset-prefix";
const RESET_CODE: u64 = 0x1020_3040;
const STOP_CODE: u64 = 0x5060_7080;

#[derive(Default)]
struct ClientArgs {
  host: Option<String>,
  port: Option<u16>,
  server_name: Option<String>,
  authority: Option<String>,
  path: Option<String>,
  ca_cert: Option<String>,
  headers: Vec<(HeaderName, HeaderValue)>,
  tls_version: Option<super::DownstreamTlsVersion>,
  scenario: String,
  expect_status: u16,
  reset_prefix_required: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerCredit {
  session_data: u64,
  uni_stream_2_data: u64,
  bidi_stream_0_data: u64,
  bidi_stream_4_data: u64,
  uni_streams: u64,
  bidi_streams: u64,
}

impl PeerCredit {
  fn permits_stream_open(self) -> bool {
    self.uni_streams >= 1 && self.bidi_streams >= 3
  }

  fn permits_echo(self) -> bool {
    self.session_data >= (BIDI_PAYLOAD.len() + UNI_PAYLOAD.len() + RESET_PREFIX.len()) as u64
      && self.uni_stream_2_data >= UNI_PAYLOAD.len() as u64
      && self.bidi_stream_0_data >= BIDI_PAYLOAD.len() as u64
      && self.bidi_stream_4_data >= RESET_PREFIX.len() as u64
      && self.permits_stream_open()
  }
}

pub(crate) async fn client(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
  let args = parse_client_args(args)?;
  let host = required(args.host, "--host")?;
  let port = required(args.port, "--port")?;
  let server_name = required(args.server_name, "--server-name")?;
  let authority = required(args.authority, "--authority")?;
  let path = required(args.path, "--path")?;
  let ca_cert = required(args.ca_cert, "--ca-cert")?;
  if args.scenario == "tls12-setting-suppression"
    && args.tls_version != Some(super::DownstreamTlsVersion::Tls12)
  {
    bail!("tls12-setting-suppression requires --tls-version tls1.2");
  }
  let config = super::downstream_client_config(Path::new(&ca_cert), b"h2", args.tls_version)?;
  let tls_name = ServerName::try_from(server_name).map_err(|_| anyhow!("invalid server name"))?;
  let tcp = tokio::time::timeout(TIMEOUT, TcpStream::connect((host.as_str(), port)))
    .await
    .context("timed out connecting H2 WebTransport probe")??;
  let mut io = tokio::time::timeout(
    TIMEOUT,
    TlsConnector::from(Arc::new(config)).connect(tls_name, tcp),
  )
  .await
  .context("timed out negotiating H2 WebTransport TLS")??;
  if io.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
    bail!("H2 WebTransport probe did not negotiate h2");
  }

  io.write_all(PREFACE).await?;
  let client_settings = if args.scenario == "tls12-setting-suppression" {
    enable_connect_settings()
  } else {
    settings_for_scenario(&args.scenario)
  };
  write_frame(&mut io, SETTINGS, 0, 0, &client_settings).await?;
  let deadline = tokio::time::Instant::now() + TIMEOUT;
  if args.scenario == "tls12-setting-suppression" {
    return scenarios::tls12_setting_suppression(&mut io, deadline).await;
  }
  let peer_credit = wait_for_server_settings(&mut io, deadline).await?;
  write_frame(
    &mut io,
    HEADERS,
    END_HEADERS,
    1,
    &request_headers(&authority, &path, &args.headers)?,
  )
  .await?;
  if args.scenario == "silent-close" {
    return scenarios::silent_close(&mut io, deadline).await;
  }
  let status = wait_for_response(&mut io, deadline).await?;
  if status != args.expect_status {
    bail!(
      "H2 WebTransport status was {status}, expected {}",
      args.expect_status
    );
  }
  if status != 200 {
    println!("{{\"status\":{status}}}");
    return Ok(());
  }
  let reset_echo_bytes = match args.scenario.as_str() {
    "echo" => run_client_echo(&mut io, deadline, peer_credit, args.reset_prefix_required).await?,
    "admin-events" => {
      return admin::events(
        &mut io,
        deadline,
        super::event_stream::requested_coding(
          args.headers.iter().map(|(name, value)| (name, value)),
        ),
      )
      .await;
    }
    scenario => return scenarios::run(scenario, &mut io, deadline, peer_credit).await,
  };
  println!(
    "{}",
    serde_json::json!({
      "status": status,
      "bidi_echo_bytes": BIDI_PAYLOAD.len(),
      "uni_echo_bytes": UNI_PAYLOAD.len(),
      "datagram_echo_bytes": DATAGRAM_PAYLOAD.len(),
      "reset_code": RESET_CODE,
      "reset_echo_bytes": reset_echo_bytes,
      "mapped_reset_prefix_bytes": usize::from(reset_echo_bytes > 0),
      "pre_header_reset_survived": true,
      "stop_code": STOP_CODE,
    })
  );
  Ok(())
}

fn parse_client_args(mut args: impl Iterator<Item = String>) -> anyhow::Result<ClientArgs> {
  let mut parsed = ClientArgs {
    scenario: "echo".into(),
    expect_status: 200,
    reset_prefix_required: true,
    ..Default::default()
  };
  while let Some(flag) = args.next() {
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--host" => parsed.host = Some(value),
      "--port" => parsed.port = Some(value.parse().context("invalid --port")?),
      "--server-name" => parsed.server_name = Some(value),
      "--authority" => parsed.authority = Some(value),
      "--path" => parsed.path = Some(value),
      "--ca-cert" => parsed.ca_cert = Some(value),
      "--scenario" => parsed.scenario = value,
      "--expect-status" => {
        parsed.expect_status = value.parse().context("invalid --expect-status")?
      }
      "--header" => parsed.headers.push(parse_header(&value)?),
      "--event-coding" => {
        let coding = match value.as_str() {
          "br" => super::event_stream::EventStreamCoding::Br,
          "zstd" => super::event_stream::EventStreamCoding::Zstd,
          "gzip" => super::event_stream::EventStreamCoding::Gzip,
          "deflate" => super::event_stream::EventStreamCoding::Deflate,
          _ => bail!("--event-coding must be br, zstd, gzip, or deflate"),
        };
        let value = coding
          .request_value()
          .expect("compressed coding has a header value");
        parsed.headers.push((
          HeaderName::from_static("oxibelt-event-stream"),
          HeaderValue::from_static(value),
        ));
      }
      "--tls-version" => parsed.tls_version = Some(super::DownstreamTlsVersion::parse(&value)?),
      "--reset-prefix" => parsed.reset_prefix_required = parse_reset_prefix(&value)?,
      _ => bail!("unknown webtransport-h2-client flag: {flag}"),
    }
  }
  Ok(parsed)
}

fn parse_reset_prefix(value: &str) -> anyhow::Result<bool> {
  match value {
    "required" => Ok(true),
    "optional" => Ok(false),
    _ => bail!("--reset-prefix must be required or optional"),
  }
}

fn parse_header(value: &str) -> anyhow::Result<(HeaderName, HeaderValue)> {
  let (name, value) = value
    .split_once(':')
    .ok_or_else(|| anyhow!("--header must use name:value"))?;
  let name = HeaderName::from_bytes(name.trim().as_bytes()).context("invalid --header name")?;
  let value = HeaderValue::from_str(value.trim()).context("invalid --header value")?;
  Ok((name, value))
}

fn required<T>(value: Option<T>, name: &'static str) -> anyhow::Result<T> {
  value.ok_or_else(|| anyhow!("missing required {name}"))
}

pub(crate) async fn upstream(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
  let (mut listen, mut cert, mut key, mut name): (
    Option<SocketAddr>,
    Option<String>,
    Option<String>,
    Option<String>,
  ) = (None, None, None, None);
  let mut reset_prefix_required = true;
  let mut close_before_connect = false;
  while let Some(flag) = args.next() {
    if flag == "--close-before-connect" {
      close_before_connect = true;
      continue;
    }
    let value = args
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--listen" => listen = Some(value.parse().context("invalid --listen")?),
      "--cert" => cert = Some(value),
      "--key" => key = Some(value),
      "--name" => name = Some(value),
      "--reset-prefix" => reset_prefix_required = parse_reset_prefix(&value)?,
      _ => bail!("unknown webtransport-h2-upstream flag: {flag}"),
    }
  }
  let mut config = super::upstream_tls_server_config(
    &required(cert, "--cert")?,
    &required(key, "--key")?,
    None,
    false,
  )?;
  config.alpn_protocols = vec![b"h2".to_vec()];
  let listener = TcpListener::bind(required(listen, "--listen")?).await?;
  let acceptor = TlsAcceptor::from(Arc::new(config));
  let name = required(name, "--name")?;
  loop {
    let (tcp, peer) = listener.accept().await?;
    let acceptor = acceptor.clone();
    let name = name.clone();
    tokio::spawn(async move {
      let result = match tokio::time::timeout(TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(mut io)) => {
          serve_connection(&mut io, reset_prefix_required, close_before_connect).await
        }
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(anyhow!("timed out negotiating H2 WebTransport TLS")),
      };
      if let Err(error) = result {
        eprintln!("{name} H2 WebTransport session from {peer} failed: {error:#}");
      }
    });
  }
}

async fn serve_connection<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  reset_prefix_required: bool,
  close_before_connect: bool,
) -> anyhow::Result<()> {
  let deadline = tokio::time::Instant::now() + TIMEOUT;
  let mut preface = [0; PREFACE.len()];
  read_exact_at(io, &mut preface, deadline).await?;
  if preface != PREFACE {
    bail!("missing HTTP/2 client preface");
  }
  // The failure fixture completes the HTTP/2 SETTINGS exchange without
  // advertising WebTransport, then closes before the CONNECT request. This
  // reproduces a peer that cleanly disappears while the client waits for the
  // WebTransport capability receipt.
  let server_settings = if close_before_connect {
    Vec::new()
  } else {
    settings()
  };
  write_frame(io, SETTINGS, 0, 0, &server_settings).await?;
  let mut saw_settings = false;
  let mut saw_server_settings_ack = false;
  let mut header_block = Vec::new();
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
        saw_settings = true;
      }
      SETTINGS => {
        validate_settings_ack(&frame)?;
        saw_server_settings_ack = true;
      }
      HEADERS if close_before_connect => {
        bail!("CONNECT arrived before closed upstream fixture terminated");
      }
      HEADERS if frame.stream_id == 1 => {
        append_header_fragment(&mut header_block, header_fragment(&frame)?)?;
        if frame.flags & END_HEADERS == 0 {
          read_continuations(io, deadline, 1, &mut header_block).await?;
        }
        break;
      }
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      WINDOW_UPDATE => validate_window_update(&frame)?,
      GOAWAY => bail!("peer sent GOAWAY before CONNECT"),
      _ => {}
    }
    if close_before_connect && saw_settings && saw_server_settings_ack {
      // The client ACK above completes both sides' initial SETTINGS exchange.
      // Returning drops the TLS stream before any extended CONNECT HEADERS.
      return Ok(());
    }
  }
  if !saw_settings {
    bail!("CONNECT arrived before client SETTINGS");
  }
  validate_hpack_block(&header_block)?;
  write_frame(io, HEADERS, END_HEADERS, 1, &response_headers()).await?;
  send_credit(io).await?;
  serve_capsules(io, deadline, reset_prefix_required).await
}

async fn run_client_echo<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
  peer_credit: PeerCredit,
  reset_prefix_required: bool,
) -> anyhow::Result<usize> {
  let mut decoder = prepare_client_streams(io, deadline, peer_credit).await?;
  let mut wire = stream_capsule(0, &BIDI_PAYLOAD[..8], false)?;
  wire.extend(stream_capsule(0, &BIDI_PAYLOAD[8..], true)?);
  wire.extend(stream_capsule(2, UNI_PAYLOAD, true)?);
  wire.extend(stream_capsule(4, RESET_PREFIX, false)?);
  write_data(io, &wire, false).await?;

  let (mut bidi, mut uni, mut reset_echo) = (Vec::new(), Vec::new(), Vec::new());
  let (mut bidi_fin, mut uni_fin, mut datagram, mut stop_seen) = (false, false, false, false);
  let mut reset_sent = false;
  while !(bidi_fin && uni_fin && datagram && stop_seen) {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      DATA if frame.stream_id == 1 => {
        let payload = data_payload(&frame)?;
        decoder.push(payload)?;
        while let Some(event) = decoder.next()? {
          match event {
            CapsuleEvent::Stream { id: 0, data, fin } => {
              append_bounded(&mut bidi, &data, STREAM_CREDIT as usize)?;
              bidi_fin |= fin;
            }
            CapsuleEvent::Stream { id: 3, data, fin } => {
              append_bounded(&mut uni, &data, STREAM_CREDIT as usize)?;
              uni_fin |= fin;
            }
            CapsuleEvent::Stream { id: 1, .. } => {}
            CapsuleEvent::Stream { id: 8, data, .. } if data.is_empty() => {}
            CapsuleEvent::Stream { id: 4, data, .. } => {
              append_bounded(&mut reset_echo, &data, STREAM_CREDIT as usize)?;
              if !reset_echo.is_empty() && !reset_sent {
                let mut controls =
                  control_capsule(WT_RESET_STREAM, &[4, RESET_CODE, RESET_PREFIX.len() as u64])?;
                // This next stream is reset before any application bytes. If
                // an H3 association header is still unacknowledged, QUIC may
                // discard the stream; the following datagram proves the
                // session and connection remain usable either way.
                controls.extend(stream_capsule(8, &[], false)?);
                controls.extend(control_capsule(WT_RESET_STREAM, &[8, RESET_CODE, 0])?);
                controls.extend(capsule(WT_DATAGRAM, DATAGRAM_PAYLOAD)?);
                write_data(io, &controls, false).await?;
                reset_sent = true;
              }
            }
            CapsuleEvent::Stream { id, .. } => bail!("unexpected peer stream {id}"),
            CapsuleEvent::Control {
              kind: WT_STOP_SENDING,
              values,
            } if values == [1, STOP_CODE] => {
              stop_seen = true;
              write_data(
                io,
                &control_capsule(WT_RESET_STREAM, &[1, STOP_CODE, 0])?,
                false,
              )
              .await?;
            }
            CapsuleEvent::Control { .. } => {}
            CapsuleEvent::Datagram(data) if data == DATAGRAM_PAYLOAD => datagram = true,
            CapsuleEvent::Datagram(_) => {}
            CapsuleEvent::Close { code, reason } => bail!("peer closed session ({code}): {reason}"),
            CapsuleEvent::Drain => {}
          }
        }
        acknowledge_data(io, 1, payload.len()).await?;
        if frame.flags & END_STREAM != 0 {
          bail!("peer ended CONNECT before echo completed");
        }
      }
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      RST_STREAM if frame.stream_id == 1 => bail!("WebTransport CONNECT was reset"),
      GOAWAY => bail!("peer sent GOAWAY during echo"),
      WINDOW_UPDATE => validate_window_update(&frame)?,
      _ => {}
    }
  }
  if bidi != BIDI_PAYLOAD {
    bail!("bidirectional echo changed payload");
  }
  if uni != UNI_PAYLOAD {
    bail!("unidirectional echo changed payload");
  }
  if reset_echo.is_empty() {
    bail!("reset stream was not established before RESET_STREAM");
  }
  if reset_prefix_required && reset_echo != RESET_PREFIX {
    bail!(
      "reset stream preserved {} bytes, expected all {} reliable bytes",
      reset_echo.len(),
      RESET_PREFIX.len()
    );
  }
  if !reset_prefix_required && !RESET_PREFIX.starts_with(&reset_echo) {
    bail!(
      "reset stream returned {} bytes that were not a valid prefix",
      reset_echo.len()
    );
  }
  write_data(io, &close_capsule(0, b"probe complete")?, true).await?;
  wait_for_connect_end(io, tokio::time::Instant::now() + Duration::from_secs(2)).await?;
  Ok(reset_echo.len())
}

async fn wait_for_connect_end<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      DATA if frame.stream_id == 1 && frame.flags & END_STREAM != 0 => return Ok(()),
      DATA if frame.stream_id == 1 => acknowledge_data(io, 1, data_payload(&frame)?.len()).await?,
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      RST_STREAM if frame.stream_id == 1 => bail!("peer reset CONNECT while closing session"),
      GOAWAY => return Ok(()),
      WINDOW_UPDATE => validate_window_update(&frame)?,
      _ => {}
    }
  }
}

async fn serve_capsules<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
  reset_prefix_required: bool,
) -> anyhow::Result<()> {
  let mut decoder = CapsuleDecoder::default();
  let mut received: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
  let mut next_server_uni = 3u64;
  let mut sent_stop_probe = false;
  let mut reset_seen = false;
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      DATA if frame.stream_id == 1 => {
        let payload = data_payload(&frame)?;
        decoder.push(payload)?;
        while let Some(event) = decoder.next()? {
          match event {
            CapsuleEvent::Stream { id, data, fin } => {
              let stream = received.entry(id).or_default();
              append_bounded(stream, &data, STREAM_CREDIT as usize)?;
              if id & 3 == 0 {
                write_data(io, &stream_capsule(id, &data, fin)?, false).await?;
              } else if id & 3 == 2 && fin {
                write_data(io, &stream_capsule(next_server_uni, stream, true)?, false).await?;
                next_server_uni = next_server_uni
                  .checked_add(4)
                  .context("stream ID overflow")?;
              } else if id & 1 != 0 {
                bail!("peer sent data on unopened server stream");
              }
            }
            CapsuleEvent::Datagram(data) => {
              write_data(io, &capsule(WT_DATAGRAM, &data)?, false).await?;
              if data == DATAGRAM_PAYLOAD && !sent_stop_probe {
                let mut controls = stream_capsule(1, b"stop-probe", true)?;
                controls.extend(control_capsule(WT_STOP_SENDING, &[1, STOP_CODE])?);
                write_data(io, &controls, false).await?;
                sent_stop_probe = true;
              }
            }
            CapsuleEvent::Control {
              kind: WT_RESET_STREAM,
              values,
            } => {
              let [id, code, reliable] = values.as_slice() else {
                bail!("invalid reset values");
              };
              let actual = received.get(id).map_or(0, |bytes| bytes.len()) as u64;
              if *reliable != actual {
                bail!("reset reliable size {reliable} did not match {actual}");
              }
              if *id == 1 && *code != STOP_CODE {
                bail!("STOP response changed error code");
              }
              if *id == 4 {
                let prefix = received.get(id).map_or(&[][..], Vec::as_slice);
                if *code != RESET_CODE {
                  bail!("reset stream {id} carried code {code:#x}; expected {RESET_CODE:#x}");
                }
                if reset_prefix_required && prefix != RESET_PREFIX {
                  bail!(
                    "reset stream {id} preserved {} bytes; expected all {} reliable bytes",
                    prefix.len(),
                    RESET_PREFIX.len()
                  );
                }
                if !reset_prefix_required && !RESET_PREFIX.starts_with(prefix) {
                  bail!(
                    "reset stream {id} preserved {} bytes that were not a valid prefix",
                    prefix.len()
                  );
                }
              }
              reset_seen |= *id == 4;
            }
            CapsuleEvent::Control {
              kind: WT_STOP_SENDING,
              values,
            } => {
              let [id, code] = values.as_slice() else {
                bail!("invalid stop values");
              };
              let reliable = received.get(id).map_or(0, |bytes| bytes.len()) as u64;
              write_data(
                io,
                &control_capsule(WT_RESET_STREAM, &[*id, *code, reliable])?,
                false,
              )
              .await?;
            }
            CapsuleEvent::Control { .. } => {}
            CapsuleEvent::Close { code, reason } => {
              if code == 0 && reason == "probe complete" && !reset_seen {
                bail!("session closed before the expected reset was delivered");
              }
              write_data(io, &[], true).await?;
              return Ok(());
            }
            CapsuleEvent::Drain => {}
          }
        }
        acknowledge_data(io, 1, payload.len()).await?;
        if frame.flags & END_STREAM != 0 {
          decoder.finish()?;
          write_data(io, &[], true).await?;
          return Ok(());
        }
      }
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      RST_STREAM if frame.stream_id == 1 => return Ok(()),
      GOAWAY => return Ok(()),
      WINDOW_UPDATE => validate_window_update(&frame)?,
      _ => {}
    }
  }
}

async fn wait_for_server_settings<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
) -> anyhow::Result<PeerCredit> {
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      SETTINGS if frame.flags & ACK == 0 => {
        let values = parse_settings(&frame.payload)?;
        if values.get(&ENABLE_CONNECT) != Some(&1) || values.get(&WT_ENABLED) != Some(&1) {
          bail!("server did not advertise extended CONNECT and WebTransport");
        }
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
        return Ok(PeerCredit {
          session_data: u64::from(values.get(&WT_INITIAL_MAX_DATA).copied().unwrap_or(0)),
          uni_stream_2_data: u64::from(
            values
              .get(&WT_INITIAL_MAX_STREAM_DATA_UNI)
              .copied()
              .unwrap_or(0),
          ),
          // The client initiates these streams, so they are "remote" from
          // the server that sent this setting.
          bidi_stream_0_data: u64::from(
            values
              .get(&WT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
              .copied()
              .unwrap_or(0),
          ),
          bidi_stream_4_data: u64::from(
            values
              .get(&WT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE)
              .copied()
              .unwrap_or(0),
          ),
          uni_streams: u64::from(
            values
              .get(&WT_INITIAL_MAX_STREAMS_UNI)
              .copied()
              .unwrap_or(0),
          ),
          bidi_streams: u64::from(
            values
              .get(&WT_INITIAL_MAX_STREAMS_BIDI)
              .copied()
              .unwrap_or(0),
          ),
        });
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      GOAWAY => bail!("server sent GOAWAY before SETTINGS"),
      _ => {}
    }
  }
}

async fn wait_for_peer_credit<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
  decoder: &mut CapsuleDecoder,
  credit: &mut PeerCredit,
  require_data_credit: bool,
) -> anyhow::Result<()> {
  while if require_data_credit {
    !credit.permits_echo()
  } else {
    !credit.permits_stream_open()
  } {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      DATA if frame.stream_id == 1 => {
        let payload = data_payload(&frame)?;
        decoder.push(payload)?;
        while let Some(event) = decoder.next()? {
          match event {
            CapsuleEvent::Control {
              kind: WT_MAX_DATA,
              values,
            } => {
              let [maximum] = values.as_slice() else {
                bail!("invalid WT_MAX_DATA credit capsule");
              };
              credit.session_data = credit.session_data.max(*maximum);
            }
            CapsuleEvent::Control {
              kind: WT_MAX_STREAM_DATA,
              values,
            } => {
              let [stream_id, maximum] = values.as_slice() else {
                bail!("invalid WT_MAX_STREAM_DATA credit capsule");
              };
              match *stream_id {
                0 => credit.bidi_stream_0_data = credit.bidi_stream_0_data.max(*maximum),
                2 => credit.uni_stream_2_data = credit.uni_stream_2_data.max(*maximum),
                4 => credit.bidi_stream_4_data = credit.bidi_stream_4_data.max(*maximum),
                _ if stream_id & 1 != 0 => {
                  bail!("peer granted send credit for a peer-initiated stream")
                }
                _ => {}
              }
            }
            CapsuleEvent::Control {
              kind: WT_MAX_STREAMS_BIDI,
              values,
            } => {
              let [maximum] = values.as_slice() else {
                bail!("invalid WT_MAX_STREAMS_BIDI credit capsule");
              };
              credit.bidi_streams = credit.bidi_streams.max(*maximum);
            }
            CapsuleEvent::Control {
              kind: WT_MAX_STREAMS_UNI,
              values,
            } => {
              let [maximum] = values.as_slice() else {
                bail!("invalid WT_MAX_STREAMS_UNI credit capsule");
              };
              credit.uni_streams = credit.uni_streams.max(*maximum);
            }
            CapsuleEvent::Control { .. } => {}
            CapsuleEvent::Close { code, reason } => {
              bail!("peer closed session before granting credit ({code}): {reason}")
            }
            CapsuleEvent::Drain => {}
            CapsuleEvent::Stream {
              data, fin: false, ..
            } if data.is_empty() => {}
            CapsuleEvent::Stream { .. } | CapsuleEvent::Datagram(_) => {
              bail!("peer sent application data before the client opened a stream")
            }
          }
        }
        acknowledge_data(io, 1, payload.len()).await?;
        if frame.flags & END_STREAM != 0 {
          bail!("peer ended CONNECT before granting flow-control credit");
        }
      }
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      RST_STREAM if frame.stream_id == 1 => {
        bail!("WebTransport CONNECT was reset before granting flow-control credit")
      }
      GOAWAY => bail!("peer sent GOAWAY before granting flow-control credit"),
      WINDOW_UPDATE => validate_window_update(&frame)?,
      _ => {}
    }
  }
  Ok(())
}

async fn prepare_client_streams<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
  mut peer_credit: PeerCredit,
) -> anyhow::Result<CapsuleDecoder> {
  send_credit(io).await?;
  let mut decoder = CapsuleDecoder::default();
  wait_for_peer_credit(io, deadline, &mut decoder, &mut peer_credit, false).await?;
  let mut opens = stream_capsule(0, &[], false)?;
  opens.extend(stream_capsule(2, &[], false)?);
  opens.extend(stream_capsule(4, &[], false)?);
  write_data(io, &opens, false).await?;
  wait_for_peer_credit(io, deadline, &mut decoder, &mut peer_credit, true).await?;
  Ok(decoder)
}

async fn wait_for_response<T: AsyncRead + AsyncWrite + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
) -> anyhow::Result<u16> {
  loop {
    let frame = read_frame_at(io, deadline).await?;
    match frame.kind {
      HEADERS if frame.stream_id == 1 => {
        let mut block = Vec::new();
        append_header_fragment(&mut block, header_fragment(&frame)?)?;
        if frame.flags & END_HEADERS == 0 {
          read_continuations(io, deadline, 1, &mut block).await?;
        }
        return hpack_status(&block)?.ok_or_else(|| anyhow!("response omitted :status"));
      }
      SETTINGS if frame.flags & ACK == 0 => {
        validate_settings(&frame.payload)?;
        write_frame(io, SETTINGS, ACK, 0, &[]).await?;
      }
      SETTINGS => validate_settings_ack(&frame)?,
      PING if frame.flags & ACK == 0 => write_frame(io, PING, ACK, 0, &frame.payload).await?,
      RST_STREAM if frame.stream_id == 1 => bail!("CONNECT reset before response"),
      GOAWAY => bail!("server sent GOAWAY before response"),
      WINDOW_UPDATE => validate_window_update(&frame)?,
      _ => {}
    }
  }
}

fn settings() -> Vec<u8> {
  let mut payload = Vec::new();
  for (id, value) in [
    (ENABLE_CONNECT, 1),
    (WT_ENABLED, 1),
    (WT_INITIAL_MAX_DATA, SESSION_CREDIT),
    (WT_INITIAL_MAX_STREAM_DATA_UNI, STREAM_CREDIT),
    (WT_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, STREAM_CREDIT),
    (WT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, STREAM_CREDIT),
    (WT_INITIAL_MAX_STREAMS_UNI, STREAM_COUNT),
    (WT_INITIAL_MAX_STREAMS_BIDI, STREAM_COUNT),
  ] {
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&value.to_be_bytes());
  }
  payload
}

fn enable_connect_settings() -> Vec<u8> {
  let mut payload = Vec::with_capacity(6);
  payload.extend_from_slice(&ENABLE_CONNECT.to_be_bytes());
  payload.extend_from_slice(&1u32.to_be_bytes());
  payload
}

fn settings_for_scenario(scenario: &str) -> Vec<u8> {
  let mut payload = settings();
  if scenario == "zero-window-reset" {
    payload.extend_from_slice(&SETTINGS_INITIAL_WINDOW_SIZE.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
  }
  payload
}

fn parse_settings(payload: &[u8]) -> anyhow::Result<BTreeMap<u16, u32>> {
  let (chunks, remainder) = payload.as_chunks::<6>();
  if !remainder.is_empty() {
    bail!("SETTINGS length was not a multiple of six");
  }
  let mut result = BTreeMap::new();
  for chunk in chunks {
    let id = u16::from_be_bytes([chunk[0], chunk[1]]);
    let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
    if (id == ENABLE_CONNECT || id == WT_ENABLED) && value > 1 {
      bail!("invalid boolean setting {id:#x}={value}");
    }
    result.insert(id, value);
  }
  Ok(result)
}

fn validate_settings(payload: &[u8]) -> anyhow::Result<()> {
  parse_settings(payload).map(|_| ())
}

fn validate_settings_ack(frame: &H2Frame) -> anyhow::Result<()> {
  if frame.stream_id != 0 || !frame.payload.is_empty() {
    bail!("invalid SETTINGS ACK");
  }
  Ok(())
}

fn request_headers(
  authority: &str,
  path: &str,
  headers: &[(HeaderName, HeaderValue)],
) -> anyhow::Result<Vec<u8>> {
  let mut block = Vec::new();
  for (name, value) in [
    (":method", "CONNECT"),
    (":scheme", "https"),
    (":authority", authority),
    (":path", path),
    (":protocol", "webtransport"),
    ("capsule-protocol", "?1"),
    ("webtransport-init", "u=65536, bl=65536, br=65536"),
  ] {
    literal_header(&mut block, name.as_bytes(), value.as_bytes())?;
  }
  for (name, value) in headers {
    literal_header(&mut block, name.as_str().as_bytes(), value.as_bytes())?;
  }
  Ok(block)
}

fn response_headers() -> Vec<u8> {
  let mut block = vec![0x88];
  literal_header(&mut block, b"capsule-protocol", b"?1").expect("fixed header");
  literal_header(
    &mut block,
    b"webtransport-init",
    b"u=65536, bl=65536, br=65536",
  )
  .expect("fixed header");
  block
}

fn literal_header(out: &mut Vec<u8>, name: &[u8], value: &[u8]) -> anyhow::Result<()> {
  if name.is_empty() || name.len() > 256 || value.len() > 4096 {
    bail!("HPACK literal exceeds oracle limits");
  }
  out.push(0);
  encode_hpack_integer(out, name.len(), 7, 0);
  out.extend_from_slice(name);
  encode_hpack_integer(out, value.len(), 7, 0);
  out.extend_from_slice(value);
  Ok(())
}

fn encode_hpack_integer(out: &mut Vec<u8>, mut value: usize, prefix: u8, high_bits: u8) {
  let mask = (1usize << prefix) - 1;
  if value < mask {
    out.push(high_bits | value as u8);
    return;
  }
  out.push(high_bits | mask as u8);
  value -= mask;
  while value >= 128 {
    out.push((value as u8 & 0x7f) | 0x80);
    value >>= 7;
  }
  out.push(value as u8);
}

fn hpack_status(block: &[u8]) -> anyhow::Result<Option<u16>> {
  let mut input = block;
  let mut status = None;
  while !input.is_empty() {
    let first = input[0];
    if first & 0x80 != 0 {
      let (index, used) = decode_hpack_integer(input, 7)?;
      input = &input[used..];
      status = status.or_else(|| static_status(index));
    } else if first & 0x40 != 0 {
      let (found, rest) = literal_status(input, 6)?;
      status = status.or(found);
      input = rest;
    } else if first & 0x20 != 0 {
      let (_, used) = decode_hpack_integer(input, 5)?;
      input = &input[used..];
    } else {
      let (found, rest) = literal_status(input, 4)?;
      status = status.or(found);
      input = rest;
    }
  }
  Ok(status)
}

fn validate_hpack_block(block: &[u8]) -> anyhow::Result<()> {
  hpack_status(block).map(|_| ())
}

fn literal_status(input: &[u8], prefix: u8) -> anyhow::Result<(Option<u16>, &[u8])> {
  let (name_index, used) = decode_hpack_integer(input, prefix)?;
  let mut rest = &input[used..];
  let mut literal_name = None;
  if name_index == 0 {
    let (name, tail) = decode_hpack_string(rest)?;
    literal_name = Some(name);
    rest = tail;
  }
  let (value, tail) = decode_hpack_string(rest)?;
  let is_status = name_index == 8 || literal_name.as_deref() == Some(b":status".as_slice());
  let status = if is_status {
    let text = std::str::from_utf8(&value).context("HPACK :status was not UTF-8")?;
    Some(text.parse().context("HPACK :status was not numeric")?)
  } else {
    None
  };
  Ok((status, tail))
}

fn static_status(index: usize) -> Option<u16> {
  match index {
    8 => Some(200),
    9 => Some(204),
    10 => Some(206),
    11 => Some(304),
    12 => Some(400),
    13 => Some(404),
    14 => Some(500),
    _ => None,
  }
}

fn decode_hpack_integer(input: &[u8], prefix: u8) -> anyhow::Result<(usize, usize)> {
  let first = *input
    .first()
    .ok_or_else(|| anyhow!("truncated HPACK integer"))?;
  let mask = (1usize << prefix) - 1;
  let mut value = usize::from(first) & mask;
  if value < mask {
    return Ok((value, 1));
  }
  let mut shift = 0u32;
  for (index, byte) in input[1..].iter().copied().enumerate() {
    if shift > 28 {
      bail!("oversized HPACK integer");
    }
    value = value
      .checked_add(usize::from(byte & 0x7f) << shift)
      .context("HPACK integer overflow")?;
    if byte & 0x80 == 0 {
      return Ok((value, index + 2));
    }
    shift += 7;
  }
  bail!("truncated HPACK integer")
}

fn decode_hpack_string(input: &[u8]) -> anyhow::Result<(Vec<u8>, &[u8])> {
  let huffman = input.first().is_some_and(|byte| byte & 0x80 != 0);
  let (length, used) = decode_hpack_integer(input, 7)?;
  if length > 4096 {
    bail!("HPACK string exceeds oracle limit");
  }
  let end = used
    .checked_add(length)
    .context("HPACK string length overflow")?;
  let bytes = input
    .get(used..end)
    .ok_or_else(|| anyhow!("truncated HPACK string"))?;
  // Other Huffman fields need only be skipped structurally. The decimal
  // alphabet is decoded so a literal indexed-name :status remains observable.
  let value = if huffman {
    decode_hpack_huffman_digits(bytes)?
  } else {
    bytes.to_vec()
  };
  Ok((value, &input[end..]))
}

fn decode_hpack_huffman_digits(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
  let codes: [(u32, usize, u8); 10] = [
    (0x00, 5, b'0'),
    (0x01, 5, b'1'),
    (0x02, 5, b'2'),
    (0x19, 6, b'3'),
    (0x1a, 6, b'4'),
    (0x1b, 6, b'5'),
    (0x1c, 6, b'6'),
    (0x1d, 6, b'7'),
    (0x1e, 6, b'8'),
    (0x1f, 6, b'9'),
  ];
  let bit_len = bytes.len() * 8;
  let mut offset = 0usize;
  let mut decoded = Vec::new();
  while bit_len.saturating_sub(offset) >= 5 {
    let remaining = bit_len - offset;
    if remaining <= 7 && read_bits(bytes, offset, remaining) == (1 << remaining) - 1 {
      offset = bit_len;
      break;
    }
    let Some((width, value)) = codes.iter().find_map(|(code, width, value)| {
      (bit_len - offset >= *width && read_bits(bytes, offset, *width) == u64::from(*code))
        .then_some((*width, *value))
    }) else {
      return Ok(Vec::new());
    };
    decoded.push(value);
    offset += width;
  }
  if offset < bit_len && read_bits(bytes, offset, bit_len - offset) != (1 << (bit_len - offset)) - 1
  {
    bail!("invalid HPACK Huffman padding");
  }
  Ok(decoded)
}

fn read_bits(bytes: &[u8], offset: usize, count: usize) -> u64 {
  let mut value = 0u64;
  for bit in offset..offset + count {
    value = (value << 1) | u64::from((bytes[bit / 8] >> (7 - bit % 8)) & 1);
  }
  value
}

#[derive(Debug)]
struct H2Frame {
  kind: u8,
  flags: u8,
  stream_id: u32,
  payload: Vec<u8>,
}

async fn write_frame<T: AsyncWrite + Unpin>(
  io: &mut T,
  kind: u8,
  flags: u8,
  stream_id: u32,
  payload: &[u8],
) -> anyhow::Result<()> {
  if payload.len() > MAX_FRAME {
    bail!("outbound HTTP/2 frame exceeds oracle limit");
  }
  let length = payload.len() as u32;
  let mut header = [0u8; 9];
  header[0] = (length >> 16) as u8;
  header[1] = (length >> 8) as u8;
  header[2] = length as u8;
  header[3] = kind;
  header[4] = flags;
  header[5..].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
  io.write_all(&header).await?;
  io.write_all(payload).await?;
  io.flush().await?;
  Ok(())
}

async fn read_frame_at<T: AsyncRead + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
) -> anyhow::Result<H2Frame> {
  let mut header = [0u8; 9];
  read_exact_at(io, &mut header, deadline).await?;
  let length =
    (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
  if length > MAX_FRAME {
    bail!("inbound HTTP/2 frame exceeds oracle limit");
  }
  let mut payload = vec![0; length];
  read_exact_at(io, &mut payload, deadline).await?;
  Ok(H2Frame {
    kind: header[3],
    flags: header[4],
    stream_id: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff,
    payload,
  })
}

async fn read_exact_at<T: AsyncRead + Unpin>(
  io: &mut T,
  buffer: &mut [u8],
  deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
  tokio::time::timeout_at(deadline, io.read_exact(buffer))
    .await
    .context("timed out reading H2 WebTransport wire")??;
  Ok(())
}

fn header_fragment(frame: &H2Frame) -> anyhow::Result<&[u8]> {
  let mut start = 0usize;
  let mut end = frame.payload.len();
  if frame.flags & PADDED != 0 {
    let padding = usize::from(
      *frame
        .payload
        .first()
        .ok_or_else(|| anyhow!("truncated padding"))?,
    );
    start += 1;
    end = end
      .checked_sub(padding)
      .context("invalid HEADERS padding")?;
  }
  if frame.flags & PRIORITY != 0 {
    start += 5;
  }
  frame
    .payload
    .get(start..end)
    .ok_or_else(|| anyhow!("invalid HEADERS payload"))
}

fn data_payload(frame: &H2Frame) -> anyhow::Result<&[u8]> {
  if frame.flags & PADDED == 0 {
    return Ok(&frame.payload);
  }
  let padding = usize::from(
    *frame
      .payload
      .first()
      .ok_or_else(|| anyhow!("truncated padding"))?,
  );
  let end = frame
    .payload
    .len()
    .checked_sub(padding)
    .context("invalid DATA padding")?;
  frame
    .payload
    .get(1..end)
    .ok_or_else(|| anyhow!("invalid DATA payload"))
}

fn append_header_fragment(block: &mut Vec<u8>, fragment: &[u8]) -> anyhow::Result<()> {
  if block.len().saturating_add(fragment.len()) > MAX_HEADER_BLOCK {
    bail!("HTTP/2 header block exceeds oracle limit");
  }
  block.extend_from_slice(fragment);
  Ok(())
}

async fn read_continuations<T: AsyncRead + Unpin>(
  io: &mut T,
  deadline: tokio::time::Instant,
  stream_id: u32,
  block: &mut Vec<u8>,
) -> anyhow::Result<()> {
  loop {
    let frame = read_frame_at(io, deadline).await?;
    if frame.kind != CONTINUATION || frame.stream_id != stream_id {
      bail!("interleaved or mismatched HTTP/2 CONTINUATION");
    }
    append_header_fragment(block, &frame.payload)?;
    if frame.flags & END_HEADERS != 0 {
      return Ok(());
    }
  }
}

fn validate_window_update(frame: &H2Frame) -> anyhow::Result<()> {
  if frame.payload.len() != 4 {
    bail!("invalid WINDOW_UPDATE length");
  }
  let increment =
    u32::from_be_bytes(frame.payload.as_slice().try_into().expect("checked length")) & 0x7fff_ffff;
  if increment == 0 {
    bail!("zero WINDOW_UPDATE increment");
  }
  Ok(())
}

async fn acknowledge_data<T: AsyncWrite + Unpin>(
  io: &mut T,
  stream_id: u32,
  length: usize,
) -> anyhow::Result<()> {
  let increment = u32::try_from(length).context("DATA length exceeds WINDOW_UPDATE")?;
  if increment == 0 {
    return Ok(());
  }
  write_frame(io, WINDOW_UPDATE, 0, 0, &increment.to_be_bytes()).await?;
  write_frame(io, WINDOW_UPDATE, 0, stream_id, &increment.to_be_bytes()).await
}

async fn write_data<T: AsyncWrite + Unpin>(
  io: &mut T,
  payload: &[u8],
  end_stream: bool,
) -> anyhow::Result<()> {
  let chunks = payload.chunks(16 * 1024);
  let count = chunks.len();
  for (index, chunk) in chunks.enumerate() {
    let flags = if end_stream && index + 1 == count {
      END_STREAM
    } else {
      0
    };
    write_frame(io, DATA, flags, 1, chunk).await?;
  }
  if payload.is_empty() && end_stream {
    write_frame(io, DATA, END_STREAM, 1, &[]).await?;
  }
  Ok(())
}

async fn send_credit<T: AsyncWrite + Unpin>(io: &mut T) -> anyhow::Result<()> {
  let mut wire = control_capsule(WT_MAX_DATA, &[u64::from(SESSION_CREDIT)])?;
  wire.extend(control_capsule(
    WT_MAX_STREAMS_BIDI,
    &[u64::from(STREAM_COUNT)],
  )?);
  wire.extend(control_capsule(
    WT_MAX_STREAMS_UNI,
    &[u64::from(STREAM_COUNT)],
  )?);
  write_data(io, &wire, false).await
}

fn encode_varint(value: u64) -> Vec<u8> {
  if value < (1 << 6) {
    vec![value as u8]
  } else if value < (1 << 14) {
    (value as u16 | 0x4000).to_be_bytes().to_vec()
  } else if value < (1 << 30) {
    (value as u32 | 0x8000_0000).to_be_bytes().to_vec()
  } else {
    (value | 0xc000_0000_0000_0000).to_be_bytes().to_vec()
  }
}

fn decode_varint(input: &[u8]) -> anyhow::Result<Option<(u64, usize)>> {
  let Some(first) = input.first().copied() else {
    return Ok(None);
  };
  let length = 1usize << (first >> 6);
  if input.len() < length {
    return Ok(None);
  }
  let mut value = u64::from(first & 0x3f);
  for byte in &input[1..length] {
    value = (value << 8) | u64::from(*byte);
  }
  Ok(Some((value, length)))
}

fn capsule(kind: u64, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
  if payload.len() > MAX_CAPSULE {
    bail!("outbound capsule exceeds oracle limit");
  }
  let mut wire = encode_varint(kind);
  wire.extend(encode_varint(payload.len() as u64));
  wire.extend_from_slice(payload);
  Ok(wire)
}

fn stream_capsule(id: u64, data: &[u8], fin: bool) -> anyhow::Result<Vec<u8>> {
  let mut payload = encode_varint(id);
  payload.extend_from_slice(data);
  capsule(if fin { WT_STREAM_FIN } else { WT_STREAM }, &payload)
}

fn control_capsule(kind: u64, values: &[u64]) -> anyhow::Result<Vec<u8>> {
  let mut payload = Vec::new();
  for value in values {
    payload.extend(encode_varint(*value));
  }
  capsule(kind, &payload)
}

fn close_capsule(code: u32, reason: &[u8]) -> anyhow::Result<Vec<u8>> {
  if reason.len() > 1024 || std::str::from_utf8(reason).is_err() {
    bail!("invalid WebTransport close reason");
  }
  let mut payload = code.to_be_bytes().to_vec();
  payload.extend_from_slice(reason);
  capsule(WT_CLOSE_SESSION, &payload)
}

#[derive(Debug, Eq, PartialEq)]
enum CapsuleEvent {
  Stream { id: u64, data: Vec<u8>, fin: bool },
  Control { kind: u64, values: Vec<u64> },
  Datagram(Vec<u8>),
  Close { code: u32, reason: String },
  Drain,
}

#[derive(Default)]
struct CapsuleDecoder {
  buffer: Vec<u8>,
}

impl CapsuleDecoder {
  fn push(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
    if self.buffer.len().saturating_add(bytes.len()) > MAX_CAPSULE + 16 {
      bail!("buffered capsule exceeds oracle limit");
    }
    self.buffer.extend_from_slice(bytes);
    Ok(())
  }

  fn next(&mut self) -> anyhow::Result<Option<CapsuleEvent>> {
    let Some((kind, kind_len)) = decode_varint(&self.buffer)? else {
      return Ok(None);
    };
    let Some((length, length_len)) = decode_varint(&self.buffer[kind_len..])? else {
      return Ok(None);
    };
    let length = usize::try_from(length).context("capsule length does not fit usize")?;
    if length > MAX_CAPSULE {
      bail!("inbound capsule exceeds oracle limit");
    }
    let header = kind_len + length_len;
    let end = header
      .checked_add(length)
      .context("capsule length overflow")?;
    if self.buffer.len() < end {
      return Ok(None);
    }
    let payload = self.buffer[header..end].to_vec();
    self.buffer.drain(..end);
    decode_capsule(kind, &payload)
  }

  fn finish(&self) -> anyhow::Result<()> {
    if !self.buffer.is_empty() {
      bail!("truncated capsule at end of CONNECT stream");
    }
    Ok(())
  }
}

fn decode_capsule(kind: u64, payload: &[u8]) -> anyhow::Result<Option<CapsuleEvent>> {
  match kind {
    WT_STREAM | WT_STREAM_FIN => {
      let (id, used) = decode_varint(payload)?.ok_or_else(|| anyhow!("missing stream ID"))?;
      Ok(Some(CapsuleEvent::Stream {
        id,
        data: payload[used..].to_vec(),
        fin: kind == WT_STREAM_FIN,
      }))
    }
    WT_DATAGRAM => Ok(Some(CapsuleEvent::Datagram(payload.to_vec()))),
    WT_CLOSE_SESSION => {
      if !(4..=1028).contains(&payload.len()) {
        bail!("invalid close length");
      }
      let code = u32::from_be_bytes(payload[..4].try_into().expect("checked length"));
      let reason = std::str::from_utf8(&payload[4..])
        .context("invalid close UTF-8")?
        .to_owned();
      Ok(Some(CapsuleEvent::Close { code, reason }))
    }
    WT_DRAIN_SESSION => {
      if !payload.is_empty() {
        bail!("nonempty drain capsule");
      }
      Ok(Some(CapsuleEvent::Drain))
    }
    WT_RESET_STREAM
    | WT_STOP_SENDING
    | WT_MAX_DATA
    | WT_MAX_STREAM_DATA
    | WT_MAX_STREAMS_BIDI
    | WT_MAX_STREAMS_UNI
    | WT_DATA_BLOCKED
    | WT_STREAM_DATA_BLOCKED
    | WT_STREAMS_BLOCKED_BIDI
    | WT_STREAMS_BLOCKED_UNI => {
      let expected = match kind {
        WT_RESET_STREAM => 3,
        WT_STOP_SENDING | WT_MAX_STREAM_DATA | WT_STREAM_DATA_BLOCKED => 2,
        _ => 1,
      };
      let mut values = Vec::with_capacity(expected);
      let mut remaining = payload;
      for _ in 0..expected {
        let (value, used) =
          decode_varint(remaining)?.ok_or_else(|| anyhow!("truncated control capsule"))?;
        values.push(value);
        remaining = &remaining[used..];
      }
      if !remaining.is_empty() {
        bail!("trailing control capsule bytes");
      }
      Ok(Some(CapsuleEvent::Control { kind, values }))
    }
    _ => Ok(None),
  }
}

fn append_bounded(target: &mut Vec<u8>, bytes: &[u8], limit: usize) -> anyhow::Result<()> {
  if target.len().saturating_add(bytes.len()) > limit {
    bail!("stream exceeds oracle limit");
  }
  target.extend_from_slice(bytes);
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn draft_varints_cover_all_widths() {
    for value in [
      0,
      63,
      64,
      16_383,
      16_384,
      (1 << 30) - 1,
      1 << 30,
      (1 << 62) - 1,
    ] {
      let encoded = encode_varint(value);
      assert_eq!(
        decode_varint(&encoded).unwrap(),
        Some((value, encoded.len()))
      );
      for prefix in 0..encoded.len() {
        assert_eq!(decode_varint(&encoded[..prefix]).unwrap(), None);
      }
    }
  }

  #[test]
  fn capsule_decoder_handles_fragmented_stream_and_control() {
    let mut wire = stream_capsule(2, b"fragmented", true).unwrap();
    wire.extend(control_capsule(WT_RESET_STREAM, &[4, RESET_CODE, 7]).unwrap());
    let mut decoder = CapsuleDecoder::default();
    let mut events = Vec::new();
    for byte in wire {
      decoder.push(&[byte]).unwrap();
      while let Some(event) = decoder.next().unwrap() {
        events.push(event);
      }
    }
    decoder.finish().unwrap();
    assert_eq!(
      events,
      [
        CapsuleEvent::Stream {
          id: 2,
          data: b"fragmented".to_vec(),
          fin: true
        },
        CapsuleEvent::Control {
          kind: WT_RESET_STREAM,
          values: vec![4, RESET_CODE, 7]
        },
      ]
    );
  }

  #[test]
  fn capsule_decoder_rejects_oversized_and_truncated_values() {
    let mut oversized = encode_varint(WT_DATAGRAM);
    oversized.extend(encode_varint((MAX_CAPSULE + 1) as u64));
    let mut decoder = CapsuleDecoder::default();
    decoder.push(&oversized).unwrap();
    assert!(decoder.next().is_err());
    let wire = stream_capsule(0, b"data", true).unwrap();
    let mut decoder = CapsuleDecoder::default();
    decoder.push(&wire[..wire.len() - 1]).unwrap();
    assert_eq!(decoder.next().unwrap(), None);
    assert!(decoder.finish().is_err());
  }

  #[test]
  fn hpack_status_handles_indexed_and_literal_values() {
    assert_eq!(hpack_status(&[0x88]).unwrap(), Some(200));
    let mut literal = Vec::new();
    literal_header(&mut literal, b":status", b"429").unwrap();
    assert_eq!(hpack_status(&literal).unwrap(), Some(429));
    assert_eq!(
      hpack_status(&[0x08, 0x83, 0x68, 0x4f, 0xff]).unwrap(),
      Some(429)
    );
  }

  #[test]
  fn settings_include_every_draft_flow_parameter() {
    let parsed = parse_settings(&settings()).unwrap();
    for id in [
      ENABLE_CONNECT,
      WT_ENABLED,
      WT_INITIAL_MAX_DATA,
      WT_INITIAL_MAX_STREAM_DATA_UNI,
      WT_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
      WT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
      WT_INITIAL_MAX_STREAMS_UNI,
      WT_INITIAL_MAX_STREAMS_BIDI,
    ] {
      assert!(parsed.contains_key(&id), "missing setting {id:#x}");
    }
  }

  #[test]
  fn zero_window_reset_blocks_peer_data_without_changing_wt_credit() {
    let parsed = parse_settings(&settings_for_scenario("zero-window-reset")).unwrap();
    assert_eq!(parsed.get(&SETTINGS_INITIAL_WINDOW_SIZE), Some(&0));
    assert_eq!(parsed.get(&WT_INITIAL_MAX_DATA), Some(&SESSION_CREDIT));
    assert_eq!(
      parsed.get(&WT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE),
      Some(&STREAM_CREDIT)
    );
  }

  #[test]
  fn tls12_client_settings_do_not_advertise_webtransport() {
    let parsed = parse_settings(&enable_connect_settings()).unwrap();
    assert_eq!(parsed.get(&ENABLE_CONNECT), Some(&1));
    assert!(!parsed.keys().any(|id| (WT_ENABLED..=0x2b66).contains(id)));
  }

  #[test]
  fn echo_credit_requires_each_opened_stream() {
    let mut credit = PeerCredit {
      session_data: (BIDI_PAYLOAD.len() + UNI_PAYLOAD.len() + RESET_PREFIX.len()) as u64,
      uni_stream_2_data: UNI_PAYLOAD.len() as u64,
      bidi_stream_0_data: BIDI_PAYLOAD.len() as u64,
      bidi_stream_4_data: RESET_PREFIX.len() as u64,
      uni_streams: 1,
      bidi_streams: 2,
    };
    assert!(!credit.permits_stream_open());
    assert!(!credit.permits_echo());
    credit.bidi_streams = 3;
    assert!(credit.permits_stream_open());
    assert!(credit.permits_echo());
    credit.bidi_stream_4_data -= 1;
    assert!(!credit.permits_echo());
  }
}
