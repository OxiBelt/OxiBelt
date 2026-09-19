//! Independent RFC 9842 origin and downstream codec oracle.
//!
//! This intentionally does not call OxiBelt's codec implementation.  It
//! checks the wire prelude and uses Brotli's raw-dictionary and Zstandard's
//! reference-prefix APIs directly, so an implementation error cannot be
//! hidden by sharing a decoder with the proxy.

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context};
use base64::Engine as _;
use bytes::{Buf, Bytes};
use h3_quinn::quinn::crypto::rustls::QuicServerConfig;
use h3_quinn::quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use http::header::{
  HeaderName, HeaderValue, ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, ETAG, VARY,
};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use zstd::stream::raw::Operation;

const DCB_MAGIC: [u8; 4] = [0xff, 0x44, 0x43, 0x42];
const DCZ_MAGIC: [u8; 8] = [0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00];
const ORIGIN_BODY: &str = "RFC 9842 dictionary coding integration payload";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Protocol {
  H1,
  H2,
  H3,
}

impl Protocol {
  pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
    match value {
      "h1" => Ok(Self::H1),
      "h2" => Ok(Self::H2),
      "h3" => Ok(Self::H3),
      _ => bail!("dictionary probe protocol must be h1, h2, or h3"),
    }
  }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Coding {
  Dcb,
  Dcz,
}

impl Coding {
  pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
    match value {
      "dcb" => Ok(Self::Dcb),
      "dcz" => Ok(Self::Dcz),
      _ => bail!("dictionary coding must be dcb or dcz"),
    }
  }

  pub(crate) const fn name(self) -> &'static str {
    match self {
      Self::Dcb => "dcb",
      Self::Dcz => "dcz",
    }
  }

  const fn magic(self) -> &'static [u8] {
    match self {
      Self::Dcb => &DCB_MAGIC,
      Self::Dcz => &DCZ_MAGIC,
    }
  }
}

struct OriginArgs {
  protocol: Protocol,
  listen: SocketAddr,
  cert: String,
  key: String,
  dictionary: Vec<u8>,
  coding: Coding,
}

struct ClientArgs {
  protocol: Protocol,
  host: String,
  port: u16,
  server_name: String,
  authority: String,
  path: String,
  ca_cert: String,
  dictionary: Vec<u8>,
  expected_body: String,
  expected_coding: Option<Coding>,
  missing_dictionary: bool,
  private_request: bool,
  request_coding: Option<Coding>,
  request_body: Option<String>,
  expected_origin_count: Option<u64>,
}

pub(crate) async fn serve_origin(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
  let args = parse_origin_args(args)?;
  let origin = Arc::new(Origin {
    dictionary: Arc::from(args.dictionary),
    coding: args.coding,
    counts: Mutex::new(HashMap::new()),
  });
  match args.protocol {
    Protocol::H1 => serve_h1(args.listen, &args.cert, &args.key, origin).await,
    Protocol::H2 => serve_h2(args.listen, &args.cert, &args.key, origin).await,
    Protocol::H3 => serve_h3(args.listen, &args.cert, &args.key, origin).await,
  }
}

pub(crate) async fn client(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
  let args = parse_client_args(args)?;
  let mut headers = HeaderMap::new();
  if !args.missing_dictionary {
    headers.insert(
      HeaderName::from_static("available-dictionary"),
      HeaderValue::from_str(&available_dictionary(&args.dictionary))
        .context("build Available-Dictionary request header")?,
    );
    headers.insert(
      ACCEPT_ENCODING,
      HeaderValue::from_static(match args.expected_coding.unwrap_or(Coding::Dcb) {
        Coding::Dcb => "dcb, dcz;q=0.5, identity",
        Coding::Dcz => "dcz, dcb;q=0.5, identity",
      }),
    );
  } else {
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
  }
  if args.private_request {
    headers.insert(
      HeaderName::from_static("cookie"),
      HeaderValue::from_static("session=private"),
    );
    headers.insert(
      HeaderName::from_static("authorization"),
      HeaderValue::from_static("Bearer dictionary-private-test"),
    );
  }
  if args.request_coding.is_some() {
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
  }
  let response = request(&args, headers).await?;
  assert_response(&args, &response)?;
  println!("dictionary-rfc9842-ok");
  Ok(())
}

fn parse_origin_args(mut values: impl Iterator<Item = String>) -> anyhow::Result<OriginArgs> {
  let mut protocol = None;
  let mut listen = None;
  let mut cert = None;
  let mut key = None;
  let mut dictionary = None;
  let mut coding = None;
  while let Some(flag) = values.next() {
    let value = values
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--protocol" => protocol = Some(Protocol::parse(&value)?),
      "--listen" => listen = Some(value.parse().context("invalid --listen")?),
      "--cert" => cert = Some(value),
      "--key" => key = Some(value),
      "--dictionary" => dictionary = Some(read_dictionary(&value)?),
      "--coding" => coding = Some(Coding::parse(&value)?),
      _ => bail!("unknown dictionary-origin option: {flag}"),
    }
  }
  Ok(OriginArgs {
    protocol: protocol.ok_or_else(|| anyhow!("--protocol is required"))?,
    listen: listen.ok_or_else(|| anyhow!("--listen is required"))?,
    cert: cert.ok_or_else(|| anyhow!("--cert is required"))?,
    key: key.ok_or_else(|| anyhow!("--key is required"))?,
    dictionary: dictionary.ok_or_else(|| anyhow!("--dictionary is required"))?,
    coding: coding.ok_or_else(|| anyhow!("--coding is required"))?,
  })
}

fn parse_client_args(mut values: impl Iterator<Item = String>) -> anyhow::Result<ClientArgs> {
  let mut protocol = None;
  let mut host = None;
  let mut port = None;
  let mut server_name = None;
  let mut authority = None;
  let mut path = None;
  let mut ca_cert = None;
  let mut dictionary = None;
  let mut expected_body = None;
  let mut expected_coding = None;
  let mut expect_plain = false;
  let mut missing_dictionary = false;
  let mut private_request = false;
  let mut expected_origin_count = None;
  let mut request_coding = None;
  let mut request_body = None;
  while let Some(flag) = values.next() {
    match flag.as_str() {
      "--missing-dictionary" => {
        missing_dictionary = true;
        continue;
      }
      "--private-request" => {
        private_request = true;
        continue;
      }
      "--expect-plain" => {
        expect_plain = true;
        continue;
      }
      _ => {}
    }
    let value = values
      .next()
      .ok_or_else(|| anyhow!("missing value for {flag}"))?;
    match flag.as_str() {
      "--protocol" => protocol = Some(Protocol::parse(&value)?),
      "--host" => host = Some(value),
      "--port" => port = Some(value.parse().context("invalid --port")?),
      "--server-name" => server_name = Some(value),
      "--authority" => authority = Some(value),
      "--path" => path = Some(value),
      "--ca-cert" => ca_cert = Some(value),
      "--dictionary" => dictionary = Some(read_dictionary(&value)?),
      "--expect-body" => expected_body = Some(value),
      "--expect-coding" => expected_coding = Some(Coding::parse(&value)?),
      "--expect-origin-count" => {
        expected_origin_count = Some(value.parse().context("invalid --expect-origin-count")?)
      }
      "--request-coding" => request_coding = Some(Coding::parse(&value)?),
      "--request-body" => request_body = Some(value),
      _ => bail!("unknown dictionary-client option: {flag}"),
    }
  }
  if expect_plain && expected_coding.is_some() {
    bail!("--expect-plain and --expect-coding are mutually exclusive");
  }
  if request_coding.is_some() != request_body.is_some() {
    bail!("--request-coding and --request-body must be supplied together");
  }
  Ok(ClientArgs {
    protocol: protocol.ok_or_else(|| anyhow!("--protocol is required"))?,
    host: host.ok_or_else(|| anyhow!("--host is required"))?,
    port: port.ok_or_else(|| anyhow!("--port is required"))?,
    server_name: server_name.ok_or_else(|| anyhow!("--server-name is required"))?,
    authority: authority.ok_or_else(|| anyhow!("--authority is required"))?,
    path: path.ok_or_else(|| anyhow!("--path is required"))?,
    ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
    dictionary: dictionary.ok_or_else(|| anyhow!("--dictionary is required"))?,
    expected_body: expected_body.ok_or_else(|| anyhow!("--expect-body is required"))?,
    expected_coding: if expect_plain { None } else { expected_coding },
    missing_dictionary,
    private_request,
    request_coding,
    request_body,
    expected_origin_count,
  })
}

fn read_dictionary(path: &str) -> anyhow::Result<Vec<u8>> {
  let bytes = std::fs::read(path).with_context(|| format!("read dictionary {path}"))?;
  if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 - 16 {
    bail!("dictionary must be within 1..=16777200 bytes");
  }
  Ok(bytes)
}

struct Origin {
  dictionary: Arc<[u8]>,
  coding: Coding,
  counts: Mutex<HashMap<String, u64>>,
}

impl Origin {
  fn response(&self, request: &Request<()>, request_body: &[u8]) -> Response<Full<Bytes>> {
    if request.uri().path().ends_with("/request-decode") {
      if request.method() != Method::POST
        || request.headers().contains_key(CONTENT_ENCODING)
        || request.headers().contains_key("available-dictionary")
        || request
          .headers()
          .get("x-waf-dictionary-decoded")
          .and_then(|value| value.to_str().ok())
          != Some("yes")
        || request_body != b"inbound dictionary payload"
      {
        return text(
          StatusCode::BAD_REQUEST,
          "dictionary request was not decoded before the WAF and origin",
        );
      }
      return plain_response(
        "request decode ok",
        self.next_count(request.uri().path()),
        false,
      );
    }
    if request.uri().path().ends_with("/private") {
      if request.headers().contains_key("available-dictionary")
        || request.headers().contains_key("cookie")
        || request.headers().contains_key("authorization")
      {
        return text(
          StatusCode::BAD_REQUEST,
          "private request forwarded credentials or a dictionary assertion",
        );
      }
      return plain_response(ORIGIN_BODY, self.next_count(request.uri().path()), false);
    }
    if !request_has_negotiation(request.headers(), self.dictionary.as_ref(), self.coding) {
      return text(
        StatusCode::BAD_REQUEST,
        "missing or invalid RFC 9842 upstream negotiation",
      );
    }
    let count = self.next_count(request.uri().path());
    if request.uri().path() == "/revalidate"
      && request
        .headers()
        .get("if-none-match")
        .and_then(|value| value.to_str().ok())
        == Some("\"dictionary-v1\"")
    {
      let mut response = Response::new(Full::new(Bytes::new()));
      *response.status_mut() = StatusCode::NOT_MODIFIED;
      response
        .headers_mut()
        .insert(ETAG, HeaderValue::from_static("\"dictionary-v1\""));
      response.headers_mut().insert(
        VARY,
        HeaderValue::from_static("available-dictionary, accept-encoding"),
      );
      response.headers_mut().insert(
        HeaderName::from_static("x-dictionary-origin-count"),
        HeaderValue::from_str(&count.to_string()).expect("count is valid"),
      );
      return response;
    }
    let encoded = match encode(
      self.coding,
      self.dictionary.as_ref(),
      ORIGIN_BODY.as_bytes(),
    ) {
      Ok(value) => value,
      Err(error) => {
        return text(
          StatusCode::INTERNAL_SERVER_ERROR,
          &format!("dictionary encoding failed: {error}"),
        )
      }
    };
    let mut response = Response::new(Full::new(Bytes::from(encoded)));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
      CONTENT_ENCODING,
      HeaderValue::from_static(self.coding.name()),
    );
    headers.insert(
      CACHE_CONTROL,
      HeaderValue::from_static(if request.uri().path() == "/revalidate" {
        "public, max-age=0"
      } else {
        "public, max-age=60"
      }),
    );
    headers.insert(ETAG, HeaderValue::from_static("\"dictionary-v1\""));
    headers.insert(
      VARY,
      HeaderValue::from_static("available-dictionary, accept-encoding"),
    );
    headers.insert(
      HeaderName::from_static("x-dictionary-origin-count"),
      HeaderValue::from_str(&count.to_string()).expect("count is valid"),
    );
    headers.insert(
      HeaderName::from_static("content-type"),
      HeaderValue::from_static("text/plain"),
    );
    response
  }

  fn next_count(&self, path: &str) -> u64 {
    let mut counts = self
      .counts
      .lock()
      .expect("dictionary origin count lock poisoned");
    let count = counts.entry(path.to_owned()).or_default();
    *count += 1;
    *count
  }
}

fn plain_response(body: &str, count: u64, revalidate: bool) -> Response<Full<Bytes>> {
  let mut response = Response::new(Full::new(Bytes::copy_from_slice(body.as_bytes())));
  *response.status_mut() = StatusCode::OK;
  let headers = response.headers_mut();
  headers.insert(
    CACHE_CONTROL,
    HeaderValue::from_static(if revalidate {
      "public, max-age=0"
    } else {
      "public, max-age=60"
    }),
  );
  headers.insert(ETAG, HeaderValue::from_static("\"dictionary-v1\""));
  headers.insert(
    HeaderName::from_static("x-dictionary-origin-count"),
    HeaderValue::from_str(&count.to_string()).expect("count is valid"),
  );
  response
}

async fn serve_h1(
  listen: SocketAddr,
  cert: &str,
  key: &str,
  origin: Arc<Origin>,
) -> anyhow::Result<()> {
  let mut config = super::upstream_tls_server_config(cert, key, None, false)?;
  config.alpn_protocols = vec![b"http/1.1".to_vec()];
  let acceptor = TlsAcceptor::from(Arc::new(config));
  let listener = TcpListener::bind(listen)
    .await
    .context("bind dictionary H1 origin")?;
  loop {
    let (stream, _) = listener
      .accept()
      .await
      .context("accept dictionary H1 connection")?;
    let acceptor = acceptor.clone();
    let origin = origin.clone();
    tokio::spawn(async move {
      let result = async {
        let tls = acceptor
          .accept(stream)
          .await
          .context("accept dictionary H1 TLS")?;
        hyper::server::conn::http1::Builder::new()
          .serve_connection(
            TokioIo::new(tls),
            service_fn(move |request: Request<Incoming>| {
              let origin = origin.clone();
              async move {
                let (parts, body) = request.into_parts();
                let body = body
                  .collect()
                  .await
                  .map(|value| value.to_bytes())
                  .unwrap_or_default();
                Ok::<_, std::convert::Infallible>(
                  origin.response(&Request::from_parts(parts, ()), &body),
                )
              }
            }),
          )
          .await
          .context("serve dictionary H1")
      }
      .await;
      if let Err(error) = result {
        eprintln!("dictionary H1 origin connection failed: {error:#}");
      }
    });
  }
}

async fn serve_h2(
  listen: SocketAddr,
  cert: &str,
  key: &str,
  origin: Arc<Origin>,
) -> anyhow::Result<()> {
  let mut config = super::upstream_tls_server_config(cert, key, None, false)?;
  config.alpn_protocols = vec![b"h2".to_vec()];
  let acceptor = TlsAcceptor::from(Arc::new(config));
  let listener = TcpListener::bind(listen)
    .await
    .context("bind dictionary H2 origin")?;
  loop {
    let (stream, _) = listener
      .accept()
      .await
      .context("accept dictionary H2 connection")?;
    let acceptor = acceptor.clone();
    let origin = origin.clone();
    tokio::spawn(async move {
      let result = async {
        let tls = acceptor
          .accept(stream)
          .await
          .context("accept dictionary H2 TLS")?;
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
          .serve_connection(
            TokioIo::new(tls),
            service_fn(move |request: Request<Incoming>| {
              let origin = origin.clone();
              async move {
                let (parts, body) = request.into_parts();
                let body = body
                  .collect()
                  .await
                  .map(|value| value.to_bytes())
                  .unwrap_or_default();
                Ok::<_, std::convert::Infallible>(
                  origin.response(&Request::from_parts(parts, ()), &body),
                )
              }
            }),
          )
          .await
          .context("serve dictionary H2")
      }
      .await;
      if let Err(error) = result {
        eprintln!("dictionary H2 origin connection failed: {error:#}");
      }
    });
  }
}

async fn serve_h3(
  listen: SocketAddr,
  cert: &str,
  key: &str,
  origin: Arc<Origin>,
) -> anyhow::Result<()> {
  let mut tls = super::upstream_tls_server_config(cert, key, None, true)?;
  tls.alpn_protocols = vec![b"h3".to_vec()];
  let crypto = QuicServerConfig::try_from(tls).context("build dictionary H3 TLS")?;
  let endpoint = Endpoint::server(QuinnServerConfig::with_crypto(Arc::new(crypto)), listen)
    .context("bind dictionary H3 origin")?;
  loop {
    let Some(incoming) = endpoint.accept().await else {
      return Ok(());
    };
    let origin = origin.clone();
    tokio::spawn(async move {
      let result = async {
        let connection = incoming.await.context("accept dictionary H3 connection")?;
        let mut connection = h3::server::builder()
          .build(h3_quinn::Connection::new(connection))
          .await
          .context("build dictionary H3 connection")?;
        while let Some(resolver) = connection
          .accept()
          .await
          .context("accept dictionary H3 request")?
        {
          let (request, mut stream) = resolver
            .resolve_request()
            .await
            .context("resolve dictionary H3 request")?;
          let mut request_body = Vec::new();
          while let Some(mut chunk) = stream
            .recv_data()
            .await
            .context("read dictionary H3 request body")?
          {
            let length = chunk.remaining();
            request_body.extend_from_slice(&chunk.copy_to_bytes(length));
          }
          let response = origin.response(&request, &request_body);
          let (parts, body) = response.into_parts();
          let body = body
            .collect()
            .await
            .context("collect dictionary H3 body")?
            .to_bytes();
          stream
            .send_response(Response::from_parts(parts, ()))
            .await
            .context("send dictionary H3 response")?;
          if !body.is_empty() {
            stream
              .send_data(body)
              .await
              .context("send dictionary H3 body")?;
          }
          stream
            .finish()
            .await
            .context("finish dictionary H3 response")?;
        }
        Ok::<_, anyhow::Error>(())
      }
      .await;
      if let Err(error) = result {
        eprintln!("dictionary H3 origin connection failed: {error:#}");
      }
    });
  }
}

async fn request(args: &ClientArgs, headers: HeaderMap) -> anyhow::Result<serde_json::Value> {
  let (method, body, headers) = if let Some(coding) = args.request_coding {
    let body = encode(
      coding,
      &args.dictionary,
      args
        .request_body
        .as_deref()
        .expect("validated request body")
        .as_bytes(),
    )?;
    let mut headers = headers;
    headers.insert(CONTENT_ENCODING, HeaderValue::from_static(coding.name()));
    (Method::POST, body, headers)
  } else {
    (Method::GET, Vec::new(), headers)
  };
  let request = super::DownstreamArgs {
    protocol: match args.protocol {
      Protocol::H1 => super::DownstreamProtocol::H1,
      Protocol::H2 => super::DownstreamProtocol::H2,
      Protocol::H3 => super::DownstreamProtocol::H3,
    },
    host: args.host.clone(),
    port: args.port,
    authority: args.authority.clone(),
    server_name: args.server_name.clone(),
    path: args.path.clone(),
    method,
    body,
    body_bytes: None,
    body_chunk_size: 16 * 1024,
    zero_length_body_end_delay_ms: None,
    omit_content_length: false,
    h2_eager_body: false,
    h3_reset_after_body_prefix: false,
    headers,
    ca_cert: args.ca_cert.clone(),
    client_identity: None,
    tls_version: None,
    quic_initial_alpn_padding_bytes: 0,
    expect_status: Some(200),
  };
  match args.protocol {
    Protocol::H1 => super::h1_downstream_request(&request).await,
    Protocol::H2 => super::h2_downstream_request(&request).await,
    Protocol::H3 => super::h3_downstream_request(&request).await,
  }
}

fn assert_response(args: &ClientArgs, response: &serde_json::Value) -> anyhow::Result<()> {
  if response["status"].as_u64() != Some(200) {
    bail!("dictionary response status was not 200: {response}");
  }
  let headers = response["headers"]
    .as_object()
    .ok_or_else(|| anyhow!("dictionary response has no headers"))?;
  if let Some(expected) = args.expected_origin_count {
    let actual = headers
      .get("x-dictionary-origin-count")
      .and_then(|value| value.as_str())
      .and_then(|value| value.parse::<u64>().ok());
    if actual != Some(expected) {
      bail!("origin count was {actual:?}, expected {expected}");
    }
  }
  let body = base64::engine::general_purpose::STANDARD
    .decode(
      response["body_base64"]
        .as_str()
        .ok_or_else(|| anyhow!("dictionary response body is absent"))?,
    )
    .context("decode response body base64")?;
  let decoded = match args.expected_coding {
    Some(coding) => {
      if headers
        .get("content-encoding")
        .and_then(|value| value.as_str())
        != Some(coding.name())
      {
        bail!(
          "downstream response did not use expected {} coding; status={:?} headers={headers:?}",
          coding.name(),
          response["status"]
        );
      }
      decode(coding, &args.dictionary, &body)?
    }
    None => {
      if headers.contains_key("content-encoding") {
        bail!("unknown downstream dictionary must not select a content coding");
      }
      body
    }
  };
  if decoded != args.expected_body.as_bytes() {
    bail!("decoded dictionary response body did not match expected payload");
  }
  Ok(())
}

fn available_dictionary(dictionary: &[u8]) -> String {
  format!(
    ":{}:",
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(dictionary))
  )
}

fn request_has_negotiation(headers: &HeaderMap, dictionary: &[u8], coding: Coding) -> bool {
  headers
    .get("available-dictionary")
    .and_then(|value| value.to_str().ok())
    == Some(available_dictionary(dictionary).as_str())
    && headers
      .get(ACCEPT_ENCODING)
      .and_then(|value| value.to_str().ok())
      .is_some_and(|value| {
        value
          .split(',')
          .any(|item| item.trim().eq_ignore_ascii_case(coding.name()))
      })
}

pub(crate) fn encode_frame(coding: Coding, dictionary: &[u8], input: &[u8]) -> io::Result<Vec<u8>> {
  let mut output = coding.magic().to_vec();
  output.extend_from_slice(&Sha256::digest(dictionary));
  match coding {
    Coding::Dcb => {
      let mut params = brotli::enc::backward_references::BrotliEncoderParams::default();
      params.quality = 9;
      params.lgwin = 24;
      let mut input = io::Cursor::new(input);
      let mut buffer_in = [0_u8; 16 * 1024];
      let mut buffer_out = [0_u8; 16 * 1024];
      let mut reader = brotli::IoReaderWrapper(&mut input);
      let mut writer = brotli::IoWriterWrapper(&mut output);
      brotli::BrotliCompressCustomIoCustomDict(
        &mut reader,
        &mut writer,
        &mut buffer_in,
        &mut buffer_out,
        &params,
        brotli::enc::StandardAlloc::default(),
        &mut |_, _, _, _| {},
        dictionary,
        io::Error::new(
          io::ErrorKind::UnexpectedEof,
          "Brotli input ended unexpectedly",
        ),
      )?;
    }
    Coding::Dcz => {
      let mut encoder = zstd::stream::write::Encoder::with_ref_prefix(&mut output, 9, dictionary)?;
      encoder.write_all(input)?;
      let _ = encoder.finish()?;
    }
  }
  Ok(output)
}

fn encode(coding: Coding, dictionary: &[u8], input: &[u8]) -> io::Result<Vec<u8>> {
  encode_frame(coding, dictionary, input)
}

fn decode(coding: Coding, dictionary: &[u8], input: &[u8]) -> anyhow::Result<Vec<u8>> {
  let prelude = coding.magic().len() + 32;
  if input.len() < prelude
    || &input[..coding.magic().len()] != coding.magic()
    || &input[coding.magic().len()..prelude] != Sha256::digest(dictionary).as_slice()
  {
    bail!("RFC 9842 prelude did not bind the expected SHA-256 dictionary");
  }
  let encoded = &input[prelude..];
  match coding {
    Coding::Dcb => decode_brotli(dictionary, encoded),
    Coding::Dcz => decode_zstd(dictionary, encoded),
  }
}

fn decode_brotli(dictionary: &[u8], encoded: &[u8]) -> anyhow::Result<Vec<u8>> {
  use brotli::{Allocator, BrotliDecompressStream, BrotliResult, BrotliState, SliceWrapperMut};
  let mut allocator = brotli::enc::StandardAlloc::default();
  let mut owned = allocator.alloc_cell(dictionary.len());
  owned.slice_mut().copy_from_slice(dictionary);
  let mut state = BrotliState::new_strict(
    brotli::enc::StandardAlloc::default(),
    brotli::enc::StandardAlloc::default(),
    brotli::enc::StandardAlloc::default(),
  );
  if !state.attach_dictionary(owned) {
    bail!("Brotli raw dictionary attachment failed");
  }
  let mut input_offset = 0;
  let mut available_in = encoded.len();
  let mut output = Vec::new();
  loop {
    let mut chunk = [0_u8; 16 * 1024];
    let mut available_out = chunk.len();
    let mut output_offset = 0;
    let mut total_out = 0;
    match BrotliDecompressStream(
      &mut available_in,
      &mut input_offset,
      encoded,
      &mut available_out,
      &mut output_offset,
      &mut chunk,
      &mut total_out,
      &mut state,
    ) {
      BrotliResult::ResultSuccess => {
        output.extend_from_slice(&chunk[..output_offset]);
        if available_in != 0 || input_offset != encoded.len() {
          bail!("trailing bytes after RFC 9842 dcb frame");
        }
        return Ok(output);
      }
      BrotliResult::NeedsMoreInput => bail!("truncated RFC 9842 dcb frame"),
      BrotliResult::NeedsMoreOutput => output.extend_from_slice(&chunk[..output_offset]),
      BrotliResult::ResultFailure => bail!("invalid RFC 9842 dcb frame"),
    }
  }
}

fn decode_zstd(dictionary: &[u8], encoded: &[u8]) -> anyhow::Result<Vec<u8>> {
  let mut decoder = zstd::stream::raw::Decoder::with_ref_prefix(dictionary)?;
  let mut offset = 0;
  let mut output = Vec::new();
  let mut complete = false;
  while offset < encoded.len() {
    let mut chunk = [0_u8; 16 * 1024];
    let status = decoder.run_on_buffers(&encoded[offset..], &mut chunk)?;
    offset += status.bytes_read;
    output.extend_from_slice(&chunk[..status.bytes_written]);
    if status.remaining == 0 {
      complete = true;
    }
    if status.bytes_read == 0 && status.bytes_written == 0 {
      bail!("RFC 9842 dcz decoder made no progress");
    }
  }
  if !complete {
    bail!("truncated RFC 9842 dcz frame");
  }
  Ok(output)
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
  let mut response = Response::new(Full::new(Bytes::copy_from_slice(body.as_bytes())));
  *response.status_mut() = status;
  response
}

#[cfg(test)]
mod tests {
  use super::{decode, encode, Coding};

  #[test]
  fn raw_dictionary_codecs_bind_and_decode_their_preludes() {
    let dictionary = b"dictionary fixture repeated dictionary fixture repeated";
    let payload = b"dictionary fixture repeated dictionary fixture repeated payload";
    for coding in [Coding::Dcb, Coding::Dcz] {
      let encoded = encode(coding, dictionary, payload).expect("encode raw dictionary frame");
      assert_eq!(
        decode(coding, dictionary, &encoded).expect("decode raw dictionary frame"),
        payload
      );
      assert!(decode(coding, b"another raw dictionary", &encoded).is_err());
    }
  }
}
