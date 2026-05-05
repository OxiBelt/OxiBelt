use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ring::digest;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::LazyConfigAcceptor;
use tracing::{error, info, warn};

use crate::proxy::{http, http3};
use crate::state::AppState;
use crate::tcp_hop;
use crate::waf::WafTlsMetadata;

const TCP_TLS_FINGERPRINT_SCHEME: &str = "rustls-tcp-negotiated-v2";
const QUIC_TLS_FINGERPRINT_SCHEME: &str = "quinn-rustls-quic-v1";

pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
  let (error_tx, mut error_rx) = mpsc::unbounded_channel();

  if state.config.listeners.http1 || state.config.listeners.http2 {
    let tcp_state = state.clone();
    let tcp_errors = error_tx.clone();
    tokio::spawn(async move {
      if let Err(error) = serve_tcp(tcp_state).await {
        let _ = tcp_errors.send(error.context("downstream TCP HTTP listener failed"));
      }
    });
  }

  if state.config.listeners.http3 {
    let h3_state = state.clone();
    let h3_errors = error_tx.clone();
    tokio::spawn(async move {
      if let Err(error) = serve_http3(h3_state).await {
        let _ = h3_errors.send(error.context("downstream HTTP/3 listener failed"));
      }
    });
  }

  drop(error_tx);

  tokio::select! {
      result = tokio::signal::ctrl_c() => {
          result.context("failed to wait for ctrl_c signal")?;
          info!("shutdown signal received");
          Ok(())
      }
      Some(error) = error_rx.recv() => Err(error),
  }
}

async fn serve_tcp(state: Arc<AppState>) -> anyhow::Result<()> {
  let bind = state.config.listeners.https_bind;
  let listener = TcpListener::bind(bind)
    .await
    .with_context(|| format!("failed to bind downstream listener to {bind}"))?;

  info!(bind = %bind, "downstream HTTPS listener started");

  loop {
    tokio::select! {
        biased;
        result = tokio::signal::ctrl_c() => {
            result.context("failed to wait for ctrl_c signal")?;
            info!("shutdown signal received");
            return Ok(());
        }
        accepted = listener.accept() => {
            let (stream, peer_addr) = match accepted {
                Ok(value) => value,
                Err(error) => {
                    warn!(error = %error, "failed to accept downstream connection");
                    continue;
                }
            };

            let connection_state = state.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, peer_addr, connection_state).await {
                    warn!(peer = %peer_addr, error = %error, "downstream connection closed with error");
                }
            });
        }
    }
  }
}

async fn serve_http3(state: Arc<AppState>) -> anyhow::Result<()> {
  let bind = state.config.listeners.https_bind;
  let server_config = state
    .quic_server_config
    .clone()
    .ok_or_else(|| anyhow::anyhow!("HTTP/3 listener is enabled without QUIC server config"))?;
  let endpoint = h3_quinn::quinn::Endpoint::server(server_config, bind)
    .with_context(|| format!("failed to bind downstream HTTP/3 listener to {bind}"))?;

  info!(bind = %bind, "downstream HTTP/3 listener started");

  loop {
    tokio::select! {
        biased;
        result = tokio::signal::ctrl_c() => {
            result.context("failed to wait for ctrl_c signal")?;
            info!("shutdown signal received");
            return Ok(());
        }
        connecting = endpoint.accept() => {
            let Some(connecting) = connecting else {
                return Ok(());
            };
            let connection_state = state.clone();
            tokio::spawn(async move {
                match connecting.await {
                    Ok(connection) => {
                        if let Err(error) = http3::handle_downstream_connection(connection, connection_state).await {
                            warn!(error = %error, "HTTP/3 downstream connection closed with error");
                        }
                    }
                    Err(error) => {
                        warn!(error = %error, "failed to accept downstream HTTP/3 connection");
                    }
                }
            });
        }
    }
  }
}

pub(crate) fn downstream_quic_tls_metadata(
  connection: &h3_quinn::quinn::Connection,
) -> WafTlsMetadata {
  let handshake_data = connection.handshake_data().and_then(|data| {
    data
      .downcast::<h3_quinn::quinn::crypto::rustls::HandshakeData>()
      .ok()
  });
  let (alpn, sni) = handshake_data
    .map(|data| {
      (
        data
          .protocol
          .as_ref()
          .map(|value| String::from_utf8_lossy(value).into_owned()),
        data.server_name.clone(),
      )
    })
    .unwrap_or_default();
  let version = Some("TLSv1_3".to_string());
  let fingerprint = Some(quic_tls_fingerprint(
    version.as_deref(),
    sni.as_deref(),
    alpn.as_deref(),
  ));

  WafTlsMetadata {
    enabled: true,
    version,
    cipher_suite: None,
    sni,
    alpn,
    fingerprint,
    fingerprint_scheme: Some(QUIC_TLS_FINGERPRINT_SCHEME.to_string()),
  }
}

async fn handle_connection(
  stream: TcpStream,
  peer_addr: SocketAddr,
  state: Arc<AppState>,
) -> anyhow::Result<()> {
  let tcp_max_hop = state.waf.person_proof_tcp_max_hop();
  if let Some(max_hop) = tcp_max_hop {
    tcp_hop::apply_tcp_max_hop(&stream, peer_addr.ip(), max_hop)
      .with_context(|| format!("failed to apply TCP max hop {max_hop} for {peer_addr}"))?;
  }

  let start = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
    .await
    .context("TLS ClientHello failed")?;
  let client_hello_metadata = client_hello_fingerprint_metadata(start.client_hello());
  let tls_stream = start
    .into_stream(state.tls_server_config.clone())
    .await
    .context("TLS handshake failed")?;

  let negotiated = tls_stream
    .get_ref()
    .1
    .alpn_protocol()
    .map(|proto| proto.to_vec())
    .unwrap_or_else(|| b"http/1.1".to_vec());
  let tls_metadata = Arc::new(downstream_tls_metadata(
    tls_stream.get_ref().1,
    &client_hello_metadata,
  ));

  let service = service_fn(move |request: hyper::Request<Incoming>| {
    let state = state.clone();
    let tls_metadata = tls_metadata.clone();
    async move {
      Ok::<_, Infallible>(http::handle(request, peer_addr, tcp_max_hop, tls_metadata, state).await)
    }
  });

  if negotiated == b"h2" {
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
      .serve_connection(TokioIo::new(tls_stream), service)
      .await
      .map_err(|error| {
        error!(peer = %peer_addr, error = %error, "HTTP/2 downstream connection failed");
        anyhow::anyhow!(error)
      })?;
  } else {
    hyper::server::conn::http1::Builder::new()
      .keep_alive(true)
      .serve_connection(TokioIo::new(tls_stream), service)
      .with_upgrades()
      .await
      .map_err(|error| {
        error!(peer = %peer_addr, error = %error, "HTTP/1.1 downstream connection failed");
        anyhow::anyhow!(error)
      })?;
  }

  Ok(())
}

#[derive(Debug, Clone, Default)]
struct ClientHelloFingerprintMetadata {
  cipher_suites: String,
  key_exchange_groups: String,
  signature_schemes: String,
  data_integrity_groups: String,
}

fn client_hello_fingerprint_metadata(
  client_hello: rustls::server::ClientHello<'_>,
) -> ClientHelloFingerprintMetadata {
  let cipher_suites = client_hello
    .cipher_suites()
    .iter()
    .map(|suite| format!("{suite:?}"))
    .collect::<Vec<_>>();
  let key_exchange_groups = client_hello
    .named_groups()
    .unwrap_or_default()
    .iter()
    .map(|group| format!("{group:?}"))
    .collect::<Vec<_>>();
  let signature_schemes = client_hello
    .signature_schemes()
    .iter()
    .map(|scheme| format!("{scheme:?}"))
    .collect::<Vec<_>>();
  let data_integrity_groups = unique_nonempty(
    cipher_suites
      .iter()
      .filter_map(|suite| cipher_suite_data_integrity_group(suite))
      .map(str::to_string),
  );

  ClientHelloFingerprintMetadata {
    cipher_suites: cipher_suites.join(","),
    key_exchange_groups: key_exchange_groups.join(","),
    signature_schemes: signature_schemes.join(","),
    data_integrity_groups: data_integrity_groups.join(","),
  }
}

fn downstream_tls_metadata(
  connection: &rustls::ServerConnection,
  client_hello: &ClientHelloFingerprintMetadata,
) -> WafTlsMetadata {
  let version = connection
    .protocol_version()
    .map(|version| format!("{version:?}"));
  let cipher_suite = connection
    .negotiated_cipher_suite()
    .map(|suite| format!("{:?}", suite.suite()));
  let key_exchange_group = connection
    .negotiated_key_exchange_group()
    .map(|group| format!("{:?}", group.name()));
  let data_integrity_group = connection
    .negotiated_cipher_suite()
    .map(|suite| negotiated_cipher_suite_data_integrity_group(suite).to_string());
  let sni = connection.server_name().map(str::to_string);
  let alpn = connection
    .alpn_protocol()
    .map(|proto| String::from_utf8_lossy(proto).into_owned());
  let fingerprint = Some(tls_fingerprint(
    client_hello,
    version.as_deref(),
    cipher_suite.as_deref(),
    key_exchange_group.as_deref(),
    data_integrity_group.as_deref(),
    sni.as_deref(),
    alpn.as_deref(),
  ));

  WafTlsMetadata {
    enabled: true,
    version,
    cipher_suite,
    sni,
    alpn,
    fingerprint,
    fingerprint_scheme: Some(TCP_TLS_FINGERPRINT_SCHEME.to_string()),
  }
}

fn tls_fingerprint(
  client_hello: &ClientHelloFingerprintMetadata,
  version: Option<&str>,
  cipher_suite: Option<&str>,
  key_exchange_group: Option<&str>,
  data_integrity_group: Option<&str>,
  sni: Option<&str>,
  alpn: Option<&str>,
) -> String {
  let payload = tls_fingerprint_payload(
    client_hello,
    version,
    cipher_suite,
    key_exchange_group,
    data_integrity_group,
    sni,
    alpn,
  );
  let hash = digest::digest(&digest::SHA256, payload.as_bytes());
  hex_encode(hash.as_ref())
}

fn tls_fingerprint_payload(
  client_hello: &ClientHelloFingerprintMetadata,
  version: Option<&str>,
  cipher_suite: Option<&str>,
  key_exchange_group: Option<&str>,
  data_integrity_group: Option<&str>,
  sni: Option<&str>,
  alpn: Option<&str>,
) -> String {
  format!(
    "{TCP_TLS_FINGERPRINT_SCHEME}\nclient_hello_cipher_suites={}\nclient_hello_key_exchange_groups={}\nclient_hello_signature_schemes={}\nclient_hello_data_integrity_groups={}\nselected_version={}\nselected_cipher_suite={}\nselected_key_exchange_group={}\nselected_data_integrity_group={}\nsni={}\nalpn={}",
    client_hello.cipher_suites,
    client_hello.key_exchange_groups,
    client_hello.signature_schemes,
    client_hello.data_integrity_groups,
    version.unwrap_or_default(),
    cipher_suite.unwrap_or_default(),
    key_exchange_group.unwrap_or_default(),
    data_integrity_group.unwrap_or_default(),
    sni.unwrap_or_default(),
    alpn.unwrap_or_default()
  )
}

fn quic_tls_fingerprint(version: Option<&str>, sni: Option<&str>, alpn: Option<&str>) -> String {
  let payload = quic_tls_fingerprint_payload(version, sni, alpn);
  let hash = digest::digest(&digest::SHA256, payload.as_bytes());
  hex_encode(hash.as_ref())
}

fn quic_tls_fingerprint_payload(
  version: Option<&str>,
  sni: Option<&str>,
  alpn: Option<&str>,
) -> String {
  format!(
    "{QUIC_TLS_FINGERPRINT_SCHEME}\nselected_version={}\nsni={}\nalpn={}",
    version.unwrap_or_default(),
    sni.unwrap_or_default(),
    alpn.unwrap_or_default()
  )
}

fn hex_encode(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut out = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
  }
  out
}

fn negotiated_cipher_suite_data_integrity_group(
  suite: rustls::SupportedCipherSuite,
) -> &'static str {
  match suite {
    rustls::SupportedCipherSuite::Tls12(suite) => {
      hash_algorithm_name(format!("{:?}", suite.common.hash_provider.algorithm()).as_str())
    }
    rustls::SupportedCipherSuite::Tls13(suite) => {
      hash_algorithm_name(format!("{:?}", suite.common.hash_provider.algorithm()).as_str())
    }
  }
}

fn cipher_suite_data_integrity_group(cipher_suite: &str) -> Option<&'static str> {
  if cipher_suite.ends_with("_SHA512") {
    Some("SHA512")
  } else if cipher_suite.ends_with("_SHA384") {
    Some("SHA384")
  } else if cipher_suite.ends_with("_SHA256") {
    Some("SHA256")
  } else if cipher_suite.ends_with("_SHA") {
    Some("SHA")
  } else if cipher_suite.ends_with("_MD5") {
    Some("MD5")
  } else {
    None
  }
}

fn hash_algorithm_name(name: &str) -> &'static str {
  match name {
    "SHA512" => "SHA512",
    "SHA384" => "SHA384",
    "SHA256" => "SHA256",
    "SHA1" => "SHA",
    "MD5" => "MD5",
    _ => "unknown",
  }
}

fn unique_nonempty(values: impl IntoIterator<Item = String>) -> Vec<String> {
  let mut unique = Vec::new();
  for value in values {
    if !value.is_empty() && !unique.contains(&value) {
      unique.push(value);
    }
  }
  unique
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn tls_fingerprint_payload_includes_client_hello_and_selected_tls_metadata() {
    let client_hello = ClientHelloFingerprintMetadata {
      cipher_suites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384".to_string(),
      key_exchange_groups: "X25519,X25519MLKEM768".to_string(),
      signature_schemes: "ECDSA_NISTP256_SHA256,RSA_PSS_SHA256".to_string(),
      data_integrity_groups: "SHA256,SHA384".to_string(),
    };

    let payload = tls_fingerprint_payload(
      &client_hello,
      Some("TLSv1_3"),
      Some("TLS_AES_128_GCM_SHA256"),
      Some("X25519MLKEM768"),
      Some("SHA256"),
      Some("example.com"),
      Some("h2"),
    );

    assert!(payload.starts_with("rustls-tcp-negotiated-v2\n"));
    assert!(
      payload.contains("client_hello_cipher_suites=TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384")
    );
    assert!(payload.contains("client_hello_key_exchange_groups=X25519,X25519MLKEM768"));
    assert!(
      payload.contains("client_hello_signature_schemes=ECDSA_NISTP256_SHA256,RSA_PSS_SHA256")
    );
    assert!(payload.contains("client_hello_data_integrity_groups=SHA256,SHA384"));
    assert!(payload.contains("selected_cipher_suite=TLS_AES_128_GCM_SHA256"));
    assert!(payload.contains("selected_key_exchange_group=X25519MLKEM768"));
    assert!(payload.contains("selected_data_integrity_group=SHA256"));
  }

  #[test]
  fn tls_fingerprint_changes_when_client_hello_or_selection_changes() {
    let client_hello = ClientHelloFingerprintMetadata {
      cipher_suites: "TLS_AES_128_GCM_SHA256".to_string(),
      key_exchange_groups: "X25519".to_string(),
      signature_schemes: "ECDSA_NISTP256_SHA256".to_string(),
      data_integrity_groups: "SHA256".to_string(),
    };
    let different_client_hello = ClientHelloFingerprintMetadata {
      cipher_suites: "TLS_AES_256_GCM_SHA384".to_string(),
      key_exchange_groups: "X25519".to_string(),
      signature_schemes: "ECDSA_NISTP256_SHA256".to_string(),
      data_integrity_groups: "SHA384".to_string(),
    };

    let base = tls_fingerprint(
      &client_hello,
      Some("TLSv1_3"),
      Some("TLS_AES_128_GCM_SHA256"),
      Some("X25519"),
      Some("SHA256"),
      Some("example.com"),
      Some("h2"),
    );
    let changed_client_hello = tls_fingerprint(
      &different_client_hello,
      Some("TLSv1_3"),
      Some("TLS_AES_128_GCM_SHA256"),
      Some("X25519"),
      Some("SHA256"),
      Some("example.com"),
      Some("h2"),
    );
    let changed_selection = tls_fingerprint(
      &client_hello,
      Some("TLSv1_3"),
      Some("TLS_AES_256_GCM_SHA384"),
      Some("X25519"),
      Some("SHA384"),
      Some("example.com"),
      Some("h2"),
    );

    assert_eq!(base.len(), 64);
    assert_ne!(base, changed_client_hello);
    assert_ne!(base, changed_selection);
  }

  #[test]
  fn quic_tls_fingerprint_payload_uses_reduced_quic_scheme() {
    let payload = quic_tls_fingerprint_payload(Some("TLSv1_3"), Some("example.com"), Some("h3"));

    assert!(payload.starts_with("quinn-rustls-quic-v1\n"));
    assert!(payload.contains("selected_version=TLSv1_3"));
    assert!(payload.contains("sni=example.com"));
    assert!(payload.contains("alpn=h3"));
  }

  #[test]
  fn quic_tls_fingerprint_changes_when_exposed_handshake_metadata_changes() {
    let base = quic_tls_fingerprint(Some("TLSv1_3"), Some("example.com"), Some("h3"));
    let changed_sni = quic_tls_fingerprint(Some("TLSv1_3"), Some("alt.example.com"), Some("h3"));
    let changed_alpn = quic_tls_fingerprint(Some("TLSv1_3"), Some("example.com"), Some("h3-29"));

    assert_eq!(base.len(), 64);
    assert_ne!(base, changed_sni);
    assert_ne!(base, changed_alpn);
  }

  #[test]
  fn cipher_suite_data_integrity_groups_are_deduplicated_in_order() {
    let groups = unique_nonempty(
      [
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_256_GCM_SHA384",
      ]
      .iter()
      .filter_map(|suite| cipher_suite_data_integrity_group(suite))
      .map(str::to_string),
    );

    assert_eq!(groups, vec!["SHA256".to_string(), "SHA384".to_string()]);
  }
}
