use super::Session;
use crate::{
    proto::{Capsule, Frame, VarInt, WebTransportDraft},
    Request, ServerBuilder, SessionError, WebTransportError,
};
use anyhow::{Context as _, Result};
use rcgen::{CertifiedKey, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::time::timeout;
use web_transport_proto::ConnectRequest;

async fn pair() -> Result<(Session, Session)> {
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let _ = rustls::crypto::ring::default_provider().install_default();
    let provider = crate::crypto::default_provider();

    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate = cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KeyPair::serialize_der(
        &signing_key,
    )));
    let server = ServerBuilder::new()
        .with_addr((Ipv4Addr::LOCALHOST, 0).into())
        .with_certificate(vec![certificate.clone()], key)?;
    let server_addr = server.local_addr()?;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![crate::ALPN.as_bytes().to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    let mut endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(client_config);

    let server_side = async {
        let incoming = quinn::Endpoint::accept(&server)
            .await
            .context("no draft16 connection")?;
        let conn = incoming.await?;
        let request = Request::accept_with_draft(conn, WebTransportDraft::Draft16).await?;
        anyhow::Ok(request.ok().await?)
    };
    let client_side = async {
        let conn = endpoint.connect(server_addr, "localhost")?.await?;
        let url: url::Url = format!("https://localhost:{}/", server_addr.port()).parse()?;
        anyhow::Ok(
            Session::connect_with_draft(conn, ConnectRequest::new(url), WebTransportDraft::Draft16)
                .await?,
        )
    };
    Ok(timeout(Duration::from_secs(10), async {
        tokio::try_join!(server_side, client_side)
    })
    .await??)
}

async fn wait_for_initial_credit(client: &Session) -> Result<()> {
    client.grant_receive_credit(1, 1, 1024)?;
    timeout(Duration::from_secs(5), async {
        loop {
            let flow = client.flow.as_ref().expect("draft16 flow");
            let sent = {
                let incoming = flow.incoming.lock().unwrap();
                incoming.max_uni == 1 && incoming.max_bidi == 1 && incoming.max_data == 1024
            };
            if sent {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("initial credit was not sent")?;
    Ok(())
}

async fn wait_for_writer_release(client: &Session) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            if Arc::strong_count(client.flow.as_ref().expect("draft16 flow")) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("credit writer retained the closed session")?;
    Ok(())
}

async fn finish_with_capsules(server: &Session, capsules: &[Capsule]) -> Result<()> {
    let mut send = server
        .connect_send
        .as_ref()
        .expect("server CONNECT stream")
        .lock()
        .await;
    for capsule in capsules {
        let mut encoded = Vec::new();
        capsule.encode(&mut encoded);
        let mut frame = Vec::new();
        Frame::DATA.encode(&mut frame);
        VarInt::try_from(encoded.len())?.encode(&mut frame);
        frame.extend_from_slice(&encoded);
        send.write_all(&frame).await?;
    }
    send.finish()?;
    Ok(())
}

#[tokio::test]
async fn remote_connect_fin_releases_credit_writer_without_streams() -> Result<()> {
    let (server, client) = pair().await?;
    wait_for_initial_credit(&client).await?;
    finish_with_capsules(&server, &[]).await?;
    timeout(Duration::from_secs(5), client.closed()).await?;
    client.close(0, b"already closed");
    wait_for_writer_release(&client).await?;
    Ok(())
}

#[tokio::test]
async fn remote_close_capsule_releases_credit_writer_without_streams() -> Result<()> {
    let (server, client) = pair().await?;
    wait_for_initial_credit(&client).await?;
    finish_with_capsules(
        &server,
        &[Capsule::CloseWebTransportSession {
            code: 42,
            reason: "remote close".into(),
        }],
    )
    .await?;
    let closed = timeout(Duration::from_secs(5), client.closed()).await?;
    assert!(matches!(
        closed,
        SessionError::WebTransportError(WebTransportError::Closed(42, reason))
            if reason == "remote close"
    ));
    wait_for_writer_release(&client).await?;
    Ok(())
}

#[tokio::test]
async fn malformed_connect_capsule_releases_credit_writer_without_streams() -> Result<()> {
    let (server, client) = pair().await?;
    wait_for_initial_credit(&client).await?;
    finish_with_capsules(
        &server,
        &[
            Capsule::CloseWebTransportSession {
                code: 42,
                reason: String::new(),
            },
            Capsule::Grease { num: 0 },
        ],
    )
    .await?;
    let closed = timeout(Duration::from_secs(5), client.closed()).await?;
    assert!(matches!(
        closed,
        SessionError::ConnectionError(quinn::ConnectionError::LocallyClosed)
    ));
    wait_for_writer_release(&client).await?;
    Ok(())
}

#[tokio::test]
async fn local_and_transport_close_release_credit_writer() -> Result<()> {
    let (server, client) = pair().await?;
    wait_for_initial_credit(&client).await?;
    client.close(42, b"local close");
    timeout(Duration::from_secs(5), client.closed()).await?;
    let server_closed = timeout(Duration::from_secs(5), server.closed()).await?;
    assert!(matches!(
        server_closed,
        SessionError::WebTransportError(WebTransportError::Closed(42, reason))
            if reason == "local close"
    ));
    wait_for_writer_release(&client).await?;

    let (server, client) = pair().await?;
    wait_for_initial_credit(&client).await?;
    server.conn.close(0u32.into(), b"transport closed");
    timeout(Duration::from_secs(5), client.closed()).await?;
    wait_for_writer_release(&client).await?;
    Ok(())
}

#[tokio::test]
async fn credit_writer_owner_follows_the_final_session_clone() -> Result<()> {
    let (server, client) = pair().await?;
    let clone = client.clone();
    drop(client);
    wait_for_initial_credit(&clone).await?;
    let writer = clone
        .credit_writer
        .as_ref()
        .expect("draft16 credit writer")
        .0
        .abort_handle();
    drop(clone);
    timeout(Duration::from_secs(5), async {
        while !writer.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("final session owner did not retire credit writer")?;
    server.conn.close(0u32.into(), b"test complete");
    Ok(())
}
