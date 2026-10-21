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

#[tokio::test]
async fn reliable_prefix_keeps_reset_stream_association_and_charges_final_size_once() -> Result<()>
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (server, client) = pair().await?;
    server.grant_receive_credit(1, 1, 64)?;
    client.grant_receive_credit(1, 1, 64)?;
    let mut send = timeout(Duration::from_secs(5), client.open_uni()).await??;
    AsyncWriteExt::write_all(&mut send, b"payload").await?;
    send.reset(77)?;
    let mut recv = timeout(Duration::from_secs(5), server.accept_uni()).await??;
    let mut body = Vec::new();
    let error = timeout(
        Duration::from_secs(5),
        AsyncReadExt::read_to_end(&mut recv, &mut body),
    )
    .await?
    .unwrap_err();
    assert!(
        matches!(error.get_ref().and_then(|e| e.downcast_ref::<quinn::ReadError>()), Some(quinn::ReadError::Reset(code)) if code.into_inner() == web_transport_proto::error_to_http3(77))
    );
    let final_size = recv.reset_info().expect("reset final size").final_size;
    assert_eq!(final_size, client.header_uni.len() as u64 + 7);
    let flow = server.flow.as_ref().unwrap();
    assert_eq!(flow.incoming.lock().unwrap().used_data, 7);
    let mut initialized = [0u8; 1];
    let _ = AsyncReadExt::read(&mut recv, &mut initialized).await;
    assert_eq!(
        flow.incoming.lock().unwrap().used_data,
        7,
        "reset charged exactly once"
    );
    Ok(())
}

#[tokio::test]
async fn reset_accounting_preserves_nonminimal_association_varint_widths() -> Result<()> {
    use tokio::io::AsyncReadExt;
    let (server, client) = pair().await?;
    server.grant_receive_credit(1, 1, 64)?;
    timeout(Duration::from_secs(5), async {
        while server
            .flow
            .as_ref()
            .unwrap()
            .incoming
            .lock()
            .unwrap()
            .max_uni
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let mut send = client.conn.open_uni().await?;
    let typ = crate::proto::StreamUni::WEBTRANSPORT.0.into_inner() as u32 | (2 << 30);
    let id = client.session_id.unwrap().into_inner() as u16 | (1 << 14);
    let mut header = Vec::new();
    header.extend_from_slice(&typ.to_be_bytes());
    header.extend_from_slice(&id.to_be_bytes());
    send.write_all(&header).await?;
    send.write_all(b"xyz").await?;
    send.reset_at(
        quinn::VarInt::try_from(web_transport_proto::error_to_http3(88))?,
        header.len() as u64,
    )?;
    let mut recv = timeout(Duration::from_secs(5), server.accept_uni()).await??;
    let mut initialized = [0u8; 8];
    let _ = timeout(
        Duration::from_secs(5),
        AsyncReadExt::read(&mut recv, &mut initialized),
    )
    .await?;
    if server
        .flow
        .as_ref()
        .unwrap()
        .incoming
        .lock()
        .unwrap()
        .used_data
        != 3
    {
        let _ = timeout(
            Duration::from_secs(5),
            AsyncReadExt::read(&mut recv, &mut initialized),
        )
        .await?;
    }
    assert_eq!(recv.reset_info().unwrap().final_size, 9);
    assert_eq!(
        server
            .flow
            .as_ref()
            .unwrap()
            .incoming
            .lock()
            .unwrap()
            .used_data,
        3,
        "header width excluded from body charge"
    );
    Ok(())
}

#[tokio::test]
async fn initialized_tokio_writes_wait_for_session_credit_and_resume_after_consumption(
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (server, client) = pair().await?;
    server.grant_receive_credit(1, 1, 4)?;
    let mut send = timeout(Duration::from_secs(5), client.open_uni()).await??;
    assert_eq!(AsyncWriteExt::write(&mut send, b"abcde").await?, 4);
    assert!(timeout(
        Duration::from_millis(20),
        AsyncWriteExt::write(&mut send, b"e")
    )
    .await
    .is_err());
    assert_eq!(
        client
            .flow
            .as_ref()
            .unwrap()
            .outgoing
            .lock()
            .unwrap()
            .used_data,
        4
    );
    let mut recv = timeout(Duration::from_secs(5), server.accept_uni()).await??;
    let mut initialized = [0u8; 4];
    timeout(
        Duration::from_secs(5),
        AsyncReadExt::read_exact(&mut recv, &mut initialized),
    )
    .await??;
    assert_eq!(&initialized, b"abcd");
    assert_eq!(
        timeout(
            Duration::from_secs(5),
            AsyncWriteExt::write(&mut send, b"e")
        )
        .await??,
        1
    );
    AsyncWriteExt::shutdown(&mut send).await?;
    let mut rest = Vec::new();
    timeout(
        Duration::from_secs(5),
        AsyncReadExt::read_to_end(&mut recv, &mut rest),
    )
    .await??;
    assert_eq!(rest, b"e");
    assert_eq!(
        server
            .flow
            .as_ref()
            .unwrap()
            .incoming
            .lock()
            .unwrap()
            .used_data,
        5
    );
    Ok(())
}
