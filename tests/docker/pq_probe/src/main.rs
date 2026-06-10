use std::env;
use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

#[derive(Clone, Copy)]
enum ProbeGroup {
    X25519,
    X25519MlKem768,
}

impl ProbeGroup {
    fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw {
            "x25519" => Ok(Self::X25519),
            "x25519mlkem768" => Ok(Self::X25519MlKem768),
            _ => bail!("unsupported probe group: {raw}"),
        }
    }

    fn supported_group(self) -> &'static dyn SupportedKxGroup {
        match self {
            Self::X25519 => rustls::crypto::aws_lc_rs::kx_group::X25519,
            Self::X25519MlKem768 => rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::X25519MlKem768 => "X25519MLKEM768",
        }
    }
}

struct Args {
    host: String,
    port: u16,
    server_name: String,
    ca_cert: String,
    group: ProbeGroup,
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut host = None;
        let mut port = None;
        let mut server_name = None;
        let mut ca_cert = None;
        let mut group = None;

        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| anyhow!("missing value for {flag}"))?;
            match flag.as_str() {
                "--host" => host = Some(value),
                "--port" => {
                    port = Some(value.parse().context("invalid --port value")?);
                }
                "--server-name" => server_name = Some(value),
                "--ca-cert" => ca_cert = Some(value),
                "--group" => group = Some(ProbeGroup::parse(&value)?),
                _ => bail!("unknown flag: {flag}"),
            }
        }

        Ok(Self {
            host: host.ok_or_else(|| anyhow!("--host is required"))?,
            port: port.ok_or_else(|| anyhow!("--port is required"))?,
            server_name: server_name.ok_or_else(|| anyhow!("--server-name is required"))?,
            ca_cert: ca_cert.ok_or_else(|| anyhow!("--ca-cert is required"))?,
            group: group.ok_or_else(|| anyhow!("--group is required"))?,
        })
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse()?;
    let provider = CryptoProvider {
        kx_groups: vec![args.group.supported_group()],
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    let client_config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .context("failed to configure TLS protocol versions")?
        .with_root_certificates(load_root_store(Path::new(&args.ca_cert))?)
        .with_no_client_auth();

    let server_name = ServerName::try_from(args.server_name.clone())
        .map_err(|_| anyhow!("invalid server name: {}", args.server_name))?;
    let mut connection = ClientConnection::new(Arc::new(client_config), server_name)
        .context("failed to create TLS client connection")?;
    let mut socket = TcpStream::connect((args.host.as_str(), args.port))
        .with_context(|| format!("failed to connect to {}:{}", args.host, args.port))?;

    while connection.is_handshaking() {
        connection.complete_io(&mut socket).map_err(|error| {
            anyhow!(
                "TLS handshake failed while probing {}: {error}",
                args.group.display_name()
            )
        })?;
    }

    let negotiated_group = connection
        .negotiated_key_exchange_group()
        .ok_or_else(|| anyhow!("TLS handshake completed without a negotiated key exchange group"))?
        .name();
    let protocol_version = connection
        .protocol_version()
        .ok_or_else(|| anyhow!("TLS handshake completed without a protocol version"))?;
    let cipher_suite = connection
        .negotiated_cipher_suite()
        .ok_or_else(|| anyhow!("TLS handshake completed without a cipher suite"))?
        .suite();

    println!(
        "handshake_ok requested_group={} negotiated_group={negotiated_group:?} protocol={protocol_version:?} cipher_suite={cipher_suite:?}",
        args.group.display_name()
    );

    Ok(())
}

fn load_root_store(path: &Path) -> anyhow::Result<RootCertStore> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .with_context(|| format!("failed to parse PEM certificates from {}", path.display()))?;

    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        bail!("no parsable certificates found in {}", path.display());
    }

    Ok(roots)
}
