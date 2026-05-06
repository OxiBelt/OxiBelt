use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Context, bail};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::config::{ProxyProtocolConfig, ProxyProtocolVersion};
use crate::identity::TrustedCidrs;

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

pub async fn accept_proxy_header(
  mut stream: TcpStream,
  peer_addr: SocketAddr,
  config: &ProxyProtocolConfig,
) -> anyhow::Result<(TcpStream, SocketAddr)> {
  if !config.enabled {
    return Ok((stream, peer_addr));
  }
  let trusted = TrustedCidrs::parse(&config.trusted_sources)?;
  if !trusted.contains(peer_addr.ip()) {
    bail!("PROXY protocol peer {peer_addr} is not trusted");
  }

  match config.version {
    ProxyProtocolVersion::V1 => {
      let addr = read_v1(&mut stream).await?;
      Ok((stream, addr))
    }
    ProxyProtocolVersion::V2 => {
      let addr = read_v2(&mut stream).await?;
      Ok((stream, addr))
    }
    ProxyProtocolVersion::Any => {
      let mut peek = [0u8; 12];
      stream
        .peek(&mut peek)
        .await
        .context("failed to peek PROXY protocol header")?;
      let addr = if &peek == V2_SIGNATURE {
        read_v2(&mut stream).await?
      } else {
        read_v1(&mut stream).await?
      };
      Ok((stream, addr))
    }
  }
}

async fn read_v1(stream: &mut TcpStream) -> anyhow::Result<SocketAddr> {
  let mut line = Vec::new();
  loop {
    if line.len() > 107 {
      bail!("PROXY protocol v1 header is too long");
    }
    let mut byte = [0u8; 1];
    stream
      .read_exact(&mut byte)
      .await
      .context("failed to read PROXY protocol v1 header")?;
    line.push(byte[0]);
    if byte[0] == b'\n' {
      break;
    }
  }
  let line = std::str::from_utf8(&line).context("PROXY protocol v1 header is not UTF-8")?;
  let line = line.trim_end_matches(['\r', '\n']);
  let parts = line.split_whitespace().collect::<Vec<_>>();
  if parts.len() != 6 || parts[0] != "PROXY" {
    bail!("invalid PROXY protocol v1 header");
  }
  if parts[1] == "UNKNOWN" {
    bail!("PROXY protocol UNKNOWN source is not accepted");
  }
  let source_ip: IpAddr = parts[2].parse().context("invalid PROXY source IP")?;
  let source_port: u16 = parts[4].parse().context("invalid PROXY source port")?;
  Ok(SocketAddr::new(source_ip, source_port))
}

async fn read_v2(stream: &mut TcpStream) -> anyhow::Result<SocketAddr> {
  let mut head = [0u8; 16];
  stream
    .read_exact(&mut head)
    .await
    .context("failed to read PROXY protocol v2 header")?;
  if &head[..12] != V2_SIGNATURE {
    bail!("invalid PROXY protocol v2 signature");
  }
  let version = head[12] >> 4;
  let command = head[12] & 0x0f;
  if version != 2 {
    bail!("invalid PROXY protocol v2 version");
  }
  if command != 1 {
    bail!("PROXY protocol v2 LOCAL command is not accepted");
  }
  let family = head[13] >> 4;
  let transport = head[13] & 0x0f;
  let len = u16::from_be_bytes([head[14], head[15]]) as usize;
  let mut payload = vec![0u8; len];
  stream
    .read_exact(&mut payload)
    .await
    .context("failed to read PROXY protocol v2 payload")?;
  if transport != 1 {
    bail!("PROXY protocol v2 only supports TCP");
  }
  match family {
    1 if payload.len() >= 12 => {
      let ip = IpAddr::V4(Ipv4Addr::new(
        payload[0], payload[1], payload[2], payload[3],
      ));
      let port = u16::from_be_bytes([payload[8], payload[9]]);
      Ok(SocketAddr::new(ip, port))
    }
    2 if payload.len() >= 36 => {
      let mut src = [0u8; 16];
      src.copy_from_slice(&payload[..16]);
      let ip = IpAddr::V6(Ipv6Addr::from(src));
      let port = u16::from_be_bytes([payload[32], payload[33]]);
      Ok(SocketAddr::new(ip, port))
    }
    _ => bail!("unsupported PROXY protocol v2 address family"),
  }
}
