//! PROXY protocol emission for upstream connections that require original peer metadata.
//! Egress framing is explicit so upstream identity propagation cannot happen accidentally.

use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::config::ProxyProtocolEgressMode;

const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

pub async fn write_header<W>(
  writer: &mut W,
  mode: ProxyProtocolEgressMode,
  source: SocketAddr,
  destination: SocketAddr,
) -> std::io::Result<()>
where
  W: AsyncWrite + Unpin,
{
  match mode {
    ProxyProtocolEgressMode::Off => Ok(()),
    ProxyProtocolEgressMode::V1 => writer.write_all(&v1_header(source, destination)).await,
    ProxyProtocolEgressMode::V2 => writer.write_all(&v2_header(source, destination)).await,
  }
}

pub fn v1_header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
  let family = match (source.ip(), destination.ip()) {
    (IpAddr::V4(_), IpAddr::V4(_)) => "TCP4",
    (IpAddr::V6(_), IpAddr::V6(_)) => "TCP6",
    _ => "UNKNOWN",
  };
  if family == "UNKNOWN" {
    return b"PROXY UNKNOWN\r\n".to_vec();
  }
  format!(
    "PROXY {family} {} {} {} {}\r\n",
    source.ip(),
    destination.ip(),
    source.port(),
    destination.port()
  )
  .into_bytes()
}

pub fn v2_header(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
  let mut header = Vec::with_capacity(52);
  header.extend_from_slice(V2_SIGNATURE);
  header.push(0x21);
  match (source.ip(), destination.ip()) {
    (IpAddr::V4(src), IpAddr::V4(dst)) => {
      header.push(0x11);
      header.extend_from_slice(&12u16.to_be_bytes());
      header.extend_from_slice(&src.octets());
      header.extend_from_slice(&dst.octets());
    }
    (IpAddr::V6(src), IpAddr::V6(dst)) => {
      header.push(0x21);
      header.extend_from_slice(&36u16.to_be_bytes());
      header.extend_from_slice(&src.octets());
      header.extend_from_slice(&dst.octets());
    }
    _ => {
      header.push(0x00);
      header.extend_from_slice(&0u16.to_be_bytes());
      return header;
    }
  }
  header.extend_from_slice(&source.port().to_be_bytes());
  header.extend_from_slice(&destination.port().to_be_bytes());
  header
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn builds_v1_ipv4_header() {
    let source = "203.0.113.10:45678".parse().unwrap();
    let destination = "192.0.2.10:443".parse().unwrap();
    assert_eq!(
      v1_header(source, destination),
      b"PROXY TCP4 203.0.113.10 192.0.2.10 45678 443\r\n"
    );
  }

  #[test]
  fn builds_v2_ipv4_header() {
    let source = "203.0.113.10:45678".parse().unwrap();
    let destination = "192.0.2.10:443".parse().unwrap();
    let header = v2_header(source, destination);
    assert_eq!(&header[..12], V2_SIGNATURE);
    assert_eq!(header[12], 0x21);
    assert_eq!(header[13], 0x11);
    assert_eq!(&header[14..16], &12u16.to_be_bytes());
    assert_eq!(&header[16..20], &[203, 0, 113, 10]);
    assert_eq!(&header[20..24], &[192, 0, 2, 10]);
    assert_eq!(&header[24..26], &45678u16.to_be_bytes());
    assert_eq!(&header[26..28], &443u16.to_be_bytes());
  }
}
