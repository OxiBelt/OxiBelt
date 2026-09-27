//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Copy, PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// WebTransport over HTTP/3 draft 16 upgrade token.
    pub const WEB_TRANSPORT_H3: Protocol = Protocol(ProtocolInner::WebTransportH3);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);
    /// RFC 9220 WebSocket over HTTP/3 protocol.
    pub const WEBSOCKET: Protocol = Protocol(ProtocolInner::WebSocket);

    /// Whether this crate recognizes the extended CONNECT protocol.
    pub fn is_supported(&self) -> bool {
        self.0 != ProtocolInner::Unsupported
    }

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::WebTransportH3 => "webtransport-h3",
            ProtocolInner::ConnectUdp => "connect-udp",
            ProtocolInner::WebSocket => "websocket",
            ProtocolInner::Unsupported => "unsupported",
        }
    }
}

#[derive(Copy, PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    WebTransportH3,
    ConnectUdp,
    WebSocket,
    Unsupported,
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "webtransport-h3" => Ok(Self(ProtocolInner::WebTransportH3)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            "websocket" => Ok(Self(ProtocolInner::WebSocket)),
            // A syntactically valid but unrecognized token is not malformed.
            _ if !s.is_empty() && s.bytes().all(is_token_byte) => {
                Ok(Self(ProtocolInner::Unsupported))
            }
            _ => Err(InvalidProtocol),
        }
    }
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::Protocol;
    use std::str::FromStr;

    #[test]
    fn websocket_and_unknown_protocol_tokens() {
        assert_eq!(Protocol::from_str("websocket").unwrap(), Protocol::WEBSOCKET);
        assert_eq!(Protocol::WEBSOCKET.as_str(), "websocket");
        assert!(!Protocol::from_str("unknown-protocol")
            .unwrap()
            .is_supported());
        assert!(Protocol::from_str("bad protocol").is_err());
        assert!(Protocol::from_str("").is_err());
    }
}
