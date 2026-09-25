use std::{str::FromStr, sync::Arc};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;

use super::{qpack, Frame, VarInt, WebTransportDraft, MAX_FRAME_SIZE};

use thiserror::Error;

// Errors that can occur during the connect request.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum ConnectError {
    #[error("unexpected end of input")]
    UnexpectedEnd,

    #[error("qpack error")]
    QpackError(#[from] qpack::DecodeError),

    #[error("unexpected frame {0:?}")]
    UnexpectedFrame(Frame),

    #[error("invalid method")]
    InvalidMethod,

    #[error("invalid url")]
    InvalidUrl(#[from] url::ParseError),

    #[error("invalid status")]
    InvalidStatus,

    #[error("expected 200, got: {0:?}")]
    WrongStatus(Option<http::StatusCode>),

    #[error("expected connect, got: {0:?}")]
    WrongMethod(Option<http::method::Method>),

    #[error("expected https, got: {0:?}")]
    WrongScheme(Option<String>),

    #[error("expected authority header")]
    WrongAuthority,

    #[error("expected webtransport, got: {0:?}")]
    WrongProtocol(Option<String>),

    #[error("expected path header")]
    WrongPath,

    #[error("invalid protocol header")]
    InvalidProtocol,

    #[error("structured field error: {0}")]
    StructuredFieldError(Arc<sfv::Error>),

    #[error("frame too large")]
    FrameTooLarge,

    #[error("non-200 status: {0:?}")]
    ErrorStatus(http::StatusCode),

    #[error("io error: {0}")]
    Io(Arc<std::io::Error>),

    #[error("invalid http header value")]
    InvalidHttpHeaderValue,

    #[error("invalid http header name")]
    InvalidHttpHeaderName,

    #[error("WebTransport H3 response dialect mismatch")]
    DraftMismatch,
}

impl From<std::io::Error> for ConnectError {
    fn from(err: std::io::Error) -> Self {
        ConnectError::Io(Arc::new(err))
    }
}

impl From<sfv::Error> for ConnectError {
    fn from(err: sfv::Error) -> Self {
        ConnectError::StructuredFieldError(Arc::new(err))
    }
}

/// A CONNECT request to initiate a WebTransport session.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    /// The URL to connect to.
    pub url: Url,

    /// The subprotocols requested (if any).
    pub protocols: Vec<String>,

    /// The raw HTTP/3 headers from the request.
    pub headers: http::HeaderMap,
    /// Wire dialect used by this request.
    pub draft: WebTransportDraft,
}

impl ConnectRequest {
    pub fn new(url: impl Into<Url>) -> Self {
        Self {
            url: url.into(),
            protocols: Vec::new(),
            headers: http::HeaderMap::new(),
            draft: WebTransportDraft::Draft02,
        }
    }

    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    pub fn with_protocols(mut self, protocols: impl IntoIterator<Item = String>) -> Self {
        self.protocols.extend(protocols);
        self
    }

    pub fn with_header(mut self, name: http::HeaderName, value: http::HeaderValue) -> Self {
        self.headers.append(name, value);
        self
    }

    pub fn with_headers(mut self, headers: http::HeaderMap) -> Self {
        self.headers.extend(headers);
        self
    }

    pub fn with_draft(mut self, draft: WebTransportDraft) -> Self {
        self.draft = draft;
        self
    }

    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, ConnectError> {
        let (typ, mut data) = Frame::read(buf).map_err(|_| ConnectError::UnexpectedEnd)?;
        if typ != Frame::HEADERS {
            return Err(ConnectError::UnexpectedFrame(typ));
        }

        Self::decode_headers(&mut data)
    }

    fn decode_headers<B: Buf>(data: &mut B) -> Result<Self, ConnectError> {
        let headers = qpack::Headers::decode(data)?;

        let scheme = match headers.get(":scheme") {
            Some("https") => "https",
            Some(scheme) => Err(ConnectError::WrongScheme(Some(scheme.to_string())))?,
            None => return Err(ConnectError::WrongScheme(None)),
        };

        let authority = headers
            .get(":authority")
            .ok_or(ConnectError::WrongAuthority)?;

        let path_and_query = headers.get(":path").ok_or(ConnectError::WrongPath)?;

        let method = headers.get(":method");
        match method
            .map(|method| method.try_into().map_err(|_| ConnectError::InvalidMethod))
            .transpose()?
        {
            Some(http::Method::CONNECT) => (),
            o => return Err(ConnectError::WrongMethod(o)),
        };

        let protocol = headers.get(":protocol");
        if !matches!(protocol, Some("webtransport" | "webtransport-h3")) {
            return Err(ConnectError::WrongProtocol(protocol.map(|s| s.to_string())));
        }
        let draft = if protocol == Some("webtransport-h3") {
            WebTransportDraft::Draft16
        } else {
            WebTransportDraft::Draft02
        };
        let draft02_marker = headers
            .fields
            .iter()
            .filter(|(name, _)| name.as_str() == "sec-webtransport-http3-draft02")
            .collect::<Vec<_>>();
        if draft == WebTransportDraft::Draft02
            && (draft02_marker.len() != 1 || draft02_marker[0].1 != "1")
        {
            return Err(ConnectError::DraftMismatch);
        }
        if headers.get("sec-webtransport-http3-draft").is_some() {
            return Err(ConnectError::DraftMismatch);
        }

        let available = headers
            .fields
            .iter()
            .filter(|(name, _)| name == protocol_negotiation::AVAILABLE_NAME)
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>();
        let protocols = if available.is_empty() {
            Vec::new()
        } else {
            // RFC 8941 List fields are combined with a comma in wire order.
            protocol_negotiation::decode_list(&available.join(", "))
                .map_err(|_| ConnectError::InvalidProtocol)?
        };

        let url = Url::parse(&format!("{scheme}://{authority}{path_and_query}"))?;

        // Save all headers, excluding pseudo-headers and protocol negotiation headers
        // (protocol negotiation is handled via the `protocols` field).
        let mut raw_headers = http::HeaderMap::new();
        for (item_header_name, item_header_value) in headers.fields.iter() {
            if item_header_name.starts_with(':') {
                continue;
            }
            if item_header_name == protocol_negotiation::AVAILABLE_NAME {
                continue;
            }
            let header_name = http::HeaderName::from_bytes(item_header_name.as_bytes())
                .map_err(|_| ConnectError::InvalidHttpHeaderName)?;
            let header_value = http::HeaderValue::from_str(item_header_value)
                .map_err(|_| ConnectError::InvalidHttpHeaderValue)?;
            raw_headers.append(header_name, header_value);
        }

        Ok(Self {
            url,
            protocols,
            headers: raw_headers,
            draft,
        })
    }

    /// Read a CONNECT request from a stream, consuming only the exact bytes of the frame.
    pub async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Self, ConnectError> {
        let buf = read_headers_frame(stream).await?;
        Self::decode_headers(&mut buf.as_slice())
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), ConnectError> {
        let mut headers = qpack::Headers::default();
        for (item_header_name, item_header_value) in self.headers.iter() {
            // Skip protocol negotiation headers; they are derived from `self.protocols`.
            if item_header_name == protocol_negotiation::AVAILABLE_NAME
                || item_header_name == "sec-webtransport-http3-draft"
                || item_header_name == "sec-webtransport-http3-draft02"
            {
                continue;
            }
            // http::HeaderValue can contain arbitrary bytes (not just UTF-8).
            // The to_str() method fails when the header value contains invalid UTF-8 bytes
            let item_header_value_str = item_header_value
                .to_str()
                .map_err(|_| ConnectError::InvalidHttpHeaderValue)?;
            headers.append(item_header_name.as_str(), item_header_value_str);
        }
        headers.set(":method", "CONNECT");
        headers.set(":scheme", self.url.scheme());
        headers.set(":authority", self.url.authority());
        let path_and_query = match self.url.query() {
            Some(query) => format!("{}?{}", self.url.path(), query),
            None => self.url.path().to_string(),
        };
        headers.set(":path", &path_and_query);
        headers.set(
            ":protocol",
            match self.draft {
                WebTransportDraft::Draft02 => "webtransport",
                WebTransportDraft::Draft16 => "webtransport-h3",
            },
        );
        if self.draft == WebTransportDraft::Draft02 {
            headers.set("sec-webtransport-http3-draft02", "1");
        }

        if !self.protocols.is_empty() {
            let encoded = protocol_negotiation::encode_list(&self.protocols)?;
            headers.set(protocol_negotiation::AVAILABLE_NAME, &encoded);
        }

        // Use a temporary buffer so we can compute the size.
        let mut tmp = Vec::new();
        headers.encode(&mut tmp);
        let size = VarInt::from_u32(tmp.len() as u32);

        Frame::HEADERS.encode(buf);
        size.encode(buf);
        buf.put_slice(&tmp);

        Ok(())
    }

    pub async fn write<S: AsyncWrite + Unpin>(&self, stream: &mut S) -> Result<(), ConnectError> {
        let mut buf = BytesMut::new();
        self.encode(&mut buf)?;
        stream.write_all_buf(&mut buf).await?;
        Ok(())
    }
}

impl From<Url> for ConnectRequest {
    fn from(url: Url) -> Self {
        Self {
            url,
            protocols: Vec::new(),
            headers: http::HeaderMap::new(),
            draft: WebTransportDraft::Draft02,
        }
    }
}

/// A CONNECT response to accept or reject a WebTransport session.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ConnectResponse {
    /// The status code of the response.
    pub status: http::status::StatusCode,

    /// The subprotocol selected by the server, if any
    pub protocol: Option<String>,
    /// Legacy draft marker, if present in the HTTP response.
    pub draft_marker: Option<String>,
    /// Ordinary HTTP/3 response headers, excluding protocol negotiation headers.
    pub headers: Vec<(http::HeaderName, http::HeaderValue)>,
}

impl ConnectResponse {
    pub const OK: Self = Self {
        status: http::StatusCode::OK,
        protocol: None,
        draft_marker: Some(String::new()),
        headers: Vec::new(),
    };

    pub fn new(status: http::StatusCode) -> Self {
        Self {
            status,
            protocol: None,
            draft_marker: Some(String::new()),
            headers: Vec::new(),
        }
    }

    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    pub fn for_draft(mut self, draft: WebTransportDraft) -> Self {
        self.draft_marker = match draft {
            WebTransportDraft::Draft02 => Some("draft02".to_string()),
            WebTransportDraft::Draft16 => None,
        };
        self
    }

    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, ConnectError> {
        let (typ, mut data) = Frame::read(buf).map_err(|_| ConnectError::UnexpectedEnd)?;
        if typ != Frame::HEADERS {
            return Err(ConnectError::UnexpectedFrame(typ));
        }

        Self::decode_headers(&mut data)
    }

    fn decode_headers<B: Buf>(data: &mut B) -> Result<Self, ConnectError> {
        let headers = qpack::Headers::decode(data)?;

        let status = match headers
            .get(":status")
            .map(|status| {
                http::StatusCode::from_str(status).map_err(|_| ConnectError::InvalidStatus)
            })
            .transpose()?
        {
            Some(status) if status.is_success() => status,
            o => return Err(ConnectError::WrongStatus(o)),
        };

        let selected = headers
            .fields
            .iter()
            .filter(|(name, _)| name == protocol_negotiation::SELECTED_NAME)
            .collect::<Vec<_>>();
        // Multiple Item fields form an invalid selected protocol; browsers
        // ignore malformed selections while accepting the CONNECT.
        let protocol = match selected.as_slice() {
            [(_, value)] => protocol_negotiation::decode_item(value).ok(),
            _ => None,
        };

        let markers = headers
            .fields
            .iter()
            .filter(|(name, _)| name.as_str() == "sec-webtransport-http3-draft")
            .collect::<Vec<_>>();
        if markers.len() > 1 {
            return Err(ConnectError::DraftMismatch);
        }
        let draft_marker = markers.first().map(|(_, value)| value.to_string());
        let mut raw_headers = Vec::new();
        for (name, value) in &headers.fields {
            if name.starts_with(':')
                || name == protocol_negotiation::SELECTED_NAME
                || name == "sec-webtransport-http3-draft"
            {
                continue;
            }
            let name = http::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| ConnectError::InvalidHttpHeaderName)?;
            let value = http::HeaderValue::from_str(value)
                .map_err(|_| ConnectError::InvalidHttpHeaderValue)?;
            raw_headers.push((name, value));
        }
        Ok(Self {
            status,
            protocol,
            draft_marker,
            headers: raw_headers,
        })
    }

    /// Read a CONNECT response from a stream, consuming only the exact bytes of the frame.
    pub async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Self, ConnectError> {
        let buf = read_headers_frame(stream).await?;
        Self::decode_headers(&mut buf.as_slice())
    }

    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), ConnectError> {
        let mut headers = qpack::Headers::default();
        for (name, value) in &self.headers {
            if name == protocol_negotiation::SELECTED_NAME || name == "sec-webtransport-http3-draft"
            {
                continue;
            }
            let value = value
                .to_str()
                .map_err(|_| ConnectError::InvalidHttpHeaderValue)?;
            headers.append(name.as_str(), value);
        }
        headers.set(":status", self.status.as_str());
        if let Some(marker) = self.draft_marker.as_deref() {
            headers.set(
                "sec-webtransport-http3-draft",
                if marker.is_empty() { "draft02" } else { marker },
            );
        }

        if let Some(protocol) = self.protocol.as_ref() {
            let encoded = protocol_negotiation::encode_item(protocol)?;
            headers.set(protocol_negotiation::SELECTED_NAME, &encoded);
        }

        // Use a temporary buffer so we can compute the size.
        let mut tmp = Vec::new();
        headers.encode(&mut tmp);
        let size = VarInt::from_u32(tmp.len() as u32);

        Frame::HEADERS.encode(buf);
        size.encode(buf);
        buf.put_slice(&tmp);

        Ok(())
    }

    pub async fn write<S: AsyncWrite + Unpin>(&self, stream: &mut S) -> Result<(), ConnectError> {
        let mut buf = BytesMut::new();
        self.encode(&mut buf)?;
        stream.write_all_buf(&mut buf).await?;
        Ok(())
    }
}

impl Default for ConnectResponse {
    fn default() -> Self {
        Self::OK
    }
}

impl From<http::StatusCode> for ConnectResponse {
    fn from(status: http::StatusCode) -> Self {
        Self {
            status,
            protocol: None,
            draft_marker: Some(String::new()),
            headers: Vec::new(),
        }
    }
}

/// Read the next HEADERS frame from the stream, skipping any GREASE frames.
///
/// Returns the raw payload bytes of the HEADERS frame.
async fn read_headers_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, ConnectError> {
    loop {
        let typ = Frame(
            VarInt::read(stream)
                .await
                .map_err(|_| ConnectError::UnexpectedEnd)?,
        );
        let size = VarInt::read(stream)
            .await
            .map_err(|_| ConnectError::UnexpectedEnd)?;

        let size = size.into_inner();
        if size > MAX_FRAME_SIZE {
            return Err(ConnectError::FrameTooLarge);
        }

        let mut payload = stream.take(size);

        if typ.is_grease() {
            let n = tokio::io::copy(&mut payload, &mut tokio::io::sink()).await?;
            if n < size {
                return Err(ConnectError::UnexpectedEnd);
            }
            continue;
        }

        let mut buf = Vec::with_capacity(size as usize);
        payload.read_to_end(&mut buf).await?;

        if buf.len() < size as usize {
            return Err(ConnectError::UnexpectedEnd);
        }

        if typ != Frame::HEADERS {
            return Err(ConnectError::UnexpectedFrame(typ));
        }

        return Ok(buf);
    }
}

mod protocol_negotiation {
    //! WebTransport sub-protocol negotiation using RFC 8941 Structured Fields,
    //!
    //! according to [draft 14](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-14.html#section-3.3)

    use sfv::{Item, ItemSerializer, List, ListEntry, ListSerializer, Parser, StringRef};

    use crate::ConnectError;

    /// The header name for the available protocols, sent within the WebTransport Connect request.
    pub const AVAILABLE_NAME: &str = "wt-available-protocols";
    /// The header name for the selected protocol, sent within the WebTransport Connect response.
    pub const SELECTED_NAME: &str = "wt-protocol";

    /// Encode a list of protocol strings as an RFC 8941 Structured Field List.
    pub fn encode_list(protocols: &[String]) -> Result<String, ConnectError> {
        let mut serializer = ListSerializer::new();
        for protocol in protocols {
            let s = StringRef::from_str(protocol)?;
            let _ = serializer.bare_item(s);
        }
        serializer.finish().ok_or(ConnectError::InvalidProtocol)
    }

    /// Decode an RFC 8941 Structured Field List of strings.
    pub fn decode_list(value: &str) -> Result<Vec<String>, ConnectError> {
        let list = Parser::new(value).parse::<List>()?;

        list.iter()
            .map(|entry| match entry {
                ListEntry::Item(item) => Ok(item
                    .bare_item
                    .as_string()
                    .ok_or(ConnectError::InvalidProtocol)?
                    .as_str()
                    .to_string()),
                _ => Err(ConnectError::InvalidProtocol),
            })
            .collect()
    }

    /// Encode a single string as an RFC 8941 Structured Field Item.
    pub fn encode_item(protocol: &str) -> Result<String, ConnectError> {
        let s = StringRef::from_str(protocol)?;
        Ok(ItemSerializer::new().bare_item(s).finish())
    }

    /// Decode an RFC 8941 Structured Field Item (single string).
    pub fn decode_item(value: &str) -> Result<String, ConnectError> {
        let item = Parser::new(value).parse::<Item>()?;
        Ok(item
            .bare_item
            .as_string()
            .ok_or(ConnectError::InvalidProtocol)?
            .as_str()
            .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn connect_wire_uses_the_selected_draft_request_and_response_markers() {
        let url = Url::parse("https://example.com/transport").unwrap();
        for draft in [WebTransportDraft::Draft02, WebTransportDraft::Draft16] {
            let mut wire = Vec::new();
            ConnectRequest::new(url.clone())
                .with_draft(draft)
                .encode(&mut wire)
                .unwrap();
            let decoded = ConnectRequest::decode(&mut wire.as_slice()).unwrap();
            assert_eq!(decoded.draft, draft);
            assert_eq!(
                decoded
                    .headers
                    .get("sec-webtransport-http3-draft02")
                    .is_some(),
                draft == WebTransportDraft::Draft02
            );
            if draft == WebTransportDraft::Draft02 {
                assert_eq!(decoded.headers["sec-webtransport-http3-draft02"], "1");
            }
            let mut response_wire = Vec::new();
            ConnectResponse::OK
                .for_draft(draft)
                .encode(&mut response_wire)
                .unwrap();
            let response = ConnectResponse::decode(&mut response_wire.as_slice()).unwrap();
            assert_eq!(
                response.draft_marker.as_deref(),
                if draft == WebTransportDraft::Draft02 {
                    Some("draft02")
                } else {
                    None
                }
            );
        }
    }

    #[test]
    fn malformed_selected_protocol_is_ignored_on_successful_connect() {
        let mut headers = qpack::Headers::default();
        headers.set(":status", "200");
        headers.set("wt-protocol", "\"unterminated");
        let mut encoded = Vec::new();
        headers.encode(&mut encoded);
        let response = ConnectResponse::decode_headers(&mut encoded.as_slice()).unwrap();
        assert_eq!(response.status, http::StatusCode::OK);
        assert_eq!(response.protocol, None);
    }

    #[test]
    fn repeated_available_protocol_fields_combine_as_a_list() {
        let mut headers = qpack::Headers::default();
        headers.set(":method", "CONNECT");
        headers.set(":scheme", "https");
        headers.set(":authority", "example.com");
        headers.set(":path", "/transport");
        headers.set(":protocol", "webtransport");
        headers.set("sec-webtransport-http3-draft02", "1");
        headers.append("wt-available-protocols", "\"one\"");
        headers.append("wt-available-protocols", "\"two\"");
        let mut encoded = Vec::new();
        headers.encode(&mut encoded);

        let request = ConnectRequest::decode_headers(&mut encoded.as_slice()).unwrap();
        assert_eq!(request.protocols, ["one", "two"]);
    }

    #[test]
    fn repeated_selected_protocol_fields_are_ignored() {
        let mut headers = qpack::Headers::default();
        headers.set(":status", "200");
        headers.append("wt-protocol", "\"one\"");
        headers.append("wt-protocol", "\"two\"");
        let mut encoded = Vec::new();
        headers.encode(&mut encoded);

        let response = ConnectResponse::decode_headers(&mut encoded.as_slice()).unwrap();
        assert_eq!(response.protocol, None);
        assert!(response.headers.is_empty());
    }

    #[test]
    fn request_preserves_repeated_header_values_in_order() {
        let url = Url::parse("https://example.com/transport").unwrap();
        let mut request = ConnectRequest::new(url);
        request
            .headers
            .append("x-duplicate", http::HeaderValue::from_static("one"));
        request
            .headers
            .append("x-duplicate", http::HeaderValue::from_static("two"));

        let mut wire = Vec::new();
        request.encode(&mut wire).unwrap();
        let decoded = ConnectRequest::decode(&mut wire.as_slice()).unwrap();
        let values = decoded
            .headers
            .get_all("x-duplicate")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values, ["one", "two"]);

        let mut wire_slice = wire.as_slice();
        let (_, mut block) = Frame::read(&mut wire_slice).unwrap();
        let fields = qpack::Headers::decode(&mut block).unwrap().fields;
        assert!(fields.first().unwrap().0.starts_with(':'));
        assert_eq!(
            fields
                .iter()
                .filter(|(name, _)| name == "x-duplicate")
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            ["one", "two"]
        );
    }

    #[test]
    fn response_preserves_repeated_ordinary_headers() {
        let mut response = ConnectResponse::OK;
        response.headers.push((
            http::HeaderName::from_static("x-response"),
            http::HeaderValue::from_static("one"),
        ));
        response.headers.push((
            http::HeaderName::from_static("x-response"),
            http::HeaderValue::from_static("two"),
        ));
        let mut wire = Vec::new();
        response.encode(&mut wire).unwrap();

        let decoded = ConnectResponse::decode(&mut wire.as_slice()).unwrap();
        let values = decoded
            .headers
            .iter()
            .filter(|(name, _)| name == "x-response")
            .map(|(_, value)| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values, ["one", "two"]);
        assert!(decoded
            .headers
            .iter()
            .all(|(name, _)| name != "sec-webtransport-http3-draft" && name != "wt-protocol"));
    }

    #[test]
    fn duplicate_pseudo_header_is_rejected() {
        let mut headers = qpack::Headers::default();
        headers.append(":status", "200");
        headers.append(":status", "404");
        let mut encoded = Vec::new();
        headers.encode(&mut encoded);
        assert!(matches!(
            ConnectResponse::decode_headers(&mut encoded.as_slice()),
            Err(ConnectError::QpackError(
                qpack::DecodeError::DuplicatePseudoHeader
            ))
        ));
    }

    /// Build a framed CONNECT request on the wire.
    fn encode_request(url: &str) -> Vec<u8> {
        let req = ConnectRequest::new(Url::parse(url).unwrap());
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        buf
    }

    /// Build a framed CONNECT response on the wire.
    fn encode_response() -> Vec<u8> {
        let resp = ConnectResponse::OK;
        let mut buf = Vec::new();
        resp.encode(&mut buf).unwrap();
        buf
    }

    /// Encode a GREASE frame: type (0x21 = first GREASE value) + length + payload.
    fn encode_grease_frame(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        VarInt::from_u32(0x21).encode(&mut buf); // GREASE frame type
        VarInt::from_u32(payload.len() as u32).encode(&mut buf);
        buf.extend_from_slice(payload);
        buf
    }

    // ---- ConnectRequest::read tests ----

    #[tokio::test]
    async fn request_read_exact_consumption() {
        // Verify read() consumes only the frame bytes, not trailing data.
        let mut wire = encode_request("https://example.com/path");
        let trailing = b"trailing data";
        wire.extend_from_slice(trailing);

        let mut cursor = Cursor::new(wire);
        let req = ConnectRequest::read(&mut cursor).await.unwrap();
        assert_eq!(req.url.as_str(), "https://example.com/path");

        // The cursor should be positioned right after the frame, leaving trailing data.
        let pos = cursor.position() as usize;
        let remaining = &cursor.into_inner()[pos..];
        assert_eq!(remaining, trailing);
    }

    #[tokio::test]
    async fn request_read_roundtrip() {
        let wire = encode_request("https://example.com/foo?bar=1");
        let mut cursor = Cursor::new(wire);
        let req = ConnectRequest::read(&mut cursor).await.unwrap();
        assert_eq!(req.url.as_str(), "https://example.com/foo?bar=1");
    }

    #[tokio::test]
    async fn request_read_skips_grease() {
        // Prepend a GREASE frame before the real HEADERS frame.
        let mut wire = encode_grease_frame(b"junk");
        wire.extend_from_slice(&encode_request("https://example.com/"));

        let mut cursor = Cursor::new(wire);
        let req = ConnectRequest::read(&mut cursor).await.unwrap();
        assert_eq!(req.url.as_str(), "https://example.com/");
    }

    #[tokio::test]
    async fn request_read_rejects_frame_too_large() {
        // Craft a frame header claiming a huge payload.
        let mut wire = Vec::new();
        Frame::HEADERS.encode(&mut wire);
        // 128 KiB > MAX_FRAME_SIZE (64 KiB)
        VarInt::from_u32(128 * 1024).encode(&mut wire);

        let mut cursor = Cursor::new(wire);
        let err = ConnectRequest::read(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, ConnectError::FrameTooLarge),
            "expected FrameTooLarge, got {err:?}"
        );
    }

    #[tokio::test]
    async fn request_read_rejects_wrong_frame_type() {
        let mut wire = Vec::new();
        Frame::DATA.encode(&mut wire);
        VarInt::from_u32(0).encode(&mut wire);

        let mut cursor = Cursor::new(wire);
        let err = ConnectRequest::read(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, ConnectError::UnexpectedFrame(f) if f == Frame::DATA),
            "expected UnexpectedFrame(DATA), got {err:?}"
        );
    }

    #[tokio::test]
    async fn request_read_empty_stream() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ConnectRequest::read(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ConnectError::UnexpectedEnd));
    }

    // ---- ConnectResponse::read tests ----

    #[tokio::test]
    async fn response_read_exact_consumption() {
        let mut wire = encode_response();
        let trailing = b"extra bytes";
        wire.extend_from_slice(trailing);

        let mut cursor = Cursor::new(wire);
        let resp = ConnectResponse::read(&mut cursor).await.unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);

        let pos = cursor.position() as usize;
        let remaining = &cursor.into_inner()[pos..];
        assert_eq!(remaining, trailing);
    }

    #[tokio::test]
    async fn response_read_roundtrip() {
        let wire = encode_response();
        let mut cursor = Cursor::new(wire);
        let resp = ConnectResponse::read(&mut cursor).await.unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn response_read_skips_grease() {
        let mut wire = encode_grease_frame(b"grease");
        wire.extend_from_slice(&encode_response());

        let mut cursor = Cursor::new(wire);
        let resp = ConnectResponse::read(&mut cursor).await.unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn response_read_rejects_frame_too_large() {
        let mut wire = Vec::new();
        Frame::HEADERS.encode(&mut wire);
        VarInt::from_u32(128 * 1024).encode(&mut wire);

        let mut cursor = Cursor::new(wire);
        let err = ConnectResponse::read(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, ConnectError::FrameTooLarge),
            "expected FrameTooLarge, got {err:?}"
        );
    }

    #[tokio::test]
    async fn response_read_rejects_wrong_frame_type() {
        let mut wire = Vec::new();
        Frame::SETTINGS.encode(&mut wire);
        VarInt::from_u32(0).encode(&mut wire);

        let mut cursor = Cursor::new(wire);
        let err = ConnectResponse::read(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, ConnectError::UnexpectedFrame(f) if f == Frame::SETTINGS),
            "expected UnexpectedFrame(SETTINGS), got {err:?}"
        );
    }

    #[tokio::test]
    async fn response_read_empty_stream() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let err = ConnectResponse::read(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ConnectError::UnexpectedEnd));
    }

    // ---- Truncated payload tests ----

    #[tokio::test]
    async fn request_read_truncated_payload() {
        // Frame header claims 100 bytes but only 5 are present.
        let mut wire = Vec::new();
        Frame::HEADERS.encode(&mut wire);
        VarInt::from_u32(100).encode(&mut wire);
        wire.extend_from_slice(b"short");

        let mut cursor = Cursor::new(wire);
        let err = ConnectRequest::read(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ConnectError::UnexpectedEnd));
    }

    #[tokio::test]
    async fn response_read_truncated_payload() {
        let mut wire = Vec::new();
        Frame::HEADERS.encode(&mut wire);
        VarInt::from_u32(100).encode(&mut wire);
        wire.extend_from_slice(b"short");

        let mut cursor = Cursor::new(wire);
        let err = ConnectResponse::read(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ConnectError::UnexpectedEnd));
    }

    #[tokio::test]
    async fn request_read_truncated_grease() {
        // GREASE frame claims 100 bytes but only 3 are present.
        let mut wire = Vec::new();
        VarInt::from_u32(0x21).encode(&mut wire);
        VarInt::from_u32(100).encode(&mut wire);
        wire.extend_from_slice(b"abc");

        let mut cursor = Cursor::new(wire);
        let err = ConnectRequest::read(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ConnectError::UnexpectedEnd));
    }
}
