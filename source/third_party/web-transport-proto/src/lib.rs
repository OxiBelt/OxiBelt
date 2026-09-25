mod capsule;
mod connect;
mod error;
mod frame;
mod flow;
mod settings;
mod stream;
mod varint;

pub use capsule::*;
pub use connect::*;
pub use error::*;
pub use frame::*;
pub use flow::*;
pub use settings::*;
pub use stream::*;
pub use varint::*;

/// WebTransport over HTTP/3 wire dialect used for a connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WebTransportDraft {
    #[default]
    Draft02,
    Draft16,
}

pub use http;

mod huffman;
mod qpack;
