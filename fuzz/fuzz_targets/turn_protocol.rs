#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use oxibelt::turn::protocol::{
    ATTR_CHANNEL_NUMBER, ATTR_DATA, ATTR_ERROR_CODE, ATTR_FINGERPRINT, ATTR_LIFETIME,
    ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_REQUESTED_TRANSPORT, ATTR_USERNAME,
    ATTR_XOR_MAPPED_ADDRESS, ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS, BINDING_REQUEST,
    CHANNEL_BIND_REQUEST, CREATE_PERMISSION_REQUEST, DATA_INDICATION, SEND_INDICATION, attr_bytes,
    attr_string, attr_u32, attr_xor_addr, decode_xor_address, encode_channel_data, encode_message,
    encode_xor_address, parse_channel_data, parse_stun, verify_fingerprint,
    verify_message_integrity,
};

const MAX_ATTRS: usize = 8;
const MAX_ATTR_VALUE_BYTES: usize = 64;
const MAX_CHANNEL_PAYLOAD_BYTES: usize = 128;
const MAX_RAW_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_RAW_BYTES)];
    exercise_raw_parsers(data);
    exercise_generated_stun(data);
    exercise_generated_channel_data(data);
});

fn exercise_raw_parsers(data: &[u8]) {
    if let Ok(message) = parse_stun(data) {
        exercise_stun_helpers(&message, data);
    }

    let _ = parse_channel_data(data);
}

fn exercise_stun_helpers(message: &oxibelt::turn::protocol::StunMessage<'_>, key: &[u8]) {
    let _ = verify_fingerprint(message);
    let _ = verify_message_integrity(message, key);

    for kind in helper_attr_kinds() {
        let _ = attr_string(message, kind);
        let _ = attr_u32(message, kind);
        let _ = attr_bytes(message, kind);
        let _ = attr_xor_addr(message, kind);
    }
}

fn exercise_generated_stun(data: &[u8]) {
    let mut input = FuzzInput::new(data);
    let transaction_id = input.transaction_id();
    let message_type = input.message_type();
    let attrs = input.attrs(&transaction_id);

    let encoded = encode_message(message_type, transaction_id, &attrs);
    if let Ok(message) = parse_stun(&encoded) {
        exercise_stun_helpers(&message, data);
    }
}

fn exercise_generated_channel_data(data: &[u8]) {
    let mut input = FuzzInput::new(data);
    let channel = 0x4000 | (input.u16() & 0x0fff);
    let payload_len = input.usize(MAX_CHANNEL_PAYLOAD_BYTES + 1);
    let payload = input.bytes(payload_len);

    if let Ok(encoded) = encode_channel_data(channel, &payload) {
        let _ = parse_channel_data(&encoded);
    }
}

fn helper_attr_kinds() -> [u16; 12] {
    [
        ATTR_USERNAME,
        ATTR_MESSAGE_INTEGRITY,
        ATTR_ERROR_CODE,
        ATTR_CHANNEL_NUMBER,
        ATTR_LIFETIME,
        ATTR_XOR_PEER_ADDRESS,
        ATTR_DATA,
        ATTR_REALM,
        ATTR_NONCE,
        ATTR_XOR_RELAYED_ADDRESS,
        ATTR_REQUESTED_TRANSPORT,
        ATTR_XOR_MAPPED_ADDRESS,
    ]
}

struct FuzzInput<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> FuzzInput<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let byte = self.data[self.offset % self.data.len()];
        self.offset = self.offset.wrapping_add(1);
        byte
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.byte(), self.byte()])
    }

    fn usize(&mut self, modulo: usize) -> usize {
        if modulo == 0 {
            return 0;
        }
        ((self.u16() as usize) ^ (self.byte() as usize)) % modulo
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    fn transaction_id(&mut self) -> [u8; 12] {
        let mut transaction_id = [0u8; 12];
        for byte in &mut transaction_id {
            *byte = self.byte();
        }
        transaction_id
    }

    fn message_type(&mut self) -> u16 {
        match self.byte() % 5 {
            0 => BINDING_REQUEST,
            1 => CREATE_PERMISSION_REQUEST,
            2 => CHANNEL_BIND_REQUEST,
            3 => SEND_INDICATION,
            _ => DATA_INDICATION,
        }
    }

    fn attrs(&mut self, transaction_id: &[u8; 12]) -> Vec<(u16, Vec<u8>)> {
        let attr_count = self.usize(MAX_ATTRS + 1);
        (0..attr_count)
            .map(|_| {
                let kind = helper_attr_kinds()[self.usize(helper_attr_kinds().len())];
                let value = self.attr_value(kind, transaction_id);
                (kind, value)
            })
            .collect()
    }

    fn attr_value(&mut self, kind: u16, transaction_id: &[u8; 12]) -> Vec<u8> {
        match kind {
            ATTR_CHANNEL_NUMBER | ATTR_LIFETIME | ATTR_REQUESTED_TRANSPORT | ATTR_FINGERPRINT => {
                self.bytes(4)
            }
            ATTR_XOR_PEER_ADDRESS | ATTR_XOR_RELAYED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS => {
                let addr = self.socket_addr();
                let encoded = encode_xor_address(addr, transaction_id);
                let _ = decode_xor_address(&encoded, transaction_id);
                encoded
            }
            _ => {
                let len = self.usize(MAX_ATTR_VALUE_BYTES + 1);
                self.bytes(len)
            }
        }
    }

    fn socket_addr(&mut self) -> SocketAddr {
        let port = self.u16();
        if self.byte() & 1 == 0 {
            SocketAddr::from((
                Ipv4Addr::new(self.byte(), self.byte(), self.byte(), self.byte()),
                port,
            ))
        } else {
            let mut octets = [0u8; 16];
            for byte in &mut octets {
                *byte = self.byte();
            }
            SocketAddr::from((Ipv6Addr::from(octets), port))
        }
    }
}
