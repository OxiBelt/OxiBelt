// WebTransport shares with HTTP/3, so we can't start at 0 or use the full VarInt.
const ERROR_FIRST: u64 = 0x52e4a40fa8db;
const ERROR_LAST: u64 = 0x52e5ac983162;

pub const fn error_from_http3(code: u64) -> Option<u32> {
    if code < ERROR_FIRST || code > ERROR_LAST {
        return None;
    }

    let code = code - ERROR_FIRST;
    // HTTP/3 reserves every 31st wire codepoint in this range for GREASE.
    // Those values are not WebTransport application errors.
    if code % 0x1f == 0x1e {
        return None;
    }
    let code = code - code / 0x1f;

    Some(code as u32)
}

pub const fn error_to_http3(code: u32) -> u64 {
    ERROR_FIRST + code as u64 + code as u64 / 0x1e
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_error_codes_skip_reserved_http3_values() {
        for code in [0, 1, 29, 30, 31, 59, 60, 61, u32::MAX] {
            let wire = error_to_http3(code);
            assert_eq!(error_from_http3(wire), Some(code));
            assert_ne!((wire - ERROR_FIRST) % 0x1f, 0x1e);
        }

        assert_eq!(error_to_http3(0), ERROR_FIRST);
        assert_eq!(error_to_http3(29), ERROR_FIRST + 29);
        assert_eq!(error_to_http3(30), ERROR_FIRST + 31);
        assert_eq!(error_to_http3(u32::MAX), ERROR_LAST);

        for wire in [ERROR_FIRST + 30, ERROR_FIRST + 61] {
            assert_eq!(error_from_http3(wire), None);
        }
        assert_eq!(error_from_http3(ERROR_FIRST - 1), None);
        assert_eq!(error_from_http3(ERROR_LAST + 1), None);
    }
}
