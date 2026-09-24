/// RFC 9846 section 4.7.3 limits the sending epoch to 2^48-1.
#[derive(Default)]
pub(crate) struct SendingEpoch(u64);

impl SendingEpoch {
    const MAX: u64 = (1 << 48) - 1;

    pub(crate) fn advance(&mut self) -> bool {
        if self.0 == Self::MAX {
            return false;
        }
        self.0 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::SendingEpoch;

    #[test]
    fn sender_limit_applies_to_local_and_peer_requested_updates() {
        let mut local_request = SendingEpoch(SendingEpoch::MAX - 1);
        assert!(local_request.advance());
        assert_eq!(local_request.0, SendingEpoch::MAX);
        assert!(!local_request.advance());
        assert_eq!(local_request.0, SendingEpoch::MAX);

        let mut peer_requested_response = SendingEpoch(SendingEpoch::MAX);
        assert!(!peer_requested_response.advance());
        assert_eq!(peer_requested_response.0, SendingEpoch::MAX);
    }
}
