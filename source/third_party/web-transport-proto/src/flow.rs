//! Draft-16 WebTransport session flow control. All limits are cumulative.

use crate::{Capsule, VarInt};

pub const MAX_STREAMS: u64 = 1 << 60;
pub const WT_FLOW_CONTROL_ERROR: u64 = 0x045d4487;
pub const WT_MAX_DATA: u64 = 0x190b4d3d;
pub const WT_MAX_STREAMS_BIDI: u64 = 0x190b4d3f;
pub const WT_MAX_STREAMS_UNI: u64 = 0x190b4d40;
pub const WT_DATA_BLOCKED: u64 = 0x190b4d41;
pub const WT_STREAMS_BLOCKED_BIDI: u64 = 0x190b4d43;
pub const WT_STREAMS_BLOCKED_UNI: u64 = 0x190b4d44;
const WT_MAX_STREAM_DATA: u64 = 0x190b4d3e;
const WT_STREAM_DATA_BLOCKED: u64 = 0x190b4d42;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FlowError {
    #[error("WebTransport flow limit exceeded")]
    Exceeded,
    #[error("WebTransport credit did not increase")]
    NonIncreasing,
    #[error("invalid WebTransport flow capsule")]
    InvalidCapsule,
    #[error("forbidden WebTransport flow capsule")]
    ForbiddenCapsule,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FlowCredit {
    pub max_uni: u64,
    pub max_bidi: u64,
    pub max_data: u64,
    pub opened_uni: u64,
    pub opened_bidi: u64,
    pub used_data: u64,
}

impl FlowCredit {
    pub fn new(max_uni: u64, max_bidi: u64, max_data: u64) -> Result<Self, FlowError> {
        if max_uni > MAX_STREAMS || max_bidi > MAX_STREAMS {
            return Err(FlowError::Exceeded);
        }
        Ok(Self { max_uni, max_bidi, max_data, ..Self::default() })
    }

    pub fn open_uni(&mut self) -> Result<(), FlowError> {
        Self::advance(&mut self.opened_uni, 1, self.max_uni)
    }

    pub fn open_bidi(&mut self) -> Result<(), FlowError> {
        Self::advance(&mut self.opened_bidi, 1, self.max_bidi)
    }

    pub fn use_data(&mut self, bytes: u64) -> Result<(), FlowError> {
        Self::advance(&mut self.used_data, bytes, self.max_data)
    }

    /// Account for the final stream size once, including bytes that a reset discarded.
    /// `body_seen` excludes the association header; `final_size` includes it.
    pub fn reset_final_size(
        &mut self,
        body_seen: u64,
        final_size: u64,
        header_size: u64,
    ) -> Result<(), FlowError> {
        let final_body = final_size.checked_sub(header_size).ok_or(FlowError::InvalidCapsule)?;
        let remaining = final_body.checked_sub(body_seen).ok_or(FlowError::InvalidCapsule)?;
        self.use_data(remaining)
    }

    fn advance(current: &mut u64, delta: u64, maximum: u64) -> Result<(), FlowError> {
        let next = current.checked_add(delta).ok_or(FlowError::Exceeded)?;
        if next > maximum { return Err(FlowError::Exceeded); }
        *current = next;
        Ok(())
    }

    pub fn apply_capsule(&mut self, capsule: &Capsule) -> Result<bool, FlowError> {
        let Capsule::Unknown { typ, payload } = capsule else { return Ok(false); };
        let kind = typ.into_inner();
        if matches!(kind, WT_MAX_STREAM_DATA | WT_STREAM_DATA_BLOCKED) {
            return Err(FlowError::ForbiddenCapsule);
        }
        if !matches!(kind, WT_MAX_DATA | WT_MAX_STREAMS_BIDI | WT_MAX_STREAMS_UNI
            | WT_DATA_BLOCKED | WT_STREAMS_BLOCKED_BIDI | WT_STREAMS_BLOCKED_UNI) {
            return Ok(false);
        }
        let mut bytes = payload.as_ref();
        let value = VarInt::decode(&mut bytes).map_err(|_| FlowError::InvalidCapsule)?.into_inner();
        if !bytes.is_empty() { return Err(FlowError::InvalidCapsule); }
        match kind {
            WT_MAX_DATA => Self::raise(&mut self.max_data, value, u64::MAX)?,
            WT_MAX_STREAMS_BIDI => Self::raise(&mut self.max_bidi, value, MAX_STREAMS)?,
            WT_MAX_STREAMS_UNI => Self::raise(&mut self.max_uni, value, MAX_STREAMS)?,
            WT_STREAMS_BLOCKED_BIDI | WT_STREAMS_BLOCKED_UNI if value > MAX_STREAMS => return Err(FlowError::Exceeded),
            _ => {}
        }
        Ok(true)
    }

    fn raise(current: &mut u64, value: u64, cap: u64) -> Result<(), FlowError> {
        if value > cap { return Err(FlowError::Exceeded); }
        if value <= *current { return Err(FlowError::NonIncreasing); }
        *current = value;
        Ok(())
    }

    pub fn credit_capsule(kind: u64, value: u64) -> Result<Capsule, FlowError> {
        if !matches!(kind, WT_MAX_DATA | WT_MAX_STREAMS_UNI | WT_MAX_STREAMS_BIDI) {
            return Err(FlowError::InvalidCapsule);
        }
        if kind != WT_MAX_DATA && value > MAX_STREAMS { return Err(FlowError::Exceeded); }
        let value = VarInt::try_from(value).map_err(|_| FlowError::Exceeded)?;
        let mut payload = Vec::new();
        value.encode(&mut payload);
        Ok(Capsule::Unknown {
            typ: VarInt::try_from(kind).map_err(|_| FlowError::InvalidCapsule)?,
            payload: payload.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_credit_then_grant_and_exact_data_boundary() {
        let mut credit = FlowCredit::new(0, 0, 0).unwrap();
        assert_eq!(credit.open_uni(), Err(FlowError::Exceeded));
        assert_eq!(credit.use_data(1), Err(FlowError::Exceeded));
        credit.apply_capsule(&FlowCredit::credit_capsule(WT_MAX_STREAMS_UNI, 1).unwrap()).unwrap();
        credit.apply_capsule(&FlowCredit::credit_capsule(WT_MAX_DATA, 4).unwrap()).unwrap();
        credit.open_uni().unwrap();
        credit.use_data(4).unwrap();
        assert_eq!(credit.use_data(1), Err(FlowError::Exceeded));
        assert_eq!(credit.open_uni(), Err(FlowError::Exceeded));
    }

    #[test]
    fn rejects_bad_credit_and_forbidden_h2_capsules() {
        let mut credit = FlowCredit::new(0, 0, 0).unwrap();
        for kind in [WT_MAX_STREAMS_BIDI, WT_MAX_STREAMS_UNI, WT_MAX_DATA] {
            let capsule = FlowCredit::credit_capsule(kind, 1).unwrap();
            credit.apply_capsule(&capsule).unwrap();
            assert_eq!(credit.apply_capsule(&capsule), Err(FlowError::NonIncreasing));
        }
        let mut encoded = Vec::new();
        VarInt::try_from(MAX_STREAMS + 1).unwrap().encode(&mut encoded);
        let oversized = Capsule::Unknown { typ: VarInt::try_from(WT_MAX_STREAMS_BIDI).unwrap(), payload: encoded.into() };
        assert_eq!(credit.apply_capsule(&oversized), Err(FlowError::Exceeded));
        for kind in [WT_MAX_STREAM_DATA, WT_STREAM_DATA_BLOCKED] {
            let capsule = Capsule::Unknown { typ: VarInt::try_from(kind).unwrap(), payload: Default::default() };
            assert_eq!(credit.apply_capsule(&capsule), Err(FlowError::ForbiddenCapsule));
        }
    }

    #[test]
    fn reset_charges_final_body_size_once() {
        let mut credit = FlowCredit::new(0, 0, 10).unwrap();
        credit.use_data(2).unwrap();
        credit.reset_final_size(2, 15, 5).unwrap();
        assert_eq!(credit.used_data, 10);
        assert_eq!(credit.reset_final_size(10, 16, 5), Err(FlowError::Exceeded));
    }
}
