//! Logical flow and exact refundable-reservation API.

use std::sync::Arc;
use std::time::Duration;

use super::{
  AcquisitionRequest, BandwidthDirection, BandwidthError, BandwidthFlow, BandwidthGrant,
  BandwidthRate, Reservation, RouteBandwidthLimiter,
};

impl BandwidthFlow {
  pub const fn direction(&self) -> BandwidthDirection {
    self.direction
  }

  /// Reports whether the active policy currently limits this flow's direction.
  pub fn is_limited(&self) -> Result<bool, BandwidthError> {
    self
      .limiter
      .policy()
      .map(|policy| policy.rate(self.direction) != BandwidthRate::Unlimited)
  }

  /// Reserves a positive, scheduler-bounded portion of `requested_bytes`.
  ///
  /// Limited grants never exceed [`super::BANDWIDTH_QUANTUM_BYTES`]. Unlimited
  /// grants return the whole request.
  pub async fn acquire(
    &mut self,
    requested_bytes: usize,
  ) -> Result<BandwidthGrant, BandwidthError> {
    self
      .limiter
      .acquire(
        self.id,
        self.direction,
        AcquisitionRequest::Divisible(requested_bytes),
      )
      .await
      .map(|acquired| acquired.grant)
  }

  /// Reserves a scheduler-bounded grant that can be returned exactly once.
  ///
  /// This is used when security inspection must account for payload before it
  /// can decide whether the payload may be forwarded. Dropping the token
  /// returns the exact reservation; blocked payload explicitly commits it.
  pub(crate) async fn acquire_refundable(
    &mut self,
    requested_bytes: usize,
  ) -> Result<RefundableBandwidthGrant, BandwidthError> {
    let acquired = self
      .limiter
      .acquire(
        self.id,
        self.direction,
        AcquisitionRequest::Divisible(requested_bytes),
      )
      .await?;
    Ok(RefundableBandwidthGrant {
      grant: acquired.grant,
      limiter: Arc::clone(&self.limiter),
      direction: self.direction,
      flow_id: self.id,
      reservation: Some(acquired.reservation),
    })
  }

  /// Reserves one indivisible protocol item, permitting explicitly bounded debt.
  ///
  /// Items no larger than the bucket capacity wait for their full byte count.
  /// A larger item is admitted only from a full bucket and only when the excess
  /// is at most `max_debt_bytes`. Later refill repays debt before producing new
  /// credit.
  pub async fn acquire_indivisible(
    &mut self,
    item_bytes: usize,
    max_debt_bytes: usize,
  ) -> Result<BandwidthGrant, BandwidthError> {
    self
      .limiter
      .acquire(
        self.id,
        self.direction,
        AcquisitionRequest::Indivisible {
          bytes: item_bytes,
          max_debt_bytes,
        },
      )
      .await
      .map(|acquired| acquired.grant)
  }
}

/// An exact divisible reservation held across a security decision.
pub(crate) struct RefundableBandwidthGrant {
  grant: BandwidthGrant,
  limiter: Arc<RouteBandwidthLimiter>,
  direction: BandwidthDirection,
  flow_id: u64,
  reservation: Option<Reservation>,
}

impl RefundableBandwidthGrant {
  pub(crate) const fn bytes(&self) -> usize {
    self.grant.bytes()
  }

  pub(crate) const fn waited(&self) -> Duration {
    self.grant.waited()
  }

  /// Keeps this payload charged and consumes the refund capability.
  pub(crate) fn commit(mut self) -> BandwidthGrant {
    self.reservation = None;
    self.grant
  }

  /// Returns this exact reservation to the active bucket policy.
  pub(crate) fn refund(mut self) {
    self.refund_inner();
  }

  /// Coalesces exact reservations from the same flow without growing a token
  /// vector for attacker-controlled message sizes.
  pub(crate) fn merge(&mut self, mut other: Self) -> Result<(), BandwidthError> {
    if !Arc::ptr_eq(&self.limiter, &other.limiter)
      || self.direction != other.direction
      || self.flow_id != other.flow_id
      || self.reservation.is_none()
      || other.reservation.is_none()
    {
      return Err(BandwidthError::ReservationMismatch);
    }
    let other_reservation = other
      .reservation
      .take()
      .ok_or(BandwidthError::ReservationMismatch)?;
    let reservation = self
      .reservation
      .as_mut()
      .ok_or(BandwidthError::ReservationMismatch)?;
    reservation.bytes = reservation.bytes.saturating_add(other_reservation.bytes);
    reservation.credit_units = reservation
      .credit_units
      .saturating_add(other_reservation.credit_units);
    reservation.debt_units = reservation
      .debt_units
      .saturating_add(other_reservation.debt_units);
    self.grant.bytes = self.grant.bytes.saturating_add(other.grant.bytes);
    self.grant.waited = self.grant.waited.saturating_add(other.grant.waited);
    Ok(())
  }

  fn refund_inner(&mut self) {
    if let Some(reservation) = self.reservation.take() {
      self.limiter.refund_reservation(self.direction, reservation);
    }
  }
}

impl Drop for RefundableBandwidthGrant {
  fn drop(&mut self) {
    self.refund_inner();
  }
}
