use super::*;
use crate::circuit_breakers::{AdmissionRejection, AdmissionRejectionReason};

#[test]
fn local_admission_rejections_are_not_endpoint_failures() {
  for reason in [
    AdmissionRejectionReason::ActiveLimit,
    AdmissionRejectionReason::QueueTimeout,
  ] {
    let rejection = AdmissionRejection {
      reason,
      retry_after: Duration::from_millis(25),
    };
    let error = anyhow::Error::new(rejection);
    assert_eq!(admission_rejection(&error), Some(rejection));
  }

  assert!(admission_rejection(&anyhow::anyhow!("connect failed")).is_none());
}

#[test]
fn family_interleave_preserves_bounded_rotation_order() {
  let addresses = vec![
    "[::1]:443".parse().unwrap(),
    "[::2]:443".parse().unwrap(),
    "127.0.0.1:443".parse().unwrap(),
    "127.0.0.2:443".parse().unwrap(),
  ];
  assert_eq!(
    interleave_families(addresses),
    vec![
      "[::1]:443".parse().unwrap(),
      "127.0.0.1:443".parse().unwrap(),
      "[::2]:443".parse().unwrap(),
      "127.0.0.2:443".parse().unwrap(),
    ]
  );
}

#[test]
fn one_success_preference_then_rotation_reaches_every_candidate() {
  let candidates = vec![
    "127.0.0.1:443".parse().unwrap(),
    "127.0.0.2:443".parse().unwrap(),
    "127.0.0.3:443".parse().unwrap(),
  ];
  let mut health = EndpointSelectionState::default();
  let initial_winner = rotate_with_preference(candidates.clone(), &mut health).0[0];
  health.preferred = Some(PreferredEndpoint {
    address: initial_winner,
    remaining: RECENT_SUCCESS_PREFERENCE_USES,
  });
  let preferred_once = rotate_with_preference(candidates.clone(), &mut health).0[0];
  let next_rotated = rotate_with_preference(candidates.clone(), &mut health).0[0];
  let final_rotated = rotate_with_preference(candidates.clone(), &mut health).0[0];
  assert_eq!(initial_winner, candidates[0]);
  assert_eq!(preferred_once, candidates[0]);
  assert_eq!(next_rotated, candidates[1]);
  assert_eq!(final_rotated, candidates[2]);
}
