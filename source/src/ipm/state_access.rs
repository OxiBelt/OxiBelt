//! Poison-aware access to the disposable IPM refresh-status snapshot.

use super::{IpmRefreshState, IpmRuntimeInner};

impl IpmRuntimeInner {
  pub(super) fn refresh_state(&self) -> IpmRefreshState {
    match self.last_refresh.read() {
      Ok(state) => state.clone(),
      Err(poisoned) => {
        let state = poisoned.into_inner().clone();
        self.last_refresh.clear_poison();
        state
      }
    }
  }

  pub(super) fn set_refresh_state(&self, next: IpmRefreshState) {
    match self.last_refresh.write() {
      Ok(mut state) => *state = next,
      Err(poisoned) => {
        *poisoned.into_inner() = next;
        self.last_refresh.clear_poison();
      }
    }
  }
}
