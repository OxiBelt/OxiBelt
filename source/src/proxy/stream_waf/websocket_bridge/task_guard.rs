use tokio::task::JoinHandle;

pub(super) struct AbortTaskOnDrop<'a, T>(pub(super) &'a mut JoinHandle<T>);

impl<T> Drop for AbortTaskOnDrop<'_, T> {
  fn drop(&mut self) {
    self.0.abort();
  }
}
