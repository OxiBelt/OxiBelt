//! Test-support allocator contract diagnostic; its duration is not a performance result.

#![deny(unsafe_code)]

use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread;

#[cfg(all(
  feature = "allocator-mimalloc-experiment",
  not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64",
    any(target_env = "gnu", target_env = "musl")
  ))
))]
compile_error!(
  "allocator-mimalloc-experiment supports only 64-bit x86 Linux GNU and musl targets."
);

#[cfg(feature = "allocator-mimalloc-experiment")]
#[global_allocator]
static GLOBAL_ALLOCATOR: oxibelt_allocator::Mimalloc = oxibelt_allocator::Mimalloc;

const THREADS: usize = 8;
const ITERATIONS: usize = 1_000;
const MAX_VECTOR_CAPACITY: usize = 64 * 1024;

#[repr(align(4096))]
struct AlignedBytes([u8; 8192]);

struct Transfer {
  origin: usize,
  iteration: usize,
  bytes: Vec<u8>,
  aligned: Box<AlignedBytes>,
}

fn pattern(seed: usize, index: usize) -> u8 {
  (seed.wrapping_add(index.wrapping_mul(31)) & 0xff) as u8
}

fn assert_pattern(bytes: &[u8], seed: usize) {
  for (index, value) in bytes.iter().enumerate() {
    assert_eq!(*value, pattern(seed, index), "data changed at byte {index}");
  }
}

fn fill_pattern(bytes: &mut [u8], seed: usize) {
  for (index, value) in bytes.iter_mut().enumerate() {
    *value = pattern(seed, index);
  }
}

fn grow_and_check(bytes: &mut Vec<u8>, seed: usize, additional: usize) {
  let previous_len = bytes.len();
  let new_len = bytes.capacity() + additional;
  assert!(new_len <= MAX_VECTOR_CAPACITY);
  bytes.resize(new_len, 0);
  assert!(bytes.capacity() <= MAX_VECTOR_CAPACITY);
  assert_pattern(&bytes[..previous_len], seed);
  assert!(bytes[previous_len..].iter().all(|byte| *byte == 0));
  fill_pattern(bytes, seed);
}

fn assert_alignment(bytes: &AlignedBytes) {
  assert_eq!((std::ptr::from_ref(bytes) as usize) % 4096, 0);
}

fn exercise_worker(worker: usize, sender: SyncSender<Transfer>, receiver: Receiver<Transfer>) {
  for iteration in 0..ITERATIONS {
    let seed = worker * ITERATIONS + iteration;
    let mut bytes = vec![0; 4096 + iteration % 4096];
    assert!(bytes.iter().all(|byte| *byte == 0));
    fill_pattern(&mut bytes, seed);
    grow_and_check(&mut bytes, seed, 8192);

    let mut aligned = Box::new(AlignedBytes([0; 8192]));
    assert_alignment(&aligned);
    assert!(aligned.0.iter().all(|byte| *byte == 0));
    fill_pattern(&mut aligned.0, seed);

    sender
      .send(Transfer {
        origin: worker,
        iteration,
        bytes,
        aligned,
      })
      .expect("next worker must accept the owned allocations");
    let mut received = receiver
      .recv()
      .expect("previous worker must transfer its owned allocations");
    assert_eq!(received.origin, (worker + THREADS - 1) % THREADS);
    assert_eq!(received.iteration, iteration);
    let received_seed = received.origin * ITERATIONS + received.iteration;
    assert_pattern(&received.bytes, received_seed);
    assert_alignment(&received.aligned);
    assert_pattern(&received.aligned.0, received_seed);

    // Growth and shrinking happen on a different thread from initial allocation.
    grow_and_check(&mut received.bytes, received_seed, 4096);
    received.bytes.truncate(received.bytes.len() / 2);
    received.bytes.shrink_to_fit();
    assert_pattern(&received.bytes, received_seed);
    drop(received);
  }
}

fn main() {
  // One queued transfer per worker bounds live payloads to a few MiB. Explicit
  // 256 KiB stacks also keep the eight-worker diagnostic well below 128 MiB.
  let (senders, receivers): (Vec<_>, Vec<_>) = (0..THREADS).map(|_| sync_channel(1)).unzip();
  let workers = receivers
    .into_iter()
    .enumerate()
    .map(|(worker, receiver)| {
      let sender = senders[(worker + 1) % THREADS].clone();
      thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || exercise_worker(worker, sender, receiver))
        .expect("diagnostic worker must start")
    })
    .collect::<Vec<_>>();
  // A worker failure closes its receiver and propagates through the ring. Main
  // must not retain senders that could prevent the remaining receivers exiting.
  drop(senders);
  let failures = workers
    .into_iter()
    .map(|worker| worker.join())
    .filter(Result::is_err)
    .count();
  assert_eq!(failures, 0, "allocator contract diagnostic worker failed");

  let variant = if cfg!(feature = "allocator-mimalloc-experiment") {
    "mimalloc-secure"
  } else {
    "system"
  };
  println!(
    "{{\"allocator_variant\":\"{variant}\",\"threads\":{THREADS},\"iterations_per_thread\":{ITERATIONS},\"checks\":{{\"alignment_4096\":\"PASS\",\"zero_initialization\":\"PASS\",\"growth_preserves_data\":\"PASS\",\"cross_thread_transfer_reallocation_drop\":\"PASS\"}}}}"
  );
}
