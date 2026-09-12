//! OxiBelt-owned bridge from Rust's allocation contract to the governed native mimalloc build.
//!
//! # Safety model
//!
//! - Only the integrated executable and allocator checker install this allocator. This crate
//!   neither installs a global allocator nor changes the embedding library's ownership.
//! - `GlobalAlloc` callers supply a valid nonzero `Layout`; reallocation additionally requires
//!   a nonzero new size whose alignment-rounded size fits in `isize`. Those trait obligations
//!   establish the native allocation functions' size and power-of-two alignment preconditions.
//! - The supported Linux x86_64 GNU/musl ABI represents C `size_t` with Rust `usize`. Pointers
//!   cross the boundary unchanged and belong exclusively to this native allocator until freed.
//! - Native success provides the requested size and alignment. Zeroed allocation initializes
//!   every requested byte; reallocation preserves the smaller requested extent. A null return
//!   from reallocation leaves the original allocation live and unchanged. Newly grown bytes
//!   are not promised to be initialized.
//! - Deallocation and reallocation require a live pointer allocated by this allocator and its
//!   current layout. The caller prevents concurrent access during those operations and double
//!   frees. Native mimalloc supports ownership transfer between threads and thread exit.
//! - The bridge never allocates recursively, logs, panics, installs callbacks, or unwinds.
//!   Native code must not unwind across the C ABI. It owns its internal synchronization and
//!   process-wide allocator state; no Rust references or file descriptors cross this boundary.
//! - Build integration must provide the reviewed secure native implementation with matching
//!   declarations, without C malloc/free overrides. Other targets compile an empty bridge
//!   and no native allocator, leaving executable allocator selection to the caller.

// Adapted from the mimalloc and libmimalloc-sys Rust bindings:
// Copyright 2019 Octavian Oncescu
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this
// software and associated documentation files (the "Software"), to deal in the Software
// without restriction, including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
// to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
// FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

#![no_std]
#![allow(
  unsafe_code,
  reason = "the private GlobalAlloc adapter must call the governed native allocator through its C ABI"
)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg(all(
  feature = "native-mimalloc",
  target_os = "linux",
  target_arch = "x86_64",
  target_pointer_width = "64",
  any(target_env = "gnu", target_env = "musl")
))]

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

// SAFETY: These declarations match the governed mimalloc header on the supported C ABI.
unsafe extern "C" {
  fn mi_malloc_aligned(size: usize, alignment: usize) -> *mut c_void;
  fn mi_zalloc_aligned(size: usize, alignment: usize) -> *mut c_void;
  fn mi_realloc_aligned(pointer: *mut c_void, new_size: usize, alignment: usize) -> *mut c_void;
  fn mi_free(pointer: *mut c_void);
}

/// Stateless adapter from Rust's global-allocation contract to governed mimalloc.
pub struct Mimalloc;

// SAFETY: The native functions satisfy GlobalAlloc's allocation, alignment, zeroing, failure,
// and cross-thread ownership contracts. This stateless bridge preserves their pointers and
// size arguments and performs no operation that can recurse into allocation or unwind.
unsafe impl GlobalAlloc for Mimalloc {
  #[inline]
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    // SAFETY: The caller supplies a valid nonzero allocation layout; its size and alignment
    // satisfy mi_malloc_aligned, whose result is either null or a suitably aligned allocation.
    unsafe { mi_malloc_aligned(layout.size(), layout.align()) }.cast()
  }

  #[inline]
  unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
    // SAFETY: The valid nonzero layout satisfies mi_zalloc_aligned, which initializes every
    // requested byte on success and returns null on allocation failure.
    unsafe { mi_zalloc_aligned(layout.size(), layout.align()) }.cast()
  }

  #[inline]
  unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
    // SAFETY: The caller transfers a live allocation from this allocator exactly once;
    // mi_free accepts its original pointer and does not require the Rust layout argument.
    unsafe { mi_free(pointer.cast()) };
  }

  #[inline]
  unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    // SAFETY: The caller supplies this allocator's live pointer, its current alignment, and
    // a valid nonzero new size. Native failure retains the old allocation; success preserves
    // the required prefix and transfers ownership to the returned pointer.
    unsafe { mi_realloc_aligned(pointer.cast(), new_size, layout.align()) }.cast()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn aligned_zeroed_allocation_preserves_contents_across_growth_and_shrink() {
    let allocator = Mimalloc;
    let initial = Layout::from_size_align(8192, 4096).expect("valid test layout");
    // SAFETY: The test layout has a nonzero size and valid alignment.
    let pointer = unsafe { allocator.alloc_zeroed(initial) };
    assert!(!pointer.is_null(), "small test allocation failed");
    assert_eq!(pointer as usize % initial.align(), 0);
    // SAFETY: Allocation success provides exclusive access to all 8192 initialized bytes.
    let bytes = unsafe { core::slice::from_raw_parts_mut(pointer, initial.size()) };
    assert!(bytes.iter().all(|byte| *byte == 0));
    bytes.fill(0x5c);

    let grown = Layout::from_size_align(16384, initial.align()).expect("valid grown layout");
    // SAFETY: The live pointer has the initial layout, its slice borrow has ended, and the
    // nonzero grown size fits the original alignment without exceeding isize::MAX.
    let pointer = unsafe { allocator.realloc(pointer, initial, grown.size()) };
    assert!(!pointer.is_null(), "small test reallocation failed");
    assert_eq!(pointer as usize % grown.align(), 0);
    // SAFETY: Reallocation preserves the initialized initial-size prefix. The uninitialized
    // grown tail is deliberately excluded from the slice and is never read.
    let prefix = unsafe { core::slice::from_raw_parts(pointer, initial.size()) };
    assert!(prefix.iter().all(|byte| *byte == 0x5c));

    let shrunk = Layout::from_size_align(4096, grown.align()).expect("valid shrunk layout");
    // SAFETY: The pointer now has the grown layout and no live borrow; the shrink size is
    // nonzero and valid for the unchanged alignment.
    let pointer = unsafe { allocator.realloc(pointer, grown, shrunk.size()) };
    assert!(!pointer.is_null(), "small test shrink failed");
    assert_eq!(pointer as usize % shrunk.align(), 0);
    // SAFETY: Successful shrink preserves this entire initialized prefix.
    let prefix = unsafe { core::slice::from_raw_parts(pointer, shrunk.size()) };
    assert!(prefix.iter().all(|byte| *byte == 0x5c));
    // SAFETY: The final pointer is live, its borrow has ended, and its current layout is shrunk.
    unsafe { allocator.dealloc(pointer, shrunk) };
  }
}
