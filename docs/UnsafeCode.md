# Unsafe-Code Governance

OxiBelt denies first-party Rust unsafe code by default. The policy covers the
main package and all of its targets, the fuzz crate, the focused unsafe-code
harness, and the standalone Rust probe workspaces under `tests/docker/`.

The root workspace policy is:

```toml
[workspace.lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"

[workspace.lints.clippy]
missing_safety_doc = "deny"
multiple_unsafe_ops_per_block = "deny"
undocumented_unsafe_blocks = "deny"
```

The standalone probes declare the equivalent package-local policy. The
repository test `unsafe_code_policy` scans tracked and non-ignored Rust source,
checks every manifest, and rejects attempts to lower these lints.

## Allowlist

Unsafe code is permitted only in these capability-isolated Linux modules:

| Module | Unavoidable capability | Safe caller boundary |
| --- | --- | --- |
| `source/src/hardening/syscalls.rs` | Landlock and `close_range` syscalls not completely exposed by the locked safe dependencies | Typed access masks plus `BorrowedFd` and `OwnedFd` |
| `source/src/tcp_hop/syscalls.rs` | `IP_MINTTL`, `IPV6_MINHOPCOUNT`, and `TCP_INFO` socket options | Typed protocol selection and `BorrowedFd` |

Each module has one reasoned file-level `allow(unsafe_code)`. Function-level,
nested, conditional, or additional unsafe-code allowances are prohibited. An
allowlisted file with no remaining unsafe operation is considered stale and
fails the policy test.

## Required Safety Evidence

Each allowlisted module must keep a module-level `Safety model` covering:

- The invariant that makes the raw operation valid.
- Caller obligations and how the safe wrapper enforces them.
- Pointer and borrowed-value lifetimes.
- Buffer sizes and how they are derived.
- Alignment and C-layout assumptions.
- File-descriptor ownership and transfer behavior.
- Thread-safety or process-wide side effects.
- Linux ABI, kernel-version, and unsupported-platform behavior.

Every unsafe block must have an immediately preceding, operation-specific
`SAFETY` comment. Keep one unsafe operation per block. Safe wrappers must not
export raw pointers, unowned raw descriptors, or public unsafe functions.

Any pull request that changes an allowlisted module or the allowlist requires
approval from a named reviewer other than the author. The pull request must
enumerate the affected blocks, explain the safety model, and link the focused
test, Miri, sanitizer, and fuzz results. A new allowlist entry is accepted only
when existing locked safe libraries cannot represent the required operation;
using an available safe wrapper is the default.

## Validation

Run the ordinary static and policy checks from the repository root:

```sh
cargo fmt --check
tests/scripts/check-tests-rustfmt.sh
tests/scripts/check-rust-module-size.sh
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --test unsafe_code_policy --locked
cargo test --all-features --locked
```

CI additionally runs the complete `oxibelt-unsafe-harness` package on the
latest stable Rust toolchain. The harness covers pure layout and typed-boundary
planning contracts, focused Linux syscall behavior, repeated concurrent
`TCP_INFO` access, and child-process isolation for irreversible Landlock and
`close_range` checks. Because the workflow tracks the stable channel rather
than an exact release, its compiler can advance without a repository change.
The separate fuzz gate continues to cover syscall-boundary input planning and
the existing protocol boundaries.

The stable harness is functional coverage only. It does not provide Miri,
AddressSanitizer, ThreadSanitizer, or UndefinedBehaviorSanitizer
instrumentation and must not be cited as dynamic undefined-behavior, memory
error, or data-race evidence. Pull requests that change an allowlisted module
or the allowlist must provide the Miri and sanitizer evidence required above
separately.

Tests may treat `ENOSYS` or `EOPNOTSUPP` as an explicitly reported unsupported
kernel capability. Generic permission failures and unexpected errno values are
failures, not unsupported-platform skips.
