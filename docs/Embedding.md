# Embedding OxiBelt

Status: Experimental

OxiBelt exposes separate library entry points for applications that give it
ownership of a runtime and applications that embed it in an existing Tokio
runtime. This distinction is a process-ownership and security boundary, not
only a convenience API. The canonical lifecycle status is
[`owned-embedded-runtime-api`](FeatureStatus.md).

## Choose an ownership model

Use the owned API for a standalone process or a host that deliberately grants
OxiBelt authority over the configured executor and selected process-global
hooks:

```rust,no_run
# use oxibelt::{OxiBelt, ProcessPolicy, RuntimePolicy};
# use oxibelt::config::Config;
# fn main() -> anyhow::Result<()> {
let config = Config::load("source/config/oxibelt.toml".as_ref())?;

OxiBelt::builder(config)
    .runtime_policy(RuntimePolicy::FromConfig)
    .process_policy(ProcessPolicy::Standalone)
    .build_owned()?
    .run()?;
# Ok(())
# }
```

`RuntimePolicy::FromConfig` resolves the configured runtime topology and worker
allocations. `ProcessPolicy::Standalone` gives the startup path authority to
install the configured crypto provider, tracing subscriber, process signals,
hardening, and owned background workers. It is the library equivalent of the
`oxibelt` CLI startup path. `OwnedServer::start` is the non-blocking alternative
that returns a `ServerHandle`. Do not select standalone ownership inside an
unrelated host process unless that process intentionally grants those
authorities.

Use the embedded API when the caller already owns a Tokio runtime:

```rust,no_run
# use oxibelt::{OxiBelt, ProcessGlobalHooks, ProcessPolicy, RuntimePolicy};
# use oxibelt::config::Config;
# async fn serve() -> anyhow::Result<()> {
let config = Config::load("source/config/oxibelt.toml".as_ref())?;

let server = OxiBelt::builder(config)
    .runtime_policy(RuntimePolicy::CurrentRuntime)
    .process_policy(ProcessPolicy::Embedded(
        ProcessGlobalHooks::CallerManaged,
    ))
    .build_embedded()?;
let mut handle = server.start().await?;

handle
    .wait_ready(std::time::Instant::now() + std::time::Duration::from_secs(10))
    .await?;
println!("{:?}", handle.runtime_topology());
println!("{:?}", handle.bound_listeners());

let result = handle
    .shutdown(std::time::Instant::now() + std::time::Duration::from_secs(30))
    .await?;
# let _ = result;
# Ok(())
# }
```

`RuntimePolicy::CurrentRuntime` requires a current Tokio runtime. It never
constructs, replaces, or resizes that runtime and never claims that configured
Tokio or Compio worker allocations apply to it. The startup report marks
main-runtime, topology-policy, executor-worker, and Compio-worker settings as
`Inapplicable`; OxiBelt-owned accept and QUIC worker allocations remain
applicable and report their actual values.

## Process-global hooks

An embedded caller must select one of these policies explicitly:

- `ProcessGlobalHooks::CallerManaged` does not install process-global hooks.
  The host is responsible for tracing, crypto defaults, signals, hardening,
  panic hooks, allocator/profiler hooks, and environment policy.
- `ProcessGlobalHooks::VerifyOnly` observes requirements that can be checked
  without changing the process. A requirement that cannot be inspected is
  reported as `Unverifiable`; it is never presented as verified.
- `ProcessGlobalHooks::ApplySelected(ProcessGlobalSelection)` requests only the
  selected `crypto`, `tracing`, `signals`, `close_range`, and `landlock`
  controls. Every unselected hook is verify-only. Selecting a hook is an
  explicit grant of process-wide authority, not an instance-local setting;
  controls that cannot be applied truthfully in the current-runtime mode are
  rejected.

The bounded startup report records each known hook as `Applied`,
`AlreadyMatching`, `Verified`, `CallerManaged`, `NotConfigured`,
`Inapplicable`, `Unsupported`, `Unverifiable`, `Rejected`, or `Conflict`.
OxiBelt never silently replaces an existing tracing subscriber, crypto
provider, signal owner, panic hook, allocator/profiler hook, or incompatible
global primitive choice. A conflicting request fails before listener
publication with a fixed stage and reason; matching crypto claims are
idempotent.

Landlock is irreversible and applies per thread and descendants. Embedded
startup rejects applying configured Landlock even through `ApplySelected`
because a pre-existing Tokio runtime cannot prove that every caller-owned
worker is confined. Use the owned API when OxiBelt must install Landlock.
`close_range`, signal installation, hot-reload signals, and tracing setup are
also caller-managed unless selected explicitly. Seccomp expectation remains a
verification of externally installed kernel state; an identity or digest is
still an orchestrator assertion rather than kernel evidence.

## Server lifecycle

`ServerHandle` is unique, non-cloneable, and marked `must_use`. Its cloneable
`ServerControl` and readiness observers do not keep a server alive. The handle
provides:

- `readiness()`, `subscribe_readiness()`, and `wait_ready(deadline)` using the
  same bounded `Starting`, `Ready`, `NotReady`, `Draining`, `Stopped`, and
  `Failed` vocabulary and predicate as `/ready`;
- `runtime_topology()` and `startup_report()` for truthful executor and
  process-global ownership;
- `bound_listeners()` with a bounded, redaction-safe inventory of listener
  kind, transport, and actual bound `SocketAddr`, including a kernel-selected
  port for a configured port of `0`;
- `control()` for a cloneable non-owning sender that can request pre-drain,
  reload, graceful shutdown, or immediate cancellation;
- `cancel()` for immediate cancellation, and consuming `shutdown(deadline)` or
  `wait()` operations that return the joined final result.

The first terminal command observed by the lifecycle driver selects graceful
or immediate shutdown. The configured shutdown delay and drain windows are
capped by a graceful caller deadline. A completed
`shutdown` or `wait` result is the proof that OxiBelt-owned listener,
connection, Admin/Ops, reload, telemetry, discovery, revocation, audit, and
runtime workers have joined or reached their bounded forced terminal state.
The terminal result is `Graceful`, `Forced`, `Cancelled`, or `Failed` with a
fixed reason.

Dropping the last `ServerHandle` initiates immediate cancellation so it does
not intentionally detach a continuing server. Drop cannot await, so
drop alone is not proof that cleanup joined. Embedded hosts must await
`shutdown` or `wait` before dropping their Tokio runtime when they need that
guarantee.

## Process concurrency and compatibility wrappers

Sequential instances are supported when the previous handle has reached
terminal completion, listener addresses are available, and immutable
process-global choices match. Concurrent instances are not a compatibility guarantee:
they may conflict over listeners, process signals, tracing, crypto,
hardening, and background resources. Hosts should serialize server ownership.

The legacy `run`, `run_with_options`, and `configure_crypto_runtime` functions
remain temporarily available but are deprecated. The async run wrappers use
safe embedded semantics: the caller's current Tokio runtime, caller-managed
process globals, and no implicit signal or Landlock ownership. Cancelling the
wrapper future drops its internal handle and initiates cancellation. A config
that requires implicit process ownership receives a structured migration
error. The crypto wrapper accepts an already-matching process claim but never
replaces a conflicting one.

New integrations should use `OxiBelt::builder`, retain `ServerHandle`, and make
runtime and process ownership explicit. See the
[configuration reference](Configuration.md#library-runtime-ownership) and
[upgrade guide](Upgrading.md#upgrade-from-065-to-the-071-line) for field
applicability and migration guidance.
