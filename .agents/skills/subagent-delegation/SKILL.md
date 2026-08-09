---
name: subagent-delegation
description: Route, delegate, and supervise Codex subagents for software-engineering work. Use when a task benefits from parallel exploration, repetitive implementation, test/log/document processing, semantic diagnosis, correctness or security review, or other bounded delegated work. Prefer cost-efficient gpt-5.6-terra and gpt-5.6-luna workers and escalate only when evidence requires it. Do not use this skill merely to choose or modify the primary agent's normal/plan mode, and do not spawn subagents for trivial work whose delegation overhead exceeds the task.
---

# Subagent Delegation

## Skill Activation and Scope

Apply this skill when subagent delegation would materially improve context hygiene, parallelism, specialization, or independent verification. The parent agent remains responsible for requirements, cross-agent decisions, and final synthesis.

Do not assume project-specific custom agents exist. If compatible custom agents are already configured, they may be used; otherwise spawn ordinary subagents with an explicit bounded objective and appropriate model/reasoning choice.

Respect applicable repository `AGENTS.md`, project skills, sandbox/approval policy, and explicit user instructions. Higher-priority project or user constraints override this routing policy.

## Purpose

Use subagents aggressively to reduce main-agent context pollution, avoid spending premium reasoning capacity on routine work, and parallelize independent investigation.

This policy applies only to **subagent selection, delegation, execution, and review**. It intentionally does **not** prescribe how the primary agent should use normal mode or plan mode.

The core principle is:

> Use the least expensive subagent that can reliably complete the delegated task, then escalate only when the task actually requires stronger reasoning.

Do not choose a more expensive model merely because the overall project is large or important. Choose based on the **local difficulty and risk of the delegated task**.

---

## Default Subagent Classes

### 1. Exploration Subagent

**Default:** `gpt-5.6-terra`, reasoning effort `medium`

Use for read-heavy repository investigation where the expected output is evidence rather than a final architectural decision.

Typical responsibilities:

- Locate relevant crates, packages, modules, files, symbols, traits, and call sites.
- Trace control flow, data flow, ownership, configuration propagation, or dependency relationships.
- Find existing patterns that a new implementation should follow.
- Identify affected tests, documentation, fixtures, build scripts, CI workflows, feature flags, or platform-specific code.
- Compare multiple existing implementations inside the repository.
- Inspect recent changes when repository history is locally available.
- Produce concise evidence with paths, symbols, and relevant constraints.
- Reduce a large search space into a small set of files for stronger agents to inspect.

Expected output:

- Findings, not speculative redesigns.
- Exact file paths and symbol names whenever possible.
- Relevant dependencies and known callers.
- Uncertainties or conflicting evidence.
- A compact summary suitable for consumption by another agent.

#### Escalate exploration to `gpt-5.6-terra high` when:

- The repository structure is highly indirect or generated.
- Control flow crosses asynchronous, concurrent, macro-generated, FFI, unsafe, or protocol state-machine boundaries.
- Correct interpretation requires substantial semantic reasoning.
- Several plausible implementations exist and distinguishing them requires more than search and local code reading.
- The investigation itself concerns a security boundary or correctness invariant.

#### Prefer `gpt-5.6-luna` instead when:

- The task is essentially exhaustive enumeration.
- Search criteria are precise.
- Little interpretation is required.
- The result can be verified mechanically.

Examples:

- "List every caller of this function."
- "Find every config key matching this naming convention."
- "Collect all tests that reference HTTP/3."
- "Find every use of this deprecated API."

---

### 2. Correctness and Security Subagent

**Default:** `gpt-5.6-terra`, reasoning effort `high`

Use when delegated work requires adversarial thinking, invariant checking, semantic validation, or reasoning about failure modes.

Typical responsibilities:

- Review authentication, authorization, ACL, privilege, identity, or trust-boundary logic.
- Review cryptographic usage and secret handling.
- Analyze concurrency, races, deadlocks, ordering, cancellation, backpressure, and lifecycle issues.
- Review unsafe Rust, FFI, syscall boundaries, memory-mapped resources, shared memory, or low-level OS integration.
- Validate protocol state machines and compatibility requirements.
- Check parser, serializer, validation, or policy-engine behavior against invariants.
- Analyze failure recovery and partial-failure behavior.
- Examine whether a patch creates bypasses, confused-deputy behavior, privilege escalation, information leaks, denial-of-service vectors, or unsafe defaults.
- Challenge assumptions made by implementation agents.

The correctness/security agent should be skeptical. It must distinguish:

- Proven behavior.
- Behavior strongly implied by code.
- Assumptions.
- Unknowns requiring tests or stronger review.

Expected output:

1. Invariants that must hold.
2. Evidence for whether they hold.
3. Concrete failure cases.
4. Severity or impact where relevant.
5. Required fixes or tests.
6. Residual uncertainty.

#### Escalate beyond Terra high when:

A subproblem is both **high consequence** and **genuinely difficult**, for example:

- A subtle security boundary whose failure could expose remote code execution, authentication bypass, cross-tenant access, privilege escalation, or secret compromise.
- A novel lock-free or highly concurrent algorithm.
- A complex protocol correctness question spanning several state machines.
- Unsafe/FFI behavior whose safety depends on non-local invariants.
- A suspected vulnerability with ambiguous exploitability.
- A change whose correctness cannot be established from local reasoning and ordinary tests.

In those cases, request review by a stronger primary/review agent rather than pretending Terra has resolved the uncertainty.

Do not escalate merely because the code is security-related. Straightforward validation logic, well-understood API usage, and mechanically checkable security properties can remain with Terra high.

---

### 3. Mechanical and Repetitive Work Subagent

**Default:** `gpt-5.6-luna`, reasoning effort `max`

Use for clearly specified transformations whose correctness can be checked through compilation, tests, diffs, formatting, or deterministic inspection.

Typical responsibilities:

- Rename symbols across known scopes.
- Migrate call sites to a new API.
- Apply an established pattern to many similar modules.
- Add repetitive trait implementations or adapters.
- Update generated-like boilerplate that is still source-controlled.
- Perform straightforward configuration migrations.
- Add repetitive test cases following an existing template.
- Fix formatting, lint, import, or simple type errors.
- Apply an explicitly described refactor with stable semantics.
- Update documentation references after a mechanical API change.

Requirements:

- The task must have a precise transformation rule.
- The expected behavior must already be decided.
- The subagent must not silently redesign APIs or semantics.
- Verification commands should be run whenever practical.
- Unexpected semantic ambiguity must be reported rather than guessed through.

#### Switch from Luna to Terra when:

- The transformation stops being mechanical.
- Different call sites need semantically different treatment.
- Ownership, lifetime, async, concurrency, or error-propagation decisions appear.
- Public compatibility is unclear.
- The required modification crosses a trust or privilege boundary.
- Tests reveal failures whose cause is not obvious.
- The work requires choosing among multiple reasonable designs.

A useful rule:

> Luna may execute a known decision; Terra should make a non-trivial local decision.

---

### 4. Tests, Logs, Documentation, and Evidence Subagent

**Default:** `gpt-5.6-luna`, reasoning effort `high` or `max`

Use Luna for high-volume evidence processing when the interpretation criteria are well specified.

Typical responsibilities:

- Run targeted test suites.
- Group failures by likely root cause.
- Extract the first meaningful failure from noisy logs.
- Compare before/after test results.
- Inspect compiler, sanitizer, profiler, benchmark, or CI output.
- Check whether documentation matches code-defined names or defaults.
- Update docs from an already-decided implementation.
- Collect relevant examples and fixtures.
- Verify that expected files or artifacts were produced.
- Summarize repetitive benchmark or test output without redesigning the system.

Use `high` when the task is primarily extraction and classification.

Use `max` when:

- Logs are long or noisy.
- Several failures need correlation.
- Documentation spans many files.
- The agent must reconcile multiple sources of local evidence.
- The task is still well-bounded but benefits from deeper persistence.

#### Use Terra instead when:

- A failing test requires semantic diagnosis rather than classification.
- Benchmark movement requires causal analysis.
- Documentation conflicts with code and deciding the intended contract requires judgment.
- A log may indicate a race, security flaw, protocol violation, or architectural bug.
- The evidence is contradictory and cannot be resolved mechanically.

Do not let a log-processing subagent turn correlation into causation. It should mark inferred causes explicitly.

---

## Final Integration and Review Subagent

When a separate final integration or review subagent is appropriate, prefer:

**Default:** `gpt-5.6`, reasoning effort `high` or `xhigh`

This is the exception to the general preference for cheaper subagents. A strong reviewer is useful when independent work from several subagents must be reconciled.

Typical responsibilities:

- Review a multi-file or multi-agent patch as one coherent change.
- Check that delegated implementations satisfy the original contract.
- Detect contradictions between independently produced changes.
- Validate public API and configuration consistency.
- Review cross-cutting error handling and rollback behavior.
- Check that tests actually exercise the intended invariants.
- Identify missing migration, compatibility, observability, security, or documentation work.
- Decide whether unresolved findings block completion.

Use `high` by default.

Use `xhigh` only when integration itself is difficult, such as:

- Large architectural changes.
- Cross-protocol behavior.
- Security-critical changes.
- Complex concurrency.
- Significant public API compatibility concerns.
- Multiple independently modified subsystems with subtle interactions.

Do not use a `gpt-5.6` subagent as a routine formatter, grep worker, test runner, or bulk migration agent.

---

## Delegation Rules

### Delegate by bounded responsibility

Each subagent should receive a small, explicit objective.

Good:

> Inspect the HTTP/3 request path and identify where request-body buffering is introduced. Return file paths, functions, and evidence. Do not modify code.

Good:

> Update all call sites of `Foo::new` to the already-approved `Foo::builder` API. Preserve behavior and run the relevant tests.

Bad:

> Improve HTTP/3 performance.

Bad:

> Fix security.

Broad goals force subagents to rediscover architecture and increase cost, overlap, and inconsistency.

---

### Give subagents enough context, but not the entire project narrative

Provide:

- The specific objective.
- Relevant files or modules if already known.
- Constraints and invariants.
- Whether modification is allowed.
- Verification expectations.
- What must be returned.

Avoid dumping unrelated discussion, historical reasoning, or large logs when the subagent can retrieve the necessary local evidence itself.

---

### Ask for evidence-first reports

For investigative tasks, require agents to separate facts from inference.

Preferred structure:

```text
Findings
- path:symbol — observed behavior

Implications
- consequence derived from the findings

Uncertainties
- anything not established from the available evidence

Recommended next action
- only when requested
```

This makes the result easier for another agent to verify.

---

## Parallelism Policy

Parallelize work when tasks are independent or mostly read-only.

Good parallel candidates:

- Repository exploration of different subsystems.
- Independent security and correctness review.
- Test execution for separate crates or feature sets.
- Documentation consistency checks.
- Call-site enumeration.
- Platform-specific investigation.
- Independent review of the same high-risk change from different perspectives.

Be conservative with simultaneous write-heavy work.

Avoid assigning multiple agents to modify:

- The same file.
- The same public API.
- Closely coupled state machines.
- The same configuration schema.
- The same migration.
- Shared generated artifacts.

unless the tasks have explicitly non-overlapping ownership.

When write conflicts are likely, prefer:

1. Parallel investigation.
2. One decision.
3. Partitioned implementation.
4. One integration review.

---

## Independent Review

For high-risk changes, the agent that implements a change should preferably not be the only agent that validates it.

Use an independent correctness/security reviewer for:

- Authentication and authorization.
- Privilege separation.
- Cryptography.
- Unsafe Rust or FFI.
- Network protocol state transitions.
- Persistent data format changes.
- Concurrency primitives.
- Resource accounting and denial-of-service controls.
- Sandboxing.
- Parser or policy-engine changes.
- Code that handles untrusted input near a sensitive boundary.

The reviewer should inspect the actual patch and relevant surrounding code, not merely the implementation agent's summary.

---

## Escalation Policy

Escalation should be **evidence-driven**, not automatic.

Escalate from Luna to Terra when:

- A decision is ambiguous.
- Mechanical work exposes semantic differences.
- Tests fail for non-obvious reasons.
- Correctness depends on non-local behavior.
- Security or concurrency reasoning becomes necessary.

Escalate from Terra to stronger review when:

- Important uncertainty remains after investigation.
- The consequences of being wrong are high.
- The change depends on a novel or unusually subtle invariant.
- Several subsystems interact in ways that cannot be validated locally.
- The agent can describe the problem but cannot establish a reliable conclusion.

Do not repeatedly escalate the same task without narrowing the uncertainty first.

A useful escalation report contains:

```text
Established:
- ...

Unresolved:
- ...

Why the current agent cannot safely decide:
- ...

Evidence/files for the next reviewer:
- ...
```

---

## Exceptions

### Small tasks

Do not spawn a subagent when delegation overhead is larger than the task itself.

Examples:

- Reading one short function.
- Fixing one obvious typo.
- Changing a single known constant.
- Running one trivial command.
- Answering a question already established by current context.

---

### Highly coupled tasks

A single stronger agent may be more efficient when the work requires continuous reasoning across many tightly coupled edits.

Examples:

- Reworking one protocol state machine across several adjacent files.
- Refactoring an ownership model where every edit depends on the previous one.
- Resolving a difficult borrow/lifetime design while simultaneously changing its API.
- Reconstructing an invariant that is distributed across many tightly coupled components.

Subagents may still be useful for independent review or test analysis after the implementation stabilizes.

---

### Novel architecture

Do not ask Luna to invent architecture from scratch.

Terra may explore alternatives, but high-impact architectural decisions should be surfaced to the stronger coordinating/review agent.

---

### Security emergencies

When investigating a plausible high-impact vulnerability:

- Prefer correctness/security agents over mechanical agents.
- Keep exploitability claims evidence-based.
- Separate confirmed vulnerability conditions from hypothetical attack paths.
- Use independent review where practical.
- Do not let speed or model-cost optimization override the need for reliable validation.

---

### Unstable or flaky tests

A Luna test agent may identify patterns, reproduce failures, and collect logs, but it should not declare a flaky failure harmless without evidence.

Escalate when:

- Failures correlate with timing or concurrency.
- Reproduction depends on environment state.
- The failure occurs near security, persistence, networking, or resource-lifecycle code.
- Suppressing the test would hide an unresolved invariant violation.

---

### Performance work

Use Luna for:

- Running benchmarks.
- Collecting measurements.
- Normalizing results.
- Identifying regressions that exceed a predefined threshold.

Use Terra for:

- Profiling interpretation.
- Hot-path investigation.
- Evaluating algorithmic or allocation-related causes.
- Distinguishing measurement noise from plausible causal changes.

Use stronger review when a proposed optimization changes:

- Concurrency semantics.
- Memory safety assumptions.
- Protocol correctness.
- Security checks.
- Backpressure.
- Resource limits.
- Public behavior.

Never trade correctness or security for benchmark improvement without making that tradeoff explicit.

---

### Platform-specific behavior

Use separate subagents for platform-specific investigation when appropriate, especially for:

- Linux vs. other operating systems.
- glibc vs. musl.
- CPU architecture differences.
- Kernel feature detection.
- Containerized vs. host execution.
- CI-specific failures.

Do not generalize a result from one platform unless the code or tests establish that the behavior is portable.

---

## Verification Requirements

A subagent that modifies code should normally perform the cheapest relevant verification first.

Possible sequence:

1. Format or syntax validation.
2. Targeted unit tests.
3. Targeted package/crate tests.
4. Static analysis or lints.
5. Relevant integration tests.
6. Broader test suites when justified.

Do not run the entire repository's most expensive validation suite after every mechanical edit unless required by project policy.

However, do not omit broad validation merely to save tokens when:

- The change is cross-cutting.
- The affected surface is uncertain.
- Previous regressions have appeared outside the obvious module.
- The repository explicitly requires broad validation before completion.

Subagents should report:

- Commands run.
- Pass/fail status.
- Important failures.
- What was not run.
- Why omitted checks were unnecessary or impractical.

---

## Context-Hygiene Rules

Subagents exist partly to prevent the coordinating agent's context from being filled with low-value intermediate material.

Therefore:

- Do not return entire logs unless requested.
- Summarize repetitive compiler errors.
- Return the smallest relevant stack trace.
- Prefer file paths and symbols over pasted source code.
- Deduplicate repeated findings.
- Collapse equivalent failures into one root-cause group.
- Report benchmark summaries rather than every sample unless raw samples are required.
- Keep exploratory dead ends out of the final report unless they materially eliminate an important hypothesis.

The coordinating agent should receive conclusions plus enough evidence to verify them, not a transcript of the exploration process.

---

## Cost-Awareness Rules

Model cost is a routing constraint, not the primary correctness criterion.

Prefer approximately:

| Work type | Default subagent |
|---|---|
| Precise enumeration / repetitive edits | Luna high/max |
| Tests, logs, docs, evidence processing | Luna high/max |
| General repository exploration | Terra medium |
| Semantic diagnosis | Terra high |
| Correctness / security review | Terra high |
| Complex cross-agent integration | `gpt-5.6` high |
| Exceptional high-risk integration | `gpt-5.6` xhigh |

Do not promote an agent solely because:

- The repository is large.
- The project is production software.
- Many files exist.
- The user considers the feature important.

Promote when the **delegated decision itself** requires greater reasoning capability.

Likewise, do not keep a weak agent on a task merely to conserve quota when evidence shows that the task exceeds its reliable scope.

---

## Recommended Subagent Workflow

For a substantial change, prefer a pipeline similar to:

```text
Exploration
  Terra medium
      |
      +--> precise enumeration
      |      Luna high/max
      |
      +--> correctness/security investigation
             Terra high
                 |
                 v
        bounded implementation tasks
        Luna max or Terra high
                 |
                 v
          tests / log triage
          Luna high/max
                 |
                 v
      independent correctness review
             Terra high
                 |
                 v
       final cross-cutting review
         gpt-5.6 high/xhigh
       only when warranted
```

Not every task needs every stage.

Remove stages that do not add meaningful confidence.

---

## Anti-Patterns

Do not:

- Use `gpt-5.6` subagents for routine repository search.
- Use Terra high for trivial rename work.
- Ask Luna to make novel security or architectural decisions.
- Spawn several agents with the same broad prompt and merge their patches blindly.
- Allow agents to modify overlapping files without ownership boundaries.
- Treat successful compilation as proof of semantic correctness.
- Treat passing tests as proof that a security invariant holds.
- Treat benchmark improvement as proof that an optimization is safe.
- Accept a subagent's summary when the conclusion is high risk and easy to inspect directly.
- Escalate models repeatedly without first identifying what uncertainty remains.
- Return huge raw logs to the coordinating agent when a compact diagnosis is sufficient.

---

## Completion Standard

Subagent delegation is successful when:

- Expensive reasoning is reserved for work that actually needs it.
- Routine work is handled by cheaper agents with objective verification.
- The coordinating context contains conclusions and evidence rather than search noise.
- Independent tasks are parallelized without creating write conflicts.
- High-risk changes receive independent semantic review.
- Uncertainty is explicitly surfaced and escalated rather than hidden.
- The final integrated result remains coherent across code, tests, configuration, documentation, security, and supported platforms.

When uncertain which subagent to choose, start with the cheaper plausible option **only if failure is cheap and detectable**. Otherwise, start with the agent whose reasoning level matches the consequence and ambiguity of the task.
