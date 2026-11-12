# Parallel module design, implementation and verification

This is the recurring workflow for the Rust implementation. Use all available
independent worker slots: currently three module workers plus the integrator,
who also owns an independent module. Concurrency does not relax API, security,
resource or evidence gates. A blocker in one module does not stop independent work.

## Durable inputs and status

Read `AGENTS.md`, architecture, the master implementation checklist and the detailed
FC/MG/VX/UDP/CL workstream list. Before implementation, each module must have
`docs/modules/<module>.md` with:

- Scope and current status; distinguish a primitive from the complete protocol.
- Public types, function signatures, ownership/lifetime and state transitions.
- Byte order/wire version when applicable; arithmetic, memory and work bounds.
- Error and backpressure semantics; no data consumed on recoverable failure.
- Authentication/trust assumptions, replay scope and reset/reconnect behavior.
- Upstream dependencies and permitted file ownership.
- Individually identified `- [ ] [ID]` tasks and a concrete test/acceptance matrix.
- Checked items with `Evidence:` links only after their stated checks pass.

A design document is a deliverable before code, not a retrospective explanation.
Interfaces begin as draft v0. Record interface-breaking revisions in the module
file and notify dependent workers before edits; consumers do not guess a pending
API. No task is complete just because its enum/trait or crate compiles.

## Work cycle

1. **Select blocking behavior first.** Reproduce and fix the master checklist
   FIX-* discrepancies before adding features or polishing a fallback. The
   integrator chooses ready, independent repair tasks and
   gives each worker exclusive files plus the exact inputs, boundary and tests.
   Keep one authoritative owner for shared core types, the public facade, root
   manifests, mode catalog, global checklist and validation tooling.
2. **Design in parallel.** Each worker writes its module document and checklist,
   then reports the proposed key API and unresolved questions. Freeze shared
   interface types before a consumer implements against them. Modules that only
   use already-existing core types can proceed without waiting for unrelated ones.
3. **Implement in parallel.** Each worker builds the smallest complete behavior
   specified by its module design, with public docs and explicit errors. Use
   injected time/I/O and bounded memory; no success-returning placeholders for
   missing networking, cryptography or device setup.
4. **Test locally.** Run the module's focused behavior/failure tests and Clippy.
   Report exact commands/results. Cargo may serialize access to the shared target
   directory; do not kill another worker's build or modify its files to unblock it.
5. **Review interfaces and failures.** A second worker or the integrator checks
   arithmetic, ownership, state reset, hostile inputs, denial-of-service limits and
   claims. Fix material findings and add a regression test where appropriate.
6. **Integrate serially.** The integrator updates facade exports/dependencies and
   shared contracts, then exercises meaningful module combinations. Reconcile
   module TODOs, master gates and catalog status. An independently tested primitive
   does not satisfy a larger end-to-end gate.
7. **Run the required suite.** Run `python3 tools/check.py` through
   `tools/record_check.py --output work/<fresh-wave>`; save output, source
   hashes and tested scope. The input map covers Rust/app/tool/config/docs/vendor
   files, CI/Cargo configuration, root manifests and `.editorconfig`, and the
   complete `simulator/src` oracle tree used by golden checks (excluding caches).
   Earlier receipts retain their original recorded scope and are not rewritten.
   Freeze the recorded source inputs during aggregate checks and builds in the
   live checkout. Workers may inspect or design in `work/`, but must not edit
   those inputs until the integrator releases them. Source copies can archive
   evidence; do not alternate compilation between them and the live checkout.
   After an exact-source native build, retain an immutable daemon, verifier,
   helper tree and source manifest before releasing workers. A receipt qualifies
   its recorded inputs, not later edits. Run privileged/native tests only for a runnable feature
   within the authorized isolated lab. Keep unsupported/skipped gates unchecked.
   Use the shared target through `CARGO_TARGET_DIR`; wait
   for Cargo's lock instead of creating a target per worker, source copy or retry.
   The integrator grants one active source tree the build directory at a time;
   do not alternate live and frozen trees concurrently. Before a source-tree
   switch, stop builds and invalidate affected workspace package artifacts;
   Cargo's lock alone does not establish source identity across copied trees.
   Preserve small source manifests, logs and receipts outside the target. Remove
   obsolete compiler output after its processes exit; it is not evidence.
8. **Commit coherent checkpoints.** Create a local Git commit after a module has
   concrete code, its scoped checks and updated evidence. Do not accumulate all
   work until the complete product is ready. The integrator owns staging and
   commits; workers keep editing their exclusive files. When live edits have
   advanced, stage the verified snapshot bytes without overwriting the working
   tree. Record unresolved aggregate/native failures in the commit description;
   a checkpoint commit is not a release or a declaration that every gate passed.
   Keep generated outputs, private credentials and in-flight module edits out of
   the checkpoint. Remote publication remains a separate action.
9. **Select the next wave.** Use dependency readiness and test results, not the
   number of unchecked boxes alone. Retain design/API/test receipts for the next
   agent so work can continue without reconstructing chat history.

## Current ownership and acceptance

The integrator owns the current repair order, shared interfaces, client wiring,
validation, ledger changes and Git index. Workers own disjoint runtime behavior,
Python parity/recovery and test-acceptance repairs. Keep the live assignments in
the task messages; obsolete wave tables are not executable priorities.

For each behavioral discrepancy, record one stable blocking task with the
observed call path, a regression that fails before the repair, and the required
real-client acceptance. Remove superseded implementations and duplicate or
self-confirming tests once their meaningful failure coverage has a replacement.
Do not keep a known-wrong branch merely to preserve a passing fixture. Retain
historical experiment receipts unchanged.

Full checks prove their recorded suite passed. They do not prove unavailable
adapters ran, complete Python-mode fidelity, native throughput or platform
support. Validate required prerequisites and unexpected skips. A checked leaf
cannot close its parent integration/performance gate. Do not report the count
of waves, tests or checked leaf tasks as product completion.

## Integration rules

Keep module changes isolated when a managed worktree is available. The local Git
repository is initialized; concurrent workers use exclusive path ownership and
the integrator alone owns the index and checkpoint commits. Never
create a second runtime or overwrite another worker's changes. Create a complete
crate manifest/source pair before starting Cargo checks. The integrator owns any
manual lockfile decisions; ordinary Cargo lockfile updates are inspected together.

Do not launch a new user-owned chat for a module; use bounded worker delegation
within this task. On interruption, leave the module document with exact completed
work, current API revision, failing commands and the next unchecked task. Never
mark a broad gate complete just to close a worker task.

## Workflow checklist

- [x] [WF-01] Define persistent module-document format, ownership and design-before-code workflow. Evidence: [this workflow](development-workflow.md).
- [x] [WF-02] Complete all four first-wave module design documents and agree on their independent public boundaries. Evidence: [implementation/tests](modules/flow-control.md).
- [x] [WF-03] Implement and focused-test each first-wave primitive with bounded failure behavior. Evidence: [implementation/tests](../crates/l2tunnel/tests/pipeline.rs).
- [x] [WF-04] Review and integrate facade exports plus meaningful cross-module tests. Evidence: [implementation/tests](../crates/l2tunnel/tests/pipeline.rs).
- [x] [WF-05] Run full workspace/tooling checks and record first-wave evidence, leaving runtime gates unchecked. Evidence: [integrated check receipt](../work/implementation-wave1/validation.json).
