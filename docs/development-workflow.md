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

1. **Select a wave.** The integrator chooses ready, independent checklist tasks and
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
   Freeze a copied source snapshot, verify its file hashes against the selected
   workspace checkpoint, and release module workers immediately after the copy.
   Run the aggregate and exact-source build in that snapshot, with an exclusive
   Cargo target directory; native tests execute only its immutable daemon,
   verifier and copied helper tree. Do not require the live development workspace
   to stay frozen during validation. A receipt qualifies its recorded snapshot,
   not concurrent later edits. Run privileged/native tests only for a runnable feature
   within the authorized isolated lab. Keep unsupported/skipped gates unchecked.
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

## Completed first coding wave

| Owner slot | Library | Design document | First complete behavior | Deliberately pending integration |
| --- | --- | --- | --- | --- |
| Worker A | `l2tunnel-flow-control` | [Flow-control module](modules/flow-control.md) | Checked cumulative-credit accounting and bounded receiver reservations | Adaptive probing, network feedback and TCP proxy |
| Worker B | `l2tunnel-qos` | [QoS module](modules/qos.md) | Bounded byte-aware weighted deficit scheduling | Full class/path hierarchy, congestion control and OS QoS bindings |
| Worker C | `l2tunnel-management` | [Management module](modules/management.md) | Draft control framing and trusted-origin boundary | Cryptographic authentication, reliable network control and distributed reload |
| Integrator | `l2tunnel-vxlan` | [VXLAN module](modules/vxlan.md) | Checked VXLAN header/frame codec and VNI/domain admission | Live VTEP sockets, learning/FDB/BUM and bridge lifecycle |

These modules have no dependency on each other's unfinished APIs. The facade is
integrated after their public surfaces settle. All ordinary data continues to use
the common user policy; no management/probe shortcut is added by these primitives.

## Current composition wave

The first primitives now have focused behavior tests. The runnable Linux slice
also includes authenticated persistent TCP/TLS, TAP/TUN/VXLAN adapters, bounded
native queues, a private Unix client API and coordinated compression epochs.
Native qualification is recorded separately from primitive acceptance.

| Owner slot | Exclusive work | Frozen upstream interfaces | Acceptance before runtime integration |
| --- | --- | --- | --- |
| Worker A | Genuine HTTPS carrier contract and implementation | Existing maintained TLS/member/session APIs; raw packet results stay separate | Specify valid HTTP streaming and bounded ordinary unauthenticated handling, then preserve original TLS/socket ownership and explicit ALPN/SNI/authentication binding |
| Worker B | Corrected measured native pressure qualification | Frozen directional pressure correction and explicitly bounded pressure-only WAN capture allocation | Preserve payload/growth/first-reopen acceptance and deadlines; execute only the exact root-verified build and audit complete captures |
| Worker C | Rolling-frame native harness | Frozen tested UDP/QUIC rolling runtime and explicit shared client | Exercise actual TAP/TUN full/half device paths, exact payloads, bounded loss and owned cleanup; retain separate large-window and Python-family gates |
| Integrator | Frozen aggregate/build, shared integration helpers and local Git checkpoints | Exact copied completed bundles, isolated build target, immutable native helpers and structural auditor | Review interfaces, run full checks, retain failed acceptance evidence, commit coherent validated snapshots and qualify native profiles while workers continue |

All four slots carry implementation or executable validation work. Module design
stays in the module ledger and is followed directly by code and focused tests;
there is no separate approval round for each internal helper. Review focuses on
material interface, ownership, security and test findings. A failing check blocks
that checkpoint's acceptance, not independent development.

Use a distinct Cargo target directory per worker and one exclusive target for
snapshot validation. Avoid repeated full-suite runs after a successful unchanged
checkpoint. The integrator may run independent clean native cases concurrently
when they have disjoint lab IDs, namespace ownership and output directories;
serialize only cases that share mutable resources or deliberately measure a
common host load. Preserve failed receipts before making the next attempt.

The wave16b aggregate passed on its frozen source; the derived wave17 aggregate
failed a raw paired-lane review assertion and remains preserved. Wave18 composes
the focused-tested causal fixture fix, raw native harness, rolling runtime and
directional native-pressure correction while these next worker lanes continue.
The previous measured native pressure rerun exposed a directional classification
defect despite focused tests passing, so native acceptance remains a separate gate.
Existing fixed-credit proxy,
aligned UDP/QUIC, standalone OpenVPN-like clean drain and other native receipts
retain their documented finite scope. All 47 complete Python family gates remain
open until their own requirements pass. See [current evidence](implementation-status.md)
and the module ledgers for evidence, failures and remaining tasks.

## Subsequent waves and readiness gates

- **Wire and session wave:** canonical config codec, bounded stream assembler,
  maintained TLS/identity dependencies, replay/keys, lane join and runtime driver.
  Freeze authentication proofs before protected packet/session state mutation.
- **Data-plane wave:** real frame/header codecs, payload FEC/ARQ, adaptive-credit
  controller and hierarchical QoS. Differential-test real bytes against Python
  vectors; never use sender payload knowledge at the receiver.
- **Integration wave:** persistent TCP/TLS, both UDP covers and standalone UDP,
  qualified raw TCP, internal management transactions and full VXLAN adapter.
  Reuse the fixed control codec during data-mode changes.
- **Client wave:** shared client-core/local API and CLI proceed with fake backends
  while Linux/Windows/Android adapters develop independently. GUI uses the same
  API after its contract stabilizes; choose the toolkit at CL-17.
- **Qualification wave:** isolated TUN/TAP/VXLAN/netem tests, actual TCP proxy, QoS
  pressure/fairness, hot switches and native clients. Performance and release
  claims require the specific native/carrier/configuration receipts.

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
