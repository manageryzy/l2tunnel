# Aligned and packed flow registration retirement

Status: implemented and integration-tested in finite loopback carrier tests;
required combined snapshot validation remains separate. Existing default flow capacity 1024 is a concurrent retained-registration
bound, not a lifetime session flow budget. Aligned and packed share the same
runtime actor. Before this correction neither retired Pipeline registrations,
and `Flow(Capacity)` was terminal at both local ingress admission and authenticated inbound learning.
Other rolling/raw actors need separate follow-up and are not edited here.

## Ownership contract and proposed API

Retiring an idle locally empty registration must not discard queued native bytes,
change a selected packet's immutable binding, reset codec/recovery state or claim
native delivery. Selected packets have left Pipeline's queue accounting but still
carry a local Binding; they pin their exact flow key until endpoint admission.
After endpoint admission, aligned/packed retain payload and channel only: local
Pipeline FlowId is not serialized or referenced by the endpoint, recovery engine,
packed source, restored record or native device handoff. Their packet ownership
continues unchanged. Runtime configuration requires fixed CRC channel mapping;
relearning the same key must derive the same channel, and FlowIds never reuse.
This is a proof of drained registration dependencies, not of delivered bytes.
Codec/header contexts and authenticated delivery credit remain independent.

A naive global `endpoint.drained()` prerequisite can deadlock: a new inbound
pending native frame cannot learn because the table is full, but that same
retained frame prevents global endpoint drain. The implementation uses
explicit registration ownership proof instead: exclude the one selected key,
require an empty local flow FIFO and original idle age, preserve fixed CRC mapping
and immutable weight, then retire via the existing caller-drained API. Incoming
prepared/native bytes still own their channel/context and are learned again with
the same deterministic channel if needed. Capacity at enqueue or inbound learn
retains exact original input/pending delivery and retries; it cannot itself
terminate the authenticated session. Original protocol/handoff expiry still
applies if pressure is permanent.

Implemented narrow pure APIs: `FlowTable::validate_time(now)` exposes the existing
nonmutating monotonic check without a full idle scan. `Pipeline::idle_step(now,
after,work,excluded)` returns a bounded scan cursor and at most one idle locally
empty candidate, excluding the caller's selected key. At most 16 registrations are
examined and one retired per actor turn; cursors wrap without allocating queues.
No new channel, timer, budget, crypto, wire or configuration default is introduced.
The existing `retire_idle_drained` remains the mutation boundary. The helper's
documentation must state that byte ownership may continue only when its consumer
has no reference to the retired local registration and retains immutable channel
metadata under fixed mapping. Active/proxy APIs keep their stricter own drain
requirements. No P-* or broader native gate follows from this repair.

## Checklist

- [x] [MOD-ALIGNEDFLOW-01] Reproduce default 1024→1025 terminal ingress after empty queues and elapsed idle time before production edits; preserve the failed observation. Evidence: [before failure](../../work/aligned-flow-retirement20/before.log).
- [x] [MOD-ALIGNEDFLOW-02] Implement bounded idle scan and registration-dependency-safe retirement, selected-key exclusion and nonterminal exact capacity retention at ingress/inbound learn. Evidence: [actor and ownership handling (retired in Common cutover)](compact-wire-cleanup.md), [bounded pure scan](../../crates/l2tunnel-pipeline/src/lib.rs).
- [x] [MOD-ALIGNEDFLOW-03] Regress selected/endpoint/recovery/native WouldBlock ownership, late same-key/channel reuse and actual aligned/packed flow churn beyond configured capacity. Evidence: [ownership and churn regressions (retired in Common cutover)](compact-wire-cleanup.md), [packed cases (retired in Common cutover)](compact-wire-cleanup.md).
- [x] [MOD-ALIGNEDFLOW-04] Pass scoped Rust tests, strict lint/docs/fmt and freeze exact source/command receipt. Evidence: [frozen scoped receipt](../../work/aligned-flow-retirement20/validation.json).
- [ ] [MOD-ALIGNEDFLOW-05] Pass the required combined `python3 tools/check.py` snapshot validation after root integration.

## Evidence and limits

The preserved [before failure](../../work/aligned-flow-retirement20/before.log)
uses the default table capacity, admits and dequeues 1024 different UDP flows at
injected time zero, then submits flow 1025 after 61 seconds. The original actor
returns terminal `Flow(Capacity)` despite zero locally queued packets. The
[before source hashes](../../work/aligned-flow-retirement20/before-source.json)
pin the three unchanged production inputs used by that observation. The after
regression retains the exact rejected packet, retires one eligible registration,
and admits that same packet on the next attempt.

[Pure tests](../../work/aligned-flow-retirement20/pure-tests.log) pass 19 packet
and 13 Pipeline tests plus two doctests. The new scan regression covers one-entry
work, excluded selected key, nonempty FIFO, removed cursor keys, wrap, zero-work
and regressing time. Cursor scans do not refresh idle time. At most one idle empty
registration retires per actor turn; a selected original pins its key until
successful endpoint admission. The selected test also proves unchanged original
metadata and bytes, stable CRC channel after relearn, and increasing local IDs.

[Aligned](../../work/aligned-flow-retirement20/aligned-tests.log) and
[packed](../../work/aligned-flow-retirement20/packed-tests.log) each pass ten
runtime tests. New authenticated UDP full/half cases transfer sixteen distinct
flows in each direction, with disjoint endpoint keys, table capacity four, native
write pause 70 milliseconds, idle age ten milliseconds, datagram loss and reorder.
Both sides receive every exact original byte. Existing UDP/QUIC TAP/TUN tests and
native-blocked original-expiry tests remain passing. A direct endpoint regression
retires while bytes remain in the sender/packer/recovery owner and again while a
recovered native frame remains blocked; complete status snapshots and exact
pending bytes remain unchanged, and the frame is delivered once after unblock.
This explicitly distinguishes registration retirement from byte delivery.

Tests use a copied source19 baseline overlaid with exactly the owned files,
avoiding unrelated in-flight proxy changes. This is local finite integration
coverage, not privileged/native qualification, simulator parity or a claim of
endpoint congestion-window ownership. A permanent table pinned entirely by local
queued/selected work remains backpressure; existing protocol retention deadlines
still expire rather than silently extending. Flow ID exhaustion, malformed input,
wrong channel binding and other errors remain terminal as before. No table,
channel, queue or timeout default changes.

Rolling `rolling/pump.rs` and raw `raw_packet.rs` have separate actors with similar
capacity/retirement gaps; they are reported for follow-up and are not modified by
this repair. Active/proxy retirement requires their own external barriers; this
channel-only endpoint ownership proof does not weaken those APIs.

Strict all-target no-dependency Clippy and rustdoc with warnings denied, plus
package `cargo fmt --check`, pass for packet, Pipeline and runtime on that copied
overlay. [Scoped validation receipt](../../work/aligned-flow-retirement20/validation.json)
pins the eight delivered files and commands. Root owns the combined required
`python3 tools/check.py` run; its result is not implied by these scoped passes.
