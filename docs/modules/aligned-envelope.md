# Aligned symbol envelope and recovery composition

Status: pure composition implemented and locally tested. A separate
[runtime composition](aligned-runtime.md) now has real-carrier loopback tests;
client selection and native OS-device qualification remain open. This slice connects actual Python aligned
body/channel/fragment bytes to the existing reliable Cauchy/ARQ engine. It does not
add a carrier, device loop, native test, source-packing timer or complete catalog
mode. In particular, existing recovery delivers sources globally in order; this
adapter cannot release a short record across a missing earlier recovery source.
The independently tested receiver's early-release capability remains a separate
integration gate. Read the [architecture](../architecture.md),
[mode inventory](../mode-parity.md), [body codec](aligned-body-codec.md),
[receiver](aligned-receiver.md) and [recovery composition](reliable.md).

## Wire and integrity boundary

The draft source envelope is exactly 48 bytes followed by the unchanged, fully
zero-extended Python aligned symbol. All integers are big endian:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 4 | `L2AS` magic |
| 4 | 1 | version 1 |
| 5 | 1 | direction: 0 initiator to responder, 1 reverse |
| 6 | 2 | exact complete inner symbol length |
| 8 | 16 | nonzero authenticated session |
| 24 | 8 | negotiated epoch |
| 32 | 8 | absolute recovery source identity |
| 40 | 8 | absolute per-channel record identity |
| 48 | symbol length | Python channel u8, low16 record serial, body/fragment/padding |

Parsing requires the exact negotiated size, matching scope, valid channel and
matching low16 record serial. The inner channel and fragment geometry are covered
by the same enclosing integrity protection as every envelope byte. Parsing is not
authentication: `receive_authenticated` may only receive complete recovery packets
after a maintained carrier's integrity and replay checks. Every FEC equation must
be authenticated before algebra; reconstructed originals retain this envelope and
are checked against the authoritative recovered source ID. There is no separate
MAC, custom cryptography or identity inferred from a user Ethernet frame.

The envelope is a new versioned protocol, not Python wire compatibility. Python
byte parity applies to its inner symbol only. Config negotiation must bind this
version, the exact complete canonical configuration digest, packet layer and
carrier profile before data. Caller-supplied scopes alone do not prove that bind.

## Codec sender contract

`codec::aligned_envelope` provides bounded `encode`/`decode` and a borrowed `View`.
`codec::aligned_sender::Sender::new(scope, Config)` owns a fixed context per
channel, one staging encoder and one context-plus-body buffer. `stage(channel,
frame)` is called only after shared MUX/QoS admission. It builds at most one
native frame's context/body transactionally; a busy/invalid/exhausted operation
leaves committed contexts, record IDs and the previous pending bytes unchanged.
Context records precede bodies, each taking a per-channel absolute RecordId.
The ordinary symbol header, kind-4 fragmentation and zero padding exactly follow
`AlignedRecordTransport._submit_record` and `_aligned_source`.

Additive `encode_raw`/`stage_raw` select kind2 without consuming header context,
including large raw packets that require fragmentation. Raw length plus three
bytes must fit 65535. `NativePolicy::RawIp` binds this selection in the pure
config digest and rejects contradictory header flags or received compressed/
context bodies, including the first piece of a fragmented body.

The sender allocates record IDs only. `write_pending(source_id, output)` uses the
recovery owner's current source identity and never consumes it. `commit_source()`
advances one immutable symbol only after recovery successfully copies it. The
composition obtains a read-only `next_source_id` snapshot, builds the envelope,
submits it and checks that returned ID before committing. A failed submit retains
the stage; a mismatch terminates the scope. Snapshot validity ends at that owner's
next successful submit, and the endpoint owns the engine exclusively. Retries use
the recovery engine's retained original bytes and never reseal a new source.

Sender bounds are a channel count of 1..256, native and symbol limits inherited
from the body codec, one maximum encoded body allocation, one staging encoder and
fixed per-channel state. No list of all fragments or cloned native frames is
built. Before stage commits, checked counts reserve all context/body record IDs;
identities never wrap. No local reset or mode switch exists in this slice.

## Pure composition API

The new `l2tunnel-aligned` crate owns one sender, one existing `Reliable`, one
aligned receiver and one fixed source handoff buffer. It imports algorithms; it
does not implement a second ARQ/FEC/codec. Its public interface is:

```text
Config { native_policy: NativePolicy, receiver: receiver::Limits, recovery: ReliableConfig,
         max_recovery_packet_bytes: usize }
Config::digest() -> Result<ConfigDigest, Error>
Endpoint::new(config, RecoveryContext) -> Result<Endpoint, Error>
enqueue_admitted(channel, native_frame, now: Duration) -> Result<(), Error>
poll_data(now, output, &mut OutboundBudget) -> Result<Option<usize>, Error>
poll_feedback(now, output, &mut OutboundBudget) -> Result<Option<usize>, Error>
receive_authenticated(packet, now) -> Result<(), Error>
prepare(channel, now, max_records) -> Result<Prepared, Error>
pending() -> Option<Delivery>
commit_delivery(now) -> Result<(), Error>
tick(now), deadline(), drained(), status(), max_packet_bytes()
```

Endpoint roles derive opposite global send/receive scopes. The receiver also exposes
its earliest record/source-hole deadline, included in the endpoint deadline. Config requires initial
source zero (the recovery allocator starts there), matching source size, a receiver
source window covering all receive/restored retention, canonical finite timing,
and an exact recovery-packet ceiling. All policy and limit fields, including
external overhead, are serialized under a fixed version domain for SHA-256 using
maintained `ring`; no manual crypto is introduced. The digest does not itself
perform negotiation or authenticate a caller.

At most one source moves out of recovery into the immutable handoff slot before
receiver admission succeeds. Receiver status separately counts not-yet-delivered native records, excluding
confirmed context and early-delivered tombstones; unknown fragment headers count
conservatively until classified. Runtime admission uses this count independently
from receipt ACKs. Receiver capacity/record-window pressure retains it
and stops further ordered dequeue. Native `prepare`/`pending`/`commit_delivery`
retain actual bytes across device WouldBlock; only whole-frame device acceptance
permits commit. Receipt ACK progress is not native-delivery credit. Applications
must stop reading native input when staging is busy and must keep servicing time,
feedback and receiver output under pressure. Enqueue success means a locally
retained frame, not peer/device delivery.

Recovery timeout, malformed identity, semantic decode failure and expiry terminate
the endpoint. Retained work is not discarded into a newly constructed epoch.
The ordered recovery queue, handoff slot and receiver have separate bounded stage
clocks. Receiver lifetime starts when receiver admission succeeds; the retained
handoff starts its own fixed lifetime when recovery transfers it. These are not
one original-wire-arrival deadline. Receiver lifetime in milliseconds must
strictly exceed the checked sum of all
configured ARQ retry intervals plus partial-block flush time. Unbounded external
carrier/device backpressure has no derivable delivery deadline: the finite
receiver lifetime deliberately fails closed and is not a delivery guarantee.

## Complete byte and storage accounting

For symbol size S, ARQ payload is exactly `48 + S`; the coded original is
`44 + 48 + S`. The full worst-case emitted repair packet is
`8 + 56 + k + 2 + 44 + 48 + S`, where k is the maximum generation source count.
It must fit `max_recovery_packet_bytes` before carrier protection. Complete path
cost adds `recovery.outer_overhead_bytes`, which must include the selected
carrier's protection/framing and IP/transport headers. All emitted source, retry,
repair and feedback records debit one shared `OutboundBudget` by actual recovery
bytes plus that overhead. No early short record or probe has a private budget.
The application must reserve feedback service within this common finite allowance.

The sender bound, receiver's existing conservative bound, recovery's configured
send/receive/restored/FEC reservations, one `48+S` output stage and one `48+S`
inbound handoff are independent finite charges. Metadata counts are bounded by
channel/record/source/generation limits. The receiver already accounts for final
fragment validation copy and pending native frame. Allocator bookkeeping is
platform-specific; this is not a measured resident-memory promise.

## Acceptance ledger

- [x] [MOD-ALIGNEDWIRE-01] Freeze exact envelope, APIs, bounds, provenance and ordered-recovery limitation before implementation. Evidence: [envelope](../../crates/l2tunnel-codec/src/aligned_envelope.rs), [sender](../../crates/l2tunnel-codec/src/aligned_sender.rs), [composition](../../crates/l2tunnel-aligned/src/lib.rs), [tests](../../crates/l2tunnel-aligned/src/tests.rs), [Python symbols](../../crates/l2tunnel-codec/tests/data/aligned-sender-goldens.tsv).
- [x] [MOD-ALIGNEDWIRE-02] Implement transactional per-channel sender and fixed envelope with independent actual Python full-symbol goldens. Evidence: [envelope](../../crates/l2tunnel-codec/src/aligned_envelope.rs), [sender](../../crates/l2tunnel-codec/src/aligned_sender.rs), [composition](../../crates/l2tunnel-aligned/src/lib.rs), [tests](../../crates/l2tunnel-aligned/src/tests.rs), [Python symbols](../../crates/l2tunnel-codec/tests/data/aligned-sender-goldens.tsv).
- [x] [MOD-ALIGNEDWIRE-03] Compose existing reliable recovery with authoritative source IDs, retained capacity handoffs, native prepare/commit and canonical digest. Evidence: [envelope](../../crates/l2tunnel-codec/src/aligned_envelope.rs), [sender](../../crates/l2tunnel-codec/src/aligned_sender.rs), [composition](../../crates/l2tunnel-aligned/src/lib.rs), [tests](../../crates/l2tunnel-aligned/src/tests.rs), [Python symbols](../../crates/l2tunnel-codec/tests/data/aligned-sender-goldens.tsv).
- [x] [MOD-ALIGNEDWIRE-04] Test malformed/scope/replay/serial/fragment limits, failed enqueue/submit, exhaustion and immutable retry bytes. Evidence: [envelope](../../crates/l2tunnel-codec/src/aligned_envelope.rs), [sender](../../crates/l2tunnel-codec/src/aligned_sender.rs), [composition](../../crates/l2tunnel-aligned/src/lib.rs), [tests](../../crates/l2tunnel-aligned/src/tests.rs), [Python symbols](../../crates/l2tunnel-codec/tests/data/aligned-sender-goldens.tsv).
- [x] [MOD-ALIGNEDWIRE-05] Test independent endpoints through real protected packets, loss/reorder, repair before RTO, ARQ fallback, shared byte budgets and native backpressure. Evidence: [envelope](../../crates/l2tunnel-codec/src/aligned_envelope.rs), [sender](../../crates/l2tunnel-codec/src/aligned_sender.rs), [composition](../../crates/l2tunnel-aligned/src/lib.rs), [tests](../../crates/l2tunnel-aligned/src/tests.rs), [Python symbols](../../crates/l2tunnel-codec/tests/data/aligned-sender-goldens.tsv).
- [x] [MOD-ALIGNEDWIRE-06] Run focused strict Rust/Python checks and coordinated stable repository aggregate; record scope and receipt. Evidence: [wave6 receipt](../../work/implementation-wave6/validation.json), 492 Rust cases including doctests and 36 Python cases, unchanged before/after source hashes; native OS qualification remains separate.
- [ ] [MOD-ALIGNEDWIRE-07] Integrate authenticated runtime negotiation, actual common MUX/device admission and native tests before exposing a client mode.
- [ ] [MOD-ALIGNEDWIRE-08] Port actual timed multi-source packing and unordered recovered-source handoff before claiming packed/early-short catalog parity.

## Finite verification

`cargo test --offline -p l2tunnel-aligned -p l2tunnel-codec -p
l2tunnel-recovery -p l2tunnel-reliable` passed 7 new composition tests, 48 codec
tests, 14 recovery tests plus its doctest, and 17 reliable tests. Codec tests with
`--no-default-features` passed 47 cases. Strict targeted Clippy and denied-warning
rustdoc passed for all four crates. All four actual Python generators reproduce
28 header, 328 body, 51 receiver trace and 2588 complete sender-symbol vectors.
The new generator calls the unchanged actual Python sender and records source
hashes; it does not implement a second aligned encoder.

Tests exercise both independent endpoint roles through real maintained AEAD/HMAC
protection with both custom prefixes, corrupted packet rejection and replay,
Cauchy restoration of a missing context before RTO, insufficient-rank ARQ fallback,
exact combined data/repair/feedback charges, full sender/recovery/native queues,
fragment progress, immutable pending output and terminal expiry. Keys in these
finite tests are test material; this is not a network authentication handshake or
native device/carrier qualification. The parent independently reviewed envelope,
source ownership, memory/expiry and budget boundaries with no material finding;
that review did not rerun tests.

The required `python3 tools/check.py` also [passed locally](../../work/aligned-envelope-checks/validation.json),
including the new sender fixture check and 33 Python tooling tests. This run did
not freeze concurrent source writers or compare before/after source hashes.
The later [wave6 receipt](../../work/implementation-wave6/validation.json) supplies
the coordinated stable aggregate for this slice: 492 Rust cases including
doctests and 36 Python cases, with identical before/after source hashes. The prior
[wave5 receipt](../../work/implementation-wave5/validation.json) qualifies the
previous header/body/receiver state only. The subsequent explicit RawIp extension
passes the current full focused suites: eight composition tests, 49 codec tests,
14 recovery tests plus its doctest, and 17 reliable tests. Its actual common MUX
and real-carrier runtime evidence is tracked in the separate runtime document.
Native client qualification, timed source packing and unordered early-short
release remain open.
