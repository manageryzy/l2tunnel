# Rolling and raw flow registration retirement

Status: implemented and integration-tested in finite local ownership and actual
loopback carrier tests. Required combined snapshot validation remains open. This additive
repair reuses the bounded Pipeline idle scanner accepted for aligned/packed.
No queue, wire, channel, timing, carrier or flow-capacity default changes.

## Ownership and implementation boundary

Both runtimes validate fixed CRC channel mapping and retain local FlowId only in
Pipeline queues or the one selected packet. That selected key pins its registration
until successful endpoint/fragment admission. Thereafter recovery, fragment and
native owners retain immutable channel plus bytes, never a local FlowId. Empty
idle registration retirement cannot remove those bytes, reset recovery/codec
state, alter channel ordering, or publish native-delivery credit. IDs remain
monotonic; same-key relearn keeps its deterministic channel. Prepared native
binding state proves header/channel validation, not a reference to a cache entry.

Each actor examines at most sixteen registrations and retires at most one per
turn, excluding its selected key. Temporary Flow(Capacity) retains the exact local
ingress or pending inbound native frame and retries. Rolling uses its existing
millisecond time domain and original native/recovery deadlines. Raw previously
learned only after complete reassembly consumed its source. The repaired path
retains exact completed bytes/channel in the existing finite native FIFO, then
retries learning ahead of the first device write. This changes no native queue capacity
and creates no second payload slot. Invalid inner headers/channel still fail
before any native side effect. Already queued packets cannot be retired.

## Checklist

- [x] [MOD-ROLLRAWFLOW-01] Reproduce terminal default flow 1025 and reverse learned-flow capacity before production behavior changes, retaining logs and hashes. Evidence: [before ingress](../../work/rolling-raw-flow21/before-ingress.log), [rolling reverse](../../work/rolling-raw-flow21/before-reverse.log), [raw completed-source reverse](../../work/rolling-raw-flow21/before-raw-reverse.log) and [source hashes](../../work/rolling-raw-flow21/before-source.json).
- [x] [MOD-ROLLRAWFLOW-02] Implement bounded registration retirement and exact temporary capacity backpressure for both owners without changing defaults or pure Pipeline APIs. Evidence: [rolling pump](../../crates/l2tunnel-runtime/src/rolling/pump.rs), [rolling owner](../../crates/l2tunnel-runtime/src/rolling/owner.rs) and [raw owner](../../crates/l2tunnel-runtime/src/raw_packet.rs).
- [x] [MOD-ROLLRAWFLOW-03] Test beyond-capacity sequential and reverse flows, pinned selection, recovery/native-held bytes, original deadlines and channel/identity continuity. Evidence: [rolling tests](../../work/rolling-raw-flow21/rolling-tests-final.log) and [raw tests](../../work/rolling-raw-flow21/raw-tests-final.log).
- [x] [MOD-ROLLRAWFLOW-04] Pass scoped tests, strict lint/docs/format checks and freeze exact source/command receipt over source21 plus the accepted aligned scanner bundle. Evidence: [exact scoped receipt](../../work/rolling-raw-flow21/validation.json).
- [ ] [MOD-ROLLRAWFLOW-05] Pass root-owned combined snapshot tools/check.py validation; native/P-family qualification remains separate.

## Preserved failures and scoped evidence

The before ingress regression fails independently in both owners with the default
1024-flow table and zero Pipeline queued packets, at injected 61 seconds for flow
1025. Reverse learned-flow regression also fails in both owners. Raw's before
case feeds actual encoded recovery/fragment/frame bytes into the independent
receiver and fails after complete reassembly consumed the source, precisely
identifying the payload-retention boundary. Afterward the completed payload stays
in the same finite native FIFO with its channel and a prepared-validation flag;
no second payload queue or channel/FlowId-dependent recovery state is introduced.

The full rolling module passes fourteen tests; raw passes sixteen. Direct
injected-time tests exercise 1100 successive local originals and 1100 reverse
learned flows in each path, with increasing local IDs, stable CRC channels and
exact retained/dequeued bytes. The raw reverse test additionally compares all
1100 actual device-write payloads. These direct handoff fixtures are distinct
from real carrier execution; they are not described as 1100-flow native labs.

New actual authenticated UDP rolling full/half cases and original-owner raw
full selective-repeat/half Cauchy cases send sixteen distinct keys each direction,
with capacity four, disjoint reverse keys, ten-millisecond idle age, actual loss
and reorder plus a 70-millisecond native-write pause. Received original bytes are
exact, raw global source ordering and cumulative native credit remain intact, and
cancellation drops each original raw I/O once. Existing UDP/QUIC TAP/TUN rolling,
raw protection/recovery/loss/fragmentation and malformed-control cases also pass.

Selected FlowId-bearing packets pin their key after dequeue. A raw admitted
4000-byte frame leaves fragments/recovery ownership unchanged during retirement
and 1100 later admissions. A completed raw native frame survives capacity,
WouldBlock, prepared-cache retirement and exact once delivery. Full-table malformed
inner headers and wrong CRC channel still fail before a device write. Rolling
prepared-native bytes and the original deadline survive registration removal;
expiry grants no delivery credit. Its existing late-success and real blocked
native expiry regressions remain passing. Raw has no separate completed-native
per-frame expiry; this repair preserves its existing carrier/recovery and first
fragment timers and adds no new deadline claim.

Verification uses a private source21 copy plus the accepted frozen aligned
scanner bundle; the root's corrected aligned ledger is a reviewed documentation
input. All-target no-dependency strict Clippy, warning-denied rustdoc and package
formatting are recorded in the receipt. The required root-owned combined
`python3 tools/check.py` run, privileged native labs, large-window recovery,
congestion fairness, full Python parity and clean shutdown remain separate gates.
