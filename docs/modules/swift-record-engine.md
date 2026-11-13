# Reusable Swift numbered records

Status: **implemented; focused pure and legacy-runtime tests passed**,
2026-11-13. The design was written and reviewed before implementation. This subordinate
FIX-13/SW-14 extraction makes the existing runtime's complete data algorithm
available beneath either the retained Swift v2 protection or the common secure
record composition. It does not implement a new connection mode, handshake,
carrier, control protocol or default. The existing [Swift ledger](swift.md),
[common session contract](secure-session.md) and full SW-11 remain authoritative.

## Boundary and compatibility

The existing pure `Sender`/`Receiver`, GF arithmetic, connection classifier and
exact header compression remain unchanged. `l2tunnel_swift::records` composes
them into the same ordered channels currently owned by the legacy runtime. It
owns the common packing-byte budget, per-channel header contexts, urgent
retransmission preference, round-robin new-data scheduling, channel-tagged data,
concatenated feedback, native delivery, cumulative algorithm counters and
directional drain/reset hooks.

The record engine accepts injected monotonic microseconds and an externally
owned full 64-bit `RecordNumber`. That number is the exact authenticated data
record number, including gaps occupied by Swift feedback or other channels.
It remains the repair coefficient seed. A caller must not substitute a truncated
outer QUIC/RTP number, per-channel sequence, recovery source ID or new local
counter. The same number passed to `poll` must protect its returned body, and
`accept` receives the number actually verified by the corresponding receiver.
The caller checks counter exhaustion and the maximum output/cover budget before
polling; failure after algorithm progress is terminal or an explicitly retained
attempt, never a reason to encrypt the body with a different number.

The caller authenticates, checks replay, selects User authority and validates
the active/draining scope before `accept`. This engine cannot grant authority
from a kind byte, Ethernet field or apparent control payload. Swift feedback is
data-algorithm feedback inside User records; authenticated management remains
the separate session service. The engine contains no keys, replay window,
handshake identity, secret export, Tokio, OS handle, privilege, real clock,
device setup, pacing budget or socket ownership.

Legacy v2 wire bodies remain byte-for-byte unchanged: kind in the low two bits,
channel in the high six, unchanged source/repair headers and GF seed, and the
same concatenated feedback blocks. Header compression still validates its own
reconstruction and uses literal fallback for arbitrary bytes, unusual headers,
wrong checksums and zero tails. Each accepted native packet follows the same
connection-affinity channel and shares the configured admission budget.

## Public API

```rust,ignore
Layer::{Ethernet, Ip}
Config { codec: swift::Config, channels: usize, layer: Layer, max_native: usize }
RecordNumber(pub u64)
Admission::{Accepted, Full, PacketSize}
Stats { sender: swift::SenderStats, receiver: swift::ReceiverStats,
        native_read: u64, native_dropped: u64, header_bytes_saved: u64 }
Error::{Configuration, Codec(swift::Error), NotDrained, Admission}

Engine::new(config: Config) -> Result<Engine, Error>
Engine::{send_config, receive_config}(&self) -> Config
Engine::body_limit(&self) -> usize
Engine::has_room(&self) -> bool
Engine::offer(&mut self, now: u64, packet: &[u8]) -> Result<Admission, Error>
Engine::poll(&mut self, now: u64, number: RecordNumber, allow_data: bool)
    -> Result<Option<&[u8]>, Error>
Engine::accept(&mut self, now: u64, number: RecordNumber, body: &mut [u8])
    -> Result<(), Error>
Engine::pop(&mut self) -> Result<Option<&[u8]>, Error>
Engine::data_ready(&self, now: u64) -> bool
Engine::{data_deadline, feedback_deadline}(&self) -> Option<u64>
Engine::{send_drained, receive_drained, deliverable}(&self) -> bool
Engine::unconfirmed(&self) -> usize
Engine::{source_floor, feedback_floor}(&self) -> RecordNumber
Engine::replace_send(&mut self, config: Config, feedback_from: RecordNumber)
    -> Result<(), Error>
Engine::replace_receive(&mut self, config: Config, source_from: RecordNumber)
    -> Result<(), Error>
Engine::stats(&self) -> Stats
```

Configuration validates checked native/header expansion, existing codec bounds
and 1..=64 channels before allocation. Layer and native packet bound are fixed
physical-session properties; directional codec budgets/channel counts can
differ. Replacements must retain that physical format. `offer` rejects packet
size or shared-queue pressure before changing a compressor context. A packing
engine refusing a pre-admitted compressed record is an explicit terminal
invariant error, not a silently dropped context update.

`poll` considers due feedback first regardless of `allow_data`, preserving the
legacy feedback priority. That flag controls only source/repair/retransmission
production. The outer owner charges every emitted body, including feedback, to
the same selected-carrier budget; it supplies actual overhead and transport
backpressure. It combines the separate wake components with its pacing and
transaction deadlines. The library supplies no extra uncharged bandwidth.

`accept` may strip channel tags in its mutable authenticated workspace. A
malformed authenticated body is a terminal protocol error; partially processed
feedback is not promised to roll back. It validates nonempty retained body
bounds, channel indices, feedback block lengths and existing inner grammar.
Returned native bytes remain valid until the next mutable call.

## Drain and policy changes

`send_drained` means all packing queues are empty and every retained source is
confirmed. `receive_drained` means no possibly deliverable packet and no pending
recovery state remain. Replacements require the corresponding drained state,
accumulate old algorithm/header counters, reset only that direction's channel
and header contexts, and install the caller's authenticated number floor. Late
old sources increment the existing duplicate observation; old feedback cannot
update fresh senders. Security counters, replay state and keys remain outside
and are never reset by these operations.

The legacy runtime keeps proposal/digest agreement, admission stopping,
per-direction barriers, terminal control-write custody, the original absolute
transaction deadline, requester outcomes and native-write accounting. It uses
these hooks only at its existing barrier points. No local reset authorizes a
peer switch. Migration of that private TLS policy grammar into the stable common
control service remains SW-15/FIX-11 work, including duplicate/lost replies,
matching digests, bounded retries, original deadlines and drain barriers.
SW-13 internal policy changes do not replace SW-11 switching between Swift and
the other record profiles. RLNC, parity, rolling, packed, proxy and all 47 P-*
mode-parity gates remain in scope.

## Known legacy limits and evidence plan

The existing channel-feedback packer reserves the worst-case 140-byte block
before asking a receiver for feedback. Codec configurations accept 64..139-byte
datagram bodies, but that composition cannot emit a feedback block at those
bounds. This extraction preserves those accepted bounds and that behavior;
it does not silently impose a new minimum or claim those small budgets work.
The current client requires path MTU at least 576 and avoids this limit. A new
common selected profile may reject such an unsupported composition at setup
until separately specified and tested feedback packing supports it.

The legacy client already fixes native layer and maximum packet size for both
directions and across policy changes. Enforcing that physical-format invariant
does not remove an implemented client option. New carrier composition must keep
requested/effective settings and unsupported combinations observable.

The [extracted implementation](../../crates/l2tunnel-swift/src/records.rs) and
[eight focused regressions](../../crates/l2tunnel-swift/src/records/tests.rs) are
on disk, and the [legacy runtime consumer](../../crates/l2tunnel-runtime/src/swift.rs)
delegates its data algorithm to that implementation. The source-stable
[focused receipt](../../work/swift-record-engine-20261113/focused-validation.json)
records eight passing record-engine regressions and all 16 existing Swift
runtime regressions, strict package Clippy and warning-denied rustdoc. The inputs
include those packages and resolved local dependencies, with concurrent
undeclared `runtime/src/secure_udp/**` and documentation explicitly outside that
focused input scope. Earlier failed compile/lint attempts remain alongside the
successful receipt. The subsequent [full aggregate](../../work/shared-session-client-20261113/validation.json)
also passed, including the [actual shared-factory composition](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs).
Selected service/native integration remains a separate gate. The tests preserve the exact
source/repair/feedback bytes and number-dependent GF behavior; exercise IP and
Ethernet literal/compressed packets with arbitrary zero tails; check shared
queue/header-context admission, multi-channel loss/reorder/repair and fairness;
bound malformed channel/feedback parsing; and prove drained directional
replacement preserves counters and rejects old feedback/data. Existing runtime
transfer, policy-switch and paused-deadline tests then exercise the extracted
consumer. The common same-socket fixture must use this complete record engine,
not only a raw single Swift stream. Tests and loopback receipts remain distinct
from native devices, Windows/Android, actual OpenVPN/HTTPS composition, ISP
classification and performance qualification.

- [x] [SWR-01] Review the pure record API, exact channel/body/number contract, physical-format invariant and preserved limits before implementation. Evidence: this design preceded the [implementation](../../crates/l2tunnel-swift/src/records.rs); the reviewed API is an implementation boundary, not an owner choice of a new wire protocol or default.
- [x] [SWR-02] Extract actual packing, exact header records, channel affinity, data/feedback scheduling, native delivery and cumulative statistics without duplicate crypto or control ownership. Evidence: [pure record engine](../../crates/l2tunnel-swift/src/records.rs) and [legacy consumer](../../crates/l2tunnel-runtime/src/swift.rs), with eight pure and 16 runtime regressions passing in the [focused receipt](../../work/swift-record-engine-20261113/focused-validation.json).
- [x] [SWR-03] Prove byte-exact source/repair/feedback, full-number GF semantics, arbitrary native bytes, queue/context admission, channel bounds and loss/reorder behavior with focused regressions. Evidence: eight passing [record regressions](../../crates/l2tunnel-swift/src/records/tests.rs), including frozen source/feedback and independently calculated GF repair bytes at seed `0x1_0000_0007`, 16-channel loss/reorder/duplicates, IP/Ethernet zero tails, context-preserving queue refusal and malformed bounds.
- [x] [SWR-04] Preserve negotiated directional drain/reset hooks, late old-data/feedback rejection and cumulative counters without resetting security state; retain full SW-11 and original transaction deadlines. Evidence: passing pure directional-reset/floor/stat tests and all existing [runtime switch/deadline regressions](../../crates/l2tunnel-runtime/src/swift.rs), including silent proposal/barrier and blocked terminal-control-write cases. These are hooks and retained Swift-internal policy behavior; full SW-11 remains open.
- [x] [SWR-05] Consume the record engine from the legacy runtime and remove its duplicate data algorithm while preserving public runtime APIs, v2 wire, pacing/charged feedback, native accounting, policy barriers and terminal-report behavior. Evidence: the [consumer delegates packing/recovery/header work](../../crates/l2tunnel-runtime/src/swift.rs); all 16 legacy runtime tests passed, including actual two-runtime loopback traffic and paused-clock deadline/terminal reporting. This does not qualify a native device or the target common carrier runtime.
- [x] [SWR-06] Compose the complete extracted engine through common protected records on the original selected UDP socket, with authenticated User/Control dispatch, exact bytes, loss/reorder, bounded control and separate common-session lifecycle gates. Evidence: the [real factory composition](../../crates/l2tunnel-client-core/src/secure_udp_tests.rs) uses the full extracted Engine, actual Noise/member roots, common AEAD, fixed reliable control and original UDP pair for both covers/profiles; exact bidirectional bytes, charged loss/duplicates/reordering and key generations passed in the [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json). Local data-scope staging is not negotiated SW-11.
- [x] [SWR-07] Record source-stable focused tests, formatting, warning-denied workspace checks and the required aggregate result; distinguish finite library/runtime fixtures from native and platform validation. Evidence: the earlier [pure/runtime focus](../../work/swift-record-engine-20261113/focused-validation.json) and [source-stable full aggregate](../../work/shared-session-client-20261113/validation.json) and [focused commands](../../work/shared-session-client-focused-20261113/attempt-5/validation.json) passed with explicit source identities. Native devices, network performance and Windows/Android execution remain separate.

The parent acceptance gates are not completed by these scoped results.
