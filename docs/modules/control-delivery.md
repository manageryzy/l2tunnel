# Fixed reliable control delivery

Status: implemented and locally protocol-tested v0, designed before implementation.
This is the bounded
delivery part of SEC-07, FIX-11 and MGT-09, not authenticated session setup,
management semantics, carrier negotiation or complete hot switching. Existing
TLS-specific control and historical experiments remain available until their
actual replacement is integrated and qualified.

## Public boundary and ownership

`l2tunnel_management::delivery` reuses the existing pure `SelectiveRepeat`
recovery engine. It owns a distinct, fixed control recovery context, finite
source retention and an original caller-supplied expiry. It has no data-profile
epoch setter, socket, clock, random source, device or crypto implementation.
Time is injected as monotonic `Duration`. Maintained common packet protection
must authenticate the control class and all received bytes before admission.

The proposed public API is:

```text
Settings { recovery: ArqConfig, interval: Duration,
           packets_per_interval: u32, bytes_per_interval: usize,
           wire_overhead: usize }
Binding { session: SessionId, lane: LaneId, local_role: Role,
          control_epoch: u64 }
Service::new(settings, binding, now, expires) -> Result<Service, Error>
Service::submit(frame: &[u8], now) -> Result<u64, Error>
Service::receive(verified: Ingress, packet: &[u8], now) -> Result<(), Error>
Service::poll(now, shared_wire_allowance, output) -> Result<Option<Emission>, Error>
Service::deliver(output, now) -> Result<Option<(u64, usize)>, Error>
Service::{deadline, drained, statistics, retained}(...)
Emission { bytes: usize, wire_bytes: usize }
```

The full 128-bit session, physical lane and sender role must match verified
management-origin evidence. User/unauthenticated ingress is rejected before
recovery parsing, allocation or state mutation. A matching byte prefix does not
grant control authority. The fixed control epoch is distinct from switchable
data epochs. Upper layers parse a delivered source as a complete stable envelope
and retain transaction request/digest/barrier semantics; recovery ACKs alone do
not mean a management action committed or reached the native device.

## Wire and resource contract

The existing selective-repeat wire is reused unchanged: a 44-byte source header
or 48-byte receipt, with network-order context and source identities. Source
bytes are opaque and exact, including arbitrary zero tails. Common security and
carrier appearance wrap each emitted attempt, using a fresh security packet
number even when retransmitting the same recovery source. The recovery source
ID and logical management request identity do not change on transport retries.

The source limit includes one complete control envelope. This first version
does not fragment an oversized management frame; it returns an explicit size
error rather than silently applying partial configuration. Configuration must
negotiate a suitable source/path budget or a later reviewed fragmentation layer.
Send/receive byte and count bounds remain independent. Counts are at most 64,
payload retention at most 16 MiB in each direction, and retry count at most 1024.
There is no default lifetime or retry policy selected by this module.

Every emission is charged its exact recovery length plus a fixed negotiated
`wire_overhead` covering the selected common protection, cover and IP/UDP cost.
The caller additionally supplies the current shared session wire allowance.
The control reservation is inside that session budget, never extra bandwidth.
Each interval reserves one feedback opportunity until feedback is emitted. When
a local source is retained, it also reserves one worst-case source opportunity
until a source or retry is emitted. Feedback is considered first only when its
emission preserves that first source slot and wire cost; source admission
preserves the first feedback slot and cost until feedback has actually emitted.
Both reservations apply to the interval and caller-supplied shared allowance.
Once one class emits, its reservation is released for the remainder of that
interval. Thus two slots can carry one feedback and one source in either order,
and repeated incoming sources or duplicates cannot spend the reserved first
source opportunity entirely on receipts. A retained source waiting for its RTO
can leave reserved capacity unused; the reservation does not advance that retry.
Actual data/control scheduling against a saturated native runtime remains an
integration gate.

Polling hands an encoded attempt to the caller; its recovery timer starts at
that handoff, as in the existing recovery API. The caller must retain it in a
bounded carrier send slot until sent or explicitly failed. This API does not
claim physical-send timestamps, wire delivery, TCP HOL avoidance or zero copy.
An output smaller than the configured recovery-packet ceiling, or an allowance
too small for admission, cannot consume a source attempt. Queue/backpressure,
malformed binding, monotonic-time, deadline and retry failures are explicit.

## Deadlines and validation

The absolute expiry is supplied once at construction. Input, duplicate sources,
receipt packets and interval refill never extend it. Every operation that takes
time checks monotonicity and expiry before state changes. The next wake combines
the independent source and feedback timers, their corresponding reservation and
allowance admission, service refill and original expiry. Blocked feedback cannot
force repeated past-deadline wakes while the reserved source waits for its RTO.
An external shared allowance increase is an explicit poll trigger. Emitted wire
cost is subtracted from the remembered shared allowance used by the next-wake
calculation. No waiting operation resets a data-mode transaction.

The first-source/first-feedback correction passed all eight delivery regressions
in the parent-serialized local run (34 management tests total), including
continuous duplicate-input feedback pressure and reserved-source RTO cases.
The same focused run passed the two-socket Noise/Swift/control composition and
strict workspace Clippy. These finite cases establish bounded source/feedback
opportunities under the tested interval budgets; native scheduling fairness
remains part of CDL-07.

- [x] [CDL-01] Implement bounded construction, fixed context and exact source delivery using maintained selective repeat, without clocks or I/O. Evidence: [service](../../crates/l2tunnel-management/src/delivery.rs) and [bounded source tests](../../crates/l2tunnel-management/src/delivery/tests.rs).
- [x] [CDL-02] Reject user-origin, wrong session/lane/role, malformed or conflicting input without consuming valid state. Evidence: [origin/context/conflict and preserved-delivery test](../../crates/l2tunnel-management/src/delivery/tests.rs).
- [x] [CDL-03] Preserve source identity and exact bytes through loss, reorder, duplicates and receipt loss, with bounded retry and retention. Evidence: [scripted loss/reorder and silent-peer tests](../../crates/l2tunnel-management/src/delivery/tests.rs).
- [x] [CDL-04] Enforce exact charged interval/shared allowance, first-source and first-feedback reservation under bidirectional source saturation and continuous valid duplicate pressure, with no attempt consumed by undersized output or blocked feedback busy-wakes while a source awaits its RTO. Evidence: all eight [delivery regressions](../../crates/l2tunnel-management/src/delivery/tests.rs) passed in the [source-stable focused run](../../work/shared-session-primitives-20261113/focused-validation.json).
- [x] [CDL-05] Enforce original expiry and monotonic time through duplicates, interval refill, backpressure and silent peers; keep fixed control context across data-scope changes. Evidence: [deadline tests](../../crates/l2tunnel-management/src/delivery/tests.rs) and [same-socket scope-change fixture](../../crates/l2tunnel/tests/common_session_udp.rs).
- [x] [CDL-06] Compose common authenticated packet protection and selectable cover with this service, rejecting protected user payloads as control and preserving old-scope control during new data policy selection. Evidence: [authenticated class/route tests](../../crates/l2tunnel/tests/secure_record.rs) and [Noise/Swift/control UDP fixture](../../crates/l2tunnel/tests/common_session_udp.rs).
- [ ] [CDL-07] Integrate actual selected-carrier runtime scheduling, native saturation, hot switches, liveness, recovery and shared client API; component tests do not close this gate.

The integrator owns this document, `management/src/delivery.rs`, its tests,
management dependency wiring and facade integration. Worker-owned cover, Noise
and packet-security APIs must be frozen before consumers use them. Verification
records commands and source identities in the [focused receipt](../../work/shared-session-primitives-20261113/focused-validation.json)
and [required local check result](../../work/shared-session-primitives-20261113/validation.json).
Component tests and loopback fixtures do not qualify CDL-07 or its parent gates.
