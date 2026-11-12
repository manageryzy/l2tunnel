# Explicit rolling-frame UDP/QUIC runtime slice

Status: the explicit runtime slice and finite unprivileged authenticated-carrier
tests are implemented and focused-tested. The interface/ownership contract was
recorded before code. This is
an additive explicitly selected runtime module, not a change to existing UDP,
QUIC, aligned/packed, proxy, client or default recovery modes. Full local/global
family, W8192 deployment, native activation and performance gates stay open.

## API and authenticated selection

`runtime::rolling` exposes `Config { delivery: managed::DeliveryConfig,
scheduler: rolling::scheduler::Policy,
pipeline: PipelineConfig, stream: u32, epoch: u64, work: WorkBudget,
passes_per_turn: usize }`, derived `Config::for_udp/for_quic`, UDP/QUIC
`base_session_config` and lane `session_config` functions, `udp_carrier_config`,
`UdpLink` / `QuicLink` full and paired constructors, and `run_udp/run_quic`.
RuntimeConfig retains TAP/TUN, compression, native ceiling/queue and poll period.
Complete scheduler scalar policy, epoch/stream, tick unit (milliseconds), shared
Pipeline/MUX policy, runtime and physical carrier/duplex policy are canonically
bound **before authentication** under the rolling-frame v2 digest domain, including
both canonical directional delivery configurations. Factories require the delivery
argument; there is no implicit queue-sized fallback. Each
full Scope uses the actual authenticated 16-byte session, negotiated epoch,
checked stream+physical-lane and global direction. Existing retained full/pair
factories verify actual link binding, roles and independent lane identities.
No authenticated old fixed or aligned connection can be relabelled rolling.

All dependencies already exist. The shared library needs only a new module
export. Reuse existing crate-private UDP/QUIC bound link factories, datagram
read/write tasks, retained reliable-control framing/heartbeat tasks and shared
wire ledger; an additive ledger constructor reserves the exact 64-byte rolling
feedback size without changing any existing profile. No new crypto, replay
primitive, TLS object, socket replacement or parallel control protocol is added.
The existing carrier authenticates/replay-checks complete datagrams; rolling
feedback is parsed only on the authenticated reliable control ACK class with a
separate exact magic/length. An Ethernet EtherType or payload grants no control
authority. Reliable native delivery credit remains its own control class.

Transport Config's existing SelectiveRepeat variant is required as the baseline
carrier geometry/binding; this explicit rolling owner instantiates no ARQ or
sealed Cauchy engine. The complete distinct rolling digest and link wrapper make
that interpretation explicit. Existing transport enums and defaults are intact.

## Frame and bounded ownership path

Every native packet, including a user latency/TCP-control probe, enters the same
Pipeline MUX (TAP FIFO/RR or explicit transparent-TUN DRR) before selection.
Selected packets pass FrameCodec and Fragmenter. One bounded frame batch is
retained per sending lane. Each rolling original contains a checked u16 channel
plus one complete existing LX fragment; its actual nonempty bytes are encoded by
the real causal rolling Sender and full-byte GF repairs. Global directions own
independent Sender/Receiver instances and identity spaces. The receiver obtains
only authenticated received wire bytes, never sender payload storage.

Budgeted Receiver service publishes ordered original fragments to the existing
Reassembler and FrameCodec. Only complete validated original frames enter the
bounded native output queue. WouldBlock retains exact bytes; only successful
full PacketDevice acceptance advances cumulative native-delivery credit. Decode
receipt/handoff is separate from that credit. Sender admission uses actual native
bytes and record counts with bandwidth/causal-RTT credit, independently of local
queue capacity. Rolling W debt, Pipeline queues, one pending ingress/selected
packet and one bounded fragment batch retain their own bounds. The receiver
enforces the authenticated native byte/record limits. Peer credit regression/beyond-admission, wrong channel/sequence,
wrong direction/kind, malformed source/feedback and expired ownership fail.

One finite shared wire ledger covers lanes, source/repair emission, feedback and
control reservation; no per-lane multiplication of configured rate. A reserved
one-slot writer queue must exist before confirming rolling output. A retained
feedback watch slot is a bounded replaceable ownership handoff: coalescing can
lose an older receipt, and later stale-tail events elicit fresh cumulative
feedback. This is not a claim of physical wire or native delivery. Existing
reliable writer operation deadlines cover held control. There are no unbounded
input, output or retry queues. The final original fragment identifies each native
record's first-flight completion; the datagram writer records its actual successful
handoff before notifying the owner through a bounded non-coalescing channel.
Repairs and retry handoffs never renew it. Authenticated credit records capture
receipt time before awaiting the owner queue. The delivery controller receives
event time and observation time separately, preserving original flush/sample
deadlines through actor stalls. Neither timestamp claims physical-wire departure.

The scheduler uses elapsed monotonic milliseconds, original debt/job/handoff
bounds and finite per-call/per-turn work. Reassembly keeps its first-fragment
expiry; each complete native output keeps its completion-time handoff expiry.
New input, polling and blocked writes cannot renew existing deadlines. Before
the first native write, validate the inner packet through Pipeline classification
and prepare its exact learned flow/channel binding; retain that preparation on
WouldBlock. Check the original native deadline both immediately before and after
the synchronous write. Late successful writes do not publish delivery credit.
All Pipeline enqueue/learn timestamps share the same millisecond domain; mixing
untruncated ingress time with truncated reverse learning caused and then fixed a
reproducible Flow(TimeRegression) matrix failure. Terminal
carrier/codec/credit/time errors cancel and join all owned tasks. The initial
runtime has no clean-drain protocol or hot reload; test cancellation is not a
clean-close receipt.

## Focused evidence and limits

The [scoped receipt](../../work/rolling-runtime16/validation.json) and
[report](../../work/rolling-runtime16/REPORT.md) record exact owned source and
root-owned helper/export hashes. Nine rolling tests cover sixteen actual
protected-UDP full/half TAP/TUN × cover × integrity/confidentiality cases, four
genuine-QUIC full/half TAP/TUN cases, a separately explicit owner-boundary final
feedback drop followed by stale-tail/new-receipt recovery, native WouldBlock,
original native expiry, changed authentication binding, actual authenticated bad
scope/native-credit rejection, malformed inner/channel no-injection and late
successful-write no-credit behavior. Datagram relays introduce actual local
loss/reorder; all peers compare independently received exact frames, including
opaque Ethernet payloads containing control-like bytes. Reliable feedback on
real carrier connections remains reliable; the separate owner-boundary drop is
not described as dropping authenticated TLS stream bytes.

This initial runtime accepts W1..128 and finite policy-controlled work/passes;
actual recovery matrices use W8. Both pure scheduler total reservations and
primitive reservations are checked before link/device ownership. Native queue,
Pipeline, one selected/ingress packet, one frame fragment batch per sender,
rolling storage and authenticated receive channels remain independently bounded.
Flow registrations are a concurrent retained-registration bound. Bounded idle
retirement, exact temporary capacity backpressure and finite beyond-capacity flow
churn are tracked in the [rolling/raw retirement ledger](rolling-raw-flow-retirement.md).
These finite tests do not qualify W8192 memory/CPU, unbounded flow churn,
pacing/congestion fairness, native namespace/device activation, clean shutdown
or complete local/global Python-family parity.

## Finite verification gates

- [x] [MOD-ROLLINGRT-01] Implement exact additive profile binding, validation and retained full/paired UDP/QUIC link factories; reject mismatches before device reads. Evidence: [scoped tests and exact-file receipt](../../work/rolling-runtime16/validation.json).
- [x] [MOD-ROLLINGRT-02] Compose common MUX, FrameCodec/Fragmenter/Reassembler and actual rolling scheduler with bounded data/feedback/native ownership and original deadlines. Evidence: [scoped tests and exact-file receipt](../../work/rolling-runtime16/validation.json).
- [x] [MOD-ROLLINGRT-02A] Reserve the exact selected 64-byte feedback cost in the shared wire ledger; verify full/half shared clones, control after maximum data, exact refill and byte/packet/overflow/invalid-bound rejection. Evidence: root-owned `selected_feedback_reservation_*` tests, both passed in the [focused receipt](../../work/rolling-runtime16/validation.json); old default ledger construction is unchanged.
- [x] [MOD-ROLLINGRT-03] Test independent full-byte TAP/TUN full/half actual authenticated UDP and genuine QUIC loopback, loss/reorder and queued native backpressure; separately prove feedback-loss recovery at the exact owner boundary. Evidence: [scoped tests and exact-file receipt](../../work/rolling-runtime16/validation.json).
- [x] [MOD-ROLLINGRT-04] Pass focused strict lint/docs/tests, record exact source hashes and independent scope review; then join a root-owned stable aggregate. Evidence: [focused receipt](../../work/rolling-runtime16/validation.json), root independent readback and [wave18 stable aggregate](../../work/implementation-wave18/validation.json), 987 Rust/142 Python cases with strict workspace lint/docs and all 620 source inputs unchanged.
- [x] [MOD-ROLLINGRT-04A] Pass the scoped rolling/helper tests, strict runtime no-deps all-target lint, warning-denied docs, formatting and root independent readback; freeze exact input hashes. Evidence: [focused receipt](../../work/rolling-runtime16/validation.json). Whole-workspace aggregate remains the parent task above.
- [ ] [MOD-ROLLINGRT-05] Add separate client selection, native owned-lab capture qualification, large-window service/memory measurements and complete Python family parity before closing parent rolling06/07 gates.
- [ ] [MOD-ROLLINGRT-06] Replace queue-sized native flight admission with authenticated actual-byte bandwidth/RTT credit and independent metadata bounds. Prove admission beyond64 with the local queue unchanged, fragment-complete first-flight timestamps, pressure, send failure and original deadlines; pass current carrier tests and the combined aggregate.
