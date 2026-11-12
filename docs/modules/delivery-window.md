# Bounded bandwidth-delay delivery window

Status: pure controller, authenticated bidirectional policy, shared client API and opt-in Linux TCP/TLS runtime implemented and locally integration-tested. Native80Mbps acceptance and wider carrier integration remain pending. No endpoint TCP cwnd or advertised-window control is provided. This ledger supplements FC flow-control work and is linked from the main checklist.

- [x] [MOD-BDP-01] Independent actual-byte and record accounting with bounded preallocated metadata. Evidence: [focused test source](../../crates/l2tunnel-flow-control/src/delivery_window/tests.rs), `delivery_window::tests::bootstrap_80mbps_70ms_has_875kb_separate_actual_byte_and_record_limits` and `early_feedback_never_invents_flush_timestamp_and_pending_metadata_is_bounded`.
- [x] [MOD-BDP-02] Causal full-flush-to-authenticated-device-feedback observations, clamps, EWMA, stale fallback and checked cumulative boundaries. Evidence: [focused test source](../../crates/l2tunnel-flow-control/src/delivery_window/tests.rs), `cumulative_feedback_uses_actual_small_bytes_and_latest_known_full_flush`, `measured_rtt_grows_shrinks_clamps_and_stales_without_revoking_debt`, `sample_clamps_ring_wrap_and_cumulative_overflow_are_bounded`.
- [x] [MOD-BDP-03] Original absolute full-flush deadlines and failure/overflow paths. Evidence: [focused test source](../../crates/l2tunnel-flow-control/src/delivery_window/tests.rs), `retries_cannot_renew_original_flush_deadline_and_expiry_is_terminal`, `invalid_bounds_time_and_feedback_preserve_accounting`.
- [x] [MOD-BDP-04] Authenticated immutable per-direction policy, runtime full-flush/delivery wiring and independently observable byte target/record cap/local queue. Evidence: [runtime receipt](../../work/managed-delivery25/validation.json), 204 runtime tests including six new delivery cases; [client receipt](../../work/client-delivery25/RECEIPT.md), five focused API tests. Real authenticated TLS with mock TAP/TUN devices covers full/paired-half modes, exact mixed-size packet delivery, 128 outstanding records with local queues of two, recycling and authenticated reload barriers. This is local integration evidence, not native kernel throughput.
- [x] [MOD-BDP-06] Selective exact-native delivery and first-flight accounting preserve independent completion order, bounded retained span and original deadlines, while cumulative callers retain their API behavior. Evidence: [pure-stage receipt](../../work/aligned-delivery27/pure-validation.json),49 unit tests plus one doctest, including 1500/40-byte reordering, ACK-before-flush, selective/cumulative overlap, ring reuse and128 mixed-size records. This receipt checks the pure primitive only; actor integration is recorded in [the aligned ledger](aligned-runtime.md), and native v2 qualification remains open.
- [ ] [MOD-BDP-05] Actual loaded native80Mbps A→B acceptance with exact payload, cleanup and both-direction wire accounting. Evidence: planned; unit tests do not prove throughput.

## Contract

`delivery_window::Controller` uses only std and existing injected `target::Micros`. `Config` explicitly selects original-native target bandwidth, bootstrap/min/max service RTT, headroom percentage, minimum/maximum outstanding bytes, maximum records, maximum packet length, metadata allocation budget, sample TTL and admission-to-full-flush timeout. No local queue length is used to derive the delivery window. All original packets, including small TCP ACK packets, charge their actual native byte length and one record. Outer framing, retransmissions, probes and feedback still need the integrating common MUX/wire budget; this primitive does not exempt any traffic.

The future byte target is ceil(bandwidth_bps * bounded_RTT_micros * headroom_percent /800000000), clamped to the configured minimum and hard maximum.80Mbps,70ms and125% yields875000 bytes. Maximum outstanding bytes is at most64MiB, maximum metadata slots8192, sample/minimum/maximum RTT and deadlines are finite. Record cap is independent: many small ACKs cannot consume unlimited metadata even below the byte target. Explicit metadata bytes are checked before fallible allocation; no payload storage is allocated or inferred.

`preview_admit(bytes,now)` validates without reserving; `admit` commits actual bytes and returns the immutable cumulative `Credit {bytes,records}` boundary. Same serialized owner must commit after a preview; a preview creates no peer promise. Targets may shrink below existing outstanding debt; debt remains fully accounted and new admission blocks until byte/record constraints permit it. A new session/policy owner is required for a configuration change; this module provides no unauthenticated hot switch.

`Config::validate` checks all finite policy and metadata bounds without allocating. `confirm_flushed(record_ordinal,now)` confirms only an actually fully flushed ordered prefix. It is not admission, a scheduling peek, or a successful partial write. Duplicate confirmations preserve original per-record times. `delivered(Credit,now)` consumes authenticated cumulative remote packet-device delivery feedback, not transport ACKs. Byte and record counters must match an originally admitted exact record boundary. `credit_at_record(ordinal)` permits older ordinal-only authenticated framing to resolve the original actual-byte boundary locally; future/stale ordinals are rejected. The caller still authenticates session/epoch/direction before invoking it.

A cumulative feedback completion contributes at most one sample, from the highest newly delivered record whose full-flush timestamp was already known and strictly precedes receipt. Sample is receipt minus original full flush. It includes remote device/actor and feedback service delay and is not native TCP RTT, minimum-path RTT or endpoint cwnd. Cumulative coalescing does not create a sample for every record. An unobserved flush never receives an invented timestamp. If delivery precedes its flush callback, byte debt releases, but bounded metadata remains until the callback; that late callback creates no retroactive measurement. Another newly delivered known-flushed record in the same cumulative prefix may still qualify causally.

Raw positive elapsed time remains visible. Clamp each sample to configured min/maxRTT before a7/8 EWMA; stale prior history starts a fresh EWMA. Eligibility uses original feedback timestamp and strict age<TTL. At TTL expiry the target uses configured bootstrapRTT; reading status never refreshes history. Finite upper RTT and64MiB cap prevent unbounded feedback-delay/window growth, but this is admission sizing, not congestion avoidance or a proof of fairness. Runtime tuning and native evidence remain required.

Every admitted record retains an original admission+flush_timeout deadline, including delivered records missing a flush callback. The timeout is an explicit new profile policy; do not retrofit it into existing runtimes silently. The earliest unflushed deadline is observable; `tick` and mutating operations latch terminal `FlushExpired` at equality. Retries neither renew nor discard ownership. Status queries report the already-latched failure and deadline but do not manufacture a timeout event. Operational times cannot regress; exact duplicate operations advance only the operation watermark, preserving all event times/deadlines.

Runtime callbacks may be observed after another admission advanced the actor clock. `confirm_flushed_at(record_ordinal,actual_flush_at,observed_at)` and `delivered_at(Credit,actual_feedback_at,observed_at)` preserve genuine original event times. Existing convenience methods pass the same timestamp for both. Observation time alone governs monotonic actor health and original deadline expiry before the event can apply; a timely actual flush reported after its admission-time deadline cannot revive the session. Actual times must not exceed observation time or precede covered admissions; advancing prefix event times cannot regress. All timestamp checks preflight before mutating the prefix. Receipt freshness is computed from original feedback time. An ACK already applied without a known full flush remains unsampled after later callbacks or duplicate ACKs. A first delayed ACK application may use genuine earlier flush and feedback timestamps already available, provided flush strictly precedes receipt.

The metadata ring is preallocated; no per-admission allocation occurs. Deadline lookup and boundary lookup are constant-time. Cumulative flush/delivery work is bounded by newly advanced records, at most8192. Draining the confirmed/delivered prefix reclaims slots and preserves monotonic cumulative counters. Checked arithmetic rejects exhaustion before admission mutation. The integrating runtime must reserve compatible receiving payload capacity and authenticate byte/record limits before enabling the profile; local queues alone cannot back arbitrary peer promises.

## Verification scope

Focused tests cover875KB bootstrap, many small actual-byte records, record-cap blocking, cumulative feedback boundaries, duplicate/stale/future feedback, RTT growth/shrink/clamps/TTL, late flush callbacks, ring wrap, metadata precheck, monotonic clock, checked cumulative exhaustion and original terminal deadlines. The source25 pure package passes41 unit tests and one documentation test, including original event timestamps distinct from delayed observation. Commands/results are recorded under `work/client-delivery25/` and `work/managed-delivery25/`; the full root `python3 tools/check.py` and native gates remain separate.

## Runtime selection and causal comparison

The shared client API exposes `connect_with_delivery`, `accept_with_delivery`,
`ConnectionConfig::mode_with_delivery` and `session_with_delivery`. All twelve
fields of both canonical directions enter a domain-separated authenticated
session digest. Existing handshake and pairing operations retain one original
deadline. Peers reject mismatched or reversed policies before user data flows.

The CLI selects this profile with `--delivery-window bdp --forward-mbps N
--reverse-mbps N --bootstrap-rtt-ms N`. Both peers use identical canonical
forward/reverse settings. System TCP/TLS frame records retain an explicit legacy
comparison baseline. Aligned/packed client APIs now require `Settings.delivery`;
their CLI requires explicit BDP selection over UDP or genuine QUIC. The shared
strict `delivery::Policy` JSON type also serves rolling configuration and the
packed capture auditor. These new client paths pass [the source27e aggregate](../../work/implementation-wave27e/validation.json);
MOD-BDP-04's earlier receipt covers TCP/TLS only. Local queue
capacity stays64 packets. BDP byte and record limits are independent, and
receiver pending storage is bounded by the negotiated hard limits. A blocked
packet is staged once, without dropping it or exempting small TCP ACKs.

The native comparison uses100/10 Mbit/s directional targets,70ms bootstrap,
125% headroom,4MiB maximum outstanding bytes and8192 metadata records. These
settings stay identical across clean, delay and loss profiles. The measured
service RTT replaces bootstrap as valid observations arrive. Schema2 profiling
exposes current target bytes, outstanding bytes/records, retained metadata,
RTT freshness and staged bytes separately from local-queue high-water marks.
The source24 legacy comparison remains preserved; source25 must independently
pass exact payload, cleanup and actual80Mbit/s forward acceptance.


## Selective native identities (source27 pure integration stage)

Aligned and packed records may complete on independent channels. Their scalar
native delivery count is not a cumulative admission prefix: delivering a later
40-byte frame must not release an earlier 1500-byte frame. The shared controller
therefore provides `delivered_record_at(admission_ordinal, actual_receipt,
observed_at)` and `confirm_record_flushed_at(admission_ordinal, actual_send,
observed_at)`. The immediate-time conveniences are `delivered_record` and
`confirm_record_flushed`. Integrators must resolve an authenticated native
channel/record identity through their own bounded original-admission ledger;
peers never supply an authoritative byte length.

`Status.delivered` counts unique actual delivered bytes and records, while
`delivered_prefix` separately identifies the contiguous completed admission
boundary. `Status.flushed` remains the true contiguous full-send prefix;
`flushed_total` counts actual confirmed native completions beyond that prefix.
A later packed completion cannot confirm a missing earlier frame. Cumulative
APIs retain their previous behavior and can overlap selective operations without
double release or replacing an original timestamp. A duplicate selective receipt
never creates a service sample, including an ACK preceding its send callback.

The original preallocated `max_records` bounds the entire retained ordinal span,
including selectively delivered holes. Releasing byte debt does not reclaim a
metadata slot across a missing earlier delivery/send callback. The earliest
unconfirmed original admission deadline remains authoritative, and callbacks
observed at or after expiry cannot revive the owner. Added metadata is included
in `Config::metadata_bytes` before allocation. This pure extension does not yet
qualify aligned/packed runtime integration or native performance. The focused pure package passes49 unit tests and one doctest, strict Clippy,
rustdoc and formatting. The immutable-source26 scalar-mapping probes fail both
expected assertions. Results are recorded in
[the pure-stage receipt](../../work/aligned-delivery27/pure-validation.json);
the first49-test run retained one test-only observation-clock ordering failure,
corrected before the final run. No whole-workspace or native claim is made.
